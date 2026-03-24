"""
Log Normalizer — ensures all log fields conform to canonical format.
Handles timestamp parsing, log level mapping, and default value injection.
"""

import re
from datetime import datetime, timezone
from typing import Optional

from app.core.logging_config import logger


# ── Timestamp Formats ────────────────────────────────────────────────────────
# Ordered by specificity — most specific formats first to avoid false matches.

TIMESTAMP_FORMATS = [
    # ISO 8601 variants
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    # Common log date formats
    "%d/%b/%Y:%H:%M:%S %z",       # Apache/Nginx: 10/Oct/2024:13:55:36 -0700
    "%d/%b/%Y:%H:%M:%S",          # Apache without timezone
    "%b %d %H:%M:%S",              # Syslog: Oct 10 13:55:36
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S,%f",       # Python logging default
    "%Y-%m-%d %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",          # US format
    "%d/%m/%Y %H:%M:%S",          # EU format
    "%Y/%m/%d %H:%M:%S",
]


# ── Log Level Mapping ────────────────────────────────────────────────────────
# Maps all common level strings to our canonical set.

LEVEL_MAP = {
    # Standard
    "INFO": "INFO",
    "WARNING": "WARNING",
    "ERROR": "ERROR",
    "CRITICAL": "CRITICAL",
    # Common aliases
    "WARN": "WARNING",
    "ERR": "ERROR",
    "FATAL": "CRITICAL",
    "CRIT": "CRITICAL",
    "EMERG": "CRITICAL",
    "ALERT": "CRITICAL",
    "PANIC": "CRITICAL",
    "DEBUG": "INFO",
    "TRACE": "INFO",
    "NOTICE": "INFO",
    "VERBOSE": "INFO",
    # HTTP status code ranges (from access logs)
    "2XX": "INFO",
    "3XX": "INFO",
    "4XX": "WARNING",
    "5XX": "ERROR",
}


def normalize_timestamp(ts_string: str) -> str:
    """
    Parse a timestamp string in any recognized format and return ISO 8601.
    Falls back to current UTC time if parsing fails entirely.

    Args:
        ts_string: Raw timestamp string from a log line.

    Returns:
        ISO 8601 formatted datetime string.
    """
    if not ts_string or not ts_string.strip():
        return datetime.now(timezone.utc).isoformat()

    cleaned = ts_string.strip().strip("[]")

    for fmt in TIMESTAMP_FORMATS:
        try:
            dt = datetime.strptime(cleaned, fmt)
            # If no timezone info, assume UTC
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            # Syslog format has no year — inject current year
            if fmt == "%b %d %H:%M:%S":
                dt = dt.replace(year=datetime.now().year, tzinfo=timezone.utc)
            return dt.isoformat()
        except ValueError:
            continue

    # Fallback: try to extract any date-like pattern
    logger.warning(f"Could not parse timestamp: '{ts_string}', using current time")
    return datetime.now(timezone.utc).isoformat()


def normalize_log_level(level_string: str) -> str:
    """
    Map any log level string to one of: INFO, WARNING, ERROR, CRITICAL.

    Args:
        level_string: Raw log level from a log line.

    Returns:
        Normalized uppercase level string.
    """
    if not level_string:
        return "INFO"

    upper = level_string.strip().upper()
    return LEVEL_MAP.get(upper, "INFO")


def normalize_log(log_dict: dict) -> dict:
    """
    Apply all normalizations to a raw log dictionary.
    Ensures timestamps are ISO, levels are canonical, and missing fields get defaults.

    Args:
        log_dict: Raw parsed log dictionary.

    Returns:
        Normalized log dictionary ready for StructuredLog validation.
    """
    # Normalize timestamp
    raw_ts = log_dict.get("timestamp", "")
    log_dict["timestamp"] = normalize_timestamp(raw_ts)

    # Normalize log level
    raw_level = log_dict.get("log_level", "INFO")
    log_dict["log_level"] = normalize_log_level(raw_level)

    # Default service
    if not log_dict.get("service"):
        log_dict["service"] = "unknown"

    # Default message
    if not log_dict.get("message"):
        log_dict["message"] = ""

    # Ensure metadata exists as dict
    if "metadata" not in log_dict or log_dict["metadata"] is None:
        log_dict["metadata"] = {}

    # Clean metadata — set empty strings to None
    meta = log_dict["metadata"]
    for key in ("ip_address", "user_id", "endpoint", "error_code"):
        val = meta.get(key)
        if val is not None and isinstance(val, str) and not val.strip():
            meta[key] = None

    return log_dict
