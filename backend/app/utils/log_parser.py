"""
Log Parser — regex-based multi-format parser that converts raw log lines
into structured dictionaries ready for normalization and validation.

Supported formats:
  1. Apache/Nginx Combined Log
  2. Syslog (RFC 3164)
  3. JSON Lines (pre-structured)
  4. Generic timestamped (YYYY-MM-DD HH:MM:SS LEVEL message)
  5. Python logging default
  6. Fallback: entire line as message
"""

import json
import re
from typing import Optional

from app.core.logging_config import logger
from app.utils.log_normalizer import normalize_log


# ── Compiled Regex Patterns ──────────────────────────────────────────────────

# Apache/Nginx Combined Log Format:
# 192.168.1.1 - user [10/Oct/2024:13:55:36 -0700] "GET /api/data HTTP/1.1" 200 2048
APACHE_PATTERN = re.compile(
    r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"         # Client IP
    r"(?P<ident>\S+)\s+"                              # Ident (usually -)
    r"(?P<user>\S+)\s+"                               # Auth user
    r"\[(?P<timestamp>[^\]]+)\]\s+"                   # Timestamp in brackets
    r'"(?P<method>\w+)\s+(?P<endpoint>\S+)\s+\S+"\s+' # Request line
    r"(?P<status>\d{3})\s+"                           # Status code
    r"(?P<size>\S+)",                                  # Response size
)

# Syslog (RFC 3164):
# Oct 10 13:55:36 myhost sshd[12345]: Failed password for invalid user
SYSLOG_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"  # Timestamp
    r"(?P<host>\S+)\s+"                                           # Hostname
    r"(?P<service>\S+?)(?:\[\d+\])?:\s+"                         # Service[PID]:
    r"(?P<message>.+)$",                                          # Message
)

# Generic timestamped log:
# 2024-03-15 14:30:00 ERROR [auth-service] Login failed for user admin
GENERIC_TS_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}[-/]\d{2}[-/]\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)\s+"
    r"(?P<level>INFO|WARNING|WARN|ERROR|ERR|CRITICAL|CRIT|FATAL|DEBUG|TRACE)\s+"
    r"(?:\[(?P<service>[^\]]+)\]\s+)?"                            # Optional [service]
    r"(?P<message>.+)$",
    re.IGNORECASE,
)

# Python logging default:
# WARNING:root:This is a warning message
PYTHON_LOG_PATTERN = re.compile(
    r"^(?P<level>INFO|WARNING|WARN|ERROR|CRITICAL|DEBUG):(?P<service>[^:]+):(?P<message>.+)$",
    re.IGNORECASE,
)


def _http_status_to_level(status_code: str) -> str:
    """Map HTTP status code to a log level string."""
    code = int(status_code) if status_code.isdigit() else 200
    if code < 400:
        return "INFO"
    elif code < 500:
        return "WARNING"
    else:
        return "ERROR"


def _try_parse_json(line: str) -> Optional[dict]:
    """
    Attempt to parse a line as JSON.
    Returns a normalized dict if successful, None otherwise.
    """
    try:
        data = json.loads(line)
        if not isinstance(data, dict):
            return None

        # Map common JSON log field names to our schema
        result = {
            "timestamp": (
                data.get("timestamp") or data.get("time") or
                data.get("@timestamp") or data.get("datetime") or data.get("ts") or ""
            ),
            "log_level": (
                data.get("log_level") or data.get("level") or
                data.get("severity") or data.get("loglevel") or "INFO"
            ),
            "service": (
                data.get("service") or data.get("source") or
                data.get("logger") or data.get("app") or
                data.get("module") or "unknown"
            ),
            "message": (
                data.get("message") or data.get("msg") or
                data.get("text") or data.get("log") or ""
            ),
            "metadata": {},
        }

        # Extract metadata fields
        meta = data.get("metadata", {})
        if isinstance(meta, dict):
            result["metadata"] = meta
        else:
            result["metadata"] = {}

        # Also check top-level for metadata fields
        for field in ("ip_address", "ip", "remote_addr", "client_ip"):
            val = data.get(field)
            if val:
                result["metadata"]["ip_address"] = str(val)
                break

        for field in ("user_id", "user", "userId", "username"):
            val = data.get(field)
            if val:
                result["metadata"]["user_id"] = str(val)
                break

        for field in ("endpoint", "path", "url", "uri", "request_path"):
            val = data.get(field)
            if val:
                result["metadata"]["endpoint"] = str(val)
                break

        for field in ("error_code", "errorCode", "error", "code", "status_code"):
            val = data.get(field)
            if val:
                result["metadata"]["error_code"] = str(val)
                break

        return result
    except (json.JSONDecodeError, TypeError, KeyError):
        return None


def _parse_apache(line: str) -> Optional[dict]:
    """Parse an Apache/Nginx combined log format line."""
    match = APACHE_PATTERN.match(line)
    if not match:
        return None

    return {
        "timestamp": match.group("timestamp"),
        "log_level": _http_status_to_level(match.group("status")),
        "service": "webserver",
        "message": f'{match.group("method")} {match.group("endpoint")} — {match.group("status")}',
        "metadata": {
            "ip_address": match.group("ip"),
            "user_id": match.group("user") if match.group("user") != "-" else None,
            "endpoint": match.group("endpoint"),
            "error_code": match.group("status") if int(match.group("status")) >= 400 else None,
        },
    }


def _parse_syslog(line: str) -> Optional[dict]:
    """Parse a syslog (RFC 3164) format line."""
    match = SYSLOG_PATTERN.match(line)
    if not match:
        return None

    message = match.group("message")

    # Infer log level from message content
    level = "INFO"
    msg_lower = message.lower()
    if any(kw in msg_lower for kw in ("error", "fail", "denied", "refused", "fatal")):
        level = "ERROR"
    elif any(kw in msg_lower for kw in ("warn", "timeout", "retry", "slow")):
        level = "WARNING"
    elif any(kw in msg_lower for kw in ("critical", "panic", "emergency", "crash")):
        level = "CRITICAL"

    return {
        "timestamp": match.group("timestamp"),
        "log_level": level,
        "service": match.group("service"),
        "message": message,
        "metadata": {},
    }


def _parse_generic_ts(line: str) -> Optional[dict]:
    """Parse a generic timestamped log line."""
    match = GENERIC_TS_PATTERN.match(line)
    if not match:
        return None

    return {
        "timestamp": match.group("timestamp"),
        "log_level": match.group("level"),
        "service": match.group("service") or "unknown",
        "message": match.group("message"),
        "metadata": {},
    }


def _parse_python_log(line: str) -> Optional[dict]:
    """Parse a Python logging default format line."""
    match = PYTHON_LOG_PATTERN.match(line)
    if not match:
        return None

    return {
        "timestamp": "",  # Python default format has no timestamp — normalizer will fill
        "log_level": match.group("level"),
        "service": match.group("service"),
        "message": match.group("message"),
        "metadata": {},
    }


def _fallback_parse(line: str) -> dict:
    """
    Fallback parser for unrecognized log formats.
    Preserves the entire line as the message field.
    """
    return {
        "timestamp": "",  # Normalizer will inject current UTC time
        "log_level": "INFO",
        "service": "unknown",
        "message": line.strip(),
        "metadata": {},
    }


# ── Parser Chain ─────────────────────────────────────────────────────────────
# Ordered by specificity: JSON first, then structured formats, then fallback.

_PARSERS = [
    ("json", _try_parse_json),
    ("apache", _parse_apache),
    ("generic_ts", _parse_generic_ts),
    ("python_log", _parse_python_log),
    ("syslog", _parse_syslog),
]


def parse_log_line(line: str) -> dict:
    """
    Parse a single log line through the parser chain.
    Returns a normalized dictionary matching the StructuredLog schema.

    Each parser is tried in order; the first successful match wins.
    If no parser matches, the fallback parser preserves the raw line.

    Args:
        line: A single line of log text.

    Returns:
        Normalized dictionary with timestamp, log_level, service, message, metadata.
    """
    stripped = line.strip()
    if not stripped:
        return normalize_log(_fallback_parse(""))

    for parser_name, parser_fn in _PARSERS:
        result = parser_fn(stripped)
        if result is not None:
            return normalize_log(result)

    # No parser matched — use fallback
    return normalize_log(_fallback_parse(stripped))


def parse_raw_logs(raw_content: str) -> tuple[list[dict], list[str]]:
    """
    Parse a multi-line raw log string into a list of structured log dicts.

    First attempts to parse the entire content as a JSON array.
    If that fails, falls back to line-by-line parsing.

    Args:
        raw_content: Multi-line raw log text.

    Returns:
        Tuple of (parsed_logs, warnings).
        - parsed_logs: list of normalized log dicts
        - warnings: list of warning messages about parse issues
    """
    warnings: list[str] = []
    parsed_logs: list[dict] = []

    # Step 1: Try parsing the entire content as a JSON array
    try:
        data = json.loads(raw_content)
        if isinstance(data, list):
            for i, item in enumerate(data):
                if isinstance(item, dict):
                    result = _try_parse_json(json.dumps(item))
                    if result:
                        parsed_logs.append(normalize_log(result))
                    else:
                        warnings.append(f"JSON array item {i}: could not map to log schema")
                        parsed_logs.append(normalize_log(_fallback_parse(str(item))))
                else:
                    warnings.append(f"JSON array item {i}: expected object, got {type(item).__name__}")
                    parsed_logs.append(normalize_log(_fallback_parse(str(item))))

            logger.info(f"Parsed {len(parsed_logs)} logs from JSON array")
            return parsed_logs, warnings
    except (json.JSONDecodeError, TypeError):
        pass  # Not a JSON array — proceed with line-by-line

    # Step 2: Line-by-line parsing
    lines = raw_content.split("\n")
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue  # Skip blank lines

        parsed = parse_log_line(stripped)
        parsed_logs.append(parsed)

    logger.info(f"Parsed {len(parsed_logs)} logs from {len(lines)} raw lines")
    return parsed_logs, warnings
