"""
AI Preprocessor — prepares structured logs for LLM and ML consumption.
Cleans, truncates, groups, and deduplicates log entries to produce
optimized context windows for AI analysis.
"""

import re
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional

from app.core.logging_config import logger
from app.models.schemas import StructuredLog


# ── Configuration ────────────────────────────────────────────────────────────

MAX_MESSAGE_LENGTH = 500      # Truncate messages beyond this length
GROUP_WINDOW_SECONDS = 30     # Time window for grouping related logs
MAX_DEDUP_COUNT = 50          # Cap dedup counter display


def _clean_message(message: str) -> str:
    """
    Clean a log message for AI consumption.

    Removes:
      - ANSI escape codes
      - Excessive whitespace and blank lines
      - Very long hex/base64 blobs (replaced with placeholder)

    Args:
        message: Raw log message.

    Returns:
        Cleaned message string.
    """
    # Remove ANSI escape codes
    cleaned = re.sub(r"\x1b\[[0-9;]*m", "", message)

    # Replace long hex strings (>40 chars) with placeholder
    cleaned = re.sub(r"[0-9a-fA-F]{40,}", "[HEX_BLOB]", cleaned)

    # Replace long base64 strings (>60 chars) with placeholder
    cleaned = re.sub(r"[A-Za-z0-9+/=]{60,}", "[BASE64_BLOB]", cleaned)

    # Collapse whitespace
    cleaned = re.sub(r"\s+", " ", cleaned).strip()

    return cleaned


def _truncate_message(message: str, max_length: int = MAX_MESSAGE_LENGTH) -> str:
    """
    Truncate a message if it exceeds max_length.
    Adds an ellipsis indicator when truncated.
    """
    if len(message) <= max_length:
        return message
    return message[:max_length - 3] + "..."


def _parse_iso_timestamp(ts: str) -> Optional[datetime]:
    """Attempt to parse an ISO timestamp string into a datetime."""
    try:
        # Handle the 'Z' suffix
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        return datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return None


def _group_related_logs(
    logs: list[dict],
    window_seconds: int = GROUP_WINDOW_SECONDS,
) -> list[dict]:
    """
    Group related logs by (service, log_level) within a time window.

    Consecutive logs from the same service at the same level within
    the time window are merged into a single entry with combined messages.

    Args:
        logs: List of processed log dicts.
        window_seconds: Maximum seconds between related logs.

    Returns:
        Grouped log list.
    """
    if not logs:
        return []

    grouped: list[dict] = []
    current_group: Optional[dict] = None

    for log in logs:
        log_ts = _parse_iso_timestamp(log.get("timestamp", ""))

        if current_group is None:
            current_group = {**log, "_messages": [log["message"]], "_count": 1}
            current_group["_ts"] = log_ts
            continue

        # Check if this log belongs to the current group
        same_service = log.get("service") == current_group.get("service")
        same_level = log.get("log_level") == current_group.get("log_level")

        # Check time proximity
        in_window = True
        if log_ts and current_group.get("_ts"):
            delta = abs((log_ts - current_group["_ts"]).total_seconds())
            in_window = delta <= window_seconds

        if same_service and same_level and in_window:
            # Add to current group
            current_group["_messages"].append(log["message"])
            current_group["_count"] += 1
        else:
            # Finalize current group and start new one
            _finalize_group(current_group)
            grouped.append(current_group)
            current_group = {**log, "_messages": [log["message"]], "_count": 1}
            current_group["_ts"] = log_ts

    if current_group:
        _finalize_group(current_group)
        grouped.append(current_group)

    return grouped


def _finalize_group(group: dict) -> None:
    """Finalize a group by combining messages and cleaning up internal fields."""
    count = group.pop("_count", 1)
    messages = group.pop("_messages", [group.get("message", "")])
    group.pop("_ts", None)

    if count > 1:
        # Combine unique messages with count
        unique_msgs = list(dict.fromkeys(messages))  # Preserve order, remove dups
        combined = " | ".join(unique_msgs[:5])  # Cap at 5 unique messages
        if count > 5:
            combined += f" | ... (+{count - 5} more)"
        group["message"] = combined
        group["_grouped_count"] = min(count, MAX_DEDUP_COUNT)
    # Single message — no change needed


def _deduplicate_consecutive(logs: list[dict]) -> list[dict]:
    """
    Collapse identical consecutive log messages into a single entry
    with a count annotation.

    Args:
        logs: List of processed log dicts.

    Returns:
        Deduplicated log list.
    """
    if not logs:
        return []

    result: list[dict] = []
    prev: Optional[dict] = None
    count = 1

    for log in logs:
        if prev and log.get("message") == prev.get("message") and \
           log.get("service") == prev.get("service"):
            count += 1
        else:
            if prev:
                if count > 1:
                    prev["message"] = f"[x{min(count, MAX_DEDUP_COUNT)}] {prev['message']}"
                result.append(prev)
            prev = {**log}
            count = 1

    if prev:
        if count > 1:
            prev["message"] = f"[x{min(count, MAX_DEDUP_COUNT)}] {prev['message']}"
        result.append(prev)

    return result


def prepare_logs_for_ai(logs: list[StructuredLog]) -> list[dict]:
    """
    Prepare a list of StructuredLog entries for AI/LLM consumption.

    Processing pipeline:
      1. Convert to plain dicts
      2. Clean messages (strip ANSI, replace blobs)
      3. Truncate long messages
      4. Deduplicate identical consecutive messages
      5. Group related logs by service + time window

    Args:
        logs: List of validated StructuredLog instances.

    Returns:
        List of cleaned, truncated, deduplicated, and grouped log dicts
        optimized for AI context windows.
    """
    if not logs:
        return []

    logger.info(f"AI preprocessing: {len(logs)} logs input")

    # Step 1: Convert to dicts and apply message cleaning
    processed: list[dict] = []
    for log in logs:
        entry = log.model_dump()
        entry["message"] = _truncate_message(_clean_message(entry["message"]))
        processed.append(entry)

    # Step 2: Deduplicate consecutive identical messages
    deduped = _deduplicate_consecutive(processed)
    logger.info(f"AI preprocessing: {len(processed)} → {len(deduped)} after dedup")

    # Step 3: Group related logs by service + time window
    grouped = _group_related_logs(deduped)
    logger.info(f"AI preprocessing: {len(deduped)} → {len(grouped)} after grouping")

    # Step 4: Strip internal metadata keys from output
    clean_output = []
    for entry in grouped:
        clean_entry = {
            "timestamp": entry.get("timestamp", ""),
            "log_level": entry.get("log_level", "INFO"),
            "service": entry.get("service", "unknown"),
            "message": entry.get("message", ""),
        }
        # Include metadata only if it has non-null values
        meta = entry.get("metadata", {})
        if isinstance(meta, dict) and any(v for v in meta.values()):
            clean_entry["metadata"] = {k: v for k, v in meta.items() if v}
        clean_output.append(clean_entry)

    logger.info(f"AI preprocessing complete: {len(clean_output)} entries ready")
    return clean_output
