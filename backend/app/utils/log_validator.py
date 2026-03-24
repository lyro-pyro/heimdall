"""
Log Validator — Pydantic-based validation and sanitization layer.
Ensures every log entry conforms to the StructuredLog schema before
it enters the system for storage or analysis.
"""

import re
from typing import Optional

from pydantic import ValidationError

from app.core.logging_config import logger
from app.models.schemas import StructuredLog


class LogValidationError(Exception):
    """Raised when a log entry fails validation."""

    def __init__(self, message: str, line_number: Optional[int] = None):
        self.line_number = line_number
        super().__init__(message)


def sanitize_message(message: str) -> str:
    """
    Clean a log message string for safe processing.

    Removes:
      - Null bytes and control characters (except newline/tab)
      - ANSI escape sequences (color codes)
      - Excessive whitespace

    Args:
        message: Raw message string.

    Returns:
        Sanitized message string.
    """
    if not message:
        return ""

    # Remove null bytes
    cleaned = message.replace("\x00", "")

    # Remove ANSI escape codes
    cleaned = re.sub(r"\x1b\[[0-9;]*m", "", cleaned)

    # Remove other control characters except \n, \r, \t
    cleaned = re.sub(r"[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]", "", cleaned)

    # Collapse excessive whitespace within the message
    cleaned = re.sub(r"[ \t]+", " ", cleaned)

    return cleaned.strip()


def validate_log(log_dict: dict, line_number: Optional[int] = None) -> StructuredLog:
    """
    Validate a single log dictionary against the StructuredLog schema.

    Performs sanitization on the message field before Pydantic validation.
    Raises LogValidationError with a clear message on failure.

    Args:
        log_dict: Normalized log dictionary.
        line_number: Optional source line number for error context.

    Returns:
        Validated StructuredLog instance.

    Raises:
        LogValidationError: If the log fails schema validation.
    """
    # Pre-validation sanitization
    if "message" in log_dict:
        log_dict["message"] = sanitize_message(log_dict["message"])

    # Reject empty messages
    if not log_dict.get("message", "").strip():
        raise LogValidationError(
            f"Log validation failed: empty message field",
            line_number=line_number,
        )

    try:
        return StructuredLog(**log_dict)
    except ValidationError as e:
        # Build a clear, human-readable error from Pydantic's errors
        errors = e.errors()
        field_errors = []
        for err in errors:
            field = " → ".join(str(loc) for loc in err["loc"])
            field_errors.append(f"'{field}': {err['msg']}")

        error_msg = f"Log validation failed: {'; '.join(field_errors)}"
        raise LogValidationError(error_msg, line_number=line_number) from e


def validate_batch(
    log_dicts: list[dict],
) -> tuple[list[StructuredLog], list[str]]:
    """
    Validate a batch of log dictionaries.
    Returns successfully validated logs and a list of error messages.

    Invalid logs are skipped (not fatal), with errors collected
    for reporting back to the caller.

    Args:
        log_dicts: List of normalized log dictionaries.

    Returns:
        Tuple of (valid_logs, error_messages).
    """
    valid_logs: list[StructuredLog] = []
    errors: list[str] = []

    for i, log_dict in enumerate(log_dicts):
        try:
            validated = validate_log(log_dict, line_number=i + 1)
            valid_logs.append(validated)
        except LogValidationError as e:
            error_msg = f"Line {e.line_number or i + 1}: {str(e)}"
            errors.append(error_msg)
            logger.warning(f"Validation skip: {error_msg}")

    logger.info(
        f"Batch validation: {len(valid_logs)} valid, {len(errors)} errors "
        f"out of {len(log_dicts)} total"
    )
    return valid_logs, errors
