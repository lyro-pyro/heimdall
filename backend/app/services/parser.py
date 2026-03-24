"""
Content parser service — extracts analyzable text from all input types.
Supports: text, file, sql, chat, log.
"""

from typing import Optional

from app.core.logging_config import logger
from app.models.schemas import StructuredLog
from app.utils.file_handling import decode_base64_content, extract_text_from_file
from app.utils.log_parser import parse_raw_logs
from app.utils.log_validator import validate_batch
from app.utils.validators import sanitize_content, validate_content_length


class Parser:
    """Multi-source content parser with validation and sanitization."""

    def parse(self, input_type: str, content: str, file_name: str | None = None) -> str:
        """
        Parse content based on input type.
        Returns cleaned, analyzable text.
        """
        logger.info(f"Parsing input_type={input_type}, content_length={len(content)}")

        # Smart content handling: truncate very large inputs instead of rejecting
        from app.core.config import settings
        max_len = settings.MAX_CONTENT_LENGTH
        if len(content) > max_len:
            logger.warning(
                f"Content length ({len(content)}) exceeds limit ({max_len}). "
                f"Truncating to first {max_len} characters for analysis."
            )
            content = content[:max_len]

        from typing import Callable, Dict
        parser_map: Dict[str, Callable[[str], str]] = {
            "text": self._parse_text,
            "file": self._parse_file,
            "sql": self._parse_sql,
            "chat": self._parse_chat,
            "log": self._parse_log,
        }

        parser_fn = parser_map.get(input_type.lower())
        if not parser_fn:
            raise ValueError(f"Unsupported input type: {input_type}")

        if input_type.lower() == "file":
            parsed = self._parse_file(content, file_name)
        else:
            parsed = parser_fn(content)

        sanitized = sanitize_content(parsed)

        logger.info(f"Parsed successfully: {len(sanitized)} characters")
        return sanitized

    def parse_to_structured(
        self,
        input_type: str,
        content: str,
        file_name: str | None = None,
    ) -> Optional[list[StructuredLog]]:
        """
        Parse raw content into structured log entries.
        Only applicable for 'log' input type; returns None for other types.

        Pipeline: raw text → log_parser (regex chain) → log_validator (Pydantic)

        Args:
            input_type: The type of input being processed.
            content: Raw log content.
            file_name: Optional file name for file-based input.

        Returns:
            List of validated StructuredLog instances, or None if not a log type.
        """
        if input_type.lower() not in ("log", "text"):
            return None

        logger.info("Parsing content into structured log entries")

        # Step 1: Parse raw lines into dictionaries
        parsed_dicts, parse_warnings = parse_raw_logs(content)

        if parse_warnings:
            for w in parse_warnings:
                logger.warning(f"Parse warning: {w}")

        if not parsed_dicts:
            logger.info("No structured logs produced from content")
            return None

        # Step 2: Validate through Pydantic
        valid_logs, validation_errors = validate_batch(parsed_dicts)

        if validation_errors:
            for err in validation_errors:
                logger.warning(f"Validation error: {err}")

        logger.info(
            f"Structured parsing complete: {len(valid_logs)} valid logs "
            f"from {len(parsed_dicts)} parsed entries"
        )

        return valid_logs if valid_logs else None

    def _parse_text(self, content: str) -> str:
        """Parse plain text input."""
        return content.strip()

    def _parse_file(self, content: str, file_name: str | None = None) -> str:
        """
        Parse file input. Expects base64-encoded content.
        Falls back to treating as raw text if base64 decoding fails.
        """
        try:
            # Try base64 decode first (for uploaded files)
            file_bytes = decode_base64_content(content)
            # Attempt to detect file type from content
            # For simplicity, try UTF-8 text first, then PDF/DOCX
            try:
                text = file_bytes.decode("utf-8")
                return text.strip()
            except UnicodeDecodeError:
                # Use actual filename to let extract_text_from_file dictate parser
                safe_name = file_name if file_name else "uploaded.pdf"
                return extract_text_from_file(file_bytes, safe_name)
        except ValueError:
            # Not base64 — treat as raw text content
            logger.info("File content not base64-encoded, treating as raw text")
            return content.strip()

    def _parse_sql(self, content: str) -> str:
        """Parse SQL/structured data input."""
        return content.strip()

    def _parse_chat(self, content: str) -> str:
        """Parse chat message input."""
        return content.strip()

    def _parse_log(self, content: str) -> str:
        """Parse log input — preserves line structure for line-by-line analysis."""
        return content.strip()

