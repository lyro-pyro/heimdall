"""Pydantic schemas for strict API contract compliance."""

from __future__ import annotations

from typing import Optional, Dict, List

from pydantic import BaseModel, Field, field_validator


class Options(BaseModel):
    """Analysis options controlling masking, blocking, and log analysis."""

    mask: bool = False
    block_high_risk: bool = False
    log_analysis: bool = True


class AnalyzeRequest(BaseModel):
    """
    Request schema for POST /analyze.
    Supports: text, file, sql, chat, log input types.
    """

    input_type: str = Field(
        ...,
        description="Type of input: text | file | sql | chat | log",
    )
    content: str = Field(
        ...,
        description="The content to analyze (raw text or base64-encoded file)",
    )
    file_name: str | None = Field(
        default=None,
        description="Optional original filename for proper MIME parsing"
    )
    options: Options = Field(default_factory=Options)

    @field_validator("input_type")
    @classmethod
    def validate_input_type(cls, v: str) -> str:
        allowed = {"text", "file", "sql", "chat", "log"}
        if v.lower() not in allowed:
            raise ValueError(f"input_type must be one of {allowed}")
        return v.lower()

    @field_validator("content")
    @classmethod
    def validate_content_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("content must not be empty")
        return v


class Finding(BaseModel):
    """A single detection finding — strict: only type, risk, line."""

    type: str
    risk: str
    line: int
    reasoning: str = ""
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    ioc: Optional[str] = None


class AnalyzeResponse(BaseModel):
    """
    Response schema for POST /analyze.
    Matches the exact API contract with no extra fields.
    """

    summary: str
    content_type: str
    findings: list[Finding]
    risk_score: int
    risk_level: str
    action: str
    insights: list[str]
    iocs: Dict[str, List[str]] = Field(default_factory=lambda: {"ips": [], "emails": [], "tokens": [], "other": []})
    structured_logs: Optional[List["StructuredLog"]] = Field(
        default=None,
        description="Structured log entries parsed from the input (when input_type is 'log')"
    )


# ── Structured Log Ingestion Models ──────────────────────────────────────────


class LogMetadata(BaseModel):
    """Optional metadata fields extracted from log lines."""

    ip_address: Optional[str] = None
    user_id: Optional[str] = None
    endpoint: Optional[str] = None
    error_code: Optional[str] = None


class StructuredLog(BaseModel):
    """
    Canonical structured log entry.
    Every log — regardless of original format — is normalized into this schema
    before storage or downstream processing.
    """

    timestamp: str = Field(
        ...,
        description="ISO 8601 datetime string (e.g. 2024-03-15T14:30:00Z)"
    )
    log_level: str = Field(
        ...,
        description="Normalized log level: INFO | WARNING | ERROR | CRITICAL"
    )
    service: str = Field(
        ...,
        description="Source system, module, or service name"
    )
    message: str = Field(
        ...,
        description="Main log message content"
    )
    metadata: LogMetadata = Field(default_factory=LogMetadata)

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        allowed = {"INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in allowed:
            # Map common aliases
            level_map = {
                "WARN": "WARNING", "ERR": "ERROR", "FATAL": "CRITICAL",
                "DEBUG": "INFO", "TRACE": "INFO", "NOTICE": "INFO",
                "EMERG": "CRITICAL", "ALERT": "CRITICAL", "CRIT": "CRITICAL",
            }
            upper = level_map.get(upper, "INFO")
        return upper


class IngestLogsRequest(BaseModel):
    """
    Request schema for POST /logs.
    Accepts raw log text, pre-structured JSON logs, or file content.
    At least one of raw_content or logs must be provided.
    """

    raw_content: Optional[str] = Field(
        default=None,
        description="Raw log text to be parsed into structured format"
    )
    logs: Optional[List[StructuredLog]] = Field(
        default=None,
        description="Pre-structured log entries (already in canonical format)"
    )
    file_name: Optional[str] = Field(
        default=None,
        description="Original filename when uploading a file"
    )

    @field_validator("raw_content")
    @classmethod
    def validate_raw_not_empty(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not v.strip():
            raise ValueError("raw_content must not be empty if provided")
        return v


class StructuredLogsResponse(BaseModel):
    """Response schema for GET /logs and POST /logs."""

    logs: List[StructuredLog]
    total: int
    parse_errors: int = 0
    parse_warnings: List[str] = Field(default_factory=list)


# Resolve forward references (AnalyzeResponse references StructuredLog defined below it)
AnalyzeResponse.model_rebuild()
