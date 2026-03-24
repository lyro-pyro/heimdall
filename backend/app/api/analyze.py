"""
API endpoints — orchestrates the full analysis pipeline and log ingestion.
Endpoints:
  POST /analyze        — Validate → Parse → Detect → Log Analyze → Risk → Policy → Insights → Response
  POST /logs           — Ingest raw or structured logs into the structured pipeline
  GET  /logs           — Retrieve stored structured logs with optional filters
  POST /ai/analyze-log — AI-powered single log analysis (explain, classify, suggest fixes)
  POST /ai/summarize   — AI-powered bulk log summary (counts, anomalies, health)
  POST /ai/classify    — AI-powered log classification (Normal/Suspicious/Malicious)
"""

from typing import Optional

from fastapi import APIRouter, HTTPException, Depends, Query

from pydantic import BaseModel, Field

from app.core.logging_config import logger
from app.models.schemas import (
    AnalyzeRequest, AnalyzeResponse, Finding,
    IngestLogsRequest, StructuredLog, StructuredLogsResponse,
)
from app.services.ai_preprocessor import prepare_logs_for_ai
from app.services.detector import Detector
from app.services.insight_engine import InsightEngine
from app.services.log_analyzer import LogAnalyzer
from app.services.parser import Parser
from app.services.policy_engine import PolicyEngine
from app.services.prompt_service import PromptService
from app.services.risk_engine import RiskEngine
from app.utils.log_parser import parse_raw_logs
from app.utils.log_validator import validate_batch, LogValidationError
from app.utils.validators import detect_content_type, is_potentially_malicious
from app.api.security import verify_api_key, check_rate_limit

router = APIRouter()

# Initialize services
parser = Parser()
detector = Detector()
log_analyzer = LogAnalyzer()
risk_engine = RiskEngine()
policy_engine = PolicyEngine()
insight_engine = InsightEngine()
prompt_service = PromptService()

# ── In-Memory Structured Log Store ────────────────────────────────────────────
# In a production system this would be a database. For this project,
# we use a simple list that persists for the lifetime of the server process.
_structured_log_store: list[StructuredLog] = []


@router.post(
    "/analyze",
    response_model=AnalyzeResponse,
    dependencies=[Depends(verify_api_key), Depends(check_rate_limit)]
)
async def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    """
    Main analysis endpoint.
    Accepts multi-source input and returns structured security analysis.
    When input_type is 'log', also attaches structured_logs to the response.
    """
    try:
        logger.info(f"━━━ Analysis Request ━━━ type={request.input_type}")

        # ── Step 1: Validation ────────────────────────────────────────────
        malicious_warnings = is_potentially_malicious(request.content)
        if malicious_warnings:
            logger.warning(f"Input validation warnings: {malicious_warnings}")

        # ── Step 2: Parse content ─────────────────────────────────────────
        parsed_content = parser.parse(request.input_type, request.content, request.file_name)
        content_type = detect_content_type(request.input_type, parsed_content)
        logger.info(f"Content parsed: content_type={content_type}")

        # ── Step 2b: Structured log parsing (for log/text input) ──────────
        structured_logs = parser.parse_to_structured(
            request.input_type, request.content, request.file_name
        )
        if structured_logs:
            logger.info(f"Structured logs produced: {len(structured_logs)} entries")
            # Store in memory for GET /logs retrieval
            _structured_log_store.extend(structured_logs)

        # ── Step 3: Detection ─────────────────────────────────────────────
        findings: list[Finding] = detector.detect(parsed_content)
        logger.info(f"Detection complete: {len(findings)} findings")

        # ── Step 4: Log Analysis (if applicable) ──────────────────────────
        log_stats = None
        if request.options.log_analysis:
            log_result = log_analyzer.analyze(parsed_content)
            log_findings = log_result["findings"]
            log_stats = log_result["stats"]

            # Merge log-specific findings (avoid duplicates)
            existing_keys = {(f.type, f.line) for f in findings}
            for lf in log_findings:
                if (lf.type, lf.line) not in existing_keys:
                    findings.append(lf)
                    existing_keys.add((lf.type, lf.line))

            logger.info(
                f"Log analysis merged: total={len(findings)} findings, "
                f"stats={log_stats}"
            )

        # ── Step 5: Risk Scoring ──────────────────────────────────────────
        risk_result = risk_engine.calculate(findings)
        risk_score = risk_result["risk_score"]
        risk_level = risk_result["risk_level"]
        logger.info(f"Risk: score={risk_score}, level={risk_level}")

        # ── Step 6: Policy Engine ─────────────────────────────────────────
        policy_result = policy_engine.apply(
            content=parsed_content,
            findings=findings,
            risk_level=risk_level,
            mask=request.options.mask,
            block_high_risk=request.options.block_high_risk,
        )
        action = policy_result["action"]
        logger.info(f"Policy action: {action}")

        # ── Step 7: Insight Generation ────────────────────────────────────
        insight_result = await insight_engine.generate(
            findings=findings,
            risk_score=risk_score,
            risk_level=risk_level,
            content_type=content_type,
            log_stats=log_stats,
        )
        summary = insight_result["summary"]
        insights = insight_result["insights"]
        logger.info(f"Insights generated: {len(insights)} items")

        # ── Aggregate IOCs ────────────────────────────────────────────────
        iocs = {"ips": [], "emails": [], "tokens": [], "other": []}
        for f in findings:
            if getattr(f, "ioc", None):
                if f.type in ("suspicious_ip", "anomalous_ip_volume"):
                    if f.ioc not in iocs["ips"]: iocs["ips"].append(f.ioc)
                elif f.type == "email":
                    if f.ioc not in iocs["emails"]: iocs["emails"].append(f.ioc)
                elif f.type in ("token", "api_key", "password", "secret", "high_entropy_string"):
                    if f.ioc not in iocs["tokens"]: iocs["tokens"].append(f.ioc)
                else:
                    if f.ioc not in iocs["other"]: iocs["other"].append(f.ioc)

        # ── Step 8: Build Response ────────────────────────────────────────
        # Sort findings by line number for clean output
        findings.sort(key=lambda f: f.line)

        response = AnalyzeResponse(
            summary=summary,
            content_type=content_type,
            findings=findings,
            risk_score=risk_score,
            risk_level=risk_level,
            action=action,
            insights=insights,
            iocs=iocs,
            structured_logs=structured_logs,
        )

        logger.info(f"━━━ Analysis Complete ━━━ findings={len(findings)}, action={action}")
        return response

    except ValueError as e:
        logger.error(f"Validation error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Analysis error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal analysis error")


# ── Structured Log Ingestion Endpoints ────────────────────────────────────────


@router.post(
    "/logs",
    response_model=StructuredLogsResponse,
    dependencies=[Depends(verify_api_key), Depends(check_rate_limit)]
)
async def ingest_logs(request: IngestLogsRequest) -> StructuredLogsResponse:
    """
    Ingest raw or structured logs.
    Accepts raw text (auto-parsed), pre-structured JSON logs, or both.
    Returns structured logs with ingestion statistics.
    """
    try:
        logger.info("━━━ Log Ingestion Request ━━━")

        all_valid_logs: list[StructuredLog] = []
        all_warnings: list[str] = []
        total_parse_errors = 0

        # ── Handle pre-structured logs ────────────────────────────────────
        if request.logs:
            logger.info(f"Received {len(request.logs)} pre-structured logs")
            all_valid_logs.extend(request.logs)

        # ── Handle raw content ────────────────────────────────────────────
        if request.raw_content:
            logger.info(f"Parsing raw content: {len(request.raw_content)} chars")

            # Parse raw text into dictionaries
            parsed_dicts, parse_warnings = parse_raw_logs(request.raw_content)
            all_warnings.extend(parse_warnings)

            # Validate through Pydantic
            valid_logs, validation_errors = validate_batch(parsed_dicts)
            all_valid_logs.extend(valid_logs)
            total_parse_errors += len(validation_errors)
            all_warnings.extend(validation_errors)

            logger.info(
                f"Raw content parsed: {len(valid_logs)} valid, "
                f"{len(validation_errors)} errors"
            )

        # ── Reject empty requests ─────────────────────────────────────────
        if not request.logs and not request.raw_content:
            raise ValueError(
                "At least one of 'raw_content' or 'logs' must be provided"
            )

        # ── Store in memory ───────────────────────────────────────────────
        _structured_log_store.extend(all_valid_logs)
        logger.info(
            f"━━━ Ingestion Complete ━━━ "
            f"stored={len(all_valid_logs)}, errors={total_parse_errors}, "
            f"total_in_store={len(_structured_log_store)}"
        )

        return StructuredLogsResponse(
            logs=all_valid_logs,
            total=len(all_valid_logs),
            parse_errors=total_parse_errors,
            parse_warnings=all_warnings[:20],  # Cap warnings at 20
        )

    except ValueError as e:
        logger.error(f"Ingestion validation error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Ingestion error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal ingestion error")


@router.get(
    "/logs",
    response_model=StructuredLogsResponse,
    dependencies=[Depends(verify_api_key), Depends(check_rate_limit)]
)
async def get_logs(
    level: Optional[str] = Query(None, description="Filter by log level (INFO, WARNING, ERROR, CRITICAL)"),
    service: Optional[str] = Query(None, description="Filter by service name"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of logs to return"),
) -> StructuredLogsResponse:
    """
    Retrieve stored structured logs with optional filters.
    Returns only structured, validated log entries.
    """
    logger.info(f"GET /logs — level={level}, service={service}, limit={limit}")

    filtered = _structured_log_store

    # ── Apply filters ─────────────────────────────────────────────────────
    if level:
        level_upper = level.upper()
        filtered = [log for log in filtered if log.log_level == level_upper]

    if service:
        service_lower = service.lower()
        filtered = [log for log in filtered if log.service.lower() == service_lower]

    # ── Apply limit (most recent first) ───────────────────────────────────
    result_logs = filtered[-limit:]

    return StructuredLogsResponse(
        logs=result_logs,
        total=len(result_logs),
    )


# ── AI-Powered Analysis Endpoints ─────────────────────────────────────────────


class SingleLogRequest(BaseModel):
    """Request for single log analysis or classification."""
    log: str = Field(..., description="Single log line to analyze")


class BulkLogsRequest(BaseModel):
    """Request for bulk log summary."""
    logs: list[StructuredLog] | None = Field(
        default=None, description="Pre-structured logs to summarize"
    )
    raw_content: str | None = Field(
        default=None, description="Raw log text to parse and summarize"
    )


@router.post(
    "/ai/analyze-log",
    dependencies=[Depends(verify_api_key), Depends(check_rate_limit)]
)
async def ai_analyze_log(request: SingleLogRequest) -> dict:
    """
    AI-powered single log analysis.
    Returns explanation, issue type, severity, causes, and recommended actions.
    Uses LLM when available, falls back to deterministic rule-based analysis.
    """
    try:
        logger.info("━━━ AI Single Log Analysis ━━━")
        result = await prompt_service.analyze_single_log(request.log)
        logger.info(f"Analysis complete: severity={result.get('severity')}")
        return result
    except Exception as e:
        logger.error(f"AI analyze error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="AI analysis error")


@router.post(
    "/ai/summarize",
    dependencies=[Depends(verify_api_key), Depends(check_rate_limit)]
)
async def ai_summarize(request: BulkLogsRequest) -> dict:
    """
    AI-powered bulk log summary.
    Returns counts, key issues, anomalies, frequent errors, and health assessment.
    Accepts pre-structured logs or raw text (auto-parsed).
    """
    try:
        logger.info("━━━ AI Bulk Log Summary ━━━")

        structured_logs: list[StructuredLog] = []

        # Use pre-structured logs if provided
        if request.logs:
            structured_logs = request.logs

        # Parse raw content if provided
        elif request.raw_content:
            parsed_dicts, _ = parse_raw_logs(request.raw_content)
            valid_logs, _ = validate_batch(parsed_dicts)
            structured_logs = valid_logs

        # Fall back to stored logs
        elif _structured_log_store:
            structured_logs = _structured_log_store[-500:]  # Last 500

        if not structured_logs:
            raise ValueError("No logs available to summarize")

        result = await prompt_service.summarize_logs(structured_logs)
        logger.info(f"Summary complete: health={result.get('health')}")
        return result

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"AI summary error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="AI summary error")


@router.post(
    "/ai/classify",
    dependencies=[Depends(verify_api_key), Depends(check_rate_limit)]
)
async def ai_classify(request: SingleLogRequest) -> dict:
    """
    AI-powered log classification.
    Classifies as Normal, Suspicious, or Malicious with confidence score.
    """
    try:
        logger.info("━━━ AI Log Classification ━━━")
        result = await prompt_service.classify_log(request.log)
        logger.info(
            f"Classification: {result.get('classification')} "
            f"(confidence={result.get('confidence')}%)"
        )
        return result
    except Exception as e:
        logger.error(f"AI classify error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="AI classification error")
