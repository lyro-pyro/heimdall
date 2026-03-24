"""
POST /analyze endpoint — orchestrates the full analysis pipeline.
Validate → Parse → Detect → Log Analyze → Risk → Policy → Insights → Response.
"""

from fastapi import APIRouter, HTTPException, Depends

from app.core.logging_config import logger
from app.models.schemas import AnalyzeRequest, AnalyzeResponse, Finding
from app.services.detector import Detector
from app.services.insight_engine import InsightEngine
from app.services.log_analyzer import LogAnalyzer
from app.services.parser import Parser
from app.services.policy_engine import PolicyEngine
from app.services.risk_engine import RiskEngine
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


@router.post(
    "/analyze", 
    response_model=AnalyzeResponse, 
    dependencies=[Depends(verify_api_key), Depends(check_rate_limit)]
)
async def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    """
    Main analysis endpoint.
    Accepts multi-source input and returns structured security analysis.
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
        )

        logger.info(f"━━━ Analysis Complete ━━━ findings={len(findings)}, action={action}")
        return response

    except ValueError as e:
        logger.error(f"Validation error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Analysis error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal analysis error")
