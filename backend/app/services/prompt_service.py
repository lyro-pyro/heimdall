"""
AI Prompt Service — structured prompt templates for LLM-powered log analysis.

Three analysis modes:
  1. Single Log Analysis — explain, classify, suggest fixes
  2. Bulk Log Summary — aggregate stats, anomalies, health assessment
  3. Log Classification — Normal / Suspicious / Malicious with confidence

Each mode has a carefully crafted prompt template and a deterministic
fallback that runs when the LLM is unavailable.
"""

import json
import re
from collections import Counter
from typing import Optional

from app.core.logging_config import logger
from app.models.schemas import StructuredLog
from app.services.ai_client import AIClient
from app.utils.patterns import (
    FAILED_LOGIN_PATTERN, IP_ADDRESS_PATTERN, SQL_INJECTION_PATTERN,
    API_KEY_PATTERN, PASSWORD_PATTERN, TOKEN_PATTERN,
)


# ── Prompt Templates ─────────────────────────────────────────────────────────

SINGLE_LOG_PROMPT = """You are a cybersecurity expert and log analyst.

Analyze the following system log and provide:
1. A clear explanation in simple English
2. The type of issue (e.g., authentication failure, network issue, system error)
3. Severity level (Low, Medium, High, Critical)
4. Possible causes
5. Recommended actions to fix or mitigate the issue

Log:
{log}

Keep the explanation concise but informative.
Avoid technical jargon unless necessary.

Respond in this exact JSON format:
{{"explanation": "...", "issue_type": "...", "severity": "...", "causes": ["..."], "actions": ["..."]}}"""

BULK_SUMMARY_PROMPT = """You are an AI system designed to analyze large-scale system logs.

Given the following logs, generate a structured summary including:
1. Total number of logs
2. Number of errors, warnings, and info messages
3. Key issues detected
4. Any suspicious patterns or anomalies
5. Most frequent error types
6. Overall system health assessment (Good, Moderate, Critical)

Logs:
{logs}

Return the output in clean bullet points.
Be precise and avoid unnecessary explanations.

Respond in this exact JSON format:
{{"total_logs": 0, "errors": 0, "warnings": 0, "info": 0, "key_issues": ["..."], "anomalies": ["..."], "frequent_errors": ["..."], "health": "..."}}"""

CLASSIFICATION_PROMPT = """You are a cybersecurity classification model.

Classify the following log into one of:
- Normal
- Suspicious
- Malicious

Also provide:
1. Confidence level (0–100%)
2. Reason for classification

Log:
{log}

Be cautious and avoid false positives.

Respond in this exact JSON format:
{{"classification": "Normal|Suspicious|Malicious", "confidence": 0, "reason": "..."}}"""


class PromptService:
    """
    AI-powered log analysis using structured prompt templates.
    Falls back to deterministic rule-based analysis when the LLM is unavailable.
    """

    def __init__(self):
        self.ai_client = AIClient()

    # ── Single Log Analysis ──────────────────────────────────────────────

    async def analyze_single_log(self, log: str) -> dict:
        """
        Analyze a single log line: explain, classify issue type, severity,
        causes, and recommended actions.
        """
        logger.info(f"Prompt service: analyzing single log ({len(log)} chars)")

        # Try AI-enhanced analysis
        try:
            prompt = SINGLE_LOG_PROMPT.format(log=log)
            response = await self.ai_client.generate(prompt)
            if response:
                parsed = self._parse_json_response(response)
                if parsed and "explanation" in parsed:
                    logger.info("AI-generated single log analysis successful")
                    return parsed
        except Exception as e:
            logger.warning(f"AI single log analysis failed: {e}")

        # Fallback: deterministic analysis
        return self._fallback_single_log(log)

    def _fallback_single_log(self, log: str) -> dict:
        """Rule-based single log analysis fallback."""
        log_lower = log.lower()

        # Detect issue type and severity
        issue_type = "general log entry"
        severity = "Low"
        causes = []
        actions = []
        explanation = "Standard log entry with no detected security issues."

        # Authentication failures
        if FAILED_LOGIN_PATTERN.search(log):
            issue_type = "authentication failure"
            severity = "High"
            explanation = "This log indicates a failed authentication attempt, which may signal unauthorized access attempts or credential compromise."
            causes = [
                "Incorrect username or password",
                "Expired or revoked credentials",
                "Brute-force attack in progress",
                "Account lockout due to repeated failures",
            ]
            actions = [
                "Verify if the user account exists and is active",
                "Check for multiple failed attempts from the same IP (brute-force)",
                "Implement account lockout policies",
                "Enable multi-factor authentication",
                "Review and update password policies",
            ]

        # SQL injection
        elif SQL_INJECTION_PATTERN.search(log):
            issue_type = "SQL injection attempt"
            severity = "Critical"
            explanation = "This log contains patterns indicative of a SQL injection attack, where an attacker attempts to manipulate database queries through malicious input."
            causes = [
                "Unvalidated user input in SQL queries",
                "Missing parameterized query usage",
                "Automated vulnerability scanner targeting the application",
            ]
            actions = [
                "Use parameterized queries or prepared statements immediately",
                "Block the source IP address",
                "Review and sanitize all user input paths",
                "Deploy a Web Application Firewall (WAF)",
                "Conduct a security audit of database access code",
            ]

        # Credential exposure
        elif PASSWORD_PATTERN.search(log) or API_KEY_PATTERN.search(log) or TOKEN_PATTERN.search(log):
            issue_type = "credential exposure"
            severity = "Critical"
            explanation = "This log contains exposed credentials (passwords, API keys, or tokens) which could be exploited by attackers to gain unauthorized access."
            causes = [
                "Credentials hardcoded in application code or config",
                "Logging verbosity set too high in production",
                "Misconfigured log sanitization filters",
            ]
            actions = [
                "Rotate all exposed credentials immediately",
                "Remove credentials from log output",
                "Use a secrets manager (e.g., HashiCorp Vault, AWS Secrets Manager)",
                "Audit logging configuration to prevent credential leaks",
            ]

        # Error patterns
        elif any(kw in log_lower for kw in ("error", "exception", "fatal", "crash", "panic")):
            issue_type = "system error"
            severity = "Medium"
            explanation = "This log records a system error or exception that may affect application stability or availability."
            causes = [
                "Unhandled exception in application code",
                "Resource exhaustion (memory, connections, disk)",
                "External dependency failure",
            ]
            actions = [
                "Review the stack trace or error details for root cause",
                "Check system resource utilization",
                "Verify external service connectivity",
                "Implement proper error handling and retry logic",
            ]

        # Warning patterns
        elif any(kw in log_lower for kw in ("warning", "warn", "timeout", "slow", "retry")):
            issue_type = "performance warning"
            severity = "Medium"
            explanation = "This log indicates a performance issue or transient failure that may degrade user experience if not addressed."
            causes = [
                "Slow database queries or network latency",
                "Resource contention under load",
                "Transient network failures",
            ]
            actions = [
                "Monitor for recurring patterns",
                "Optimize slow queries or operations",
                "Scale resources if under sustained load",
            ]

        # Suspicious IP
        elif any(kw in log_lower for kw in ("suspicious", "blocked", "denied", "unauthorized")):
            issue_type = "suspicious activity"
            severity = "High"
            explanation = "This log flags suspicious activity, potentially indicating an intrusion attempt or policy violation."
            causes = [
                "Unauthorized access attempt from external source",
                "Policy violation by internal user",
                "Automated attack or scanning activity",
            ]
            actions = [
                "Investigate the source IP address",
                "Review access control policies",
                "Enable additional monitoring and alerting",
                "Consider IP blocking if pattern persists",
            ]

        return {
            "explanation": explanation,
            "issue_type": issue_type,
            "severity": severity,
            "causes": causes if causes else ["No specific cause identified"],
            "actions": actions if actions else ["Continue monitoring; no immediate action required"],
        }

    # ── Bulk Log Summary ─────────────────────────────────────────────────

    async def summarize_logs(self, logs: list[StructuredLog]) -> dict:
        """
        Generate a structured summary of multiple log entries:
        counts, issues, anomalies, health assessment.
        """
        logger.info(f"Prompt service: summarizing {len(logs)} logs")

        # Try AI-enhanced summary (only for manageable sizes)
        if len(logs) <= 100:
            try:
                logs_text = "\n".join(
                    f"[{l.timestamp}] {l.log_level} [{l.service}] {l.message}"
                    for l in logs
                )
                prompt = BULK_SUMMARY_PROMPT.format(logs=logs_text)
                response = await self.ai_client.generate(prompt)
                if response:
                    parsed = self._parse_json_response(response)
                    if parsed and "health" in parsed:
                        logger.info("AI-generated bulk summary successful")
                        return parsed
            except Exception as e:
                logger.warning(f"AI bulk summary failed: {e}")

        # Fallback: deterministic summary
        return self._fallback_summary(logs)

    def _fallback_summary(self, logs: list[StructuredLog]) -> dict:
        """Rule-based bulk log summary fallback."""
        total = len(logs)
        level_counts = Counter(l.log_level for l in logs)

        errors = level_counts.get("ERROR", 0) + level_counts.get("CRITICAL", 0)
        warnings = level_counts.get("WARNING", 0)
        info = level_counts.get("INFO", 0)

        # Detect key issues
        key_issues = []
        anomalies = []
        error_messages = []

        service_error_counts = Counter()
        ip_counts = Counter()

        for log in logs:
            msg_lower = log.message.lower()

            if log.log_level in ("ERROR", "CRITICAL"):
                error_messages.append(log.message[:80])
                service_error_counts[log.service] += 1

            if FAILED_LOGIN_PATTERN.search(log.message):
                key_issues.append("Failed authentication attempts detected")

            if PASSWORD_PATTERN.search(log.message) or API_KEY_PATTERN.search(log.message):
                key_issues.append("Credential exposure in log output")

            if SQL_INJECTION_PATTERN.search(log.message):
                key_issues.append("SQL injection patterns detected")

            # Extract IPs for anomaly detection
            ips = IP_ADDRESS_PATTERN.findall(log.message)
            for ip in ips:
                ip_counts[ip] += 1

        # Deduplicate issues
        key_issues = list(dict.fromkeys(key_issues))

        # Find frequent error types
        error_type_counts = Counter(msg[:50] for msg in error_messages)
        frequent_errors = [
            f"{msg} (x{count})" for msg, count in error_type_counts.most_common(5)
        ]

        # Anomaly detection
        for ip, count in ip_counts.most_common(3):
            if count >= 5:
                anomalies.append(f"IP {ip} appears {count} times — potential scanning or brute-force")

        for service, err_count in service_error_counts.most_common(3):
            if err_count >= 3:
                anomalies.append(f"Service '{service}' has {err_count} errors — may need attention")

        # Health assessment
        error_ratio = errors / total if total > 0 else 0
        if error_ratio > 0.3 or any("Critical" in i for i in key_issues):
            health = "Critical"
        elif error_ratio > 0.1 or warnings > total * 0.25:
            health = "Moderate"
        else:
            health = "Good"

        return {
            "total_logs": total,
            "errors": errors,
            "warnings": warnings,
            "info": info,
            "key_issues": key_issues if key_issues else ["No critical issues detected"],
            "anomalies": anomalies if anomalies else ["No anomalies detected"],
            "frequent_errors": frequent_errors if frequent_errors else ["None"],
            "health": health,
        }

    # ── Log Classification ───────────────────────────────────────────────

    async def classify_log(self, log: str) -> dict:
        """
        Classify a single log as Normal, Suspicious, or Malicious
        with a confidence score and reason.
        """
        logger.info(f"Prompt service: classifying log ({len(log)} chars)")

        # Try AI-enhanced classification
        try:
            prompt = CLASSIFICATION_PROMPT.format(log=log)
            response = await self.ai_client.generate(prompt)
            if response:
                parsed = self._parse_json_response(response)
                if parsed and "classification" in parsed:
                    logger.info("AI-generated classification successful")
                    return parsed
        except Exception as e:
            logger.warning(f"AI classification failed: {e}")

        # Fallback: deterministic classification
        return self._fallback_classify(log)

    def _fallback_classify(self, log: str) -> dict:
        """Rule-based log classification fallback."""
        log_lower = log.lower()
        score = 0
        reasons = []

        # Malicious indicators (+30-50 each)
        if SQL_INJECTION_PATTERN.search(log):
            score += 50
            reasons.append("SQL injection pattern detected")

        if re.search(r"(?:;\s*(?:rm|cat|wget|curl)\s|`[^`]+`|\$\([^)]+\))", log):
            score += 50
            reasons.append("Command injection pattern detected")

        if re.search(r"<script[^>]*>", log, re.IGNORECASE):
            score += 40
            reasons.append("XSS script injection detected")

        # Suspicious indicators (+15-25 each)
        if FAILED_LOGIN_PATTERN.search(log):
            score += 20
            reasons.append("Failed authentication attempt")

        if PASSWORD_PATTERN.search(log) or API_KEY_PATTERN.search(log) or TOKEN_PATTERN.search(log):
            score += 25
            reasons.append("Credential or secret exposure detected")

        if any(kw in log_lower for kw in ("unauthorized", "forbidden", "denied", "blocked")):
            score += 15
            reasons.append("Access denial indicator")

        if any(kw in log_lower for kw in ("suspicious", "malicious", "exploit", "attack")):
            score += 20
            reasons.append("Threat keyword detected in log message")

        if re.search(r"(?:\.\.\/|\.\.\\|%2e%2e)", log, re.IGNORECASE):
            score += 30
            reasons.append("Path traversal attempt detected")

        # Classify based on accumulated score
        if score >= 40:
            classification = "Malicious"
            confidence = min(95, 60 + score)
        elif score >= 15:
            classification = "Suspicious"
            confidence = min(85, 40 + score * 2)
        else:
            classification = "Normal"
            confidence = max(70, 95 - score * 5)
            reasons = ["No malicious or suspicious patterns detected"]

        return {
            "classification": classification,
            "confidence": confidence,
            "reason": "; ".join(reasons),
        }

    # ── Helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _parse_json_response(response: str) -> Optional[dict]:
        """Extract and parse JSON from an LLM response string."""
        try:
            start = response.find("{")
            end = response.rfind("}") + 1
            if start >= 0 and end > start:
                return json.loads(response[start:end])
        except (json.JSONDecodeError, Exception):
            pass
        return None
