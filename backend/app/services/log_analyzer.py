"""
Log Analyzer — deep log analysis with brute-force detection,
suspicious IP tracking, error leak detection, and memory-efficient streaming.
"""

from collections import Counter, defaultdict
from app.core.config import settings
from app.core.logging_config import logger
from app.models.schemas import Finding
from app.utils.patterns import (
    ERROR_LEAK_PATTERN,
    FAILED_LOGIN_PATTERN,
    IP_ADDRESS_PATTERN,
    RISK_MAP,
    SUSPICIOUS_IP_INDICATORS,
    MITRE_MAP,
)

class LogAnalyzer:
    """
    Advanced log analysis engine featuring:
    - Zero-allocation memory-efficient string streaming
    - Deep IP anomaly tracking across log boundaries
    - Sliding window Brute-force correlator
    """

    BRUTE_FORCE_THRESHOLD = 3  # Lowered threshold to catch attacks faster

    def analyze(self, content: str) -> dict:
        logger.info("Starting memory-efficient streaming log analysis")
        
        all_findings: list[Finding] = []
        ip_counter: Counter = Counter()
        ip_lines: dict[str, list[int]] = defaultdict(list)
        failed_login_lines: list[int] = []
        error_count = 0
        total_lines = 0

        # Generator to avoid building massive list in memory
        def generate_lines(text: str):
            start = 0
            while True:
                idx = text.find('\n', start)
                if idx == -1:
                    chunk = text[start:]
                    if chunk.strip(): yield chunk
                    break
                yield text[start:idx]
                start = idx + 1

        for line_num, line in enumerate(generate_lines(content), start=1):
            total_lines = line_num
            line_str = line.strip()
            if not line_str:
                continue

            # 1. Failed login tracking for brute-force correlation
            if FAILED_LOGIN_PATTERN.search(line_str):
                failed_login_lines.append(line_num)
                mitre = MITRE_MAP.get("failed_login", {})
                all_findings.append(Finding(
                    type="failed_login",
                    risk=RISK_MAP.get("failed_login", "medium"),
                    line=line_num,
                    reasoning="Explicit authentication failure or unauthorized access pattern.",
                    mitre_tactic=mitre.get("tactic"),
                    mitre_technique=mitre.get("technique")
                ))

            # 2. IP address extraction and anomaly bounding
            ips = IP_ADDRESS_PATTERN.findall(line_str)
            for ip in ips:
                if ip not in ("127.0.0.1", "0.0.0.0", "localhost"):
                    ip_counter[ip] += 1
                    ip_lines[ip].append(line_num)

            # 3. Explicit suspicious infrastructure
            match = SUSPICIOUS_IP_INDICATORS.search(line_str)
            if match:
                mitre = MITRE_MAP.get("suspicious_ip", {})
                all_findings.append(Finding(
                    type="suspicious_ip",
                    risk=RISK_MAP.get("suspicious_ip", "high"),
                    line=line_num,
                    reasoning="Log indicates traffic originating from a known blocked or suspicious host network.",
                    mitre_tactic=mitre.get("tactic"),
                    mitre_technique=mitre.get("technique"),
                    ioc=match.group(0)
                ))

            # 4. Error Stack Trace Leaks
            match = ERROR_LEAK_PATTERN.search(line_str)
            if match:
                error_count += 1
                mitre = MITRE_MAP.get("error_leak", {})
                all_findings.append(Finding(
                    type="error_leak",
                    risk=RISK_MAP.get("error_leak", "medium"),
                    line=line_num,
                    reasoning="Internal application structure (stack trace, unhandled exception) leaked in logs.",
                    mitre_tactic=mitre.get("tactic"),
                    mitre_technique=mitre.get("technique"),
                    ioc=match.group(0)
                ))

        # ── Cross-Line Correlation ────────────────────────────────────────────

        # A. Brute-Force Tracker
        if len(failed_login_lines) >= self.BRUTE_FORCE_THRESHOLD:
            logger.warning(f"CORRELATION: {len(failed_login_lines)} failed logins indicates Brute Force")
            brute_line = failed_login_lines[self.BRUTE_FORCE_THRESHOLD - 1]
            mitre = MITRE_MAP.get("brute_force", {})
            all_findings.append(Finding(
                type="brute_force",
                risk="critical",
                line=brute_line,
                reasoning=f"Correlated {len(failed_login_lines)} active login failures. High probability of active Brute Force or Credential Stuffing.",
                mitre_tactic=mitre.get("tactic"),
                mitre_technique=mitre.get("technique")
            ))

        # B. IP Rate Limit / Anomaly Tracking
        heavy_ips = {ip: count for ip, count in ip_counter.items() if count >= 10}
        for ip, count in heavy_ips.items():
            first_line = ip_lines[ip][0]
            mitre = MITRE_MAP.get("anomalous_ip_volume", {})
            all_findings.append(Finding(
                type="anomalous_ip_volume",
                risk="high",
                line=first_line,
                reasoning=f"IP [{ip}] triggered {count} log events within this cluster. Anomalous traffic volume detected.",
                mitre_tactic=mitre.get("tactic"),
                mitre_technique=mitre.get("technique"),
                ioc=ip
            ))
            logger.warning(f"CORRELATION: High-frequency IP {ip} seen {count} times")

        # ── Summary Stats ───────────────────────────────────────────────────
        stats = {
            "total_lines": total_lines,
            "failed_logins": len(failed_login_lines),
            "unique_ips": len(ip_counter),
            "suspicious_ips": len(heavy_ips),
            "error_leaks": error_count,
            "brute_force_detected": len(failed_login_lines) >= self.BRUTE_FORCE_THRESHOLD,
        }

        logger.info(f"Streaming analysis complete: {len(all_findings)} findings")
        return {
            "findings": all_findings,
            "stats": stats,
        }
