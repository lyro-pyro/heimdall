"""
Detector service — deterministic regex-based sensitive data and security issue detection.
Now includes Shannon Entropy logic for catching obfuscated secrets and encoded tokens.
"""

import math
from collections import Counter
from app.core.logging_config import logger
from app.models.schemas import Finding
from app.utils.patterns import (
    RISK_MAP,
    SECURITY_PATTERNS,
    SENSITIVE_PATTERNS,
    MITRE_MAP,
)

class Detector:
    """
    Deterministic detection engine.
    Produces Finding objects with type, risk, line number, and reasoning.
    """

    def detect(self, content: str) -> list[Finding]:
        logger.info("Starting deterministic detection scan with entropy analysis")
        findings: list[Finding] = []
        lines = content.split("\n")

        for line_num, line in enumerate(lines, start=1):
            if not line.strip():
                continue

            # 1. Check sensitive data patterns
            for pattern_name, pattern in SENSITIVE_PATTERNS.items():
                match = pattern.search(line)
                if match:
                    risk = RISK_MAP.get(pattern_name, "medium")
                    mitre = MITRE_MAP.get(pattern_name, {})
                    finding = Finding(
                        type=pattern_name, 
                        risk=risk, 
                        line=line_num,
                        reasoning=f"Matched known rigorous regex pattern for {pattern_name}.",
                        mitre_tactic=mitre.get("tactic"),
                        mitre_technique=mitre.get("technique"),
                        ioc=match.group(0)
                    )
                    if not self._is_duplicate(findings, finding):
                        findings.append(finding)

            # 2. Check security issue patterns
            for pattern_name, pattern in SECURITY_PATTERNS.items():
                match = pattern.search(line)
                if match:
                    risk = RISK_MAP.get(pattern_name, "medium")
                    mitre = MITRE_MAP.get(pattern_name, {})
                    finding = Finding(
                        type=pattern_name, 
                        risk=risk, 
                        line=line_num,
                        reasoning=f"Identified clear security misconfiguration or leak: {pattern_name}.",
                        mitre_tactic=mitre.get("tactic"),
                        mitre_technique=mitre.get("technique"),
                        ioc=match.group(0)
                    )
                    if not self._is_duplicate(findings, finding):
                        findings.append(finding)

            # 3. High Entropy Detection (Base64, Obfuscated Tokens)
            for word in line.split():
                # Clean word of punctuation that might skew entropy
                clean_word = word.strip("'\":;,.[]{}()<>")
                # Only analyze words long enough to be an obfuscated secret
                if len(clean_word) > 20:  
                    entropy = self._calculate_entropy(clean_word)
                    if entropy >= 4.5:
                        mitre = MITRE_MAP.get("high_entropy_string", {})
                        finding = Finding(
                            type="high_entropy_string",
                            risk="high",
                            line=line_num,
                            reasoning=f"High Shannon entropy ({entropy:.2f}) indicates potential obfuscated secret, base64 data, or JWT token.",
                            mitre_tactic=mitre.get("tactic"),
                            mitre_technique=mitre.get("technique"),
                            ioc=clean_word
                        )
                        if not self._is_duplicate(findings, finding):
                            findings.append(finding)

        logger.info(f"Detection complete: {len(findings)} findings")
        return findings

    @staticmethod
    def _calculate_entropy(data: str) -> float:
        """Calculates Shannon Entropy for a given string."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        for count in Counter(data).values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _is_duplicate(findings: list[Finding], new_finding: Finding) -> bool:
        """Check if this exact finding already exists."""
        return any(
            f.type == new_finding.type
            and f.line == new_finding.line
            for f in findings
        )
