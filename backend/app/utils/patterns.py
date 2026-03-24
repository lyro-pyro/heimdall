"""
Compiled regex patterns for deterministic sensitive data detection.
All detection is pattern-based — no AI dependency for security-critical detections.
"""

import re

# ── Sensitive Data Patterns ──────────────────────────────────────────────────

EMAIL_PATTERN = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    re.IGNORECASE,
)

PHONE_PATTERN = re.compile(
    r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{4}",
)

API_KEY_PATTERN = re.compile(
    r"(?:"
    r"(?:api[_\-]?key|apikey|api_secret|access[_\-]?key)\s*[:=]\s*['\"]?[a-zA-Z0-9\-_]{8,}['\"]?"
    r"|AKIA[0-9A-Z]{16}"
    r"|sk-[a-zA-Z0-9\-]{8,}"
    r"|key-[a-zA-Z0-9\-]{8,}"
    r")",
    re.IGNORECASE,
)

PASSWORD_PATTERN = re.compile(
    r"(?:password|passwd|pwd|pass)\s*[:=]\s*['\"]?[^\s'\"]{4,}['\"]?",
    re.IGNORECASE,
)

TOKEN_PATTERN = re.compile(
    r"(?:"
    r"(?:token|auth_token|access_token|bearer|jwt)\s*[:=]\s*['\"]?[a-zA-Z0-9\-_.]{8,}['\"]?"
    r"|Bearer\s+[a-zA-Z0-9\-_.]+(?:\.[a-zA-Z0-9\-_.]+){1,}"
    r")",
    re.IGNORECASE,
)

SECRET_PATTERN = re.compile(
    r"(?:secret|client_secret|app_secret|private_key)\s*[:=]\s*['\"]?[a-zA-Z0-9\-_/+=]{8,}['\"]?",
    re.IGNORECASE,
)

# ── Security Issue Patterns ──────────────────────────────────────────────────

STACK_TRACE_PATTERN = re.compile(
    r"(?:Traceback \(most recent call last\)|at\s+\S+:\d+|at\s+\S+\.\S+\(.*:\d+\)|Exception in thread|"
    r"^\s+File\s+\".*\",\s+line\s+\d+|java\.\w+\..*Exception|"
    r"panic:|runtime error:)",
    re.MULTILINE,
)

DEBUG_MODE_PATTERN = re.compile(
    r"(?:DEBUG\s*[:=]\s*(?:true|1|on|yes|enabled)|debug\s+mode\s+(?:is\s+)?(?:on|enabled|active)|DEBUG\s+stack\s+trace)",
    re.IGNORECASE,
)

HARDCODED_CREDENTIAL_PATTERN = re.compile(
    r"(?:root:.*@|admin:.*@|mysql://\w+:\w+@|postgres://\w+:\w+@|mongodb://\w+:\w+@|"
    r"redis://:\w+@|ftp://\w+:\w+@)",
    re.IGNORECASE,
)

# ── Log Analysis Patterns ────────────────────────────────────────────────────

FAILED_LOGIN_PATTERN = re.compile(
    r"(?:failed\s+(?:login|auth(?:entication)?|sign[\s-]?in)|"
    r"invalid\s+(?:credentials?|password|username)|"
    r"(?:login|auth)\s+(?:fail(?:ure|ed)?|denied|rejected)|"
    r"access\s+denied|unauthorized\s+access|"
    r"401\s+unauthorized)",
    re.IGNORECASE,
)

IP_ADDRESS_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
)

SUSPICIOUS_IP_INDICATORS = re.compile(
    r"(?:blocked|banned|blacklisted|malicious|suspicious)\s+(?:ip|address|host)",
    re.IGNORECASE,
)

ERROR_LEAK_PATTERN = re.compile(
    r"(?:internal\s+server\s+error|sql\s+syntax\s+error|"
    r"undefined\s+(?:variable|method|function)|"
    r"null\s*pointer|segmentation\s+fault|"
    r"unhandled\s+exception|fatal\s+error|"
    r"errno|stacktrace|core\s+dump)",
    re.IGNORECASE,
)

SQL_INJECTION_PATTERN = re.compile(
    r"(?:'\s*(?:OR|AND)\s+['\d]|--\s*$|;\s*DROP\s+TABLE|"
    r"UNION\s+(?:ALL\s+)?SELECT|/\*.*\*/|"
    r"(?:exec|execute)\s*\(|xp_cmdshell)",
    re.IGNORECASE,
)

# ── Detection Registry ──────────────────────────────────────────────────────

SENSITIVE_PATTERNS = {
    "email": EMAIL_PATTERN,
    "phone": PHONE_PATTERN,
    "api_key": API_KEY_PATTERN,
    "password": PASSWORD_PATTERN,
    "token": TOKEN_PATTERN,
    "secret": SECRET_PATTERN,
}

SECURITY_PATTERNS = {
    "stack_trace": STACK_TRACE_PATTERN,
    "debug_leak": DEBUG_MODE_PATTERN,
    "hardcoded_credential": HARDCODED_CREDENTIAL_PATTERN,
    "error_leak": ERROR_LEAK_PATTERN,
    "sql_injection": SQL_INJECTION_PATTERN,
}

LOG_PATTERNS = {
    "failed_login": FAILED_LOGIN_PATTERN,
    "suspicious_ip": SUSPICIOUS_IP_INDICATORS,
}

# ── Risk Mapping ─────────────────────────────────────────────────────────────

RISK_MAP: dict[str, str] = {
    "api_key": "high",
    "password": "critical",
    "token": "high",
    "email": "low",
    "phone": "low",
    "secret": "critical",
    "stack_trace": "medium",
    "debug_leak": "medium",
    "hardcoded_credential": "critical",
    "error_leak": "medium",
    "sql_injection": "high",
    "failed_login": "medium",
    "suspicious_ip": "high",
    "brute_force": "critical",
    "high_entropy_string": "high",
    "anomalous_ip_volume": "high",
}

# ── MITRE ATT&CK Mapping ─────────────────────────────────────────────────────

MITRE_MAP: dict[str, dict[str, str]] = {
    "api_key": {"tactic": "Credential Access", "technique": "T1552: Unsecured Credentials"},
    "password": {"tactic": "Credential Access", "technique": "T1552: Unsecured Credentials"},
    "token": {"tactic": "Credential Access", "technique": "T1552: Unsecured Credentials"},
    "secret": {"tactic": "Credential Access", "technique": "T1552: Unsecured Credentials"},
    "email": {"tactic": "Reconnaissance", "technique": "T1589: Gather Victim Identity Information"},
    "phone": {"tactic": "Reconnaissance", "technique": "T1589: Gather Victim Identity Information"},
    "stack_trace": {"tactic": "Discovery", "technique": "T1082: System Information Discovery"},
    "debug_leak": {"tactic": "Discovery", "technique": "T1082: System Information Discovery"},
    "hardcoded_credential": {"tactic": "Credential Access", "technique": "T1552: Unsecured Credentials"},
    "error_leak": {"tactic": "Discovery", "technique": "T1082: System Information Discovery"},
    "sql_injection": {"tactic": "Initial Access", "technique": "T1190: Exploit Public-Facing Application"},
    "failed_login": {"tactic": "Credential Access", "technique": "T1110: Brute Force"},
    "suspicious_ip": {"tactic": "Command and Control", "technique": "T1008: Fallback Channels"},
    "brute_force": {"tactic": "Credential Access", "technique": "T1110: Brute Force"},
    "high_entropy_string": {"tactic": "Defense Evasion", "technique": "T1140: Deobfuscate/Decode Files or Information"},
    "anomalous_ip_volume": {"tactic": "Impact", "technique": "T1498: Network Denial of Service"}
}
