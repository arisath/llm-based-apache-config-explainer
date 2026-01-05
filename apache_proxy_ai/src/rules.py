import re
from schema import Severity, FindingType

PRIVATE_IP_RE = re.compile(
    r'http[s]?://('
    r'127\.|'
    r'10\.|'
    r'192\.168\.|'
    r'172\.(1[6-9]|2[0-9]|3[0-1])\.'
    r')',
    re.I
)

def run_rules(chunk: dict) -> list[dict]:
    findings = []
    directives = chunk["directives"]

    # Rule: Open forward proxy
    for d in directives:
        if d.lower() == "proxyrequests on":
            findings.append(_finding(
                rule_id="OPEN_PROXY",
                severity=Severity.CRITICAL,
                ftype=FindingType.EXPOSURE,
                evidence=[d],
                explanation="Apache is configured as an open forward proxy.",
                impact="Allows arbitrary proxying, anonymization, and access to internal networks.",
                recommendation="Set ProxyRequests Off and restrict <Proxy *> access."
            ))

    # Rule: Reverse proxy to private/internal backend
    for d in directives:
        if d.lower().startswith("proxypass") and PRIVATE_IP_RE.search(d):
            findings.append(_finding(
                rule_id="INTERNAL_BACKEND_EXPOSED",
                severity=Severity.HIGH,
                ftype=FindingType.EXPOSURE,
                evidence=[d],
                explanation="Reverse proxy forwards traffic to an internal/private backend.",
                impact="External users may access internal-only services.",
                recommendation="Restrict access, require authentication, or isolate the backend."
            ))

    # Rule: ProxyPreserveHost risk
    for d in directives:
        if d.lower() == "proxypreservehost on":
            findings.append(_finding(
                rule_id="PROXY_PRESERVE_HOST",
                severity=Severity.MEDIUM,
                ftype=FindingType.RISKY_DEFAULT,
                evidence=[d],
                explanation="Original Host header is forwarded to the backend.",
                impact="Host header trust issues may enable routing or auth bypass.",
                recommendation="Disable unless explicitly required by the backend."
            ))

    # Rule: AllowOverride All
    for d in directives:
        if d.lower() == "allowoverride all":
            findings.append(_finding(
                rule_id="ALLOWOVERRIDE_ALL",
                severity=Severity.MEDIUM,
                ftype=FindingType.RISKY_DEFAULT,
                evidence=[d],
                explanation="All directives can be overridden via .htaccess.",
                impact="Expands attack surface and weakens central policy enforcement.",
                recommendation="Limit AllowOverride to required directive classes."
            ))

    # Rule: Require all granted
    for d in directives:
        if d.lower() == "require all granted":
            findings.append(_finding(
                rule_id="UNRESTRICTED_ACCESS",
                severity=Severity.MEDIUM,
                ftype=FindingType.MISCONFIGURATION,
                evidence=[d],
                explanation="No access control restrictions are applied.",
                impact="All clients can access the resource.",
                recommendation="Apply IP or authentication-based restrictions where appropriate."
            ))

    return findings


def _finding(rule_id, severity, ftype, evidence, explanation, impact, recommendation):
    return {
        "id": rule_id,
        "type": ftype.value,
        "severity": severity.value,
        "confidence": 0.95,
        "evidence": evidence,
        "explanation": explanation,
        "impact": impact,
        "recommendation": recommendation
    }
