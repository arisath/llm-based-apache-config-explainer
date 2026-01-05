import re

# Patterns intentionally broad — security > precision
PATTERNS = [
    # Credentials in URLs
    re.compile(r'(http[s]?://)([^:@/\s]+):([^@/\s]+)@', re.I),

    # SSL private keys / cert paths
    re.compile(r'^\s*SSLCertificate(Key)?File\s+\S+', re.I),
    re.compile(r'^\s*SSLCertificateChainFile\s+\S+', re.I),

    # Auth directives
    re.compile(r'^\s*AuthUserFile\s+\S+', re.I),
    re.compile(r'^\s*AuthGroupFile\s+\S+', re.I),

    # Proxy basic auth in config
    re.compile(r'^\s*ProxyPass\s+\S+\s+http[s]?://[^/\s]+@', re.I),

    # Environment variables that may contain secrets
    re.compile(r'\$\{[^}]*PASS[^}]*\}', re.I),
    re.compile(r'\$\{[^}]*KEY[^}]*\}', re.I),
]

REDACTION_TOKEN = "<REDACTED>"

def redact_line(line: str) -> str:
    redacted = line
    for pattern in PATTERNS:
        if pattern.search(redacted):
            redacted = pattern.sub(REDACTION_TOKEN, redacted)
    return redacted

def redact_directives(directives: list[str]) -> list[str]:
    return [redact_line(d) for d in directives]
