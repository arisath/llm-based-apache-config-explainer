from flask import Flask, request, jsonify
import re
import json

app = Flask(__name__)

# ---------------------------
# Regex patterns
# ---------------------------
RE_PROXYREQUESTS = re.compile(r'^\s*ProxyRequests\s+(\w+)', re.I | re.M)
RE_PROXYPASS = re.compile(r'^\s*ProxyPass\s+(\S+)\s+(\S+)', re.I | re.M)
RE_PROXYPASSREV = re.compile(r'^\s*ProxyPassReverse\s+(\S+)\s+(\S+)', re.I | re.M)
RE_PROXYPRESERVE = re.compile(r'^\s*ProxyPreserveHost\s+(\w+)', re.I | re.M)
RE_PROXY_BLOCK = re.compile(r'<Proxy\s+([^>]+)>', re.I)
RE_REQUIRE = re.compile(r'^\s*Require\s+(.+)', re.I | re.M)
RE_SERVERNAME = re.compile(r'^\s*ServerName\s+(\S+)', re.I | re.M)

PRIVATE_IP_RE = re.compile(
    r'http[s]?://('
    r'10\.|'
    r'192\.168\.|'
    r'172\.(1[6-9]|2[0-9]|3[0-1])\.|'
    r'127\.'
    r')',
    re.I
)

# ---------------------------
# Deterministic rule engine
# ---------------------------
def analyze_config(conf_text):
    findings = []

    # 1. Open proxy
    m = RE_PROXYREQUESTS.search(conf_text)
    if m and m.group(1).lower() == "on":
        findings.append({
            "id": "OPEN_PROXY",
            "severity": "high",
            "confidence": 0.99,
            "evidence": "ProxyRequests On",
            "description": "Apache is configured as a forward proxy, allowing arbitrary proxying."
        })

    # 2. ProxyPass to private IP
    for m in RE_PROXYPASS.finditer(conf_text):
        path, target = m.group(1), m.group(2)
        if PRIVATE_IP_RE.search(target):
            findings.append({
                "id": "INTERNAL_BACKEND_EXPOSED",
                "severity": "high",
                "confidence": 0.9,
                "evidence": f"ProxyPass {path} {target}",
                "description": "Reverse proxy forwards traffic to an internal/private backend."
            })

    # 3. Missing ProxyPassReverse
    proxy_pairs = set(RE_PROXYPASS.findall(conf_text))
    reverse_pairs = set(RE_PROXYPASSREV.findall(conf_text))
    for pair in proxy_pairs:
        if pair not in reverse_pairs:
            findings.append({
                "id": "MISSING_PROXYPASSREVERSE",
                "severity": "medium",
                "confidence": 0.7,
                "evidence": f"ProxyPass {pair[0]} {pair[1]}",
                "description": "ProxyPassReverse is missing for this backend mapping."
            })

    # 4. ProxyPreserveHost risk
    m = RE_PROXYPRESERVE.search(conf_text)
    if m and m.group(1).lower() == "on":
        findings.append({
            "id": "PROXY_PRESERVE_HOST",
            "severity": "medium",
            "confidence": 0.6,
            "evidence": "ProxyPreserveHost On",
            "description": "Backend will receive the original Host header."
        })

    # 5. Unrestricted <Proxy *>
    if RE_PROXY_BLOCK.search(conf_text):
        if not RE_REQUIRE.search(conf_text):
            findings.append({
                "id": "UNRESTRICTED_PROXY_BLOCK",
                "severity": "high",
                "confidence": 0.85,
                "evidence": "<Proxy *> without Require directive",
                "description": "Proxy access is not restricted by IP or authentication."
            })

    return findings

# ---------------------------
# LLM integration (stub)
# ---------------------------
def generate_llm_report(conf_text, findings):
    """
    Replace this stub with:
    - OpenAI
    - Azure OpenAI
    - Local LLM (llama.cpp, Ollama, etc.)
    """

    summary = (
        "This Apache configuration defines a reverse proxy that forwards client "
        "requests to one or more backend services. Based on the directives present, "
        "the proxy behavior may expose internal services or allow unintended proxy use."
    )

    remediations = []
    for f in findings:
        if f["id"] == "OPEN_PROXY":
            remediations.append(
                "Set `ProxyRequests Off` and restrict proxy access using `<Proxy *>` "
                "with `Require ip` or authentication."
            )
        elif f["id"] == "INTERNAL_BACKEND_EXPOSED":
            remediations.append(
                "Restrict access to the proxied path or require authentication. "
                "Ensure internal backends are not reachable by untrusted users."
            )
        elif f["id"] == "PROXY_PRESERVE_HOST":
            remediations.append(
                "Disable `ProxyPreserveHost` unless the backend explicitly requires it."
            )
        elif f["id"] == "MISSING_PROXYPASSREVERSE":
            remediations.append(
                "Add a corresponding `ProxyPassReverse` directive."
            )

    fixed_config_example = """
ProxyRequests Off

<Proxy *>
    Require ip 10.0.0.0/8
</Proxy>

ProxyPreserveHost Off
"""

    return {
        "summary": summary,
        "findings": findings,
        "remediations": remediations,
        "example_fixed_config": fixed_config_example.strip()
    }

# ---------------------------
# API endpoint
# ---------------------------
@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(force=True)
    conf_text = data.get("config", "")

    findings = analyze_config(conf_text)
    report = generate_llm_report(conf_text, findings)

    return jsonify(report)

# ---------------------------
# Run
# ---------------------------
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
