# Apache Reverse Proxy LLM Analyzer

**A tool to analyze Apache HTTPD reverse proxy configurations using a local LLM (Ollama) and produce human-readable reports of allowed behaviors, misconfigurations, and potential security risks.**

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [Notes](#notes)

---

## Overview

This project provides a **deterministic, explainable security analysis** of Apache HTTPD reverse proxy configurations.

Given configuration files (`httpd.conf`, `sites-enabled`, `.htaccess`), the tool:

1. Extracts and chunks relevant directives.
2. Redacts sensitive information (passwords, keys).
3. Sends chunks to a local Ollama LLM for analysis.
4. Produces a **validated JSON output** with `allowed_behavior` and detailed findings.
5. Converts JSON into **human-readable reports**, highlighting misconfigurations and potential vulnerabilities.

The tool emphasizes:

- **Prompt grounding** for deterministic outputs.
- **Schema validation** to guarantee consistent JSON.
- **Post-processing safety**, ensuring compliance even if the model output is slightly inconsistent.

---

## Features

- Analyzes multiple configuration sources (`httpd.conf`, `sites-enabled`, `.htaccess`).
- Redacts sensitive data automatically.
- Converts LLM outputs into structured JSON and readable reports.
- Highlights misconfigurations with **severity enums** (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- Fully compatible with **local Ollama LLM** — no cloud dependency.
- Supports Python 3.9+.

---

## Architecture

```
[Apache Config Files]
        │
        ▼
   Config Chunker
        │
        ▼
  Redactor (removes secrets)
        │
        ▼
  LLM Analysis (Ollama)
        │
        ▼
 JSON Validator (schema enforcement)
        │
        ▼
Human-readable Report Generator
```

Key principles:

- **Chunking** ensures large configs are handled without overloading the model.
- **Prompt grounding** guarantees outputs are structured JSON.
- **Deterministic outputs** allow automated pipelines and validation.

---

## Requirements

- macOS / Linux (Python 3.9+)
- [Homebrew](https://brew.sh/) (for Python and Ollama)
- [Ollama](https://ollama.com) running locally
- Python packages:

```
requests
jsonschema
```

---

## Installation

1. Install Python 3.9 via Homebrew:

```
brew install python@3.9
```

2. Clone the repository:

```
git clone <repo_url>
cd apache_proxy_ai
```

3. Create a virtual environment:

```
python3 -m venv venv39
source venv39/bin/activate
```

4. Install Python dependencies:

```
pip install requests jsonschema
```

5. Ensure Ollama is installed and the model is available:

```
ollama list
ollama pull llama3.1:8b  # or gemma3:1b
ollama serve             # keep it running
```

---

## Usage

Run the analysis pipeline:

```
python3 src/main.py
```

**Input files:**

- `httpd.conf`
- `sites-enabled/*`
- `.htaccess`

**Output:**

- JSON file with `scope_id`, `scope_type`, `allowed_behavior`, and `findings`.
- Human-readable report highlighting misconfigurations and severity levels.

---

## Configuration

- `src/llm_ollama.py`:

  - `OLLAMA_URL` – default `http://localhost:11434/api/chat`
  - `MODEL` – default `"llama3.1:8b"`
  - `SYSTEM_PROMPT` – contains grounding instructions for deterministic JSON output.

- `src/redactor.py` – defines patterns for sensitive data redaction.
- `src/schema.py` – defines JSON schema for validation.

---

## Testing

You can test the tool with example **insecure Apache configurations**:

```
ServerTokens Full
ServerSignature On
ProxyRequests On
<Proxy *>
Require all granted
</Proxy>
AllowOverride All
```

The tool will:

- Flag open proxy exposure (`CRITICAL`)
- Warn about `.htaccess` overrides (`MEDIUM`)
- Highlight unrestricted access (`MEDIUM`)

---

## Project Structure

```
apache_proxy_ai/
├─ src/
│  ├─ main.py            # Entry point
│  ├─ llm_ollama.py      # Local Ollama integration
│  ├─ redactor.py        # Redacts secrets from directives
│  ├─ chunker.py         # Splits config into manageable chunks
│  ├─ rules.py           # Optional rule definitions / severity mappings
│  ├─ schema.py          # JSON schema for validation
│  ├─ validator.py       # Validates LLM output
├─ examples/             # Sample insecure configs for testing
├─ README.md
├─ requirements.txt
```

---

## Notes

- **Not fine-tuned:** The model is not modified; all behavior comes from **prompt engineering**.
- **Robustness:** Post-processing ensures schema compliance even if the LLM output is slightly inconsistent.
- **Extensible:** You can add more directives, rules, or chunking logic as needed.

## Example Report
```
================================================================================
SCOPE: GLOBAL | GLOBAL
--------------------------------------------------------------------------------
Not specified by model.

Findings:
  [CRITICAL] OPEN_PROXY
    Evidence: ProxyRequests On
    Impact: Allows arbitrary proxying, anonymization, and access to internal networks.
    Recommendation: Set ProxyRequests Off and restrict <Proxy *> access.

  [MEDIUM] ALLOWOVERRIDE_ALL
    Evidence: AllowOverride All
    Impact: Expands attack surface and weakens central policy enforcement.
    Recommendation: Limit AllowOverride to required directive classes.

  [MEDIUM] UNRESTRICTED_ACCESS
    Evidence: Require all granted
    Impact: All clients can access the resource.
    Recommendation: Apply IP or authentication-based restrictions where appropriate.

================================================================================
SCOPE: VIRTUAL_HOST | *:80
--------------------------------------------------------------------------------
Not specified by model.

Findings:
  [HIGH] INTERNAL_BACKEND_EXPOSED
    Evidence: ProxyPass /api http://127.0.0.1:8080/
    Impact: External users may access internal-only services.
    Recommendation: Restrict access, require authentication, or isolate the backend.

  [HIGH] INTERNAL_BACKEND_EXPOSED
    Evidence: ProxyPassReverse /api http://127.0.0.1:8080/
    Impact: External users may access internal-only services.
    Recommendation: Restrict access, require authentication, or isolate the backend.

  [MEDIUM] PROXY_PRESERVE_HOST
    Evidence: ProxyPreserveHost On
    Impact: Host header trust issues may enable routing or auth bypass.
    Recommendation: Disable unless explicitly required by the backend.

  [MEDIUM] UNRESTRICTED_ACCESS
    Evidence: Require all granted
    Impact: All clients can access the resource.
    Recommendation: Apply IP or authentication-based restrictions where appropriate.

================================================================================
SCOPE: VIRTUAL_HOST | *:80
--------------------------------------------------------------------------------
Not specified by model.

Findings:
  [MEDIUM] UNRESTRICTED_ACCESS
    Evidence: Require all granted
    Impact: All clients can access the resource.
    Recommendation: Apply IP or authentication-based restrictions where appropriate.

================================================================================
SCOPE: GLOBAL | GLOBAL
--------------------------------------------------------------------------------
Not specified by model.

Findings:
  [MEDIUM] UNRESTRICTED_ACCESS
    Evidence: Require all granted
    Impact: All clients can access the resource.
    Recommendation: Apply IP or authentication-based restrictions where appropriate.
```