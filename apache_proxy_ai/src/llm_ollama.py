import requests
import json
import re

OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL = "gemma3:1b"

SYSTEM_PROMPT = """
You are a security configuration analysis engine.

Rules (MANDATORY):
- Only analyze directives explicitly provided.
- Do NOT assume Apache defaults.
- If behavior is inferred, prefix with "INFERRED:".
- Output MUST be valid JSON and MUST match the provided schema.
- Use severity enums exactly: INFO, LOW, MEDIUM, HIGH, CRITICAL.
- If no issues exist, return an empty findings array.
- Do NOT include commentary, markdown, or explanation outside JSON.
- OUTPUT MUST BE VALID JSON JSON matching this schema exactly:
{
  "scope_id": "string",
  "scope_type": "enum",
  "allowed_behavior": "string",
  "findings": "array of findings"
}
- Do NOT include Markdown, comments, or any text outside the JSON object.
"""

def analyze_chunk(chunk: dict, deterministic_findings: list) -> dict:
    user_prompt = {
        "task": "Analyze Apache configuration scope",
        "scope_type": chunk["scope_type"],
        "scope_id": chunk["scope_id"],
        "directives": chunk["directives"],
        "deterministic_findings": deterministic_findings,
        "required_json_schema": {
            "scope_id": "string",
            "scope_type": "enum",
            "allowed_behavior": "string",
            "findings": "array"
        }
    }

    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(user_prompt)}
        ],
        "options": {
            "temperature": 0,
            "top_p": 0.9,
            "repeat_penalty": 1.1
        },
        "stream": False
    }

    r = requests.post(OLLAMA_URL, json=payload, timeout=60)
    print("HTTP status:", r.status_code)
    print("Raw response:", r.text)  # <- debug
    r.raise_for_status()

    content = r.json()["message"]["content"]
    content = extract_json(content)


    # Hard fail if model emits anything other than JSON
    try:
        parsed = json.loads(content)
        # Fix naming and missing fields
        parsed.setdefault("findings", parsed.pop("deterministic_findings", []))
        parsed.setdefault("allowed_behavior", "Not specified by model.")
    except json.JSONDecodeError as e:
        raise RuntimeError(
            f"Ollama returned non-JSON output. "
            f"This indicates prompt grounding failure.\n{content}"
        )

    return parsed



def extract_json(content: str) -> str:
    """
    Extract JSON from a string that may include markdown code fences.
    Works even if there is extra whitespace or newlines.
    """
    # Strip leading/trailing whitespace
    content = content.strip()

    # Match ```json ... ``` or ``` ... ```
    # Non-greedy match with optional newlines
    match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", content, re.DOTALL)
    if match:
        return match.group(1).strip()

    # fallback: assume content is pure JSON
    return content