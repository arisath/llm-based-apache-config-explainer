import json
from jsonschema import validate, ValidationError

def load_schema(path="schemas/analysis.schema.json"):
    with open(path, "r") as f:
        return json.load(f)

SCHEMA = load_schema()

def validate_analysis(result: dict):
    try:
        validate(instance=result, schema=SCHEMA)
    except ValidationError as e:
        raise RuntimeError(f"Schema validation failed: {e.message}")
