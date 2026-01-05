from chunker import build_chunks
from redactor import redact_directives
from rules import run_rules
from llm_ollama import analyze_chunk
from validator import validate_analysis



def main():
    chunks = build_chunks("config")
    all_results = []

    for chunk in chunks:
        chunk["directives"] = redact_directives(chunk["directives"])
        deterministic_findings = run_rules(chunk)

        analysis = analyze_chunk(
            chunk=chunk,
            deterministic_findings=deterministic_findings
        )

        validate_analysis(analysis)
        all_results.append(analysis)

    for result in all_results:
        print("=" * 80)
        print(f"SCOPE: {result['scope_type']} | {result['scope_id']}")
        print("-" * 80)
        print(result["allowed_behavior"])
        print()

        if result["findings"]:
            print("Findings:")
            for f in result["findings"]:
                print(f"  [{f['severity']}] {f['id']}")
                print(f"    Evidence: {', '.join(f['evidence'])}")
                print(f"    Impact: {f['impact']}")
                print(f"    Recommendation: {f['recommendation']}")
                print()
        else:
            print("No findings identified.\n")

    print("Analysis complete.")


if __name__ == "__main__":
    main()
