"""LLM-based vulnerability reasoning (Stage 5)."""
from vulnscan5g.llm.client import OllamaClient
from vulnscan5g.llm.prompts import reason_prompt
from vulnscan5g.models.finding import Finding
from vulnscan5g.preprocess.cleaner import get_raw_snippet


def reason(finding: Finding, code: str, client: OllamaClient | None = None) -> Finding:
    """Enrich a Finding with LLM explanation. Mutates and returns the finding."""
    client = client or OllamaClient()
    snippet = get_raw_snippet(code, finding.line, window=5)
    prompt = reason_prompt(snippet, finding.vuln_type, finding.cwe_id)

    try:
        response = client.generate(prompt)
        finding.llm_explanation = response

        # Parse confirmation
        upper = response.upper()
        if "CONFIRMED: YES" in upper:
            finding.llm_confirmed = True
            finding.confidence = min(1.0, finding.confidence + 0.25)
            finding.llm_confidence = finding.confidence
        elif "CONFIRMED: NO" in upper or "REJECTED" in upper:
            finding.llm_confirmed = False
            finding.confidence = max(0.0, finding.confidence - 0.3)
            finding.llm_confidence = finding.confidence
        else:
            finding.llm_confidence = finding.confidence
    except Exception as e:
        finding.llm_explanation = f"LLM unavailable: {e}"

    return finding
