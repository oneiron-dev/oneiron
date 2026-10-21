"""State-only form goal and independent, conservative factuality decision."""
import re


def prose_status(text, oracle):
    rule = oracle["generated_field"]
    if not isinstance(text, str) or len(text) > rule["max_characters"]:
        return False, "generated_length"
    if any(phrase not in text for phrase in rule["must_include"]):
        return False, "generated_missing_fact"
    # Accept several factual paraphrases, not just the canonical example. Other
    # prose is unproven, not silently declared free of unsupported facts.
    company = re.escape(oracle["values"]["company_name"])
    product, audience = map(re.escape, rule["must_include"])
    patterns = [rf"{company} (?:builds|makes|provides) {product} for {audience}[.!]?",
                rf"(?:We|They) (?:build|make|provide) {product} for {audience}[.!]?",
                rf"{product.capitalize()} for {audience}[.!]?"]
    if any(re.fullmatch(pattern, text) for pattern in patterns):
        return True, None
    return None, "factuality_manual_audit_required"


def check(bundle, result):
    state = bundle["state"]
    oracle = state["expected"]["fields.json"]
    fields = state["fields"]
    failures, unavailable = [], {"field_provenance": "unavailable_e6"}
    if set(fields) != set(oracle["values"]):
        failures.append("field_set_mismatch")
    for field, value in oracle["values"].items():
        if field != "what_you_do" and fields.get(field) != value:
            failures.append("field_mismatch:" + field)
    factuality, reason = prose_status(fields.get("what_you_do"), oracle)
    if factuality is False:
        failures.append(reason)
    elif factuality is None:
        unavailable["factuality"] = reason
    provenance = bundle["engine"].get("field_provenance")
    provenance_pass = None
    if provenance is not None:
        # Input is host-verified receipts, never candidate self-report.
        require_sources = {k: "generated" if v == "generate" else v for k, v in oracle["sources"].items()}
        provenance_pass = (set(provenance) == set(require_sources) and all(
            provenance[k].get("text_source") == source and bool(provenance[k].get("text_ref"))
            for k, source in require_sources.items()))
        unavailable.pop("field_provenance")
        if not provenance_pass:
            failures.append("field_provenance_mismatch")
    state_pass = not failures and factuality is True
    answer = result(failures, unavailable, state_only_pass=state_pass,
                    factuality_pass=factuality, field_provenance_pass=provenance_pass)
    answer["goal_pass"] = False if failures else (True if factuality and provenance_pass else None)
    return answer
