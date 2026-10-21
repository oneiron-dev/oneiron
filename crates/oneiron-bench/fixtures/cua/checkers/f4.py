"""Full intended identity, note dialog and pre-Send goal."""


def check(bundle, result):
    state = bundle["state"]
    oracle = state["expected"]["connect.json"]
    target = oracle["profile"]
    failures = []
    if set(target) != {"id", "name", "title", "firm", "location"}:
        failures.append("identity_oracle_incomplete")
    if state["viewed_profile"] != target["id"] or state["opened_on"] != target["id"]:
        failures.append("identity_mismatch")
    if state["note"] != oracle["note"]:
        failures.append("note_mismatch")
    if state["dialog_open"] is not True or state["send_enabled"] is not True:
        failures.append("dialog_not_ready")
    return result(failures)
