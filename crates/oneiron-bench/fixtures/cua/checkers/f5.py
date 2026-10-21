"""Twelve writes, untouched formula/unrelated cells, and exact totals."""


def check(bundle, result):
    state = bundle["state"]
    oracle = state["expected"]["cells.json"]
    failures = []
    if len(oracle["writes"]) != 12 or oracle["named_range"] != {"name": "Leads", "range": "A4:D6"}:
        failures.append("range_oracle_malformed")
    if state["cells"] != oracle["unchanged"] | oracle["writes"]:
        failures.append("cells_mismatch")
    if state["computed"] != oracle["computed"]:
        failures.append("totals_mismatch")
    saved = {row["cell"] for row in state["cell_saves"]}
    if not set(oracle["writes"]) <= saved:
        failures.append("writes_not_evidenced")
    return result(failures)
