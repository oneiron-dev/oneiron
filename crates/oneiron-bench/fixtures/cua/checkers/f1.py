"""Keyed exact artifact comparison; ordering of records has no meaning."""
import csv
import io


def keyed(rows):
    if not isinstance(rows, list) or len(rows) != 20:
        raise ValueError("twenty_records_required")
    mapping = {r["id"]: r for r in rows}
    if len(mapping) != 20:
        raise ValueError("duplicate_ids")
    return mapping


def tiers(text):
    reader = csv.DictReader(io.StringIO(text), delimiter="\t")
    if reader.fieldnames != ["id", "tier"]:
        raise ValueError("ranked_header")
    rows = list(reader)
    return keyed(rows)


def check(bundle, result):
    expected = bundle["state"]["expected"]
    files = bundle["artifacts"]["files"]
    failures = []
    if set(files) != set(expected):
        failures.append("artifact_set_mismatch")
    for name, oracle in expected.items():
        try:
            parse = tiers if name == "ranked.tsv" else keyed
            if parse(files[name]) != parse(oracle):
                failures.append("artifact_mismatch:" + name)
        except (KeyError, TypeError, ValueError):
            failures.append("artifact_malformed:" + name)
    return result(failures, {"first_useful_action": "unavailable_static_profile_reads_not_logged"})
