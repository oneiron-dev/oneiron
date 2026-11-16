#!/usr/bin/env python3
"""Rewrites every host-door verb row to name its proof rule (UC-01 PR 0a, fable/19 DESIGN stage 0).

Usage: python3 -I scripts/refactor/tools/door_rule_rows.py [<repo root>] [--check]

A host-door row said `"host_door": true`, named its proof kind in `host_door_proof` (or none, with
`"host_door_precheck": false`) and listed its rows with `host_door_lists`. After this script it names its proof
rule in `proof`, says `"door": "hand"` (its door fn is hand-written), and lists with `lists`:

- `host_door: true`          -> `"proof": <rule>, "door": "hand"`, at the same place in the row;
- `host_door_proof: <kind>`  -> the rule the kind folds into (KIND_RULES), and the key goes;
- no kind, precheck false    -> the rule of the old hand list of verb names (HAND_LIST_RULES), which the facade
                                checked before hooks anyway, else `in_door`: the door proves its caller itself,
                                after the hooks. `host_door_precheck` goes either way;
- `host_door_lists`          -> `lists`, in place.

The six `host_door_*` argument flags and the `host` projections of run, browser and board rows keep their names
(UC-01 PR 6.2 renames them). A row already in the new form is left as it is, so the script runs again after each
rebase. It refuses a kind it does not know and a row whose fields disagree. `--check` changes nothing and exits 1
when a row would change. Prints one line per kind of change and the counts.
"""

import json
import pathlib
import sys

# Each proof kind a row names, and the rule it folds into (fable/19 DESIGN section 2.2). Two kinds share a rule
# only when their admit fns admit the same callers; their refusal texts may differ.
KIND_RULES = {
    "owner": "owner",
    "shared_person": "person",
    "trusted_contact_person": "person",
    "workflow_member": "member",
    "check_in_holder": "member",
    "engine_controller": "owner_or_holder",
    "substrate_reader": "owner_or_holder",
    "run_reader": "owner_or_holder",
    "skill_reader": "owner_or_holder",
    "import_canceller": "owner_or_holder",
    "skill_forker": "owner_or_holder",
    "claim_settler": "owner_or_caller",
    "consent_revoker": "owner_or_caller",
    "model_binding_proposer": "owner_or_caller",
    "origin_publish": "caller",
    "diary_reader": "caller",
    "facade_actor": "caller",
    "artifact_asker": "caller",
    "code_import": "caller",
    "slide_reviewer": "caller",
    "image_editor": "caller",
    "code_export_preview": "lane_caller",
    "review_policy": "lane_caller",
    "view_editor": "lane_caller",
    "checkout_holder": "lane_caller",
    "media_owner_grade": "owner_grade",
    "video_job_owner_grade": "owner_grade",
    "usage_repair_list": "usage_repair",
    "usage_repair_remove": "usage_repair",
    "usage_repair_receipts": "usage_repair",
    "off_record": "off_record",
    "off_record_room": "off_record_room",
    "voice_bank": "voice_bank",
    "booking_owner_act": "booking_owner_act",
    "packs_setup": "packs_setup",
    "decision_holder": "decision_holder",
    "hyde_caller": "hyde_caller",
    "guest_document_reader": "guest_document_reader",
    "tradeoff_picker": "tradeoff_picker",
    "artifact_publisher": "artifact_publisher",
    "model_step_caller": "model_step_caller",
    "policy_putter": "policy_power",
    "ramp_demoter": "ramp_power",
    "grants_answer": "grants_answer",
    "credential_holder": "credential_holder",
    "foreign_code": "foreign_code",
    "verdict_asker": "verdict_asker",
    "eval_authoring": "eval_authoring",
    "saved_query": "saved_query",
}

# The old hand list of verb names in host_doors/admission.rs: rows that said `"host_door_precheck": false` and that
# the facade checked before hooks anyway, by name (FIX-LIST HOST-DOOR-HAND-LIST-PRECHECK-MISMATCH). Each gets the
# rule its listed fn is, with the check before hooks, as it runs today.
HAND_LIST_RULES = {
    # share_doors::principal: facade_caller_or.
    "vault.shares.view": "caller",
    "vault.shares.revoke": "caller",
    "vault.notes.follow_citation": "caller",
    # weave_doors::own_caller: host_preflight, then facade_actor.
    "vault.weave.lens": "caller",
    "vault.weave.digest": "caller",
    # weave_doors::person_lens: a person's proof, then the credential's own actor.
    "vault.weave.link.wrong": "lens_person",
    "vault.weave.item.wrong": "lens_person",
    # graph_ask_doors::asker: the same lines as host_doors/support.rs `asking` (ai.verdict's verdict_asker).
    "vault.graph.ask": "verdict_asker",
    "vault.graph.admit": "verdict_asker",
    "vault.questions.create": "verdict_asker",
    "vault.questions.edit": "verdict_asker",
    "vault.questions.pause": "verdict_asker",
    "vault.questions.backfill": "verdict_asker",
    "vault.questions.read": "verdict_asker",
    "vault.questions.refresh": "verdict_asker",
    "vault.questions.schedule": "verdict_asker",
}

OLD_KEYS = ("host_door", "host_door_proof", "host_door_precheck", "host_door_lists")


def rule_of(name, row):
    """The rule `row` names after the rewrite."""
    kind = row.get("host_door_proof")
    precheck = row.get("host_door_precheck", True)
    if kind is not None:
        if kind not in KIND_RULES:
            sys.exit(f"{name}: unknown proof kind {kind!r}; add it to KIND_RULES")
        if precheck is not True:
            sys.exit(f"{name}: names kind {kind!r} but says host_door_precheck {precheck!r}")
        if name in HAND_LIST_RULES:
            sys.exit(f"{name}: names kind {kind!r} and is on the old hand list")
        return KIND_RULES[kind], "kind"
    if precheck is not False:
        sys.exit(f"{name}: a host door that names no kind must say host_door_precheck false")
    if name in HAND_LIST_RULES:
        return HAND_LIST_RULES[name], "hand list"
    return "in_door", "in door"


def rewrite(name, row):
    """The row in the new form, and what changed, or (row, None) when it is already new."""
    if row.get("host_door") is not True:
        if any(key in row for key in OLD_KEYS):
            sys.exit(f"{name}: has {[k for k in OLD_KEYS if k in row]} without host_door true")
        return row, None
    if any(key in row for key in ("proof", "door", "lists")):
        sys.exit(f"{name}: has both the old and the new host-door fields")
    rule, how = rule_of(name, row)
    out = {}
    for key, value in row.items():
        if key == "host_door":
            out["proof"] = rule
            out["door"] = "hand"
        elif key == "host_door_lists":
            out["lists"] = value
        elif key in ("host_door_proof", "host_door_precheck"):
            continue
        else:
            out[key] = value
    return out, how


def main():
    args = [a for a in sys.argv[1:] if a != "--check"]
    check = "--check" in sys.argv[1:]
    root = pathlib.Path(args[0] if args else ".")
    verbs = root / "scripts/sdk/verbs"
    if not verbs.is_dir():
        sys.exit(f"{verbs}: not a directory")
    counts = {}
    changed = 0
    for path in sorted(verbs.glob("*.json")):
        text = path.read_text()
        row = json.loads(text)
        new, how = rewrite(path.stem, row)
        if how is None:
            continue
        counts[how] = counts.get(how, 0) + 1
        rule = new["proof"]
        counts[f"rule {rule}"] = counts.get(f"rule {rule}", 0) + 1
        changed += 1
        if not check:
            path.write_text(json.dumps(new, indent=2, ensure_ascii=False) + "\n")
    for key in sorted(counts):
        print(f"{key}: {counts[key]}")
    print(f"rows {'to rewrite' if check else 'rewritten'}: {changed}")
    if check and changed:
        sys.exit(1)


if __name__ == "__main__":
    main()
