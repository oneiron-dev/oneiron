#!/usr/bin/env python3
"""V-stage generator (S3 vault-CRUD insertion into entity modules). Starts with
the 7 pure-method-move entities (no free items / promotions / D3 edits per TS
D1.2). Reuses PR-0's verified method lists, re-homed vault.rs -> <entity>.rs."""
import os
import re
import subprocess
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gen  # PR-0 generator: VAULT_A / VAULT_B method lists
import rustlex as R

ROOT = "/Volumes/Cinema/pink-worktrees/t1443"
OUT = os.path.join(ROOT, "scripts/refactor/moves")
V = "crates/oneiron/src/vault.rs"

# pull the impl-Vault method lists PR-0 verified, per entity
A = {name: moves for name, moves in gen.VAULT_A["moves"]}
B = {name: moves for name, moves in gen.VAULT_B["moves"]}

# 7 clean entities: methods only, no free items, no D3 consumer edits, no promotions
CLEAN = {
    "habit": A["habit"], "authority": A["authority"], "access_grant": A["access_grant"],
    "outbound_grant": A["outbound_grant"], "channel_identity": A["channel_identity"],
    "counterparty_contact": A["counterparty_contact"], "claim": B["claim"],
}
ANCHORS = ("## anchors\n"
           "struct\t-\tVault\t-\tcrates/oneiron/src/vault.rs\n"
           "method\timpl Vault\topen\t-\tcrates/oneiron/src/vault.rs\n"
           "impl\t-\timpl ActorBound<'_>\t-\tcrates/oneiron/src/vault.rs\n\n")

STOPS = []


def gen_clean(entity, moves):
    dst = f"crates/oneiron/src/{entity}.rs"
    vdoc = R.Doc(gen.git_show(V))
    tsv = []
    for kind, name, cfg in moves:
        if kind != "method":
            STOPS.append(f"{entity}: unexpected non-method {name}")
            continue
        m = R.find_item(vdoc, "method", "impl Vault", name, cfg)
        if len(m) != 1:
            STOPS.append(f"{entity}: {name} located {len(m)}x in vault.rs")
            continue
        tsv.append(("method", "impl Vault", name, cfg, V, dst, "no"))
    with open(os.path.join(OUT, f"V-{entity}.tsv"), "w") as f:
        f.write("# kind\tcontainer\titem_name\tcfg\tsrc_file\tdst_file\theader_change\n")
        for r in tsv:
            f.write("\t".join(r) + "\n")
    with open(os.path.join(OUT, f"V-{entity}.decls"), "w") as f:
        f.write("## crate\ncrates/oneiron\n\n")
        f.write(f"## allowed\n{V}\n{dst}\n\n")
        f.write(ANCHORS)
        f.write(f"## impl-delta\n+ {dst}\timpl Vault\n\n")
        # the new impl Vault wrapper is the only non-item, non-use addition
        f.write(f"## add\n{dst}\timpl Vault {{\n{dst}\t}}\n")
    return len(tsv)


# ---- intricate entities: free-item clusters + D2.2c vis + D2.2b/frag promotions + D3 ----
# free item: (kind, name, cfg, header_change). method: (name, cfg, header_change).
INTRICATE = {
    "companion": {
        "free": [("fn", "companion_record_id_for_key_in_txn", "-", "no"),
                 ("fn", "companion_record_any_id_for_key_in_txn", "-", "no"),
                 ("struct", "CompanionRecordKeyLookup", "-", "no"),
                 ("fn", "companion_record_key_lookup_in_txn", "-", "no")],
        "methods": [(n, c, "no") for (_, n, c) in
                    [m for m in gen.VAULT_A["moves"] if m[0] == "companion"][0][1] if _ == "method"] if False else
                   [("companion_profile_access_grant", "-", "no"), ("create_companion_record", "-", "no"),
                    ("update_companion_record", "-", "no"), ("get_companion_record", "-", "no"),
                    ("retire_companion_record", "-", "no"), ("end_companion_relationship", "-", "no"),
                    ("revive_companion_record", "-", "no"), ("companion_record_id_for_key", "-", "no"),
                    ("companion_register", "-", "no"), ("ensure_companion_register_kind", "-", "no"),
                    ("companion_register_kind_registered", "-", "no"), ("read_companion_record_in_txn", "-", "no"),
                    ("apply_companion_record_body", "-", "no")],
        "frag": [],
    },
    "affect": {
        "free": [("const", n, "-", "no") for n in
                 ["VAD_ANNOTATION_META_KEY_PREFIX", "VAD_ANNOTATION_META_KEY_LEN",
                  "VAD_ANNOTATION_CLAIM_PREDICATE", "VAD_ANNOTATION_CLAIM_ID_DOMAIN",
                  "VAD_KEY_VALENCE", "VAD_KEY_AROUSAL", "VAD_KEY_DOMINANCE", "VAD_KEY_SOURCE",
                  "VAD_KEY_ANNOTATED_AT"]]
                + [("fn", "vad_annotation_meta_key", "-", "no"), ("fn", "vad_annotation_claim_id", "-", "no"),
                   ("fn", "vad_annotation_value", "-", "no"), ("fn", "vad_annotation_claim_body", "-", "no"),
                   ("fn", "decode_vad_annotation_claim_body_if_present", "-", "no"),
                   ("fn", "vad_annotation_source_from_str", "-", "no"), ("fn", "vad_annotation_f32", "-", "no"),
                   ("fn", "vad_annotation_from_value", "-", "no"),
                   ("struct", "VadAnnotationCleanup", "-", "no"), ("impl", "impl VadAnnotationCleanup", "-", "no"),
                   ("fn", "delete_vad_annotation_metadata_in_txn", "-", "no"),
                   ("fn", "delete_vad_annotation_metadata_for_type_in_txn", "-", "no"),
                   ("fn", "vad_annotation_claim_matches_subject", "-", "no"),
                   ("fn", "vad_annotation_delete_scope_exists_in_txn", "-", "yes"),
                   ("struct", "StoredClaimVadState", "-", "no")],
        "methods": [(n, "-", "no") for n in
                    ["annotate_turn_vad", "get_turn_vad_annotation", "annotate_message_vad",
                     "get_message_vad_annotation", "consolidate_claim_vad", "consolidate_claim_vad_in_txn",
                     "clear_claim_vad_outputs_in_txn", "close_claim_vad_states", "claim_body_for_claim_vad_in_txn",
                     "turn_vad_annotation_in_txn", "claim_vad_incident_edges_in_txn", "record_claim_vad_edge",
                     "active_claim_vad_states_in_txn", "update_coping_outcome_from_turn_vad",
                     "update_coping_outcome_from_turn_vad_delta", "update_coping_outcome_from_turn_vad_delta_checked",
                     "annotate_entity_vad", "guard_vad_annotation_claim_slot", "get_entity_vad_annotation"]],
        "frag": [],
    },
    "provenance": {
        "free": [("struct", "StoredProvenanceClaim", "-", "yes"),
                 ("impl", "impl StoredProvenanceClaim", "-", "no"),
                 ("fn", "closed_claim_put_payload", "-", "no")],
        "methods": [("put_edge_provenance", "-", "no"), ("supersede_edge_provenance", "-", "no"),
                    ("retract_edge_provenance", "-", "no"), ("ensure_model_substrate", "-", "no"),
                    ("write_edge_provenance", "-", "no"), ("load_provenance_claim_in_txn", "-", "no"),
                    ("live_edge_provenance_claims_in_txn", "-", "yes"),
                    ("retracted_edge_provenance_claims_in_txn", "-", "yes"),
                    ("edge_provenance_claims_in_txn", "-", "no")],
        # precedence/flags promoted pub(crate) inside the moved impl StoredProvenanceClaim block
        "frag": [("precedence", "flags")],
    },
    "deletion": {
        "free": [("const", "MAX_MEMORY_TIMELINE_RECORDS", "-", "no"),
                 ("static", "AFTER_HEADER_READ", "-", "no"),
                 ("fn", "install_after_header_read_signal", "-", "no"),
                 ("fn", "signal_after_header_read", "test", "no"),
                 ("fn", "signal_after_header_read", "not(test)", "no"),
                 ("fn", "is_delete_protected_engine_record", "-", "no"),
                 ("fn", "memory_timeline_record_cmp", "-", "no"),
                 ("struct", "CapturedProvenanceDelete", "-", "no"),
                 ("fn", "sweep_extras", "-", "no")],
        "methods": [(n, ("feature = \"sync\"" if n == "write_crdt_tombstone_SYNC" else
                         "not(feature = \"sync\")" if n == "write_crdt_tombstone_NOSYNC" else "-"),
                     ("yes" if n == "entity_deletion_metadata" else "no")) for n in
                    ["delete_entity", "delete_entity_with_reason", "delete_entity_without_header",
                     "capture_provenance_delete", "refresh_subject_edge_after_claim_delete_in_txn",
                     "refresh_to_retracted_survivor_or_bare", "purge_entity_active_store_in_txn",
                     "soft_erase_active_store_in_txn", "apply_replayed_tombstone", "apply_replayed_tombstone_for_sync",
                     "local_hard_delete_marker_exists_in_txn", "active_delete_scope_exists_in_txn",
                     "write_crdt_tombstone_SYNC", "finish_crdt_tombstone_persist", "write_crdt_tombstone_NOSYNC",
                     "put_pending_tombstone_in_txn", "clear_pending_tombstone", "put_redaction_audit_receipt_in_txn",
                     "write_redaction_receipt_and_sweep_in_txn", "enqueue_hard_erase_sweep_in_txn",
                     "allocate_next_hard_erase_sweep_seq", "max_hard_erase_sweep_seq", "memory_timeline",
                     "memory_timeline_record", "entity_deletion_metadata", "deletion_metadata_from_tombstone_value",
                     "hydrate_deletion_reason", "select_tombstone_metadata_value"]],
        "frag": [],
    },
}
# fix write_crdt_tombstone method names (the _SYNC/_NOSYNC were just cfg markers)
for e in ("deletion",):
    INTRICATE[e]["methods"] = [(("write_crdt_tombstone" if n.startswith("write_crdt_tombstone") else n), c, h)
                               for (n, c, h) in INTRICATE[e]["methods"]]


def sweep_vault_consumers(names, entity):
    """crate::vault::<name> -> crate::<entity>::<name> across the tree.
    Inline -> edit rows; use-lines -> allowed (gate-verified via check C)."""
    # git grep candidate filter (no \b — git ERE lacks it); precise boundary via Python re.sub
    p = subprocess.run(["git", "-C", ROOT, "grep", "-n", "-I", "-E",
                            r"crate::vault::(" + "|".join(re.escape(n) for n in names) + r")",
                            gen.BASE_REV, "--", "*.rs"], capture_output=True, text=True)
    edits = []
    allow = set()
    forbidden = ("crates/oneiron/src/vault.rs",)
    for ln in p.stdout.splitlines():
        try:
            _, path, lineno, content = ln.split(":", 3)
        except ValueError:
            continue
        if path in forbidden:
            continue
        s = content.strip()
        allow.add(path)
        if s.startswith("use ") or s.startswith("pub use ") or s.startswith("pub(crate) use "):
            continue  # use-tree: gate-verified
        new = re.sub(r"crate::vault::(" + "|".join(re.escape(n) for n in names) + r")\b",
                     lambda m: f"crate::{entity}::{m.group(1)}", s)
        if new != s:
            edits.append((path, s, new))
    return edits, allow


def gen_intricate(entity, spec):
    dst = f"crates/oneiron/src/{entity}.rs"
    vdoc = R.Doc(gen.git_show(V))
    tsv = []
    decl = []
    impl_add = [(dst, "impl Vault")]
    impl_rem = []
    frag = []
    add = [f"{dst}\timpl Vault {{", f"{dst}\t}}"]
    # free items
    pub_names = []
    for kind, name, cfg, hc in spec["free"]:
        if kind == "impl":
            m = R.find_item(vdoc, "impl", "-", name, cfg)
            if len(m) != 1:
                STOPS.append(f"V-{entity}: impl {name} {len(m)}x")
                continue
            hdr = m[0]["header"]
            tsv.append(("impl", "-", hdr, cfg, V, dst, "no"))
            impl_rem.append((V, hdr))
            impl_add.append((dst, hdr))
            continue
        m = R.find_item(vdoc, kind, "-", name, cfg)
        if len(m) != 1:
            STOPS.append(f"V-{entity}: {kind} {name} cfg={cfg} {len(m)}x")
            continue
        it = m[0]
        tsv.append((kind, "-", name, cfg, V, dst, hc))
        if hc == "yes":
            decl.append("+ pub ( crate ) " + R.logical_head(vdoc, it["sig_line"]))
        if it["vis"] in ("pub", "pub ( crate )") and hc == "no":
            pub_names.append(name)
    # methods
    for name, cfg, hc in spec["methods"]:
        m = R.find_item(vdoc, "method", "impl Vault", name, cfg)
        if len(m) != 1:
            STOPS.append(f"V-{entity}: method {name} cfg={cfg} {len(m)}x")
            continue
        tsv.append(("method", "impl Vault", name, cfg, V, dst, hc))
        if hc == "yes":
            decl.append("+ pub ( crate ) " + R.logical_head(vdoc, m[0]["sig_line"]))
    # frag-edits (promote impl-internal methods, e.g. StoredProvenanceClaim precedence/flags)
    for pair in spec["frag"]:
        for fname in pair:
            # locate the method inside the moved impl block for its first line
            for it in R.enumerate_items(vdoc):
                if it["kind"] == "impl" and any(mm["name"] == fname for mm in it["methods"]):
                    for mm in it["methods"]:
                        if mm["name"] == fname:
                            old = vdoc.lines[mm["sig_line"]].strip()
                            frag.append((V, old, "pub(crate) " + old))
                            decl.append("+ pub ( crate ) " + R.logical_head(vdoc, mm["sig_line"]))
    # D3 consumer sweep (crate::vault::<pub moved name> -> crate::<entity>::)
    edits, allow = sweep_vault_consumers(pub_names, entity) if pub_names else ([], set())
    # use-tree consumers the inline sweep's ::NAME regex missed (e.g. tests.rs:45
    # `use crate::vault::{vad_annotation_claim_id, vad_annotation_meta_key}`)
    if pub_names:
        ut_a, ut_e = gen.use_tree_scan("crate::vault", {n: entity for n in pub_names})
        allow |= ut_a.get(entity, set())
        for row in ut_e.get(entity, []):
            if row not in edits:
                edits.append(row)
    allowed = {V, dst} | allow
    # write
    with open(os.path.join(OUT, f"V-{entity}.tsv"), "w") as f:
        f.write("# kind\tcontainer\titem_name\tcfg\tsrc_file\tdst_file\theader_change\n")
        for r in tsv:
            f.write("\t".join(r) + "\n")
    with open(os.path.join(OUT, f"V-{entity}.decls"), "w") as f:
        f.write("## crate\ncrates/oneiron\n\n## allowed\n" + "".join(a + "\n" for a in sorted(allowed)) + "\n")
        f.write(ANCHORS)
        f.write("## decl\n" + "".join(d + "\n" for d in sorted(decl)) + "\n")
        f.write("## impl-delta\n")
        for it in sorted(impl_rem):
            f.write(f"- {it[0]}\t{it[1]}\n")
        for it in sorted(impl_add):
            f.write(f"+ {it[0]}\t{it[1]}\n")
        f.write("\n## edit\n" + "".join(f"{e[0]}\t{e[1]}\t{e[2]}\n" for e in edits))
        f.write("\n## frag-edit\n" + "".join(f"{fr[0]}\t{fr[1]}\t{fr[2]}\n" for fr in frag))
        f.write("\n## add\n" + "".join(a + "\n" for a in add))
    return len(tsv), len(edits)


def gen_v0():
    """V-0: 9 pub(crate) promotions in vault.rs. Emits BOTH `## edit` (the first-line
    visibility change) AND `## decl` (the pub-inventory additions) — omitting decl was
    BLOCKER 1 / H1: a visibility-only stage IS a pub-inventory change, invisible to smoke
    (base=HEAD zeroes the delta) but caught by apply-then-check-2."""
    vdoc = R.Doc(gen.git_show(V))
    free = [("fn", "edge_kind_prefix"), ("fn", "require_key_len"),
            ("fn", "entity_id_from_type_index_key"), ("const", "CLAIM_OF_DEFAULT_WEIGHT"),
            ("const", "SUPERSEDES_DEFAULT_WEIGHT"), ("const", "MAX_EDGE_QUERY_RESULTS")]
    meths = [("read_entity_header", "-"), ("live_window", 'feature = "sync"'),
             ("filtered_edge_peers", "-")]
    edits, decl = [], []
    for k, n in free:
        m = R.find_item(vdoc, k, "-", n, "-")
        if len(m) != 1:
            STOPS.append(f"V-0: {k} {n} {len(m)}x")
            continue
        old = vdoc.lines[m[0]["sig_line"]].strip()
        if old.startswith("pub"):
            STOPS.append(f"V-0: {n} already pub")
            continue
        edits.append((V, old, "pub(crate) " + old))
        decl.append("+ pub ( crate ) " + R.logical_head(vdoc, m[0]["sig_line"]))
    for n, cfg in meths:
        m = R.find_item(vdoc, "method", "impl Vault", n, cfg)
        if len(m) != 1:
            STOPS.append(f"V-0: method {n} {len(m)}x")
            continue
        old = vdoc.lines[m[0]["sig_line"]].strip()
        edits.append((V, old, "pub(crate) " + old))
        decl.append("+ pub ( crate ) " + R.logical_head(vdoc, m[0]["sig_line"]))
    for _, o, nw in edits:
        assert R.edit_delta_ok(o, nw), o
    with open(os.path.join(OUT, "V-0.tsv"), "w") as f:
        f.write("# V-0: visibility-only, no item moves (9 pub(crate) promotions in vault.rs)\n")
    with open(os.path.join(OUT, "V-0.decls"), "w") as f:
        f.write("## crate\ncrates/oneiron\n\n## allowed\n" + V + "\n\n")
        f.write(ANCHORS)
        f.write("## decl\n" + "".join(d + "\n" for d in sorted(decl)) + "\n")
        f.write("## edit\n" + "".join(f"{e[0]}\t{e[1]}\t{e[2]}\n" for e in edits))
    return len(edits)


if __name__ == "__main__":
    counts = {}
    counts["V-0"] = gen_v0()
    for entity, moves in CLEAN.items():
        counts[entity] = gen_clean(entity, moves)
    for entity, spec in INTRICATE.items():
        n, e = gen_intricate(entity, spec)
        print(f"V-{entity}: {n} rows, {e} D3 edits")
    for e, c in counts.items():
        print(f"V-{e}: {c} method moves")
    if STOPS:
        print("\nSTOPS:", STOPS, file=sys.stderr)
        sys.exit(1)
    print("OK — 7 clean V-stages generated, no STOPs")
