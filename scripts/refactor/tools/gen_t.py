#!/usr/bin/env python3
"""Stage-T generator (types.rs dissolution, D9). Enumerate-and-partition types.rs
into the 12 concept modules, verify the census, then emit T1-T12 .tsv/.decls with
consumer edits (inline crate::types::<name> re-points), comment rows, add boilerplate,
lib.rs flat re-point, and the T12 exhaustion stage."""
import os
import re
import subprocess
import sys
import collections

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rustlex as R

ROOT = "/Volumes/Cinema/pink-worktrees/t1443"
BASE_REV = os.environ.get("BASE_REV", "b2437d700")
OUT = os.path.join(ROOT, "scripts/refactor/moves")
TYPES = "crates/oneiron/src/types.rs"

STOPS = []


def die(m):
    print("STOP:", m, file=sys.stderr)
    STOPS.append(m)


def git_show(path, rev=None):
    p = subprocess.run(["git", "-C", ROOT, "show", f"{rev or BASE_REV}:{path}"],
                       capture_output=True, text=True)
    return p.stdout if p.returncode == 0 else None


# name -> dest module, by explicit list (fns/consts) + type name. Verified against D9.1.1.
DEST = {}


def _assign(dest, names):
    for n in names:
        if n in DEST:
            die(f"double-assign {n}: {DEST[n]} and {dest}")
        DEST[n] = dest


_assign("registry", [
    # 35 ENTITY_TYPE_*
    "ENTITY_TYPE_CLAIM", "ENTITY_TYPE_TURN", "ENTITY_TYPE_SESSION", "ENTITY_TYPE_MESSAGE",
    "ENTITY_TYPE_PERSON", "ENTITY_TYPE_RELATIONSHIP", "ENTITY_TYPE_EVENT", "ENTITY_TYPE_SKILL",
    "ENTITY_TYPE_SUMMARY", "ENTITY_TYPE_PLACE", "ENTITY_TYPE_ASSET_TEXT", "ENTITY_TYPE_CONVERSATION",
    "ENTITY_TYPE_ORG", "ENTITY_TYPE_FACET", "ENTITY_TYPE_WORLD", "ENTITY_TYPE_ASSET",
    "ENTITY_TYPE_NOTIFICATION", "ENTITY_TYPE_AGENT_DEF", "ENTITY_TYPE_TASK_LIST", "ENTITY_TYPE_TASK",
    "ENTITY_TYPE_MACHINE", "ENTITY_TYPE_CODE_ARTIFACT", "ENTITY_TYPE_CODE_SYMBOL",
    "ENTITY_TYPE_BLOB_ARTIFACT", "ENTITY_TYPE_REDACTION_AUDIT", "ENTITY_TYPE_MODEL",
    "ENTITY_TYPE_AUTHORITY_LOG", "ENTITY_TYPE_POLICY_MANIFEST", "ENTITY_TYPE_FEDERATION_GRANT",
    "ENTITY_TYPE_ACCESS_GRANT", "ENTITY_TYPE_PSYCH_PROFILE", "ENTITY_TYPE_CHANNEL_IDENTITY",
    "ENTITY_TYPE_COUNTERPARTY_CONTACT", "ENTITY_TYPE_OUTBOUND_GRANT", "ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT",
    # 10 TYPE_BYTE_* + MAINTENANCE
    "TYPE_BYTE_SEMANTIC", "TYPE_BYTE_BAND_CORE_START", "TYPE_BYTE_BAND_CORE_END",
    "TYPE_BYTE_BAND_COMPANION_START", "TYPE_BYTE_BAND_COMPANION_END", "TYPE_BYTE_BAND_PRODUCTIVITY_START",
    "TYPE_BYTE_BAND_PRODUCTIVITY_END", "TYPE_BYTE_BAND_CRM_START", "TYPE_BYTE_BAND_CRM_END",
    "TYPE_BYTE_BAND_MAINTENANCE_START", "MAINTENANCE_TYPE_BYTE_BAND_START",
    "ENTITY_TYPE_REGISTRY",
    "EntityClassification", "TypeByteBand", "EntityTypeRegistryEntry", "StructuralKindRegistration",
    "band_of", "is_structural_kind", "short_id_prefix", "entity_type_registry_entry",
    "static_short_id_prefix_collision", "validate_entity_type", "validate_public_entity_type",
])
_assign("entity_id", [
    "ENTITY_ID_LEN", "FOREIGN_WORLD_ID_RANGE_START_BYTE",
    "EntityId", "LocalWorldId", "ForeignWorldId",
    "is_foreign_world_id_range", "parse_entity_id", "is_reserved_entity_id_bytes",
    "bytes_to_hex_lower", "hex_nibble",
])
_assign("edge", [
    "EDGE_KEY_LEN", "EDGE_VALUE_STRUCTURAL_LEN", "EDGE_VALUE_SEMANTIC_LEN",
    "EDGE_VALUE_SEMANTIC_PROVENANCED_LEN",
    "EdgeKind", "EdgeValueLayout", "EdgeConfirmationStatus", "EdgeActorClass",
    "EdgeProvenanceFlags", "DecodedEdgeValue", "EdgeInfo", "StrictEdgeRecord",
    "edge_value_layout_for_kind", "read_f32_le", "read_u64_le", "read_vad",
    "decode_edge_value", "decode_edge_value_for_kind", "parse_strict_edge_record",
    "parse_strict_edge_record_key", "edge_record_error", "validate_edge_weight", "encode_edge_value",
])
_assign("write_envelope", [
    "WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY", "WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY",
    "WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY", "WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY",
    "WriteActor", "WriteProvenance", "WriteEnvelope", "ClaimCandidate", "write_envelope_evidence",
])
_assign("temporal", [
    "TEMPORAL_SECONDS_PER_DAY", "TEMPORAL_RECENT_DAYS",
    "TemporalExpression", "TemporalExpressionParseError", "TemporalGranularity", "TemporalAnchorMode",
    "TimeRange",
    "parse_temporal_expression", "temporal_expression_from_query", "normalize_temporal_expression",
    "temporal_query_tokens", "is_temporal_unit_token", "is_temporal_quantity_token",
    "unsupported_last_quantity_expression", "is_weekday_token", "utc_day_start",
    "previous_calendar_month_range", "previous_calendar_year_range", "unix_seconds_from_civil_saturating",
    "unix_seconds_from_civil", "unix_days_from_timestamp", "civil_from_unix_days", "unix_days_from_civil",
])
_assign("config", [
    "HnswConfig", "VaultConfig", "TextAnalyzerConfig", "TextIndexOptions", "Bm25RankProfile",
])
_assign("pipeline", ["ScoredEntity", "Signal"])
_assign("context_pack", [
    "PackFormat", "FieldProfile", "PackItemAccountingReason", "EmptyReason",
    "ContextEntity", "PackStats", "PackTokenStats", "PackSectionTokenStats", "PackItemTokenStats",
    "PackItemAccounting", "EmptyContext", "ContextPack", "TokenAllocation", "ContextPackRetrievalBudget",
    "allocate_context_pack_item_budgets",
])
_assign("eiri", [
    "EIRI_CONTEXT_VERSION_V4",
    "EiriMemoryBoardSlot", "EiriMemoryBoardSource",
    "EiriMemoryBoardBudget", "EiriCompanionAssembly", "EiriMemoryBoardRow", "EiriMemoryBoard",
    "EiriSessionRagState", "SessionContext", "NotificationItem", "UnprocessedItem",
    "ResumeBudget", "ResumeBundle",
])
_assign("affect", ["Vad", "VadAnnotation", "VadComponent", "VadAnnotationSource"])
_assign("deletion", [
    "HydratedShortIdDeletionReason", "HydratedShortIdDeletionSource", "MemoryTimelineRecordState",
    "NamedMemoryVerb", "MemoryOperationKind", "HydratedShortIdDeletion", "MemoryTimelineRecord",
    "MemoryTimeline",
])
_assign("habit", ["TASK_BODY_ROLE_KEY", "TaskRole", "task_body_for_test", "task_role_from_body_bytes"])

# new modules created by T (need module-doc `//!` + `pub mod` in lib.rs)
NEW_MODULES = {"registry", "entity_id", "edge", "write_envelope", "temporal", "config", "eiri"}
# T11 creates habit.rs too (per D9.5 row 4)
EXISTING = {"affect", "deletion", "pipeline", "context_pack"}

# batch -> dest(s)
BATCH_DESTS = {
    "T1": ["registry"], "T2": ["entity_id"], "T3": ["affect"], "T4": ["edge"],
    "T5": ["write_envelope"], "T6": ["temporal"], "T7": ["config"],
    "T8": ["pipeline", "context_pack"], "T9": ["eiri"], "T10": ["deletion"], "T11": ["habit"],
}


def impl_target(header):
    """The type name an impl block is FOR (last type token, ignoring trait)."""
    # header canon like "impl Default for VaultConfig" or "impl EdgeKind" or
    # "impl TryFrom < EntityId > for LocalWorldId"
    toks = header.split()
    if "for" in toks:
        after = toks[toks.index("for") + 1:]
        return after[0] if after else None
    return toks[1] if len(toks) > 1 else None


def partition():
    doc = R.Doc(git_show(TYPES))
    items = R.enumerate_items(doc)
    by_dest = collections.defaultdict(list)
    for it in items:
        k = it["kind"]
        if k in ("use", "mod"):
            continue
        if k == "impl":
            tgt = impl_target(it["header"])
            dest = DEST.get(tgt)
            if dest is None:
                die(f"impl UNASSIGNED (target {tgt!r}): {it['header']}")
                continue
            by_dest[dest].append(it)
            continue
        dest = DEST.get(it["name"])
        if dest is None:
            die(f"item UNASSIGNED ({k}): {it['name']} @L{it['sig_line']+1}")
            continue
        by_dest[dest].append(it)
    return doc, by_dest


# D9.2.1 flat-exported names per dest (the 71-name bijection)
FLAT = {
    "registry": ["ENTITY_TYPE_ACCESS_GRANT", "ENTITY_TYPE_AUTHORITY_LOG",
        "ENTITY_TYPE_CHANNEL_IDENTITY", "ENTITY_TYPE_CODE_ARTIFACT", "ENTITY_TYPE_CODE_SYMBOL",
        "ENTITY_TYPE_COUNTERPARTY_CONTACT", "ENTITY_TYPE_FEDERATION_GRANT",
        "ENTITY_TYPE_OUTBOUND_GRANT", "ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT",
        "ENTITY_TYPE_PSYCH_PROFILE", "StructuralKindRegistration", "TypeByteBand"],
    "entity_id": ["EntityId"],
    "edge": ["DecodedEdgeValue", "EdgeActorClass", "EdgeConfirmationStatus", "EdgeInfo",
        "EdgeKind", "EdgeProvenanceFlags", "EdgeValueLayout"],
    "write_envelope": ["ClaimCandidate", "WriteActor", "WriteEnvelope", "WriteProvenance"],
    "temporal": ["TemporalAnchorMode", "TemporalGranularity", "TimeRange"],
    "config": ["Bm25RankProfile", "HnswConfig", "TextAnalyzerConfig", "TextIndexOptions",
        "VaultConfig"],
    "pipeline": ["ScoredEntity", "Signal"],
    "context_pack": ["ContextEntity", "ContextPack", "ContextPackRetrievalBudget",
        "EmptyContext", "EmptyReason", "FieldProfile", "PackFormat", "PackItemTokenStats",
        "PackSectionTokenStats", "PackStats", "PackTokenStats", "TokenAllocation"],
    "eiri": ["EIRI_CONTEXT_VERSION_V4", "EiriCompanionAssembly", "EiriMemoryBoard",
        "EiriMemoryBoardBudget", "EiriMemoryBoardRow", "EiriMemoryBoardSlot",
        "EiriMemoryBoardSource", "EiriSessionRagState", "NotificationItem", "ResumeBudget",
        "ResumeBundle", "SessionContext", "UnprocessedItem"],
    "affect": ["Vad", "VadAnnotation", "VadAnnotationSource", "VadComponent"],
    "deletion": ["HydratedShortIdDeletion", "HydratedShortIdDeletionReason",
        "HydratedShortIdDeletionSource", "MemoryOperationKind", "MemoryTimeline",
        "MemoryTimelineRecord", "MemoryTimelineRecordState", "NamedMemoryVerb"],
}
BATCH_ORDER = ["T1", "T2", "T3", "T4", "T5", "T6", "T7", "T8", "T9", "T10", "T11"]
BATCH_DESTS = {"T1": ["registry"], "T2": ["entity_id"], "T3": ["affect"], "T4": ["edge"],
    "T5": ["write_envelope"], "T6": ["temporal"], "T7": ["config"],
    "T8": ["pipeline", "context_pack"], "T9": ["eiri"], "T10": ["deletion"], "T11": ["habit"]}
NEW_MODS = ["registry", "entity_id", "edge", "write_envelope", "temporal", "config", "eiri"]
# module docs for the 7 new files (Fable-authored boilerplate)
MODDOC = {
    "registry": "//! Entity-type registry: type bytes, bands, classification, the registry array + lookups/validators.",
    "entity_id": "//! `EntityId` + world-id newtypes + id parsing/hex.",
    "edge": "//! Edge kinds, layouts, value codec, strict edge-record parsing, `EdgeInfo`.",
    "write_envelope": "//! Write-path stamping: `WriteActor`/`WriteProvenance`/`WriteEnvelope`/`ClaimCandidate` + evidence stamping.",
    "temporal": "//! `TimeRange`, temporal expressions/parsing, granularity/anchor enums.",
    "config": "//! Caller-facing runtime configuration: `VaultConfig` + `HnswConfig` + `TextAnalyzerConfig` + `TextIndexOptions` + `Bm25RankProfile`.",
    "eiri": "//! Eiri Context v4 board + session-RAG + companion resume wire types.",
    "habit": "//! Productivity-pack task-role vocabulary + task/habit checkin validators.",
}
# test-distribution rows: dst-module -> [(kind, name)]
TESTS = {
    "entity_id": [("fn", "entity_id_hex_round_trip"), ("fn", "entity_id_from_hex_rejects_invalid"),
        ("fn", "local_world_id_rejects_foreign_range"), ("fn", "foreign_world_id_accepts_only_foreign_range")],
    "edge": [("fn", "strict_edge_record_parser_decodes_key_and_value"),
        ("fn", "strict_edge_record_parser_normalizes_corruption_errors")],
    "temporal": [("const", "FROZEN_NOW"),
        ("fn", "temporal_expression_parser_resolves_supported_forms_from_frozen_clock"),
        ("fn", "temporal_expression_query_parser_rejects_unsupported_last_forms"),
        ("fn", "temporal_expression_query_parser_ignores_non_temporal_last_nouns"),
        ("fn", "temporal_expression_query_parser_rejects_multiple_hints"),
        ("fn", "temporal_expression_query_parser_rejects_unsupported_non_last_forms"),
        ("fn", "unix_seconds_from_civil_keeps_epoch_boundary_at_zero"),
        ("fn", "unix_seconds_from_civil_rejects_pre_epoch_dates"),
        ("fn", "temporal_expression_calendar_ranges_saturate_at_epoch_boundary"),
        ("fn", "temporal_expression_rejects_extreme_timestamp_without_wrapping")],
    "habit": [("fn", "task_role_from_body_bytes_rejects_malformed_bodies")],
    "context_pack": [("fn", "context_pack_retrieval_budget_default_token_allocation_splits_other_weight"),
        ("fn", "context_pack_retrieval_budget_default_small_limit_keeps_positive_buckets_eligible")],
}
# which dst file the tests land in: new modules -> the module .rs (inline mod tests);
# context_pack -> the existing context_pack/tests.rs
TEST_DST = {"entity_id": "crates/oneiron/src/entity_id.rs", "edge": "crates/oneiron/src/edge.rs",
    "temporal": "crates/oneiron/src/temporal.rs", "habit": "crates/oneiron/src/habit.rs",
    "context_pack": "crates/oneiron/src/context_pack/tests.rs"}

OUT = os.path.join(ROOT, "scripts/refactor/moves")


def parse_lib_groups():
    doc = R.Doc(git_show("crates/oneiron/src/lib.rs"))
    groups = {}
    for it in R.enumerate_items(doc):
        if it["kind"] != "use" or it["vis"] != "pub":
            continue
        h = R.logical_head(doc, it["sig_line"])
        m = re.match(r"^pub use crate :: ([a-z_]+) :: \{ (.*) \}$", h)
        if m:
            groups.setdefault(m.group(1), []).extend(x.strip() for x in m.group(2).split(","))
    return groups


def repoint_line(line, names):
    """Re-point every `(crate|oneiron)::types::<name>` on the line to its dest, for
    names in the given set."""
    def sub(m):
        pre, nm = m.group(1), m.group(2)
        return f"{pre}::{DEST[nm]}::{nm}" if nm in names else m.group(0)
    return re.sub(r"(crate|oneiron)::types::([A-Za-z_][A-Za-z0-9_]*)", sub, line)


def sweep():
    """Return: edits[batch] = list of (file, old, new); allowed[batch] = set(files)."""
    p = subprocess.run(["git", "-C", ROOT, "grep", "-n", "-I", "-E",
                        r"(crate|oneiron)::types::[A-Za-z_]", BASE_REV, "--", "*.rs"],
                       capture_output=True, text=True)
    occ = re.compile(r"(?:crate|oneiron)::types::([A-Za-z_][A-Za-z0-9_]*)")
    edits = collections.defaultdict(list)
    allowed = collections.defaultdict(set)
    for ln in p.stdout.splitlines():
        try:
            _, path, lineno, content = ln.split(":", 3)
        except ValueError:
            continue
        names = [n for n in occ.findall(content) if n in DEST]
        if not names:
            continue
        s = content.strip()
        is_use = s.startswith("use ") or s.startswith("pub use ") or s.startswith("pub(crate) use ")
        # batch of each name present
        line_batches = []
        for b in BATCH_ORDER:
            bn = [n for n in names if DEST[n] in BATCH_DESTS[b]]
            if bn:
                line_batches.append((b, bn))
        for b, _ in line_batches:
            allowed[b].add(path)
        if is_use:
            continue  # use-tree split: gate-verified (allowed only)
        # inline: chained per-batch single/multi-region edit
        cur = s
        done = set()
        for b, bn in line_batches:
            new = repoint_line(cur, set(bn))
            edits[b].append((path, cur, new))
            cur = new
    return edits, allowed


def emit(doc, by_dest):
    import gen
    libgroups = parse_lib_groups()
    edits, allowed = sweep()
    # use-tree consumer files (single + multi-line) the inline sweep's ::NAME regex
    # missed — in-crate AND cross-crate. allowed-only unless a single-line use-tree
    # maps to one module (then a byte-verified prefix re-point edit).
    ut_allow = collections.defaultdict(set)
    ut_edits = collections.defaultdict(list)
    for pfx in ("crate::types", "oneiron::types"):
        a, e = gen.use_tree_scan(pfx, DEST)
        for d, fs in a.items():
            ut_allow[d] |= fs
        for d, es in e.items():
            ut_edits[d] += es
    # running types-group flat-name set (post-U 71 = union of FLAT)
    types_group = set()
    for names in FLAT.values():
        types_group.update(names)
    row_counts = {}
    for b in BATCH_ORDER:
        dests = BATCH_DESTS[b]
        tsv = []
        decl = []          # signed lines
        impl_add = []
        impl_rem = []
        add = []           # file<TAB>line
        comment = []
        fragedit = []
        allow = {TYPES, "crates/oneiron/src/lib.rs"}
        allow |= allowed[b]
        for dest in dests:
            allow |= ut_allow[dest]
            for row in ut_edits[dest]:
                if row not in edits[b]:
                    edits[b].append(row)
        errlit = set()
        # moves
        for dest in dests:
            if dest in NEW_MODS or dest == "habit":
                dstf = f"crates/oneiron/src/{dest}.rs"
                add.append(f"{dstf}\t{MODDOC[dest]}")
                decl.append(f"+ pub mod {dest}")
            else:
                dstf = f"crates/oneiron/src/{dest}.rs"
            allow.add(dstf)
            errlit.add(dstf)
            for it in sorted(by_dest[dest], key=lambda x: x["sig_line"]):
                if it["kind"] == "impl":
                    hdr = it["header"]
                    tsv.append(("impl", "-", hdr, "-", TYPES, dstf, "no"))
                    impl_rem.append((TYPES, hdr))
                    impl_add.append((dstf, hdr))
                else:
                    tsv.append((it["kind"], "-", it["name"], "-", TYPES, dstf, "no"))
        # test-distribution rows
        for dest in dests:
            if dest in TESTS:
                tdst = TEST_DST[dest]
                allow.add(tdst)
                for kind, name in TESTS[dest]:
                    tsv.append((kind, "mod tests", name, "-", TYPES, tdst, "no"))
                # new-file inline tests wrapper (registry/write_envelope have no tests)
                if tdst.endswith(f"/{dest}.rs"):
                    add.append(f"{tdst}\t#[cfg(test)]")
                    add.append(f"{tdst}\tmod tests {{")
                    add.append(f"{tdst}\t}}")
        # lib.rs decl: types group shrink + dest group
        batch_flat = set()
        for dest in dests:
            batch_flat |= set(FLAT.get(dest, []))
        if batch_flat:
            before = sorted(types_group)
            after = sorted(types_group - batch_flat)
            decl.append("- " + R.norm_head("pub use crate :: types :: { " + " , ".join(before) + " }"))
            if after:
                decl.append("+ " + R.norm_head("pub use crate :: types :: { " + " , ".join(after) + " }"))
            for dest in dests:
                fl = FLAT.get(dest, [])
                if not fl:
                    continue
                if dest in libgroups:  # join existing group
                    old = sorted(libgroups[dest])
                    new = sorted(set(libgroups[dest]) | set(fl))
                    decl.append("- " + R.norm_head("pub use crate :: " + dest + " :: { " + " , ".join(old) + " }"))
                    decl.append("+ " + R.norm_head("pub use crate :: " + dest + " :: { " + " , ".join(new) + " }"))
                else:  # new group
                    decl.append("+ " + R.norm_head("pub use crate :: " + dest + " :: { " + " , ".join(sorted(fl)) + " }"))
            types_group -= batch_flat
        # T1 comment rows (the two orphan interstitials). Ranges are valid for
        # the post-S2 base (re-derived after #412 removed 24 lines above them);
        # re-derive again if types.rs shifts before T1 lands.
        if b == "T1":
            comment.append("crates/oneiron/src/types.rs:72-76\tcrates/oneiron/src/registry.rs")
            comment.append("crates/oneiron/src/types.rs:83-85\tcrates/oneiron/src/registry.rs")
        # T2 ForeignWorldId doctest frag-edit
        if b == "T2":
            fragedit.append("crates/oneiron/src/types.rs\t"
                            "/// use oneiron::types::{EntityId, ForeignWorldId};\t"
                            "/// use oneiron::entity_id::{EntityId, ForeignWorldId};")
        write_batch(b, tsv, decl, impl_add, impl_rem, edits[b], fragedit, comment, add,
                    sorted(allow), sorted(errlit))
        row_counts[b] = len(tsv)
    # T12 finale
    emit_t12(row_counts)
    return row_counts


def write_batch(b, tsv, decl, impl_add, impl_rem, edits, fragedit, comment, add, allow, errlit):
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, f"{b}.tsv"), "w") as f:
        f.write("# kind\tcontainer\titem_name\tcfg\tsrc_file\tdst_file\theader_change\n")
        for r in tsv:
            f.write("\t".join(r) + "\n")
    with open(os.path.join(OUT, f"{b}.decls"), "w") as f:
        f.write("## crate\ncrates/oneiron\n\n")
        f.write("## flat-name-check\nyes\n\n")
        f.write("## allowed\n" + "".join(a + "\n" for a in allow) + "\n")
        f.write("## error-literal\n" + "".join(e + "\n" for e in errlit) + "\n")
        f.write("## decl\n" + "".join(d + "\n" for d in sorted(decl)) + "\n")
        f.write("## impl-delta\n")
        for it in sorted(impl_rem):
            f.write(f"- {it[0]}\t{it[1]}\n")
        for it in sorted(impl_add):
            f.write(f"+ {it[0]}\t{it[1]}\n")
        f.write("\n## edit\n")
        for (fn, o, nw) in edits:
            f.write(f"{fn}\t{o}\t{nw}\n")
        f.write("\n## frag-edit\n" + "".join(fe + "\n" for fe in fragedit))
        f.write("\n## comment\n" + "".join(c + "\n" for c in comment))
        f.write("\n## add\n" + "".join(a + "\n" for a in add))


def emit_t12(row_counts):
    with open(os.path.join(OUT, "T12.tsv"), "w") as f:
        f.write("# T12 finale: no item moves — delete types.rs, remove `pub mod types;`\n")
    with open(os.path.join(OUT, "T12.decls"), "w") as f:
        f.write("## crate\ncrates/oneiron\n\n")
        f.write("## allowed\ncrates/oneiron/src/lib.rs\ncrates/oneiron/src/types.rs\n\n")
        f.write("## decl\n- pub mod types\n\n")
        f.write("## exhaust\ncrates/oneiron/src/types.rs\n\n")
        f.write("## exhaust-stages\n" + "".join(b + "\n" for b in BATCH_ORDER) + "\n")
    row_counts["T12"] = 0


if __name__ == "__main__":
    doc, by_dest = partition()
    emit(doc, by_dest)
    # census
    print("=== T partition census (kind counts per dest) ===")
    total = collections.Counter()
    for dest in sorted(by_dest):
        kc = collections.Counter(it["kind"] for it in by_dest[dest])
        total.update(kc)
        print(f"  {dest:16} {dict(kc)}")
    print(f"  {'TOTAL':16} {dict(total)}")
    assigned = sum(len(v) for v in by_dest.values())
    print(f"assigned items: {assigned}")
    if STOPS:
        print(f"\n{len(STOPS)} STOP(s)", file=sys.stderr)
        sys.exit(1)
    print("OK partition complete, no STOPs")
