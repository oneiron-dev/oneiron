#!/usr/bin/env python3
"""Generate stage manifests (.tsv + .decls) and handoff line-number tables from
the ratified move lists, validating every row against the BASE checkout.

- Locates each item in base (exactly-one-match) -> STOP-and-report on mismatch.
- Derives header_change from the item's actual base visibility + the bump rule.
- Emits <stage>.tsv, <stage>.decls (allowed/forbid/anchors/uniqueness/decl/impl-delta),
  and a per-stage line-number report for the handoff move tables.

Run from repo root. rustlex.py must be importable (same dir).
"""
import os
import sys
import collections

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rustlex as R

ROOT = "/Volumes/Cinema/pink-worktrees/t1443"
OUT = os.path.join(ROOT, "scripts/refactor/moves")
REPORT_DIR = "/Users/olety/.claude-pink/jobs/0b1ef39f/tmp/linereports"

BUMPABLE = {"fn", "struct", "enum", "type", "const", "static"}

BASE_REV = os.environ.get("BASE_REV", "b2437d700")


def _git_show_base(path):
    import subprocess
    p = subprocess.run(["git", "-C", ROOT, "show", f"{BASE_REV}:{path}"],
                       capture_output=True, text=True)
    return p.stdout if p.returncode == 0 else None


def use_tree_scan(prefix, name_to_dest):
    """Robust consumer scan for `use PREFIX::{...}` (single AND multi-line) — the
    git-grep `::NAME` regex can't see brace-nested / continuation-line use-trees,
    which dropped ~25 T files + tests.rs (V-affect) + projection.rs (U) from allowed.
    prefix e.g. 'crate::types' / 'crate::vault' / 'oneiron::types'; name_to_dest maps
    a leaf name -> its destination module. Returns (allowed[dest]->set(files),
    edits[dest]->[(file,old,new)]). A SINGLE-LINE use-tree whose names all map to ONE
    dest becomes a byte-verified prefix re-point edit; every other use-tree is
    allowed-only (gate-verified split via check C)."""
    import subprocess
    allowed = collections.defaultdict(set)
    edits = collections.defaultdict(list)
    prefix_canon = R.canon(prefix)
    dest_base = prefix.rsplit("::", 1)[0]  # 'crate' / 'oneiron'
    p = subprocess.run(["git", "-C", ROOT, "grep", "-l", "-I", "-F", prefix + "::",
                        BASE_REV, "--", "*.rs"], capture_output=True, text=True)
    cand = [ln.split(":", 1)[1] for ln in p.stdout.splitlines() if ":" in ln]
    for f in cand:
        txt = _git_show_base(f)
        if txt is None:
            continue
        doc = R.Doc(txt)
        for it in R.enumerate_items(doc):
            if it["kind"] != "use":
                continue
            h = R.logical_head(doc, it["sig_line"])
            if prefix_canon + " ::" not in h:
                continue
            # the module path the leaf names hang off (up to '{' or minus last segment).
            # ONLY direct children of `prefix` are flat-name consumers; a NESTED path
            # like `crate::types::companion::{X}` belongs to the nested sweep — mishandling
            # it produced the D-1 `crate::companion::companion::` regression.
            if "{" in h:
                mod_path = R.canon(h[4:h.index("{")]).rstrip(": ").strip()
                names = [x.strip() for x in h[h.index("{") + 1:h.rindex("}")].split(",")]
            else:
                mod_path = R.canon(h[4:].rsplit("::", 1)[0]).strip()
                names = [h.split()[-1]]
            if mod_path != prefix_canon:
                continue
            names = [n for n in names if n and n not in ("*",)]
            hit = [n for n in names if n in name_to_dest]
            if not hit:
                continue
            dests = {name_to_dest[n] for n in hit}
            for dstm in dests:
                allowed[dstm].add(f)
            if (len(dests) == 1 and it["sig_line"] == it["end_line"]
                    and all(n in name_to_dest for n in names)):
                dstm = next(iter(dests))
                old = doc.lines[it["sig_line"]].strip()
                new = old.replace(prefix + "::", f"{dest_base}::{dstm}::", 1)
                if new != old:
                    edits[dstm].append((f, old, new))
    return allowed, edits

# --- stage specs ----------------------------------------------------------
# move entry: (kind, name, cfg)  kind in {method, fn, struct, enum, type, const,
# static, impl}. For method: container is impl Vault (vault) or given.
# For impl: name is the full header.

VAULT_A = {
    "crate": "crates/oneiron",
    "src": "crates/oneiron/src/vault.rs",
    "dstdir": "crates/oneiron/src/vault",
    "reexport": "named",
    "container": "impl Vault",
    "anchors": [
        ("struct", "-", "Vault", "-", "crates/oneiron/src/vault.rs"),
        ("method", "impl Vault", "open", "-", "crates/oneiron/src/vault.rs"),
        ("impl", "-", "impl ActorBound<'_>", "-", "crates/oneiron/src/vault.rs"),
    ],
    "uniqueness": [],
    "moves": [
        ("habit", [("method", "put_habit_checkin", "-")]),
        ("authority", [
            ("method", "put_authority_log_entry", "-"),
            ("method", "get_authority_log_entry", "-"),
            ("method", "backfill_authority_first_seen_sidecars", "-"),
            ("method", "authority_fold", "-"),
            ("method", "apply_authority_log_entry_body", "-"),
        ]),
        ("access_grant", [
            ("method", "put_access_grant", "-"),
            ("method", "create_access_grant", "-"),
            ("method", "revoke_access_grant", "-"),
            ("method", "get_access_grant", "-"),
            ("method", "write_access_grant_body", "-"),
            ("method", "apply_access_grant_body", "-"),
        ]),
        ("outbound_grant", [
            ("method", "mint_standing_outbound_grant", "-"),
            ("method", "revoke_standing_outbound_grant", "-"),
            ("method", "get_standing_outbound_grant", "-"),
            ("method", "apply_standing_outbound_grant_body", "-"),
        ]),
        ("channel_identity", [
            ("method", "create_channel_identity", "-"),
            ("method", "create_own_app_channel_identity", "-"),
            ("method", "transition_channel_identity", "-"),
            ("method", "get_channel_identity", "-"),
            ("method", "channel_identity_by_assignment", "-"),
            ("method", "channel_identity_assignment_conflict_in_txn", "-"),
            ("method", "apply_channel_identity_body", "-"),
        ]),
        ("counterparty_contact", [
            ("method", "create_counterparty_contact", "-"),
            ("method", "opt_out_counterparty_contact", "-"),
            ("method", "revoke_counterparty_contact", "-"),
            ("method", "get_counterparty_contact", "-"),
            ("method", "find_counterparty_contact", "-"),
            ("method", "counterparty_contacts_for_identity", "-"),
            ("method", "counterparty_contact_assignment_conflict_in_txn", "-"),
            ("method", "apply_counterparty_contact_body", "-"),
        ]),
        ("companion", [
            ("fn", "companion_record_id_for_key_in_txn", "-"),
            ("fn", "companion_record_any_id_for_key_in_txn", "-"),
            ("fn", "companion_record_key_lookup_in_txn", "-"),
            ("method", "companion_profile_access_grant", "-"),
            ("method", "create_companion_record", "-"),
            ("method", "update_companion_record", "-"),
            ("method", "get_companion_record", "-"),
            ("method", "retire_companion_record", "-"),
            ("method", "end_companion_relationship", "-"),
            ("method", "revive_companion_record", "-"),
            ("method", "companion_record_id_for_key", "-"),
            ("method", "companion_register", "-"),
            ("method", "ensure_companion_register_kind", "-"),
            ("method", "companion_register_kind_registered", "-"),
            ("method", "read_companion_record_in_txn", "-"),
            ("method", "apply_companion_record_body", "-"),
        ]),
    ],
}

VAULT_B = {
    "crate": "crates/oneiron",
    "src": "crates/oneiron/src/vault.rs",
    "dstdir": "crates/oneiron/src/vault",
    "reexport": "named",
    "container": "impl Vault",
    "anchors": [
        ("struct", "-", "Vault", "-", "crates/oneiron/src/vault.rs"),
        ("method", "impl Vault", "open", "-", "crates/oneiron/src/vault.rs"),
        ("impl", "-", "impl ActorBound<'_>", "-", "crates/oneiron/src/vault.rs"),
    ],
    "uniqueness": [],
    "moves": [
        ("affect", [
            ("fn", "vad_annotation_meta_key", "-"),
            ("fn", "vad_annotation_claim_id", "-"),
            ("fn", "vad_annotation_value", "-"),
            ("fn", "vad_annotation_claim_body", "-"),
            ("fn", "decode_vad_annotation_claim_body_if_present", "-"),
            ("fn", "vad_annotation_source_from_str", "-"),
            ("fn", "vad_annotation_f32", "-"),
            ("fn", "vad_annotation_from_value", "-"),
            ("struct", "VadAnnotationCleanup", "-"),
            ("impl", "impl VadAnnotationCleanup", "-"),
            ("fn", "delete_vad_annotation_metadata_in_txn", "-"),
            ("fn", "delete_vad_annotation_metadata_for_type_in_txn", "-"),
            ("fn", "vad_annotation_claim_matches_subject", "-"),
            ("fn", "vad_annotation_delete_scope_exists_in_txn", "-"),
            ("method", "annotate_turn_vad", "-"),
            ("method", "get_turn_vad_annotation", "-"),
            ("method", "annotate_message_vad", "-"),
            ("method", "get_message_vad_annotation", "-"),
            ("method", "consolidate_claim_vad", "-"),
            ("method", "consolidate_claim_vad_in_txn", "-"),
            ("method", "clear_claim_vad_outputs_in_txn", "-"),
            ("method", "close_claim_vad_states", "-"),
            ("method", "claim_body_for_claim_vad_in_txn", "-"),
            ("method", "turn_vad_annotation_in_txn", "-"),
            ("method", "claim_vad_incident_edges_in_txn", "-"),
            ("method", "record_claim_vad_edge", "-"),
            ("method", "active_claim_vad_states_in_txn", "-"),
            ("method", "update_coping_outcome_from_turn_vad", "-"),
            ("method", "update_coping_outcome_from_turn_vad_delta", "-"),
            ("method", "update_coping_outcome_from_turn_vad_delta_checked", "-"),
            ("method", "annotate_entity_vad", "-"),
            ("method", "guard_vad_annotation_claim_slot", "-"),
            ("method", "get_entity_vad_annotation", "-"),
        ]),
        ("claim", [
            ("method", "put_claim", "-"),
            ("method", "put_claim_candidate_without_lexical_query_reconcile", "-"),
            ("method", "supersede_claim_for_code_run_trap", "-"),
            ("method", "put_edge_for_code_run_trap", "-"),
            ("method", "validate_code_run_write_actor_binding_in_txn", "-"),
            ("method", "check_code_run_write_gate_in_txn", "-"),
            ("method", "get_claim", "-"),
            ("method", "get_claim_in_txn", "-"),
            ("method", "claims_for_subject", "-"),
            ("method", "claims_for_subject_in_txn", "-"),
            ("method", "claim_bodies_for_subjects_matching", "-"),
            ("method", "claim_for_lifecycle_in", "-"),
            ("method", "require_active_claim", "-"),
            ("method", "require_source_trust_supersession_rights", "-"),
            ("method", "supersede_claim", "-"),
            ("method", "supersede_claim_in_txn", "-"),
            ("method", "retract_claim", "-"),
            ("method", "claim_facet_refs_in", "-"),
        ]),
        ("provenance", [
            ("method", "put_edge_provenance", "-"),
            ("method", "supersede_edge_provenance", "-"),
            ("method", "retract_edge_provenance", "-"),
            ("method", "ensure_model_substrate", "-"),
            ("method", "write_edge_provenance", "-"),
            ("method", "load_provenance_claim_in_txn", "-"),
            ("method", "live_edge_provenance_claims_in_txn", "-"),
            ("method", "retracted_edge_provenance_claims_in_txn", "-"),
            ("method", "edge_provenance_claims_in_txn", "-"),
            ("struct", "StoredProvenanceClaim", "-"),
            ("impl", "impl StoredProvenanceClaim", "-"),
            ("fn", "closed_claim_put_payload", "-"),
        ]),
        ("deletion", [
            ("method", "delete_entity", "-"),
            ("method", "delete_entity_with_reason", "-"),
            ("method", "delete_entity_without_header", "-"),
            ("method", "capture_provenance_delete", "-"),
            ("method", "refresh_subject_edge_after_claim_delete_in_txn", "-"),
            ("method", "refresh_to_retracted_survivor_or_bare", "-"),
            ("method", "purge_entity_active_store_in_txn", "-"),
            ("method", "soft_erase_active_store_in_txn", "-"),
            ("method", "apply_replayed_tombstone", "-"),
            ("method", "apply_replayed_tombstone_for_sync", "-"),
            ("method", "local_hard_delete_marker_exists_in_txn", "-"),
            ("method", "active_delete_scope_exists_in_txn", "-"),
            ("method", "write_crdt_tombstone", 'feature = "sync"'),
            ("method", "finish_crdt_tombstone_persist", "-"),
            ("method", "write_crdt_tombstone", 'not(feature = "sync")'),
            ("method", "put_pending_tombstone_in_txn", "-"),
            ("method", "clear_pending_tombstone", "-"),
            ("method", "put_redaction_audit_receipt_in_txn", "-"),
            ("method", "write_redaction_receipt_and_sweep_in_txn", "-"),
            ("method", "enqueue_hard_erase_sweep_in_txn", "-"),
            ("method", "allocate_next_hard_erase_sweep_seq", "-"),
            ("method", "max_hard_erase_sweep_seq", "-"),
            ("method", "memory_timeline", "-"),
            ("method", "memory_timeline_record", "-"),
            ("method", "entity_deletion_metadata", "-"),
            ("method", "deletion_metadata_from_tombstone_value", "-"),
            ("method", "hydrate_deletion_reason", "-"),
            ("method", "select_tombstone_metadata_value", "-"),
            ("fn", "is_delete_protected_engine_record", "-"),
            ("fn", "memory_timeline_record_cmp", "-"),
            ("fn", "sweep_extras", "-"),
        ]),
    ],
    # tests-mod move handled specially below
    "tests_mod": ("crates/oneiron/src/vault.rs", "crates/oneiron/src/vault/tests.rs"),
}


def load_base(path):
    txt = R_git_show(path)
    if txt is None:
        die(f"BASE file not found: {path}")
    return R.Doc(txt)


def R_git_show(path):
    import subprocess
    p = subprocess.run(["git", "-C", ROOT, "show", f"BASE_REV:{path}"],
                       capture_output=True, text=True)
    return p.stdout if p.returncode == 0 else None


BASE_REV = os.environ.get("BASE_REV", "b2437d700")


def git_show(path):
    import subprocess
    p = subprocess.run(["git", "-C", ROOT, "show", f"{BASE_REV}:{path}"],
                       capture_output=True, text=True)
    return p.stdout if p.returncode == 0 else None


STOPS = []


def die(msg):
    print("STOP:", msg, file=sys.stderr)
    STOPS.append(msg)


def locate(doc, kind, container, name, cfg, src):
    if kind == "method":
        ms = R.find_item(doc, "method", container, name, cfg)
    elif kind == "impl":
        ms = R.find_item(doc, "impl", "-", name, cfg)
    else:
        ms = R.find_item(doc, kind, "-", name, cfg)
    if len(ms) != 1:
        die(f"{src}: expected 1 match for kind={kind} name={name!r} "
            f"container={container!r} cfg={cfg!r}, got {len(ms)}")
        return None
    return ms[0]


def gen_vault(stage_id, spec):
    doc = R.Doc(git_show(spec["src"]))
    src = spec["src"]
    dstdir = spec["dstdir"]
    tsv_rows = []
    decl_add = []           # canon head strings
    impl_add = []           # (file, header)
    impl_rem = []
    line_report = []        # (dst, kind, name, cfg, base_line, vis, header_change)
    allowed = {src}

    for basename, moves in spec["moves"]:
        dst = f"{dstdir}/{basename}.rs"
        allowed.add(dst)
        free_names = []
        has_method = False
        for kind, name, cfg in moves:
            container = spec["container"] if kind == "method" else "-"
            it = locate(doc, kind, container, name, cfg, src)
            if it is None:
                continue
            base_line = it["sig_line"] + 1
            vis = it.get("vis", "")
            bumpable = kind in BUMPABLE
            if bumpable and vis == "" :
                hc = "yes"
            else:
                hc = "no"
            if bumpable and vis == "pub":
                die(f"{src}: bumpable {kind} {name} is fully `pub` at base — "
                    f"downgrade to pub(crate) would break surface")
            # tsv item_name for impl rows = full header (normalized as written)
            item_name = name
            tsv_rows.append((kind, container, item_name, cfg, src, dst, hc))
            line_report.append((dst, kind, item_name, cfg, base_line, vis, hc))
            if kind == "method":
                has_method = True
            elif kind == "impl":
                # relocate impl header
                hdr = it["header"] if it.get("header") else R.canon(name)
                impl_rem.append((src, hdr))
                impl_add.append((dst, hdr))
            else:  # free fn/struct/etc
                free_names.append(name)
                if hc == "yes":
                    head = "pub ( crate ) " + R.logical_head(doc, it["sig_line"])
                    decl_add.append(head)
        if has_method:
            impl_add.append((dst, "impl Vault"))
        if spec["reexport"] == "named" and free_names:
            names = sorted(free_names)
            modname = basename
            shim = f"pub(crate) use self::{modname}::{{{', '.join(names)}}};"
            decl_add.append(R.logical_head(R.Doc(shim), 0))

    # tests mod (vault-B)
    if "tests_mod" in spec:
        tsrc, tdst = spec["tests_mod"]
        allowed.add(tdst)
        tdoc = R.Doc(git_show(tsrc))
        tm = R.find_item(tdoc, "mod", "-", "tests", "-")
        if len(tm) != 1:
            die(f"{tsrc}: tests mod match count {len(tm)}")
        else:
            tsv_rows.append(("mod", "-", "tests", "-", tsrc, tdst, "no"))
            line_report.append((tdst, "mod", "tests", "-", tm[0]["sig_line"] + 1, "", "no"))
            # impls inside the tests body relocate tsrc -> tdst
            inner = mod_inner_text(tdoc, tm[0])
            for hdr in R.impl_headers(R.Doc(inner)):
                impl_rem.append((tsrc, hdr))
                impl_add.append((tdst, hdr))

    write_stage(stage_id, spec, tsv_rows, decl_add, impl_add, impl_rem, allowed, line_report)


def mod_inner_text(doc, it):
    mls = doc.mlines[it["sig_line"]].lstrip()
    start_off = doc.loff[it["sig_line"]] + (len(doc.mlines[it["sig_line"]]) - len(mls))
    bo, eo = R._scan_extent(doc, start_off)
    return doc.src[bo + 1:eo]


def write_stage(stage_id, spec, tsv_rows, decl_add, impl_add, impl_rem, allowed, line_report):
    os.makedirs(OUT, exist_ok=True)
    os.makedirs(REPORT_DIR, exist_ok=True)
    # tsv
    with open(os.path.join(OUT, f"{stage_id}.tsv"), "w") as f:
        f.write("# kind\tcontainer\titem_name\tcfg\tsrc_file\tdst_file\theader_change\n")
        for r in tsv_rows:
            f.write("\t".join(r) + "\n")
    # decls
    with open(os.path.join(OUT, f"{stage_id}.decls"), "w") as f:
        f.write(f"## crate\n{spec['crate']}\n\n")
        f.write("## allowed\n")
        for a in sorted(allowed):
            f.write(a + "\n")
        f.write("\n## forbid\n")
        f.write("\n## anchors\n")
        for a in spec.get("anchors", []):
            f.write("\t".join(a) + "\n")
        f.write("\n## uniqueness\n")
        for u in spec.get("uniqueness", []):
            f.write(u + "\n")
        f.write("\n## error-literal\n")
        f.write("\n## decl\n")
        for d in sorted(decl_add):
            f.write("+ " + d + "\n")
        f.write("\n## impl-delta\n")
        for it in sorted(impl_rem):
            f.write(f"- {it[0]}\t{it[1]}\n")
        for it in sorted(impl_add):
            f.write(f"+ {it[0]}\t{it[1]}\n")
    # line report
    with open(os.path.join(REPORT_DIR, f"{stage_id}.tsv"), "w") as f:
        f.write("dst\tkind\titem\tcfg\tbase_line\tbase_vis\theader_change\n")
        for r in line_report:
            f.write("\t".join(str(x) for x in r) + "\n")
    print(f"[{stage_id}] rows={len(tsv_rows)} decl+={len(decl_add)} impl+={len(impl_add)} impl-={len(impl_rem)} allowed={len(allowed)}")


# ==========================================================================
# api.rs split (D2) — enumerate-and-partition with completeness verification
# ==========================================================================

API_SRC = "crates/oneiron-server/src/api.rs"
API_DSTDIR = "crates/oneiron-server/src/api"

API_STAYERS = {
    "api_routes", "health", "check_api_auth", "scoped_read_for_core_auth",
    "scoped_read_for_legacy_api", "scoped_read_for_actor_ref", "query_params",
    "query_rejection_error", "json_payload", "json_rejection_error",
    "has_json_content_type", "default_limit", "parse_entity_id_param",
    "require_entity_type", "parse_optional_entity_id", "unix_seconds_now",
    "hex_bytes", "core_engine_error",  # fns
    "ApiDoc", "HealthResponse", "ViewQuery",  # structs
    "API_LEVEL", "LEGACY_SCOPED_READ_ACTOR_REF",  # consts
}

# type clusters assigned by name prefix (unambiguous — verified no cross-domain
# collisions). Checked before EXPLICIT for struct/enum/type items.
API_TYPE_PREFIX = [
    ("Companion", "companion"),
    ("CoreRunTree", "run_tree"),
    ("CoreMemory", "memory"),
    ("ContextPack", "context_pack"),
    ("CoreContext", "context_pack"),
    ("CoreEiri", "context_pack"),
    ("Eiri", "context_pack"),
]

API_IMPL = {
    "impl McpGatewayError": "mcp_gateway",
    "impl EiriSessionRagStore": "context_pack",
    "impl VadPayload": "vad",
    "impl From<Vad> for VadPayload": "vad",
    "impl From<TurnVadAnnotationSource> for VadAnnotationSource": "vad",
    "impl From<VadAnnotationSource> for TurnVadAnnotationSource": "vad",
    "impl TurnVadAnnotateResponse": "vad",
}

# explicit name -> domain (fns, consts, statics, and types not prefix-covered)
API_EXPLICIT = {
    "openapi": [
        "openapi_json", "skills_pack", "openapi_document", "merge_error_components",
        "mark_entity_response_as_binary", "fill_schema_description_gaps",
        "set_schema_property_description", "add_security_scheme",
        "SKILL_PACK_NAME", "SKILL_PACK_ENDPOINT", "SKILL_PACK_FORMAT",
        "SKILL_PACK_MIME_TYPE", "SKILL_PACK_LAYER_BOUNDARY", "SKILL_PACK_LOAD_HINT",
        "SKILL_PACK_RESOLUTION",
    ],
    "artifacts": [
        "serve_artifact_root", "serve_artifact_path", "serve_artifact_file",
        "artifact_snapshot_selector", "normalize_artifact_route_path",
        "artifact_root_redirect_response", "artifact_file_response",
        "artifact_cache_control", "request_etag_matches", "artifact_content_type",
        "ArtifactServeQuery",
        "ARTIFACT_POINTER_CACHE_CONTROL", "ARTIFACT_IMMUTABLE_CACHE_CONTROL",
        "ARTIFACT_CONTENT_SECURITY_POLICY",
    ],
    "mcp_gateway": [
        "mcp_gateway", "handle_mcp_request", "resolve_mcp_gateway_actor",
        "mcp_connector_credential", "mcp_actor_resolution_error", "mcp_params",
        "mcp_tool_validation_error", "ensure_mcp_actor_matches", "mcp_validated_actor",
        "execute_mcp_tool", "execute_mcp_nav", "execute_mcp_read", "execute_mcp_edit",
        "execute_mcp_propose_claim", "execute_mcp_proposed_control_record",
        "mcp_claim_candidate_from_args", "mcp_control_record_candidate",
        "mcp_write_envelope", "mcp_claim_subject", "mcp_required_str",
        "mcp_required_json", "mcp_required_f32", "mcp_edit_receipt",
        "mcp_existing_edit_receipt", "mcp_idempotency_entity_id", "mcp_edit_lifecycle",
        "mcp_edit_verb_name", "mcp_ask_result", "mcp_routed_ask_result",
        "mcp_scoped_read", "mcp_actor_result", "mcp_actor_class_wire", "mcp_text_content",
        "mcp_api_error", "mcp_engine_error", "mcp_error_response",
        "McpJsonRpcRequest", "McpToolCallParams", "McpGatewayError",
        "MCP_CREDENTIAL_HEADER", "MCP_PROTOCOL_VERSION",
    ],
    "discover": [
        "discover", "discover_response", "is_agent_visible_entity_type",
        "runtime_status_for_config", "runtime_health_status_for_config",
        "skill_pack_discovery", "discovered_entities", "predicate_namespaces",
        "supported_formats", "feature_flags", "outbound_capability_discovery",
        "rate_limit_status",
        "DiscoverResponse", "SkillPackDiscovery", "BoundContext", "DiscoveredEntity",
        "FeatureFlags", "OutboundCapabilityDiscovery", "OutboundConnectorManifestSummary",
        "RateLimitStatus",
        "SUPPORTED_FORMATS", "EFFECTIVE_AUTH_SCOPES", "CAPABILITIES", "CAPABILITY_MODES",
    ],
    "companion": [
        "create_companion_access_grant", "revoke_companion_access_grant",
        "get_companion_profile", "refresh_companion_profile",
        "create_companion_register_record", "get_companion_register_record",
        "update_companion_register_record", "retire_companion_register_record",
        "end_companion_register_relationship", "optional_companion_profile_refresh_request",
        "companion_profile_access", "companion_profile_response_state",
        "companion_profile_payload", "companion_profile_stale_reason",
        "companion_profile_drift_anchors", "parse_source_revision_ids_query",
        "parse_source_revision_ids_body", "parse_source_revision_ids", "entity_ids_hex",
        "non_empty_source_revision_ids", "select_refresh_source_revision_ids",
        "same_source_revision_selection", "require_companion_profile_read",
        "require_companion_access_grant_write",
        "require_companion_access_grant_write_for_principal", "auth_bound_principal_ref",
        "companion_profile_principal_ref", "companion_scope_entity_refs",
        "companion_access_grant_response", "companion_scope_response",
        "companion_register_record_from_payload", "validate_companion_register_scope_export",
        "companion_register_scope_from_payload", "companion_register_subject_from_payload",
        "companion_register_provenance_from_payload", "companion_register_record_response",
        "companion_goodbye_artifact_hook_payload", "companion_register_record_payload",
        "companion_register_scope_payload", "companion_register_subject_payload",
        "companion_register_kind_from_wire", "companion_register_lifecycle_from_wire",
        "companion_register_export_from_wire", "companion_register_actor_class",
        "companion_register_source_from_wire", "companion_register_approval_from_wire",
        "companion_access_denied", "companion_create_error",
        "companion_register_engine_error", "companion_engine_error",
    ],
    "resume": [
        "resume", "resume_bundle", "resume_session_context", "pending_notifications",
        "pending_unprocessed_items", "current_resume_budget", "resume_caller",
        "notification_body_json", "notification_scoped_to_caller",
        "notification_already_surfaced", "caller_marker_contains",
        "RESUME_NOTIFICATION_LIMIT", "RESUME_NOTIFICATION_SCAN_LIMIT",
    ],
    "consumer_usage": [
        "get_consumer_usage", "get_consumer_usage_details", "top_up_consumer",
        "record_usage_event", "usage_mode_for_event", "get_usage_rollup", "usage_error",
        "consumer_top_up_idempotency_conflict_error",
        "ConsumerUsageQuery", "UsageRollupQuery",
    ],
    "search": [
        "search_vector", "search_text", "search_fetch_limit", "search_meta",
        "search_response", "project_scoped_search_result",
        "VectorSearchQuery", "SearchResult", "SearchResponse", "TextSearchQuery",
    ],
    "entity": [
        "get_entity", "get_edges", "EdgeResult",
    ],
    "vad": [
        "annotate_turn_vad", "read_turn_vad_annotation", "require_message_in_turn",
        "vad_annotation_core_error",
        "VadPayload", "TurnVadAnnotationSource", "TurnVadAnnotateRequest",
        "TurnVadAnnotateQuery", "TurnVadAnnotateResponse",
    ],
    "lease": [
        "lease_revoke", "LeaseRevokeRequest", "LeaseRevokeResponse",
    ],
    # ---- api-B ----
    "core": [
        "core_batch", "list_core_outbound_capabilities", "get_core_outbound_capability",
        "get_core_outbound_verb_contract", "core_query", "core_hydrate",
        "core_batch_short_id_hydrate", "outbound_capability_error",
        "hydrate_short_id_response", "core_hydrate_deletion_metadata",
        "core_entity_timestamps", "encode_core_body", "core_body_for_write",
        "normalize_platform_announcement_body", "is_platform_announcement_body",
        "announcement_status", "announcement_original_text", "object_string_field",
        "object_bool_field", "stage_core_entity_put", "core_text_fields",
        "non_empty_query", "validate_core_query_seeds", "run_core_query",
        "parse_short_ref_request", "parse_short_ref", "parse_short_ref_parts",
        "core_list_limit", "core_list_entities_by_type", "collect_live_entity_page",
        "count_live_entities_by_type", "is_deleted_shell_for_core_list",
        "project_entity_ids", "write_core_entity", "project_core_entity",
        "CoreTextField", "CoreBatchEntityInput", "CoreBatchRequest",
        "CoreBatchEntityResult", "CoreBatchResponse", "CoreQueryRequest",
        "CoreHydrateRequest", "CoreHydrateStatus", "CoreHydrateResponse",
        "CoreHydrateDeletionMetadata", "CoreHydrateDeletionSource",
        "CoreHydrateDeletionReason", "CoreBatchShortIdHydrateRequest",
        "CoreBatchShortIdHydrateResponse", "CoreBatchShortIdHydrateItem",
        "CoreShortIdHydrateOutcome", "CoreShortIdHydrateError",
        "CoreShortIdHydrateErrorKind", "CoreListQuery", "CoreCreateEntityRequest",
        "CoreEntityWriteResponse", "CoreEntityTimestamps", "CoreEntityWriteInput",
        "CORE_MAX_BATCH_ENTITIES", "CORE_MAX_LIST_LIMIT",
        "PLATFORM_ANNOUNCEMENT_MESSAGE_TYPE", "PLATFORM_ANNOUNCEMENT_VOICE",
        "ANNOUNCEMENT_STATUS_ACTIVE", "ANNOUNCEMENT_STATUS_CORRECTED",
        "ANNOUNCEMENT_STATUS_RETRACTED",
    ],
    "run_tree": [
        "core_run_tree", "core_run_tree_observe", "core_run_tree_intervene",
        "validate_core_run_tree_query", "core_run_tree_response", "core_run_tree_node",
        "core_run_tree_status", "core_run_tree_event", "core_run_tree_event_kind",
        "job_intervention_kind", "core_run_tree_intervention_effect",
        "core_run_tree_repair", "parse_job_id_param",
        "CORE_RUN_TREE_RUN_ID_MAX_BYTES",
    ],
    "memory": [
        "core_memory_timeline", "core_memory_verb", "core_memory_timeline_response",
        "core_memory_timeline_state", "core_memory_operation_kind",
        "parse_required_entity_id", "core_memory_delete_reason",
    ],
    "conversations": [
        "list_core_conversations", "create_core_conversation",
        "list_core_conversation_turns", "create_core_conversation_turn", "get_core_turn",
        "core_list_conversation_turns", "count_live_conversation_turns",
        "CoreCreateTurnRequest",
    ],
    "context_pack": [
        "core_context_pack", "context_pack", "resolved_context_pack_depth",
        "validate_context_pack_depth", "apply_context_pack_policy",
        "apply_context_pack_time", "apply_context_pack_budget",
        "resolve_context_pack_retrieval_budgets", "widen_context_pack_retrieval_budget",
        "resolve_eiri_context_v4_request", "resolve_eiri_companion_assembly",
        "companion_scope_resolution_authorized", "parse_companion_ref",
        "validate_eiri_session_id", "is_shared_eiri_session_scope_id",
        "companion_scope_wire", "eiri_memory_board_budget", "eiri_session_rag_store",
        "eiri_session_rag_key", "eiri_session_rag_scope_key",
        "current_eiri_session_rag_state", "advance_eiri_session_rag_state",
        "apply_context_pack_response_limits",
        "apply_context_pack_response_retrieval_budget", "scrub_context_pack_visible_stats",
        "run_context_pack_builder", "field_profile_for_view",
        "context_pack_json_projection_config", "core_context_pack_evidence_for_results",
        "core_context_pack_response", "core_context_entity", "core_context_edge",
        "core_context_pack_stats", "core_context_pack_state",
        "core_context_pack_state_reason", "core_context_pack_evidence",
        "core_context_pack_score_evidence", "core_context_pack_score_component",
        "signal_name", "retrieval_signal_name", "default_true", "default_context_neighbors",
        "EIRI_SESSION_RAG_STATE",
        "EIRI_SESSION_RAG_STATE_MAX_ENTRIES", "EIRI_SESSION_RAG_SESSION_ID_MAX_BYTES",
        "EIRI_SESSION_RAG_LAST_RESULT_IDS_MAX", "SHARED_EIRI_SESSION_SCOPE_IDS",
    ],
}

API_A_DOMAINS = ["openapi", "artifacts", "mcp_gateway", "discover", "companion",
                 "resume", "consumer_usage", "search", "entity", "vad", "lease"]
API_B_DOMAINS = ["core", "run_tree", "memory", "conversations", "context_pack"]


# ==========================================================================
# D3 test-split waves (PR-5..8 = tests-w1..4)
# ==========================================================================

def _top(stem):
    return (f"crates/oneiron/src/{stem}.rs", f"crates/oneiron/src/{stem}/tests.rs")


def _srv(stem):
    return (f"crates/oneiron-server/src/{stem}.rs",
            f"crates/oneiron-server/src/{stem}/tests.rs")


# PR-5 (w1): 10 codec-adjacent oneiron top-level files
W1 = [_top(s) for s in [
    "claim", "authority", "companion", "persona_snapshot", "psych_profile",
    "channel_identity", "counterparty_contact", "federation", "outbound_grant",
    "access_grant",
]]

# PR-6 (w2): remaining oneiron top-level files (D3 rows 1-59 minus w1)
W2 = [_top(s) for s in [
    "types", "store", "serialize", "gate", "pipeline", "context_pack", "lens",
    "dreamer_runner", "policy_model", "repo_mutation", "code_revision", "bm25",
    "ppr", "receipt", "hnsw", "job_queue", "code_run", "code_symbol", "graph_fs",
    "channel_identity_provider", "dreamer_tournament", "engine_executor", "codebase",
    "maintain", "sweep", "inbox", "llm", "provenance", "genui", "deletion",
    "code_sandbox", "off_record", "blob_artifact", "delivery_window", "critic",
    "channel_identity_lifecycle", "skill", "run_tree", "ingest", "extraction_eval",
    "identity_reputation", "artifact_hosting", "export", "thread_lens", "recovery",
    "surface_event", "embed", "settings", "fusion",
]]

# PR-7 (w3): oneiron submodules (D3 rows 60-76)
W3 = [
    ("crates/oneiron/src/settings/model_versioning.rs",
     "crates/oneiron/src/settings/model_versioning/tests.rs"),
    ("crates/oneiron/src/llm/budget.rs", "crates/oneiron/src/llm/budget/tests.rs"),
    ("crates/oneiron/src/edit_roundtrip/opc.rs",
     "crates/oneiron/src/edit_roundtrip/opc/tests.rs"),
    ("crates/oneiron/src/analyzer/mod.rs", "crates/oneiron/src/analyzer/tests.rs"),
    ("crates/oneiron/src/analyzer/japanese.rs",
     "crates/oneiron/src/analyzer/japanese/tests.rs"),
    ("crates/oneiron/src/analyzer/script.rs",
     "crates/oneiron/src/analyzer/script/tests.rs"),
] + [
    (f"crates/oneiron/src/sync/{s}.rs", f"crates/oneiron/src/sync/{s}/tests.rs")
    for s in ["bridge", "client", "connection", "lease", "manager", "quarantine",
              "queue", "quota", "selector", "transport", "window"]
]

# PR-8 (w4): oneiron-server files (D3 rows 77-87)
W4 = [_srv(s) for s in [
    "mcp", "handler", "server", "usage", "config", "runtime", "error",
    "idempotency", "commands", "projection", "auth",
]]

TESTS_STAGES = [
    ("tests-w1", W1, "crates/oneiron"),
    ("tests-w2", W2, "crates/oneiron"),
    ("tests-w3", W3, "crates/oneiron"),
    ("tests-w4", W4, "crates/oneiron-server"),
]


def gen_tests(stage_id, rows, crate):
    tsv_rows = []
    impl_add = []
    impl_rem = []
    line_report = []
    allowed = set()
    for src, dst in rows:
        allowed.add(src)
        allowed.add(dst)
        txt = git_show(src)
        if txt is None:
            die(f"tests: src not found at base: {src}")
            continue
        doc = R.Doc(txt)
        tm = R.find_item(doc, "mod", "-", "tests", "-")
        if len(tm) != 1:
            die(f"{src}: expected exactly 1 `mod tests`, got {len(tm)}")
            continue
        if tm[0]["body_open_line"] is None:
            die(f"{src}: `mod tests` has no inline body (already out-of-line?)")
            continue
        tsv_rows.append(("mod", "-", "tests", "-", src, dst, "no"))
        line_report.append((dst, "mod", "tests", "-", tm[0]["sig_line"] + 1, "", "no"))
        inner = mod_inner_text(doc, tm[0])
        for hdr in R.impl_headers(R.Doc(inner)):
            impl_rem.append((src, hdr))
            impl_add.append((dst, hdr))
    spec = {"crate": crate, "anchors": [], "uniqueness": []}
    write_stage(stage_id, spec, tsv_rows, [], impl_add, impl_rem, allowed, line_report)


def partition_api(doc):
    """Assign every non-stayer top-level item to exactly one domain. STOP on any
    unassigned or doubly-assigned item."""
    name2dom = {}
    for dom, names in API_EXPLICIT.items():
        for nm in names:
            if nm in name2dom:
                die(f"api EXPLICIT double-assign: {nm} in {name2dom[nm]} and {dom}")
            name2dom[nm] = dom
    assign = collections.defaultdict(list)  # domain -> [item dict]
    for it in R.enumerate_items(doc):
        k = it["kind"]
        if k in ("use", "mod"):
            continue
        if k == "impl":
            hdr = it["header"]
            # normalize header key to match API_IMPL keys (drop spaces via canon compare)
            dom = None
            for key, d in API_IMPL.items():
                if R.canon(key) == hdr:
                    dom = d
                    break
            if dom is None:
                die(f"api impl UNASSIGNED: {hdr}")
                continue
            assign[dom].append(it)
            continue
        nm = it["name"]
        if nm in API_STAYERS:
            continue
        dom = None
        if k in ("struct", "enum", "type"):
            for pfx, d in API_TYPE_PREFIX:
                if nm.startswith(pfx):
                    dom = d
                    break
        if dom is None:
            dom = name2dom.get(nm)
        if dom is None:
            die(f"api item UNASSIGNED (kind={k}): {nm} @L{it['sig_line']+1}")
            continue
        assign[dom].append(it)
    return assign


def gen_api(stage_id, domains, assign, tests_dst=None):
    doc = R.Doc(git_show(API_SRC))
    tsv_rows = []
    decl_add = []
    impl_add = []
    impl_rem = []
    line_report = []
    allowed = {API_SRC}
    if tests_dst:
        allowed.add(tests_dst)
        tm = R.find_item(doc, "mod", "-", "tests", "-")
        if len(tm) != 1:
            die(f"{API_SRC}: tests mod match count {len(tm)}")
        else:
            tsv_rows.append(("mod", "-", "tests", "-", API_SRC, tests_dst, "no"))
            line_report.append((tests_dst, "mod", "tests", "-", tm[0]["sig_line"] + 1, "", "no"))
            inner = mod_inner_text(doc, tm[0])
            for hdr in R.impl_headers(R.Doc(inner)):
                impl_rem.append((API_SRC, hdr))
                impl_add.append((tests_dst, hdr))
    for dom in domains:
        dst = f"{API_DSTDIR}/{dom}.rs"
        allowed.add(dst)
        for it in assign[dom]:
            k = it["kind"]
            if k == "impl":
                hdr = it["header"]
                tsv_rows.append(("impl", "-", hdr, "-", API_SRC, dst, "no"))
                line_report.append((dst, "impl", hdr, "-", it["sig_line"] + 1, "", "no"))
                impl_rem.append((API_SRC, hdr))
                impl_add.append((dst, hdr))
                continue
            nm = it["name"]
            vis = it.get("vis", "")
            bumpable = k in BUMPABLE
            hc = "yes" if (bumpable and vis == "") else "no"
            if bumpable and vis == "pub":
                die(f"{API_SRC}: {k} {nm} is fully `pub` at base — pub(crate) bump would downgrade")
            tsv_rows.append((k, "-", nm, "-", API_SRC, dst, hc))
            line_report.append((dst, k, nm, "-", it["sig_line"] + 1, vis, hc))
            if hc == "yes":
                decl_add.append("pub ( crate ) " + R.logical_head(doc, it["sig_line"]))
        # glob re-export per domain
        decl_add.append(R.logical_head(R.Doc(f"pub(crate) use self::{dom}::*;"), 0))

    spec = {
        "crate": "crates/oneiron-server",
        "anchors": [
            ("fn", "-", "api_routes", "-", API_SRC),
            ("struct", "-", "ApiDoc", "-", API_SRC),
        ],
        "uniqueness": [API_SRC, f"{API_DSTDIR}/*.rs"],
    }
    write_stage(stage_id, spec, tsv_rows, decl_add, impl_add, impl_rem, allowed, line_report)


if __name__ == "__main__":
    gen_vault("vault-A", VAULT_A)
    gen_vault("vault-B", VAULT_B)
    apidoc = R.Doc(git_show(API_SRC))
    assign = partition_api(apidoc)
    total = sum(len(v) for v in assign.values())
    print(f"[api partition] {total} items assigned across {len(assign)} domains")
    gen_api("api-A", API_A_DOMAINS, assign)
    gen_api("api-B", API_B_DOMAINS, assign, tests_dst="crates/oneiron-server/src/api/tests.rs")
    for sid, rows, crate in TESTS_STAGES:
        gen_tests(sid, rows, crate)
    if STOPS:
        print(f"\n{len(STOPS)} STOP(s) — fix before proceeding", file=sys.stderr)
        sys.exit(1)
    print("OK — all generated with no STOPs")
    if STOPS:
        print(f"\n{len(STOPS)} STOP(s) — fix before proceeding", file=sys.stderr)
        sys.exit(1)
    print("OK — vault stages generated with no STOPs")
