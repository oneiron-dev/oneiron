use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use oneiron::{
    code_run::SelfEffect, code_sandbox::SANDBOX_WIT_WORLD_NAME,
    code_sandbox::SandboxBoundaryContract, code_sandbox::SandboxGuestTier,
    code_sandbox::SandboxImportClass,
};

// Which FILES count as production is decided once, in the shared scanner
// (`src/test_util/source_scan.rs`, mounted here through `common`): test-only
// files by name, by a `tests/`/`benches/` directory, or transitively through
// `#[cfg(test)]` and `#[path]` mounts. This file keeps the needles, the pinned
// baselines and the in-file `#[cfg(test)]` masking it always had.
use crate::common::source_scan::{
    SourceTree, cfg_test_external_files, is_ident_byte, is_ident_start, normalized,
    production_source, test_only_by_path,
};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RawHit {
    path: String,
    ident: String,
    line: String,
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate lives under crates/oneiron")
        .to_path_buf()
}

fn relative_path<'a>(repo: &Path, path: &'a Path) -> &'a Path {
    path.strip_prefix(repo).unwrap_or(path)
}

fn line_number(source: &str, byte_idx: usize) -> usize {
    source.as_bytes()[..byte_idx]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count()
        + 1
}

fn source_line(source: &str, line: usize) -> String {
    source
        .lines()
        .nth(line.saturating_sub(1))
        .unwrap_or_default()
        .trim()
        .to_owned()
}

fn find_substring_hits(source: &str, needle: &str) -> Vec<usize> {
    let mut hits = Vec::new();
    let mut start = 0;
    while let Some(rel) = source[start..].find(needle) {
        let hit = start + rel;
        hits.push(hit);
        start = hit + needle.len();
    }
    hits
}

fn raw_escape_ident(ident: &str) -> bool {
    matches!(
        ident,
        "with_write_txn"
            | "try_with_write_txn"
            | "put_edge"
            | "put_vector"
            | "sync_state_put"
            | "sync_state_put_in_write_txn"
    )
}

fn raw_escape_hits(rel: &str, source: &str) -> Vec<RawHit> {
    let bytes = source.as_bytes();
    let mut hits = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if is_ident_start(bytes[i]) {
            let start = i;
            i += 1;
            while i < bytes.len() && is_ident_byte(bytes[i]) {
                i += 1;
            }
            let ident = &source[start..i];
            if raw_escape_ident(ident) {
                let line = line_number(source, start);
                hits.push(RawHit {
                    path: rel.to_owned(),
                    ident: ident.to_owned(),
                    line: source_line(source, line),
                });
            }
        } else {
            i += 1;
        }
    }
    hits
}

/// Assembles the F2 hit map, counted per distinct hit.
///
/// The gate and the negative row below both go through this, so "an extra
/// `with_write_txn` on the surface fails F2" is proved by the assembly the
/// gate actually runs rather than by a copy of the pinned map incremented by
/// hand.
fn f2_actual_hits(sources: impl IntoIterator<Item = (String, String)>) -> BTreeMap<RawHit, usize> {
    let mut actual = BTreeMap::<RawHit, usize>::new();
    for (rel, source) in sources {
        if !f2_surface_path(&rel) {
            continue;
        }
        for hit in raw_escape_hits(&rel, &production_source(&source)) {
            *actual.entry(hit).or_default() += 1;
        }
    }
    actual
}

/// Every production file of `tree`, as the `(relative path, source)` pairs
/// [`f2_actual_hits`] reads.
fn f2_tree_pairs<'a>(
    repo: &'a Path,
    tree: &'a SourceTree,
) -> impl Iterator<Item = (String, String)> + 'a {
    tree.production_sources()
        .map(move |(path, source)| (normalized(relative_path(repo, path)), source.to_owned()))
}

#[test]
fn of060_f1_put_replicated_stays_sync_only() {
    let repo = repo_root();
    let mut violations = Vec::new();
    let tree = SourceTree::read(&repo.join("crates"));

    for (path, source) in tree.production_sources() {
        let rel = normalized(relative_path(&repo, path));
        let source = production_source(source);
        for pattern in [".put_replicated", "::put_replicated"] {
            for hit in find_substring_hits(&source, pattern) {
                if !rel.starts_with("crates/oneiron/src/sync/") {
                    violations.push(format!("{rel}:{}: {pattern}", line_number(&source, hit)));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "OF-060 F1: put_replicated must stay reachable only from oneiron sync production code:\n{}",
        violations.join("\n")
    );
}

#[test]
fn of060_f1_external_mount_keeps_production_controls_scanned() {
    let root = Path::new("");
    let parent = PathBuf::from("src/indexes.rs");
    // Named so only the transitive rule can exclude it: a `*_tests.rs` name
    // would be test-only by itself.
    let mounted = PathBuf::from("src/fixture_probe.rs");
    let test_mount = "#[cfg(test)]\n#[path = \"fixture_probe.rs\"]\nmod tests;";
    let production = "fn seed() { vault.put_replicated(); }";
    let rejected_calls = |sources: &[(PathBuf, String)]| {
        let test_only = cfg_test_external_files(root, sources);
        let mut violations = 0;
        for (path, source) in sources {
            let rel = normalized(relative_path(root, path));
            if test_only_by_path(&rel) || test_only.contains(path) {
                continue;
            }
            let source = production_source(source);
            for pattern in [".put_replicated", "::put_replicated"] {
                if !rel.starts_with("crates/oneiron/src/sync/") {
                    violations += find_substring_hits(&source, pattern).len();
                }
            }
        }
        violations
    };
    assert!(!test_only_by_path(&normalized(&mounted)));
    // A visibility does not change the mount; inline modules resolve their
    // targets under the parent's stem and module chain.
    for (source, target) in [
        (test_mount, "src/fixture_probe.rs"),
        (
            "#[cfg(test)]\n#[path = \"fixture_probe.rs\"]\npub(crate) mod tests;",
            "src/fixture_probe.rs",
        ),
        (
            "#[cfg(test)]\n#[path = \"fixture_probe.rs\"]\npub mod tests;",
            "src/fixture_probe.rs",
        ),
        (
            r#"#[cfg(test)] mod helpers { #[path = "fixture_probe.rs"] mod probe; }"#,
            "src/indexes/helpers/fixture_probe.rs",
        ),
        (
            r#"mod outer { #[cfg(test)] #[path = "fixture_probe.rs"] mod probe; }"#,
            "src/indexes/outer/fixture_probe.rs",
        ),
    ] {
        assert_eq!(
            rejected_calls(&[
                (parent.clone(), source.to_owned()),
                (PathBuf::from(target), production.to_owned()),
            ]),
            0,
            "test-only calls must be exempt: {source}",
        );
    }
    // The shared scanner's own mount in a mod-rs root.
    assert_eq!(
        rejected_calls(&[
            (
                PathBuf::from("src/lib.rs"),
                "#[cfg(test)]\npub(crate) mod test_util {\n    mod source_scan;\n}".to_owned(),
            ),
            (
                PathBuf::from("src/test_util/source_scan.rs"),
                production.to_owned(),
            ),
        ]),
        0,
    );
    for source in [
        "",
        r#"#[path = "fixture_probe.rs"] mod fixture;"#,
        "mod fixture_probe;",
        r#"#[cfg(not(test))] #[path = "fixture_probe.rs"] mod fixture;"#,
        r#"#[cfg(any(test, feature = "sync"))] #[path = "fixture_probe.rs"] mod fixture;"#,
        "// #[cfg(test)]\n#[path = \"fixture_probe.rs\"] mod fixture;",
        r#"/* #[cfg(test)] */ #[path = "fixture_probe.rs"] mod fixture;"#,
        r##"const DOC: &str = r#"#[cfg(test)] #[path = "fixture_probe.rs"] mod tests;"#;"##,
        r##"const DOC: &str = "#[cfg(test)]"; #[path = "fixture_probe.rs"] mod fixture;"##,
        r#"#[cfg(test)] const MARKER: () = (); #[path = "fixture_probe.rs"] mod fixture;"#,
        r#"macro_rules! quote { () => { #[cfg(test)] #[path = "fixture_probe.rs"] mod tests; }; }"#,
        r#"fn body() { #[cfg(test)] #[path = "fixture_probe.rs"] mod tests; }"#,
        r##"#[cfg(test)] #[path = r#"fixture_probe.rs"#] mod tests;"##,
    ] {
        assert_eq!(
            rejected_calls(&[
                (parent.clone(), source.to_owned()),
                (mounted.clone(), production.to_owned()),
            ]),
            1,
            "production calls must be rejected: {source}",
        );
    }
    for production_mount in [
        r#"#[path = "fixture_probe.rs"] mod live;"#,
        "mod fixture_probe;",
    ] {
        assert_eq!(
            rejected_calls(&[
                (parent.clone(), format!("{test_mount}\n{production_mount}")),
                (mounted.clone(), production.to_owned()),
            ]),
            1,
            "a shared mount must not exempt a production call",
        );
        let another_parent = [
            (parent.clone(), test_mount.to_owned()),
            (PathBuf::from("src/live.rs"), production_mount.to_owned()),
            (mounted.clone(), production.to_owned()),
        ];
        assert_eq!(
            rejected_calls(&another_parent),
            1,
            "a production mount in another parent must prevent exemption",
        );
    }
}

#[test]
fn of060_f2_surface_raw_escape_hatches_are_pinned() {
    let repo = repo_root();
    let tree = SourceTree::read(&repo.join("crates"));

    assert_eq!(
        f2_actual_hits(f2_tree_pairs(&repo, &tree)),
        f2_expected_raw_escape_hits(),
        "OF-060 F2: surface raw escape-hatch references changed. New foreign/guest writes must go through a stamper; remove or intentionally update this pinned baseline."
    );
}

fn f2_expected_raw_escape_hits() -> BTreeMap<RawHit, usize> {
    BTreeMap::from([
        (
            RawHit {
                path: "crates/oneiron-napi/src/lib/vault.rs".to_owned(),
                ident: "put_edge".to_owned(),
                line: "pub fn put_edge(&self, src: Buffer, kind: u32, tgt: Buffer, weight: f64) -> napi::Result<()> {".to_owned(),
            },
            1,
        ),
        (
            RawHit {
                path: "crates/oneiron-napi/src/lib/vault.rs".to_owned(),
                ident: "put_edge".to_owned(),
                line: ".put_edge(&src_id, edge_kind, &tgt_id, weight as f32)".to_owned(),
            },
            1,
        ),
        (
            RawHit {
                path: "crates/oneiron-napi/src/lib/vault.rs".to_owned(),
                ident: "put_vector".to_owned(),
                line: "pub fn put_vector(&self, id: Buffer, vector: Vec<f64>) -> napi::Result<()> {".to_owned(),
            },
            1,
        ),
        (
            RawHit {
                path: "crates/oneiron-napi/src/lib/vault.rs".to_owned(),
                ident: "put_vector".to_owned(),
                line: "self.vault.put_vector(&eid, &f32_vec).map_err(to_napi_err)".to_owned(),
            },
            1,
        ),
        (
            RawHit {
                path: "crates/oneiron-server/src/idempotency.rs".to_owned(),
                ident: "sync_state_put".to_owned(),
                line: ".sync_state_put(store_key, &raw)".to_owned(),
            },
            1,
        ),
        // Server-plane auth metadata: one empty row per revoked bearer-token
        // id (ONE-1636). Same class as the idempotency entry above — it writes
        // no entity, edge, or vector, so no stamper applies to it.
        (
            RawHit {
                path: "crates/oneiron-server/src/auth.rs".to_owned(),
                ident: "sync_state_put".to_owned(),
                line: "vault.sync_state_put(&key, &[])?;".to_owned(),
            },
            1,
        ),
        // ONE-1595 (c435a02d, PR #845): trusted managed-vault metadata,
        // not foreign/guest content. The open gate seals a computed DEK MAC
        // at a fixed key after the canary waiver; WakeLedger::advance_rev
        // persists the engine-owned revision for restart ordering. Neither
        // writes an entity, edge, or vector or accepts a caller-selected key.
        // Pin only these two call lines; every new raw hit still fails below.
        (
            RawHit {
                path: "crates/oneiron-server/src/managed/vault_gates.rs".to_owned(),
                ident: "sync_state_put".to_owned(),
                line: ".sync_state_put(DEK_MAC_KEY, mac.as_bytes())".to_owned(),
            },
            1,
        ),
        (
            RawHit {
                path: "crates/oneiron-server/src/managed/ledger.rs".to_owned(),
                ident: "sync_state_put".to_owned(),
                line: ".sync_state_put(LEDGER_REV_KEY, &rev.to_le_bytes())".to_owned(),
            },
            1,
        ),
        (
            RawHit {
                path: "crates/oneiron-server/src/server/leases.rs".to_owned(),
                ident: "with_write_txn".to_owned(),
                line: "if let Err(err) = self.vault.with_write_txn(|wtxn| {".to_owned(),
            },
            1,
        ),
        // BK/1815 (15c62bc2): resolve_booker_contact uses an approved atomic
        // booking transaction, not a stamper bypass. Pin exactly one call.
        (
            RawHit {
                path: "crates/oneiron-server/src/api/booking/subject.rs".to_owned(),
                ident: "with_write_txn".to_owned(),
                line: ".with_write_txn(|txn| {".to_owned(),
            },
            1,
        ),
        // MCP proposed-control-record write (ONE-1936). This is NOT a raw
        // write bypassing a stamper: the transaction wraps the write-verb
        // target guard and a stamped `batch_in().claim_candidate(...)`, which
        // carries the same `WriteEnvelope` the unguarded `batch()` path did.
        // The explicit transaction is REQUIRED — guarding the target in one
        // transaction and writing the proposal in another recreates the
        // grounding-read race the ticket closes.
        (
            RawHit {
                path: "crates/oneiron-server/src/api/mcp_gateway/facade_verbs.rs".to_owned(),
                ident: "with_write_txn".to_owned(),
                line: ".with_write_txn(|wtxn| {".to_owned(),
            },
            1,
        ),
        (
            RawHit {
                path: "crates/oneiron-server/src/usage/ledger.rs".to_owned(),
                ident: "try_with_write_txn".to_owned(),
                line: ".try_with_write_txn(|wtxn| -> Result<LedgerWriteResult, UsageError> {".to_owned(),
            },
            1,
        ),
        (
            RawHit {
                path: "crates/oneiron-server/src/usage/ledger.rs".to_owned(),
                ident: "sync_state_put_in_write_txn".to_owned(),
                line: ".sync_state_put_in_write_txn(wtxn, &tenant_key, &tenant_raw)?;".to_owned(),
            },
            1,
        ),
        (
            RawHit {
                path: "crates/oneiron-server/src/usage/ledger.rs".to_owned(),
                ident: "sync_state_put_in_write_txn".to_owned(),
                line: ".sync_state_put_in_write_txn(wtxn, &vault_key, &vault_raw)?;".to_owned(),
            },
            1,
        ),
        (
            RawHit {
                path: "crates/oneiron-server/src/usage/ledger.rs".to_owned(),
                ident: "sync_state_put_in_write_txn".to_owned(),
                line: ".sync_state_put_in_write_txn(wtxn, &event_key, &entry_raw)?;".to_owned(),
            },
            1,
        ),
        (
            RawHit {
                path: "crates/oneiron-server/src/usage/ledger.rs".to_owned(),
                ident: "try_with_write_txn".to_owned(),
                line: ".try_with_write_txn(|wtxn| -> Result<TopUpWriteResult, UsageError> {".to_owned(),
            },
            1,
        ),
        (
            RawHit {
                path: "crates/oneiron-server/src/usage/ledger.rs".to_owned(),
                ident: "sync_state_put_in_write_txn".to_owned(),
                line: "self.vault.sync_state_put_in_write_txn(".to_owned(),
            },
            2,
        ),
    ])
}

#[test]
fn of060_f2_extra_booking_write_txn_is_not_pinned() {
    let repo = repo_root();
    let tree = SourceTree::read(&repo.join("crates"));
    let expected = f2_expected_raw_escape_hits();
    let booking_path = "crates/oneiron-server/src/api/booking/subject.rs";
    let approved_line = ".with_write_txn(|txn| {";
    let approved_hits = raw_escape_hits(booking_path, &production_source(approved_line));
    assert_eq!(approved_hits.len(), 1);
    assert_eq!(expected.get(&approved_hits[0]), Some(&1));

    // Even an identical second call exceeds the pin. A different line in the
    // same file or the same line in another booking file must also fail F2.
    for (rel, extra_line) in [
        (booking_path, approved_line),
        (booking_path, ".with_write_txn(|extra_txn| {"),
        (
            "crates/oneiron-server/src/api/booking/extra.rs",
            approved_line,
        ),
    ] {
        assert!(!test_only_by_path(rel) && f2_surface_path(rel));
        let extra_hits = raw_escape_hits(rel, &production_source(extra_line));
        assert_eq!(extra_hits.len(), 1);
        let actual = f2_actual_hits(
            f2_tree_pairs(&repo, &tree).chain([(rel.to_owned(), extra_line.to_owned())]),
        );
        assert_ne!(
            actual, expected,
            "OF-060 F2: extra booking with_write_txn must fail: {rel}: {extra_line}"
        );
    }
}

fn f2_surface_path(rel: &str) -> bool {
    rel.starts_with("crates/oneiron-server/src/")
        || rel.starts_with("crates/oneiron-napi/src/")
        || rel.starts_with("crates/oneiron/src/code_run/")
        || rel.starts_with("crates/oneiron/src/code_sandbox/")
}

#[test]
fn of060_p3_code_mode_guest_surface_links_named_verbs_only() {
    let first_party = SandboxBoundaryContract::for_tier(SandboxGuestTier::FirstPartyDreamer);
    assert_eq!(first_party.wit_world(), SANDBOX_WIT_WORLD_NAME);

    let mut write_imports = BTreeMap::new();
    for import in first_party
        .linked_imports()
        .iter()
        .filter(|import| import.class() == SandboxImportClass::WriteTrap)
    {
        assert!(
            write_imports
                .insert(
                    import.name(),
                    import.write_trap_effect().expect("named write trap"),
                )
                .is_none(),
            "write-import names must be unique",
        );
    }
    assert_eq!(
        write_imports,
        BTreeMap::from([
            ("self.memory.put_claim", SelfEffect::MemoryPutClaim),
            (
                "self.memory.supersede_claim",
                SelfEffect::MemorySupersedeClaim,
            ),
            ("self.memory.put_edge", SelfEffect::MemoryPutEdge),
        ]),
        "OF-060 P3: write imports must map exactly to the authorized memory effects",
    );

    for tier in [
        SandboxGuestTier::FirstPartyDreamer,
        SandboxGuestTier::Foreign,
        SandboxGuestTier::Untrusted,
    ] {
        let contract = SandboxBoundaryContract::for_tier(tier);
        for import in contract.linked_imports() {
            assert!(
                !matches!(
                    import.write_trap_effect(),
                    Some(SelfEffect::MemoryWriteFixture),
                ),
                "OF-060 P3: {tier:?} must not expose the fixture write effect",
            );
            for forbidden in [
                "batch",
                "bulk",
                "raw",
                "delete",
                "put_entity",
                "put_replicated",
                "set_edge_weight",
                "write_fixture",
            ] {
                assert!(
                    !import.name().contains(forbidden),
                    "OF-060 P3: {tier:?} code-mode WIT import {} exposes raw escape hatch fragment {forbidden}",
                    import.name()
                );
            }
        }
    }
}

#[test]
fn of060_f3_core_does_not_import_gateway_or_server_code() {
    let repo = repo_root();
    let mut violations = Vec::new();

    let tree = SourceTree::read(&repo.join("crates/oneiron/src"));
    for (path, source) in tree.production_sources() {
        let rel = normalized(relative_path(&repo, path));
        let source = production_source(source);
        for pattern in [
            "oneiron_server::",
            "oneiron-server",
            "crate::mcp",
            "super::mcp",
            "mcp::",
            "crate::server",
            "server::",
            "crate::api",
            "api::",
            "crate::handler",
            "handler::",
            "gateway::",
        ] {
            for hit in find_substring_hits(&source, pattern) {
                // Match path segments, not suffixes such as `api::` in `agent_api::`.
                if hit > 0 && is_ident_byte(source.as_bytes()[hit - 1]) {
                    continue;
                }
                violations.push(format!("{rel}:{}: {pattern}", line_number(&source, hit)));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "OF-060 F3: oneiron core must not import or path-reference gateway/MCP/server code:\n{}",
        violations.join("\n")
    );
}
