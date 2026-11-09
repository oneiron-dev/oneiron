use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use oneiron::{
    code_run::SelfEffect, code_sandbox::SANDBOX_WIT_WORLD_NAME,
    code_sandbox::SandboxBoundaryContract, code_sandbox::SandboxGuestTier,
    code_sandbox::SandboxImportClass, code_sandbox::SandboxLinkedImportEffects,
    task_verb::sdk::RunVerb,
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
            | "with_write_txn_grouped"
            | "try_with_write_txn_grouped"
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

fn f2_expected_raw_escape_hits() -> BTreeMap<RawHit, usize> {
    BTreeMap::from([
        // W7-C10: host-owned key metadata and observed wire receipts, never
        // guest entity writes. Their fixed prefixes stay service-private.
        // OF-520's limit questions are such rows too: one per crossed limits
        // row and window, in the declared `wire:limit-question:v1:` table.
        (RawHit { path: "crates/oneiron-server/src/control_keys.rs".to_owned(),ident:"sync_state_put_in_write_txn".to_owned(),line:".sync_state_put_in_write_txn(txn, &key, &encode(&row)?)?;".to_owned()}, 3),
        (RawHit { path: "crates/oneiron-server/src/control_keys.rs".to_owned(),ident:"sync_state_put_in_write_txn".to_owned(),line:".sync_state_put_in_write_txn(txn, &new_key, &encode(&new)?)?;".to_owned()}, 1),
        (RawHit { path: "crates/oneiron-server/src/control_keys.rs".to_owned(),ident:"sync_state_put_in_write_txn".to_owned(),line:".sync_state_put_in_write_txn(txn, &old_key, &encode(&old)?)?;".to_owned()}, 1),
        (RawHit { path: "crates/oneiron-server/src/control_keys.rs".to_owned(),ident:"try_with_write_txn_grouped".to_owned(),line:"let result = self.vault.try_with_write_txn_grouped(|txn| {".to_owned()}, 1),
        (RawHit { path: "crates/oneiron-server/src/control_keys.rs".to_owned(),ident:"try_with_write_txn_grouped".to_owned(),line:"self.vault.try_with_write_txn_grouped(|txn| {".to_owned()}, 3),
        (RawHit { path: "crates/oneiron-server/src/wire_telemetry.rs".to_owned(),ident:"sync_state_put".to_owned(),line:"self.vault.sync_state_put(".to_owned()}, 1),
        (RawHit { path: "crates/oneiron-server/src/wire_telemetry.rs".to_owned(),ident:"sync_state_put".to_owned(),line:"self.vault.sync_state_put(&key, &encode(&question)?)?;".to_owned()}, 1),
        (RawHit { path: "crates/oneiron-server/src/wire_telemetry.rs".to_owned(),ident:"sync_state_put".to_owned(),line:"self.vault.sync_state_put(MANIFEST, &encode(thresholds)?)".to_owned()}, 1),
        (RawHit { path: "crates/oneiron-server/src/wire_telemetry.rs".to_owned(),ident:"sync_state_put_in_write_txn".to_owned(),line:".sync_state_put_in_write_txn(txn, &key, &encode(&question)?)?;".to_owned()}, 1),
        (RawHit { path: "crates/oneiron-server/src/wire_telemetry.rs".to_owned(),ident:"with_write_txn_grouped".to_owned(),line:"self.vault.with_write_txn_grouped(|txn| {".to_owned()}, 1),
        // OF-305: a provider's offer cooldowns, this deployment's routing state
        // under a fixed service-private prefix, never a guest entity write.
        (RawHit { path: "crates/oneiron-server/src/models/cooldown.rs".to_owned(),ident:"try_with_write_txn_grouped".to_owned(),line:"let kept = vault.try_with_write_txn_grouped(|txn| {".to_owned()}, 1),
        (RawHit { path: "crates/oneiron-server/src/models/cooldown.rs".to_owned(),ident:"sync_state_put_in_write_txn".to_owned(),line:"vault.sync_state_put_in_write_txn(txn, &key, &bytes)?;".to_owned()}, 1),
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
                line: "pub fn put_vector(&self, id: Buffer, vector: Array<'_>) -> napi::Result<()> {".to_owned(),
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
        // id (ONE-1636). ONE-1939 wraps the row in a single-winner transaction.
        // Same class as idempotency: no entity, edge, or vector is written.
        (
            RawHit {
                path: "crates/oneiron-server/src/auth.rs".to_owned(),
                ident: "with_write_txn_grouped".to_owned(),
                line: "Ok(vault.with_write_txn_grouped(|txn| {".to_owned(),
            },
            1,
        ),
        (
            RawHit {
                path: "crates/oneiron-server/src/auth.rs".to_owned(),
                ident: "sync_state_put_in_write_txn".to_owned(),
                line: "vault.sync_state_put_in_write_txn(txn, &key, &[])?;".to_owned(),
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
                ident: "with_write_txn_grouped".to_owned(),
                line: "if let Err(err) = self.vault.with_write_txn_grouped(|wtxn| {".to_owned(),
            },
            1,
        ),
        // BK/1815 (15c62bc2): resolve_booker_contact uses an approved atomic
        // booking transaction, not a stamper bypass. Pin exactly one call.
        (
            RawHit {
                path: "crates/oneiron-server/src/api/booking/subject.rs".to_owned(),
                ident: "with_write_txn_grouped".to_owned(),
                line: ".with_write_txn_grouped(|txn| {".to_owned(),
            },
            1,
        ),
        // W7-C09: host-owned lease and money metadata, never foreign/guest
        // entities, edges or vectors. Lease scope is minted under one fixed key.
        // Usage writes validated stamped events, vault-only derived rollups,
        // and a converted host limit. Restore rebuilds rollups atomically.
        // Deleted tenant rollups and cloud-only top-ups have no exception here.
        (
            RawHit {
                path: "crates/oneiron-server/src/managed/vault_gates.rs".to_owned(),
                ident: "with_write_txn_grouped".to_owned(),
                line: ".with_write_txn_grouped(|txn| {".to_owned(),
            },
            1,
        ),
        (
            RawHit {
                path: "crates/oneiron-server/src/managed/vault_gates.rs".to_owned(),
                ident: "sync_state_put_in_write_txn".to_owned(),
                line: "vault.sync_state_put_in_write_txn(txn, KEY, &id.to_be_bytes())?;".to_owned(),
            },
            1,
        ),
        (
            RawHit {
                path: "crates/oneiron-server/src/usage/ledger.rs".to_owned(),
                ident: "try_with_write_txn_grouped".to_owned(),
                line: ".try_with_write_txn_grouped(|txn| -> Result<_, UsageError> {".to_owned(),
            },
            2,
        ),
        (
            RawHit {
                path: "crates/oneiron-server/src/usage/ledger.rs".to_owned(),
                ident: "sync_state_put_in_write_txn".to_owned(),
                line: ".sync_state_put_in_write_txn(txn, &key, &encode_entry(&stored)?)?;".to_owned(),
            },
            1,
        ),
        (
            RawHit {
                path: "crates/oneiron-server/src/usage/ledger.rs".to_owned(),
                ident: "sync_state_put_in_write_txn".to_owned(),
                line: "self.vault.sync_state_put_in_write_txn(".to_owned(),
            },
            3,
        ),
        (
            RawHit {
                path: "crates/oneiron-server/src/usage/limit.rs".to_owned(),
                ident: "try_with_write_txn_grouped".to_owned(),
                line: ".try_with_write_txn_grouped(|txn| -> Result<(), UsageError> {".to_owned(),
            },
            1,
        ),
        (
            RawHit {
                path: "crates/oneiron-server/src/usage/limit.rs".to_owned(),
                ident: "sync_state_put_in_write_txn".to_owned(),
                line: "self.vault.sync_state_put_in_write_txn(txn, &key, &raw)?;".to_owned(),
            },
            1,
        ),
    ])
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
                    import.name().to_owned(),
                    import.write_trap_effect().expect("named write trap"),
                )
                .is_none(),
            "write-import names must be unique",
        );
    }
    // The memory writes reach the guest as verb-table rows the run answers
    // itself, each its own named, gated effect: the same closed set.
    for verb in RunVerb::ALL.iter().filter(|verb| verb.writes()) {
        assert!(
            write_imports
                .insert(format!("self.memory.{}", verb.as_str()), verb.effect())
                .is_none(),
            "write-import names must be unique",
        );
    }
    assert_eq!(
        write_imports,
        BTreeMap::from([
            (
                "self.memory.put_claim".to_owned(),
                SelfEffect::MemoryPutClaim
            ),
            (
                "self.memory.supersede_claim".to_owned(),
                SelfEffect::MemorySupersedeClaim,
            ),
            ("self.memory.put_edge".to_owned(), SelfEffect::MemoryPutEdge),
            ("self.report_blocked".to_owned(), SelfEffect::ReportBlocked),
        ]),
        "OF-060 P3: write imports must map exactly to authorized memory effects and the blocked-report receipt",
    );
    for verb in RunVerb::ALL {
        assert_ne!(
            verb.effect(),
            SelfEffect::MemoryWriteFixture,
            "OF-060 P3: a run row must not expose the fixture write effect",
        );
    }

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
