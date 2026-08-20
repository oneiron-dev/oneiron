use super::*;
use crate::Vault;
use crate::attempt_queue::{ATTEMPT_RECORD_VERSION, AttemptQueue, EnqueueAttempt, EnqueueOutcome};
use crate::entity_id::EntityId;
use crate::error::ErrorKind;
use crate::receipt::MAX_RECEIPT_QUERY_SCAN;
use crate::temporal::TimeRange;
use crate::test_util::assert_secret_scan_rejected;
use std::collections::BTreeMap;
use std::sync::{Arc, Barrier};

// The flat store.rs module used to provide these names to `use super::*`;
// after the directory split the externals are imported directly.
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::companion::{COMPANION_REGISTER_PACK_ID, COMPANION_REGISTER_SHORT_ID_PREFIX};
use crate::config::VaultConfig;
use crate::error::{Error, Result};
use crate::registry::{TypeByteZone, zone_of};
use heed::RwTxn;
use heed::types::Bytes;
use std::collections::BTreeSet;
use std::path::Path;
use std::str;

fn is_primary_gate_decision_key_expr(fragment: &str) -> bool {
    fragment.contains("gate_decision_key(")
        && !fragment.contains("pending_deletion_gate_decision_key(")
}

fn statement_starts_fn_item(statement: &str) -> bool {
    for line in statement.lines() {
        let t = line.trim_start();

        let t = t
            .strip_prefix("pub(crate) ")
            .or_else(|| t.strip_prefix("pub(super) "))
            .or_else(|| t.strip_prefix("pub "))
            .unwrap_or(t);

        if t.starts_with("fn ") {
            return true;
        }
    }

    false
}

/// First `let <ident> = ...` / `let mut <ident>: ...` name in a semicolon chunk.
fn let_binding_ident(statement: &str) -> Option<&str> {
    let bytes = statement.as_bytes();

    let mut search = 0;

    while search < statement.len() {
        let rel = statement[search..].find("let ")?;

        let abs = search + rel;

        if abs > 0 {
            let prev = bytes[abs - 1] as char;

            if prev.is_ascii_alphanumeric() || prev == '_' {
                search = abs + 4;

                continue;
            }
        }

        let mut rest = statement[abs + 4..].trim_start();

        if let Some(stripped) = rest.strip_prefix("mut ") {
            rest = stripped.trim_start();
        }

        let name_len = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .map(char::len_utf8)
            .sum::<usize>();

        if name_len == 0 {
            search = abs + 4;

            continue;
        }

        let name = &rest[..name_len];

        let after = rest[name_len..].trim_start();

        if after.starts_with('=') || after.starts_with(':') {
            return Some(name);
        }

        search = abs + 4;
    }

    None
}

fn delete_references_amp_ident(statement: &str, name: &str) -> bool {
    let needle = format!("&{name}");

    let bytes = statement.as_bytes();

    let mut search = 0;

    while let Some(rel) = statement[search..].find(&needle) {
        let abs = search + rel;

        let after = abs + needle.len();

        let ok_after = after >= statement.len()
            || (!bytes[after].is_ascii_alphanumeric() && bytes[after] != b'_');

        if ok_after {
            return true;
        }

        search = abs + 1;
    }

    false
}

fn open_test_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(VaultConfig::device())
}

fn entity_id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("test ids should be valid")
}

/// The ABI handshake stays strictly symmetric for EVERY stored version, with
/// exactly one carve-out: ONE-1754's immediate predecessor routes to the
/// byte-space v3 re-key instead of erroring. Iterating the whole u16 space is
/// the point — it proves the carve-out is one value wide, not a range.
#[test]
fn storage_abi_gate_is_strictly_symmetric_for_every_stored_version() {
    for stored in 0..=u16::MAX {
        let result = gate_storage_abi_value(Some(stored), STORAGE_ABI_VERSION, false);
        if stored == STORAGE_ABI_VERSION {
            assert_eq!(
                result.expect("equal ABI versions must open"),
                StorageAbiGate::Current
            );
        } else if stored == STORAGE_ABI_VERSION_V3_REKEY_PREDECESSOR {
            assert_eq!(
                result.expect("the immediate predecessor opens for the v3 re-key"),
                StorageAbiGate::RekeyByteSpaceV3
            );
        } else {
            assert!(
                matches!(
                    result,
                    Err(Error::StorageAbiVersionChanged {
                        stored: Some(actual),
                        current: STORAGE_ABI_VERSION,
                    }) if actual == stored
                ),
                "stored ABI {stored} must fail against current ABI {STORAGE_ABI_VERSION}",
            );
        }
    }

    // The carve-out is pinned to the CURRENT version. A reader running some
    // other ABI must not inherit an accept-the-predecessor branch.
    assert!(matches!(
        gate_storage_abi_value(
            Some(STORAGE_ABI_VERSION_V3_REKEY_PREDECESSOR),
            STORAGE_ABI_VERSION + 1,
            false
        ),
        Err(Error::StorageAbiVersionChanged { .. })
    ));

    assert_eq!(
        gate_storage_abi_value(None, STORAGE_ABI_VERSION, true)
            .expect("a genuinely new vault initializes its ABI row"),
        StorageAbiGate::StampCurrent
    );
    assert!(matches!(
        gate_storage_abi_value(None, STORAGE_ABI_VERSION, false),
        Err(Error::StorageAbiVersionChanged {
            stored: None,
            current: STORAGE_ABI_VERSION,
        })
    ));
}

#[test]
fn receipt_family_versions_require_a_storage_abi_bump() {
    const RECEIPT_FAMILY_VERSION_ABI_PINS: &[(u16, [u8; 5])] = &[(17, [0, 2, 0, 1, 1])];

    let receipt_versions = [
        GATE_DECISION_LEDGER_VERSION,
        ATTEMPT_RECORD_VERSION,
        PENDING_GATE_CONSENT_VERSION,
        PENDING_GATE_CONSENT_INDEX_STATE_VERSION,
        RECEIPT_FAMILY_INDEX_VERSION,
    ];
    assert!(
        RECEIPT_FAMILY_VERSION_ABI_PINS.contains(&(STORAGE_ABI_VERSION, receipt_versions)),
        "receipt-family versions must be explicitly pinned to STORAGE_ABI_VERSION",
    );

    assert!(receipt_family_version_abi_pins_are_strictly_monotonic(
        RECEIPT_FAMILY_VERSION_ABI_PINS
    ));
    for (axis, changed_versions) in [
        ("gate decision ledger", [1, 2, 0, 1, 1]),
        ("attempt record", [0, 3, 0, 1, 1]),
        ("pending consent body", [0, 2, 1, 1, 1]),
        ("pending consent index state", [0, 2, 0, 2, 1]),
        ("receipt family index", [0, 2, 0, 1, 2]),
    ] {
        assert!(
            !RECEIPT_FAMILY_VERSION_ABI_PINS.contains(&(STORAGE_ABI_VERSION, changed_versions)),
            "an unbumped {axis} version must not satisfy the ABI pin",
        );
    }
    assert!(!receipt_family_version_abi_pins_are_strictly_monotonic(&[
        (11, [0, 2, 0, 1, 1]),
        (11, [2, 4, 1, 3, 3]),
    ]));
    assert!(!receipt_family_version_abi_pins_are_strictly_monotonic(&[
        (11, [0, 2, 0, 1, 1]),
        (12, [0, 1, 1, 3, 2]),
    ]));
    assert!(receipt_family_version_abi_pins_are_strictly_monotonic(&[
        (11, [0, 2, 0, 1, 1]),
        (12, [1, 3, 1, 2, 2]),
    ]));
}

fn receipt_family_version_abi_pins_are_strictly_monotonic(pins: &[(u16, [u8; 5])]) -> bool {
    pins.windows(2).all(|pair| {
        let (previous_abi, previous_versions) = pair[0];
        let (current_abi, current_versions) = pair[1];
        current_abi > previous_abi
            && current_versions
                .iter()
                .zip(previous_versions)
                .all(|(current, previous)| current >= &previous)
            && current_versions != previous_versions
    })
}

#[test]
fn current_abi_vault_is_rejected_before_an_older_abi_reader_checks_receipt_markers() -> Result<()> {
    // 12 is an arbitrary OLDER reader, pinned as a literal because it names a
    // version this engine is not; the vault's own stamp is derived so an ABI
    // bump cannot leave a stale expectation behind.
    const OLDER_READER_ABI: u16 = 12;

    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();
    {
        let vault = Vault::open(path, VaultConfig::device())?;
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.vault_meta.put(
            &mut wtxn,
            RECEIPT_FAMILY_INDEX_VERSION_KEY,
            &[RECEIPT_FAMILY_INDEX_VERSION + 1],
        )?;
        wtxn.commit()?;
    }

    let err = match Store::open_with_storage_abi_version_for_test(
        path,
        &VaultConfig::device(),
        OLDER_READER_ABI,
    ) {
        Ok(_) => panic!(
            "an ABI-{OLDER_READER_ABI} reader must reject an ABI-{STORAGE_ABI_VERSION} vault at \
             the ABI gate"
        ),
        Err(err) => err,
    };
    assert!(matches!(
        err,
        Error::StorageAbiVersionChanged {
            stored: Some(STORAGE_ABI_VERSION),
            current: OLDER_READER_ABI,
        }
    ));
    Ok(())
}

fn put_text(vault: &Vault, id: EntityId, text: &str) -> Result<()> {
    vault
        .batch()
        .put(&id, 1, TimeRange { start: 1, end: 1 }, 1, b"payload")
        .text(&id, &[("body", text)])
        .commit()
}

fn raw_retrieval_run_row(vault: &Vault, run_id: RetrievalRunId) -> Result<Vec<u8>> {
    let rtxn = vault.store.env.read_txn()?;
    vault
        .store
        .vault_meta
        .get(&rtxn, &retrieval_run_key(run_id))?
        .map(|value| value.to_vec())
        .ok_or(Error::CorruptedIndex("retrieval run telemetry"))
}

fn raw_retrieval_outcome_row(
    vault: &Vault,
    run_id: RetrievalRunId,
    outcome_key: &str,
) -> Result<Vec<u8>> {
    let rtxn = vault.store.env.read_txn()?;
    vault
        .store
        .vault_meta
        .get(&rtxn, &retrieval_outcome_key(run_id, outcome_key))?
        .map(|value| value.to_vec())
        .ok_or(Error::CorruptedIndex("retrieval outcome telemetry"))
}

fn record_click_outcome(vault: &Vault, run_id: RetrievalRunId) -> Result<()> {
    vault.record_retrieval_outcome(RetrievalOutcome {
        run_id,
        key: "click".to_owned(),
        reward: Some(1.0),
        accepted: Some(true),
        metadata: BTreeMap::new(),
    })
}

fn synthetic_gate_decision_id(prefix: u8, value: u64) -> GateDecisionId {
    let mut bytes = [prefix; 16];
    bytes[8..].copy_from_slice(&value.to_be_bytes());
    GateDecisionId::from_bytes(bytes)
}

fn gate_decision(
    decision_id: GateDecisionId,
    created_at: u64,
    grant_ref: Option<&str>,
) -> GateDecisionRecord {
    GateDecisionRecord {
        version: GATE_DECISION_LEDGER_VERSION,
        decision_id,
        created_at,
        outcome: "approved".to_owned(),
        reason_codes: vec!["gate.test.receipt_family".to_owned()],
        receipt_reasons: Vec::new(),
        system_notices: Vec::new(),
        actor_class: "agent".to_owned(),
        actor_ref: None,
        content_kind: "claim".to_owned(),
        policy_manifest_version: "v0".to_owned(),
        claim_id: None,
        grant_ref: grant_ref.map(str::to_owned),
        diff_handle: vec![0xAA],
        read_frontier_hash: [0xBB; 32],
        redacted_at: None,
    }
}

#[test]
fn fixed_seed_reopen_repeated_invalidations_use_uuidv7_successors_newest_first() -> Result<()> {
    let (dir, vault) = open_test_vault();
    // Fixed timestamp/random seed models a frozen UUIDv7 clock across retries.
    let seed = GateDecisionId::from_bytes([0, 0, 0, 0, 0, 1, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 0]);
    let mut expected = Vec::new();
    for created_at in 1..=3 {
        let mut record = gate_decision(seed, created_at, None);
        record.outcome = "invalidated".to_owned();
        vault.with_write_txn(|wtxn| {
            vault
                .store
                .append_fresh_gate_decision_in_txn(wtxn, &mut record)
        })?;
        expected.push(record.decision_id);
    }
    drop(vault);
    let reopened = Vault::open(dir.path(), crate::config::VaultConfig::default())?;
    for created_at in 4..=6 {
        let mut record = gate_decision(seed, created_at, None);
        record.outcome = "invalidated".to_owned();
        reopened.with_write_txn(|wtxn| {
            reopened
                .store
                .append_fresh_gate_decision_in_txn(wtxn, &mut record)
        })?;
        expected.push(record.decision_id);
    }
    assert_eq!(
        expected.len(),
        expected
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
    );
    assert!(expected.iter().all(|id| {
        let bytes = id.as_bytes();
        bytes[6] >> 4 == 0x7 && bytes[8] >> 6 == 0b10
    }));
    // The scan is the GLOBAL decision ledger, so it also contains rows this
    // fixture never appended: reopening the vault runs the default-policy seed
    // path (ONE-1869), whose receipt carries a real wall-clock UUIDv7 id and
    // therefore sorts ahead of these frozen-clock successors. Restrict the
    // comparison to this fixture's own fixed-seed timestamp prefix — the six
    // ids under test all share `seed`'s 6-byte UUIDv7 timestamp — so the
    // newest-first ordering assertion stays exact without asserting anything
    // about seeding.
    let seed_timestamp_prefix = &seed.as_bytes()[..6];
    assert_eq!(
        reopened
            .store
            .gate_decisions(10)?
            .into_iter()
            .map(|record| record.decision_id)
            .filter(|decision_id| &decision_id.as_bytes()[..6] == seed_timestamp_prefix)
            .collect::<Vec<_>>(),
        expected.into_iter().rev().collect::<Vec<_>>(),
        "reverse primary-key scan remains newest-first after logical successors"
    );
    Ok(())
}

#[test]
fn rollback_deletes_the_grant_ref_index_row_with_the_primary() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let grant_ref = "bundle:dreamer_run:p6-rollback";
    let d1 = gate_decision(synthetic_gate_decision_id(0x61, 1), 1, Some(grant_ref));
    let d2 = gate_decision(synthetic_gate_decision_id(0x62, 2), 2, None);
    vault.with_write_txn(|wtxn| {
        vault.store.append_gate_decision_in_txn(wtxn, &d1)?;
        vault.store.append_gate_decision_in_txn(wtxn, &d2)?;
        Ok(())
    })?;

    vault.with_write_txn(|wtxn| {
        vault
            .store
            .delete_gate_decision_in_txn(wtxn, d1.decision_id)?;
        vault
            .store
            .delete_gate_decision_in_txn(wtxn, d2.decision_id)?;
        Ok(())
    })?;

    assert!(
        vault
            .store
            .gate_decisions_for_grant_ref(grant_ref)?
            .is_empty()
    );
    assert!(gate_decision_primary(&vault, d1.decision_id)?.is_none());
    assert!(gate_decision_primary(&vault, d2.decision_id)?.is_none());
    assert_eq!(grant_ref_index_row_count(&vault)?, 0);
    Ok(())
}

fn gate_decision_primary(
    vault: &Vault,
    decision_id: GateDecisionId,
) -> Result<Option<GateDecisionRecord>> {
    let rtxn = vault.store.env.read_txn()?;
    vault.store.gate_decision_in_txn(&rtxn, decision_id)
}

fn grant_ref_index_row_count(vault: &Vault) -> Result<usize> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, GATE_DECISION_GRANT_REF_INDEX_PREFIX)?
        .count())
}

/// A `grant_ref: None` record has no sidecar row of its own, so its deletion
/// must be a plain primary delete — never a delete that reaches into another
/// decision's index rows.
#[test]
fn delete_without_grant_ref_has_no_sidecar_effect() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let grant_ref = "bundle:dreamer_run:p6-no-sidecar";
    let claim = [0x31; 16];
    let indexed = gate_decision(synthetic_gate_decision_id(0x63, 1), 1, Some(grant_ref));
    let claim_bound = claim_bound_gate_decision(synthetic_gate_decision_id(0x64, 2), 2, &claim);
    let bare = gate_decision(synthetic_gate_decision_id(0x65, 3), 3, None);
    append_gate_decisions(
        &vault,
        &[indexed.clone(), claim_bound.clone(), bare.clone()],
    )?;

    vault.with_write_txn(|wtxn| {
        vault
            .store
            .delete_gate_decision_in_txn(wtxn, bare.decision_id)
    })?;

    assert!(gate_decision_primary(&vault, bare.decision_id)?.is_none());
    assert_eq!(
        vault.store.gate_decisions_for_grant_ref(grant_ref)?,
        vec![indexed]
    );
    assert_eq!(grant_ref_index_row_count(&vault)?, 1);
    assert_eq!(
        claim_index_decision_ids(&vault, &claim)?,
        vec![claim_bound.decision_id]
    );
    assert_eq!(claim_index_row_count(&vault)?, 1);
    Ok(())
}

/// After a delete, the grant-ref index must describe exactly the survivors:
/// no `CorruptedIndex` from a row pointing at a removed primary, and no
/// collateral loss of a sibling under the same grant ref.
#[test]
fn grant_ref_lookup_after_delete_is_consistent() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let grant_ref = "bundle:dreamer_run:p6-survivors";
    let other_ref = "bundle:dreamer_run:p6-untouched";
    let deleted = gate_decision(synthetic_gate_decision_id(0x66, 1), 1, Some(grant_ref));
    let survivor = gate_decision(synthetic_gate_decision_id(0x67, 2), 2, Some(grant_ref));
    let newer_survivor = gate_decision(synthetic_gate_decision_id(0x69, 3), 3, Some(grant_ref));
    let unrelated = gate_decision(synthetic_gate_decision_id(0x6A, 4), 4, Some(other_ref));
    append_gate_decisions(
        &vault,
        &[
            deleted.clone(),
            survivor.clone(),
            newer_survivor.clone(),
            unrelated.clone(),
        ],
    )?;

    vault.with_write_txn(|wtxn| {
        vault
            .store
            .delete_gate_decision_in_txn(wtxn, deleted.decision_id)
    })?;

    assert!(gate_decision_primary(&vault, deleted.decision_id)?.is_none());
    assert_eq!(
        vault.store.gate_decisions_for_grant_ref(grant_ref)?,
        vec![newer_survivor, survivor]
    );
    assert_eq!(
        vault.store.gate_decisions_for_grant_ref(other_ref)?,
        vec![unrelated]
    );
    assert_eq!(grant_ref_index_row_count(&vault)?, 3);
    Ok(())
}

/// Source-level guard for the ONE-1883 invariant: a primary `gate_decision:v0:`
/// row may only be removed inside `delete_gate_decision_record_in_txn`, which
/// also drops the grant-ref and claim index rows. A future deleter that reaches
/// for `vault_meta.delete` directly fails here instead of silently orphaning an
/// index row — including the two-statement key-alias form
/// `let key = gate_decision_key(...); ...delete(..., &key)`. The
/// `gate_delete_pending:v0:` recovery sidecar is a distinct keyspace and is
/// deliberately not counted.
///
/// The scanned source is gathered by reading the `store/` directory at test
/// time — every `*.rs` file except this one, sorted for determinism — so a
/// submodule added later cannot escape the invariant while the guard keeps
/// passing. A minimum-file-count floor keeps an empty or mislocated directory
/// from passing vacuously.
#[test]
fn only_the_central_helper_deletes_a_primary_gate_decision_row() {
    use std::collections::HashSet;

    let store_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/store");
    let mut sources: Vec<std::path::PathBuf> = std::fs::read_dir(&store_dir)
        .expect("the store module directory must be readable")
        .map(|entry| {
            entry
                .expect("store directory entries must be readable")
                .path()
        })
        .filter(|path| {
            path.extension().is_some_and(|ext| ext == "rs")
                && path.file_name().is_some_and(|name| name != "tests.rs")
        })
        .collect();
    sources.sort();

    // Fail-closed floor: the store module held 13 non-test files when this
    // guard was written. The floor is a minimum, not a count — files added
    // later are picked up automatically and need no update here.
    assert!(
        sources.len() >= 13,
        "the store source scan found only {} files in {} — the scan is mislocated",
        sources.len(),
        store_dir.display(),
    );

    let store_src: String = sources
        .iter()
        .map(|path| {
            std::fs::read_to_string(path)
                .unwrap_or_else(|err| panic!("reading {} must succeed: {err}", path.display()))
        })
        .collect::<Vec<_>>()
        .join("\n");
    let store_src = store_src.as_str();

    let helper_start = store_src
        .find("fn delete_gate_decision_record_in_txn(")
        .expect("the central gate-decision delete helper must exist");
    let helper_end = helper_start
        + store_src[helper_start..]
            .find("\n    }\n")
            .expect("the helper body must terminate at method indentation");

    let mut primary_key_aliases: HashSet<String> = HashSet::new();
    let mut offset = 0;
    let mut offenders = Vec::new();
    for statement in store_src.split_inclusive(';') {
        // Drop aliases across fn items so a prior `let key = gate_decision_key(...)`
        // cannot false-positive a later function's unrelated `&key` delete
        // (e.g. pending-deletion sidecar cleanup).
        if statement_starts_fn_item(statement) {
            primary_key_aliases.clear();
        }

        if let Some(name) = let_binding_ident(statement) {
            if is_primary_gate_decision_key_expr(statement) {
                primary_key_aliases.insert(name.to_owned());
            } else {
                primary_key_aliases.remove(name);
            }
        }

        if statement.contains(".delete(") {
            let direct = is_primary_gate_decision_key_expr(statement);
            let via_alias = primary_key_aliases
                .iter()
                .any(|name| delete_references_amp_ident(statement, name));
            if (direct || via_alias) && !(helper_start..helper_end).contains(&offset) {
                offenders.push(statement.trim().to_owned());
            }
        }

        offset += statement.len();
    }

    assert!(
        offenders.is_empty(),
        "primary gate-decision deletes outside delete_gate_decision_record_in_txn: {offenders:#?}",
    );
}

#[test]
fn grant_ref_index_reaches_a_receipt_beyond_the_legacy_scan_budget() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let grant_ref = "bundle:dreamer_run:older-target";
    // The old ledger query reads newest-first.  Keep the matching record
    // below 100,001 newer unrelated records so a bounded global scan cannot
    // rediscover it by accident.
    let target = gate_decision(synthetic_gate_decision_id(0x01, 1), 1, Some(grant_ref));
    vault.with_write_txn(|wtxn| {
        vault.store.append_gate_decision_in_txn(wtxn, &target)?;
        for offset in 0..=MAX_RECEIPT_QUERY_SCAN {
            let filler = gate_decision(
                synthetic_gate_decision_id(0xF1, offset as u64),
                10 + offset as u64,
                None,
            );
            vault.store.append_gate_decision_in_txn(wtxn, &filler)?;
        }
        Ok(())
    })?;

    let legacy_scan = vault.store.gate_decisions(MAX_RECEIPT_QUERY_SCAN)?;
    assert_eq!(legacy_scan.len(), MAX_RECEIPT_QUERY_SCAN);
    assert!(
        legacy_scan
            .iter()
            .all(|record| record.grant_ref.as_deref() != Some(grant_ref))
    );
    assert_eq!(
        vault.store.gate_decisions_for_grant_ref(grant_ref)?,
        vec![target]
    );
    Ok(())
}

/// The pending-consent tray is versioned on its OWN constant.
///
/// The two families share a numeric value today, so no round-trip can tell
/// them apart; what a stored row cannot survive is the DECISION ledger being
/// bumped while the pending body stays where it is. Reading the validator's
/// source is the only way to pin that from here, and it is the same technique
/// the primary-gate-decision guard above uses.
#[test]
fn the_pending_consent_tray_validates_against_its_own_version() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/store/pending_gate_consent.rs");
    let src = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("reading {} must succeed: {err}", path.display()));
    let start = src
        .find("fn vet_pending_gate_consent_record(")
        .expect("the pending-consent validator must be findable by its signature");
    let end = start
        + src[start..]
            .find("\n}\n")
            .expect("the pending-consent validator must terminate");
    let body = &src[start..end];

    assert!(
        body.contains("PENDING_GATE_CONSENT_VERSION"),
        "the pending-consent body version must be its own pin",
    );
    assert!(
        !body.contains("GATE_DECISION_LEDGER_VERSION"),
        "a decision-ledger bump must not decode every stored pending row as corrupt",
    );
    // The pin is on the value already on disk, not a new one.
    assert_eq!(PENDING_GATE_CONSENT_VERSION, 0);
}

/// A row written at the pending family's own version still round-trips
/// through the tray unchanged.
#[test]
fn a_pending_consent_row_round_trips_at_its_own_version() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    let decision = gate_decision(synthetic_gate_decision_id(0x51, 3), 3, None);
    let pending = PendingGateConsentRecord {
        version: PENDING_GATE_CONSENT_VERSION,
        claim_id: [0x52; 16],
        decision_id: decision.decision_id,
        created_at: 3,
        diff_handle: decision.diff_handle.clone(),
        read_frontier_hash: decision.read_frontier_hash,
        reason_codes: vec!["gate.pending.round_trip".to_owned()],
        dreamer_run_id: None,
    };
    vault.with_write_txn(|wtxn| {
        vault.store.append_gate_decision_in_txn(wtxn, &decision)?;
        vault.store.put_pending_gate_consent_in_txn(wtxn, &pending)
    })?;

    let rtxn = vault.store.env.read_txn()?;
    let stored = vault
        .store
        .pending_gate_consent_in_txn(&rtxn, &EntityId::from_bytes(pending.claim_id)?)?
        .expect("pending row is stored");

    assert_eq!(stored, pending);
    Ok(())
}

#[test]
fn open_backfills_receipt_family_sidecars_without_a_storage_abi_change() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let config = VaultConfig::device();
    let run_id = "legacy-receipt-family-run";
    let grant_ref = "bundle:dreamer_run:legacy-receipt-family-run";
    let decision = gate_decision(synthetic_gate_decision_id(0x44, 7), 7, Some(grant_ref));
    let pending = PendingGateConsentRecord {
        version: PENDING_GATE_CONSENT_VERSION,
        claim_id: [0x77; 16],
        decision_id: decision.decision_id,
        created_at: 7,
        diff_handle: decision.diff_handle.clone(),
        read_frontier_hash: decision.read_frontier_hash,
        reason_codes: vec!["gate.pending.receipt_family".to_owned()],
        dreamer_run_id: Some(run_id.to_owned()),
    };

    let vault = Vault::open(dir.path(), config.clone())?;
    let queue = AttemptQueue::new(&vault);
    let EnqueueOutcome::Enqueued(attempt) = queue.enqueue(EnqueueAttempt {
        kind: "legacy-receipt-family".to_owned(),
        payload: b"legacy".to_vec(),
        dedupe_key: None,
        run_id: Some(run_id.to_owned()),
        now: 7,
    })?
    else {
        panic!("expected a fresh legacy attempt");
    };
    vault.with_write_txn(|wtxn| {
        vault.store.append_gate_decision_in_txn(wtxn, &decision)?;
        vault
            .store
            .put_pending_gate_consent_in_txn(wtxn, &pending)?;

        for prefix in [
            GATE_DECISION_GRANT_REF_INDEX_PREFIX,
            PENDING_GATE_CONSENT_RUN_INDEX_PREFIX,
            PENDING_GATE_CONSENT_GROUP_INDEX_PREFIX,
            PENDING_GATE_CONSENT_HASH_INDEX_PREFIX,
            PENDING_GATE_CONSENT_INDEX_STATE_PREFIX,
            ATTEMPT_RUN_INDEX_PREFIX,
        ] {
            let mut keys = Vec::new();
            for row in vault.store.vault_meta.prefix_iter(&*wtxn, prefix)? {
                let (key, _) = row?;
                keys.push(key.to_vec());
            }
            for key in keys {
                vault.store.vault_meta.delete(wtxn, &key)?;
            }
        }
        vault
            .store
            .vault_meta
            .delete(wtxn, RECEIPT_FAMILY_INDEX_VERSION_KEY)?;
        Ok(())
    })?;
    drop(vault);

    let reopened = Vault::open(dir.path(), config)?;
    assert_eq!(
        AttemptQueue::new(&reopened).list_run(run_id)?,
        vec![
            AttemptQueue::new(&reopened)
                .get(attempt.id)?
                .expect("backfilled attempt")
        ]
    );
    assert_eq!(
        reopened.store.gate_decisions_for_grant_ref(grant_ref)?,
        vec![decision]
    );
    assert_eq!(
        reopened.store.pending_gate_consents_for_run(run_id)?,
        vec![pending.clone()]
    );
    assert_eq!(
        reopened.store.pending_gate_consents_for_group_key(run_id)?,
        vec![pending]
    );
    let rtxn = reopened.store.env.read_txn()?;
    assert_eq!(
        reopened
            .store
            .vault_meta
            .get(&rtxn, RECEIPT_FAMILY_INDEX_VERSION_KEY)?
            .as_deref(),
        Some(&[RECEIPT_FAMILY_INDEX_VERSION][..])
    );
    Ok(())
}

#[test]
fn retrieval_run_without_trace_omits_trace_field_from_msgpack() -> Result<()> {
    let record = RetrievalRunRecord::new(
        RetrievalRunId::now(),
        RetrievalAction::Pipeline,
        1,
        2,
        vec![RetrievalSignal::Text],
        Vec::new(),
        0,
        0,
        None,
    );

    assert!(record.trace.is_none());
    let encoded = encode_retrieval_run(&record)?;
    let encoded_value =
        rmpv::decode::read_value(&mut &encoded[..]).expect("encoded retrieval run msgpack");
    let rmpv::Value::Map(fields) = encoded_value else {
        panic!("encoded retrieval run must be a msgpack map");
    };
    assert!(
        fields.iter().all(|(key, _)| key.as_str() != Some("trace")),
        "flag-off trace extension must omit the top-level trace key"
    );
    let decoded = decode_retrieval_run(&encoded)?;
    assert_eq!(decoded.trace, None);
    Ok(())
}

#[test]
fn context_pack_finalization_preserves_reranked_trace_stage() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let run_id = RetrievalRunId::now();
    let kept = entity_id(0xD1);
    let dropped = entity_id(0xD2);
    let score_breakdown = vec![
        RetrievalScoreBreakdown {
            result_id: *kept.as_bytes(),
            final_rank: 1,
            final_score: 2.0,
            components: vec![RetrievalScoreComponent {
                signal: RetrievalSignal::Text,
                rank: 1,
                score: 2.0,
            }],
        },
        RetrievalScoreBreakdown {
            result_id: *dropped.as_bytes(),
            final_rank: 2,
            final_score: 1.0,
            components: vec![RetrievalScoreComponent {
                signal: RetrievalSignal::Text,
                rank: 2,
                score: 1.0,
            }],
        },
    ];
    let record = RetrievalRunRecord::new(
        run_id,
        RetrievalAction::ContextPack,
        1,
        2,
        vec![RetrievalSignal::Text],
        score_breakdown.clone(),
        0,
        0,
        None,
    )
    .with_trace(Some(RetrievalTrace {
        fork_hash: [0xD0; 32],
        per_channel: Vec::new(),
        fused: RetrievalTraceStageRecord {
            stage: RetrievalTraceStage::Fused,
            candidates: score_breakdown.clone(),
        },
        blended: RetrievalTraceStageRecord {
            stage: RetrievalTraceStage::Blended,
            candidates: score_breakdown.clone(),
        },
        reranked: RetrievalTraceStageRecord {
            stage: RetrievalTraceStage::Reranked,
            candidates: score_breakdown.clone(),
        },
        final_stage: RetrievalTraceStageRecord {
            stage: RetrievalTraceStage::Final,
            candidates: score_breakdown,
        },
    }));
    vault.store.record_retrieval_run(&record)?;

    vault
        .store
        .finalize_context_pack_retrieval_run(run_id, 10, 0, &[*kept.as_bytes()], None)?;

    let finalized = vault
        .retrieval_run(run_id)?
        .expect("finalized context-pack run");
    let trace = finalized.trace.expect("trace remains present");
    assert_eq!(trace.reranked.candidates.len(), 2);
    assert_eq!(trace.final_stage.candidates.len(), 1);
    assert_eq!(trace.reranked.candidates[1].result_id, *dropped.as_bytes());
    assert_eq!(trace.final_stage.candidates[0].result_id, *kept.as_bytes());
    Ok(())
}

#[test]
fn provisional_context_pack_trace_is_hidden_until_finalized() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let run_id = RetrievalRunId::now();
    let kept = entity_id(0xD3);
    let score_breakdown = vec![RetrievalScoreBreakdown {
        result_id: *kept.as_bytes(),
        final_rank: 1,
        final_score: 2.0,
        components: vec![RetrievalScoreComponent {
            signal: RetrievalSignal::Text,
            rank: 1,
            score: 2.0,
        }],
    }];
    let fork_hash = [0xD3; 32];
    let record = RetrievalRunRecord::new(
        run_id,
        RetrievalAction::ContextPack,
        1,
        2,
        vec![RetrievalSignal::Text],
        score_breakdown.clone(),
        0,
        0,
        None,
    )
    .with_trace(Some(RetrievalTrace {
        fork_hash,
        per_channel: Vec::new(),
        fused: RetrievalTraceStageRecord {
            stage: RetrievalTraceStage::Fused,
            candidates: score_breakdown.clone(),
        },
        blended: RetrievalTraceStageRecord {
            stage: RetrievalTraceStage::Blended,
            candidates: score_breakdown.clone(),
        },
        reranked: RetrievalTraceStageRecord {
            stage: RetrievalTraceStage::Reranked,
            candidates: score_breakdown.clone(),
        },
        final_stage: RetrievalTraceStageRecord {
            stage: RetrievalTraceStage::Final,
            candidates: score_breakdown,
        },
    }));

    vault
        .store
        .record_context_pack_provisional_retrieval_run(&record)?;
    assert!(
        vault.retrieval_trace_by_fork_hash(fork_hash)?.is_none(),
        "provisional context-pack traces must not be fork-hash visible"
    );

    vault
        .store
        .finalize_context_pack_retrieval_run(run_id, 10, 0, &[*kept.as_bytes()], None)?;

    assert_eq!(
        vault
            .retrieval_trace_by_fork_hash(fork_hash)?
            .expect("finalized trace should be fork-hash visible")
            .fork_hash,
        fork_hash
    );
    Ok(())
}

#[test]
fn unknown_zero_retrieval_trace_fork_hash_is_not_indexed() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let run_id = RetrievalRunId::now();
    let id = entity_id(0xD4);
    let score_breakdown = vec![RetrievalScoreBreakdown {
        result_id: *id.as_bytes(),
        final_rank: 1,
        final_score: 1.0,
        components: vec![RetrievalScoreComponent {
            signal: RetrievalSignal::Text,
            rank: 1,
            score: 1.0,
        }],
    }];
    let record = RetrievalRunRecord::new(
        run_id,
        RetrievalAction::Pipeline,
        1,
        2,
        vec![RetrievalSignal::Text],
        score_breakdown.clone(),
        0,
        0,
        None,
    )
    .with_trace(Some(RetrievalTrace {
        fork_hash: [0; 32],
        per_channel: Vec::new(),
        fused: RetrievalTraceStageRecord {
            stage: RetrievalTraceStage::Fused,
            candidates: score_breakdown.clone(),
        },
        blended: RetrievalTraceStageRecord {
            stage: RetrievalTraceStage::Blended,
            candidates: score_breakdown.clone(),
        },
        reranked: RetrievalTraceStageRecord {
            stage: RetrievalTraceStage::Reranked,
            candidates: score_breakdown.clone(),
        },
        final_stage: RetrievalTraceStageRecord {
            stage: RetrievalTraceStage::Final,
            candidates: score_breakdown,
        },
    }));

    vault.store.record_retrieval_run(&record)?;

    assert!(
        vault.retrieval_trace_by_fork_hash([0; 32])?.is_none(),
        "all-zero fork hash is the legacy unknown sentinel, not an index key"
    );
    Ok(())
}

#[test]
fn delete_retrieval_run_removes_fork_index_when_run_row_is_corrupt() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let run_id = RetrievalRunId::now();
    let id = entity_id(0xD5);
    let score_breakdown = vec![RetrievalScoreBreakdown {
        result_id: *id.as_bytes(),
        final_rank: 1,
        final_score: 1.0,
        components: vec![RetrievalScoreComponent {
            signal: RetrievalSignal::Text,
            rank: 1,
            score: 1.0,
        }],
    }];
    let fork_hash = [0xD5; 32];
    let record = RetrievalRunRecord::new(
        run_id,
        RetrievalAction::Pipeline,
        1,
        2,
        vec![RetrievalSignal::Text],
        score_breakdown.clone(),
        0,
        0,
        None,
    )
    .with_trace(Some(RetrievalTrace {
        fork_hash,
        per_channel: Vec::new(),
        fused: RetrievalTraceStageRecord {
            stage: RetrievalTraceStage::Fused,
            candidates: score_breakdown.clone(),
        },
        blended: RetrievalTraceStageRecord {
            stage: RetrievalTraceStage::Blended,
            candidates: score_breakdown.clone(),
        },
        reranked: RetrievalTraceStageRecord {
            stage: RetrievalTraceStage::Reranked,
            candidates: score_breakdown.clone(),
        },
        final_stage: RetrievalTraceStageRecord {
            stage: RetrievalTraceStage::Final,
            candidates: score_breakdown,
        },
    }));

    vault.store.record_retrieval_run(&record)?;
    assert!(vault.retrieval_trace_by_fork_hash(fork_hash)?.is_some());

    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .vault_meta
        .put(&mut wtxn, &retrieval_run_key(run_id), b"not-msgpack")?;
    wtxn.commit()?;

    vault.store.delete_retrieval_run(run_id)?;
    assert!(
        vault.retrieval_trace_by_fork_hash(fork_hash)?.is_none(),
        "delete must self-heal stale fork-index rows even when the run row is undecodable"
    );
    Ok(())
}

#[test]
fn delete_retrieval_run_removes_fork_index_when_run_has_no_trace() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let run_id = RetrievalRunId::now();
    let fork_hash = [0xD6; 32];
    let record = RetrievalRunRecord::new(
        run_id,
        RetrievalAction::Pipeline,
        1,
        2,
        vec![RetrievalSignal::Text],
        Vec::new(),
        0,
        0,
        None,
    );

    vault.store.record_retrieval_run(&record)?;
    let mut wtxn = vault.store.env.write_txn()?;
    vault.store.vault_meta.put(
        &mut wtxn,
        &retrieval_trace_fork_key(&fork_hash, run_id),
        b"1",
    )?;
    wtxn.commit()?;

    vault.store.delete_retrieval_run(run_id)?;
    assert!(
        vault.retrieval_trace_by_fork_hash(fork_hash)?.is_none(),
        "delete must self-heal stale fork-index rows when the run row has no trace"
    );
    Ok(())
}

#[test]
fn register_structural_kind_rejects_secret_pack_before_vault_meta_write() {
    let (_dir, vault) = open_test_vault();

    let error = vault
        .register_structural_kind(
            110,
            "zz",
            TypeByteZone::CompiledProduct,
            "ghp_0123456789abcdefghijklmnopqrstuvwxyz",
        )
        .expect_err("secret-shaped structural pack must reject");

    assert_secret_scan_rejected(error, "gate.secret_scan.github_token");
    assert!(vault.structural_kind_registration(65).is_none());
    assert!(vault.store.structural_kind_registrations().is_empty());
}

#[test]
fn store_metadata_allows_secret_prefix_embedded_in_larger_identifier() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let registration = vault.register_structural_kind(
        110,
        "zz",
        TypeByteZone::CompiledProduct,
        "myghp_0123456789abcdefghijklmnopqrstuvwxyz_label",
    )?;
    assert_eq!(
        registration.pack,
        "myghp_0123456789abcdefghijklmnopqrstuvwxyz_label"
    );

    let id = entity_id(0x47);
    put_text(&vault, id, "retrieval outcome embedded prefix")?;
    let result = vault
        .query()
        .search_text("retrieval outcome embedded prefix", 10)
        .run_with_telemetry()?;
    let run_id = result.run_id.expect("telemetry run id");
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "source".to_owned(),
        "myghp_0123456789abcdefghijklmnopqrstuvwxyz_label".to_owned(),
    );
    vault.record_retrieval_outcome(RetrievalOutcome {
        run_id,
        key: "click".to_owned(),
        reward: Some(1.0),
        accepted: Some(true),
        metadata,
    })?;

    let outcomes = vault.retrieval_outcomes(run_id)?;
    assert_eq!(outcomes.len(), 1);
    assert_eq!(
        outcomes[0].metadata.get("source").map(String::as_str),
        Some("myghp_0123456789abcdefghijklmnopqrstuvwxyz_label")
    );

    Ok(())
}

#[test]
fn record_retrieval_outcome_rejects_secret_key_and_metadata_before_vault_meta_write() -> Result<()>
{
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x46);
    put_text(&vault, id, "retrieval outcome secret scan")?;
    let result = vault
        .query()
        .search_text("retrieval outcome secret scan", 10)
        .run_with_telemetry()?;
    let run_id = result.run_id.expect("telemetry run id");

    let secret_key_error = vault
        .record_retrieval_outcome(RetrievalOutcome {
            run_id,
            key: "ghp_0123456789abcdefghijklmnopqrstuvwxyz_suffix".to_owned(),
            reward: Some(1.0),
            accepted: Some(true),
            metadata: BTreeMap::new(),
        })
        .expect_err("secret-shaped retrieval outcome key must reject");
    assert_secret_scan_rejected(secret_key_error, "gate.secret_scan.github_token");
    assert!(vault.retrieval_outcomes(run_id)?.is_empty());

    let mut metadata = BTreeMap::new();
    metadata.insert(
        "source".to_owned(),
        "ghp_0123456789abcdefghijklmnopqrstuvwxyz".to_owned(),
    );
    let metadata_error = vault
        .record_retrieval_outcome(RetrievalOutcome {
            run_id,
            key: "click".to_owned(),
            reward: Some(1.0),
            accepted: Some(true),
            metadata,
        })
        .expect_err("secret-shaped retrieval outcome metadata must reject");
    assert_secret_scan_rejected(metadata_error, "gate.secret_scan.github_token");
    assert!(vault.retrieval_outcomes(run_id)?.is_empty());

    Ok(())
}

#[test]
fn retrieval_runs_rejects_malformed_key_shape_and_run_id_mismatch() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x40);
    put_text(&vault, id, "telemetry key shape")?;
    assert_eq!(vault.search_text("telemetry key shape", 10)?.len(), 1);
    let run_id = vault.retrieval_runs(1)?[0].run_id;
    let raw = raw_retrieval_run_row(&vault, run_id)?;
    let mut malformed_key = retrieval_run_key(run_id);
    malformed_key.push(0);
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, &malformed_key, &raw)?;
        Ok(())
    })?;
    let error = vault
        .retrieval_runs(10)
        .expect_err("malformed retrieval run key should fail closed");
    assert!(matches!(
        error,
        Error::CorruptedIndex("retrieval run telemetry")
    ));

    let (_dir, vault) = open_test_vault();
    let first_id = entity_id(0x41);
    let second_id = entity_id(0x42);
    put_text(&vault, first_id, "telemetrykeyfirst")?;
    put_text(&vault, second_id, "telemetrykeysecond")?;
    assert_eq!(vault.search_text("telemetrykeyfirst", 10)?.len(), 1);
    let first_run_id = vault.retrieval_runs(1)?[0].run_id;
    let first_raw = raw_retrieval_run_row(&vault, first_run_id)?;
    std::thread::sleep(std::time::Duration::from_millis(2));
    assert_eq!(vault.search_text("telemetrykeysecond", 10)?.len(), 1);
    let second_run_id = vault.retrieval_runs(1)?[0].run_id;
    let second_key = retrieval_run_key(second_run_id);
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, &second_key, &first_raw)?;
        Ok(())
    })?;
    let error = vault
        .retrieval_runs(10)
        .expect_err("retrieval run key/value id mismatch should fail closed");
    assert!(matches!(
        error,
        Error::CorruptedIndex("retrieval run telemetry")
    ));
    Ok(())
}

#[test]
fn retrieval_outcomes_rejects_key_value_mismatches() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x43);
    put_text(&vault, id, "outcomekeymismatch")?;
    let first = vault
        .query()
        .search_text("outcomekeymismatch", 10)
        .run_with_telemetry()?;
    assert_eq!(first.value.len(), 1);
    let run_id = first.run_id.expect("outcome key mismatch run id");
    record_click_outcome(&vault, run_id)?;
    let raw = raw_retrieval_outcome_row(&vault, run_id, "click")?;
    let wrong_key = retrieval_outcome_key(run_id, "dismiss");
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, &wrong_key, &raw)?;
        Ok(())
    })?;
    let error = vault
        .retrieval_outcomes(run_id)
        .expect_err("outcome key/value key mismatch should fail closed");
    assert!(matches!(
        error,
        Error::CorruptedIndex("retrieval outcome telemetry")
    ));

    let (_dir, vault) = open_test_vault();
    let first_id = entity_id(0x44);
    let second_id = entity_id(0x45);
    put_text(&vault, first_id, "outcomerunfirst")?;
    put_text(&vault, second_id, "outcomerunsecond")?;
    let first = vault
        .query()
        .search_text("outcomerunfirst", 10)
        .run_with_telemetry()?;
    assert_eq!(first.value.len(), 1);
    let first_run_id = first.run_id.expect("first outcome run id");
    record_click_outcome(&vault, first_run_id)?;
    let first_raw = raw_retrieval_outcome_row(&vault, first_run_id, "click")?;
    let second = vault
        .query()
        .search_text("outcomerunsecond", 10)
        .run_with_telemetry()?;
    assert_eq!(second.value.len(), 1);
    let second_run_id = second.run_id.expect("second outcome run id");
    let second_key = retrieval_outcome_key(second_run_id, "click");
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, &second_key, &first_raw)?;
        Ok(())
    })?;
    let error = vault
        .retrieval_outcomes(second_run_id)
        .expect_err("outcome key/value run id mismatch should fail closed");
    assert!(matches!(
        error,
        Error::CorruptedIndex("retrieval outcome telemetry")
    ));
    Ok(())
}

#[test]
fn search_falls_back_to_bootstrap_when_blend_weight_table_is_corrupt() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x4E);
    put_text(&vault, id, "corrupt blend fallback")?;
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .vault_meta
            .put(wtxn, RETRIEVAL_BLEND_WEIGHT_TABLE_KEY, b"not-msgpack")?;
        Ok(())
    })?;

    let table_error = vault
        .retrieval_blend_weight_table()
        .expect_err("administrative table read should still report corruption");
    assert!(matches!(
        table_error,
        Error::CorruptedIndex("retrieval blend weight table")
    ));

    let result = vault
        .query()
        .search_text("corrupt blend fallback", 10)
        .run_with_telemetry()?;
    assert_eq!(result.value.len(), 1);
    assert_eq!(result.value[0].id, id);
    Ok(())
}

#[test]
fn retrieval_blend_tuning_updates_weight_table_from_rewarded_breakdowns() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let run_id = RetrievalRunId::now();
    let positive = entity_id(0x48);
    let negative = entity_id(0x49);
    let record = RetrievalRunRecord::new(
        run_id,
        RetrievalAction::Pipeline,
        100,
        10,
        vec![RetrievalSignal::Text],
        vec![
            RetrievalScoreBreakdown {
                result_id: *positive.as_bytes(),
                final_rank: 1,
                final_score: 2.0,
                components: vec![
                    RetrievalScoreComponent {
                        signal: RetrievalSignal::Recency,
                        rank: 1,
                        score: 1.0,
                    },
                    RetrievalScoreComponent {
                        signal: RetrievalSignal::Salience,
                        rank: 2,
                        score: -1.0,
                    },
                ],
            },
            RetrievalScoreBreakdown {
                result_id: *negative.as_bytes(),
                final_rank: 2,
                final_score: 1.0,
                components: vec![
                    RetrievalScoreComponent {
                        signal: RetrievalSignal::Recency,
                        rank: 2,
                        score: -1.0,
                    },
                    RetrievalScoreComponent {
                        signal: RetrievalSignal::Salience,
                        rank: 1,
                        score: 1.0,
                    },
                ],
            },
        ],
        2,
        0,
        None,
    );
    vault.store.record_retrieval_run(&record)?;
    vault.record_retrieval_outcome(RetrievalOutcome {
        run_id,
        key: "beam.reward".to_owned(),
        reward: Some(1.0),
        accepted: Some(true),
        metadata: BTreeMap::new(),
    })?;

    let before = vault.retrieval_blend_weight_table()?;
    let updated = vault.tune_retrieval_blend_weights(RetrievalBlendTuningConfig {
        max_runs: 10,
        learning_rate: 0.10,
        min_reward_count: 1,
    })?;

    assert!(updated.weights.recency > before.weights.recency);
    assert!(updated.weights.salience < before.weights.salience);
    assert_eq!(updated.data_window.run_count, 1);
    assert_eq!(updated.data_window.outcome_count, 1);
    assert_eq!(updated.data_window.candidate_count, 2);
    assert_eq!(updated.data_window.started_at_min, Some(100));
    assert_eq!(updated.data_window.started_at_max, Some(100));
    assert_eq!(
        updated.provenance.get("algorithm").map(String::as_str),
        Some(RETRIEVAL_BLEND_TUNER_ALGORITHM)
    );
    assert_eq!(vault.retrieval_blend_weight_table()?, updated);
    Ok(())
}

#[test]
fn concurrent_retrieval_blend_tuning_applies_both_gradient_steps() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let run_id = RetrievalRunId::now();
    let record = RetrievalRunRecord::new(
        run_id,
        RetrievalAction::Pipeline,
        200,
        10,
        vec![RetrievalSignal::Text],
        vec![RetrievalScoreBreakdown {
            result_id: *entity_id(0x4F).as_bytes(),
            final_rank: 1,
            final_score: 1.0,
            components: vec![RetrievalScoreComponent {
                signal: RetrievalSignal::Recency,
                rank: 1,
                score: 1.0,
            }],
        }],
        1,
        0,
        None,
    );
    vault.store.record_retrieval_run(&record)?;
    vault.record_retrieval_outcome(RetrievalOutcome {
        run_id,
        key: "beam.reward".to_owned(),
        reward: Some(1.0),
        accepted: Some(true),
        metadata: BTreeMap::new(),
    })?;

    let before = vault.retrieval_blend_weight_table()?;
    let expected_once =
        apply_retrieval_blend_weight_update(before.weights, [1.0, 0.0, 0.0, 0.0], 0.10, 1)?;
    let expected_twice =
        apply_retrieval_blend_weight_update(expected_once, [1.0, 0.0, 0.0, 0.0], 0.10, 1)?;

    let vault = Arc::new(vault);
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let vault = Arc::clone(&vault);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            vault.tune_retrieval_blend_weights(RetrievalBlendTuningConfig {
                max_runs: 1,
                learning_rate: 0.10,
                min_reward_count: 1,
            })
        }));
    }
    barrier.wait();
    for handle in handles {
        handle.join().expect("tuning thread should not panic")?;
    }

    let final_entry = vault.retrieval_blend_weight_table()?;
    assert_eq!(final_entry.weights, expected_twice);
    Ok(())
}

#[test]
fn retrieval_blend_tuning_max_runs_counts_completed_runs_not_provisional_rows() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let completed_run_id = RetrievalRunId::now();
    let completed = RetrievalRunRecord::new(
        completed_run_id,
        RetrievalAction::Pipeline,
        300,
        10,
        vec![RetrievalSignal::Text],
        vec![RetrievalScoreBreakdown {
            result_id: *entity_id(0x4A).as_bytes(),
            final_rank: 1,
            final_score: 1.0,
            components: vec![RetrievalScoreComponent {
                signal: RetrievalSignal::Recency,
                rank: 1,
                score: 1.0,
            }],
        }],
        1,
        0,
        None,
    );
    vault.store.record_retrieval_run(&completed)?;
    vault.record_retrieval_outcome(RetrievalOutcome {
        run_id: completed_run_id,
        key: "beam.reward".to_owned(),
        reward: Some(1.0),
        accepted: Some(true),
        metadata: BTreeMap::new(),
    })?;

    std::thread::sleep(std::time::Duration::from_millis(2));
    let provisional_run_id = RetrievalRunId::now();
    let provisional = RetrievalRunRecord::new(
        provisional_run_id,
        RetrievalAction::ContextPack,
        400,
        10,
        vec![RetrievalSignal::Text],
        vec![RetrievalScoreBreakdown {
            result_id: *entity_id(0x4B).as_bytes(),
            final_rank: 1,
            final_score: 1.0,
            components: vec![RetrievalScoreComponent {
                signal: RetrievalSignal::Salience,
                rank: 1,
                score: 1.0,
            }],
        }],
        1,
        0,
        None,
    );
    vault
        .store
        .record_context_pack_provisional_retrieval_run(&provisional)?;

    let before = vault.retrieval_blend_weight_table()?;
    let updated = vault.tune_retrieval_blend_weights(RetrievalBlendTuningConfig {
        max_runs: 1,
        learning_rate: 0.10,
        min_reward_count: 1,
    })?;

    assert!(updated.weights.recency > before.weights.recency);
    assert_eq!(updated.data_window.run_count, 1);
    assert_eq!(updated.data_window.outcome_count, 1);
    assert_eq!(updated.data_window.started_at_min, Some(300));
    assert_eq!(updated.data_window.started_at_max, Some(300));
    Ok(())
}

#[test]
fn retrieval_blend_tuning_counts_only_blend_contributing_rewards() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let blend_run_id = RetrievalRunId::now();
    let blend = RetrievalRunRecord::new(
        blend_run_id,
        RetrievalAction::Pipeline,
        500,
        10,
        vec![RetrievalSignal::Text],
        vec![RetrievalScoreBreakdown {
            result_id: *entity_id(0x4C).as_bytes(),
            final_rank: 1,
            final_score: 1.0,
            components: vec![RetrievalScoreComponent {
                signal: RetrievalSignal::Recency,
                rank: 1,
                score: 1.0,
            }],
        }],
        1,
        0,
        None,
    );
    vault.store.record_retrieval_run(&blend)?;
    vault.record_retrieval_outcome(RetrievalOutcome {
        run_id: blend_run_id,
        key: "beam.reward".to_owned(),
        reward: Some(1.0),
        accepted: Some(true),
        metadata: BTreeMap::new(),
    })?;

    std::thread::sleep(std::time::Duration::from_millis(2));
    let text_only_run_id = RetrievalRunId::now();
    let text_only = RetrievalRunRecord::new(
        text_only_run_id,
        RetrievalAction::VaultSearch,
        600,
        10,
        vec![RetrievalSignal::Text],
        vec![RetrievalScoreBreakdown {
            result_id: *entity_id(0x4D).as_bytes(),
            final_rank: 1,
            final_score: 10.0,
            components: vec![RetrievalScoreComponent {
                signal: RetrievalSignal::Text,
                rank: 1,
                score: 10.0,
            }],
        }],
        1,
        0,
        None,
    );
    vault.store.record_retrieval_run(&text_only)?;
    vault.record_retrieval_outcome(RetrievalOutcome {
        run_id: text_only_run_id,
        key: "beam.reward".to_owned(),
        reward: Some(1.0),
        accepted: Some(true),
        metadata: BTreeMap::new(),
    })?;

    let error = vault
        .tune_retrieval_blend_weights(RetrievalBlendTuningConfig {
            max_runs: 2,
            learning_rate: 0.10,
            min_reward_count: 2,
        })
        .expect_err("text-only reward should not satisfy min_reward_count");
    assert!(matches!(error, Error::InvalidConfig(message) if message.contains("found 1")));

    let before = vault.retrieval_blend_weight_table()?;
    let expected_weights =
        apply_retrieval_blend_weight_update(before.weights, [1.0, 0.0, 0.0, 0.0], 0.10, 1)?;
    let updated = vault.tune_retrieval_blend_weights(RetrievalBlendTuningConfig {
        max_runs: 2,
        learning_rate: 0.10,
        min_reward_count: 1,
    })?;

    assert_eq!(updated.weights, expected_weights);
    assert_eq!(updated.data_window.run_count, 1);
    assert_eq!(updated.data_window.outcome_count, 1);
    assert_eq!(updated.data_window.candidate_count, 1);
    assert_eq!(updated.data_window.started_at_min, Some(500));
    assert_eq!(updated.data_window.started_at_max, Some(500));
    Ok(())
}

#[test]
fn retrieval_blend_weight_table_load_normalizes_persisted_weights() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let mut provenance = BTreeMap::new();
    provenance.insert("source".to_owned(), "test".to_owned());
    provenance.insert("algorithm".to_owned(), "test.unnormalized".to_owned());
    let entry = RetrievalBlendWeightTableEntry {
        version: RETRIEVAL_BLEND_WEIGHT_TABLE_VERSION,
        weights: RetrievalBlendWeights::new(2.0, 3.0, 4.0, 1.0),
        tuned_at: 123,
        provenance,
        data_window: RetrievalBlendWeightDataWindow::default(),
    };
    let raw = rmp_serde::to_vec_named(&entry).expect("encode synthetic blend table");
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .vault_meta
            .put(wtxn, RETRIEVAL_BLEND_WEIGHT_TABLE_KEY, &raw)?;
        Ok(())
    })?;

    let loaded = vault.retrieval_blend_weight_table()?;
    let sum = loaded.weights.recency
        + loaded.weights.salience
        + loaded.weights.confidence
        + loaded.weights.gravity;
    assert!((sum - 1.0).abs() < 1.0e-6);
    assert!((loaded.weights.recency - 0.2).abs() < 1.0e-6);
    assert!((loaded.weights.salience - 0.3).abs() < 1.0e-6);
    assert!((loaded.weights.confidence - 0.4).abs() < 1.0e-6);
    assert!((loaded.weights.gravity - 0.1).abs() < 1.0e-6);
    assert_eq!(loaded.tuned_at, 123);
    Ok(())
}

// ===== EMB-2 (ONE-1334) HNSW compatibility record v3 =====

fn funnel_compat_config(fast_dims: Option<u16>) -> VaultConfig {
    let mut config = VaultConfig::device();
    config.dimensions = 4;
    config.fast_dims = fast_dims;
    config.embedding_model = Some("test/model@v1".to_owned());
    config.map_size = 32 * 1024 * 1024;
    config
}

#[test]
fn v2_hnsw_compat_record_opens_as_current_with_no_fast_dims() -> Result<()> {
    let dir = tempfile::tempdir()?;
    {
        let vault = Vault::open(dir.path(), funnel_compat_config(None))?;
        // Populate vector data: a Legacy classification would hard-error a
        // populated vault, which is exactly what the v2->Current rule must
        // prevent.
        let id = entity_id(0x71);
        vault.put_entity(&id, 1, TimeRange { start: 1, end: 1 }, 1, b"node")?;
        vault.put_vector(&id, &[1.0, 0.0, 0.0, 0.0])?;

        // Overwrite the fresh v3 record with a hand-rolled v2 (27-byte)
        // record, simulating a vault written by a pre-EMB-2 binary.
        let hnsw = funnel_compat_config(None).hnsw;
        let mut encoded = [0_u8; HNSW_COMPATIBILITY_V2_LEN];
        encoded[0] = HNSW_COMPATIBILITY_V2_VERSION;
        encoded[1..9].copy_from_slice(&4_u64.to_le_bytes());
        encoded[9..17].copy_from_slice(&(hnsw.m_max_0 as u64).to_le_bytes());
        encoded[17..25].copy_from_slice(&(hnsw.ef_construction as u64).to_le_bytes());
        encoded[25] = HNSW_DISTANCE_METRIC_COSINE;
        encoded[26] = HNSW_INDEX_STRUCTURE_FLAT_NSW;
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .hnsw_meta
            .put(&mut wtxn, HNSW_CONFIG_KEY, &encoded)?;
        wtxn.commit()?;
    }

    {
        let vault = Vault::open(dir.path(), funnel_compat_config(None))?;
        let results = vault.search_vector(&[1.0, 0.0, 0.0, 0.0], 4)?;
        assert_eq!(results.len(), 1, "populated v2 vault must stay searchable");
        let rtxn = vault.store.env.read_txn()?;
        let raw = vault
            .store
            .hnsw_meta
            .get(&rtxn, HNSW_CONFIG_KEY)?
            .expect("compat record");
        assert_eq!(
            raw.len(),
            HNSW_COMPATIBILITY_V2_LEN,
            "v2 records are never rewritten in place"
        );
    }

    let Err(err) = Vault::open(dir.path(), funnel_compat_config(Some(2))) else {
        panic!("enabling fast_dims on a v2 vault must fail HnswConfigChanged");
    };
    match err {
        Error::HnswConfigChanged { stored, requested } => {
            assert!(stored.contains("fast_dims=none"), "stored: {stored}");
            assert!(requested.contains("fast_dims=2"), "requested: {requested}");
        }
        other => panic!("expected HnswConfigChanged, got {other:?}"),
    }
    Ok(())
}

#[test]
fn v3_hnsw_compat_record_round_trips_fast_dims() -> Result<()> {
    let dir = tempfile::tempdir()?;
    {
        let vault = Vault::open(dir.path(), funnel_compat_config(Some(2)))?;
        let rtxn = vault.store.env.read_txn()?;
        let raw = vault
            .store
            .hnsw_meta
            .get(&rtxn, HNSW_CONFIG_KEY)?
            .expect("compat record");
        assert_eq!(raw.len(), HNSW_COMPATIBILITY_LEN, "29-byte v3 record");
        assert_eq!(raw[0], HNSW_COMPATIBILITY_VERSION);
        assert_eq!(
            u16::from_le_bytes(raw[27..29].try_into().expect("fast_dims tail")),
            2
        );
    }

    drop(Vault::open(dir.path(), funnel_compat_config(Some(2)))?);

    let Err(err) = Vault::open(dir.path(), funnel_compat_config(Some(3))) else {
        panic!("changed fast_dims must fail");
    };
    assert!(matches!(err, Error::HnswConfigChanged { .. }));

    let Err(err) = Vault::open(dir.path(), funnel_compat_config(None)) else {
        panic!("removing fast_dims must fail");
    };
    assert!(matches!(err, Error::HnswConfigChanged { .. }));
    Ok(())
}

#[test]
fn invalid_fast_dims_fails_closed_at_open() -> Result<()> {
    for fd in [0_u16, 4, 5] {
        let dir = tempfile::tempdir()?;
        let Err(err) = Vault::open(dir.path(), funnel_compat_config(Some(fd))) else {
            panic!("fast_dims {fd} must be rejected at open (dimensions = 4)");
        };
        assert!(
            matches!(err, Error::InvalidConfig(ref msg)
                if msg == "fast_dims must be greater than zero and less than dimensions"),
            "fast_dims {fd}: got {err:?}"
        );
    }
    Ok(())
}

// ---- ERASE-A (ONE-1637) claim index ----------------------------------------

fn claim_bound_gate_decision(
    decision_id: GateDecisionId,
    created_at: u64,
    claim_id: &[u8; 16],
) -> GateDecisionRecord {
    let mut record = gate_decision(decision_id, created_at, None);
    record.claim_id = Some(*claim_id);
    record
}

fn append_gate_decisions(vault: &Vault, records: &[GateDecisionRecord]) -> Result<()> {
    vault.with_write_txn(|wtxn| {
        for record in records {
            vault.store.append_gate_decision_in_txn(wtxn, record)?;
        }
        Ok(())
    })
}

fn claim_index_decision_ids(vault: &Vault, claim_id: &[u8; 16]) -> Result<Vec<GateDecisionId>> {
    let rtxn = vault.store.env.read_txn()?;
    let prefix = gate_decision_claim_index_prefix(claim_id);
    let mut ids = Vec::new();
    for row in vault.store.vault_meta.prefix_iter(&rtxn, &prefix)? {
        let (key, value) = row?;
        assert!(value.is_empty(), "claim index rows carry no value");
        ids.push(GateDecisionId::from_bytes(index_suffix_id(
            &key,
            &prefix,
            "gate decision claim index",
        )?));
    }
    Ok(ids)
}

fn claim_index_row_count(vault: &Vault) -> Result<usize> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, GATE_DECISION_CLAIM_INDEX_PREFIX)?
        .count())
}

/// Deletes every claim-index row inside an already-open write txn. Collects
/// first: LMDB forbids mutating a DB while one of its iterators is live.
fn delete_claim_index_rows_in_txn(vault: &Vault, wtxn: &mut RwTxn<'_>) -> Result<()> {
    let mut keys = Vec::new();
    for row in vault
        .store
        .vault_meta
        .prefix_iter(wtxn, GATE_DECISION_CLAIM_INDEX_PREFIX)?
    {
        keys.push(row?.0.to_vec());
    }
    for key in &keys {
        vault.store.vault_meta.delete(wtxn, key)?;
    }
    Ok(())
}

/// The v1 retention skeleton the ONE-1638 erase coupling leaves in place of a
/// redacted primary: accountability fields kept, claim-bearing fields scrubbed.
fn redacted_skeleton(record: &GateDecisionRecord, at: u64) -> GateDecisionRecord {
    GateDecisionRecord {
        version: GATE_DECISION_LEDGER_VERSION_REDACTED,
        reason_codes: Vec::new(),
        receipt_reasons: Vec::new(),
        system_notices: Vec::new(),
        actor_ref: None,
        grant_ref: None,
        diff_handle: Vec::new(),
        redacted_at: Some(at),
        ..record.clone()
    }
}

/// Rewinds a vault to its pre-ERASE-A shape: primaries intact, zero claim-index
/// rows, no backfill flag.
fn strip_claim_index_and_flag(vault: &Vault) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    delete_claim_index_rows_in_txn(vault, &mut wtxn)?;
    vault
        .store
        .vault_meta
        .delete(&mut wtxn, GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_KEY)?;
    wtxn.commit()?;
    Ok(())
}

#[test]
fn append_writes_claim_index_row_for_claim_bound_decisions() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = [0x11; 16];
    let bound = claim_bound_gate_decision(synthetic_gate_decision_id(0x71, 1), 1, &claim);
    let unbound = gate_decision(synthetic_gate_decision_id(0x72, 2), 2, None);
    append_gate_decisions(&vault, &[bound.clone(), unbound])?;

    assert_eq!(
        claim_index_decision_ids(&vault, &claim)?,
        vec![bound.decision_id]
    );
    assert_eq!(claim_index_row_count(&vault)?, 1);
    Ok(())
}

#[test]
fn rollback_deletes_the_claim_index_row_with_the_primary() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = [0x12; 16];
    let bound = claim_bound_gate_decision(synthetic_gate_decision_id(0x73, 3), 3, &claim);
    append_gate_decisions(&vault, std::slice::from_ref(&bound))?;
    assert_eq!(claim_index_row_count(&vault)?, 1);

    vault.with_write_txn(|wtxn| {
        vault
            .store
            .delete_gate_decision_in_txn(wtxn, bound.decision_id)
    })?;

    assert!(claim_index_decision_ids(&vault, &claim)?.is_empty());
    assert_eq!(claim_index_row_count(&vault)?, 0);
    assert!(gate_decision_primary(&vault, bound.decision_id)?.is_none());
    Ok(())
}

/// The claim-index twin of `grant_ref_lookup_after_delete_is_consistent`:
/// index-accelerated discovery must return the exact survivors after a delete,
/// agree with the scan fallback, and never raise `CorruptedIndex` because an
/// index row outlived its primary.
#[test]
fn claim_lookup_after_delete_is_consistent() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = [0x13; 16];
    let other = [0x14; 16];
    let deleted = claim_bound_gate_decision(synthetic_gate_decision_id(0x77, 7), 7, &claim);
    let survivor = claim_bound_gate_decision(synthetic_gate_decision_id(0x78, 8), 8, &claim);
    let unrelated = claim_bound_gate_decision(synthetic_gate_decision_id(0x79, 9), 9, &other);
    append_gate_decisions(
        &vault,
        &[deleted.clone(), survivor.clone(), unrelated.clone()],
    )?;
    vault.store.backfill_gate_decision_claim_index()?;

    vault.with_write_txn(|wtxn| {
        vault
            .store
            .delete_gate_decision_in_txn(wtxn, deleted.decision_id)
    })?;

    {
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .gate_decision_claim_index_backfill_complete_in_txn(&rtxn)?,
            "the indexed discovery path must be the one under test",
        );
        assert_eq!(
            vault.store.gate_decisions_for_claim_in_txn(&rtxn, &claim)?,
            vec![survivor.clone()]
        );
        assert_eq!(
            vault
                .store
                .scan_gate_decisions_for_claim_in_txn(&rtxn, &claim)?,
            vec![survivor.clone()]
        );
        assert_eq!(
            vault.store.gate_decisions_for_claim_in_txn(&rtxn, &other)?,
            vec![unrelated]
        );
        assert_eq!(
            vault
                .store
                .verify_claim_erasure_by_scan_in_txn(&rtxn, &claim)?,
            vec![survivor.decision_id]
        );
    }

    assert_eq!(
        claim_index_decision_ids(&vault, &claim)?,
        vec![survivor.decision_id]
    );
    assert_eq!(claim_index_row_count(&vault)?, 2);
    assert!(gate_decision_primary(&vault, deleted.decision_id)?.is_none());
    Ok(())
}

/// A mixed ledger: two claims interleaved with unbound rows, appended out of
/// decision_id order so ascending-order parity is a real assertion.
fn mixed_claim_ledger(vault: &Vault, left: &[u8; 16], right: &[u8; 16]) -> Result<()> {
    append_gate_decisions(
        vault,
        &[
            claim_bound_gate_decision(synthetic_gate_decision_id(0x83, 3), 3, left),
            gate_decision(synthetic_gate_decision_id(0x86, 6), 6, None),
            claim_bound_gate_decision(synthetic_gate_decision_id(0x81, 1), 1, left),
            claim_bound_gate_decision(synthetic_gate_decision_id(0x84, 4), 4, right),
            claim_bound_gate_decision(synthetic_gate_decision_id(0x82, 2), 2, left),
            gate_decision(synthetic_gate_decision_id(0x87, 7), 7, None),
        ],
    )
}

#[test]
fn claim_discovery_index_and_scan_paths_are_result_identical() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let left = [0x21; 16];
    let right = [0x22; 16];
    mixed_claim_ledger(&vault, &left, &right)?;
    vault.store.backfill_gate_decision_claim_index()?;

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .gate_decision_claim_index_backfill_complete_in_txn(&rtxn)?
    );
    for claim in [left, right, [0x23; 16]] {
        let indexed = vault.store.gate_decisions_for_claim_in_txn(&rtxn, &claim)?;
        let scanned = vault
            .store
            .scan_gate_decisions_for_claim_in_txn(&rtxn, &claim)?;
        assert_eq!(indexed, scanned, "paths must agree for claim {claim:?}");
        assert!(
            indexed
                .windows(2)
                .all(|pair| pair[0].decision_id.as_bytes() < pair[1].decision_id.as_bytes()),
            "discovery must be ascending by decision_id",
        );
        assert!(indexed.iter().all(|record| record.claim_id == Some(claim)));
    }
    assert_eq!(
        vault
            .store
            .gate_decisions_for_claim_in_txn(&rtxn, &left)?
            .len(),
        3
    );
    Ok(())
}

#[test]
fn claim_discovery_falls_back_to_scan_while_backfill_incomplete() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let left = [0x24; 16];
    let right = [0x25; 16];
    mixed_claim_ledger(&vault, &left, &right)?;

    let expected = {
        let rtxn = vault.store.env.read_txn()?;
        vault.store.gate_decisions_for_claim_in_txn(&rtxn, &left)?
    };
    assert_eq!(expected.len(), 3);

    // Simulate a pre-ERASE-A vault: rows exist, index does not.
    strip_claim_index_and_flag(&vault)?;
    assert_eq!(claim_index_row_count(&vault)?, 0);

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        !vault
            .store
            .gate_decision_claim_index_backfill_complete_in_txn(&rtxn)?
    );
    // The kill-shot: un-backfilled rows stay visible to erase discovery.
    assert_eq!(
        vault.store.gate_decisions_for_claim_in_txn(&rtxn, &left)?,
        expected
    );
    Ok(())
}

#[test]
fn backfill_indexes_preexisting_rows_and_sets_flag_atomically() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let left = [0x26; 16];
    let right = [0x27; 16];
    mixed_claim_ledger(&vault, &left, &right)?;
    strip_claim_index_and_flag(&vault)?;

    let first = vault.store.backfill_gate_decision_claim_index()?;
    assert!(!first.already_complete);
    assert_eq!(first.rows_indexed, 4);
    assert_eq!(claim_index_row_count(&vault)?, 4);
    assert_eq!(claim_index_decision_ids(&vault, &left)?.len(), 3);
    {
        let rtxn = vault.store.env.read_txn()?;
        assert_eq!(
            vault
                .store
                .vault_meta
                .get(&rtxn, GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_KEY)?
                .as_deref(),
            Some(GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_VALUE.as_slice()),
        );
    }

    let second = vault.store.backfill_gate_decision_claim_index()?;
    assert!(second.already_complete);
    assert_eq!(second.rows_indexed, 0);
    assert_eq!(claim_index_row_count(&vault)?, 4);
    Ok(())
}

#[test]
fn empty_ledger_vault_opens_with_backfill_flag_set() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let config = VaultConfig::device();
    {
        let vault = Vault::open(dir.path(), config.clone())?;
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .gate_decision_claim_index_backfill_complete_in_txn(&rtxn)?,
            "a fresh vault's ledger is vacuously fully indexed",
        );
        drop(rtxn);
        append_gate_decisions(
            &vault,
            &[claim_bound_gate_decision(
                synthetic_gate_decision_id(0x88, 8),
                8,
                &[0x28; 16],
            )],
        )?;
        strip_claim_index_and_flag(&vault)?;
    }

    let vault = Vault::open(dir.path(), config)?;
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        !vault
            .store
            .gate_decision_claim_index_backfill_complete_in_txn(&rtxn)?,
        "a populated ledger must not self-flag: it needs the maintenance op",
    );
    Ok(())
}

#[test]
fn erasure_verify_scans_keyspace_and_never_trusts_the_index() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = [0x29; 16];
    let other = [0x2A; 16];
    mixed_claim_ledger(&vault, &claim, &other)?;
    let expected: Vec<GateDecisionId> = (1..=3)
        .map(|value| synthetic_gate_decision_id(0x80 + value as u8, value))
        .collect();

    // A LYING index: rows removed, flag set. Index-accelerated discovery would
    // report the claim as already empty.
    let mut wtxn = vault.store.env.write_txn()?;
    delete_claim_index_rows_in_txn(&vault, &mut wtxn)?;
    vault.store.vault_meta.put(
        &mut wtxn,
        GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_KEY,
        &GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_VALUE,
    )?;
    // A bogus index row with no primary: fatal to the index reader, invisible
    // to the verify.
    vault.store.vault_meta.put(
        &mut wtxn,
        &gate_decision_claim_index_key(&claim, synthetic_gate_decision_id(0xEE, 99)),
        b"",
    )?;
    wtxn.commit()?;

    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        vault
            .store
            .verify_claim_erasure_by_scan_in_txn(&rtxn, &claim)?,
        expected,
        "the verify must scan the ledger, not the index it would certify",
    );
    assert!(matches!(
        vault.store.gate_decisions_for_claim_in_txn(&rtxn, &claim),
        Err(Error::CorruptedIndex("gate decision claim index")),
    ));
    Ok(())
}

#[test]
fn erasure_verify_excludes_redacted_rows_and_other_claims() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = [0x2B; 16];
    let live = claim_bound_gate_decision(synthetic_gate_decision_id(0x91, 1), 1, &claim);
    let to_redact = claim_bound_gate_decision(synthetic_gate_decision_id(0x92, 2), 2, &claim);
    let other = claim_bound_gate_decision(synthetic_gate_decision_id(0x93, 3), 3, &[0x2C; 16]);
    append_gate_decisions(&vault, &[live.clone(), to_redact.clone(), other])?;

    // Stand in for the ONE-1638 in-place redaction: primary rewritten to a v1
    // skeleton, claim-index row deliberately retained.
    let skeleton = redacted_skeleton(&to_redact, 42);
    let mut wtxn = vault.store.env.write_txn()?;
    vault.store.vault_meta.put(
        &mut wtxn,
        &gate_decision_key(to_redact.decision_id),
        &encode_gate_decision(&skeleton)?,
    )?;
    wtxn.commit()?;

    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        vault
            .store
            .verify_claim_erasure_by_scan_in_txn(&rtxn, &claim)?,
        vec![live.decision_id],
        "only unredacted claim-bound rows block completeness",
    );
    assert_eq!(
        vault.store.gate_decisions_for_claim_in_txn(&rtxn, &claim)?,
        vec![live, skeleton],
        "discovery still surfaces the retained skeleton",
    );
    Ok(())
}

#[test]
fn record_schema_v0_bytes_stable_and_v1_skeleton_vets() -> Result<()> {
    // Golden msgpack of the shared fixture, captured BEFORE `redacted_at`
    // existed. `skip_serializing_if` keeps a `None` field off the wire, so v0
    // rows written by any prior build are byte-identical to today's.
    const GOLDEN_V0: &str = "8DA776657273696F6E00AB6465636973696F6E5F696481A56279746573DC00106161616161616161000000000\
0000001AA637265617465645F617401A76F7574636F6D65A8617070726F766564AC726561736F6E5F636F64657391B8676174652E746573742E7\
26563656970745F66616D696C79AB6163746F725F636C617373A56167656E74A96163746F725F726566C0AC636F6E74656E745F6B696E64A5636\
C61696DB7706F6C6963795F6D616E69666573745F76657273696F6EA27630A8636C61696D5F6964C0A96772616E745F726566A8673A676F6C646\
56EAB646966665F68616E646C6591CCAAB2726561645F66726F6E746965725F68617368DC0020CCBBCCBBCCBBCCBBCCBBCCBBCCBBCCBBCCBBCCB\
BCCBBCCBBCCBBCCBBCCBBCCBBCCBBCCBBCCBBCCBBCCBBCCBBCCBBCCBBCCBBCCBBCCBBCCBBCCBBCCBBCCBBCCBB";
    let golden: Vec<u8> = (0..GOLDEN_V0.len() / 2)
        .map(|index| {
            u8::from_str_radix(&GOLDEN_V0[index * 2..index * 2 + 2], 16).expect("golden hex")
        })
        .collect();
    let live = gate_decision(synthetic_gate_decision_id(0x61, 1), 1, Some("g:golden"));
    assert_eq!(
        encode_gate_decision(&live)?,
        golden,
        "v0 bytes must not move"
    );
    assert_eq!(decode_gate_decision(&golden)?, live);
    assert!(live.redacted_at.is_none(), "pre-field bytes decode as None");

    let skeleton = redacted_skeleton(&live, 7);
    assert_eq!(
        decode_gate_decision(&encode_gate_decision(&skeleton)?)?,
        skeleton
    );

    let (_dir, vault) = open_test_vault();
    for born_redacted in [
        skeleton.clone(),
        GateDecisionRecord {
            redacted_at: Some(7),
            ..live.clone()
        },
    ] {
        let result = vault.with_write_txn(|wtxn| {
            vault
                .store
                .append_gate_decision_in_txn(wtxn, &born_redacted)
        });
        assert!(
            matches!(
                result,
                Err(Error::InvariantViolation("gate decision born redacted"))
            ),
            "appends stay version-0-and-unredacted only: {result:?}",
        );
    }

    let rejects = [
        GateDecisionRecord {
            redacted_at: Some(7),
            ..live.clone()
        },
        // Half of the deliberate `actor_class` asymmetry: fatal on the v1
        // skeleton, where the field is ours and the retention design keeps it.
        // The v0 half is pinned positively below.
        GateDecisionRecord {
            actor_class: String::new(),
            ..skeleton.clone()
        },
        GateDecisionRecord {
            version: 2,
            ..live.clone()
        },
        GateDecisionRecord {
            redacted_at: None,
            ..skeleton.clone()
        },
        GateDecisionRecord {
            redacted_at: Some(0),
            ..skeleton.clone()
        },
        GateDecisionRecord {
            reason_codes: vec!["gate.x".to_owned()],
            ..skeleton.clone()
        },
        GateDecisionRecord {
            grant_ref: Some("g:leak".to_owned()),
            ..skeleton.clone()
        },
        GateDecisionRecord {
            actor_ref: Some("agent-leak".to_owned()),
            ..skeleton.clone()
        },
        GateDecisionRecord {
            content_kind: String::new(),
            ..skeleton
        },
    ];
    for reject in rejects {
        let encoded = rmp_serde::to_vec_named(&reject).expect("test encode");
        assert!(
            matches!(
                decode_gate_decision(&encoded),
                Err(Error::CorruptedIndex("gate decision ledger"))
            ),
            "malformed record must not decode: {reject:?}",
        );
    }

    // The other half of the asymmetry, pinned POSITIVELY so a later
    // "symmetrize the vet" edit has to delete an assertion rather than silently
    // pass. On v0 the class is caller-asserted: the gate answers an empty one
    // with a recorded `gate.deny.missing_actor_class` denial, and that denial
    // row must round-trip. Vetting it fatal would let any caller trade an
    // auditable deny for a torn write txn — and leave a decode-fatal row that
    // aborts every later ledger scan.
    let empty_class = GateDecisionRecord {
        actor_class: String::new(),
        ..live
    };
    let encoded = rmp_serde::to_vec_named(&empty_class).expect("test encode");
    assert_eq!(
        decode_gate_decision(&encoded)?,
        empty_class,
        "a recorded deny-missing-actor-class row must survive the round trip",
    );
    let (_dir, vault) = open_test_vault();
    vault.with_write_txn(|wtxn| vault.store.append_gate_decision_in_txn(wtxn, &empty_class))?;
    Ok(())
}

/// A v1 skeleton may NOT retain a `diff_handle`.
///
/// E-A's D1 table only length-capped the field on the redacted column, so a row
/// that called itself redacted could keep a live binding to the exact body the
/// redaction exists to scrub — a length cap cannot tell a scrubbed sentinel from
/// a real handle. Empty is the only self-evidently scrubbed value, and this is
/// the test that makes a later "just cap the length" relaxation fail.
///
/// The planted-row half is the one that bites: skeletons reach disk by in-place
/// primary overwrite (never through `append_gate_decision_in_txn`), so the vet
/// only protects anything if the READERS refuse a retained handle too.
#[test]
fn redacted_skeleton_must_not_retain_a_diff_handle() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = [0x3D; 16];
    let live = claim_bound_gate_decision(synthetic_gate_decision_id(0x95, 1), 1, &claim);
    append_gate_decisions(&vault, std::slice::from_ref(&live))?;
    assert!(
        !live.diff_handle.is_empty(),
        "v0 must still REQUIRE a handle — the tightening is v1-only",
    );

    let scrubbed = redacted_skeleton(&live, 9);
    assert!(scrubbed.diff_handle.is_empty());
    assert_eq!(
        decode_gate_decision(&encode_gate_decision(&scrubbed)?)?,
        scrubbed,
        "the empty-handle skeleton is the accepted shape",
    );

    // The live binding itself, a one-byte stub, and a blob that exactly
    // saturates the old length cap: all three are retained handles.
    for handle in [
        live.diff_handle,
        vec![0x00],
        vec![0x5A; GATE_DIFF_HANDLE_MAX_LEN],
    ] {
        let retained = GateDecisionRecord {
            diff_handle: handle.clone(),
            ..scrubbed.clone()
        };
        let encoded = rmp_serde::to_vec_named(&retained).expect("test encode");
        assert!(
            matches!(
                decode_gate_decision(&encoded),
                Err(Error::CorruptedIndex("gate decision ledger"))
            ),
            "a redacted skeleton keeping {} handle bytes must not vet",
            handle.len(),
        );

        // Planted straight onto the primary, exactly as an in-place redaction
        // writes. Every reader must fail closed instead of serving the binding.
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.vault_meta.put(
            &mut wtxn,
            &gate_decision_key(retained.decision_id),
            &encoded,
        )?;
        wtxn.commit()?;
        let rtxn = vault.store.env.read_txn()?;
        for (reader, result) in [
            (
                "point read",
                vault
                    .store
                    .gate_decision_in_txn(&rtxn, retained.decision_id)
                    .map(|_| ()),
            ),
            (
                "claim discovery",
                vault
                    .store
                    .gate_decisions_for_claim_in_txn(&rtxn, &claim)
                    .map(|_| ()),
            ),
            (
                "erasure verify",
                vault
                    .store
                    .verify_claim_erasure_by_scan_in_txn(&rtxn, &claim)
                    .map(|_| ()),
            ),
        ] {
            assert!(
                matches!(result, Err(Error::CorruptedIndex("gate decision ledger"))),
                "{reader} must refuse a handle-retaining skeleton: {result:?}",
            );
        }
        drop(rtxn);

        // And the append door stays shut on it as well (born-redacted guard).
        let appended =
            vault.with_write_txn(|wtxn| vault.store.append_gate_decision_in_txn(wtxn, &retained));
        assert!(
            matches!(
                appended,
                Err(Error::InvariantViolation("gate decision born redacted"))
            ),
            "append must never mint a skeleton, handle-bearing or not: {appended:?}",
        );
    }

    // Overwrite the corrupt primary with the properly scrubbed skeleton: the
    // same readers recover, so the refusals above were about the handle and not
    // about the row being redacted at all.
    let mut wtxn = vault.store.env.write_txn()?;
    vault.store.vault_meta.put(
        &mut wtxn,
        &gate_decision_key(scrubbed.decision_id),
        &encode_gate_decision(&scrubbed)?,
    )?;
    wtxn.commit()?;
    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        vault.store.gate_decisions_for_claim_in_txn(&rtxn, &claim)?,
        vec![scrubbed],
        "discovery still surfaces a correctly scrubbed skeleton",
    );
    assert!(
        vault
            .store
            .verify_claim_erasure_by_scan_in_txn(&rtxn, &claim)?
            .is_empty(),
        "a scrubbed skeleton does not block erasure completeness",
    );
    Ok(())
}

/// The pushdown pin: the caller's filter runs DURING the cursor walk, so a
/// filtered read never materializes the whole ledger first.
///
/// Two halves, and the second is the one that bites. (a) an early `Err` from
/// the visitor stops the walk at the row that raised it — impossible if every
/// record were decoded into a `Vec` before the filter saw any of them. (b) the
/// live filtered readers observe the SAME early-stop, which is what pins them
/// to the streaming helper rather than to a collect-then-filter that merely
/// returns the same values.
#[test]
fn ledger_scan_applies_the_caller_filter_during_the_cursor_walk() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = [0x31; 16];
    // Row 1 is claim-bound; rows 2..=4 are not. A collect-first scan decodes
    // all four before any filter runs; a streaming scan visits them in order.
    append_gate_decisions(
        &vault,
        &[
            claim_bound_gate_decision(synthetic_gate_decision_id(0xA1, 1), 1, &claim),
            gate_decision(synthetic_gate_decision_id(0xA2, 2), 2, None),
            gate_decision(synthetic_gate_decision_id(0xA3, 3), 3, None),
            gate_decision(synthetic_gate_decision_id(0xA4, 4), 4, None),
        ],
    )?;

    {
        let rtxn = vault.store.env.read_txn()?;
        let mut visited = 0_usize;
        let result = vault.store.for_each_gate_decision_in_txn(&rtxn, |_record| {
            visited += 1;
            if visited == 2 {
                return Err(Error::InvariantViolation("probe stop"));
            }
            Ok(())
        });
        assert!(
            matches!(result, Err(Error::InvariantViolation("probe stop"))),
            "the visitor's error must propagate: {result:?}",
        );
        assert_eq!(
            visited, 2,
            "the walk must stop AT the refusing row, not after decoding the ledger",
        );
    }

    // A row whose bytes cannot decode. An unfiltered walk must hit it; a walk
    // that stops earlier proves rows past the stop were never decoded.
    let mut wtxn = vault.store.env.write_txn()?;
    vault.store.vault_meta.put(
        &mut wtxn,
        &gate_decision_key(synthetic_gate_decision_id(0xA5, 5)),
        b"not-msgpack",
    )?;
    wtxn.commit()?;

    let rtxn = vault.store.env.read_txn()?;
    let mut seen = 0_usize;
    assert!(
        matches!(
            vault.store.for_each_gate_decision_in_txn(&rtxn, |_record| {
                seen += 1;
                Ok(())
            }),
            Err(Error::CorruptedIndex("gate decision ledger")),
        ),
        "an unfiltered walk reaches the malformed trailing row and aborts",
    );
    assert_eq!(seen, 4, "the four decodable rows precede the malformed one");

    // Both filtered readers stop at the first refusing row too: they are the
    // same walk, not a collect-then-filter wearing its shape.
    let mut discovered = 0_usize;
    assert!(
        matches!(
            vault.store.for_each_gate_decision_in_txn(&rtxn, |record| {
                discovered += 1;
                if record.claim_id == Some(claim) {
                    return Err(Error::InvariantViolation("probe stop"));
                }
                Ok(())
            }),
            Err(Error::InvariantViolation("probe stop")),
        ),
        "the claim-bound first row must halt the walk immediately",
    );
    assert_eq!(
        discovered, 1,
        "matching on row 1 must not require decoding rows 2..=5",
    );
    Ok(())
}

#[test]
fn claim_index_keyspace_is_disjoint_from_ledger_and_grant_ref_ranges() {
    let claim = [0x2D; 16];
    let decision_id = synthetic_gate_decision_id(0x94, 4);
    let ledger_lower = GATE_DECISION_KEY_PREFIX;
    let ledger_upper = gate_decision_upper_bound();
    let grant_ref_key = gate_decision_grant_ref_index_key("g:disjoint", decision_id);

    for key in [
        gate_decision_claim_index_key(&claim, decision_id),
        gate_decision_claim_index_prefix(&claim),
        GATE_DECISION_CLAIM_INDEX_PREFIX.to_vec(),
        GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_KEY.to_vec(),
    ] {
        assert!(
            key.as_slice() >= ledger_upper.as_slice(),
            "{key:?} must sort at or past the ledger upper bound",
        );
        assert!(!key.starts_with(ledger_lower));
        assert!(!key.starts_with(GATE_DECISION_GRANT_REF_INDEX_PREFIX));
        assert!(!GATE_DECISION_GRANT_REF_INDEX_PREFIX.starts_with(&key));
    }

    // The sibling index sorts BELOW the primary range, so neither the primary
    // full-scan nor either prefix-iter can ever see the other's rows.
    assert!(grant_ref_key.as_slice() < ledger_lower);
    assert!(gate_decision_key(decision_id).starts_with(ledger_lower));
}

#[test]
fn claim_index_corruption_fails_loud_instead_of_answering() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = [0x2E; 16];
    let foreign = [0x2F; 16];
    let mine = claim_bound_gate_decision(synthetic_gate_decision_id(0x95, 5), 5, &claim);
    let theirs = claim_bound_gate_decision(synthetic_gate_decision_id(0x96, 6), 6, &foreign);
    append_gate_decisions(&vault, &[mine, theirs.clone()])?;
    vault.store.backfill_gate_decision_claim_index()?;

    // A row filed under the wrong claim: its primary EXISTS, so only the
    // claim-back check can catch the mis-binding.
    let mut wtxn = vault.store.env.write_txn()?;
    vault.store.vault_meta.put(
        &mut wtxn,
        &gate_decision_claim_index_key(&claim, theirs.decision_id),
        b"",
    )?;
    wtxn.commit()?;
    {
        let rtxn = vault.store.env.read_txn()?;
        assert!(matches!(
            vault.store.gate_decisions_for_claim_in_txn(&rtxn, &claim),
            Err(Error::CorruptedIndex("gate decision claim index")),
        ));
        // The scan path never consults the index, so it stays truthful.
        assert_eq!(
            vault
                .store
                .scan_gate_decisions_for_claim_in_txn(&rtxn, &claim)?
                .len(),
            1
        );
    }

    // A flag byte we never write is corruption, not a soft "incomplete" that
    // would silently downgrade discovery to a scan.
    let mut wtxn = vault.store.env.write_txn()?;
    vault.store.vault_meta.put(
        &mut wtxn,
        GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_KEY,
        &[2],
    )?;
    wtxn.commit()?;
    let rtxn = vault.store.env.read_txn()?;
    for result in [
        vault
            .store
            .gate_decision_claim_index_backfill_complete_in_txn(&rtxn)
            .map(|_| ()),
        vault
            .store
            .gate_decisions_for_claim_in_txn(&rtxn, &claim)
            .map(|_| ()),
    ] {
        assert!(matches!(
            result,
            Err(Error::CorruptedIndex(
                "gate decision claim index backfill flag"
            )),
        ));
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// ONE-1754 · byte-space v3 persisted type-byte re-key
//
// These fixtures build a genuinely PRE-v3 vault at the raw LMDB level — old
// type bytes in the envelopes, old `type_index` keys, old `sid_counter:` keys,
// an old structural-kind registry row — and then open it with the current
// engine so the sanctioned migration branch runs for real. A vault created by
// the current engine is already v3-shaped, so it cannot stand in for one.
// ═══════════════════════════════════════════════════════════════════════════

/// A pre-v3 row: one entity of `old_byte`, with a body and timestamps that must
/// survive the re-key byte-for-byte.
struct LegacyRow {
    id: EntityId,
    old_byte: u8,
    new_byte: u8,
    kind: &'static str,
}

fn legacy_rows() -> Vec<LegacyRow> {
    TYPE_BYTE_REKEY_V3
        .iter()
        .enumerate()
        .map(|(index, entry)| LegacyRow {
            // Distinct, non-reserved ids: the low byte varies per kind.
            id: EntityId::from_bytes([
                0x11,
                u8::try_from(index + 1).expect("fixture index fits u8"),
                3,
                4,
                5,
                6,
                7,
                8,
                9,
                10,
                11,
                12,
                13,
                14,
                15,
                16,
            ])
            .expect("fixture id is valid"),
            old_byte: entry.old,
            new_byte: entry.new,
            kind: entry.kind,
        })
        .collect()
}

fn legacy_body(kind: &str) -> Vec<u8> {
    format!("body-of-{kind}").into_bytes()
}

fn legacy_envelope(row: &LegacyRow) -> Vec<u8> {
    let mut value = Vec::new();
    value.push(row.old_byte);
    value.extend_from_slice(&0x0102_0304_0506_0708_u64.to_be_bytes());
    value.extend_from_slice(&0x1112_1314_1516_1718_u64.to_be_bytes());
    value.extend_from_slice(&0x2122_2324_2526_2728_u64.to_be_bytes());
    value.extend_from_slice(&legacy_body(row.kind));
    value
}

fn type_index_key(type_byte: u8, id: &EntityId) -> [u8; 17] {
    let mut key = [0u8; 17];
    key[0] = type_byte;
    key[1..].copy_from_slice(id.as_bytes());
    key
}

/// A stand-in edge whose key and value must come back byte-identical: edge keys
/// carry entity IDS, never endpoint type bytes, so the re-key has no business
/// touching them.
fn legacy_edge_key(rows: &[LegacyRow]) -> Vec<u8> {
    let mut key = Vec::new();
    key.extend_from_slice(rows[0].id.as_bytes());
    key.push(6); // ChildOf
    key.extend_from_slice(rows[1].id.as_bytes());
    key
}

const LEGACY_EDGE_VALUE: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

/// Writes a pre-v3 vault: every moved kind present at its OLD byte, with the
/// predecessor ABI stamped. `mutate` gets the last word so a test can inject a
/// specific corruption before the migration sees the data.
fn write_pre_v3_vault(
    path: &Path,
    rows: &[LegacyRow],
    mutate: impl FnOnce(&Store, &mut RwTxn<'_>) -> Result<()>,
) -> Result<()> {
    let store = Store::open_with_storage_abi_version_for_test(
        path,
        &VaultConfig::device(),
        STORAGE_ABI_VERSION_V3_REKEY_PREDECESSOR,
    )?;
    let mut wtxn = store.env.write_txn()?;
    // Creating the root seeds the default policy manifest (ONE-1869), and that
    // seed writer stamps the CURRENT `ENTITY_TYPE_POLICY_MANIFEST` byte — a v3
    // byte — even though this opener stamped the PREDECESSOR ABI. That row is a
    // v3 artifact in a vault this fixture is claiming is pre-v3, and byte 67 is
    // a re-key DESTINATION the map does not vacate, so the next open's
    // occupied-destination guard correctly refuses to migrate: no genuine
    // predecessor vault can hold it (pre-v3 engines put this kind at 123 and
    // seeded nothing at all), so tolerating it in production would blind a
    // fail-closed guard to a real squatter. Remove it here instead, using the
    // same helper the legacy-fixture opener in `lib.rs` uses, so the fixture
    // describes an honestly pre-v3 vault and the migration under test runs
    // against the rows this function actually writes.
    crate::batch::deindex_entity_for_test(
        &store,
        &mut wtxn,
        &crate::gate::default_policy_manifest_id()?,
    )?;
    for row in rows {
        store
            .entities
            .put(&mut wtxn, row.id.as_bytes(), &legacy_envelope(row))?;
        store
            .type_index
            .put(&mut wtxn, &type_index_key(row.old_byte, &row.id), &[])?;
        store.vault_meta.put(
            &mut wtxn,
            &short_id_counter_key(row.old_byte),
            &u64::from(row.old_byte).to_le_bytes(),
        )?;
    }
    store
        .edges_out
        .put(&mut wtxn, &legacy_edge_key(rows), LEGACY_EDGE_VALUE)?;
    store
        .edges_in
        .put(&mut wtxn, &legacy_edge_key(rows), LEGACY_EDGE_VALUE)?;
    mutate(&store, &mut wtxn)?;
    wtxn.commit()?;
    drop(store);
    Ok(())
}

/// Reads the stamp WITHOUT going through the ABI gate.
///
/// Opening the store to read its own version would beg the question: the gate
/// is exactly what these tests are measuring, and after a successful re-key the
/// predecessor engine can no longer open the vault at all.
fn stored_abi(path: &Path) -> Result<Option<u16>> {
    // SAFETY: the vault is closed at every call site (the Store handle is
    // dropped first), the path is a plain local temp dir, and the map size is
    // not being changed concurrently.
    let env = unsafe {
        heed::EnvOpenOptions::new()
            .map_size(VaultConfig::device().map_size)
            .max_readers(VaultConfig::device().max_readers)
            .max_dbs(MAX_DBS)
            .open(path)?
    };
    let rtxn = env.read_txn()?;
    let vault_meta: heed::Database<Bytes, Bytes> = env
        .open_database(&rtxn, Some("vault_meta"))?
        .expect("vault_meta exists");
    let raw = vault_meta.get(&rtxn, STORAGE_ABI_VERSION_KEY)?;
    let value = raw
        .map(|bytes| u16::from_le_bytes(bytes.try_into().expect("the ABI stamp is a u16 LE row")));
    drop(rtxn);
    drop(env);
    Ok(value)
}

/// Reads each row's persisted type byte WITHOUT opening a `Store`.
///
/// Same reason as [`stored_abi`]: the rollback assertions must not route
/// through the open path they are measuring. A fixture that injects a
/// deliberately unloadable row would fail any reopen for that reason alone,
/// which would hide whether the bytes themselves rolled back.
fn raw_entity_type_bytes(path: &Path, rows: &[LegacyRow]) -> Result<Vec<Option<u8>>> {
    // SAFETY: the vault is closed at every call site, the path is a plain local
    // temp dir, and the map size is not being changed concurrently.
    let env = unsafe {
        heed::EnvOpenOptions::new()
            .map_size(VaultConfig::device().map_size)
            .max_readers(VaultConfig::device().max_readers)
            .max_dbs(MAX_DBS)
            .open(path)?
    };
    let rtxn = env.read_txn()?;
    let entities: heed::Database<Bytes, Bytes> = env
        .open_database(&rtxn, Some("entities"))?
        .expect("entities exists");
    let mut type_bytes = Vec::with_capacity(rows.len());
    for row in rows {
        type_bytes.push(
            entities
                .get(&rtxn, row.id.as_bytes())?
                .and_then(|raw| raw.first().copied()),
        );
    }
    drop(rtxn);
    drop(env);
    Ok(type_bytes)
}

/// ONE transaction vacates and reuses the overlapping bytes, preserves every
/// id, body and timestamp, leaves edges untouched, and lands equal per-kind
/// counts.
#[test]
fn byte_space_v3_rekey_moves_every_kind_in_one_transaction() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let rows = legacy_rows();
    write_pre_v3_vault(dir.path(), &rows, |_, _| Ok(()))?;

    // Sources and destinations genuinely overlap — this is the property that
    // makes staged delete-then-write mandatory rather than stylistic.
    let sources: BTreeSet<u8> = TYPE_BYTE_REKEY_V3.iter().map(|entry| entry.old).collect();
    let destinations: BTreeSet<u8> = TYPE_BYTE_REKEY_V3.iter().map(|entry| entry.new).collect();
    let reused: BTreeSet<u8> = sources.intersection(&destinations).copied().collect();
    assert!(
        reused.contains(&80) && reused.contains(&81) && reused.contains(&82),
        "the fixture must exercise vacate-and-reuse on 80/81/82, got {reused:?}"
    );

    let store = Store::open(dir.path(), &VaultConfig::device())?;
    let rtxn = store.env.read_txn()?;

    for row in &rows {
        let raw = store
            .entities
            .get(&rtxn, row.id.as_bytes())?
            .unwrap_or_else(|| panic!("{} survived the re-key", row.kind));
        assert_eq!(raw[0], row.new_byte, "{} type byte", row.kind);
        assert_eq!(
            &raw[1..ENTITY_METADATA_HEADER_LEN],
            &legacy_envelope(row)[1..ENTITY_METADATA_HEADER_LEN],
            "{} timestamps must be byte-for-byte unchanged",
            row.kind
        );
        assert_eq!(
            &raw[ENTITY_METADATA_HEADER_LEN..],
            legacy_body(row.kind).as_slice(),
            "{} body must be byte-for-byte unchanged",
            row.kind
        );

        assert!(
            store
                .type_index
                .get(&rtxn, &type_index_key(row.new_byte, &row.id))?
                .is_some(),
            "{} type-index row must land at the new byte",
            row.kind
        );
        // The source row is gone unless another kind moved INTO that byte.
        if !destinations.contains(&row.old_byte) {
            assert!(
                store
                    .type_index
                    .get(&rtxn, &type_index_key(row.old_byte, &row.id))?
                    .is_none(),
                "{} type-index row must not survive at the old byte",
                row.kind
            );
        }

        assert_eq!(
            store
                .vault_meta
                .get(&rtxn, &short_id_counter_key(row.new_byte))?
                .map(|raw| raw.to_vec()),
            Some(u64::from(row.old_byte).to_le_bytes().to_vec()),
            "{} short-id counter must move with its kind, value intact",
            row.kind
        );
    }

    // Per-kind counts: one entity and one index row per moved kind, and nothing
    // left over anywhere.
    assert_eq!(store.entities.len(&rtxn)?, rows.len() as u64);
    assert_eq!(store.type_index.len(&rtxn)?, rows.len() as u64);

    // Edges are byte-for-byte untouched.
    assert_eq!(
        store
            .edges_out
            .get(&rtxn, &legacy_edge_key(&rows))?
            .map(|raw| raw.to_vec()),
        Some(LEGACY_EDGE_VALUE.to_vec())
    );
    assert_eq!(
        store
            .edges_in
            .get(&rtxn, &legacy_edge_key(&rows))?
            .map(|raw| raw.to_vec()),
        Some(LEGACY_EDGE_VALUE.to_vec())
    );
    assert_eq!(store.edges_out.len(&rtxn)?, 1);
    assert_eq!(store.edges_in.len(&rtxn)?, 1);
    drop(rtxn);
    drop(store);

    assert_eq!(
        stored_abi(dir.path())?,
        Some(STORAGE_ABI_VERSION),
        "the new ABI is stamped after the assertions pass"
    );
    Ok(())
}

/// A moved structural-kind registry record follows its byte and has its zone
/// code RE-DERIVED — a relocated row must not keep a zone describing where it
/// used to live.
#[test]
fn byte_space_v3_rekey_moves_structural_kind_registrations() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let rows = legacy_rows();
    // COMPANION_REGISTER is the one moved kind with a real dynamic-registration
    // history, and it moves from the companion band into the system zone.
    let companion = TYPE_BYTE_REKEY_V3
        .iter()
        .find(|entry| entry.kind == "COMPANION_REGISTER")
        .copied()
        .expect("COMPANION_REGISTER is in the map");
    write_pre_v3_vault(dir.path(), &rows, |store, wtxn| {
        // Band code 2 is the pre-v3 COMPANION band, the row's honest origin.
        let record = pre_v3_registration_record(
            companion.old,
            2,
            COMPANION_REGISTER_SHORT_ID_PREFIX,
            COMPANION_REGISTER_PACK_ID,
        );
        store
            .vault_meta
            .put(wtxn, &structural_kind_registry_key(companion.old), &record)?;
        Ok(())
    })?;

    let store = Store::open(dir.path(), &VaultConfig::device())?;
    let rtxn = store.env.read_txn()?;
    assert!(
        store
            .vault_meta
            .get(&rtxn, &structural_kind_registry_key(companion.old))?
            .is_none(),
        "the registry record must not survive at the old byte"
    );
    let moved = store
        .vault_meta
        .get(&rtxn, &structural_kind_registry_key(companion.new))?
        .expect("the registry record must land at the new byte")
        .to_vec();
    let decoded =
        decode_structural_kind_registration(&structural_kind_registry_key(companion.new), &moved)?;
    assert_eq!(decoded.type_byte, companion.new);
    assert_eq!(decoded.short_id_prefix, COMPANION_REGISTER_SHORT_ID_PREFIX);
    assert_eq!(decoded.pack, COMPANION_REGISTER_PACK_ID);
    assert_eq!(
        decoded.zone,
        zone_of(companion.new),
        "the zone code is re-derived from the destination byte, never carried"
    );
    Ok(())
}

/// Builds a pre-v3 dynamic registration record: version 1, and a byte-2
/// discriminant drawn from the PRE-V3 SIX-BAND table (Companion 2, Productivity
/// 3, CRM 4), which is a different table from the v3 zone ordinals.
fn pre_v3_registration_record(type_byte: u8, band_code: u8, prefix: &str, pack: &str) -> Vec<u8> {
    let mut record = vec![
        STRUCTURAL_KIND_REGISTRY_RECORD_VERSION_PRE_V3,
        type_byte,
        band_code,
        u8::try_from(prefix.len()).expect("fixture prefix length fits u8"),
    ];
    record.extend_from_slice(
        &u16::try_from(pack.len())
            .expect("fixture pack length fits u16")
            .to_le_bytes(),
    );
    record.extend_from_slice(prefix.as_bytes());
    record.extend_from_slice(pack.as_bytes());
    record
}

/// Dynamic registrations the map does NOT move still have to survive the ABI
/// bump.
///
/// A legitimate pre-v3 vault could register a pack anywhere in the old
/// companion/productivity/CRM bands, so rows at 87-99 and 107-119 are neither
/// re-key sources nor collision-checked destinations. Their persisted byte-2
/// discriminant is a pre-v3 BAND ordinal, and v3 reads that same byte off a
/// different table — old Productivity (3) reads as CompiledProduct, old CRM (4)
/// as EngineExperimental — so an untouched row declares a zone its byte is not
/// in. The re-key rewrites every surviving row in its own transaction, before
/// the new ABI is stamped.
#[test]
fn byte_space_v3_rekey_rezones_registry_rows_the_map_does_not_move() -> Result<()> {
    // Neither byte is a re-key source or destination, and neither carries a
    // static kind — exactly the gap the map leaves open.
    const PRODUCTIVITY_BYTE: u8 = 90;
    const CRM_BYTE: u8 = 110;

    let dir = tempfile::tempdir()?;
    let rows = legacy_rows();
    write_pre_v3_vault(dir.path(), &rows, |store, wtxn| {
        store.vault_meta.put(
            wtxn,
            &structural_kind_registry_key(PRODUCTIVITY_BYTE),
            &pre_v3_registration_record(PRODUCTIVITY_BYTE, 3, "qz", "productivity-pack"),
        )?;
        store.vault_meta.put(
            wtxn,
            &structural_kind_registry_key(CRM_BYTE),
            &pre_v3_registration_record(CRM_BYTE, 4, "zx", "crm-pack"),
        )?;
        Ok(())
    })?;

    // The load-time registry vet runs AFTER the open transaction commits, so a
    // row left declaring the wrong zone does not merely mis-report itself — it
    // fails the open of a vault already stamped at the new ABI.
    let store = Store::open(dir.path(), &VaultConfig::device())?;
    let rtxn = store.env.read_txn()?;
    for (byte, prefix, pack) in [
        (PRODUCTIVITY_BYTE, "qz", "productivity-pack"),
        (CRM_BYTE, "zx", "crm-pack"),
    ] {
        let key = structural_kind_registry_key(byte);
        let raw = store
            .vault_meta
            .get(&rtxn, &key)?
            .unwrap_or_else(|| panic!("the registration at {byte} must survive the re-key"))
            .to_vec();
        let decoded = decode_structural_kind_registration(&key, &raw)?;
        assert_eq!(decoded.type_byte, byte);
        assert_eq!(decoded.short_id_prefix, prefix);
        assert_eq!(decoded.pack, pack);
        assert_eq!(
            decoded.zone,
            zone_of(byte),
            "the surviving row at {byte} must carry its v3 zone, not a pre-v3 band ordinal"
        );
    }
    drop(rtxn);
    drop(store);

    assert_eq!(
        stored_abi(dir.path())?,
        Some(STORAGE_ABI_VERSION),
        "the new ABI is stamped once the migrated registry is proven loadable"
    );
    Ok(())
}

/// Every rejection path aborts the WHOLE transaction: old bytes and the old ABI
/// marker both survive, so the vault stays openable by the predecessor engine.
#[test]
fn byte_space_v3_rekey_rolls_back_whole_transaction_on_any_anomaly() -> Result<()> {
    struct Case {
        name: &'static str,
        inject: fn(&Store, &mut RwTxn<'_>, &[LegacyRow]) -> Result<()>,
    }

    let cases = [
        Case {
            // A destination byte this map does not vacate already holds rows.
            name: "destination_collision",
            inject: |store, wtxn, _rows| {
                let squatter = EntityId::from_bytes([0x5A; 16]).expect("squatter id");
                let mut value = vec![79_u8];
                value.extend_from_slice(&[0; 24]);
                store.entities.put(wtxn, squatter.as_bytes(), &value)?;
                store
                    .type_index
                    .put(wtxn, &type_index_key(79, &squatter), &[])?;
                Ok(())
            },
        },
        Case {
            // An envelope too short to carry a full header.
            name: "malformed_envelope",
            inject: |store, wtxn, rows| {
                store
                    .entities
                    .put(wtxn, rows[0].id.as_bytes(), &[rows[0].old_byte, 1, 2])?;
                Ok(())
            },
        },
        Case {
            // An entity with no type-index row: the id sets disagree, so the
            // counts cannot balance.
            name: "count_mismatch",
            inject: |store, wtxn, rows| {
                store
                    .type_index
                    .delete(wtxn, &type_index_key(rows[0].old_byte, &rows[0].id))?;
                Ok(())
            },
        },
        Case {
            // A short-id counter already sitting on an unvacated destination.
            name: "short_id_counter_collision",
            inject: |store, wtxn, _rows| {
                store
                    .vault_meta
                    .put(wtxn, &short_id_counter_key(79), &7_u64.to_le_bytes())?;
                Ok(())
            },
        },
        Case {
            // A surviving registration the map does not move, malformed past
            // what the loader accepts (a three-letter short-id prefix). The
            // registry is loaded AFTER the open transaction commits, so the
            // re-key has to prove the migrated registry loads BEFORE it stamps
            // — otherwise the rejection lands on a vault already carrying the
            // new ABI, which the predecessor engine can no longer open.
            name: "unloadable_surviving_registry_row",
            inject: |store, wtxn, _rows| {
                store.vault_meta.put(
                    wtxn,
                    &structural_kind_registry_key(95),
                    &pre_v3_registration_record(95, 3, "abc", "stray-pack"),
                )?;
                Ok(())
            },
        },
    ];

    for case in cases {
        let dir = tempfile::tempdir()?;
        let rows = legacy_rows();
        let inject = case.inject;
        write_pre_v3_vault(dir.path(), &rows, |store, wtxn| inject(store, wtxn, &rows))?;

        let error = match Store::open(dir.path(), &VaultConfig::device()) {
            Ok(_) => panic!("case {}: the re-key must fail closed", case.name),
            Err(error) => error,
        };
        assert_eq!(
            error.kind(),
            ErrorKind::CorruptedIndex,
            "case {}: wrong error: {error:?}",
            case.name
        );

        // Rollback: the old stamp survives, so the predecessor engine can still
        // open this vault.
        assert_eq!(
            stored_abi(dir.path())?,
            Some(STORAGE_ABI_VERSION_V3_REKEY_PREDECESSOR),
            "case {}: a failed re-key must leave the old ABI marker",
            case.name
        );

        // …and so does every old byte.
        let type_bytes = raw_entity_type_bytes(dir.path(), &rows)?;
        for (row, actual) in rows.iter().zip(type_bytes).skip(1) {
            assert_eq!(
                actual,
                Some(row.old_byte),
                "case {}: {} must still carry its OLD byte after rollback",
                case.name,
                row.kind
            );
        }
    }
    Ok(())
}

// ─── ONE-1930: short-id aliases + the presentation-prefix re-key ───

/// Puts one entity and returns `(short_id, content_hash)` from its reverse row.
fn seed_short_id(vault: &Vault, id: &EntityId, body: &[u8]) -> Result<(String, u8)> {
    vault
        .batch()
        .put_replicated(id, 1, TimeRange { start: 1, end: 1 }, 2, body)
        .commit()?;
    let rtxn = vault.store.env.read_txn()?;
    let value = vault
        .store
        .short_ids_reverse
        .get(&rtxn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let (short_id, hash) = crate::batch::parse_short_id_value(&value)?;
    Ok((short_id.to_owned(), hash))
}

/// One hop, and only one. Every shape the blueprint forbids is refused by the
/// single alias write door rather than by whatever the resolver happens to do
/// with it later.
#[test]
fn short_id_alias_rejects_chains_cycles_and_overwrites() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let first = entity_id(0x41);
    let second = entity_id(0x42);
    let (first_short_id, first_hash) = seed_short_id(&vault, &first, b"first")?;
    let (second_short_id, second_hash) = seed_short_id(&vault, &second, b"second")?;
    let first_target = ShortIdAliasTarget::EntityForwardKey(
        crate::batch::encode_short_id_forward_key(&first_short_id, first_hash),
    );
    let second_target = ShortIdAliasTarget::EntityForwardKey(
        crate::batch::encode_short_id_forward_key(&second_short_id, second_hash),
    );

    let mut wtxn = vault.store.env.write_txn()?;

    // A legacy id that is not a presentation id at all.
    for malformed in ["", "cl", "CL17", "s1", "cl-17"] {
        assert_eq!(
            vault
                .store
                .insert_short_id_alias(&mut wtxn, malformed, &first_target)
                .expect_err("malformed legacy id must be refused")
                .kind(),
            ErrorKind::InvariantViolation,
            "{malformed:?}"
        );
    }

    // Self-cycle: an id may not alias itself.
    assert_eq!(
        vault
            .store
            .insert_short_id_alias(&mut wtxn, &first_short_id, &first_target)
            .expect_err("self-cycle must be refused")
            .kind(),
        ErrorKind::InvariantViolation
    );

    // A legitimate alias lands, and re-inserting the SAME row is a no-op so a
    // retried re-key stays idempotent.
    vault
        .store
        .insert_short_id_alias(&mut wtxn, "zz1", &first_target)?;
    vault
        .store
        .insert_short_id_alias(&mut wtxn, "zz1", &first_target)?;
    assert_eq!(
        vault.store.resolve_short_id_alias(&wtxn, "zz1")?,
        Some(first_target.clone())
    );

    // Overwrite: the same legacy id may not be repointed at another entity.
    assert_eq!(
        vault
            .store
            .insert_short_id_alias(&mut wtxn, "zz1", &second_target)
            .expect_err("repointing an alias must be refused")
            .kind(),
        ErrorKind::InvariantViolation
    );

    // Chain: `first_short_id` is now itself aliased by `zz1`, so nothing may
    // target it — following two hops is exactly what the one-hop rule forbids.
    vault
        .store
        .insert_short_id_alias(&mut wtxn, "zz2", &second_target)?;
    let alias_to_alias = ShortIdAliasTarget::EntityForwardKey(
        crate::batch::encode_short_id_forward_key("zz1", first_hash),
    );
    assert_eq!(
        vault
            .store
            .insert_short_id_alias(&mut wtxn, "zz3", &alias_to_alias)
            .expect_err("aliasing an alias must be refused")
            .kind(),
        ErrorKind::InvariantViolation
    );
    wtxn.commit()?;
    Ok(())
}

/// A live forward row always wins over an alias, so an alias can never mask a
/// real entity even when one is minted at the same spelling later.
#[test]
fn short_id_alias_never_shadows_a_live_forward_row() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let aliased = entity_id(0x43);
    let (aliased_short_id, aliased_hash) = seed_short_id(&vault, &aliased, b"aliased")?;

    let real = entity_id(0x44);
    let (real_short_id, real_hash) = seed_short_id(&vault, &real, b"real")?;

    vault.alias_short_id_to_entity(&real_short_id, &aliased)?;
    assert_eq!(
        vault.short_id_alias(&real_short_id)?,
        Some(ShortIdAliasTarget::EntityForwardKey(
            crate::batch::encode_short_id_forward_key(&aliased_short_id, aliased_hash)
        ))
    );

    // The alias exists, but the canonical row is consulted first.
    let hydrated = vault
        .hydrate_short_id(&real_short_id, real_hash)?
        .expect("the live forward row resolves");
    assert_eq!(hydrated.id, real, "a live forward row must beat an alias");
    Ok(())
}

/// The vault-namespace alias variant is real, not decorative: `vtN` is a
/// presentation slug that resolves to a durable 32-byte vault identity.
#[test]
fn short_id_alias_resolves_a_vault_namespace_target() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let vault_id: crate::authority::AuthorityVaultId = [0x7c; 32];

    vault.alias_short_id_to_vault("vt5", vault_id)?;
    assert_eq!(
        vault.short_id_alias("vt5")?,
        Some(ShortIdAliasTarget::Vault(vault_id))
    );

    // A vault target does not resolve to an ENTITY, and saying so is the
    // resolver's job rather than a panic.
    assert!(vault.hydrate_short_id("vt5", 0x01)?.is_none());
    Ok(())
}

/// The grammar marker and the rows it describes commit or roll back TOGETHER.
///
/// A destination spelling already held by a different entity is the collision
/// the pass must fail closed on; when it does, nothing it staged may survive —
/// not the moved rows, not the aliases, and not the marker that would make a
/// reopen skip the pass entirely.
#[test]
fn short_id_rekey_collision_rolls_back_rows_and_grammar_marker() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let victim = entity_id(0x45);
    let (victim_short_id, victim_hash) = seed_short_id(&vault, &victim, b"victim")?;
    let parsed = crate::entity_id::parse_presentation_id(&victim_short_id)?;
    assert_eq!(parsed.prefix, "tn", "seeded rows are TURNs");
    let colliding_short_id = format!("xy{}", parsed.digits);

    // Park an unrelated entity on the destination spelling.
    let squatter = entity_id(0x46);
    vault
        .batch()
        .put_replicated(&squatter, 1, TimeRange { start: 1, end: 1 }, 2, b"squatter")
        .commit()?;
    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.short_ids.put(
            &mut wtxn,
            &crate::batch::encode_short_id_forward_key(&colliding_short_id, victim_hash),
            squatter.as_bytes(),
        )?;
        wtxn.commit()?;
    }

    let map = &[ShortIdPrefixRekey {
        kind: "TURN",
        type_byte: 1,
        old_prefix: "tn",
        new_prefix: "xy",
    }];

    // Put the vault back in its pre-ONE-1930 state so the fixture can mirror
    // the open path exactly: ONE transaction that runs the pass and stamps the
    // marker only on `Ok`.
    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .vault_meta
            .delete(&mut wtxn, SHORT_ID_GRAMMAR_VERSION_KEY)?;
        wtxn.commit()?;
    }

    let mut wtxn = vault.store.env.write_txn()?;
    let error = vault
        .store
        .rekey_short_ids_v1(&mut wtxn, map)
        .expect_err("a destination collision must fail closed");
    assert_eq!(error.kind(), ErrorKind::CorruptedIndex);
    // The open path stamps the marker only after this returns `Ok`, so the
    // stamp below is never reached and the abort takes the staged rows with it.
    vault.store.vault_meta.put(
        &mut wtxn,
        SHORT_ID_GRAMMAR_VERSION_KEY,
        &SHORT_ID_GRAMMAR_VERSION.to_le_bytes(),
    )?;
    wtxn.abort();

    let rtxn = vault.store.env.read_txn()?;
    // The victim still carries its ORIGINAL spelling, no alias was minted, and
    // the marker is gone — a reopen will retry rather than skip.
    let value = vault
        .store
        .short_ids_reverse
        .get(&rtxn, victim.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let (rolled_back, _) = crate::batch::parse_short_id_value(&value)?;
    assert_eq!(rolled_back, victim_short_id);
    assert_eq!(
        vault
            .store
            .resolve_short_id_alias(&rtxn, &victim_short_id)?,
        None
    );
    assert_eq!(
        vault
            .store
            .vault_meta
            .get(&rtxn, SHORT_ID_GRAMMAR_VERSION_KEY)?
            .map(|raw| raw.to_vec()),
        None,
        "the grammar marker must roll back with the rows it describes"
    );
    Ok(())
}

/// Opening a vault stamps the grammar marker, and reopening is a no-op.
#[test]
fn short_id_grammar_marker_is_stamped_once_at_open() -> Result<()> {
    let dir = tempfile::tempdir()?;
    {
        let store = Store::open(dir.path(), &VaultConfig::device())?;
        let rtxn = store.env.read_txn()?;
        assert_eq!(
            read_vault_meta_u16(
                &store.vault_meta,
                &rtxn,
                SHORT_ID_GRAMMAR_VERSION_KEY,
                "short id grammar version",
            )?,
            Some(SHORT_ID_GRAMMAR_VERSION)
        );
    }
    let store = Store::open(dir.path(), &VaultConfig::device())?;
    let rtxn = store.env.read_txn()?;
    assert_eq!(
        read_vault_meta_u16(
            &store.vault_meta,
            &rtxn,
            SHORT_ID_GRAMMAR_VERSION_KEY,
            "short id grammar version",
        )?,
        Some(SHORT_ID_GRAMMAR_VERSION)
    );
    Ok(())
}

/// Aliases and the grammar marker are ADDITIVE `vault_meta` rows: no storage-ABI
/// bump, no 29th named database. A predecessor engine still opens the vault.
#[test]
fn short_id_aliases_add_no_named_database_and_no_abi_bump() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let target = entity_id(0x47);
    seed_short_id(&vault, &target, b"target")?;
    vault.alias_short_id_to_entity("zz9", &target)?;

    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        read_vault_meta_u16(
            &vault.store.vault_meta,
            &rtxn,
            STORAGE_ABI_VERSION_KEY,
            "storage ABI version",
        )?,
        Some(STORAGE_ABI_VERSION),
        "aliasing must not move the storage ABI"
    );
    assert!(
        !DB_MANIFEST.iter().any(|db| db.name.contains("alias")),
        "aliases live in vault_meta, never in a named database"
    );

    // The alias row is reachable as an ordinary `vault_meta` row, which is what
    // lets a predecessor engine ignore it instead of choking on it.
    assert!(
        vault
            .store
            .vault_meta
            .prefix_iter(&rtxn, SHORT_ID_ALIAS_KEY_PREFIX)?
            .count()
            == 1,
        "the alias must be a vault_meta row under its versioned prefix"
    );
    Ok(())
}

#[test]
fn critical_confirm_sweep_state_codec_is_exact_and_canonical() -> Result<()> {
    let (_tmp, vault) = open_test_vault();
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .put_critical_confirm_expiry_sweep_state_in_txn(wtxn, Some(7), Some(9))?;
        assert_eq!(
            vault
                .store
                .critical_confirm_expiry_sweep_state_in_txn(&*wtxn)?,
            (Some(7), Some(9)),
        );
        vault
            .store
            .put_critical_confirm_expiry_sweep_state_in_txn(wtxn, None, None)?;
        assert_eq!(
            vault
                .store
                .critical_confirm_expiry_sweep_state_in_txn(&*wtxn)?,
            (None, None),
        );
        Ok(())
    })?;
    Ok(())
}

#[test]
fn critical_confirm_sweep_state_codec_rejects_malformed_and_noncanonical_values() -> Result<()> {
    let (_tmp, vault) = open_test_vault();
    let malformed = [
        vec![0; 17],
        vec![2; 18],
        {
            let mut value = vec![0; 18];
            value[1] = 1;
            value
        },
        {
            let mut value = vec![0; 18];
            value[0] = 1;
            value[1..9].copy_from_slice(&10_u64.to_be_bytes());
            value[9] = 1;
            value[10..18].copy_from_slice(&9_u64.to_be_bytes());
            value
        },
    ];
    for value in malformed {
        vault.with_write_txn(|wtxn| {
            vault
                .store
                .vault_meta
                .put(wtxn, CRITICAL_CONFIRM_EXPIRY_CURSOR_KEY, &value)?;
            assert!(matches!(
                vault
                    .store
                    .critical_confirm_expiry_sweep_state_in_txn(&*wtxn),
                Err(Error::CorruptedIndex("critical confirm sweep state")),
            ));
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn retrieval_signal_hyde_round_trip() {
    assert_eq!(
        serde_json::to_string(&RetrievalSignal::Hyde).unwrap(),
        "\"hyde\""
    );
    assert_eq!(
        serde_json::from_str::<RetrievalSignal>("\"hyde\"").unwrap(),
        RetrievalSignal::Hyde
    );
    assert_eq!(RetrievalSignal::Hyde.as_blend_signal(), None);
}

// --- gate system-notice attribution guard -----------------------------------
//
// The guard exists to mirror what every writer already holds: a notice names
// the plane it came from, and version/docs_url are that plane's attribution.
// Accepting either without a plane, or accepting a plane the engine does not
// publish, records an attribution nobody can trace back to a rule.

fn policy_notice_record(
    policy_plane: Option<&str>,
    policy_version: Option<&str>,
    docs_url: Option<&str>,
) -> GateSystemNoticeRecord {
    GateSystemNoticeRecord {
        notice_type: "policy_block".to_owned(),
        channel: "policy.notice".to_owned(),
        voice: "system".to_owned(),
        audience: "user_and_model".to_owned(),
        body: "Withheld under a policy row.".to_owned(),
        row_ref: None,
        setting_change_offer: None,
        policy_plane: policy_plane.map(str::to_owned),
        policy_version: policy_version.map(str::to_owned),
        docs_url: docs_url.map(str::to_owned),
    }
}

#[test]
fn gate_notice_plane_tokens_mirror_the_policy_plane_enum() {
    // `store` sits under `policy_model`, so the guard spells the plane tokens
    // as literals. This is the only thing keeping the two spellings equal.
    use crate::policy_model::PolicyPlane;

    let published: Vec<&str> = [PolicyPlane::OwnerPolicy, PolicyPlane::HostedLegal]
        .iter()
        .map(|plane| plane.as_str())
        .collect();
    assert_eq!(GATE_SYSTEM_NOTICE_PLANE_TOKENS.to_vec(), published);
}

#[test]
fn gate_notice_accepts_what_the_in_crate_writers_produce() {
    // The owner-plane writer: plane only, no versioned document behind it.
    assert!(valid_gate_system_notice_record(&policy_notice_record(
        Some("owner_policy"),
        None,
        None
    )));
    // The hosted-legal writer: plane plus the hosted policy's attribution.
    assert!(valid_gate_system_notice_record(&policy_notice_record(
        Some("hosted_legal"),
        Some("2026-08-01"),
        Some("https://policy.example.test/hosted")
    )));
    // The hosted writer with no registered policy to point at: version, no url.
    assert!(valid_gate_system_notice_record(&policy_notice_record(
        Some("hosted_legal"),
        Some("2026-08-01"),
        None
    )));
    // The manifest-reseed writer: not a policy verdict, so no attribution.
    assert!(valid_gate_system_notice_record(&policy_notice_record(
        None, None, None
    )));
}

#[test]
fn gate_notice_rejects_a_plane_the_engine_does_not_publish() {
    // Well-formed snake_case is not the bar; being one of the two planes is.
    for plane in ["engine_floor", "hosted", "owner", "hosted_legal_v2"] {
        assert!(
            !valid_gate_system_notice_record(&policy_notice_record(Some(plane), None, None)),
            "invented plane {plane:?} was accepted"
        );
    }
    // Still rejected on the older grounds too: charset and emptiness.
    assert!(!valid_gate_system_notice_record(&policy_notice_record(
        Some("OwnerPolicy"),
        None,
        None
    )));
    assert!(!valid_gate_system_notice_record(&policy_notice_record(
        Some(""),
        None,
        None
    )));
}

#[test]
fn gate_notice_rejects_attribution_with_no_plane_behind_it() {
    // A version names the version of something; a docs_url points at what that
    // something publishes. Neither is readable without the plane.
    assert!(!valid_gate_system_notice_record(&policy_notice_record(
        None,
        Some("2026-08-01"),
        None
    )));
    assert!(!valid_gate_system_notice_record(&policy_notice_record(
        None,
        None,
        Some("https://policy.example.test/hosted")
    )));
    assert!(!valid_gate_system_notice_record(&policy_notice_record(
        None,
        Some("2026-08-01"),
        Some("https://policy.example.test/hosted")
    )));
}

#[test]
fn gate_notice_rejects_owner_plane_attribution_it_cannot_have() {
    // The owner plane publishes no versioned document, so a version or a link
    // on an owner notice points at a text that does not exist.
    assert!(!valid_gate_system_notice_record(&policy_notice_record(
        Some("owner_policy"),
        Some("2026-08-01"),
        None
    )));
    assert!(!valid_gate_system_notice_record(&policy_notice_record(
        Some("owner_policy"),
        None,
        Some("https://policy.example.test/owner")
    )));
    assert!(!valid_gate_system_notice_record(&policy_notice_record(
        Some("owner_policy"),
        Some("2026-08-01"),
        Some("https://policy.example.test/owner")
    )));
}

#[test]
fn gate_notice_rejects_a_hosted_verdict_that_names_no_version() {
    // A hosted notice cites a published document. Without the version it was
    // decided under, the citation cannot be traced back to the text.
    assert!(!valid_gate_system_notice_record(&policy_notice_record(
        Some("hosted_legal"),
        None,
        None
    )));
    assert!(!valid_gate_system_notice_record(&policy_notice_record(
        Some("hosted_legal"),
        None,
        Some("https://policy.example.test/hosted")
    )));
}

/// The guard runs on DECODE, not only on append.
///
/// The three tests above check the predicate. This one checks the consequence,
/// which is the half that actually costs something: `decode_gate_decision` vets
/// every row it reads, so tightening the predicate makes a non-conforming row
/// that is ALREADY ON DISK unreadable — `CorruptedIndex`, from a point read as
/// much as from a scan. "No writer in this crate can produce one" is a claim
/// about today's writers, not about the bytes in a vault someone opened last
/// year, and a later loosen-then-tighten cycle would leave exactly these rows
/// behind. Pinned here so that consequence is a decision and not a surprise.
#[test]
fn a_persisted_notice_with_unattributable_policy_fields_stops_decoding() -> Result<()> {
    let base = gate_decision(synthetic_gate_decision_id(0x7E, 1), 3, None);
    for (case, notice) in [
        (
            "a plane the engine does not publish",
            policy_notice_record(Some("engine_floor"), None, None),
        ),
        (
            "version and docs_url with no plane behind them",
            policy_notice_record(
                None,
                Some("2026-08-01"),
                Some("https://policy.example.test/hosted"),
            ),
        ),
    ] {
        let row = GateDecisionRecord {
            system_notices: vec![notice],
            ..base.clone()
        };
        // The writer path's own encoder, so these bytes are byte-for-byte what
        // a build predating the guard would have committed.
        let encoded = encode_gate_decision(&row)?;
        let decoded = decode_gate_decision(&encoded).map(|_| ());
        assert!(
            matches!(decoded, Err(Error::CorruptedIndex("gate decision ledger"))),
            "{case}: raw decode must fail closed: {decoded:?}",
        );

        // Planted straight onto the primary, which is how such a row would
        // exist at all — the append door has been shut on it since the guard
        // landed, so nothing can put one there through the front.
        let (_dir, vault) = open_test_vault();
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .vault_meta
            .put(&mut wtxn, &gate_decision_key(row.decision_id), &encoded)?;
        wtxn.commit()?;
        let rtxn = vault.store.env.read_txn()?;
        let read = vault
            .store
            .gate_decision_in_txn(&rtxn, row.decision_id)
            .map(|_| ());
        assert!(
            matches!(read, Err(Error::CorruptedIndex("gate decision ledger"))),
            "{case}: point read must refuse the planted row: {read:?}",
        );
        drop(rtxn);

        let appended =
            vault.with_write_txn(|wtxn| vault.store.append_gate_decision_in_txn(wtxn, &row));
        assert!(
            matches!(appended, Err(Error::CorruptedIndex("gate decision ledger"))),
            "{case}: append must refuse it too: {appended:?}",
        );
    }
    Ok(())
}
