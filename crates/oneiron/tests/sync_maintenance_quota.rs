// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use loro::{ExportMode, LoroDoc};
use oneiron::registry::ENTITY_TYPE_EVENT;
use oneiron::sync::bridge::{Materializer, register_observer_b};
use oneiron::sync::quarantine::{QuarantineContainer, pending_remat_windows, quarantined_records};
use oneiron::sync::quota::{
    DEFAULT_MAINTENANCE_INGEST_MAX_OPS_PER_PEER_WINDOW, MaintenanceIngestQuotaConfig,
    maintenance_ingest_quota_config, maintenance_ingest_quota_snapshots,
    set_maintenance_ingest_quota_config,
};
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::forward_rematerialize;
use oneiron::{
    AUTHORITY_LOG_SCHEMA_VERSION, AuthorityAttestation, AuthorityEntryHash, AuthorityKey,
    AuthorityLogEntry, AuthorityOp, AuthoritySignature, AuthorityTier, AuthorityVaultId,
    DEFAULT_PENDING_WIDEN_DELAY_SECS, DeviceAuthority, ENTITY_TYPE_AUTHORITY_LOG, EntityId,
    ROLE_ADMIN, ROLE_AGENT, ROLE_OWNER, TimeRange, Vault, VaultConfig, authority_entry_hash,
    authority_transcript, encode_authority_log_entry_body, genesis_vault_id,
};

const WINDOW: &str = "2026-03";
const LEARNED_AT: u64 = 1_772_400_000;

fn test_config() -> VaultConfig {
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = None;
    cfg.max_readers = 16;
    cfg
}

fn test_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), test_config()).unwrap();
    (dir, vault)
}

fn set_quota(vault: &Vault, max_ops_per_peer_window: u32, quota_window_secs: u64) {
    set_maintenance_ingest_quota_config(
        vault,
        MaintenanceIngestQuotaConfig {
            max_ops_per_peer_window,
            quota_window_secs,
        },
    )
    .unwrap();
}

fn authority_key_from_ed(key: &SigningKey) -> AuthorityKey {
    AuthorityKey::Ed25519(key.verifying_key().to_bytes())
}

fn attestation() -> AuthorityAttestation {
    AuthorityAttestation {
        kind: "SoftwareArgon2id".to_owned(),
        evidence: vec![1, 2, 3],
    }
}

fn device(key: AuthorityKey, roles: u16) -> DeviceAuthority {
    DeviceAuthority {
        key,
        transport_key_binding: [7; 32],
        attestation: attestation(),
        tier: AuthorityTier::Software,
        roles,
    }
}

fn unsigned_entry(
    vault_id: Option<AuthorityVaultId>,
    seq: u64,
    parent_hashes: Vec<AuthorityEntryHash>,
    op: AuthorityOp,
    signer_key: AuthorityKey,
    ts: u64,
) -> AuthorityLogEntry {
    AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id,
        seq,
        parent_hashes,
        op,
        signer: AuthoritySignature {
            suite: signer_key.suite(),
            public_key: signer_key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts,
    }
}

fn sign_entry(mut entry: AuthorityLogEntry, key: &SigningKey) -> AuthorityLogEntry {
    let transcript = authority_transcript(&entry).unwrap();
    entry.signer.signature = key.sign(&transcript).to_bytes().to_vec();
    entry
}

fn cosign_entry(
    mut entry: AuthorityLogEntry,
    signer: &SigningKey,
    cosigner: &SigningKey,
) -> AuthorityLogEntry {
    let cosigner_key = authority_key_from_ed(cosigner);
    entry.signer.signature = vec![0; 64];
    entry.cosigns.clear();
    entry.cosigns.push(AuthoritySignature {
        suite: cosigner_key.suite(),
        public_key: cosigner_key,
        signature: vec![0; 64],
    });
    let transcript = authority_transcript(&entry).unwrap();
    entry.signer.signature = signer.sign(&transcript).to_bytes().to_vec();
    entry.cosigns[0].signature = cosigner.sign(&transcript).to_bytes().to_vec();
    entry
}

fn genesis_entry(seed: u8) -> (SigningKey, AuthorityLogEntry, AuthorityVaultId) {
    let signing = SigningKey::from_bytes(&[seed; 32]);
    let key = authority_key_from_ed(&signing);
    let entry = sign_entry(
        unsigned_entry(
            None,
            0,
            Vec::new(),
            AuthorityOp::Genesis {
                device: device(key.clone(), ROLE_OWNER | ROLE_ADMIN),
                genesis_nonce: [seed.wrapping_add(10); 32],
                tier_floor: AuthorityTier::Software,
                pending_widen_delay_secs: DEFAULT_PENDING_WIDEN_DELAY_SECS,
            },
            key,
            LEARNED_AT,
        ),
        &signing,
    );
    let vault_id = genesis_vault_id(&entry).unwrap();
    (signing, entry, vault_id)
}

fn enroll_entry(
    vault_id: AuthorityVaultId,
    parent_hash: AuthorityEntryHash,
    signer: &SigningKey,
    new_key: &SigningKey,
    seq: u64,
) -> AuthorityLogEntry {
    let signer_key = authority_key_from_ed(signer);
    sign_entry(
        unsigned_entry(
            Some(vault_id),
            seq,
            vec![parent_hash],
            AuthorityOp::EnrollDevice {
                device: device(authority_key_from_ed(new_key), ROLE_ADMIN | ROLE_AGENT),
            },
            signer_key,
            LEARNED_AT + seq,
        ),
        signer,
    )
}

fn set_tier_floor_entry(
    vault_id: AuthorityVaultId,
    parent_hash: AuthorityEntryHash,
    signer: &SigningKey,
    seq: u64,
) -> AuthorityLogEntry {
    let signer_key = authority_key_from_ed(signer);
    sign_entry(
        unsigned_entry(
            Some(vault_id),
            seq,
            vec![parent_hash],
            AuthorityOp::SetTierFloor {
                tier_floor: AuthorityTier::Software,
            },
            signer_key,
            LEARNED_AT + seq,
        ),
        signer,
    )
}

fn authority_blob(entry: &AuthorityLogEntry) -> Vec<u8> {
    authority_blob_with_times(entry, LEARNED_AT, LEARNED_AT, LEARNED_AT)
}

fn authority_blob_with_times(
    entry: &AuthorityLogEntry,
    occurred_start: u64,
    occurred_end: u64,
    learned_at: u64,
) -> Vec<u8> {
    let body = encode_authority_log_entry_body(entry).unwrap();
    let mut blob = Vec::with_capacity(25 + body.len());
    blob.push(ENTITY_TYPE_AUTHORITY_LOG);
    blob.extend_from_slice(&occurred_start.to_be_bytes());
    blob.extend_from_slice(&occurred_end.to_be_bytes());
    blob.extend_from_slice(&learned_at.to_be_bytes());
    blob.extend_from_slice(&body);
    blob
}

fn insert_authority_blob(doc: &LoroDoc, id: EntityId, blob: &[u8]) {
    doc.get_map("entities")
        .insert(id.to_hex().as_str(), blob)
        .unwrap();
}

/// Inserts an authority entry under its CONTENT-DERIVED store key
/// (ONE-1604-D1: AUTHORITY_LOG ids are never caller-chosen) and returns that id.
/// The hand-built CRDT fixture derives the key through the engine's own
/// `authority_log_entity_id` so remote rows carry the same key the engine
/// would have chosen.
fn insert_authority_entry(doc: &LoroDoc, entry: &AuthorityLogEntry) -> EntityId {
    let id = oneiron::authority::authority_log_entity_id(entry).unwrap();
    insert_authority_blob(doc, id, &authority_blob(entry));
    id
}

fn seed_local_genesis(
    vault: &Vault,
    seed: u8,
) -> (SigningKey, AuthorityLogEntry, AuthorityVaultId) {
    let (signing, genesis, vault_id) = genesis_entry(seed);
    vault
        .put_authority_log_entry(
            &genesis,
            TimeRange {
                start: LEARNED_AT,
                end: LEARNED_AT,
            },
            LEARNED_AT,
        )
        .unwrap();
    (signing, genesis, vault_id)
}

fn quota_quarantine_count(vault: &Vault) -> usize {
    quarantined_records(vault)
        .unwrap()
        .into_iter()
        .filter(|(_, record)| {
            record.container == QuarantineContainer::Entities
                && record.reason_code == "MaintenanceIngestQuotaExceeded"
        })
        .count()
}

fn invalid_authority_log_quarantine_count(vault: &Vault) -> usize {
    entity_quarantine_reasons(vault)
        .into_iter()
        .filter(|reason| reason == "InvalidAuthorityLogBody")
        .count()
}

fn entity_quarantine_reasons(vault: &Vault) -> Vec<String> {
    quarantined_records(vault)
        .unwrap()
        .into_iter()
        .filter(|(_, record)| record.container == QuarantineContainer::Entities)
        .map(|(_, record)| record.reason_code)
        .collect()
}

#[test]
fn known_key_flood_quarantines_excess_and_bounds_authority_log_growth() {
    let (_dir, vault) = test_vault();
    set_quota(&vault, 2, 60 * 60);
    let materializer = Materializer::new();
    let window_key = WindowKey::new(WINDOW);
    let doc = create_window_doc("user", &window_key);

    let (owner_key, genesis, vault_id) = seed_local_genesis(&vault, 0x41);
    let before = vault
        .count_entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)
        .unwrap();
    let mut parent = authority_entry_hash(&genesis).unwrap();

    for idx in 0..5u64 {
        let entry = set_tier_floor_entry(vault_id, parent, &owner_key, idx + 1);
        parent = authority_entry_hash(&entry).unwrap();
        insert_authority_entry(&doc, &entry);
    }
    doc.commit();

    let accepted = forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap();
    assert_eq!(accepted, 2);
    assert_eq!(
        vault
            .count_entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)
            .unwrap(),
        before + 2
    );
    assert_eq!(quota_quarantine_count(&vault), 3);

    let snapshots = maintenance_ingest_quota_snapshots(&vault).unwrap();
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].accepted_count, 2);
    assert_eq!(snapshots[0].max_ops_per_peer_window, 2);

    let accepted_again = forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap();
    assert_eq!(accepted_again, 0);
    assert_eq!(
        vault
            .count_entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)
            .unwrap(),
        before + 2
    );
}

#[test]
fn foreign_authority_log_is_quarantined_not_batch_abort_on_replay_doors() {
    let (_dir, vault) = test_vault();
    let materializer = Materializer::new();
    let window_key = WindowKey::new(WINDOW);
    let doc = create_window_doc("user", &window_key);
    let (owner_key, genesis, vault_id) = seed_local_genesis(&vault, 0x45);
    let (_, foreign_genesis, _) = genesis_entry(0x46);
    let good_entry = set_tier_floor_entry(
        vault_id,
        authority_entry_hash(&genesis).unwrap(),
        &owner_key,
        1,
    );
    let foreign_id = insert_authority_entry(&doc, &foreign_genesis);
    let good_id = insert_authority_entry(&doc, &good_entry);
    doc.commit();

    assert_eq!(
        forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap(),
        1
    );
    assert!(
        !vault
            .entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)
            .unwrap()
            .contains(&foreign_id),
        "foreign authority log must be quarantined, not materialized"
    );
    assert!(
        vault
            .entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)
            .unwrap()
            .contains(&good_id),
        "valid sibling must still materialize after quarantining a foreign authority log"
    );
    assert_eq!(invalid_authority_log_quarantine_count(&vault), 1);

    let (_dir_b, vault_b) = test_vault();
    let vault_b = Arc::new(vault_b);
    let doc_b = LoroDoc::new();
    let materializer_b = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc_b, &vault_b, &materializer_b, WINDOW);
    let (owner_key_b, genesis_b, vault_id_b) = seed_local_genesis(&vault_b, 0x47);
    let (_, foreign_genesis_b, _) = genesis_entry(0x48);
    let good_entry_b = set_tier_floor_entry(
        vault_id_b,
        authority_entry_hash(&genesis_b).unwrap(),
        &owner_key_b,
        1,
    );
    let foreign_id_b = insert_authority_entry(&doc_b, &foreign_genesis_b);
    let good_id_b = insert_authority_entry(&doc_b, &good_entry_b);
    doc_b.commit();

    assert!(
        !vault_b
            .entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)
            .unwrap()
            .contains(&foreign_id_b),
        "observer-b must quarantine foreign authority log, not materialize it"
    );
    assert!(
        vault_b
            .entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)
            .unwrap()
            .contains(&good_id_b),
        "observer-b must continue materializing valid siblings"
    );
    assert_eq!(invalid_authority_log_quarantine_count(vault_b.as_ref()), 1);
}

#[test]
fn same_vault_unknown_signers_share_fallback_bucket() {
    let (_dir, vault) = test_vault();
    set_quota(&vault, 1, 60 * 60);
    let materializer = Materializer::new();
    let window_key = WindowKey::new(WINDOW);
    let doc = create_window_doc("user", &window_key);
    let (owner_key, genesis, vault_id) = seed_local_genesis(&vault, 0x49);
    let parent_hash = authority_entry_hash(&genesis).unwrap();
    let before = vault
        .count_entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)
        .unwrap();

    for idx in 0..3 {
        let rogue_key = SigningKey::from_bytes(&[0x5a + idx; 32]);
        let rogue_entry = set_tier_floor_entry(vault_id, parent_hash, &rogue_key, 1);
        insert_authority_entry(&doc, &rogue_entry);
    }
    let valid_entry = set_tier_floor_entry(vault_id, parent_hash, &owner_key, 1);
    insert_authority_entry(&doc, &valid_entry);
    doc.commit();

    assert_eq!(
        forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap(),
        2
    );
    assert_eq!(
        vault
            .count_entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)
            .unwrap(),
        before + 2
    );
    assert_eq!(
        invalid_authority_log_quarantine_count(&vault),
        0,
        "same-vault unknown signers are bounded by a shared quota bucket, not terminally rejected"
    );
    assert_eq!(
        quota_quarantine_count(&vault),
        2,
        "fresh signer rotation must not create independent quota buckets"
    );

    let snapshots = maintenance_ingest_quota_snapshots(&vault).unwrap();
    assert_eq!(snapshots.len(), 2);
    assert!(
        snapshots
            .iter()
            .all(|snapshot| snapshot.accepted_count == 1)
    );
}

#[test]
fn newly_enrolled_signer_entry_can_replay_before_enrollment() {
    let (_dir, vault) = test_vault();
    set_quota(&vault, 8, 60 * 60);
    let materializer = Materializer::new();
    let window_key = WindowKey::new(WINDOW);
    let doc = create_window_doc("user", &window_key);
    let (owner_key, genesis, vault_id) = seed_local_genesis(&vault, 0x4b);
    let new_key = SigningKey::from_bytes(&[0x6b; 32]);
    let enroll = enroll_entry(
        vault_id,
        authority_entry_hash(&genesis).unwrap(),
        &owner_key,
        &new_key,
        1,
    );
    let first_new_signer_entry = cosign_entry(
        set_tier_floor_entry(
            vault_id,
            authority_entry_hash(&enroll).unwrap(),
            &new_key,
            0,
        ),
        &new_key,
        &owner_key,
    );
    let before = vault
        .count_entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)
        .unwrap();

    let child_id = insert_authority_entry(&doc, &first_new_signer_entry);
    let enroll_id = insert_authority_entry(&doc, &enroll);
    doc.commit();

    assert_eq!(
        forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap(),
        2
    );
    let authority_ids = vault.entities_by_type(ENTITY_TYPE_AUTHORITY_LOG).unwrap();
    assert!(authority_ids.contains(&child_id));
    assert!(authority_ids.contains(&enroll_id));
    assert_eq!(
        vault
            .count_entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)
            .unwrap(),
        before + 2
    );
    assert_eq!(invalid_authority_log_quarantine_count(&vault), 0);
}

#[test]
fn under_quota_peer_is_unaffected_by_another_peer_flood() {
    let (_dir, vault) = test_vault();
    set_quota(&vault, 1, 60 * 60);
    let materializer = Materializer::new();
    let window_key = WindowKey::new(WINDOW);
    let doc = create_window_doc("user", &window_key);

    let (owner_key, genesis, vault_id) = seed_local_genesis(&vault, 0x42);
    let peer_key = SigningKey::from_bytes(&[0x24; 32]);
    let enroll = enroll_entry(
        vault_id,
        authority_entry_hash(&genesis).unwrap(),
        &owner_key,
        &peer_key,
        1,
    );
    vault
        .put_authority_log_entry(
            &enroll,
            TimeRange {
                start: LEARNED_AT,
                end: LEARNED_AT,
            },
            LEARNED_AT,
        )
        .unwrap();
    let before = vault
        .count_entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)
        .unwrap();

    let owner_one = set_tier_floor_entry(
        vault_id,
        authority_entry_hash(&enroll).unwrap(),
        &owner_key,
        2,
    );
    let owner_two = set_tier_floor_entry(
        vault_id,
        authority_entry_hash(&owner_one).unwrap(),
        &owner_key,
        3,
    );
    let peer_entry = set_tier_floor_entry(
        vault_id,
        authority_entry_hash(&enroll).unwrap(),
        &peer_key,
        1,
    );
    insert_authority_entry(&doc, &owner_one);
    insert_authority_entry(&doc, &owner_two);
    let peer_id = insert_authority_entry(&doc, &peer_entry);
    doc.commit();

    let accepted = forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap();
    assert_eq!(accepted, 2);
    assert_eq!(
        vault
            .count_entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)
            .unwrap(),
        before + 2
    );
    assert_eq!(quota_quarantine_count(&vault), 1);
    assert!(
        vault
            .entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)
            .unwrap()
            .contains(&peer_id),
        "peer below its own quota must still materialize"
    );

    let snapshots = maintenance_ingest_quota_snapshots(&vault).unwrap();
    assert_eq!(snapshots.len(), 2);
    assert!(
        snapshots
            .iter()
            .all(|snapshot| snapshot.accepted_count == 1)
    );
}

#[test]
fn honest_burst_quarantines_then_lazily_readmits_once_under_quota() {
    let (_dir, vault) = test_vault();
    set_quota(&vault, 2, u64::MAX);
    let materializer = Materializer::new();
    let window_key = WindowKey::new(WINDOW);
    let doc = create_window_doc("user", &window_key);

    let (owner_key, genesis, vault_id) = seed_local_genesis(&vault, 0x43);
    let before = vault
        .count_entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)
        .unwrap();
    let mut parent = authority_entry_hash(&genesis).unwrap();

    for idx in 0..4u64 {
        let entry = set_tier_floor_entry(vault_id, parent, &owner_key, idx + 1);
        parent = authority_entry_hash(&entry).unwrap();
        insert_authority_entry(&doc, &entry);
    }
    doc.commit();

    let first = forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap();
    assert_eq!(first, 2);
    assert_eq!(quota_quarantine_count(&vault), 2);
    assert_eq!(
        pending_remat_windows(&vault).unwrap(),
        vec![WINDOW.to_owned()],
        "quota overflow must keep a replay marker for lazy re-admission"
    );
    assert_eq!(
        vault
            .count_entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)
            .unwrap(),
        before + 2
    );

    set_quota(&vault, 4, u64::MAX);
    let second = forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap();
    assert_eq!(second, 2);
    assert_eq!(
        vault
            .count_entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)
            .unwrap(),
        before + 4
    );

    let snapshots = maintenance_ingest_quota_snapshots(&vault).unwrap();
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].accepted_count, 4);
    assert!(
        pending_remat_windows(&vault).unwrap().is_empty(),
        "successful lazy re-admission must clear the replay marker"
    );
}

/// The named rollback path is the POST-DEBIT one: the row must clear the
/// replicated authority door (which is what debits quota) and then be
/// rejected by `apply_put`'s envelope time-range gate. That only happens when
/// the blob sits at its own CONTENT-DERIVED store key — a caller-chosen id
/// rejects as `AuthorityLogStoreKeyMismatch` inside the door, BEFORE the
/// debit, and would silently retire the coverage this test is named for.
///
/// The derived key also carries a cross-type occupant, so the assertions
/// cover the ONE-1604-D1 dominance side effect on the same rejection: a
/// rejected row rolls back its quota debit AND leaves the squatter in place.
#[test]
fn observer_b_rolls_back_quota_when_replicated_apply_rejects() {
    let (_dir, vault) = test_vault();
    let vault = Arc::new(vault);
    set_quota(&vault, 1, 60 * 60);
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, WINDOW);
    let (owner_key, genesis, vault_id) = seed_local_genesis(&vault, 0x4a);
    let parent_hash = authority_entry_hash(&genesis).unwrap();
    let before = vault
        .count_entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)
        .unwrap();

    let bad_entry = set_tier_floor_entry(vault_id, parent_hash, &owner_key, 1);
    let bad_id = oneiron::authority::authority_log_entity_id(&bad_entry).unwrap();
    // A hostile peer pre-squats the derived id with an ordinary row.
    vault
        .put_entity(
            &bad_id,
            ENTITY_TYPE_EVENT,
            TimeRange {
                start: LEARNED_AT,
                end: LEARNED_AT,
            },
            LEARNED_AT,
            b"occupant",
        )
        .unwrap();
    let occupant = vault.get_raw(&bad_id).unwrap().expect("occupant stored");

    let bad_blob =
        authority_blob_with_times(&bad_entry, LEARNED_AT + 10, LEARNED_AT, LEARNED_AT + 10);
    insert_authority_blob(&doc, bad_id, &bad_blob);
    doc.commit();

    assert_eq!(
        entity_quarantine_reasons(&vault),
        vec!["InvalidTimeRange".to_owned()],
        "the rejection must be the post-debit envelope gate, not a pre-debit key mismatch"
    );
    assert_eq!(
        vault
            .count_entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)
            .unwrap(),
        before,
        "invalid metadata must not materialize"
    );
    assert!(
        maintenance_ingest_quota_snapshots(&vault)
            .unwrap()
            .is_empty(),
        "remote apply rejection must roll back the quota debit"
    );
    assert_eq!(
        vault.get_raw(&bad_id).unwrap(),
        Some(occupant),
        "a rejected authority row must not evict the occupant of its derived key"
    );

    // Same entry, well-formed envelope. Signing is deterministic, so this
    // re-lands on `bad_id` — the rejected row's rollback must have left both
    // the quota budget AND the key's occupant exactly as the retry found
    // them.
    let valid_entry = set_tier_floor_entry(vault_id, parent_hash, &owner_key, 1);
    let valid_id = insert_authority_entry(&doc, &valid_entry);
    assert_eq!(valid_id, bad_id, "content addressing must reuse the key");
    doc.commit();

    assert_eq!(
        vault
            .count_entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)
            .unwrap(),
        before + 1,
        "valid sibling must still have the peer quota available"
    );
    // The dominance side effect belongs to the ACCEPTED row, not the rejected
    // one: only now does the squatter go.
    assert_eq!(
        vault.get_authority_log_entry(&bad_id).unwrap(),
        Some(valid_entry),
        "the admitted row must displace the squatter and own its derived key"
    );
    let snapshots = maintenance_ingest_quota_snapshots(&vault).unwrap();
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].accepted_count, 1);
}

#[test]
fn quota_state_and_config_never_cross_sync_boundary() {
    let (_dir_a, vault_a) = test_vault();
    set_quota(&vault_a, 1, 60 * 60);
    let materializer_a = Materializer::new();
    let window_key = WindowKey::new(WINDOW);
    let doc_a = create_window_doc("user", &window_key);

    let (owner_key, genesis, vault_id) = seed_local_genesis(&vault_a, 0x44);
    let entry = set_tier_floor_entry(
        vault_id,
        authority_entry_hash(&genesis).unwrap(),
        &owner_key,
        1,
    );
    insert_authority_entry(&doc_a, &entry);
    doc_a.commit();
    assert_eq!(
        forward_rematerialize(&vault_a, &doc_a, &materializer_a, &window_key).unwrap(),
        1
    );
    assert_eq!(
        maintenance_ingest_quota_snapshots(&vault_a).unwrap()[0].max_ops_per_peer_window,
        1
    );

    let snapshot = doc_a.export(ExportMode::Snapshot).unwrap();
    let imported_doc = LoroDoc::from_snapshot(&snapshot).unwrap();
    let (_dir_b, vault_b) = test_vault();
    vault_b
        .put_authority_log_entry(
            &genesis,
            TimeRange {
                start: LEARNED_AT,
                end: LEARNED_AT,
            },
            LEARNED_AT,
        )
        .unwrap();

    assert!(
        maintenance_ingest_quota_snapshots(&vault_b)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        maintenance_ingest_quota_config(&vault_b)
            .unwrap()
            .max_ops_per_peer_window,
        DEFAULT_MAINTENANCE_INGEST_MAX_OPS_PER_PEER_WINDOW
    );

    let materializer_b = Materializer::new();
    assert_eq!(
        forward_rematerialize(&vault_b, &imported_doc, &materializer_b, &window_key).unwrap(),
        1
    );
    let snapshots_b = maintenance_ingest_quota_snapshots(&vault_b).unwrap();
    assert_eq!(snapshots_b.len(), 1);
    assert_eq!(snapshots_b[0].accepted_count, 1);
    assert_eq!(
        snapshots_b[0].max_ops_per_peer_window,
        DEFAULT_MAINTENANCE_INGEST_MAX_OPS_PER_PEER_WINDOW
    );
}
