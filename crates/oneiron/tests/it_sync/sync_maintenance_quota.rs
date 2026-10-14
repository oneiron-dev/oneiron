// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use loro::LoroDoc;
use oneiron::registry::ENTITY_TYPE_EVENT;
use oneiron::sync::bridge::{Materializer, register_observer_b};
use oneiron::sync::quarantine::{QuarantineContainer, pending_remat_windows, quarantined_records};
use oneiron::sync::quota::{
    MaintenanceIngestQuotaConfig, maintenance_ingest_quota_snapshots,
    set_maintenance_ingest_quota_config,
};
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::forward_rematerialize;
use oneiron::{
    EntityId, TimeRange, Vault, VaultConfig, authority::AUTHORITY_LOG_SCHEMA_VERSION,
    authority::AuthorityAttestation, authority::AuthorityEntryHash, authority::AuthorityKey,
    authority::AuthorityLogCheck, authority::AuthorityLogEntry,
    authority::AuthorityObservationPolicy, authority::AuthorityOp, authority::AuthoritySignature,
    authority::AuthorityTier, authority::AuthorityVaultId,
    authority::DEFAULT_PENDING_WIDEN_DELAY_SECS, authority::DeviceAuthority, authority::ROLE_ADMIN,
    authority::ROLE_AGENT, authority::ROLE_OWNER, authority::authority_entry_hash,
    authority::authority_transcript, authority::encode_authority_log_entry_body,
    authority::genesis_vault_id, registry::ENTITY_TYPE_AUTHORITY_LOG,
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
                recovery: oneiron::authority::GenesisRecoveryStep::Saved([1; 32]),
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
                // Agent-only: the vault door refuses any other client
                // enrollment, so only this one gives its key standing.
                device: device(authority_key_from_ed(new_key), ROLE_AGENT),
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

/// H72 positive control (W2-T3): a row signed by a key whose enrollment has
/// not arrived is held, never stored. Once the enrollment lands, the next
/// forward pass replays the held row and it materializes.
#[test]
fn a_row_by_a_not_yet_enrolled_signer_lands_after_its_enrollment() {
    let (_dir, vault) = test_vault();
    let vault = Arc::new(vault);
    let window_key = WindowKey::new(WINDOW);
    let doc = create_window_doc("user", &window_key);
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, WINDOW);
    let (owner_key, genesis, vault_id) = seed_local_genesis(&vault, 0x4c);
    let new_key = SigningKey::from_bytes(&[0x6c; 32]);
    let enroll = enroll_entry(
        vault_id,
        authority_entry_hash(&genesis).unwrap(),
        &owner_key,
        &new_key,
        1,
    );
    let child = cosign_entry(
        set_tier_floor_entry(
            vault_id,
            authority_entry_hash(&enroll).unwrap(),
            &new_key,
            1,
        ),
        &new_key,
        &owner_key,
    );
    let stored = |id: &EntityId| {
        vault
            .entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)
            .unwrap()
            .contains(id)
    };

    let child_id = insert_authority_entry(&doc, &child);
    doc.commit();
    assert!(
        !stored(&child_id),
        "a row whose signer is not enrolled is never stored"
    );
    assert_eq!(
        entity_quarantine_reasons(&vault),
        vec!["AuthorityLogSignerPending".to_owned()]
    );

    let enroll_id = insert_authority_entry(&doc, &enroll);
    doc.commit();
    assert!(stored(&enroll_id));
    forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap();
    assert!(
        stored(&child_id),
        "the held row lands once its signer is enrolled"
    );
}

/// H72: a peer frame that carries a whole valid log, keyed by entity id as
/// the CRDT map holds it, lands every row, and folds as the same log
/// delivered parents first, one row a frame, does. The owner enrolls four
/// agents as siblings at sequences 1 to 4, which entity-id order shuffles,
/// and binds each one on its enrollment at 5 to 8. One more row, by the
/// second agent on the first agent's binding, revokes that binding: its
/// signer stands only through a sibling enrollment.
#[test]
fn a_frame_carrying_a_whole_log_in_entity_id_order_lands_every_row() {
    let (owner_key, genesis, vault_id) = genesis_entry(0x4f);
    let root = authority_entry_hash(&genesis).unwrap();
    let agents: Vec<_> = (1..=4_u8)
        .map(|n| SigningKey::from_bytes(&[0x70 + n; 32]))
        .collect();
    let mut log = Vec::new();
    for (n, agent) in (1_u8..).zip(&agents) {
        let seq = u64::from(n);
        let enroll = enroll_entry(vault_id, root, &owner_key, agent, seq);
        let bind = AuthorityOp::BindActor {
            authority_key: authority_key_from_ed(agent),
            actor_ref: EntityId::from_bytes([0x60 + n; 16]).unwrap(),
            actor_class: "system".into(),
            epoch: 1,
        };
        log.push(cosign_entry(
            unsigned_entry(
                Some(vault_id),
                4 + seq,
                vec![authority_entry_hash(&enroll).unwrap()],
                bind,
                authority_key_from_ed(&owner_key),
                LEARNED_AT + 4 + seq,
            ),
            &owner_key,
            agent,
        ));
        log.push(enroll);
    }
    let across = cosign_entry(
        unsigned_entry(
            Some(vault_id),
            1,
            vec![
                authority_entry_hash(&log[0]).unwrap(),
                authority_entry_hash(&log[3]).unwrap(),
            ],
            AuthorityOp::RevokeActor {
                authority_key: authority_key_from_ed(&agents[0]),
                epoch: 1,
            },
            authority_key_from_ed(&agents[1]),
            LEARNED_AT + 9,
        ),
        &agents[1],
        &owner_key,
    );
    log.push(across);

    let receive = |frames: Vec<Vec<&AuthorityLogEntry>>| {
        let (_dir, vault) = test_vault();
        let vault = Arc::new(vault);
        let window_key = WindowKey::new(WINDOW);
        let doc = create_window_doc("user", &window_key);
        let materializer = Arc::new(Materializer::new());
        let _subs = register_observer_b(&doc, &vault, &materializer, WINDOW);
        seed_local_genesis(&vault, 0x4f);
        for frame in frames {
            for entry in frame {
                insert_authority_entry(&doc, entry);
            }
            doc.commit();
        }
        forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap();
        let stored = vault.entities_by_type(ENTITY_TYPE_AUTHORITY_LOG).unwrap();
        (stored, vault.authority_fold().unwrap())
    };
    let mut parents_first: Vec<_> = log.iter().collect();
    parents_first.sort_by_key(|entry| {
        (
            *entry.signer_key() != authority_key_from_ed(&owner_key),
            entry.seq,
        )
    });
    let (one_by_one, expected) = receive(parents_first.into_iter().map(|row| vec![row]).collect());
    let (whole, fold) = receive(vec![log.iter().collect()]);

    for entry in &log {
        let id = oneiron::authority::authority_log_entity_id(entry).unwrap();
        assert!(
            one_by_one.contains(&id) && whole.contains(&id),
            "a row never landed"
        );
    }
    let rows: Vec<_> = log
        .iter()
        .map(|entry| {
            let hash = authority_entry_hash(entry).unwrap();
            let op = format!("{:?}", entry.op);
            (
                entry.seq,
                op.split([' ', '(', '{']).next().unwrap_or("").to_owned(),
                hash[0],
                expected.valid_entries.contains(&hash),
            )
        })
        .collect();
    let issues: Vec<_> = expected
        .issues
        .iter()
        .map(|issue| format!("{issue:?}").chars().take(24).collect::<String>())
        .collect();
    assert!(
        rows.iter().all(|row| row.3),
        "the parents-first delivery folds every row: {rows:?} {issues:?}"
    );
    assert_eq!(fold.valid_entries, expected.valid_entries);
    assert_eq!(fold.roster, expected.roster);
}

/// H72, rule 5 (Engine check): a key no slip issuer vouches for, here an
/// admin the owner admitted, stores up to the `authority_log_signer_bound`
/// row. Its next row in the same frame waits: not stored, its typed refusal
/// and its retry marker kept, and the log raises the
/// `authority_log_signer_bound` check. The owner raises the row, and the next pass lands the held row
/// with no re-send.
#[test]
fn a_row_past_its_signers_bound_waits_and_lands_once_the_owner_raises_it() {
    let (_dir, vault) = test_vault();
    let vault = Arc::new(vault);
    let window_key = WindowKey::new(WINDOW);
    let doc = create_window_doc("user", &window_key);
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, WINDOW);
    let (owner_key, genesis, vault_id) = seed_local_genesis(&vault, 0x51);
    let bound = |log_signer_bound| {
        vault
            .set_authority_observation_policy(AuthorityObservationPolicy {
                log_signer_bound,
                ..AuthorityObservationPolicy::default()
            })
            .unwrap();
    };
    bound(2);
    let admin = SigningKey::from_bytes(&[0x71; 32]);
    let admitted = sign_entry(
        unsigned_entry(
            Some(vault_id),
            1,
            vec![authority_entry_hash(&genesis).unwrap()],
            AuthorityOp::EnrollDevice {
                device: device(authority_key_from_ed(&admin), ROLE_ADMIN),
            },
            authority_key_from_ed(&owner_key),
            LEARNED_AT + 1,
        ),
        &owner_key,
    );
    let mut parent = authority_entry_hash(&admitted).unwrap();
    let rows: Vec<_> = (1..=3)
        .map(|seq| {
            let row = set_tier_floor_entry(vault_id, parent, &admin, seq);
            parent = authority_entry_hash(&row).unwrap();
            row
        })
        .collect();
    let stored = |row: &AuthorityLogEntry| {
        vault
            .entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)
            .unwrap()
            .contains(&oneiron::authority::authority_log_entity_id(row).unwrap())
    };
    let signer_checks = || {
        vault
            .authority_log_checks()
            .unwrap()
            .into_iter()
            .filter(|check| check.kind == AuthorityLogCheck::SIGNER_BOUND)
            .map(|check| (check.signer.is_some(), check.count, check.threshold))
            .collect::<Vec<_>>()
    };

    insert_authority_entry(&doc, &admitted);
    for row in &rows {
        insert_authority_entry(&doc, row);
    }
    doc.commit();
    forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap();
    assert!(stored(&admitted) && stored(&rows[0]) && stored(&rows[1]));
    assert!(!stored(&rows[2]), "the row past its signer's bound waits");
    assert!(
        entity_quarantine_reasons(&vault).contains(&"AuthorityLogFull".to_owned()),
        "{:?}",
        entity_quarantine_reasons(&vault)
    );
    assert_eq!(
        pending_remat_windows(&vault).unwrap(),
        vec![WINDOW.to_owned()],
        "the held row keeps its retry marker"
    );
    assert_eq!(signer_checks(), vec![(true, 2, 2)]);

    bound(4);
    forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap();
    assert!(stored(&rows[2]), "the held row lands with no re-send");
    assert!(pending_remat_windows(&vault).unwrap().is_empty());
    assert!(signer_checks().is_empty());
}

/// Invalid envelopes retain the existing occupant; valid retries displace it.
/// Neither outcome consumes an authority ingest quota.

#[test]
fn observer_b_invalid_envelope_leaves_no_quota_trace_and_retry_admits() {
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
        "the rejection must be the envelope gate, not a key mismatch"
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
        "authority ingest never debits a rate quota"
    );
    assert_eq!(
        vault.get_raw(&bad_id).unwrap(),
        Some(occupant),
        "a rejected authority row must not evict the occupant of its derived key"
    );

    // Same entry, well-formed envelope. Signing is deterministic, so this
    // re-lands on `bad_id`; the rejected row must have left its occupant intact.
    let valid_entry = set_tier_floor_entry(vault_id, parent_hash, &owner_key, 1);
    let valid_id = insert_authority_entry(&doc, &valid_entry);
    assert_eq!(valid_id, bad_id, "content addressing must reuse the key");
    doc.commit();

    assert_eq!(
        vault
            .count_entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)
            .unwrap(),
        before + 1,
        "a valid retry must materialize"
    );
    // The dominance side effect belongs to the ACCEPTED row, not the rejected
    // one: only now does the squatter go.
    assert_eq!(
        vault.get_authority_log_entry(&bad_id).unwrap(),
        Some(valid_entry),
        "the admitted row must displace the squatter and own its derived key"
    );
    let snapshots = maintenance_ingest_quota_snapshots(&vault).unwrap();
    assert!(snapshots.is_empty());
}
