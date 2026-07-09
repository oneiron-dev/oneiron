use super::*;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::deletion::DeleteReason;
use crate::edge::EdgeActorClass;
use crate::provenance::{EdgeProvenanceClaimBody, EdgeRef, SupersessionStatus};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON, ENTITY_TYPE_TASK};
use crate::types::{
    ClaimCandidate, HnswConfig, VaultConfig, WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY,
    WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY, WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY, WriteActor,
    WriteEnvelope, WriteProvenance,
};
use core::assert_matches;
#[cfg(feature = "sync")]
use ed25519_dalek::{Signer, SigningKey};
use rmpv::Value;

struct EdgeFixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    edge: EdgeRef,
    claim_id: EntityId,
}

type RawEdgeValuePair = (Option<Vec<u8>>, Option<Vec<u8>>);

fn test_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = Some("test-model-v1".to_owned());
    config.max_readers = 16;
    config.hnsw = HnswConfig::default();
    config
}

fn open_raw_test_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), test_config()).expect("open vault");
    (dir, vault)
}

fn open_test_vault() -> (tempfile::TempDir, Vault) {
    let (tmp, vault) = open_raw_test_vault();
    clear_default_policy_manifest_for_test(&vault);
    (tmp, vault)
}

fn clear_default_policy_manifest_for_test(vault: &Vault) {
    let id = crate::gate::default_policy_manifest_id().expect("default policy manifest id");
    vault
        .with_write_txn(|wtxn| {
            crate::batch::deindex_entity_for_test(&vault.store, wtxn, &id)?;
            Ok(())
        })
        .expect("clear default policy manifest");
}

fn test_time_range(start: u64, end: u64) -> TimeRange {
    TimeRange { start, end }
}

#[test]
fn checkin_on_non_habit_rejected() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let task = EntityId::now();
    let checkin = EntityId::now();
    let task_body = crate::types::task_body_for_test(TaskRole::Task);
    let checkin_body = crate::types::task_body_for_test(TaskRole::HabitCheckin);

    vault.put_entity(
        &task,
        ENTITY_TYPE_TASK,
        test_time_range(10, 10),
        10,
        &task_body,
    )?;

    let err = vault
        .put_habit_checkin(&task, &checkin, test_time_range(11, 11), 11, &checkin_body)
        .expect_err("check-in under non-Habit TASK must be rejected");

    assert_eq!(err.kind(), ErrorKind::InvalidTaskBody);
    assert!(!vault.entity_exists(&checkin)?);
    assert!(!vault.edge_exists(&checkin, EdgeKind::ChildOf, &task)?);
    Ok(())
}

#[test]
fn checkin_immutable() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let habit = EntityId::now();
    let checkin = EntityId::now();
    let habit_body = crate::types::task_body_for_test(TaskRole::Habit);
    let checkin_body = crate::types::task_body_for_test(TaskRole::HabitCheckin);
    let replacement_body = crate::types::task_body_for_test(TaskRole::Task);

    vault.put_entity(
        &habit,
        ENTITY_TYPE_TASK,
        test_time_range(10, 10),
        10,
        &habit_body,
    )?;
    vault.put_habit_checkin(&habit, &checkin, test_time_range(11, 11), 11, &checkin_body)?;
    let original = vault
        .get_raw(&checkin)?
        .expect("check-in row must be written");

    let err = vault
        .put_entity(
            &checkin,
            ENTITY_TYPE_TASK,
            test_time_range(12, 12),
            12,
            &replacement_body,
        )
        .expect_err("check-in re-put must be rejected");

    assert_eq!(err.kind(), ErrorKind::InvalidTaskBody);
    assert_eq!(vault.get_raw(&checkin)?, Some(original));
    Ok(())
}

#[test]
fn checkin_same_role_mutation_rejected_and_identical_reput_idempotent() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let habit = EntityId::now();
    let checkin = EntityId::now();
    let habit_body = crate::types::task_body_for_test(TaskRole::Habit);
    let checkin_body = crate::types::task_body_for_test(TaskRole::HabitCheckin);

    vault.put_entity(
        &habit,
        ENTITY_TYPE_TASK,
        test_time_range(10, 10),
        10,
        &habit_body,
    )?;
    vault.put_habit_checkin(&habit, &checkin, test_time_range(11, 11), 11, &checkin_body)?;
    let original = vault
        .get_raw(&checkin)?
        .expect("check-in row must be written");

    // Re-put with the role still HabitCheckin but mutated occurred/learned_at:
    // the immutability guard protects payload/time, not just role changes.
    let err = vault
        .put_entity(
            &checkin,
            ENTITY_TYPE_TASK,
            test_time_range(20, 20),
            20,
            &checkin_body,
        )
        .expect_err("same-role check-in time mutation must be rejected");
    assert_eq!(err.kind(), ErrorKind::InvalidTaskBody);
    assert_eq!(vault.get_raw(&checkin)?, Some(original.clone()));

    // An identical re-put (same role, body, occurred, learned_at) stays accepted.
    vault.put_entity(
        &checkin,
        ENTITY_TYPE_TASK,
        test_time_range(11, 11),
        11,
        &checkin_body,
    )?;
    assert_eq!(vault.get_raw(&checkin)?, Some(original));
    Ok(())
}

#[test]
fn habit_with_checkins_cannot_change_role() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let habit = EntityId::now();
    let checkin = EntityId::now();
    let habit_body = crate::types::task_body_for_test(TaskRole::Habit);
    let checkin_body = crate::types::task_body_for_test(TaskRole::HabitCheckin);
    let demoted_body = crate::types::task_body_for_test(TaskRole::Task);

    vault.put_entity(
        &habit,
        ENTITY_TYPE_TASK,
        test_time_range(10, 10),
        10,
        &habit_body,
    )?;
    vault.put_habit_checkin(&habit, &checkin, test_time_range(11, 11), 11, &checkin_body)?;
    let original = vault.get_raw(&habit)?.expect("habit row must be written");

    let err = vault
        .put_entity(
            &habit,
            ENTITY_TYPE_TASK,
            test_time_range(12, 12),
            12,
            &demoted_body,
        )
        .expect_err("demoting a Habit that has check-ins must be rejected");

    match err {
        Error::InvalidTaskBody(msg) => {
            assert_eq!(msg, "Habit TASK with check-ins cannot change role");
        }
        other => panic!("expected InvalidTaskBody, got {other:?}"),
    }
    assert_eq!(vault.get_raw(&habit)?, Some(original));
    Ok(())
}

fn first_party_eiri_connector_actor_id() -> Result<EntityId> {
    EntityId::from_bytes(crate::gate::FIRST_PARTY_EIRI_CONNECTOR_ACTOR_ID)
        .map_err(|_| Error::InvariantViolation("invalid first-party Eiri actor fixture id"))
}

fn first_party_eiri_connector_actor_ref() -> String {
    crate::gate::first_party_eiri_connector_actor_ref()
}

fn raw_edge_values(vault: &Vault, edge: &EdgeRef) -> Result<RawEdgeValuePair> {
    let rtxn = vault.store.env.read_txn()?;
    let key_out = Store::encode_edge_key(&edge.source, edge.kind, &edge.target);
    let key_in = Store::encode_edge_key(&edge.target, edge.kind, &edge.source);
    let out = vault
        .store
        .edges_out
        .get(&rtxn, &key_out)?
        .map(<[u8]>::to_vec);
    let inn = vault
        .store
        .edges_in
        .get(&rtxn, &key_in)?
        .map(<[u8]>::to_vec);
    Ok((out, inn))
}

fn assert_edge_is_provenanced_reject(err: Error, expected_kind: EdgeKind, context: &str) {
    match err {
        Error::EdgeIsProvenanced { kind } => {
            assert_eq!(kind, expected_kind as u8, "{context}: kind byte");
        }
        other => panic!("{context}: expected EdgeIsProvenanced, got {other:?}"),
    }
}

fn assert_raw_edge_unchanged(
    vault: &Vault,
    edge: &EdgeRef,
    before: &[u8],
    context: &str,
) -> Result<()> {
    let (after_out, after_in) = raw_edge_values(vault, edge)?;
    assert_eq!(
        after_out.as_deref(),
        Some(before),
        "{context}: edges_out must stay byte-identical"
    );
    assert_eq!(
        after_in.as_deref(),
        Some(before),
        "{context}: edges_in must stay byte-identical"
    );
    Ok(())
}

const GITHUB_PAT_SECRET_FIXTURE: &[u8] = b"token=ghp_0123456789abcdefghijklmnopqrstuvwxyz";

fn assert_secret_scan_rejected(err: Error) {
    match err {
        Error::GateWriteRejected {
            outcome,
            reason_codes,
        } => {
            assert_eq!(outcome, "deny");
            assert_eq!(
                reason_codes.as_slice(),
                &["gate.secret_scan.detected", "gate.secret_scan.github_token"]
            );
        }
        other => panic!("expected secret-scan GateWriteRejected, got {other:?}"),
    }
}

#[test]
fn secret_scan_rejects_known_secret_fixture_before_persistence() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let safe_id = EntityId::now();
    let secret_id = EntityId::now();
    let occurred = test_time_range(10, 10);

    let err = vault
        .batch()
        .put(
            &safe_id,
            ENTITY_TYPE_PERSON,
            occurred,
            10,
            b"ordinary memory",
        )
        .put(
            &secret_id,
            ENTITY_TYPE_PERSON,
            occurred,
            10,
            GITHUB_PAT_SECRET_FIXTURE,
        )
        .commit()
        .expect_err("known secret fixture must reject before any batch write");

    assert_secret_scan_rejected(err);
    assert!(vault.get(&safe_id)?.is_none());
    assert!(vault.get(&secret_id)?.is_none());
    Ok(())
}

#[test]
fn secret_scan_allows_non_secret_write_unchanged() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let occurred = test_time_range(20, 20);
    let data = b"ordinary memory body";

    vault
        .batch()
        .put(&id, ENTITY_TYPE_PERSON, occurred, 20, data)
        .text(&id, &[("body", "ordinary memory body")])
        .commit()?;

    assert_eq!(vault.get(&id)?.as_deref(), Some(&data[..]));
    assert_eq!(vault.search_text("ordinary", 10)?.len(), 1);
    Ok(())
}

#[test]
fn secret_scan_rejects_phonetic_payload_before_persistence() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let safe_id = EntityId::now();
    let phonetic_id = EntityId::now();
    let occurred = test_time_range(25, 25);
    let secret_code =
        std::str::from_utf8(GITHUB_PAT_SECRET_FIXTURE).expect("secret fixture is UTF-8");

    let err = vault
        .batch()
        .put(
            &safe_id,
            ENTITY_TYPE_PERSON,
            occurred,
            25,
            b"ordinary memory",
        )
        .phonetic(&phonetic_id, &[secret_code])
        .commit()
        .expect_err("known secret fixture in phonetic payload must reject before batch write");

    assert_secret_scan_rejected(err);
    assert!(vault.get(&safe_id)?.is_none());

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .phonetic_index
            .get(&rtxn, secret_code.as_bytes())?
            .is_none()
    );
    assert!(
        vault
            .store
            .phonetic_forward
            .get(&rtxn, phonetic_id.as_bytes())?
            .is_none()
    );
    Ok(())
}

#[test]
fn txn_batch_secret_scan_rejects_before_staging_writes() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let safe_id = EntityId::now();
    let secret_id = EntityId::now();
    let occurred = test_time_range(30, 30);
    let mut wtxn = vault.store.env.write_txn()?;

    let err = vault
        .batch_in()
        .put(
            &safe_id,
            ENTITY_TYPE_PERSON,
            occurred,
            30,
            b"ordinary memory",
        )
        .put(
            &secret_id,
            ENTITY_TYPE_PERSON,
            occurred,
            30,
            GITHUB_PAT_SECRET_FIXTURE,
        )
        .apply(&mut wtxn)
        .expect_err("txn batch secret fixture must reject before staging writes");

    assert_secret_scan_rejected(err);
    wtxn.commit()?;

    assert!(vault.get(&safe_id)?.is_none());
    assert!(vault.get(&secret_id)?.is_none());
    Ok(())
}

fn provenanced_edge_fixture() -> Result<EdgeFixture> {
    let (dir, vault) = open_test_vault();
    let src = EntityId::now();
    let tgt = EntityId::now();
    let actor = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&src, ENTITY_TYPE_PERSON, occurred, 1, b"src")?;
    vault.put_entity(&tgt, ENTITY_TYPE_PERSON, occurred, 1, b"tgt")?;
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_edge(&src, EdgeKind::Mentions, &tgt, 0.25)?;

    let edge = EdgeRef::new(src, EdgeKind::Mentions, tgt);
    let claim_id = EntityId::now();
    vault.put_edge_provenance(
        &claim_id,
        &edge,
        &EdgeProvenanceClaimBody::new(actor, 0.75, SupersessionStatus::Confirmed),
        EdgeActorClass::Human,
        1_000,
    )?;

    Ok(EdgeFixture {
        _dir: dir,
        vault,
        edge,
        claim_id,
    })
}

fn evidence_entry<'a>(evidence: &'a Value, key: &str) -> &'a Value {
    let Value::Map(entries) = evidence else {
        panic!("expected write envelope evidence map, got {evidence:?}");
    };
    entries
        .iter()
        .find_map(|(entry_key, entry_value)| {
            (entry_key.as_str() == Some(key)).then_some(entry_value)
        })
        .unwrap_or_else(|| panic!("missing evidence key {key:?} in {evidence:?}"))
}

fn has_pending_embedding_marker(vault: &Vault, id: &EntityId) -> Result<bool> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(vault.store.pending_embedding_token(&rtxn, id)?.is_some())
}

fn raw_pending_embedding_marker(vault: &Vault, id: &EntityId) -> Result<Option<Vec<u8>>> {
    let rtxn = vault.store.env.read_txn()?;
    let key = Store::pending_embedding_marker_key(id);
    Ok(vault
        .store
        .sync_state
        .get(&rtxn, key.as_str())?
        .map(<[u8]>::to_vec))
}

fn overwrite_pending_embedding_marker(vault: &Vault, id: &EntityId, token: &[u8]) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    let key = Store::pending_embedding_marker_key(id);
    vault.store.sync_state.put(&mut wtxn, key.as_str(), token)?;
    wtxn.commit()?;
    Ok(())
}

fn pending_embedding_token(vault: &Vault, id: &EntityId) -> Result<Vec<u8>> {
    let rtxn = vault.store.env.read_txn()?;
    vault
        .store
        .pending_embedding_token(&rtxn, id)?
        .ok_or(Error::InvariantViolation("pending embedding token missing"))
}

fn seed_raw_claim_record(vault: &Vault, id: &EntityId, body: ClaimBody) -> Result<()> {
    let data = crate::claim::encode_claim_body(&body)?;
    let occurred = test_time_range(30, 30);
    let learned_at = 31_u64;
    let mut payload = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + data.len());
    payload.push(ENTITY_TYPE_CLAIM);
    payload.extend_from_slice(&occurred.start.to_be_bytes());
    payload.extend_from_slice(&occurred.end.to_be_bytes());
    payload.extend_from_slice(&learned_at.to_be_bytes());
    payload.extend_from_slice(&data);

    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .entities
        .put(&mut wtxn, id.as_bytes(), &payload)?;
    let type_key = Store::encode_type_key(ENTITY_TYPE_CLAIM, id);
    vault.store.type_index.put(&mut wtxn, &type_key, &[])?;
    let occurred_start_key = Store::encode_temporal_key(occurred.start, id);
    vault
        .store
        .temporal_occurred_start
        .put(&mut wtxn, &occurred_start_key, &[])?;
    let learned_key = Store::encode_temporal_key(learned_at, id);
    vault
        .store
        .temporal_learned
        .put(&mut wtxn, &learned_key, &[])?;
    wtxn.commit()?;
    Ok(())
}

fn seed_stale_vector_state(vault: &Vault, id: &EntityId, vector: &[f32]) -> Result<()> {
    let mut bytes = Vec::with_capacity(vector.len() * 4);
    for component in vector {
        bytes.extend_from_slice(&component.to_le_bytes());
    }
    let mut wtxn = vault.store.env.write_txn()?;
    vault.store.vectors.put(&mut wtxn, id.as_bytes(), &bytes)?;
    let mut pending_rebuild = false;
    crate::hnsw::hnsw_insert_batched(
        &vault.store,
        &vault.config,
        &mut wtxn,
        id,
        vector,
        &mut pending_rebuild,
    )?;
    crate::hnsw::run_pending_legacy_rebuild(
        &vault.store,
        &vault.config,
        &mut wtxn,
        pending_rebuild,
    )?;
    wtxn.commit()?;
    Ok(())
}

fn seed_claim_of_edge(vault: &Vault, claim: &EntityId, subject: &EntityId) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    apply_edge(
        &vault.store,
        &mut wtxn,
        *claim,
        EdgeKind::ClaimOf,
        *subject,
        1.0,
        Vad::NEUTRAL,
    )?;
    wtxn.commit()?;
    Ok(())
}

#[test]
fn fresh_default_policy_manifest_grants_first_party_eiri_tool_output_auto() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();

    let first_party_eiri_actor = first_party_eiri_connector_actor_id()?;
    let first_party_eiri_actor_ref = first_party_eiri_connector_actor_ref();
    let policy = {
        let wtxn = vault.store.env.write_txn()?;
        crate::gate::resolve_policy_manifest(&vault.store, &wtxn)?
    };
    assert_eq!(
        policy.actor_ceiling("agent", Some(&first_party_eiri_actor_ref)),
        crate::gate::PolicyApprovalCeiling::Auto
    );
    assert_eq!(policy.signatures().len(), 1);
    let signed_auto_frontier = policy.read_frontier_hash()?;

    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(
        &first_party_eiri_actor,
        ENTITY_TYPE_PERSON,
        occurred,
        1,
        b"first-party Eiri connector",
    )?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let claim = EntityId::now();
    let envelope = WriteEnvelope::new(
        WriteActor::new(first_party_eiri_actor, EdgeActorClass::Agent),
        ClaimSource::ToolOutput,
        WriteProvenance::new(Value::from("fixture"))?,
        ClaimApprovalStatus::Auto,
    );
    let candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    );

    vault
        .batch()
        .claim_candidate(&claim, candidate, &envelope, test_time_range(10, 10), 11)
        .commit()?;

    let stored = vault.get_claim(&claim)?.expect("candidate claim stored");
    assert_eq!(stored.approval, ClaimApprovalStatus::Auto);
    assert_eq!(stored.source, Some(ClaimSource::ToolOutput));

    let decisions = vault.store.gate_decisions(10)?;
    let decision = decisions
        .iter()
        .find(|decision| decision.claim_id == Some(*claim.as_bytes()))
        .expect("first-party Eiri write must record a gate decision");
    assert_eq!(decision.outcome, "allow");
    assert_eq!(decision.reason_codes, vec!["gate.allow"]);
    assert_eq!(decision.actor_class, "agent");
    assert_eq!(
        decision.actor_ref.as_deref(),
        Some(first_party_eiri_actor_ref.as_str())
    );

    let policy_after_write = {
        let wtxn = vault.store.env.write_txn()?;
        crate::gate::resolve_policy_manifest(&vault.store, &wtxn)?
    };
    assert_eq!(
        signed_auto_frontier,
        policy_after_write.read_frontier_hash()?
    );
    Ok(())
}

fn lh_prefixed_id(fill: u8) -> Result<EntityId> {
    let mut raw = [fill; ENTITY_ID_LEN];
    raw[0] = b'L';
    raw[1] = b'H';
    EntityId::from_bytes(raw).map_err(|_| Error::InvariantViolation("invalid LH fixture id"))
}

fn test_write_envelope(actor: EntityId) -> Result<WriteEnvelope> {
    Ok(WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(Value::from("fixture"))?,
        ClaimApprovalStatus::Approved,
    ))
}

#[test]
fn write_envelope_validation_rejects_missing_required_axes() -> Result<()> {
    let actor = WriteActor::new(EntityId::now(), EdgeActorClass::Human);
    let provenance = WriteProvenance::new(Value::from("fixture"))?;

    let err = WriteEnvelope::try_new(
        None,
        Some(ClaimSource::UserStated),
        Some(provenance.clone()),
        Some(ClaimApprovalStatus::Proposed),
    )
    .expect_err("actor is required");
    assert!(matches!(
        err,
        Error::InvalidClaimBody("write envelope missing actor")
    ));

    let err = WriteEnvelope::try_new(
        Some(actor),
        None,
        Some(provenance.clone()),
        Some(ClaimApprovalStatus::Proposed),
    )
    .expect_err("source is required");
    assert!(matches!(
        err,
        Error::InvalidClaimBody("write envelope missing source")
    ));

    let err = WriteEnvelope::try_new(
        Some(actor),
        Some(ClaimSource::UserStated),
        None,
        Some(ClaimApprovalStatus::Proposed),
    )
    .expect_err("provenance is required");
    assert!(matches!(
        err,
        Error::InvalidClaimBody("write envelope missing provenance")
    ));

    let err = WriteEnvelope::try_new(
        Some(actor),
        Some(ClaimSource::UserStated),
        Some(provenance),
        None,
    )
    .expect_err("approval is required");
    assert!(matches!(
        err,
        Error::InvalidClaimBody("write envelope missing approval")
    ));

    let err = WriteProvenance::new(Value::Nil).expect_err("nil provenance must reject");
    assert!(matches!(
        err,
        Error::InvalidClaimBody("write envelope missing provenance")
    ));
    Ok(())
}

#[test]
fn claim_candidate_rejects_missing_actor_entity() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    vault.put_entity(
        &subject,
        ENTITY_TYPE_PERSON,
        test_time_range(1, 1),
        1,
        b"subject",
    )?;

    let claim = EntityId::now();
    let missing_actor = EntityId::now();
    let envelope = WriteEnvelope::new(
        WriteActor::new(missing_actor, EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(Value::from("fixture"))?,
        ClaimApprovalStatus::Proposed,
    );
    let candidate = ClaimCandidate::new(
        "profile.name",
        ClaimSubject::Entity(subject),
        Value::from("Alice"),
        0.9,
    );

    let err = vault
        .batch()
        .claim_candidate(&claim, candidate, &envelope, test_time_range(1, 1), 2)
        .commit()
        .expect_err("missing actor entity must reject");
    assert!(matches!(err, Error::EntityNotFound));
    assert!(vault.get_claim(&claim)?.is_none());
    Ok(())
}

#[test]
fn claim_candidate_write_stamps_approved_envelope() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let claim = EntityId::now();
    let provenance = Value::Map(vec![(
        Value::from("source_record_id"),
        Value::from("fixture-approved-1"),
    )]);
    let envelope = WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(provenance.clone())?,
        ClaimApprovalStatus::Approved,
    );
    let candidate = ClaimCandidate::new(
        "profile.name",
        ClaimSubject::Entity(subject),
        Value::from("Alice"),
        0.9,
    )
    .with_salience(0.4);

    vault
        .batch()
        .claim_candidate(&claim, candidate, &envelope, test_time_range(10, 10), 11)
        .commit()?;

    let stored = vault.get_claim(&claim)?.expect("candidate claim stored");
    assert_eq!(stored.approval, ClaimApprovalStatus::Approved);
    assert_eq!(stored.source, Some(ClaimSource::UserStated));
    assert_eq!(stored.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(stored.salience, Some(0.4));

    let evidence = stored.evidence.as_ref().expect("envelope evidence");
    match evidence_entry(evidence, WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY) {
        Value::Binary(bytes) => assert_eq!(bytes.as_slice(), actor.as_bytes()),
        other => panic!("actor evidence must be binary, got {other:?}"),
    }
    assert_eq!(
        evidence_entry(evidence, WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY).as_u64(),
        Some(EdgeActorClass::Human as u64)
    );
    assert_eq!(
        evidence_entry(evidence, WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY),
        &provenance
    );
    assert_eq!(vault.claims_for_subject(&subject)?, vec![claim]);
    Ok(())
}

#[test]
fn affect_trigger_batch_helper_writes_and_conflict_uses_claim_lifecycle() -> Result<()> {
    let (_tmp, vault) = open_test_vault();
    let occurred = test_time_range(1, 1);
    let actor = EntityId::now();
    let person = EntityId::now();
    let trigger = EntityId::now();
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&person, ENTITY_TYPE_PERSON, occurred, 1, b"person")?;
    vault.put_entity(
        &trigger,
        ENTITY_TYPE_TASK,
        occurred,
        1,
        &crate::types::task_body_for_test(crate::types::TaskRole::Task),
    )?;
    let envelope = test_write_envelope(actor)?;

    let affect_claim = EntityId::now();
    let trigger_value = crate::affect::AffectTriggerValue::new(
        person,
        trigger,
        crate::affect::VadDelta::new(-0.2, 0.4, -0.3)?,
        0.75,
        2,
        9,
    )?;
    vault
        .batch()
        .affect_trigger_claim(
            &affect_claim,
            trigger_value.clone(),
            &envelope,
            test_time_range(10, 10),
            11,
        )
        .commit()?;

    let stored = vault
        .get_claim(&affect_claim)?
        .expect("affect trigger claim stored");
    assert_eq!(
        crate::affect::decode_affect_trigger_claim(&stored)?,
        Some(trigger_value)
    );
    assert_eq!(stored.subject, ClaimSubject::Entity(person));
    assert_eq!(vault.claims_for_subject(&person)?, vec![affect_claim]);

    let open_conflict = EntityId::now();
    let resolved_conflict = EntityId::now();
    vault
        .batch()
        .conflict_open_claim(
            &open_conflict,
            person,
            Value::from("open conflict"),
            0.7,
            &envelope,
            test_time_range(20, 20),
            21,
        )
        .conflict_resolved_claim(
            &resolved_conflict,
            person,
            Value::from("resolved conflict"),
            0.8,
            &envelope,
            test_time_range(22, 22),
            23,
        )
        .commit()?;
    vault.supersede_claim(&resolved_conflict, &open_conflict, 30)?;

    let open_stored = vault
        .get_claim(&open_conflict)?
        .expect("open conflict preserved");
    let resolved_stored = vault
        .get_claim(&resolved_conflict)?
        .expect("resolved conflict active");
    assert_eq!(open_stored.subject, ClaimSubject::Entity(person));
    assert_eq!(resolved_stored.subject, ClaimSubject::Entity(person));
    assert_eq!(open_stored.lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(resolved_stored.lifecycle, ClaimLifecycleStatus::Active);
    Ok(())
}

#[test]
fn claim_candidate_lexical_hints_write_read_and_search_source_claim() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let claim = EntityId::now();
    let envelope = test_write_envelope(actor)?;
    let candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    );

    vault
        .batch()
        .claim_candidate_with_lexical_hints(
            &claim,
            candidate,
            &envelope,
            test_time_range(10, 10),
            11,
            &[
                "green tea preferences",
                "  matcha order history  ",
                "green tea preferences",
            ],
        )
        .commit()?;

    let hint_claims = vault.claims_for_subject(&claim)?;
    assert_eq!(hint_claims.len(), 2);
    let mut stored_queries = Vec::new();
    for hint_claim in &hint_claims {
        assert!(
            hint_claim
                .as_bytes()
                .starts_with(&crate::claim::LEXICAL_QUERY_HINT_ID_PREFIX)
        );
        assert!(
            !has_pending_embedding_marker(&vault, hint_claim)?,
            "lexical hint side claims must not be queued for embeddings"
        );
        let stored = vault
            .get_claim(hint_claim)?
            .expect("lexical hint claim stored");
        assert_eq!(stored.predicate, crate::claim::PREDICATE_LEXICAL_QUERY_HINT);
        assert!(stored.stale, "lexical hint side claims are derived data");
        assert_eq!(stored.source, Some(ClaimSource::UserStated));
        assert!(stored.evidence.is_some());
        let value = crate::claim::decode_lexical_query_hint_value(&stored.value)?;
        assert_eq!(value.target, claim);
        stored_queries.push(value.query);
    }
    stored_queries.sort();
    assert_eq!(
        stored_queries,
        vec!["green tea preferences", "matcha order history"]
    );

    let hits = vault.search_text("matcha order", 10)?;
    assert_eq!(hits.first().map(|hit| hit.id), Some(claim));
    assert!(
        !hits.iter().any(|hit| hint_claims.contains(&hit.id)),
        "lexical hint docs must collapse to the source claim"
    );
    let ppr_hits = vault.query().search_ppr(&[claim], 2).run()?;
    assert!(
        !ppr_hits.iter().any(|hit| hint_claims.contains(&hit.id)),
        "lexical hint side claims must not surface through PPR"
    );
    let rtxn = vault.store.env.read_txn()?;
    for hint in &hint_claims {
        assert!(
            vault
                .store
                .short_ids_reverse
                .get(&rtxn, hint.as_bytes())?
                .is_none(),
            "lexical hint side claims must not receive public short ids"
        );
    }
    Ok(())
}

#[test]
fn lexical_hint_claim_of_edges_do_not_dilute_ppr_claim_neighbors() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let claim = EntityId::now();
    let envelope = test_write_envelope(actor)?;
    let candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    );
    vault
        .batch()
        .claim_candidate_with_lexical_hints(
            &claim,
            candidate,
            &envelope,
            test_time_range(10, 10),
            11,
            &["ppr synthetic one", "ppr synthetic two"],
        )
        .commit()?;
    let hint_claims = vault.claims_for_subject(&claim)?;
    assert_eq!(hint_claims.len(), 2);

    let real_neighbor = EntityId::now();
    let real_neighbor_body = ClaimBody::new(
        "profile.related",
        ClaimSubject::Entity(claim),
        Value::from("real ppr neighbor"),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    seed_raw_claim_record(&vault, &real_neighbor, real_neighbor_body)?;
    seed_claim_of_edge(&vault, &real_neighbor, &claim)?;

    let rtxn = vault.store.env.read_txn()?;
    let scores = crate::ppr::ppr_compute(&vault.store, &rtxn, &[claim], 1, 0.15)?;
    let score_for = |id: EntityId| -> f32 {
        scores
            .iter()
            .find(|scored| scored.id == id)
            .map_or(0.0, |scored| scored.score)
    };
    assert!(
        score_for(real_neighbor) > 0.84,
        "real ClaimOf neighbor should receive the full inbound ClaimOf mass"
    );
    for hint in hint_claims {
        assert_eq!(
            score_for(hint),
            0.0,
            "lexical hint ClaimOf rows must not receive PPR mass"
        );
    }
    Ok(())
}

#[test]
fn claim_candidate_lexical_hints_bypass_hint_policy_gate() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let claim = EntityId::now();
    let envelope = test_write_envelope(actor)?;
    let candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    );
    vault
        .batch()
        .claim_candidate_with_lexical_hints(
            &claim,
            candidate,
            &envelope,
            test_time_range(10, 10),
            11,
            &["policy bypass lexical hint"],
        )
        .commit()?;

    assert_eq!(
        vault
            .search_text("policy bypass lexical", 10)?
            .first()
            .map(|hit| hit.id),
        Some(claim)
    );
    Ok(())
}

#[test]
fn raw_lexical_hint_put_does_not_bypass_policy_gate() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let claim = EntityId::now();
    let envelope = test_write_envelope(actor)?;
    let candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    );
    vault
        .batch()
        .claim_candidate(&claim, candidate, &envelope, test_time_range(10, 10), 11)
        .commit()?;

    let query = "raw policy lexical hint";
    let hint = lexical_query_hint_claim_id(&claim, query)?;
    let mut body = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(claim),
        crate::claim::encode_lexical_query_hint_value(&claim, query),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    body.stale = true;
    let data = crate::claim::encode_claim_body(&body)?;

    let err = vault
        .batch()
        .put(&hint, ENTITY_TYPE_CLAIM, test_time_range(20, 20), 21, &data)
        .commit()
        .expect_err("raw lexical hint puts must still pass ordinary policy");
    assert_matches!(err, Error::GateWriteRejected { .. });
    assert!(vault.search_text(query, 10)?.is_empty());
    Ok(())
}

#[test]
fn claim_candidate_lexical_hints_replace_and_delete_stale_side_records() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let claim = EntityId::now();
    let envelope = test_write_envelope(actor)?;
    let write_hints = |hints: &[&str]| -> Result<()> {
        let candidate = ClaimCandidate::new(
            "profile.preference",
            ClaimSubject::Entity(subject),
            Value::from("sencha"),
            0.9,
        );
        vault
            .batch()
            .claim_candidate_with_lexical_hints(
                &claim,
                candidate,
                &envelope,
                test_time_range(10, 10),
                11,
                hints,
            )
            .commit()
    };

    write_hints(&["retireduniquealpha", "liveuniquebeta"])?;
    let obsolete_hint = lexical_query_hint_claim_id(&claim, "retireduniquealpha")?;
    let live_hint = lexical_query_hint_claim_id(&claim, "liveuniquebeta")?;
    assert!(vault.get_claim(&obsolete_hint)?.is_some());
    assert!(vault.get_claim(&live_hint)?.is_some());

    write_hints(&["liveuniquebeta"])?;
    assert!(vault.get_claim(&obsolete_hint)?.is_none());
    assert!(vault.get_claim(&live_hint)?.is_some());
    assert_eq!(vault.claims_for_subject(&claim)?, vec![live_hint]);
    assert!(vault.search_text("retireduniquealpha", 10)?.is_empty());
    assert_eq!(
        vault
            .search_text("liveuniquebeta", 10)?
            .first()
            .map(|hit| hit.id),
        Some(claim)
    );

    let plain_candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    );
    vault
        .batch()
        .claim_candidate(
            &claim,
            plain_candidate,
            &envelope,
            test_time_range(12, 12),
            13,
        )
        .commit()?;
    assert!(vault.get_claim(&live_hint)?.is_none());
    assert!(vault.claims_for_subject(&claim)?.is_empty());
    assert!(vault.search_text("liveuniquebeta", 10)?.is_empty());

    write_hints(&["liveuniquebeta"])?;
    assert!(vault.get_claim(&live_hint)?.is_some());

    vault.batch().delete(&claim).commit()?;
    assert!(vault.get_claim(&live_hint)?.is_none());
    assert!(vault.claims_for_subject(&claim)?.is_empty());
    assert!(vault.search_text("liveuniquebeta", 10)?.is_empty());
    Ok(())
}

#[test]
fn local_raw_claim_put_removes_lexical_hint_side_records() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let claim = EntityId::now();
    let envelope = test_write_envelope(actor)?;
    let candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    );
    vault
        .batch()
        .claim_candidate_with_lexical_hints(
            &claim,
            candidate,
            &envelope,
            test_time_range(10, 10),
            11,
            &["rawputretiredunique"],
        )
        .commit()?;

    let hint = lexical_query_hint_claim_id(&claim, "rawputretiredunique")?;
    assert!(vault.get_claim(&hint)?.is_some());
    assert_eq!(
        vault
            .search_text("rawputretiredunique", 10)?
            .first()
            .map(|hit| hit.id),
        Some(claim)
    );

    let replacement = ClaimBody::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("gyokuro"),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    vault.put_claim(&claim, &replacement, test_time_range(12, 12), 13)?;

    assert!(vault.get_claim(&hint)?.is_none());
    assert!(vault.claims_for_subject(&claim)?.is_empty());
    assert!(vault.search_text("rawputretiredunique", 10)?.is_empty());
    assert_eq!(vault.claims_for_subject(&subject)?, vec![claim]);
    Ok(())
}

#[test]
fn soft_delete_removes_lexical_hint_side_records() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let claim = EntityId::now();
    let envelope = test_write_envelope(actor)?;
    let candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    );
    vault
        .batch()
        .claim_candidate_with_lexical_hints(
            &claim,
            candidate,
            &envelope,
            test_time_range(10, 10),
            11,
            &["soft delete lexical hint"],
        )
        .commit()?;
    let hint = lexical_query_hint_claim_id(&claim, "soft delete lexical hint")?;

    vault.delete_entity_with_reason(&claim, DeleteReason::UserDelete)?;

    assert!(vault.get_claim(&hint)?.is_none());
    assert!(vault.claims_for_subject(&claim)?.is_empty());
    assert!(vault.search_text("soft delete lexical", 10)?.is_empty());
    Ok(())
}

#[test]
fn plain_overwrite_removes_orphan_lexical_hint_without_claim_of() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let claim = EntityId::now();
    let envelope = test_write_envelope(actor)?;
    let candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    );
    vault
        .batch()
        .claim_candidate(&claim, candidate, &envelope, test_time_range(10, 10), 11)
        .commit()?;

    let stale_query = "legacy orphan lexical hint";
    let orphan_hint = lexical_query_hint_claim_id(&claim, stale_query)?;
    let mut orphan_body = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(claim),
        crate::claim::encode_lexical_query_hint_value(&claim, stale_query),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    orphan_body.stale = true;
    seed_raw_claim_record(&vault, &orphan_hint, orphan_body)?;
    vault
        .batch()
        .text(&orphan_hint, &[("query_hint", stale_query)])
        .commit()?;
    assert!(
        vault.claims_for_subject(&claim)?.is_empty(),
        "fixture intentionally omits the legacy hint ClaimOf edge"
    );
    assert_eq!(
        vault
            .search_text(stale_query, 10)?
            .first()
            .map(|hit| hit.id),
        Some(claim)
    );

    let replacement = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("hojicha"),
        0.9,
    );
    vault
        .batch()
        .claim_candidate(&claim, replacement, &envelope, test_time_range(12, 12), 13)
        .commit()?;

    assert!(vault.get_claim(&orphan_hint)?.is_none());
    assert!(vault.search_text(stale_query, 10)?.is_empty());
    Ok(())
}

#[test]
fn raw_claim_put_rejects_malformed_lexical_hint_claim() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let target = EntityId::now();
    let hint = EntityId::now();
    let body = crate::claim::ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(target),
        Value::from("not a typed lexical hint value"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    let data = crate::claim::encode_claim_body(&body)?;

    let err = vault
        .batch()
        .put(&hint, ENTITY_TYPE_CLAIM, test_time_range(10, 10), 11, &data)
        .commit()
        .expect_err("malformed lexical hint values must reject at the write door");
    assert_matches!(err, Error::InvalidClaimBody(_));
    assert!(vault.get_claim(&hint)?.is_none());
    Ok(())
}

#[test]
fn raw_lexical_hint_put_rejects_non_lh_prefixed_id() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let target = EntityId::now();
    let subject = EntityId::now();
    vault.put_entity(
        &subject,
        ENTITY_TYPE_PERSON,
        test_time_range(1, 1),
        1,
        b"subject",
    )?;
    let target_body = ClaimBody::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    seed_raw_claim_record(&vault, &target, target_body)?;

    let mut raw = [0x44; ENTITY_ID_LEN];
    raw[ENTITY_ID_LEN - 1] &= 0x7F;
    let hint =
        EntityId::from_bytes(raw).map_err(|_| Error::InvariantViolation("invalid test id"))?;
    assert!(
        !hint
            .as_bytes()
            .starts_with(&crate::claim::LEXICAL_QUERY_HINT_ID_PREFIX)
    );
    let mut body = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(target),
        crate::claim::encode_lexical_query_hint_value(&target, "non lh id hint"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    body.stale = true;
    let data = crate::claim::encode_claim_body(&body)?;

    let err = vault
        .batch()
        .put(&hint, ENTITY_TYPE_CLAIM, test_time_range(10, 10), 11, &data)
        .commit()
        .expect_err("lexical.query_hint records must live under derived LH ids");
    assert_matches!(err, Error::InvalidClaimBody(_));
    assert!(vault.get_claim(&hint)?.is_none());
    Ok(())
}

#[test]
fn lexical_hint_write_door_rejects_self_and_synthetic_targets() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let self_hint = lexical_query_hint_claim_id(&EntityId::now(), "self target")?;
    let mut self_body = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(self_hint),
        crate::claim::encode_lexical_query_hint_value(&self_hint, "self target"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    self_body.stale = true;
    let self_data = crate::claim::encode_claim_body(&self_body)?;
    let mut wtxn = vault.store.env.write_txn()?;
    let err = apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        &mut wtxn,
        vec![BatchOp::Put {
            id: self_hint,
            entity_type: ENTITY_TYPE_CLAIM,
            occurred: test_time_range(20, 20),
            learned_at: 21,
            data: self_data,
            allow_maintenance: true,
            allow_reserved_predicate: true,
        }],
        true,
        false,
        false,
    )
    .expect_err("self-target lexical hints must reject");
    assert_matches!(err, Error::InvalidClaimBody(_));
    drop(wtxn);
    assert!(vault.get_claim(&self_hint)?.is_none());

    let source = EntityId::now();
    let source_body = ClaimBody::new(
        "profile.preference",
        ClaimSubject::Entity(EntityId::now()),
        Value::from("sencha"),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    seed_raw_claim_record(&vault, &source, source_body)?;
    let synthetic_target = lexical_query_hint_claim_id(&source, "synthetic target")?;
    let mut synthetic_target_body = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(source),
        crate::claim::encode_lexical_query_hint_value(&source, "synthetic target"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    synthetic_target_body.stale = true;
    seed_raw_claim_record(&vault, &synthetic_target, synthetic_target_body)?;
    let outer_hint = lexical_query_hint_claim_id(&source, "outer target")?;
    let mut synthetic_body = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(synthetic_target),
        crate::claim::encode_lexical_query_hint_value(&synthetic_target, "outer target"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    synthetic_body.stale = true;
    let synthetic_data = crate::claim::encode_claim_body(&synthetic_body)?;
    let mut wtxn = vault.store.env.write_txn()?;
    let err = apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        &mut wtxn,
        vec![BatchOp::Put {
            id: outer_hint,
            entity_type: ENTITY_TYPE_CLAIM,
            occurred: test_time_range(22, 22),
            learned_at: 23,
            data: synthetic_data,
            allow_maintenance: true,
            allow_reserved_predicate: true,
        }],
        true,
        false,
        false,
    )
    .expect_err("lexical hints targeting synthetic hints must reject");
    assert_matches!(err, Error::InvalidClaimBody(_));
    drop(wtxn);
    assert!(vault.get_claim(&outer_hint)?.is_none());
    Ok(())
}

#[test]
fn lexical_hint_write_door_rejects_non_claim_targets() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let target = EntityId::now();
    vault.put_entity(
        &target,
        ENTITY_TYPE_PERSON,
        test_time_range(1, 1),
        1,
        b"not a claim",
    )?;
    let hint = lexical_query_hint_claim_id(&target, "non claim target")?;
    let mut body = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(target),
        crate::claim::encode_lexical_query_hint_value(&target, "non claim target"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    body.stale = true;
    let data = crate::claim::encode_claim_body(&body)?;

    let mut wtxn = vault.store.env.write_txn()?;
    let err = apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        &mut wtxn,
        vec![BatchOp::Put {
            id: hint,
            entity_type: ENTITY_TYPE_CLAIM,
            occurred: test_time_range(20, 20),
            learned_at: 21,
            data,
            allow_maintenance: true,
            allow_reserved_predicate: true,
        }],
        true,
        false,
        false,
    )
    .expect_err("lexical hints must target claim records");
    assert_matches!(err, Error::InvalidClaimBody(_));
    drop(wtxn);
    assert!(vault.get_claim(&hint)?.is_none());
    Ok(())
}

#[test]
fn legacy_cyclic_lexical_hints_delete_without_recursive_cleanup() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let hint_a = lexical_query_hint_claim_id(&EntityId::now(), "cycle a")?;
    let hint_b = lexical_query_hint_claim_id(&EntityId::now(), "cycle b")?;
    let mut body_a = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(hint_b),
        crate::claim::encode_lexical_query_hint_value(&hint_b, "cycle a"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    body_a.stale = true;
    let mut body_b = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(hint_a),
        crate::claim::encode_lexical_query_hint_value(&hint_a, "cycle b"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    body_b.stale = true;
    seed_raw_claim_record(&vault, &hint_a, body_a)?;
    seed_raw_claim_record(&vault, &hint_b, body_b)?;
    seed_claim_of_edge(&vault, &hint_a, &hint_b)?;
    seed_claim_of_edge(&vault, &hint_b, &hint_a)?;

    vault.batch().delete(&hint_a).commit()?;

    assert!(vault.get_claim(&hint_a)?.is_none());
    assert!(vault.get_claim(&hint_b)?.is_none());

    let self_hint = lexical_query_hint_claim_id(&EntityId::now(), "legacy self")?;
    let mut self_body = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(self_hint),
        crate::claim::encode_lexical_query_hint_value(&self_hint, "legacy self"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    self_body.stale = true;
    seed_raw_claim_record(&vault, &self_hint, self_body)?;
    seed_claim_of_edge(&vault, &self_hint, &self_hint)?;

    vault.batch().delete(&self_hint).commit()?;

    assert!(vault.get_claim(&self_hint)?.is_none());
    Ok(())
}

#[test]
fn replicated_lexical_hint_put_indexes_query_text_and_deletes_without_claim_of() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let claim = EntityId::now();
    let envelope = test_write_envelope(actor)?;
    let candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    );
    vault
        .batch()
        .claim_candidate(&claim, candidate, &envelope, test_time_range(10, 10), 11)
        .commit()?;

    let query = "replicated rematerialized hint";
    let hint = lexical_query_hint_claim_id(&claim, query)?;
    let mut body = crate::claim::ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(claim),
        crate::claim::encode_lexical_query_hint_value(&claim, query),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    body.stale = true;
    let data = crate::claim::encode_claim_body(&body)?;
    assert!(
        vault.claims_for_subject(&claim)?.is_empty(),
        "regression fixture starts without a hint ClaimOf edge"
    );
    let mut wtxn = vault.store.env.write_txn()?;
    apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        &mut wtxn,
        vec![BatchOp::Put {
            id: hint,
            entity_type: ENTITY_TYPE_CLAIM,
            occurred: test_time_range(20, 20),
            learned_at: 21,
            data,
            allow_maintenance: true,
            allow_reserved_predicate: true,
        }],
        true,
        false,
        false,
    )?;
    wtxn.commit()?;

    assert!(
        !has_pending_embedding_marker(&vault, &hint)?,
        "replayed lexical hint side claims must not be queued for embeddings"
    );
    assert_eq!(vault.claims_for_subject(&claim)?, vec![hint]);
    assert_eq!(
        vault.search_text(query, 10)?.first().map(|hit| hit.id),
        Some(claim)
    );

    vault.batch().delete(&claim).commit()?;

    assert!(vault.get_claim(&hint)?.is_none());
    assert!(vault.search_text(query, 10)?.is_empty());
    Ok(())
}

#[test]
fn replicated_lexical_hint_put_defers_until_target_claim_materializes() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    vault.put_entity(
        &subject,
        ENTITY_TYPE_PERSON,
        test_time_range(1, 1),
        1,
        b"subject",
    )?;

    let claim = EntityId::from_bytes([0x7A; ENTITY_ID_LEN])
        .map_err(|_| Error::InvariantViolation("invalid test claim id"))?;
    let query = "deferred replay lexical hint";
    let hint = lexical_query_hint_claim_id(&claim, query)?;
    let mut hint_body = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(claim),
        crate::claim::encode_lexical_query_hint_value(&claim, query),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    hint_body.stale = true;
    let hint_data = crate::claim::encode_claim_body(&hint_body)?;

    let claim_body = ClaimBody::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    let claim_data = crate::claim::encode_claim_body(&claim_body)?;

    let mut wtxn = vault.store.env.write_txn()?;
    apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        &mut wtxn,
        vec![
            BatchOp::Put {
                id: hint,
                entity_type: ENTITY_TYPE_CLAIM,
                occurred: test_time_range(20, 20),
                learned_at: 21,
                data: hint_data,
                allow_maintenance: true,
                allow_reserved_predicate: true,
            },
            BatchOp::Put {
                id: claim,
                entity_type: ENTITY_TYPE_CLAIM,
                occurred: test_time_range(10, 10),
                learned_at: 11,
                data: claim_data,
                allow_maintenance: true,
                allow_reserved_predicate: true,
            },
        ],
        true,
        false,
        false,
    )?;
    wtxn.commit()?;

    assert_eq!(vault.claims_for_subject(&claim)?, vec![hint]);
    assert_eq!(
        vault.search_text(query, 10)?.first().map(|hit| hit.id),
        Some(claim)
    );
    Ok(())
}

#[test]
fn deferred_lexical_hint_materialization_fails_closed_when_text_index_untrusted() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let subject = EntityId::now();
    let claim = EntityId::from_bytes([0x7B; ENTITY_ID_LEN])
        .map_err(|_| Error::InvariantViolation("invalid test claim id"))?;
    let query = "deferred trust replay lexical hint";
    let hint = lexical_query_hint_claim_id(&claim, query)?;

    let mut hint_body = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(claim),
        crate::claim::encode_lexical_query_hint_value(&claim, query),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    hint_body.stale = true;
    let hint_data = crate::claim::encode_claim_body(&hint_body)?;

    let claim_body = ClaimBody::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    let claim_data = crate::claim::encode_claim_body(&claim_body)?;

    {
        let vault = Vault::open(dir.path(), test_config())?;
        vault
            .batch()
            .put(
                &subject,
                ENTITY_TYPE_PERSON,
                test_time_range(1, 1),
                1,
                b"subject",
            )
            .text(&subject, &[("body", "trusted seed text")])
            .commit()?;

        let mut wtxn = vault.store.env.write_txn()?;
        apply_ops(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            &mut wtxn,
            vec![BatchOp::Put {
                id: hint,
                entity_type: ENTITY_TYPE_CLAIM,
                occurred: test_time_range(20, 20),
                learned_at: 21,
                data: hint_data,
                allow_maintenance: true,
                allow_reserved_predicate: true,
            }],
            true,
            false,
            false,
        )?;
        wtxn.commit()?;

        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .text_forward
                .get(&rtxn, hint.as_bytes())?
                .is_none(),
            "missing-target replicated hint must defer text indexing"
        );
    }

    let mut cfg = test_config();
    cfg.skip_text_index_manifest_check = true;
    let vault = Vault::open(dir.path(), cfg)?;
    let mut wtxn = vault.store.env.write_txn()?;
    let err = apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        &mut wtxn,
        vec![BatchOp::Put {
            id: claim,
            entity_type: ENTITY_TYPE_CLAIM,
            occurred: test_time_range(30, 30),
            learned_at: 31,
            data: claim_data,
            allow_maintenance: true,
            allow_reserved_predicate: true,
        }],
        false,
        false,
        false,
    )
    .expect_err("target-only replay must not index deferred hints while untrusted");
    assert_matches!(err, Error::CorruptedIndex(_));
    drop(wtxn);

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .text_forward
            .get(&rtxn, hint.as_bytes())?
            .is_none(),
        "failed deferred materialization must leave hint text unindexed"
    );
    drop(rtxn);
    assert!(
        vault.get_claim(&claim)?.is_none(),
        "failed target replay transaction must not commit the target claim"
    );
    Ok(())
}

#[test]
fn bm25_drops_orphan_and_inactive_lexical_hint_postings() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let missing_hint_query = "missingrowuniquealpha";
    let missing_hint = lexical_query_hint_claim_id(&EntityId::now(), missing_hint_query)?;
    vault
        .batch()
        .text(&missing_hint, &[("query_hint", missing_hint_query)])
        .commit()?;
    assert_eq!(
        vault
            .search_text(missing_hint_query, 10)?
            .first()
            .map(|hit| hit.id),
        Some(missing_hint)
    );

    let missing_claim = EntityId::now();
    let orphan_query = "orphanrowuniquebeta";
    let orphan_hint = lexical_query_hint_claim_id(&missing_claim, orphan_query)?;
    let mut orphan_body = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(missing_claim),
        crate::claim::encode_lexical_query_hint_value(&missing_claim, orphan_query),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    orphan_body.stale = true;
    seed_raw_claim_record(&vault, &orphan_hint, orphan_body)?;
    vault
        .batch()
        .text(&orphan_hint, &[("query_hint", orphan_query)])
        .commit()?;
    assert!(vault.search_text(orphan_query, 10)?.is_empty());

    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;
    let claim = EntityId::now();
    let envelope = test_write_envelope(actor)?;
    let candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    );
    vault
        .batch()
        .claim_candidate(&claim, candidate, &envelope, test_time_range(10, 10), 11)
        .commit()?;

    let inactive_query = "inactiverowuniquegamma";
    let inactive_hint = lexical_query_hint_claim_id(&claim, inactive_query)?;
    let mut inactive_body = ClaimBody::new(
        crate::claim::PREDICATE_LEXICAL_QUERY_HINT,
        ClaimSubject::Entity(claim),
        crate::claim::encode_lexical_query_hint_value(&claim, inactive_query),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Superseded,
    );
    inactive_body.stale = true;
    seed_raw_claim_record(&vault, &inactive_hint, inactive_body)?;
    vault
        .batch()
        .text(&inactive_hint, &[("query_hint", inactive_query)])
        .commit()?;
    assert!(vault.search_text(inactive_query, 10)?.is_empty());

    let soft_deleted_query = "softdeletedrowuniquedelta";
    let soft_deleted_hint = lexical_query_hint_claim_id(&claim, soft_deleted_query)?;
    let header = EntityMetadataHeader {
        entity_type: ENTITY_TYPE_CLAIM,
        occurred_start: 30,
        occurred_end: 30,
        learned_at: 31,
    };
    let mut payload = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN);
    payload.push(header.entity_type);
    payload.extend_from_slice(&header.occurred_start.to_be_bytes());
    payload.extend_from_slice(&header.occurred_end.to_be_bytes());
    payload.extend_from_slice(&header.learned_at.to_be_bytes());
    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .entities
        .put(&mut wtxn, soft_deleted_hint.as_bytes(), &payload)?;
    let type_key = Store::encode_type_key(ENTITY_TYPE_CLAIM, &soft_deleted_hint);
    vault.store.type_index.put(&mut wtxn, &type_key, &[])?;
    wtxn.commit()?;
    vault
        .batch()
        .text(&soft_deleted_hint, &[("query_hint", soft_deleted_query)])
        .commit()?;
    assert!(vault.search_text(soft_deleted_query, 10)?.is_empty());
    Ok(())
}

#[test]
fn retained_lexical_hint_reput_clears_stale_vector_and_embedding_state() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let claim = EntityId::now();
    let envelope = test_write_envelope(actor)?;
    let write_hints = || -> Result<()> {
        let candidate = ClaimCandidate::new(
            "profile.preference",
            ClaimSubject::Entity(subject),
            Value::from("sencha"),
            0.9,
        );
        vault
            .batch()
            .claim_candidate_with_lexical_hints(
                &claim,
                candidate,
                &envelope,
                test_time_range(10, 10),
                11,
                &["retained vector cleanup hint"],
            )
            .commit()
    };

    write_hints()?;
    let hint = lexical_query_hint_claim_id(&claim, "retained vector cleanup hint")?;
    let err = vault
        .put_vector(&hint, &[1.0, 0.0, 0.0, 0.0])
        .expect_err("synthetic lexical hint vectors must reject");
    assert_matches!(err, Error::InvalidClaimBody(_));
    assert!(vault.get_vector(&hint)?.is_none());
    assert!(
        !vault
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)?
            .iter()
            .any(|hit| hit.id == hint),
        "rejected vector writes must never expose lexical hints"
    );

    seed_stale_vector_state(&vault, &hint, &[1.0, 0.0, 0.0, 0.0])?;
    overwrite_pending_embedding_marker(&vault, &hint, b"stale lexical hint marker")?;

    assert_eq!(
        vault.get_vector(&hint)?.as_deref(),
        Some([1.0, 0.0, 0.0, 0.0].as_slice())
    );
    assert!(raw_pending_embedding_marker(&vault, &hint)?.is_some());
    assert!(
        vault
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)?
            .iter()
            .any(|hit| hit.id == hint),
        "seeded stale vector must be reachable before the retained hint re-put"
    );

    write_hints()?;

    assert!(
        raw_pending_embedding_marker(&vault, &hint)?.is_none(),
        "retained lexical hint re-put must clear stale embedding marker state"
    );
    assert!(
        vault.get_vector(&hint)?.is_none(),
        "retained lexical hint re-put must delete stale vector rows"
    );
    assert!(
        !vault
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)?
            .iter()
            .any(|hit| hit.id == hint),
        "retained lexical hint must not remain reachable through vector search"
    );
    assert_eq!(
        vault
            .search_text("retained vector cleanup hint", 10)?
            .first()
            .map(|hit| hit.id),
        Some(claim),
        "lexical hint text must remain searchable after vector cleanup"
    );
    Ok(())
}

#[test]
fn lh_prefixed_normal_ids_are_not_treated_as_synthetic_hints() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let normal_entity = lh_prefixed_id(0x11)?;
    vault.put_entity(
        &normal_entity,
        ENTITY_TYPE_PERSON,
        test_time_range(1, 1),
        1,
        b"ordinary LH-prefixed entity",
    )?;
    vault
        .batch()
        .text(&normal_entity, &[("body", "ordinary LH text")])
        .commit()?;
    assert_eq!(
        vault
            .search_text("ordinary LH text", 10)?
            .first()
            .map(|hit| hit.id),
        Some(normal_entity)
    );
    vault.put_vector(&normal_entity, &[1.0, 0.0, 0.0, 0.0])?;
    assert_eq!(
        vault.get_vector(&normal_entity)?.as_deref(),
        Some([1.0, 0.0, 0.0, 0.0].as_slice())
    );

    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(2, 2);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 2, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 2, b"subject")?;

    let claim = lh_prefixed_id(0x22)?;
    let envelope = test_write_envelope(actor)?;
    let candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    );
    vault
        .batch()
        .claim_candidate_with_lexical_hints(
            &claim,
            candidate,
            &envelope,
            test_time_range(10, 10),
            11,
            &["normal LH source claim hint"],
        )
        .commit()?;

    assert_eq!(
        vault
            .search_text("normal LH source", 10)?
            .first()
            .map(|hit| hit.id),
        Some(claim)
    );
    Ok(())
}

#[test]
fn claim_candidate_lexical_hint_ids_are_order_stable() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let claim = EntityId::now();
    let envelope = test_write_envelope(actor)?;
    let write_hints = |hints: &[&str]| -> Result<()> {
        let candidate = ClaimCandidate::new(
            "profile.preference",
            ClaimSubject::Entity(subject),
            Value::from("sencha"),
            0.9,
        );
        vault
            .batch()
            .claim_candidate_with_lexical_hints(
                &claim,
                candidate,
                &envelope,
                test_time_range(10, 10),
                11,
                hints,
            )
            .commit()
    };

    write_hints(&["spring roadmap migration", "account recovery plan"])?;
    let mut first_hint_claims = vault.claims_for_subject(&claim)?;
    first_hint_claims.sort();
    assert_eq!(first_hint_claims.len(), 2);

    write_hints(&["account recovery plan", "spring roadmap migration"])?;
    let mut reordered_hint_claims = vault.claims_for_subject(&claim)?;
    reordered_hint_claims.sort();
    assert_eq!(reordered_hint_claims, first_hint_claims);
    assert!(reordered_hint_claims.iter().all(|hint_claim| {
        hint_claim
            .as_bytes()
            .starts_with(&crate::claim::LEXICAL_QUERY_HINT_ID_PREFIX)
    }));

    let roadmap_hits = vault.search_text("spring roadmap migration", 10)?;
    assert_eq!(roadmap_hits.first().map(|hit| hit.id), Some(claim));
    assert!(
        !roadmap_hits
            .iter()
            .any(|hit| reordered_hint_claims.contains(&hit.id)),
        "reordered lexical hint docs must collapse to the source claim"
    );

    let recovery_hits = vault.search_text("account recovery plan", 10)?;
    assert_eq!(recovery_hits.first().map(|hit| hit.id), Some(claim));
    assert!(
        !recovery_hits
            .iter()
            .any(|hit| reordered_hint_claims.contains(&hit.id)),
        "reordered lexical hint docs must collapse to the source claim"
    );
    Ok(())
}

#[test]
fn claim_candidate_lexical_hints_are_capped() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let claim = EntityId::now();
    let envelope = test_write_envelope(actor)?;
    let candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    );
    let hints = [
        "hint zero",
        "hint one",
        "hint two",
        "hint three",
        "hint four",
        "hint five",
        "hint six",
        "hint seven",
        "hint eight",
        "hint nine",
    ];

    vault
        .batch()
        .claim_candidate_with_lexical_hints(
            &claim,
            candidate,
            &envelope,
            test_time_range(10, 10),
            11,
            &hints,
        )
        .commit()?;

    let hint_claims = vault.claims_for_subject(&claim)?;
    assert_eq!(
        hint_claims.len(),
        crate::claim::MAX_LEXICAL_QUERY_HINTS_PER_CLAIM
    );
    assert!(
        vault
            .search_text("seven", 10)?
            .iter()
            .any(|hit| hit.id == claim)
    );
    assert!(vault.search_text("nine", 10)?.is_empty());
    Ok(())
}

fn claim_candidate_fixture(vault: &Vault, value: &str) -> Result<(WriteEnvelope, ClaimCandidate)> {
    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let envelope = test_write_envelope(actor)?;
    let candidate = ClaimCandidate::new(
        "profile.name",
        ClaimSubject::Entity(subject),
        Value::from(value),
        0.9,
    );
    Ok((envelope, candidate))
}

fn commit_claim_candidate_with_value(vault: &Vault, claim: EntityId, value: &str) -> Result<()> {
    let (envelope, candidate) = claim_candidate_fixture(vault, value)?;
    vault
        .batch()
        .claim_candidate(&claim, candidate, &envelope, test_time_range(10, 10), 11)
        .commit()
}

fn commit_claim_candidate_fixture(vault: &Vault, claim: EntityId) -> Result<()> {
    commit_claim_candidate_with_value(vault, claim, "Alice")
}

#[test]
fn claim_candidate_commit_writes_pending_embedding_marker_before_vector_exists() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();

    commit_claim_candidate_fixture(&vault, claim)?;

    assert!(vault.get_claim(&claim)?.is_some(), "claim must be durable");
    assert!(
        vault.get_vector(&claim)?.is_none(),
        "claim commit must not fabricate a vector row"
    );
    assert!(
        has_pending_embedding_marker(&vault, &claim)?,
        "claim commit must mark embedding as pending"
    );
    Ok(())
}

#[test]
fn batch_vector_rejects_non_finite_without_persisting_vectors() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let good = EntityId::now();
    let bad = EntityId::now();

    let err = vault
        .batch()
        .vector(&good, &[1.0, 0.0, 0.0, 0.0])
        .vector(&bad, &[0.0, f32::NEG_INFINITY, 0.0, 0.0])
        .commit()
        .expect_err("non-finite batch vector must fail closed");

    assert_matches!(
        err,
        Error::InvalidVector { index: 1, value }
            if value.is_infinite() && value.is_sign_negative()
    );
    assert!(vault.get_vector(&good)?.is_none());
    assert!(vault.get_vector(&bad)?.is_none());
    Ok(())
}

#[test]
fn vector_fill_clears_pending_embedding_marker() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    commit_claim_candidate_fixture(&vault, claim)?;
    let token = pending_embedding_token(&vault, &claim)?;

    vault
        .batch()
        .vector_for_pending_embedding(&claim, &[1.0, 0.0, 0.0, 0.0], &token)
        .commit()?;

    assert_eq!(
        vault.get_vector(&claim)?.as_deref(),
        Some([1.0, 0.0, 0.0, 0.0].as_slice())
    );
    assert!(
        !has_pending_embedding_marker(&vault, &claim)?,
        "vector fill must clear the pending marker"
    );
    assert!(
        raw_pending_embedding_marker(&vault, &claim)?.is_none(),
        "token-proven vector fill must remove durable marker state"
    );
    Ok(())
}

#[test]
fn pending_vector_fill_rejects_non_finite_without_clearing_marker() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    commit_claim_candidate_fixture(&vault, claim)?;
    let token = pending_embedding_token(&vault, &claim)?;

    let err = vault
        .batch()
        .vector_for_pending_embedding(&claim, &[1.0, f32::INFINITY, 0.0, 0.0], &token)
        .commit()
        .expect_err("non-finite pending vector fill must fail closed");

    assert_matches!(
        err,
        Error::InvalidVector { index: 1, value }
            if value.is_infinite() && value.is_sign_positive()
    );
    assert!(vault.get_vector(&claim)?.is_none());
    assert_eq!(pending_embedding_token(&vault, &claim)?, token);
    Ok(())
}

#[test]
fn duplicate_vector_fill_keeps_pending_embedding_marker_cleared() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    commit_claim_candidate_fixture(&vault, claim)?;
    let token = pending_embedding_token(&vault, &claim)?;

    vault
        .batch()
        .vector_for_pending_embedding(&claim, &[1.0, 0.0, 0.0, 0.0], &token)
        .commit()?;
    vault
        .batch()
        .vector_for_pending_embedding(&claim, &[1.0, 0.0, 0.0, 0.0], &token)
        .commit()?;

    assert!(
        !has_pending_embedding_marker(&vault, &claim)?,
        "duplicate fills must be idempotent"
    );
    assert_eq!(
        vault
            .query()
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
            .run()?
            .len(),
        1
    );
    Ok(())
}

#[test]
fn plain_vector_fill_keeps_current_pending_embedding_marker() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    commit_claim_candidate_fixture(&vault, claim)?;
    let token = pending_embedding_token(&vault, &claim)?;

    vault.put_vector(&claim, &[1.0, 0.0, 0.0, 0.0])?;

    assert_eq!(
        vault.get_vector(&claim)?.as_deref(),
        Some([1.0, 0.0, 0.0, 0.0].as_slice())
    );
    assert_eq!(
        pending_embedding_token(&vault, &claim)?,
        token,
        "un-tokened vector fills cannot prove they embedded the current claim body"
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn replicated_claim_materialization_writes_pending_embedding_marker() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    let body = ClaimBody::new(
        "profile.name",
        ClaimSubject::Entity(EntityId::now()),
        Value::from("replicated Alice"),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    let data = crate::claim::encode_claim_body(&body)?;

    vault
        .batch()
        .put_replicated(&claim, ENTITY_TYPE_CLAIM, test_time_range(1, 1), 2, &data)
        .commit()?;

    assert!(
        has_pending_embedding_marker(&vault, &claim)?,
        "replicated claim materialization must request embedding"
    );
    assert!(
        !pending_embedding_token(&vault, &claim)?.is_empty(),
        "replicated marker must carry a body token"
    );
    Ok(())
}

#[cfg(feature = "sync")]
fn authority_test_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

#[cfg(feature = "sync")]
fn authority_key_from_signing(signing: &SigningKey) -> crate::authority::AuthorityKey {
    crate::authority::AuthorityKey::Ed25519(signing.verifying_key().to_bytes())
}

#[cfg(feature = "sync")]
fn authority_test_device(key: crate::authority::AuthorityKey) -> crate::authority::DeviceAuthority {
    crate::authority::DeviceAuthority {
        key,
        transport_key_binding: [0; 32],
        attestation: crate::authority::AuthorityAttestation {
            kind: "SoftwareArgon2id".to_owned(),
            evidence: vec![1, 2, 3],
        },
        tier: crate::authority::AuthorityTier::Software,
        roles: crate::authority::ROLE_OWNER,
    }
}

#[cfg(feature = "sync")]
fn authority_genesis_fixture(seed: u8) -> crate::authority::AuthorityLogEntry {
    let signing = authority_test_key(seed);
    let key = authority_key_from_signing(&signing);
    let mut entry = crate::authority::AuthorityLogEntry {
        schema_version: 1,
        vault_id: None,
        seq: 0,
        parent_hashes: Vec::new(),
        op: crate::authority::AuthorityOp::Genesis {
            device: authority_test_device(key.clone()),
            genesis_nonce: [seed.wrapping_add(1); 32],
            tier_floor: crate::authority::AuthorityTier::Software,
            pending_widen_delay_secs: 86_400,
        },
        signer: crate::authority::AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: u64::from(seed),
    };
    let transcript = crate::authority::authority_transcript(&entry).expect("transcript");
    entry.signer.signature = signing.sign(&transcript).to_bytes().to_vec();
    entry
}

#[cfg(feature = "sync")]
fn authority_enroll_fixture(
    vault_id: crate::authority::AuthorityVaultId,
    parent: &crate::authority::AuthorityLogEntry,
    signer: &SigningKey,
    new_seed: u8,
    seq: u64,
) -> crate::authority::AuthorityLogEntry {
    let signer_key = authority_key_from_signing(signer);
    let new_key = authority_key_from_signing(&authority_test_key(new_seed));
    let mut entry = crate::authority::AuthorityLogEntry {
        schema_version: 1,
        vault_id: Some(vault_id),
        seq,
        parent_hashes: vec![crate::authority::authority_entry_hash(parent).expect("parent hash")],
        op: crate::authority::AuthorityOp::EnrollDevice {
            device: authority_test_device(new_key),
        },
        signer: crate::authority::AuthoritySignature {
            suite: signer_key.suite(),
            public_key: signer_key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: u64::from(new_seed),
    };
    let transcript = crate::authority::authority_transcript(&entry).expect("transcript");
    entry.signer.signature = signer.sign(&transcript).to_bytes().to_vec();
    entry
}

#[cfg(feature = "sync")]
fn authority_first_seen_for_test(vault: &Vault, key: &str) -> Result<Option<u64>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(vault
        .store
        .sync_state
        .get(&rtxn, key)?
        .and_then(crate::authority::decode_authority_first_seen_secs))
}

#[cfg(feature = "sync")]
#[test]
fn authority_log_first_seen_sidecar_drives_live_fold() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let owner = authority_test_key(74);
    let genesis = authority_genesis_fixture(74);
    let vault_id = crate::authority::genesis_vault_id(&genesis)?;
    let enroll = authority_enroll_fixture(vault_id, &genesis, &owner, 75, 1);
    let enroll_hash = crate::authority::authority_entry_hash(&enroll)?;
    let enroll_sidecar = crate::authority::authority_first_seen_sync_key(&enroll_hash);
    let enroll_key = authority_key_from_signing(&authority_test_key(75));
    let genesis_id = EntityId::now();
    let enroll_id = EntityId::now();

    vault.put_authority_log_entry(&genesis_id, &genesis, test_time_range(1, 1), 1)?;
    vault.put_authority_log_entry(&enroll_id, &enroll, test_time_range(2, 2), 2)?;

    let first_seen = authority_first_seen_for_test(&vault, &enroll_sidecar)?
        .expect("authority log put must create first-seen sidecar");
    let fold = vault.authority_fold()?;
    assert!(fold.pending_widens.contains_key(&enroll_hash));
    assert!(!fold.roster.contains_key(&enroll_key));

    vault.put_authority_log_entry(&enroll_id, &enroll, test_time_range(3, 3), 999_999)?;
    assert_eq!(
        authority_first_seen_for_test(&vault, &enroll_sidecar)?,
        Some(first_seen),
        "metadata-only rewrites must not move local first-seen"
    );

    vault.with_write_txn(|wtxn| {
        vault
            .store
            .sync_state
            .delete(wtxn, enroll_sidecar.as_str())?;
        Ok(())
    })?;
    let missing_sidecar_fold = vault.authority_fold()?;
    assert_eq!(
        missing_sidecar_fold
            .pending_widens
            .get(&enroll_hash)
            .and_then(|pending| pending.first_seen_at_secs),
        None,
        "missing local first-seen data must fail closed instead of trusting entity metadata"
    );
    assert!(!missing_sidecar_fold.roster.contains_key(&enroll_key));
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn authority_log_write_does_not_mark_legacy_backfill_complete() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let genesis = authority_genesis_fixture(86);

    vault.put_authority_log_entry(&EntityId::now(), &genesis, test_time_range(1, 1), 1)?;

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .sync_state
            .get(
                &rtxn,
                crate::authority::authority_first_seen_backfill_sync_key(),
            )?
            .is_none(),
        "a single authority write must not suppress the legacy sidecar scan"
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn authority_log_first_seen_ignores_future_learned_at_metadata() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let genesis = authority_genesis_fixture(87);
    let genesis_hash = crate::authority::authority_entry_hash(&genesis)?;
    let genesis_sidecar = crate::authority::authority_first_seen_sync_key(&genesis_hash);
    let future_learned_at = crate::unix_seconds_now()
        .saturating_add(crate::authority::DEFAULT_PENDING_WIDEN_DELAY_SECS);

    vault.put_authority_log_entry(
        &EntityId::now(),
        &genesis,
        test_time_range(1, 1),
        future_learned_at,
    )?;

    let first_seen = authority_first_seen_for_test(&vault, &genesis_sidecar)?
        .expect("authority log put must create first-seen sidecar");
    assert!(
        first_seen < future_learned_at,
        "local first-seen must come from local observation time, not future learned_at metadata"
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn authority_fold_backfills_legacy_missing_first_seen_sidecars_once() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let owner = authority_test_key(84);
    let genesis = authority_genesis_fixture(84);
    let vault_id = crate::authority::genesis_vault_id(&genesis)?;
    let enroll = authority_enroll_fixture(vault_id, &genesis, &owner, 85, 1);
    let enroll_hash = crate::authority::authority_entry_hash(&enroll)?;
    let enroll_sidecar = crate::authority::authority_first_seen_sync_key(&enroll_hash);
    let enroll_key = authority_key_from_signing(&authority_test_key(85));

    vault.put_authority_log_entry(&EntityId::now(), &genesis, test_time_range(1, 1), 1)?;
    vault.put_authority_log_entry(&EntityId::now(), &enroll, test_time_range(2, 2), 2)?;
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .sync_state
            .delete(wtxn, enroll_sidecar.as_str())?;
        vault.store.sync_state.delete(
            wtxn,
            crate::authority::authority_first_seen_backfill_sync_key(),
        )?;
        Ok(())
    })?;

    let backfilled_fold = vault.authority_fold()?;
    assert!(backfilled_fold.roster.contains_key(&enroll_key));
    assert_eq!(
        authority_first_seen_for_test(&vault, &enroll_sidecar)?,
        Some(2),
        "legacy sidecar migration should preserve the stored learned-at observation"
    );

    vault.with_write_txn(|wtxn| {
        vault
            .store
            .sync_state
            .delete(wtxn, enroll_sidecar.as_str())?;
        Ok(())
    })?;
    let missing_after_marker = vault.authority_fold()?;
    assert!(
        !missing_after_marker.roster.contains_key(&enroll_key),
        "after migration, a missing sidecar must still fail closed"
    );
    assert_eq!(
        missing_after_marker
            .pending_widens
            .get(&enroll_hash)
            .and_then(|pending| pending.first_seen_at_secs),
        None
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn replicated_authority_log_rejects_foreign_vault_root() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let local = authority_genesis_fixture(72);
    vault.put_authority_log_entry(&EntityId::now(), &local, test_time_range(1, 1), 1)?;

    let foreign = authority_genesis_fixture(73);
    let foreign_body = crate::authority::encode_authority_log_entry_body(&foreign)?;
    let err = vault
        .batch()
        .put_replicated(
            &EntityId::now(),
            ENTITY_TYPE_AUTHORITY_LOG,
            test_time_range(2, 2),
            2,
            &foreign_body,
        )
        .commit()
        .expect_err("foreign authority log must not enter replicated storage");

    assert_eq!(err.kind(), ErrorKind::InvalidAuthorityLogBody);
    Ok(())
}

#[test]
fn stale_vector_fill_does_not_clear_or_overwrite_newer_claim_marker() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    commit_claim_candidate_with_value(&vault, claim, "Alice")?;
    let old_token = pending_embedding_token(&vault, &claim)?;

    vault
        .batch()
        .vector_for_pending_embedding(&claim, &[1.0, 0.0, 0.0, 0.0], &old_token)
        .commit()?;
    commit_claim_candidate_with_value(&vault, claim, "Bob")?;
    let new_token = pending_embedding_token(&vault, &claim)?;
    assert_ne!(
        old_token, new_token,
        "claim body overwrite must mint a new token"
    );

    vault
        .batch()
        .vector_for_pending_embedding(&claim, &[0.0, 1.0, 0.0, 0.0], &old_token)
        .commit()?;

    assert_eq!(
        vault.get_vector(&claim)?.as_deref(),
        Some([1.0, 0.0, 0.0, 0.0].as_slice()),
        "stale fill must not overwrite the current vector row"
    );
    assert_eq!(
        pending_embedding_token(&vault, &claim)?,
        new_token,
        "stale fill must leave the newer marker token pending"
    );

    vault
        .batch()
        .vector_for_pending_embedding(&claim, &[0.0, 1.0, 0.0, 0.0], &new_token)
        .commit()?;
    assert!(
        !has_pending_embedding_marker(&vault, &claim)?,
        "current-token fill must clear the marker"
    );
    assert_eq!(
        vault.get_vector(&claim)?.as_deref(),
        Some([0.0, 1.0, 0.0, 0.0].as_slice())
    );
    Ok(())
}

#[test]
fn plain_vector_fill_does_not_clear_stale_pending_embedding_marker() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    commit_claim_candidate_with_value(&vault, claim, "Alice")?;
    let old_token = pending_embedding_token(&vault, &claim)?;

    commit_claim_candidate_with_value(&vault, claim, "Bob")?;
    let new_token = pending_embedding_token(&vault, &claim)?;
    assert_ne!(
        old_token, new_token,
        "claim body overwrite must mint a new token"
    );
    overwrite_pending_embedding_marker(&vault, &claim, &old_token)?;
    assert!(
        !has_pending_embedding_marker(&vault, &claim)?,
        "stale marker token must not report as current pending work"
    );

    vault.put_vector(&claim, &[1.0, 0.0, 0.0, 0.0])?;

    assert_eq!(
        vault.get_vector(&claim)?.as_deref(),
        Some([1.0, 0.0, 0.0, 0.0].as_slice())
    );
    assert_eq!(
        raw_pending_embedding_marker(&vault, &claim)?.as_deref(),
        Some(old_token.as_slice()),
        "plain vector fills must not clear stale markers by id alone"
    );
    Ok(())
}

#[test]
fn plain_vector_fill_after_claim_overwrite_keeps_newer_pending_embedding_marker() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    commit_claim_candidate_with_value(&vault, claim, "Alice")?;
    let old_token = pending_embedding_token(&vault, &claim)?;

    commit_claim_candidate_with_value(&vault, claim, "Bob")?;
    let new_token = pending_embedding_token(&vault, &claim)?;
    assert_ne!(
        old_token, new_token,
        "claim body overwrite must mint a new token"
    );

    vault.put_vector(&claim, &[1.0, 0.0, 0.0, 0.0])?;

    assert_eq!(
        vault.get_vector(&claim)?.as_deref(),
        Some([1.0, 0.0, 0.0, 0.0].as_slice()),
        "legacy vector path still writes the row"
    );
    assert_eq!(
        pending_embedding_token(&vault, &claim)?,
        new_token,
        "un-tokened vector fills must not clear a newer pending marker"
    );
    assert_eq!(
        raw_pending_embedding_marker(&vault, &claim)?.as_deref(),
        Some(new_token.as_slice()),
        "the durable marker row must remain for the current claim body"
    );
    Ok(())
}

#[test]
fn same_batch_claim_then_vector_clears_pending_embedding_marker() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    let (envelope, candidate) = claim_candidate_fixture(&vault, "Alice")?;

    vault
        .batch()
        .claim_candidate(&claim, candidate, &envelope, test_time_range(10, 10), 11)
        .vector(&claim, &[1.0, 0.0, 0.0, 0.0])
        .commit()?;

    assert!(
        !has_pending_embedding_marker(&vault, &claim)?,
        "same-batch vector after claim materialization proves freshness"
    );
    assert!(
        raw_pending_embedding_marker(&vault, &claim)?.is_none(),
        "same-batch vector after claim must remove durable marker state"
    );
    Ok(())
}

#[test]
fn same_batch_delete_clears_pending_embedding_token_cache_before_plain_vector() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    let (envelope, candidate) = claim_candidate_fixture(&vault, "Alice")?;

    vault
        .batch()
        .claim_candidate(&claim, candidate, &envelope, test_time_range(10, 10), 11)
        .delete(&claim)
        .vector(&claim, &[1.0, 0.0, 0.0, 0.0])
        .commit()?;

    assert!(
        vault.get_claim(&claim)?.is_none(),
        "delete must remove the same-batch claim materialization"
    );
    assert_eq!(
        vault.get_vector(&claim)?.as_deref(),
        Some([1.0, 0.0, 0.0, 0.0].as_slice()),
        "delete must not leave a stale same-batch token that drops later vectors"
    );
    assert!(
        raw_pending_embedding_marker(&vault, &claim)?.is_none(),
        "delete must clear durable pending marker state"
    );
    Ok(())
}

#[test]
fn same_batch_vector_then_claim_leaves_pending_embedding_marker() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    let (envelope, candidate) = claim_candidate_fixture(&vault, "Alice")?;

    vault
        .batch()
        .vector(&claim, &[1.0, 0.0, 0.0, 0.0])
        .claim_candidate(&claim, candidate, &envelope, test_time_range(10, 10), 11)
        .commit()?;

    assert!(
        has_pending_embedding_marker(&vault, &claim)?,
        "vector before claim materialization cannot prove it embedded the claim"
    );
    Ok(())
}

#[test]
fn soft_delete_removes_pending_embedding_state_for_claim_shell() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    commit_claim_candidate_fixture(&vault, claim)?;
    assert!(has_pending_embedding_marker(&vault, &claim)?);

    let outcome = vault.delete_entity_with_reason(&claim, DeleteReason::UserDelete)?;

    assert!(outcome.existed);
    assert!(
        !has_pending_embedding_marker(&vault, &claim)?,
        "soft-erased header-only claims must not remain pending"
    );
    assert!(
        raw_pending_embedding_marker(&vault, &claim)?.is_none(),
        "soft delete must remove the durable marker row, not only hide API-visible pending state"
    );
    Ok(())
}

#[test]
fn raw_public_batch_put_rejects_claim_without_write_envelope() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    let mut body = ClaimBody::new(
        "profile.name",
        ClaimSubject::Entity(subject),
        Value::from("Alice"),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    body.source = Some(ClaimSource::UserStated);
    let data = crate::claim::encode_claim_body(&body)?;

    let batch_claim = EntityId::now();
    let err = vault
        .batch()
        .put(
            &batch_claim,
            ENTITY_TYPE_CLAIM,
            test_time_range(1, 1),
            2,
            &data,
        )
        .commit()
        .expect_err("raw batch claim put must require WriteEnvelope");
    assert!(matches!(
        err,
        Error::InvalidClaimBody(ERR_RAW_CLAIM_PUT_REQUIRES_ENVELOPE)
    ));
    assert!(vault.get_claim(&batch_claim)?.is_none());

    let txn_claim = EntityId::now();
    let err = vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .put(
                    &txn_claim,
                    ENTITY_TYPE_CLAIM,
                    test_time_range(1, 1),
                    2,
                    &data,
                )
                .apply(wtxn)
        })
        .expect_err("raw transaction-batch claim put must require WriteEnvelope");
    assert!(matches!(
        err,
        Error::InvalidClaimBody(ERR_RAW_CLAIM_PUT_REQUIRES_ENVELOPE)
    ));
    assert!(vault.get_claim(&txn_claim)?.is_none());
    Ok(())
}

#[test]
fn raw_public_put_rejects_legacy_generated_code_revision_without_auto_permit() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    let mut body = ClaimBody::new(
        "code.revision",
        ClaimSubject::Entity(subject),
        Value::from("finalized"),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.source = Some(ClaimSource::Generated);
    let data = crate::claim::encode_claim_body(&body)?;

    let claim = EntityId::now();
    let err = vault
        .put_entity(&claim, ENTITY_TYPE_CLAIM, test_time_range(1, 1), 2, &data)
        .expect_err("generated source requires explicit auto permit");
    assert!(matches!(
        err,
        Error::SourceNotTrustedForAuto {
            claim_source: "generated"
        }
    ));
    assert!(vault.get_claim(&claim)?.is_none());
    Ok(())
}

#[test]
fn claim_candidate_overwrite_reconciles_claim_of_edges() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let subject_a = EntityId::now();
    let subject_b = EntityId::now();
    let edge_source = EntityId::now();
    let edge_target = EntityId::now();
    let occurred = test_time_range(1, 1);
    for (id, body) in [
        (actor, b"actor".as_slice()),
        (subject_a, b"subject-a".as_slice()),
        (subject_b, b"subject-b".as_slice()),
        (edge_source, b"edge-source".as_slice()),
        (edge_target, b"edge-target".as_slice()),
    ] {
        vault.put_entity(&id, ENTITY_TYPE_PERSON, occurred, 1, body)?;
    }

    let claim = EntityId::now();
    let envelope = test_write_envelope(actor)?;
    vault
        .batch()
        .claim_candidate(
            &claim,
            ClaimCandidate::new(
                "profile.name",
                ClaimSubject::Entity(subject_a),
                Value::from("Alice"),
                0.9,
            ),
            &envelope,
            test_time_range(10, 10),
            11,
        )
        .commit()?;
    assert_eq!(vault.claims_for_subject(&subject_a)?, vec![claim]);

    vault
        .batch()
        .claim_candidate(
            &claim,
            ClaimCandidate::new(
                "profile.name",
                ClaimSubject::Entity(subject_b),
                Value::from("Bob"),
                0.8,
            ),
            &envelope,
            test_time_range(12, 12),
            13,
        )
        .commit()?;
    assert!(vault.claims_for_subject(&subject_a)?.is_empty());
    assert_eq!(vault.claims_for_subject(&subject_b)?, vec![claim]);

    let edge_subject = ClaimSubject::Edge {
        source: edge_source,
        kind: EdgeKind::Supports,
        target: edge_target,
    };
    vault
        .batch()
        .claim_candidate(
            &claim,
            ClaimCandidate::new(
                "graph.observation",
                edge_subject,
                Value::from("supports"),
                0.7,
            ),
            &envelope,
            test_time_range(14, 14),
            15,
        )
        .commit()?;
    assert!(vault.claims_for_subject(&subject_b)?.is_empty());
    let stored = vault.get_claim(&claim)?.expect("candidate claim stored");
    assert_eq!(stored.subject, edge_subject);
    assert!(
        vault
            .edges_out(&claim)?
            .iter()
            .all(|edge| edge.kind != EdgeKind::ClaimOf),
        "edge-subject overwrite must remove stale ClaimOf rows"
    );
    Ok(())
}

#[test]
fn public_timestamped_builder_rejects_over_provenanced_edge() -> Result<()> {
    let fixture = provenanced_edge_fixture()?;
    let vault = &fixture.vault;
    let src = fixture.edge.source;
    let kind = fixture.edge.kind;
    let tgt = fixture.edge.target;
    let vad = Vad {
        valence: 0.1,
        arousal: 0.2,
        dominance: 0.3,
    };

    let (before_out, before_in) = raw_edge_values(vault, &fixture.edge)?;
    let before_out = before_out.expect("provenanced edge");
    assert_eq!(before_out.len(), EDGE_VALUE_SEMANTIC_PROVENANCED_LEN);
    assert_eq!(before_in.as_deref(), Some(before_out.as_slice()));

    let err = vault
        .batch()
        .edge_with_created_at(&src, kind, &tgt, 0.5, 2_000)
        .commit()
        .expect_err("batch edge_with_created_at must reject");
    assert_edge_is_provenanced_reject(err, kind, "batch edge_with_created_at");
    assert_raw_edge_unchanged(
        vault,
        &fixture.edge,
        &before_out,
        "batch edge_with_created_at",
    )?;

    let err = vault
        .batch()
        .edge_with_created_at_and_vad(&src, kind, &tgt, 0.5, 2_001, vad)
        .commit()
        .expect_err("batch edge_with_created_at_and_vad must reject");
    assert_edge_is_provenanced_reject(err, kind, "batch edge_with_created_at_and_vad");
    assert_raw_edge_unchanged(
        vault,
        &fixture.edge,
        &before_out,
        "batch edge_with_created_at_and_vad",
    )?;

    let err = vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .edge_with_created_at(&src, kind, &tgt, 0.5, 2_002)
                .apply(wtxn)
        })
        .expect_err("batch_in edge_with_created_at must reject");
    assert_edge_is_provenanced_reject(err, kind, "batch_in edge_with_created_at");
    assert_raw_edge_unchanged(
        vault,
        &fixture.edge,
        &before_out,
        "batch_in edge_with_created_at",
    )?;

    let err = vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .edge_with_created_at_and_vad(&src, kind, &tgt, 0.5, 2_003, vad)
                .apply(wtxn)
        })
        .expect_err("batch_in edge_with_created_at_and_vad must reject");
    assert_edge_is_provenanced_reject(err, kind, "batch_in edge_with_created_at_and_vad");
    assert_raw_edge_unchanged(
        vault,
        &fixture.edge,
        &before_out,
        "batch_in edge_with_created_at_and_vad",
    )?;

    let claim = vault
        .get_claim(&fixture.claim_id)?
        .expect("provenance claim readable");
    assert_eq!(claim.lifecycle, ClaimLifecycleStatus::Active);
    Ok(())
}

#[test]
fn public_timestamped_builder_accepts_over_bare_edge() -> Result<()> {
    let (dir, vault) = open_test_vault();
    let _dir = dir;
    let src = EntityId::now();
    let tgt = EntityId::now();
    let absent_tgt = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&src, ENTITY_TYPE_PERSON, occurred, 1, b"src")?;
    vault.put_entity(&tgt, ENTITY_TYPE_PERSON, occurred, 1, b"tgt")?;
    vault.put_entity(&absent_tgt, ENTITY_TYPE_PERSON, occurred, 1, b"absent")?;
    vault.put_edge(&src, EdgeKind::Mentions, &tgt, 0.25)?;

    let bare_edge = EdgeRef::new(src, EdgeKind::Mentions, tgt);
    vault
        .batch()
        .edge_with_created_at(&src, EdgeKind::Mentions, &tgt, 0.5, 2_000)
        .commit()?;
    let (bare_out, bare_in) = raw_edge_values(&vault, &bare_edge)?;
    let bare_out = bare_out.expect("bare edge");
    assert_eq!(bare_out.len(), EDGE_VALUE_SEMANTIC_LEN);
    assert_eq!(bare_in.as_deref(), Some(bare_out.as_slice()));

    let absent_edge = EdgeRef::new(src, EdgeKind::About, absent_tgt);
    vault
        .batch()
        .edge_with_created_at_and_vad(&src, EdgeKind::About, &absent_tgt, 0.5, 2_001, Vad::NEUTRAL)
        .commit()?;
    let (absent_out, absent_in) = raw_edge_values(&vault, &absent_edge)?;
    let absent_out = absent_out.expect("formerly absent edge");
    assert_eq!(absent_out.len(), EDGE_VALUE_SEMANTIC_LEN);
    assert_eq!(absent_in.as_deref(), Some(absent_out.as_slice()));
    Ok(())
}

#[test]
fn public_timestamped_builder_keeps_structural_edge_layout() -> Result<()> {
    let (dir, vault) = open_test_vault();
    let _dir = dir;
    let child = EntityId::now();
    let parent = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(
        &child,
        ENTITY_TYPE_TASK,
        occurred,
        1,
        &crate::types::task_body_for_test(crate::types::TaskRole::Task),
    )?;
    vault.put_entity(
        &parent,
        ENTITY_TYPE_TASK,
        occurred,
        1,
        &crate::types::task_body_for_test(crate::types::TaskRole::Task),
    )?;

    vault
        .batch()
        .edge_with_created_at(&child, EdgeKind::ChildOf, &parent, 0.5, 2_000)
        .commit()?;

    let edge = EdgeRef::new(child, EdgeKind::ChildOf, parent);
    let (out, inn) = raw_edge_values(&vault, &edge)?;
    let out = out.expect("structural edge");
    assert_eq!(out.len(), EDGE_VALUE_STRUCTURAL_LEN);
    assert_eq!(inn.as_deref(), Some(out.as_slice()));

    let err = vault
        .batch()
        .edge_with_created_at_and_vad(
            &child,
            EdgeKind::ChildOf,
            &parent,
            0.5,
            2_001,
            Vad {
                valence: 0.1,
                arousal: 0.2,
                dominance: 0.3,
            },
        )
        .commit()
        .expect_err("structural edge must reject VAD payload");
    assert!(
        matches!(
            err,
            Error::InvariantViolation("structural edges do not carry VAD")
        ),
        "expected structural VAD rejection, got {err:?}"
    );
    assert_raw_edge_unchanged(&vault, &edge, &out, "structural VAD rejection")?;
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn replay_edge_with_created_at_accepts_bare_over_provenanced() -> Result<()> {
    let fixture = provenanced_edge_fixture()?;
    let vault = &fixture.vault;
    let src = fixture.edge.source;
    let kind = fixture.edge.kind;
    let tgt = fixture.edge.target;
    let (before_out, _) = raw_edge_values(vault, &fixture.edge)?;
    assert_eq!(
        before_out.expect("provenanced edge").len(),
        EDGE_VALUE_SEMANTIC_PROVENANCED_LEN
    );

    vault.with_write_txn(|wtxn| {
        apply_ops(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            wtxn,
            vec![BatchOp::EdgeWithCreatedAt {
                src,
                kind,
                tgt,
                weight: 0.91,
                created_at: 3_000,
                vad: Vad::NEUTRAL,
                provenance: None,
            }],
            true,
            false,
            false,
        )
    })?;

    let (after_out, after_in) = raw_edge_values(vault, &fixture.edge)?;
    let after_out = after_out.expect("replayed edge");
    assert_eq!(after_out.len(), EDGE_VALUE_SEMANTIC_LEN);
    assert_eq!(after_in.as_deref(), Some(after_out.as_slice()));
    Ok(())
}

fn entity(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; ENTITY_ID_LEN]).expect("test entity id")
}

fn child_of_edge(child: EntityId, parent: EntityId) -> BatchOp {
    BatchOp::Edge {
        src: child,
        kind: EdgeKind::ChildOf,
        tgt: parent,
        weight: 1.0,
        vad: Vad::NEUTRAL,
    }
}

#[test]
fn child_of_overlay_orders_entity_clear_against_same_pair_edge() {
    let child = entity(0x41);
    let parent = entity(0x42);

    let edge_after_clear = ChildOfBatchOverlay::from_ops(&[
        BatchOp::Delete { id: child },
        child_of_edge(child, parent),
    ]);
    assert_eq!(
        edge_after_clear.final_edge_override(&child, &parent),
        Some(true),
        "a ChildOf edge re-added after clearing the child must win"
    );

    let clear_after_edge = ChildOfBatchOverlay::from_ops(&[
        child_of_edge(child, parent),
        BatchOp::Delete { id: child },
    ]);
    assert_eq!(
        clear_after_edge.final_edge_override(&child, &parent),
        Some(false),
        "clearing the child after touching the ChildOf pair must win"
    );
}
