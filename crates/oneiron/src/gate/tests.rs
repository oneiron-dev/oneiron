use super::*;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, ScopedReadActorKey,
    claim_body_decode_count, decode_claim_body, reset_claim_body_decode_count,
};
use crate::context_pack::ContextEntity;
use crate::context_pack::ContextPack;
use crate::context_pack::PackItemAccounting;
use crate::context_pack::PackStats;
use crate::context_pack::PackTokenStats;
use crate::counterparty_contact::{
    CounterpartyContactRecord, CounterpartyContactStatus, CounterpartyFirstTouch,
    CounterpartyOptOutReason,
};
use crate::edge::{EdgeActorClass, EdgeConfirmationStatus, EdgeKind, EdgeProvenanceFlags};
use crate::error::{ErrorKind, GateDenialOutcome, GateDenialReason};
use crate::pipeline::ScoredEntity;
use crate::provenance::{EdgeProvenanceClaimBody, EdgeRef, SupersessionStatus};
use crate::receipt::{ReceiptKind, ReceiptQuery, StandingOutboundGrantsLensQuery};
use crate::registry::{ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON};
use crate::temporal::TimeRange;
use crate::write_envelope::ClaimCandidate;
use crate::write_envelope::WriteActor;
use crate::write_envelope::WriteProvenance;
use std::time::Duration;

fn test_id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("valid test id")
}

fn test_time(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

fn temp_vault() -> (tempfile::TempDir, crate::Vault) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault =
        crate::Vault::open(tmp.path(), crate::config::VaultConfig::default()).expect("open vault");
    clear_policy_manifests_for_test(&vault);
    (tmp, vault)
}

fn clear_policy_manifests_for_test(vault: &crate::Vault) {
    vault
        .with_write_txn(|wtxn| {
            let mut ids = Vec::new();
            for row in vault
                .store
                .type_index
                .prefix_iter(wtxn, &[ENTITY_TYPE_POLICY_MANIFEST])?
            {
                let (key, _) = row?;
                let id = EntityId::from_bytes(
                    key[1..]
                        .try_into()
                        .map_err(|_| Error::CorruptedIndex("type index key"))?,
                )
                .map_err(|_| Error::CorruptedIndex("type index key"))?;
                ids.push(id);
            }
            for id in ids {
                crate::batch::deindex_entity_for_test(&vault.store, wtxn, &id)?;
            }
            Ok(())
        })
        .expect("clear default policy manifest");
}

#[test]
fn companion_profile_access_grants_allow_deny_and_revoke() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let grant_id = test_id(0xA1);
    let principal = test_id(0xB1);
    let other_principal = test_id(0xB3);
    let person = test_id(0xC1);
    let persona = test_id(0xD1);
    let other_persona = test_id(0xD2);

    assert_eq!(
        vault.companion_profile_access_grant(&principal, &person, &persona)?,
        None,
        "missing grant must fail closed"
    );

    let grant = crate::AccessGrant::companion_profile_read(principal, person, persona, 10);
    vault.create_access_grant(&grant_id, &grant)?;

    assert_eq!(
        vault.companion_profile_access_grant(&principal, &person, &persona)?,
        Some(grant_id),
        "exact active grant should authorize"
    );
    assert_eq!(
        vault.companion_profile_access_grant(&other_principal, &person, &persona)?,
        None,
        "principal mismatch must deny"
    );
    assert_eq!(
        vault.companion_profile_access_grant(&principal, &person, &other_persona)?,
        None,
        "scope mismatch must deny"
    );

    let revoked = vault.revoke_access_grant(&grant_id, 20)?;
    assert_eq!(revoked.status, crate::AccessGrantStatus::Revoked);
    assert_eq!(
        vault.companion_profile_access_grant(&principal, &person, &persona)?,
        None,
        "revoked grant must fail closed"
    );
    Ok(())
}

#[test]
fn companion_profile_access_grant_fails_closed_on_malformed_record() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let malformed_id = test_id(0x01);
    let valid_id = test_id(0xA2);
    let principal = test_id(0xB2);
    let person = test_id(0xC2);
    let persona = test_id(0xD3);

    put_malformed_access_grant_bytes(&vault, &malformed_id, b"not-msgpack")?;
    let grant = crate::AccessGrant::companion_profile_read(principal, person, persona, 10);
    vault.create_access_grant(&valid_id, &grant)?;

    let err = vault
        .companion_profile_access_grant(&principal, &person, &persona)
        .expect_err("malformed AccessGrant row must fail closed before any later allow");
    assert!(
        matches!(err, Error::CorruptedIndex("access grant body")),
        "expected CorruptedIndex for malformed AccessGrant row, got {err:?}"
    );
    Ok(())
}

fn encode_policy_manifest(extra_entries: Vec<(Value, Value)>) -> Vec<u8> {
    let mut entries = vec![
        (
            Value::from(POLICY_SCHEMA_VERSION_KEY),
            Value::from(POLICY_SCHEMA_VERSION),
        ),
        (Value::from(POLICY_PACK_ID_KEY), Value::from("gate-test")),
        (Value::from(POLICY_PACK_VERSION_KEY), Value::from("v1")),
        (
            Value::from(POLICY_MIN_ENGINE_VERSION_KEY),
            Value::from(env!("CARGO_PKG_VERSION")),
        ),
        (
            Value::from(POLICY_DEFAULTS_KEY),
            Value::Map(vec![
                (Value::from(AXIS_CRITICALITY_KEY), Value::from("normal")),
                (Value::from(AXIS_SENSITIVITY_KEY), Value::from("normal")),
            ]),
        ),
        (
            Value::from(POLICY_RULES_KEY),
            Value::Array(vec![Value::Map(vec![
                (Value::from(RULE_PREFIX_KEY), Value::from("health.")),
                (
                    Value::from(RULE_AXES_KEY),
                    Value::Map(vec![
                        (Value::from(AXIS_CRITICALITY_KEY), Value::from("critical")),
                        (Value::from(AXIS_SENSITIVITY_KEY), Value::from("sensitive")),
                    ]),
                ),
            ])]),
        ),
        (
            Value::from(POLICY_ACTOR_CEILINGS_KEY),
            Value::Array(vec![
                Value::Map(vec![
                    (Value::from(ACTOR_CLASS_KEY), Value::from("first_party")),
                    (Value::from(ACTOR_CEILING_KEY), Value::from("auto")),
                ]),
                Value::Map(vec![
                    (Value::from(ACTOR_CLASS_KEY), Value::from("first_party")),
                    (Value::from(ACTOR_REF_KEY), Value::from("probation")),
                    (Value::from(ACTOR_CEILING_KEY), Value::from("proposed")),
                ]),
            ]),
        ),
    ];
    entries.extend(extra_entries);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Value::Map(entries)).expect("manifest encode");
    out
}

fn encode_first_party_eiri_default_policy_manifest() -> Vec<u8> {
    default_policy_manifest()
}

fn rewrite_policy_manifest_entries(
    data: &mut Vec<u8>,
    rewrite: impl FnOnce(&mut Vec<(Value, Value)>),
) {
    let mut cursor = Cursor::new(data.as_slice());
    let Value::Map(mut entries) = rmpv::decode::read_value(&mut cursor).expect("decode") else {
        unreachable!("test manifest is a map");
    };
    rewrite(&mut entries);
    data.clear();
    rmpv::encode::write_value(data, &Value::Map(entries)).expect("re-encode");
}

fn source_trust_entry(source: ClaimSource, max_auto_sensitivity: u8) -> (Value, Value) {
    let row = Value::Map(vec![
        (
            Value::from(SOURCE_TRUST_MAX_AUTO_SENSITIVITY_KEY),
            Value::from(u64::from(max_auto_sensitivity)),
        ),
        (
            Value::from(SOURCE_TRUST_RECEIPTED_KEY),
            Value::Boolean(true),
        ),
        (Value::from(SOURCE_TRUST_WARNED_KEY), Value::Boolean(true)),
    ]);
    (
        Value::from(POLICY_SOURCE_TRUST_KEY),
        Value::Map(vec![(Value::from(source.as_str()), row)]),
    )
}

fn source_trust_entry_without_auto_permit(
    source: ClaimSource,
    max_auto_sensitivity: u8,
) -> (Value, Value) {
    (
        Value::from(POLICY_SOURCE_TRUST_KEY),
        Value::Map(vec![(
            Value::from(source.as_str()),
            Value::from(u64::from(max_auto_sensitivity)),
        )]),
    )
}

fn actor_ceiling_row(actor_class: &str, ceiling: &str) -> Value {
    Value::Map(vec![
        (Value::from(ACTOR_CLASS_KEY), Value::from(actor_class)),
        (Value::from(ACTOR_CEILING_KEY), Value::from(ceiling)),
    ])
}

fn actor_ceiling_row_for_ref(actor_class: &str, actor_ref: &str, ceiling: &str) -> Value {
    Value::Map(vec![
        (Value::from(ACTOR_CLASS_KEY), Value::from(actor_class)),
        (Value::from(ACTOR_REF_KEY), Value::from(actor_ref)),
        (Value::from(ACTOR_CEILING_KEY), Value::from(ceiling)),
    ])
}

fn replace_actor_ceilings(data: &mut Vec<u8>, rows: Vec<Value>) {
    rewrite_policy_manifest_entries(data, |entries| {
        for (key, value) in entries {
            if key.as_str() == Some(POLICY_ACTOR_CEILINGS_KEY) {
                *value = Value::Array(rows);
                return;
            }
        }
    });
}

fn append_actor_ceiling(data: &mut Vec<u8>, row: Value) {
    rewrite_policy_manifest_entries(data, |entries| {
        for (key, value) in entries {
            if key.as_str() == Some(POLICY_ACTOR_CEILINGS_KEY) {
                let Value::Array(rows) = value else {
                    unreachable!("actor ceilings are an array");
                };
                rows.push(row);
                return;
            }
        }
    });
}

fn trust_human_candidate_actor(data: &mut Vec<u8>) {
    append_actor_ceiling(data, actor_ceiling_row("human", "auto"));
}

fn scoped_grants_entry() -> (Value, Value) {
    (
        Value::from(POLICY_SCOPED_GRANTS_KEY),
        Value::Array(vec![Value::Map(vec![
            (Value::from(ACTOR_REF_KEY), Value::from("dreamer")),
            (Value::from(GRANT_EFFECTOR_KEY), Value::from("channel_send")),
            (
                Value::from(GRANT_SCOPE_KEY),
                Value::Map(vec![(Value::from("audience"), Value::from("cold"))]),
            ),
            (
                Value::from(GRANT_RECEIPT_REQUIRED_KEY),
                Value::Boolean(true),
            ),
        ])]),
    )
}

fn external_effect_scoped_grant_entry(
    actor_ref: &str,
    effector: &str,
    scope: Value,
    budget: Option<Value>,
) -> (Value, Value) {
    let mut row = vec![
        (Value::from(ACTOR_REF_KEY), Value::from(actor_ref)),
        (Value::from(GRANT_EFFECTOR_KEY), Value::from(effector)),
        (Value::from(GRANT_SCOPE_KEY), scope),
    ];
    if let Some(budget) = budget {
        row.push((Value::from(GRANT_BUDGET_KEY), budget));
    }
    (
        Value::from(POLICY_SCOPED_GRANTS_KEY),
        Value::Array(vec![Value::Map(row)]),
    )
}

fn signatures_entry() -> (Value, Value) {
    (
        Value::from(POLICY_SIGNATURES_KEY),
        Value::Array(vec![Value::Map(vec![
            (Value::from(SIGNATURE_ALG_KEY), Value::from("ed25519")),
            (Value::from(SIGNATURE_KEY_ID_KEY), Value::from("owner")),
            (
                Value::from(SIGNATURE_SIG_KEY),
                Value::from("first-party-eiri-auto"),
            ),
        ])]),
    )
}

fn policy_manifest_blob(data: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(crate::batch::ENTITY_METADATA_HEADER_LEN + data.len());
    payload.push(ENTITY_TYPE_POLICY_MANIFEST);
    payload.extend_from_slice(&1_u64.to_be_bytes());
    payload.extend_from_slice(&1_u64.to_be_bytes());
    payload.extend_from_slice(&1_u64.to_be_bytes());
    payload.extend_from_slice(data);
    payload
}

fn access_grant_blob(data: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(crate::batch::ENTITY_METADATA_HEADER_LEN + data.len());
    payload.push(ENTITY_TYPE_ACCESS_GRANT);
    payload.extend_from_slice(&1_u64.to_be_bytes());
    payload.extend_from_slice(&1_u64.to_be_bytes());
    payload.extend_from_slice(&1_u64.to_be_bytes());
    payload.extend_from_slice(data);
    payload
}

#[cfg(feature = "sync")]
fn authority_log_blob(data: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(crate::batch::ENTITY_METADATA_HEADER_LEN + data.len());
    payload.push(crate::registry::ENTITY_TYPE_AUTHORITY_LOG);
    payload.extend_from_slice(&1_u64.to_be_bytes());
    payload.extend_from_slice(&1_u64.to_be_bytes());
    payload.extend_from_slice(&1_u64.to_be_bytes());
    payload.extend_from_slice(data);
    payload
}

fn put_malformed_access_grant_bytes(
    vault: &crate::Vault,
    id: &EntityId,
    data: &[u8],
) -> Result<()> {
    let payload = access_grant_blob(data);

    vault.with_write_txn(|wtxn| {
        vault.store.entities.put(wtxn, id.as_bytes(), &payload)?;
        let type_key = Store::encode_type_key(ENTITY_TYPE_ACCESS_GRANT, id);
        vault.store.type_index.put(wtxn, &type_key, &[])?;
        Ok(())
    })
}

fn put_policy_manifest_bytes(vault: &crate::Vault, seed: u8, data: &[u8]) -> Result<()> {
    let id = test_id(seed);
    let payload = policy_manifest_blob(data);

    vault.with_write_txn(|wtxn| {
        vault.store.entities.put(wtxn, id.as_bytes(), &payload)?;
        let type_key = Store::encode_type_key(ENTITY_TYPE_POLICY_MANIFEST, &id);
        vault.store.type_index.put(wtxn, &type_key, &[])?;
        Ok(())
    })
}

fn resolve(vault: &crate::Vault) -> Result<PolicyManifestResolution> {
    let rtxn = vault.store.env.read_txn()?;
    resolve_policy_manifest(&vault.store, &rtxn)
}

#[test]
fn policy_manifest_budget_exhaustion_defaults_to_suspend() -> Result<()> {
    assert_eq!(
        PolicyManifestResolution::default().on_budget_exhausted(),
        BudgetExhaustionPolicy::Suspend
    );

    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, 0x81, &encode_policy_manifest(vec![]))?;

    let policy = resolve(&vault)?;
    assert_eq!(
        policy.on_budget_exhausted(),
        BudgetExhaustionPolicy::Suspend
    );
    Ok(())
}

#[test]
fn policy_manifest_budget_exhaustion_parses_continue_and_overdraft() -> Result<()> {
    let (_tmp, continue_vault) = temp_vault();
    let continue_manifest = encode_policy_manifest(vec![(
        Value::from(POLICY_ON_BUDGET_EXHAUSTED_KEY),
        Value::from("continue_on_local"),
    )]);
    put_policy_manifest_bytes(&continue_vault, 0x82, &continue_manifest)?;
    assert_eq!(
        resolve(&continue_vault)?.on_budget_exhausted(),
        BudgetExhaustionPolicy::ContinueOnLocal
    );

    let (_tmp, overdraft_vault) = temp_vault();
    let overdraft_manifest = encode_policy_manifest(vec![(
        Value::from(POLICY_ON_BUDGET_EXHAUSTED_KEY),
        Value::Map(vec![
            (Value::from("kind"), Value::from("overdraft")),
            (Value::from("cap"), Value::from(25_u64)),
        ]),
    )]);
    put_policy_manifest_bytes(&overdraft_vault, 0x83, &overdraft_manifest)?;
    assert_eq!(
        resolve(&overdraft_vault)?.on_budget_exhausted(),
        BudgetExhaustionPolicy::Overdraft { cap: 25 }
    );
    Ok(())
}

#[test]
fn conflicting_budget_exhaustion_policies_fail_closed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        0x84,
        &encode_policy_manifest(vec![(
            Value::from(POLICY_ON_BUDGET_EXHAUSTED_KEY),
            Value::from("continue_on_local"),
        )]),
    )?;
    put_policy_manifest_bytes(
        &vault,
        0x85,
        &encode_policy_manifest(vec![(
            Value::from(POLICY_ON_BUDGET_EXHAUSTED_KEY),
            Value::from("suspend"),
        )]),
    )?;

    let policy = resolve(&vault)?;
    assert!(policy.diagnostics().malformed_manifest_seen);
    assert!(policy.is_fail_closed());
    Ok(())
}

fn first_party_eiri_connector_actor_id() -> EntityId {
    EntityId::from_bytes(FIRST_PARTY_EIRI_CONNECTOR_ACTOR_ID)
        .expect("first-party Eiri actor fixture id")
}

fn first_party_eiri_connector_actor_ref() -> String {
    super::first_party_eiri_connector_actor_ref()
}

fn has_pending_gate_consent(vault: &crate::Vault, id: &EntityId) -> Result<bool> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(vault
        .store
        .pending_gate_consent_in_txn(&rtxn, id)?
        .is_some())
}

fn source_trust_claim(source: ClaimSource) -> ClaimBody {
    let mut body = ClaimBody::new(
        "profile.name",
        ClaimSubject::Entity(test_id(0x21)),
        Value::from("Ada"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.source = Some(source);
    body
}

fn core_read_scoped_grant_entry(actor_ref: &str, scope: Value) -> (Value, Value) {
    (
        Value::from(POLICY_SCOPED_GRANTS_KEY),
        Value::Array(vec![Value::Map(vec![
            (Value::from(ACTOR_REF_KEY), Value::from(actor_ref)),
            (
                Value::from(GRANT_EFFECTOR_KEY),
                Value::from(SCOPED_READ_EFFECTOR_CORE_READ),
            ),
            (Value::from(GRANT_SCOPE_KEY), scope),
            (
                Value::from(GRANT_RECEIPT_REQUIRED_KEY),
                Value::Boolean(false),
            ),
        ])]),
    )
}

fn receipt_required_core_read_scoped_grant_entry(actor_ref: &str, scope: Value) -> (Value, Value) {
    (
        Value::from(POLICY_SCOPED_GRANTS_KEY),
        Value::Array(vec![Value::Map(vec![
            (Value::from(ACTOR_REF_KEY), Value::from(actor_ref)),
            (
                Value::from(GRANT_EFFECTOR_KEY),
                Value::from(SCOPED_READ_EFFECTOR_CORE_READ),
            ),
            (Value::from(GRANT_SCOPE_KEY), scope),
        ])]),
    )
}

fn budgeted_core_read_scoped_grant_entry(actor_ref: &str, scope: Value) -> (Value, Value) {
    (
        Value::from(POLICY_SCOPED_GRANTS_KEY),
        Value::Array(vec![Value::Map(vec![
            (Value::from(ACTOR_REF_KEY), Value::from(actor_ref)),
            (
                Value::from(GRANT_EFFECTOR_KEY),
                Value::from(SCOPED_READ_EFFECTOR_CORE_READ),
            ),
            (Value::from(GRANT_SCOPE_KEY), scope),
            (
                Value::from(GRANT_RECEIPT_REQUIRED_KEY),
                Value::Boolean(false),
            ),
            (
                Value::from(GRANT_BUDGET_KEY),
                Value::Map(vec![(Value::from("limit"), Value::from(1_u64))]),
            ),
        ])]),
    )
}

fn core_read_world_grant_manifest(actor_ref: &str, world: EntityId) -> Vec<u8> {
    encode_policy_manifest(vec![core_read_scoped_grant_entry(
        actor_ref,
        Value::Map(vec![(
            Value::from("world_ref"),
            Value::from(world.to_hex()),
        )]),
    )])
}

fn put_claim_body(vault: &crate::Vault, id: &EntityId, body: &ClaimBody) -> Result<()> {
    let data = crate::claim::encode_claim_body(body)?;
    let mut payload = Vec::with_capacity(crate::batch::ENTITY_METADATA_HEADER_LEN + data.len());
    payload.push(crate::registry::ENTITY_TYPE_CLAIM);
    payload.extend_from_slice(&1_u64.to_be_bytes());
    payload.extend_from_slice(&1_u64.to_be_bytes());
    payload.extend_from_slice(&1_u64.to_be_bytes());
    payload.extend_from_slice(&data);

    vault.with_write_txn(|wtxn| {
        vault.store.entities.put(wtxn, id.as_bytes(), &payload)?;
        let type_key = Store::encode_type_key(crate::registry::ENTITY_TYPE_CLAIM, id);
        vault.store.type_index.put(wtxn, &type_key, &[])?;
        Ok(())
    })
}

fn put_claim_text_body(
    vault: &crate::Vault,
    id: &EntityId,
    text: &str,
    body: &ClaimBody,
) -> Result<()> {
    put_claim_body(vault, id, body)?;
    vault.batch().text(id, &[("body", text)]).commit()
}

fn put_text_entity(
    vault: &crate::Vault,
    id: &EntityId,
    entity_type: u8,
    text: &str,
    fields: serde_json::Value,
) -> Result<()> {
    let payload = rmp_serde::to_vec_named(&fields).expect("msgpack encode");
    vault
        .batch()
        .put(id, entity_type, test_time(1), 1, &payload)
        .text(id, &[("body", text)])
        .commit()
}

fn put_vector_entity(vault: &crate::Vault, id: &EntityId, vector: &[f32]) -> Result<()> {
    vault.put_entity(
        id,
        crate::registry::ENTITY_TYPE_PERSON,
        test_time(1),
        1,
        b"vector entity",
    )?;
    vault.put_vector(id, vector)
}

fn put_dangling_short_id(
    vault: &crate::Vault,
    short_id: &str,
    content_hash: u8,
    id: &EntityId,
) -> Result<()> {
    let key = crate::batch::encode_short_id_forward_key(short_id, content_hash);
    vault.with_write_txn(|wtxn| {
        vault.store.short_ids.put(wtxn, &key, id.as_bytes())?;
        Ok(())
    })
}

#[cfg(feature = "sync")]
fn source_trust_claim_data(source: ClaimSource) -> Vec<u8> {
    crate::claim::encode_claim_body(&source_trust_claim(source)).expect("claim encode")
}

#[cfg(feature = "sync")]
fn federated_claim_update(id: &EntityId, body: &ClaimBody) -> Result<Vec<u8>> {
    use crate::batch::ENTITY_METADATA_HEADER_LEN;
    use crate::sync::loro_support::{export_all_updates, map_insert_bytes};
    use crate::sync::schema::create_window_doc;
    use crate::sync::types::WindowKey;

    let data = crate::claim::encode_claim_body(body)?;
    let mut blob = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + data.len());
    blob.push(crate::registry::ENTITY_TYPE_CLAIM);
    blob.extend_from_slice(&5_u64.to_be_bytes());
    blob.extend_from_slice(&5_u64.to_be_bytes());
    blob.extend_from_slice(&5_u64.to_be_bytes());
    blob.extend_from_slice(&data);

    let key = WindowKey::new("2026-03");
    let doc = create_window_doc("federation-remote", &key);
    map_insert_bytes(&doc.get_map("entities"), &id.to_hex(), &blob)?;
    doc.commit();
    export_all_updates(&doc)
}

fn claim_candidate_from_body(body: &ClaimBody) -> ClaimCandidate {
    let mut candidate = ClaimCandidate::new(
        body.predicate.clone(),
        body.subject,
        body.value.clone(),
        body.confidence,
    )
    .with_validity(body.valid_from, body.valid_to)
    .with_stale(body.stale);
    if let Some(salience) = body.salience {
        candidate = candidate.with_salience(salience);
    }
    if let Some(evidence) = body.evidence.clone() {
        candidate = candidate.with_evidence(evidence);
    }
    if let Some(world) = body.world {
        candidate = candidate.with_world(world);
    }
    if let Some(scope) = body.scope.clone() {
        candidate = candidate.with_scope(scope);
    }
    candidate
}

#[test]
fn scoped_read_actor_key_rejects_unkeyed_bulk_bypass() {
    assert!(ScopedReadActorKey::new("").is_none());
    assert!(ScopedReadActorKey::new("   ").is_none());
    assert_eq!(
        ScopedReadActorKey::new(" reader ")
            .expect("trimmed actor key")
            .actor_ref(),
        "reader"
    );
}

#[test]
fn scoped_read_core_read_world_scope_contains_actor_readable_claims() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let world = test_id(0x31);
    let other_world = test_id(0x32);
    let data = encode_policy_manifest(vec![core_read_scoped_grant_entry(
        "reader",
        Value::Map(vec![(
            Value::from("world_ref"),
            Value::from(world.to_hex()),
        )]),
    )]);
    put_policy_manifest_bytes(&vault, 0x61, &data)?;
    let policy = resolve(&vault)?;
    let actor_key = ScopedReadActorKey::new("reader").expect("actor key");
    assert_eq!(policy.scoped_grants().len(), 1);
    assert_eq!(
        policy.scoped_grants()[0].actor_ref.as_deref(),
        Some("reader")
    );
    assert_eq!(
        policy.scoped_grants()[0].effector,
        SCOPED_READ_EFFECTOR_CORE_READ
    );
    assert!(scoped_read_entity_id_from_value(&Value::from(world.to_hex())).is_some());

    let base_id = test_id(0xA0);
    let allowed_id = test_id(0xA1);
    let denied_id = test_id(0xA2);

    let base = source_trust_claim(ClaimSource::UserStated);
    let mut allowed = source_trust_claim(ClaimSource::UserStated);
    allowed.world = Some(world);
    let mut denied = source_trust_claim(ClaimSource::UserStated);
    denied.world = Some(other_world);
    put_claim_body(&vault, &base_id, &base)?;
    put_claim_body(&vault, &allowed_id, &allowed)?;
    put_claim_body(&vault, &denied_id, &denied)?;

    assert!(scoped_read_claim_allowed(&policy, &actor_key, &base, &[]));
    assert!(scoped_read_claim_allowed(
        &policy,
        &actor_key,
        &allowed,
        &[]
    ));
    assert!(!scoped_read_claim_allowed(
        &policy,
        &actor_key,
        &denied,
        &[]
    ));

    let scoped_read = vault.scoped_read(actor_key);
    let ids: Vec<_> = scoped_read
        .filter_scored_entities(vec![
            ScoredEntity {
                id: base_id,
                score: 1.0,
            },
            ScoredEntity {
                id: allowed_id,
                score: 0.9,
            },
            ScoredEntity {
                id: denied_id,
                score: 0.8,
            },
        ])?
        .into_iter()
        .map(|result| result.id)
        .collect();
    assert_eq!(ids, vec![base_id, allowed_id]);

    let other_actor =
        vault.scoped_read(ScopedReadActorKey::new("other-reader").expect("actor key"));
    assert!(
        other_actor
            .filter_scored_entities(vec![ScoredEntity {
                id: allowed_id,
                score: 1.0,
            }])?
            .is_empty(),
        "a core:read grant for one actor must not create a vault-wide read lane"
    );

    Ok(())
}

#[test]
fn scoped_read_receipt_required_core_grants_fail_closed_without_receipt() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let world = test_id(0x33);
    let data = encode_policy_manifest(vec![receipt_required_core_read_scoped_grant_entry(
        "reader",
        Value::Map(vec![(
            Value::from("world_ref"),
            Value::from(world.to_hex()),
        )]),
    )]);
    put_policy_manifest_bytes(&vault, 0x6C, &data)?;

    let id = test_id(0x34);
    let mut body = source_trust_claim(ClaimSource::UserStated);
    body.world = Some(world);
    put_claim_body(&vault, &id, &body)?;

    let policy = resolve(&vault)?;
    assert_eq!(policy.scoped_grants().len(), 1);
    assert!(policy.scoped_grants()[0].receipt_required);
    let actor_key = ScopedReadActorKey::new("reader").expect("actor key");
    assert!(
        !scoped_read_claim_allowed(&policy, &actor_key, &body, &[]),
        "ScopedReadActorKey does not carry a consent receipt, so receipt-required grants must fail closed"
    );

    let scoped_read = vault.scoped_read(actor_key);
    assert!(scoped_read.get(&id)?.is_none());
    Ok(())
}

#[test]
fn scoped_read_budgeted_core_grants_fail_closed_without_budget_enforcer() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let world = test_id(0x3A);
    let data = encode_policy_manifest(vec![budgeted_core_read_scoped_grant_entry(
        "reader",
        Value::Map(vec![(
            Value::from("world_ref"),
            Value::from(world.to_hex()),
        )]),
    )]);
    put_policy_manifest_bytes(&vault, 0x3B, &data)?;

    let id = test_id(0x3C);
    let mut body = source_trust_claim(ClaimSource::UserStated);
    body.world = Some(world);
    put_claim_body(&vault, &id, &body)?;

    let policy = resolve(&vault)?;
    assert_eq!(policy.scoped_grants().len(), 1);
    assert!(policy.scoped_grants()[0].budget.is_some());
    let actor_key = ScopedReadActorKey::new("reader").expect("actor key");
    assert!(
        !scoped_read_claim_allowed(&policy, &actor_key, &body, &[]),
        "ScopedRead has no read-budget counter or receipt state, so budgeted grants must fail closed"
    );

    let scoped_read = vault.scoped_read(actor_key);
    assert!(scoped_read.get(&id)?.is_none());
    Ok(())
}

#[test]
fn scoped_read_without_core_grants_preserves_claim_surfaceable_gate() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, 0x62, &encode_policy_manifest(vec![]))?;

    let live_id = test_id(0xB0);
    let proposed_id = test_id(0xB1);
    let stale_id = test_id(0xB2);

    let live = source_trust_claim(ClaimSource::UserStated);
    let mut proposed = source_trust_claim(ClaimSource::UserStated);
    proposed.approval = ClaimApprovalStatus::Proposed;
    let mut stale = source_trust_claim(ClaimSource::UserStated);
    stale.stale = true;

    assert!(crate::claim::claim_surfaceable(&live));
    assert!(!crate::claim::claim_surfaceable(&proposed));
    assert!(!crate::claim::claim_surfaceable(&stale));

    put_claim_body(&vault, &live_id, &live)?;
    put_claim_body(&vault, &proposed_id, &proposed)?;
    put_claim_body(&vault, &stale_id, &stale)?;

    let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
    assert!(scoped_read.get(&live_id)?.is_some());
    assert!(scoped_read.get(&proposed_id)?.is_none());
    assert!(scoped_read.get(&stale_id)?.is_none());

    let visible: Vec<_> = scoped_read
        .filter_scored_entities(vec![
            ScoredEntity {
                id: live_id,
                score: 1.0,
            },
            ScoredEntity {
                id: proposed_id,
                score: 0.9,
            },
            ScoredEntity {
                id: stale_id,
                score: 0.8,
            },
        ])?
        .into_iter()
        .map(|result| result.id)
        .collect();
    assert_eq!(visible, vec![live_id]);
    Ok(())
}

#[test]
fn scoped_read_search_candidate_limit_is_not_widened_without_core_read_grants() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, 0x6D, &encode_policy_manifest(vec![]))?;
    for seed in 0x35..=0x38 {
        put_text_entity(
            &vault,
            &test_id(seed),
            crate::registry::ENTITY_TYPE_PERSON,
            "nowiden",
            serde_json::json!({"name": format!("person-{seed}")}),
        )?;
    }

    let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
    assert_eq!(scoped_read.search_candidate_limit(1, true, false)?, 1);
    Ok(())
}

#[test]
fn scoped_read_hybrid_candidate_limit_uses_text_vector_union() -> Result<()> {
    let _tmp = tempfile::tempdir().expect("temp dir");
    let mut config = crate::config::VaultConfig::device();
    config.dimensions = 4;
    config.embedding_model = Some("scoped-read-test-model".to_owned());
    let vault = crate::Vault::open(_tmp.path(), config)?;
    let world = test_id(0x39);
    put_policy_manifest_bytes(
        &vault,
        0x3D,
        &core_read_world_grant_manifest("reader", world),
    )?;
    for seed in [0x3E, 0x3F] {
        put_text_entity(
            &vault,
            &test_id(seed),
            crate::registry::ENTITY_TYPE_PERSON,
            "hybrid-union",
            serde_json::json!({"name": format!("text-{seed}")}),
        )?;
    }
    for (seed, vector) in [
        (0x40, [1.0_f32, 0.0, 0.0, 0.0]),
        (0x41, [0.0_f32, 1.0, 0.0, 0.0]),
        (0x42, [0.0_f32, 0.0, 1.0, 0.0]),
    ] {
        put_vector_entity(&vault, &test_id(seed), &vector)?;
    }

    let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
    assert_eq!(scoped_read.search_candidate_limit(1, true, false)?, 2);
    assert_eq!(scoped_read.search_candidate_limit(1, false, true)?, 3);
    assert_eq!(
        scoped_read.search_candidate_limit(1, true, true)?,
        5,
        "hybrid scoped search must fetch the possible text/vector union before actor filtering"
    );
    Ok(())
}

#[test]
fn scoped_read_core_grant_preserves_claim_surfaceable_gate() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let world = test_id(0xC0);
    put_policy_manifest_bytes(
        &vault,
        0x63,
        &core_read_world_grant_manifest("reader", world),
    )?;

    let live_id = test_id(0xC1);
    let proposed_id = test_id(0xC2);
    let mut live = source_trust_claim(ClaimSource::UserStated);
    live.world = Some(world);
    let mut proposed = source_trust_claim(ClaimSource::UserStated);
    proposed.world = Some(world);
    proposed.approval = ClaimApprovalStatus::Proposed;
    put_claim_body(&vault, &live_id, &live)?;
    put_claim_body(&vault, &proposed_id, &proposed)?;

    let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
    assert!(scoped_read.get(&live_id)?.is_some());
    assert!(
        scoped_read.get(&proposed_id)?.is_none(),
        "matching scoped grant must still preserve claim_surfaceable"
    );
    let visible: Vec<_> = scoped_read
        .filter_scored_entities(vec![
            ScoredEntity {
                id: proposed_id,
                score: 1.0,
            },
            ScoredEntity {
                id: live_id,
                score: 0.9,
            },
        ])?
        .into_iter()
        .map(|result| result.id)
        .collect();
    assert_eq!(visible, vec![live_id]);
    Ok(())
}

#[test]
fn scoped_read_search_filters_before_limit_truncation() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let allowed_world = test_id(0xC3);
    let denied_world = test_id(0xC4);
    put_policy_manifest_bytes(
        &vault,
        0x64,
        &core_read_world_grant_manifest("reader", allowed_world),
    )?;

    let denied_ids = [
        test_id(0xC5),
        test_id(0xC6),
        test_id(0xC7),
        test_id(0xC8),
        test_id(0xC9),
    ];
    for (index, id) in denied_ids.iter().enumerate() {
        let mut body = source_trust_claim(ClaimSource::UserStated);
        body.world = Some(denied_world);
        let text = std::iter::repeat_n("scopedslots", 10 - index)
            .collect::<Vec<_>>()
            .join(" ");
        put_claim_text_body(&vault, id, &text, &body)?;
    }

    let allowed_id = test_id(0xCA);
    let mut allowed = source_trust_claim(ClaimSource::UserStated);
    allowed.world = Some(allowed_world);
    put_claim_text_body(&vault, &allowed_id, "scopedslots", &allowed)?;

    let unscoped_top = vault.search_text("scopedslots", denied_ids.len())?;
    assert!(
        !unscoped_top.iter().any(|hit| hit.id == allowed_id),
        "test setup must place denied hits ahead of the allowed claim"
    );

    let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
    let visible: Vec<_> = scoped_read
        .search_text("scopedslots", 1)?
        .into_iter()
        .map(|hit| hit.id)
        .collect();
    assert_eq!(visible, vec![allowed_id]);
    Ok(())
}

#[test]
fn scoped_read_hydrate_preserves_dangling_short_id_result() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, 0x65, &encode_policy_manifest(vec![]))?;

    let missing_id = test_id(0xCB);
    put_dangling_short_id(&vault, "cldangling", 0x5A, &missing_id)?;

    let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
    let hydrated = scoped_read
        .hydrate_short_id("cldangling", 0x5A)?
        .expect("dangling short id should surface deletion metadata");
    assert_eq!(hydrated.id, missing_id);
    assert!(hydrated.body.is_none());
    assert_eq!(
        hydrated
            .deletion
            .expect("dangling short id deletion")
            .source,
        crate::types::HydratedShortIdDeletionSource::DanglingShortId
    );
    Ok(())
}

#[test]
fn scoped_read_hydrate_preserves_deleted_claim_short_id_metadata() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, 0x6F, &encode_policy_manifest(vec![]))?;

    let claim_id = test_id(0xD0);
    put_claim_body(
        &vault,
        &claim_id,
        &source_trust_claim(ClaimSource::UserStated),
    )?;
    let short_id = "cldeleted";
    let content_hash = 0x5B;
    put_dangling_short_id(&vault, short_id, content_hash, &claim_id)?;

    let outcome =
        vault.delete_entity_with_reason(&claim_id, crate::deletion::DeleteReason::UserDelete)?;
    assert!(outcome.existed);

    let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
    let hydrated = scoped_read
        .hydrate_short_id(short_id, content_hash)?
        .expect("deleted claim short id should preserve deletion metadata");
    assert_eq!(hydrated.id, claim_id);
    assert_eq!(hydrated.entity_type, crate::registry::ENTITY_TYPE_CLAIM);
    assert!(hydrated.body.is_none());
    let deletion = hydrated.deletion.expect("deleted claim metadata");
    assert!(matches!(
        deletion.source,
        crate::types::HydratedShortIdDeletionSource::Tombstone
            | crate::types::HydratedShortIdDeletionSource::PendingTombstone
    ));
    assert_eq!(
        deletion.reason,
        Some(crate::types::HydratedShortIdDeletionReason::UserDelete)
    );
    assert!(!deletion.hard);
    Ok(())
}

#[test]
fn scoped_read_context_pack_scrubs_edges_to_denied_claims() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let allowed_world = test_id(0xCC);
    let denied_world = test_id(0xCD);
    put_policy_manifest_bytes(
        &vault,
        0x66,
        &core_read_world_grant_manifest("reader", allowed_world),
    )?;

    let source = test_id(0xCE);
    let denied_claim = test_id(0xCF);
    let claim_subject = test_id(0x21);
    put_text_entity(
        &vault,
        &source,
        crate::registry::ENTITY_TYPE_TURN,
        "edgevisible",
        serde_json::json!({"text": "edgevisible"}),
    )?;
    put_text_entity(
        &vault,
        &claim_subject,
        crate::registry::ENTITY_TYPE_PERSON,
        "claim subject",
        serde_json::json!({"name": "subject"}),
    )?;
    let mut denied = source_trust_claim(ClaimSource::UserStated);
    denied.world = Some(denied_world);
    put_claim_body(&vault, &denied_claim, &denied)?;
    vault.put_edge(&source, EdgeKind::Supports, &denied_claim, 0.7)?;

    let mut pack = vault
        .context_pack()
        .search_text("edgevisible", 10)
        .include_edges(true)
        .run()?;
    assert!(
        pack.results
            .iter()
            .flat_map(|entity| entity.edges.iter().flatten())
            .any(|edge| edge.target == denied_claim),
        "test setup should hydrate the denied target edge before scoped filtering"
    );

    let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
    scoped_read.filter_context_pack(&mut pack)?;
    let leaked = pack
        .results
        .iter()
        .chain(pack.neighbors.iter())
        .flat_map(|entity| entity.edges.iter().flatten())
        .any(|edge| edge.target == denied_claim);
    assert!(
        !leaked,
        "scoped context-pack edges must not reveal denied claims"
    );
    Ok(())
}

#[test]
fn scoped_read_context_pack_drops_neighbors_reached_only_from_filtered_results() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let facet = test_id(0x6E);
    put_policy_manifest_bytes(
        &vault,
        0x70,
        &encode_policy_manifest(vec![core_read_scoped_grant_entry(
            "reader",
            Value::Map(vec![(Value::from("facet"), Value::from(facet.to_hex()))]),
        )]),
    )?;

    let denied_seed = test_id(0x71);
    let readable_neighbor = test_id(0x72);
    put_text_entity(
        &vault,
        &facet,
        crate::registry::ENTITY_TYPE_FACET,
        "facet",
        serde_json::json!({"name": "facet"}),
    )?;
    put_text_entity(
        &vault,
        &test_id(0x21),
        crate::registry::ENTITY_TYPE_PERSON,
        "claim subject",
        serde_json::json!({"name": "subject"}),
    )?;
    let denied = source_trust_claim(ClaimSource::UserStated);
    put_claim_text_body(&vault, &denied_seed, "neighborleak", &denied)?;
    put_text_entity(
        &vault,
        &readable_neighbor,
        crate::registry::ENTITY_TYPE_PERSON,
        "neighbor target",
        serde_json::json!({"name": "neighbor"}),
    )?;
    vault.put_edge(&denied_seed, EdgeKind::Mentions, &readable_neighbor, 0.9)?;

    let mut pack = vault
        .context_pack()
        .search_text("neighborleak", 10)
        .edge_hop(1)
        .max_neighbors(10)
        .run()?;
    assert!(
        pack.results.iter().any(|entity| entity.id == denied_seed),
        "test setup should surface the denied primary result before scoped filtering"
    );
    assert!(
        pack.neighbors
            .iter()
            .any(|entity| entity.id == readable_neighbor),
        "test setup should expand to the readable neighbor before scoped filtering"
    );

    let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
    scoped_read.filter_context_pack(&mut pack)?;
    assert!(
        pack.results.is_empty(),
        "the denied primary seed should be removed"
    );
    assert!(
        pack.neighbors.is_empty(),
        "neighbors reached only through a denied primary seed must not remain visible"
    );
    Ok(())
}

#[test]
fn scoped_read_context_pack_retains_neighbors_reached_from_kept_results_without_edges() -> Result<()>
{
    let (_tmp, vault) = temp_vault();
    let allowed_world = test_id(0x73);
    let denied_world = test_id(0x74);
    put_policy_manifest_bytes(
        &vault,
        0x75,
        &core_read_world_grant_manifest("reader", allowed_world),
    )?;

    let kept_seed = test_id(0x76);
    let denied_seed = test_id(0x77);
    let readable_neighbor = test_id(0x78);
    put_text_entity(
        &vault,
        &kept_seed,
        crate::registry::ENTITY_TYPE_TURN,
        "kept seed",
        serde_json::json!({"text": "kept seed"}),
    )?;
    put_text_entity(
        &vault,
        &readable_neighbor,
        crate::registry::ENTITY_TYPE_PERSON,
        "readable neighbor",
        serde_json::json!({"name": "readable neighbor"}),
    )?;
    let mut denied = source_trust_claim(ClaimSource::UserStated);
    denied.world = Some(denied_world);
    put_claim_body(&vault, &denied_seed, &denied)?;
    vault.put_edge(&kept_seed, EdgeKind::Mentions, &readable_neighbor, 0.9)?;

    let entity = |id: EntityId, entity_type: u8, score: f32| ContextEntity {
        id,
        short_id: id.to_hex(),
        content_hash: 0,
        entity_type,
        score,
        fields: None,
        edges: None,
        vector: None,
    };
    let mut pack = ContextPack {
        results: vec![
            entity(kept_seed, crate::registry::ENTITY_TYPE_TURN, 1.0),
            entity(denied_seed, crate::registry::ENTITY_TYPE_CLAIM, 0.9),
        ],
        neighbors: vec![entity(
            readable_neighbor,
            crate::registry::ENTITY_TYPE_PERSON,
            0.0,
        )],
        stats: PackStats {
            candidates_considered: 2,
            signals_used: Vec::new(),
            query_time_us: 0,
            entities_hydrated: 2,
            neighbors_hydrated: 1,
            cosine_ghosts_dampened: 0,
            claims_suppressed: 0,
            tokens: PackTokenStats::default(),
            items_truncated: PackItemAccounting::item_budget(),
            items_dropped: PackItemAccounting::token_budget(),
        },
        empty: None,
    };

    let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
    scoped_read.filter_context_pack(&mut pack)?;
    assert_eq!(
        pack.results
            .iter()
            .map(|entity| entity.id)
            .collect::<Vec<_>>(),
        vec![kept_seed]
    );
    assert_eq!(
        pack.neighbors
            .iter()
            .map(|entity| entity.id)
            .collect::<Vec<_>>(),
        vec![readable_neighbor],
        "omitted serialized edges must not cause readable neighbors from kept seeds to be pruned"
    );
    Ok(())
}

#[test]
fn scoped_read_context_pack_filters_before_response_limit() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let facet = test_id(0xE1);
    put_policy_manifest_bytes(
        &vault,
        0x6B,
        &encode_policy_manifest(vec![core_read_scoped_grant_entry(
            "reader",
            Value::Map(vec![(Value::from("facet"), Value::from(facet.to_hex()))]),
        )]),
    )?;
    put_text_entity(
        &vault,
        &test_id(0x21),
        crate::registry::ENTITY_TYPE_PERSON,
        "claim subject",
        serde_json::json!({"name": "subject"}),
    )?;
    put_text_entity(
        &vault,
        &facet,
        crate::registry::ENTITY_TYPE_FACET,
        "facet",
        serde_json::json!({"name": "facet"}),
    )?;

    let denied_ids = [test_id(0xE3), test_id(0xE4), test_id(0xE5), test_id(0xE6)];
    for (index, id) in denied_ids.iter().enumerate() {
        let body = source_trust_claim(ClaimSource::UserStated);
        let text = std::iter::repeat_n("packslots", 8 - index)
            .collect::<Vec<_>>()
            .join(" ");
        put_claim_text_body(&vault, id, &text, &body)?;
    }

    let allowed_id = test_id(0xE7);
    let allowed = source_trust_claim(ClaimSource::UserStated);
    put_claim_text_body(&vault, &allowed_id, "packslots", &allowed)?;
    vault.put_edge(&allowed_id, EdgeKind::FacetOf, &facet, 0.7)?;

    let unscoped_top = vault
        .context_pack()
        .limit(denied_ids.len())
        .search_text("packslots", denied_ids.len())
        .run()?;
    assert!(
        !unscoped_top
            .results
            .iter()
            .any(|entity| entity.id == allowed_id),
        "test setup must place denied pack results ahead of the allowed claim"
    );

    let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
    let candidate_limit = scoped_read.search_candidate_limit(1, true, false)?;
    let mut pack = vault
        .context_pack()
        .limit(candidate_limit)
        .retrieval_budget(crate::context_pack::ContextPackRetrievalBudget::new(
            candidate_limit,
            candidate_limit,
            candidate_limit,
            candidate_limit,
            candidate_limit,
            crate::context_pack::DEFAULT_MAX_NEIGHBORS,
        ))
        .search_text("packslots", candidate_limit)
        .run()?;
    scoped_read.filter_context_pack(&mut pack)?;
    pack.results.truncate(1);
    assert_eq!(pack.results.len(), 1);
    assert_eq!(pack.results[0].id, allowed_id);
    Ok(())
}

#[test]
fn scoped_read_memory_timeline_prunes_links_to_filtered_records() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let allowed_world = test_id(0xD0);
    let denied_world = test_id(0xD1);
    put_policy_manifest_bytes(
        &vault,
        0x67,
        &core_read_world_grant_manifest("reader", allowed_world),
    )?;

    let old = test_id(0xD2);
    let new = test_id(0xD3);
    let mut denied = source_trust_claim(ClaimSource::UserStated);
    denied.world = Some(denied_world);
    let mut allowed = source_trust_claim(ClaimSource::UserStated);
    allowed.world = Some(allowed_world);
    put_claim_body(&vault, &old, &denied)?;
    put_claim_body(&vault, &new, &allowed)?;
    vault.put_edge(&new, EdgeKind::Supersedes, &old, 0.3)?;

    let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
    let timeline = scoped_read.memory_timeline(&new)?;
    assert_eq!(timeline.records.len(), 1);
    let record = &timeline.records[0];
    assert_eq!(record.id, new);
    assert!(record.supersedes.is_empty());
    assert!(record.superseded_by.is_empty());
    Ok(())
}

#[test]
fn scoped_read_memory_timeline_rejects_unreadable_anchor() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let allowed_world = test_id(0xD7);
    let denied_world = test_id(0xD8);
    put_policy_manifest_bytes(
        &vault,
        0x69,
        &core_read_world_grant_manifest("reader", allowed_world),
    )?;

    let old = test_id(0xD9);
    let denied_anchor = test_id(0xDA);
    let mut allowed = source_trust_claim(ClaimSource::UserStated);
    allowed.world = Some(allowed_world);
    let mut denied = source_trust_claim(ClaimSource::UserStated);
    denied.world = Some(denied_world);
    put_claim_body(&vault, &old, &allowed)?;
    put_claim_body(&vault, &denied_anchor, &denied)?;
    vault.put_edge(&denied_anchor, EdgeKind::Supersedes, &old, 0.3)?;

    let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
    let timeline = scoped_read.memory_timeline(&denied_anchor)?;
    assert!(
        timeline.records.is_empty(),
        "unreadable anchors must not reveal readable chain neighbors"
    );
    Ok(())
}

#[test]
fn scoped_read_edges_out_scrubs_denied_sources_and_targets() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let allowed_world = test_id(0xDB);
    let denied_world = test_id(0xDC);
    put_policy_manifest_bytes(
        &vault,
        0x6A,
        &core_read_world_grant_manifest("reader", allowed_world),
    )?;

    let source = test_id(0xDD);
    let allowed_claim = test_id(0xDE);
    let denied_claim = test_id(0xDF);
    put_text_entity(
        &vault,
        &source,
        crate::registry::ENTITY_TYPE_TURN,
        "source",
        serde_json::json!({"text": "source"}),
    )?;
    let mut allowed = source_trust_claim(ClaimSource::UserStated);
    allowed.world = Some(allowed_world);
    let mut denied = source_trust_claim(ClaimSource::UserStated);
    denied.world = Some(denied_world);
    put_claim_body(&vault, &allowed_claim, &allowed)?;
    put_claim_body(&vault, &denied_claim, &denied)?;
    vault.put_edge(&source, EdgeKind::Supports, &allowed_claim, 0.7)?;
    vault.put_edge(&source, EdgeKind::Opposes, &denied_claim, 0.7)?;

    let denied_source = test_id(0xE0);
    put_claim_body(&vault, &denied_source, &denied)?;
    vault.put_edge(&denied_source, EdgeKind::Supports, &allowed_claim, 0.7)?;

    let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
    let edges = scoped_read
        .edges_out(&source)?
        .expect("readable source should return scoped edges");
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].target, allowed_claim);
    assert!(
        scoped_read.edges_out(&denied_source)?.is_none(),
        "denied edge sources must not reveal outgoing relationships"
    );
    Ok(())
}

#[test]
fn scoped_read_facet_grants_match_facet_of_edges() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let facet = test_id(0xD4);
    put_policy_manifest_bytes(
        &vault,
        0x68,
        &encode_policy_manifest(vec![core_read_scoped_grant_entry(
            "reader",
            Value::Map(vec![(Value::from("facet"), Value::from(facet.to_hex()))]),
        )]),
    )?;
    put_text_entity(
        &vault,
        &facet,
        crate::registry::ENTITY_TYPE_FACET,
        "facet",
        serde_json::json!({"name": "facet"}),
    )?;

    let faceted_claim = test_id(0xD5);
    let unfaceted_claim = test_id(0xD6);
    let body = source_trust_claim(ClaimSource::UserStated);
    put_claim_body(&vault, &faceted_claim, &body)?;
    put_claim_body(&vault, &unfaceted_claim, &body)?;
    vault.put_edge(&faceted_claim, EdgeKind::FacetOf, &facet, 0.7)?;

    let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
    assert!(
        scoped_read.get(&faceted_claim)?.is_some(),
        "facet grant must match the claim's outgoing FacetOf edge"
    );
    assert!(
        scoped_read.get(&unfaceted_claim)?.is_none(),
        "facet grant must not fall through to unfaceted claims"
    );
    Ok(())
}

fn claim_candidate_write_parts(
    vault: &crate::Vault,
    body: &ClaimBody,
) -> Result<(ClaimCandidate, WriteEnvelope)> {
    let actor = test_id(0x20);
    claim_candidate_write_parts_for_actor(vault, body, actor, EdgeActorClass::Human)
}

fn claim_candidate_write_parts_for_actor(
    vault: &crate::Vault,
    body: &ClaimBody,
    actor: EntityId,
    actor_class: EdgeActorClass,
) -> Result<(ClaimCandidate, WriteEnvelope)> {
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, test_time(1), 1, b"gate actor")?;
    if let ClaimSubject::Entity(subject) = body.subject {
        vault.put_entity(
            &subject,
            ENTITY_TYPE_PERSON,
            test_time(1),
            1,
            b"gate subject",
        )?;
    }
    let source = body.source.unwrap_or(ClaimSource::UserStated);
    let envelope = WriteEnvelope::new(
        WriteActor::new(actor, actor_class),
        source,
        WriteProvenance::new(Value::from("gate-test"))?,
        body.approval,
    );
    Ok((claim_candidate_from_body(body), envelope))
}

fn dreamer_claim_candidate_write_parts(
    vault: &crate::Vault,
    body: &ClaimBody,
    actor: EntityId,
    run_id: &str,
) -> Result<(ClaimCandidate, WriteEnvelope)> {
    vault.put_entity(
        &actor,
        ENTITY_TYPE_PERSON,
        test_time(1),
        1,
        b"dreamer actor",
    )?;
    if let ClaimSubject::Entity(subject) = body.subject {
        vault.put_entity(
            &subject,
            ENTITY_TYPE_PERSON,
            test_time(1),
            1,
            b"dreamer subject",
        )?;
    }
    let envelope = WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Agent),
        ClaimSource::Generated,
        WriteProvenance::new(Value::Map(vec![
            (
                Value::from(DREAMER_PROVENANCE_RUNNER_KEY),
                Value::from(DREAMER_RUNNER_JOB_KIND),
            ),
            (
                Value::from(DREAMER_PROVENANCE_RUN_ID_KEY),
                Value::from(run_id),
            ),
        ]))?,
        body.approval,
    );
    Ok((claim_candidate_from_body(body), envelope))
}

fn gate_evaluator_input(
    actor_class: &str,
    actor_ref: Option<&str>,
    source: ClaimSource,
    criticality: PolicyCriticality,
) -> GateEvaluatorInput {
    GateEvaluatorInput {
        actor: GateActor {
            actor_class: actor_class.to_owned(),
            actor_ref: actor_ref.map(str::to_owned),
        },
        source: Some(source),
        content_kind: GateContentKind::Claim,
        sensitivity_band: Some(0),
        criticality,
        policy_manifest_version: POLICY_SCHEMA_VERSION.to_owned(),
        provenance: GateProvenanceHandles {
            actor_entity_ref: Some(test_id(0xA0)),
            substrate_ref: Some(test_id(0xA1)),
            source_revision_ref: Some([0xA2; ENTITY_ID_LEN]),
            body_snapshot_ref: Some([0xA3; ENTITY_ID_LEN]),
            ..GateProvenanceHandles::default()
        },
        external_effect: None,
    }
}

fn external_effect_gate_input(
    actor_ref: &str,
    verb: &str,
    channel: &str,
) -> ExternalEffectGateInput {
    ExternalEffectGateInput {
        actor: GateActor {
            actor_class: "first_party".to_owned(),
            actor_ref: Some(actor_ref.to_owned()),
        },
        provenance: GateProvenanceHandles {
            actor_entity_ref: Some(test_id(0xE0)),
            ..GateProvenanceHandles::default()
        },
        verb: verb.to_owned(),
        channel: channel.to_owned(),
        channel_identity_ref: None,
        counterparty: None,
        brief_ref: None,
        send_ref: None,
        standing_grant_ref: None,
        counterparty_first_touch: None,
        counterparty_opted_out: false,
        counterparty_opt_out_receipt_reason: None,
        has_opted_in: true,
        has_permission: true,
        policy_risk: ExternalEffectPolicyRisk::Normal,
    }
}

fn gate_reason_strs(decision: &GateDecision) -> Vec<&'static str> {
    decision
        .reason_codes()
        .iter()
        .map(|code| code.as_str())
        .collect()
}

fn assert_auto_source_rejected(vault: &crate::Vault, seed: u8, source: ClaimSource) -> Result<()> {
    let id = test_id(seed);
    let body = source_trust_claim(source);
    let (candidate, envelope) = claim_candidate_write_parts(vault, &body)?;
    let err = vault
        .batch()
        .claim_candidate(&id, candidate, &envelope, test_time(6), 6)
        .commit()
        .expect_err("manifest must reject risky auto source");
    assert!(
        matches!(err, Error::SourceNotTrustedForAuto { claim_source: got } if got == source.as_str()),
        "expected source trust error for {}, got {err:?}",
        source.as_str()
    );
    assert!(vault.get_raw(&id)?.is_none());
    Ok(())
}

fn assert_auto_source_gate_rejected(
    vault: &crate::Vault,
    seed: u8,
    source: ClaimSource,
    outcome: &'static str,
    reason_codes: &[&'static str],
) -> Result<()> {
    let id = test_id(seed);
    let body = source_trust_claim(source);
    let (candidate, envelope) = claim_candidate_write_parts(vault, &body)?;
    let err = vault
        .batch()
        .claim_candidate(&id, candidate, &envelope, test_time(6), 6)
        .commit()
        .expect_err("active policy write gate must reject risky auto source");
    assert_gate_rejected(err, outcome, reason_codes);
    assert!(vault.get_raw(&id)?.is_none());
    Ok(())
}

fn assert_gate_rejected(err: Error, outcome: &'static str, reason_codes: &[&'static str]) {
    let typed = err
        .gate_denial()
        .expect("GateWriteRejected must expose typed denial taxonomy");
    assert_eq!(typed.outcome().as_str(), outcome);
    let typed_reason_codes = typed
        .reason_codes()
        .iter()
        .map(|reason| reason.as_str())
        .collect::<Vec<_>>();
    assert_eq!(typed_reason_codes, reason_codes);

    match err {
        Error::GateWriteRejected {
            outcome: got_outcome,
            reason_codes: got_reasons,
        } => {
            assert_eq!(got_outcome, outcome);
            assert_eq!(got_reasons, reason_codes);
        }
        other => panic!("expected GateWriteRejected, got {other:?}"),
    }
}

fn assert_metric_counter_advanced(
    before: &GateMetricsSnapshot,
    after: &GateMetricsSnapshot,
    outcome: GateOutcome,
    reason_class: GateMetricReasonClass,
    delta: u64,
) {
    let before_count = before.count(outcome, reason_class);
    let after_count = after.count(outcome, reason_class);
    assert!(
        after_count >= before_count + delta,
        "expected metric {}/{} to advance by at least {delta}; before={before_count}, after={after_count}",
        outcome.as_str(),
        reason_class.as_str()
    );
}

#[test]
fn min_of_two_caps() {
    for (confirmed_scope, introducer_ceiling, expected) in [
        (
            PolicyApprovalCeiling::Auto,
            PolicyApprovalCeiling::Auto,
            PolicyApprovalCeiling::Auto,
        ),
        (
            PolicyApprovalCeiling::Auto,
            PolicyApprovalCeiling::Proposed,
            PolicyApprovalCeiling::Proposed,
        ),
        (
            PolicyApprovalCeiling::Proposed,
            PolicyApprovalCeiling::Auto,
            PolicyApprovalCeiling::Proposed,
        ),
        (
            PolicyApprovalCeiling::Proposed,
            PolicyApprovalCeiling::Proposed,
            PolicyApprovalCeiling::Proposed,
        ),
    ] {
        assert_eq!(
            foreign_agent_effective_ceiling(confirmed_scope, introducer_ceiling),
            expected
        );
    }
}

#[test]
fn introducer_lower_wins() {
    assert_eq!(
        foreign_agent_effective_ceiling(
            PolicyApprovalCeiling::Auto,
            PolicyApprovalCeiling::Proposed,
        ),
        PolicyApprovalCeiling::Proposed
    );
}

#[test]
fn widen_on_request_path() {
    let capped = foreign_agent_effective_ceiling(
        PolicyApprovalCeiling::Auto,
        PolicyApprovalCeiling::Proposed,
    );

    assert_eq!(
        foreign_agent_ceiling_after_widen_request(
            capped,
            PolicyApprovalCeiling::Auto,
            &GateDecision::pending(vec![GateReasonCode::PendingActorCeiling]),
        ),
        PolicyApprovalCeiling::Proposed
    );
    assert_eq!(
        foreign_agent_ceiling_after_widen_request(
            capped,
            PolicyApprovalCeiling::Auto,
            &GateDecision::allow(),
        ),
        PolicyApprovalCeiling::Auto
    );
}

fn stored_claim_body(vault: &crate::Vault, id: &EntityId) -> Result<ClaimBody> {
    let raw = vault.get_raw(id)?.ok_or(Error::EntityNotFound)?;
    decode_claim_body(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..], true)
}

fn edge_provenance_flags(
    vault: &crate::Vault,
    source: &EntityId,
    kind: EdgeKind,
    target: &EntityId,
) -> Result<EdgeProvenanceFlags> {
    let edge = vault
        .edges_out(source)?
        .into_iter()
        .find(|edge| edge.kind == kind && edge.target == *target)
        .ok_or(Error::EdgeNotFound)?;
    edge.provenance.ok_or(Error::InvariantViolation(
        "test edge should carry provenance flags",
    ))
}

#[test]
fn gate_metrics_snapshot_has_stable_privacy_preserving_labels() {
    let snapshot = gate_metrics_snapshot();
    assert_eq!(
        snapshot.counters().len(),
        GATE_METRIC_OUTCOME_COUNT * GATE_METRIC_REASON_CLASS_COUNT
    );

    let labels = snapshot
        .counters()
        .iter()
        .map(|counter| (counter.outcome().as_str(), counter.reason_class().as_str()))
        .collect::<Vec<_>>();
    for counter in snapshot.counters() {
        assert_eq!(
            counter.count(),
            snapshot.count(counter.outcome(), counter.reason_class())
        );
    }
    assert!(labels.contains(&("allow", "allow")));
    assert!(labels.contains(&("pending", "actor_ceiling")));
    assert!(labels.contains(&("pending", "source_trust")));
    assert!(labels.contains(&("deny", "policy_fail_closed")));
}

#[test]
fn gate_metrics_counters_advance_for_representative_decisions() {
    let before = gate_metrics_snapshot();
    record_gate_decision_metrics(&GateDecision::allow());
    record_gate_decision_metrics(&GateDecision::deny(GateReasonCode::DenyPolicyFailClosed));
    record_gate_decision_metrics(&GateDecision::pending(vec![
        GateReasonCode::PendingSourceTrust,
        GateReasonCode::PendingCriticalityFloor,
    ]));
    let after = gate_metrics_snapshot();

    assert_metric_counter_advanced(
        &before,
        &after,
        GateOutcome::Allow,
        GateMetricReasonClass::Allow,
        1,
    );
    assert_metric_counter_advanced(
        &before,
        &after,
        GateOutcome::Deny,
        GateMetricReasonClass::PolicyFailClosed,
        1,
    );
    assert_metric_counter_advanced(
        &before,
        &after,
        GateOutcome::Pending,
        GateMetricReasonClass::SourceTrust,
        1,
    );
    assert_metric_counter_advanced(
        &before,
        &after,
        GateOutcome::Pending,
        GateMetricReasonClass::CriticalityFloor,
        1,
    );
}

#[test]
fn gate_metrics_advance_at_claim_write_chokepoint_without_double_counting() -> Result<()> {
    let before = gate_metrics_snapshot();

    let (_allow_tmp, allow_vault) = temp_vault();
    let mut allow_policy = encode_policy_manifest(vec![]);
    trust_human_candidate_actor(&mut allow_policy);
    put_policy_manifest_bytes(&allow_vault, 0x40, &allow_policy)?;
    let allow_body = source_trust_claim(ClaimSource::UserStated);
    let (allow_candidate, allow_envelope) = claim_candidate_write_parts(&allow_vault, &allow_body)?;
    allow_vault
        .batch()
        .claim_candidate(
            &test_id(0x41),
            allow_candidate,
            &allow_envelope,
            test_time(3),
            3,
        )
        .commit()?;

    let (_pending_tmp, pending_vault) = temp_vault();
    put_policy_manifest_bytes(&pending_vault, 0x42, &encode_policy_manifest(vec![]))?;
    let pending_body = source_trust_claim(ClaimSource::UserStated);
    let (pending_candidate, pending_envelope) =
        claim_candidate_write_parts(&pending_vault, &pending_body)?;
    let pending_err = pending_vault
        .batch()
        .claim_candidate(
            &test_id(0x43),
            pending_candidate,
            &pending_envelope,
            test_time(3),
            3,
        )
        .commit()
        .expect_err("untrusted actor class must remain pending");
    assert_gate_rejected(pending_err, "pending", &["gate.pending.actor_ceiling"]);

    let (_deny_tmp, deny_vault) = temp_vault();
    put_policy_manifest_bytes(&deny_vault, 0x45, b"not-msgpack")?;
    let deny_body = source_trust_claim(ClaimSource::UserStated);
    let (deny_candidate, deny_envelope) = claim_candidate_write_parts(&deny_vault, &deny_body)?;
    let deny_err = deny_vault
        .batch()
        .claim_candidate(
            &test_id(0x44),
            deny_candidate,
            &deny_envelope,
            test_time(3),
            3,
        )
        .commit()
        .expect_err("missing policy manifest must fail closed");
    assert_gate_rejected(deny_err, "deny", &["gate.deny.policy_fail_closed"]);

    let after = gate_metrics_snapshot();
    assert_metric_counter_advanced(
        &before,
        &after,
        GateOutcome::Allow,
        GateMetricReasonClass::Allow,
        1,
    );
    assert_metric_counter_advanced(
        &before,
        &after,
        GateOutcome::Pending,
        GateMetricReasonClass::ActorCeiling,
        1,
    );
    assert_metric_counter_advanced(
        &before,
        &after,
        GateOutcome::Deny,
        GateMetricReasonClass::PolicyFailClosed,
        1,
    );
    Ok(())
}

#[test]
fn gate_evaluator_default_policy_fails_closed_with_typed_denial() {
    let policy = PolicyManifestResolution::default();
    let input = gate_evaluator_input(
        "first_party",
        None,
        ClaimSource::UserStated,
        PolicyCriticality::Normal,
    );

    let decision = policy.evaluate_gate(&input);
    assert_eq!(decision.outcome(), GateOutcome::Deny);
    assert_eq!(
        decision.reason_codes(),
        &[GateReasonCode::DenyPolicyFailClosed]
    );
    let err = Error::GateWriteRejected {
        outcome: decision.outcome().as_str(),
        reason_codes: decision
            .reason_codes()
            .iter()
            .map(|reason| reason.as_str())
            .collect(),
    };
    let typed = err
        .gate_denial()
        .expect("default fail-closed denial must be typed");
    assert_eq!(typed.outcome(), GateDenialOutcome::Deny);
    assert_eq!(
        typed.reason_codes(),
        &[GateDenialReason::DenyPolicyFailClosed]
    );
}

#[test]
fn gate_evaluator_actor_source_criticality_matrix() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let data = encode_policy_manifest(vec![]);
    put_policy_manifest_bytes(&vault, 0x71, &data)?;
    let policy = resolve(&vault)?;

    let cases = [
        (
            "auto actor trusted source normal criticality",
            None,
            ClaimSource::UserStated,
            PolicyCriticality::Normal,
            GateOutcome::Allow,
            vec![GateReasonCode::Allow],
        ),
        (
            "auto actor trusted source critical floor",
            None,
            ClaimSource::UserStated,
            PolicyCriticality::Critical,
            GateOutcome::Pending,
            vec![GateReasonCode::PendingCriticalityFloor],
        ),
        (
            "auto actor low source trust normal criticality",
            None,
            ClaimSource::ToolOutput,
            PolicyCriticality::Normal,
            GateOutcome::Pending,
            vec![GateReasonCode::PendingSourceTrust],
        ),
        (
            "auto actor low source trust critical floor",
            None,
            ClaimSource::ToolOutput,
            PolicyCriticality::Critical,
            GateOutcome::Pending,
            vec![
                GateReasonCode::PendingSourceTrust,
                GateReasonCode::PendingCriticalityFloor,
            ],
        ),
        (
            "proposed actor trusted source normal criticality",
            Some("probation"),
            ClaimSource::UserStated,
            PolicyCriticality::Normal,
            GateOutcome::Pending,
            vec![GateReasonCode::PendingActorCeiling],
        ),
        (
            "proposed actor trusted source critical floor",
            Some("probation"),
            ClaimSource::UserStated,
            PolicyCriticality::Critical,
            GateOutcome::Pending,
            vec![
                GateReasonCode::PendingActorCeiling,
                GateReasonCode::PendingCriticalityFloor,
            ],
        ),
        (
            "proposed actor low source trust normal criticality",
            Some("probation"),
            ClaimSource::ToolOutput,
            PolicyCriticality::Normal,
            GateOutcome::Pending,
            vec![
                GateReasonCode::PendingActorCeiling,
                GateReasonCode::PendingSourceTrust,
            ],
        ),
        (
            "proposed actor low source trust critical floor",
            Some("probation"),
            ClaimSource::ToolOutput,
            PolicyCriticality::Critical,
            GateOutcome::Pending,
            vec![
                GateReasonCode::PendingActorCeiling,
                GateReasonCode::PendingSourceTrust,
                GateReasonCode::PendingCriticalityFloor,
            ],
        ),
    ];

    for (name, actor_ref, source, criticality, outcome, reasons) in cases {
        let input = gate_evaluator_input("first_party", actor_ref, source, criticality);
        let decision = policy.evaluate_gate(&input);
        assert_eq!(decision.outcome(), outcome, "{name}");
        assert_eq!(decision.reason_codes(), reasons.as_slice(), "{name}");
        assert!(
            decision
                .reason_codes()
                .iter()
                .all(|code| code.as_str().starts_with("gate.")),
            "{name}: reason codes must be stable gate.* strings"
        );
    }

    Ok(())
}

#[test]
fn gate_evaluator_denial_reason_codes_are_stable() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let data = encode_policy_manifest(vec![]);
    put_policy_manifest_bytes(&vault, 0x72, &data)?;
    let policy = resolve(&vault)?;

    let mut missing_actor_class = gate_evaluator_input(
        "first_party",
        None,
        ClaimSource::UserStated,
        PolicyCriticality::Normal,
    );
    missing_actor_class.actor.actor_class = " \t ".to_owned();
    let decision = policy.evaluate_gate(&missing_actor_class);
    assert_eq!(decision.outcome(), GateOutcome::Deny);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.deny.missing_actor_class"]
    );

    let mut missing_actor_provenance = gate_evaluator_input(
        "first_party",
        None,
        ClaimSource::UserStated,
        PolicyCriticality::Normal,
    );
    missing_actor_provenance.provenance.actor_entity_ref = None;
    let decision = policy.evaluate_gate(&missing_actor_provenance);
    assert_eq!(decision.outcome(), GateOutcome::Deny);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.deny.missing_actor_provenance"]
    );

    let mut missing_policy_version = gate_evaluator_input(
        "first_party",
        None,
        ClaimSource::UserStated,
        PolicyCriticality::Normal,
    );
    missing_policy_version.policy_manifest_version.clear();
    let decision = policy.evaluate_gate(&missing_policy_version);
    assert_eq!(decision.outcome(), GateOutcome::Deny);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.deny.missing_policy_manifest_version"]
    );

    let fail_closed_policy = PolicyManifestResolution::default();
    let input = gate_evaluator_input(
        "first_party",
        None,
        ClaimSource::UserStated,
        PolicyCriticality::Normal,
    );
    let decision = fail_closed_policy.evaluate_gate(&input);
    assert_eq!(decision.outcome(), GateOutcome::Deny);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.deny.policy_fail_closed"]
    );

    Ok(())
}

#[test]
fn gate_evaluator_missing_source_preserves_write_gate_semantics() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let data = encode_policy_manifest(vec![]);
    put_policy_manifest_bytes(&vault, 0x74, &data)?;
    let policy = resolve(&vault)?;

    let mut input = gate_evaluator_input(
        "first_party",
        None,
        ClaimSource::ToolOutput,
        PolicyCriticality::Normal,
    );
    input.source = None;
    input.sensitivity_band = None;

    let decision = policy.evaluate_gate(&input);
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    assert_eq!(gate_reason_strs(&decision), vec!["gate.allow"]);

    Ok(())
}

#[test]
fn gate_evaluator_source_trust_respects_sensitivity_ceiling() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let data = encode_policy_manifest(vec![source_trust_entry(ClaimSource::ToolOutput, 0)]);
    put_policy_manifest_bytes(&vault, 0x75, &data)?;
    let policy = resolve(&vault)?;

    let mut input = gate_evaluator_input(
        "first_party",
        None,
        ClaimSource::ToolOutput,
        PolicyCriticality::Normal,
    );

    let decision = policy.evaluate_gate(&input);
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    assert_eq!(gate_reason_strs(&decision), vec!["gate.allow"]);

    input.sensitivity_band = Some(1);
    let decision = policy.evaluate_gate(&input);
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.pending.source_trust"]
    );

    input.sensitivity_band = None;
    let decision = policy.evaluate_gate(&input);
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.pending.source_trust"]
    );

    Ok(())
}

#[test]
fn gate_evaluator_generated_source_requires_explicit_auto_permit() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let data = encode_policy_manifest(vec![source_trust_entry_without_auto_permit(
        ClaimSource::Generated,
        0,
    )]);
    put_policy_manifest_bytes(&vault, 0x76, &data)?;
    let policy = resolve(&vault)?;

    let input = gate_evaluator_input(
        "first_party",
        None,
        ClaimSource::Generated,
        PolicyCriticality::Normal,
    );
    let decision = policy.evaluate_gate(&input);
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.pending.source_trust"]
    );

    let (_tmp, vault) = temp_vault();
    let data = encode_policy_manifest(vec![source_trust_entry(ClaimSource::Generated, 0)]);
    put_policy_manifest_bytes(&vault, 0x77, &data)?;
    let policy = resolve(&vault)?;
    let decision = policy.evaluate_gate(&input);
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    assert_eq!(gate_reason_strs(&decision), vec!["gate.allow"]);

    Ok(())
}

#[test]
fn gate_evaluator_content_kind_reasons_are_stable() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let data = encode_policy_manifest(vec![]);
    put_policy_manifest_bytes(&vault, 0x73, &data)?;
    let policy = resolve(&vault)?;

    let mut edge_provenance = gate_evaluator_input(
        "first_party",
        None,
        ClaimSource::UserStated,
        PolicyCriticality::Normal,
    );
    edge_provenance.content_kind = GateContentKind::EdgeProvenanceClaim;
    assert_eq!(
        edge_provenance.content_kind.as_str(),
        "edge_provenance_claim"
    );
    let decision = policy.evaluate_gate(&edge_provenance);
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    assert_eq!(gate_reason_strs(&decision), vec!["gate.allow"]);

    let mut policy_manifest = gate_evaluator_input(
        "first_party",
        None,
        ClaimSource::UserStated,
        PolicyCriticality::Normal,
    );
    policy_manifest.content_kind = GateContentKind::PolicyManifest;
    assert_eq!(policy_manifest.content_kind.as_str(), "policy_manifest");
    let decision = policy.evaluate_gate(&policy_manifest);
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.pending.policy_manifest_authority"]
    );

    let mut external_effect = gate_evaluator_input(
        "first_party",
        None,
        ClaimSource::UserStated,
        PolicyCriticality::Normal,
    );
    external_effect.content_kind = GateContentKind::ExternalEffect;
    assert_eq!(external_effect.content_kind.as_str(), "external_effect");
    let decision = policy.evaluate_gate(&external_effect);
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.pending.external_effect_authority"]
    );
    assert_eq!(decision.outcome().as_str(), "pending");

    Ok(())
}

#[test]
fn external_effect_scoped_grant_allows_and_records_receipt() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let data = encode_policy_manifest(vec![external_effect_scoped_grant_entry(
        "sender",
        "external:send",
        Value::Map(vec![(
            Value::from(EXTERNAL_EFFECT_SCOPE_CHANNEL_KEY),
            Value::from("line"),
        )]),
        None,
    )]);
    put_policy_manifest_bytes(&vault, 0xD0, &data)?;
    let policy = resolve(&vault)?;
    let effect = external_effect_gate_input("sender", "send", "line");

    let (_decision_id, decision) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &effect, &policy)
    })?;

    assert_eq!(decision.outcome(), GateOutcome::Allow);
    assert_eq!(gate_reason_strs(&decision), vec!["gate.allow"]);

    let decisions = vault.store.gate_decisions(10)?;
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].outcome, "allow");
    assert_eq!(decisions[0].reason_codes, vec!["gate.allow"]);
    assert_eq!(decisions[0].actor_class, "first_party");
    assert_eq!(decisions[0].actor_ref.as_deref(), Some("sender"));
    assert_eq!(decisions[0].content_kind, "external_effect");
    assert_eq!(decisions[0].claim_id, None);
    assert!(!decisions[0].diff_handle.is_empty());
    assert_eq!(
        decisions[0].read_frontier_hash,
        policy.read_frontier_hash()?
    );
    Ok(())
}

#[test]
fn standing_outbound_grant_allows_in_scope_external_effect_and_records_join() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, 0xD8, &encode_policy_manifest(vec![]))?;

    let grant_id = test_id(0xD9);
    let intent = GrantMintIntent {
        principal_ref: "sender".to_owned(),
        origin_component_id: "ask-1".to_owned(),
        origin_action_id: "escalate_always_this_verb_class".to_owned(),
        origin_receipt_ref: Some("gate:ask-1".to_owned()),
        scope: GrantMintIntentScope::VerbClass {
            verb_class: "send".to_owned(),
        },
    };
    vault.mint_standing_outbound_grant(&grant_id, &intent, 10)?;
    let policy = resolve(&vault)?;

    let mut effect = external_effect_gate_input("sender", "send", "line");
    effect.has_opted_in = false;
    let (_decision_id, decision) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &effect, &policy)
    })?;

    assert_eq!(decision.outcome(), GateOutcome::Allow);
    let grant = vault
        .get_standing_outbound_grant(&grant_id)?
        .expect("grant stored");
    assert!(grant.last_used_at.is_some());

    let decisions = vault.store.gate_decisions(10)?;
    let grant_ref = format!("grant:{}", grant_id.to_hex());
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].grant_ref.as_deref(), Some(grant_ref.as_str()));

    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))?;
    assert_eq!(
        receipts[0].fields.get("grant_ref").map(String::as_str),
        Some(grant_ref.as_str())
    );
    let projection = vault.receipt_projection_by_grant(grant_ref, ReceiptQuery::new(10))?;
    assert_eq!(projection.receipts.len(), 2);
    assert!(
        projection
            .receipts
            .iter()
            .any(|receipt| receipt.receipt_kind == ReceiptKind::Gate)
    );
    Ok(())
}

#[test]
fn standing_outbound_grant_lookup_uses_principal_index_before_type_scan() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, 0xDD, &encode_policy_manifest(vec![]))?;

    let grant_id = test_id(0xDE);
    let intent = GrantMintIntent {
        principal_ref: "sender".to_owned(),
        origin_component_id: "ask-1".to_owned(),
        origin_action_id: "escalate_always_this_verb_class".to_owned(),
        origin_receipt_ref: Some("gate:ask-1".to_owned()),
        scope: GrantMintIntentScope::VerbClass {
            verb_class: "send".to_owned(),
        },
    };
    vault.mint_standing_outbound_grant(&grant_id, &intent, 10)?;
    let policy = resolve(&vault)?;

    vault.with_write_txn(|wtxn| {
        let mut type_key = Vec::with_capacity(ENTITY_ID_LEN + 1);
        type_key.push(ENTITY_TYPE_OUTBOUND_GRANT);
        type_key.extend_from_slice(grant_id.as_bytes());
        vault.store.type_index.delete(wtxn, &type_key)?;
        Ok(())
    })?;

    let mut effect = external_effect_gate_input("sender", "send", "line");
    effect.has_opted_in = false;
    let (_decision_id, decision) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &effect, &policy)
    })?;

    assert_eq!(decision.outcome(), GateOutcome::Allow);
    Ok(())
}

#[test]
fn forged_standing_grant_ref_does_not_authorize_external_effect() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, 0xD7, &encode_policy_manifest(vec![]))?;
    let policy = resolve(&vault)?;

    let mut effect = external_effect_gate_input("sender", "send", "line");
    effect.has_opted_in = false;
    effect.standing_grant_ref = Some(format!("grant:{}", test_id(0xD7).to_hex()));
    let (_decision_id, decision) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &effect, &policy)
    })?;

    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.pending.external_effect_authority"]
    );
    let decisions = vault.store.gate_decisions(10)?;
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].grant_ref, None);
    Ok(())
}

#[test]
fn standing_outbound_grant_reasks_out_of_scope_stale_and_revoked_sends() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, 0xDA, &encode_policy_manifest(vec![]))?;

    let grant_id = test_id(0xDB);
    let intent = GrantMintIntent {
        principal_ref: "sender".to_owned(),
        origin_component_id: "ask-1".to_owned(),
        origin_action_id: "escalate_always_this_channel".to_owned(),
        origin_receipt_ref: Some("gate:ask-1".to_owned()),
        scope: GrantMintIntentScope::Channel {
            channel: "line".to_owned(),
        },
    };
    vault.mint_standing_outbound_grant(&grant_id, &intent, 10)?;
    let policy = resolve(&vault)?;

    let mut out_of_scope = external_effect_gate_input("sender", "send", "email");
    out_of_scope.has_opted_in = false;
    let (_decision_id, decision) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &out_of_scope, &policy)
    })?;
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.pending.external_effect_authority"]
    );

    let mut lifecycle_effect = external_effect_gate_input("sender", "provision", "line");
    lifecycle_effect.has_opted_in = false;
    let (_decision_id, decision) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &lifecycle_effect, &policy)
    })?;
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.pending.external_effect_authority"]
    );

    put_policy_manifest_bytes(&vault, 0xDC, &encode_policy_manifest(vec![]))?;
    let stale_policy = resolve(&vault)?;
    let mut in_scope_stale = external_effect_gate_input("sender", "send", "line");
    in_scope_stale.has_opted_in = false;
    let (_decision_id, decision) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &in_scope_stale, &stale_policy)
    })?;
    assert_eq!(decision.outcome(), GateOutcome::Pending);

    vault.revoke_standing_outbound_grant(&grant_id, 20)?;
    let mut in_scope_revoked = external_effect_gate_input("sender", "send", "line");
    in_scope_revoked.has_opted_in = false;
    let (_decision_id, decision) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &in_scope_revoked, &stale_policy)
    })?;
    assert_eq!(decision.outcome(), GateOutcome::Pending);

    let lens = vault.standing_outbound_grants_lens(StandingOutboundGrantsLensQuery::new(10, 10))?;
    assert_eq!(lens.grants.len(), 1);
    assert_eq!(lens.grants[0].status, "revoked");
    assert_eq!(lens.grants[0].revoked_at, Some(20));
    assert_eq!(lens.grants[0].scope_dial, "always_this_channel");
    assert_eq!(
        lens.grants[0].origin_receipt_ref.as_deref(),
        Some("gate:ask-1")
    );
    Ok(())
}

#[test]
fn counterparty_contact_records_are_visible_and_revocable_by_identity() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let identity = test_id(0xC7);
    let intro_id = test_id(0xC8);
    let inbound_id = test_id(0xC9);
    let intro = CounterpartyContactRecord::user_introduction(identity, " kenji@example.com ", 10)?;
    let inbound = CounterpartyContactRecord::inbound_first(identity, "+15551234567", 11)?;

    vault.create_counterparty_contact(&intro_id, &intro)?;
    vault.create_counterparty_contact(&inbound_id, &inbound)?;

    let found = vault
        .find_counterparty_contact(&identity, "kenji@example.com")?
        .expect("intro contact visible by target");
    assert_eq!(found.0, intro_id);
    assert_eq!(
        found.1.first_touch,
        CounterpartyFirstTouch::UserIntroduction
    );
    assert_eq!(found.1.counterparty, "kenji@example.com");

    let contacts = vault.counterparty_contacts_for_identity(&identity)?;
    assert_eq!(contacts.len(), 2);

    let revoked = vault.revoke_counterparty_contact(&intro_id, 20)?;
    assert_eq!(revoked.status, CounterpartyContactStatus::Revoked);
    assert_eq!(revoked.revoked_at, Some(20));
    assert_eq!(
        vault
            .get_counterparty_contact(&intro_id)?
            .expect("revoked stored"),
        revoked
    );
    Ok(())
}

#[test]
fn counterparty_contact_lookup_uses_dedicated_index_before_scan() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let identity = test_id(0xC7);
    let contact_id = test_id(0xC8);
    let contact = CounterpartyContactRecord::user_introduction(identity, "kenji@example.com", 10)?;
    vault.create_counterparty_contact(&contact_id, &contact)?;

    vault.with_write_txn(|wtxn| {
        let type_key = Store::encode_type_key(ENTITY_TYPE_COUNTERPARTY_CONTACT, &contact_id);
        vault.store.type_index.delete(wtxn, &type_key)?;
        Ok(())
    })?;

    let found = vault
        .find_counterparty_contact(&identity, "kenji@example.com")?
        .expect("lookup index finds contact without type-index scan row");
    assert_eq!(found.0, contact_id);
    assert_eq!(found.1.counterparty, "kenji@example.com");

    let duplicate_id = test_id(0xC9);
    let duplicate = CounterpartyContactRecord::inbound_first(identity, " kenji@example.com ", 20)?;
    let err = vault
        .create_counterparty_contact(&duplicate_id, &duplicate)
        .expect_err("lookup index rejects duplicate counterparty assignment");
    assert_eq!(err.kind(), ErrorKind::CounterpartyContactAlreadyExists);
    Ok(())
}

#[test]
fn external_effect_denies_opted_out_counterparty_regardless_of_grant() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let data = encode_policy_manifest(vec![external_effect_scoped_grant_entry(
        "sender",
        "send",
        Value::Map(vec![(
            Value::from(EXTERNAL_EFFECT_SCOPE_CHANNEL_KEY),
            Value::from("line"),
        )]),
        None,
    )]);
    put_policy_manifest_bytes(&vault, 0xD5, &data)?;
    let policy = resolve(&vault)?;

    let identity = test_id(0xCA);
    let contact_id = test_id(0xCB);
    let contact = CounterpartyContactRecord::user_introduction(identity, "kenji@example.com", 10)?;
    vault.create_counterparty_contact(&contact_id, &contact)?;
    let opted_out = vault.opt_out_counterparty_contact(
        &contact_id,
        CounterpartyOptOutReason::Unsubscribe,
        20,
    )?;
    assert!(opted_out.is_opted_out());

    let mut effect = external_effect_gate_input("sender", "send", "line");
    effect.channel_identity_ref = Some(identity);
    effect.counterparty = Some("kenji@example.com".to_owned());

    let (_decision_id, decision) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &effect, &policy)
    })?;

    assert_eq!(decision.outcome(), GateOutcome::Deny);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.deny.counterparty_opt_out"]
    );
    assert_eq!(
        decision.receipt_reasons(),
        &[
            "counterparty_opt_out_unsubscribe",
            "counterparty_first_touch_user_introduction"
        ]
    );

    let decisions = vault.store.gate_decisions(10)?;
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].outcome, "deny");
    assert_eq!(
        decisions[0].reason_codes,
        vec!["gate.deny.counterparty_opt_out"]
    );
    assert_eq!(
        decisions[0].receipt_reasons,
        vec![
            "counterparty_opt_out_unsubscribe",
            "counterparty_first_touch_user_introduction"
        ]
    );

    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))?;
    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipts[0].policy_trace,
        vec![
            "gate.deny.counterparty_opt_out",
            "counterparty_opt_out_unsubscribe",
            "counterparty_first_touch_user_introduction"
        ]
    );
    assert_eq!(
        receipts[0].fields.get("receipt_reason").map(String::as_str),
        Some("counterparty_opt_out_unsubscribe")
    );
    assert_eq!(
        receipts[0]
            .fields
            .get("receipt_reasons")
            .map(String::as_str),
        Some("counterparty_opt_out_unsubscribe,counterparty_first_touch_user_introduction")
    );
    Ok(())
}

#[test]
fn external_effect_public_first_touch_applies_hold_floor_and_receipt() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let data = encode_policy_manifest(vec![external_effect_scoped_grant_entry(
        "sender",
        "send",
        Value::Map(vec![
            (
                Value::from(EXTERNAL_EFFECT_SCOPE_CHANNEL_KEY),
                Value::from("line"),
            ),
            (
                Value::from(EXTERNAL_EFFECT_SCOPE_POLICY_RISK_KEY),
                Value::from(ExternalEffectPolicyRisk::Normal.as_str()),
            ),
        ]),
        None,
    )]);
    put_policy_manifest_bytes(&vault, 0xD6, &data)?;
    let policy = resolve(&vault)?;
    let identity = test_id(0xCE);

    let mut normal_effect = external_effect_gate_input("sender", "send", "line");
    normal_effect.channel_identity_ref = Some(identity);
    normal_effect.counterparty = Some("unknown@example.com".to_owned());
    let (_decision_id, decision) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &normal_effect, &policy)
    })?;
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    assert_eq!(gate_reason_strs(&decision), vec!["gate.allow"]);
    assert!(decision.receipt_reasons().is_empty());

    let contact_id = test_id(0xCF);
    let public_contact = CounterpartyContactRecord::public(identity, "public@example.com", 10)?;
    vault.create_counterparty_contact(&contact_id, &public_contact)?;

    let mut public_effect = external_effect_gate_input("sender", "send", "line");
    public_effect.channel_identity_ref = Some(identity);
    public_effect.counterparty = Some("public@example.com".to_owned());
    let (_decision_id, decision) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &public_effect, &policy)
    })?;
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.pending.external_effect_authority"]
    );
    assert_eq!(
        decision.receipt_reasons(),
        &["counterparty_first_touch_public"]
    );

    let decisions = vault.store.gate_decisions(10)?;
    let shaped = decisions
        .iter()
        .find(|record| record.receipt_reasons == vec!["counterparty_first_touch_public"])
        .expect("public first-touch gate decision is persisted with receipt reason");
    assert_eq!(shaped.outcome, "pending");
    assert_eq!(
        shaped.reason_codes,
        vec!["gate.pending.external_effect_authority"]
    );

    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))?;
    let shaped_receipt = receipts
        .iter()
        .find(|receipt| {
            receipt
                .policy_trace
                .iter()
                .any(|reason| reason == "counterparty_first_touch_public")
        })
        .expect("public first-touch gate receipt is projected");
    assert_eq!(
        shaped_receipt.policy_trace,
        vec![
            "gate.pending.external_effect_authority",
            "counterparty_first_touch_public"
        ]
    );
    assert_eq!(
        shaped_receipt
            .fields
            .get("receipt_reason")
            .map(String::as_str),
        Some("counterparty_first_touch_public")
    );
    Ok(())
}

#[test]
fn external_effect_requires_opt_in_and_permission() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let data = encode_policy_manifest(vec![external_effect_scoped_grant_entry(
        "sender",
        "send",
        Value::Map(vec![(
            Value::from(EXTERNAL_EFFECT_SCOPE_CHANNEL_KEY),
            Value::from("line"),
        )]),
        None,
    )]);
    put_policy_manifest_bytes(&vault, 0xD1, &data)?;
    let policy = resolve(&vault)?;

    let mut missing_opt_in = external_effect_gate_input("sender", "send", "line");
    missing_opt_in.has_opted_in = false;
    let decision = policy.evaluate_gate(&missing_opt_in.gate_input());
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.pending.external_effect_authority"]
    );

    let mut missing_permission = external_effect_gate_input("sender", "send", "line");
    missing_permission.has_permission = false;
    let decision = policy.evaluate_gate(&missing_permission.gate_input());
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.pending.external_effect_authority"]
    );
    Ok(())
}

#[test]
fn external_effect_policy_risk_holds_but_owner_grant_can_dial_allow_all() -> Result<()> {
    let (_pending_tmp, pending_vault) = temp_vault();
    put_policy_manifest_bytes(&pending_vault, 0xD2, &encode_policy_manifest(vec![]))?;
    let pending_policy = resolve(&pending_vault)?;
    let mut risky = external_effect_gate_input("sender", "send", "line");
    risky.policy_risk = ExternalEffectPolicyRisk::HoldToProposal;

    let decision = pending_policy.evaluate_gate(&risky.gate_input());
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.pending.external_effect_authority"]
    );

    let (_allowed_tmp, allowed_vault) = temp_vault();
    let data = encode_policy_manifest(vec![external_effect_scoped_grant_entry(
        "sender",
        "external:*",
        Value::Map(vec![
            (
                Value::from(EXTERNAL_EFFECT_SCOPE_CHANNEL_KEY),
                Value::from("line"),
            ),
            (
                Value::from(EXTERNAL_EFFECT_SCOPE_POLICY_RISK_KEY),
                Value::from(EXTERNAL_EFFECT_WILDCARD),
            ),
        ]),
        None,
    )]);
    put_policy_manifest_bytes(&allowed_vault, 0xD3, &data)?;
    let allowed_policy = resolve(&allowed_vault)?;
    let decision = allowed_policy.evaluate_gate(&risky.gate_input());
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    assert_eq!(gate_reason_strs(&decision), vec!["gate.allow"]);
    Ok(())
}

#[test]
fn external_effect_budgeted_grants_hold_without_budget_enforcer() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let data = encode_policy_manifest(vec![external_effect_scoped_grant_entry(
        "sender",
        "send",
        Value::Map(vec![(
            Value::from(EXTERNAL_EFFECT_SCOPE_CHANNEL_KEY),
            Value::from("line"),
        )]),
        Some(Value::Map(vec![(Value::from("limit"), Value::from(1_u64))])),
    )]);
    put_policy_manifest_bytes(&vault, 0xD4, &data)?;
    let policy = resolve(&vault)?;
    let effect = external_effect_gate_input("sender", "send", "line");
    let decision = policy.evaluate_gate(&effect.gate_input());
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.pending.external_effect_authority"]
    );
    Ok(())
}

#[test]
fn external_effect_fail_closed_policy_holds_instead_of_denies() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let policy = resolve(&vault)?;
    assert!(policy.is_fail_closed());
    let effect = external_effect_gate_input("sender", "send", "line");

    let (_decision_id, decision) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &effect, &policy)
    })?;

    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.pending.external_effect_authority"]
    );
    let decisions = vault.store.gate_decisions(10)?;
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].outcome, "pending");
    assert_eq!(
        decisions[0].reason_codes,
        vec!["gate.pending.external_effect_authority"]
    );
    assert_eq!(decisions[0].content_kind, "external_effect");
    assert_eq!(decisions[0].claim_id, None);
    Ok(())
}

#[test]
fn policy_manifest_valid_fixture_resolves_gate_inputs() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut data = encode_policy_manifest(vec![
        source_trust_entry(ClaimSource::ToolOutput, 0),
        scoped_grants_entry(),
        signatures_entry(),
    ]);
    replace_actor_ceilings(
        &mut data,
        vec![
            actor_ceiling_row("first_party", "auto"),
            actor_ceiling_row_for_ref("first_party", "probation", "proposed"),
            actor_ceiling_row_for_ref("agent", &first_party_eiri_connector_actor_ref(), "auto"),
            actor_ceiling_row("human", "auto"),
        ],
    );
    put_policy_manifest_bytes(&vault, 0x51, &data)?;

    let policy = resolve(&vault)?;
    assert!(!policy.is_fail_closed());
    assert_eq!(policy.diagnostics().manifest_count, 1);
    assert_eq!(
        policy.actor_ceiling("first_party", None),
        PolicyApprovalCeiling::Auto
    );
    assert_eq!(
        policy.actor_ceiling("first_party", Some("probation")),
        PolicyApprovalCeiling::Proposed
    );
    assert_eq!(
        policy.actor_ceiling("agent", Some(&first_party_eiri_connector_actor_ref())),
        PolicyApprovalCeiling::Auto
    );
    assert_eq!(
        policy.criticality_for_predicate("health.allergy"),
        PolicyCriticality::Critical
    );
    assert_eq!(
        policy.sensitivity_for_predicate("health.allergy"),
        PolicySensitivity::Sensitive
    );
    assert_eq!(policy.scoped_grants().len(), 1);
    assert_eq!(policy.signatures().len(), 1);

    let id = test_id(0x63);
    let body = source_trust_claim(ClaimSource::ToolOutput);
    let (candidate, envelope) = claim_candidate_write_parts(&vault, &body)?;
    reset_claim_body_decode_count();
    vault
        .batch()
        .claim_candidate(&id, candidate, &envelope, test_time(3), 3)
        .commit()?;
    assert!(vault.get_raw(&id)?.is_some());
    assert_eq!(
        claim_body_decode_count(),
        1,
        "policy gate must reuse the write-door decode"
    );
    Ok(())
}

#[test]
fn first_party_eiri_tool_output_auto_write_reaches_auto() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let data = encode_first_party_eiri_default_policy_manifest();
    put_policy_manifest_bytes(&vault, 0xB4, &data)?;

    let claim_id = test_id(0xB5);
    let body = source_trust_claim(ClaimSource::ToolOutput);
    let (candidate, envelope) = claim_candidate_write_parts_for_actor(
        &vault,
        &body,
        first_party_eiri_connector_actor_id(),
        EdgeActorClass::Agent,
    )?;

    vault
        .batch()
        .claim_candidate(&claim_id, candidate, &envelope, test_time(3), 3)
        .commit()?;

    let stored = stored_claim_body(&vault, &claim_id)?;
    assert_eq!(stored.approval, ClaimApprovalStatus::Auto);
    assert_eq!(stored.source, Some(ClaimSource::ToolOutput));

    let decisions = vault.store.gate_decisions(10)?;
    let decision = decisions
        .iter()
        .find(|decision| decision.claim_id == Some(*claim_id.as_bytes()))
        .expect("first-party Eiri write must record a gate decision");
    assert_eq!(decision.outcome, "allow");
    assert_eq!(decision.reason_codes, vec!["gate.allow"]);
    assert_eq!(decision.actor_class, "agent");
    assert_eq!(
        decision.actor_ref.as_deref(),
        Some(first_party_eiri_connector_actor_ref().as_str())
    );
    Ok(())
}

#[test]
fn dreamer_generated_auto_write_requires_manifest_signature() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut data = encode_policy_manifest(vec![source_trust_entry(ClaimSource::Generated, 0)]);
    append_actor_ceiling(
        &mut data,
        actor_ceiling_row_for_ref("agent", &first_party_eiri_connector_actor_ref(), "auto"),
    );
    put_policy_manifest_bytes(&vault, 0xC4, &data)?;

    let claim_id = test_id(0xC5);
    let body = source_trust_claim(ClaimSource::Generated);
    let (candidate, envelope) = dreamer_claim_candidate_write_parts(
        &vault,
        &body,
        first_party_eiri_connector_actor_id(),
        "dreamer-run-auth",
    )?;

    let err = vault
        .batch()
        .claim_candidate(&claim_id, candidate, &envelope, test_time(3), 3)
        .commit()
        .expect_err("unsigned manifest must not grant Dreamer Auto writes");

    assert_gate_rejected(err, "pending", &["gate.pending.policy_manifest_authority"]);
    assert!(vault.get_raw(&claim_id)?.is_none());
    Ok(())
}

#[test]
fn dreamer_generated_auto_write_with_signed_manifest_reaches_auto() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut data = encode_policy_manifest(vec![
        source_trust_entry(ClaimSource::Generated, 0),
        signatures_entry(),
    ]);
    append_actor_ceiling(
        &mut data,
        actor_ceiling_row_for_ref("agent", &first_party_eiri_connector_actor_ref(), "auto"),
    );
    put_policy_manifest_bytes(&vault, 0xC6, &data)?;

    let claim_id = test_id(0xC7);
    let body = source_trust_claim(ClaimSource::Generated);
    let (candidate, envelope) = dreamer_claim_candidate_write_parts(
        &vault,
        &body,
        first_party_eiri_connector_actor_id(),
        "dreamer-run-auth",
    )?;

    vault
        .batch()
        .claim_candidate(&claim_id, candidate, &envelope, test_time(3), 3)
        .commit()?;

    let stored = stored_claim_body(&vault, &claim_id)?;
    assert_eq!(stored.approval, ClaimApprovalStatus::Auto);
    assert_eq!(stored.source, Some(ClaimSource::Generated));

    let decisions = vault.store.gate_decisions(10)?;
    let decision = decisions
        .iter()
        .find(|decision| decision.claim_id == Some(*claim_id.as_bytes()))
        .expect("signed Dreamer Auto write must record a gate decision");
    assert_eq!(decision.outcome, "allow");
    assert_eq!(decision.reason_codes, vec!["gate.allow"]);
    assert_eq!(decision.actor_class, "agent");
    assert_eq!(
        decision.actor_ref.as_deref(),
        Some(first_party_eiri_connector_actor_ref().as_str())
    );
    Ok(())
}

#[test]
fn foreign_tool_output_connector_stays_pending_actor_ceiling() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let data = encode_first_party_eiri_default_policy_manifest();
    put_policy_manifest_bytes(&vault, 0xB6, &data)?;

    let claim_id = test_id(0xB7);
    let body = source_trust_claim(ClaimSource::ToolOutput);
    let (candidate, envelope) =
        claim_candidate_write_parts_for_actor(&vault, &body, test_id(0xB8), EdgeActorClass::Agent)?;

    let err = vault
        .batch()
        .claim_candidate(&claim_id, candidate, &envelope, test_time(3), 3)
        .commit()
        .expect_err("foreign connector must not inherit first-party Auto");

    assert_gate_rejected(err, "pending", &["gate.pending.actor_ceiling"]);
    assert!(vault.get_raw(&claim_id)?.is_none());
    Ok(())
}

#[test]
fn default_policy_vad_rule_is_exact() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let data = encode_first_party_eiri_default_policy_manifest();
    put_policy_manifest_bytes(&vault, 0xC0, &data)?;
    let policy = resolve(&vault)?;

    assert_eq!(
        policy.criticality_for_predicate("affect.vad"),
        PolicyCriticality::Normal
    );
    for predicate in ["affect.vad.extra", "affect.vader.note"] {
        assert_eq!(
            policy.criticality_for_predicate(predicate),
            PolicyCriticality::Critical,
            "{predicate} must not inherit the internal VAD exemption"
        );
    }

    let claim_id = test_id(0xC1);
    let mut body = source_trust_claim(ClaimSource::UserStated);
    body.predicate = "affect.vad.extra".to_owned();
    let (candidate, envelope) = claim_candidate_write_parts(&vault, &body)?;
    let err = vault
        .batch()
        .claim_candidate(&claim_id, candidate, &envelope, test_time(3), 3)
        .commit()
        .expect_err("VAD-like predicates must stay subject to the criticality floor");
    assert_gate_rejected(err, "pending", &["gate.pending.criticality_floor"]);
    assert!(vault.get_raw(&claim_id)?.is_none());
    Ok(())
}

#[test]
fn default_policy_preserves_non_eiri_edge_provenance_writers() -> Result<()> {
    for (seed, actor_entity_type, actor_class) in [
        (0xC2, ENTITY_TYPE_PERSON, EdgeActorClass::Agent),
        (0xD2, ENTITY_TYPE_MACHINE, EdgeActorClass::System),
    ] {
        let (_tmp, vault) = temp_vault();
        let data = encode_first_party_eiri_default_policy_manifest();
        put_policy_manifest_bytes(&vault, seed, &data)?;

        let src = test_id(seed + 1);
        let tgt = test_id(seed + 2);
        let actor = test_id(seed + 3);
        let claim_id = test_id(seed + 4);
        let occurred = test_time(8);
        vault.put_entity(&src, ENTITY_TYPE_PERSON, occurred, 8, b"src")?;
        vault.put_entity(&tgt, ENTITY_TYPE_PERSON, occurred, 8, b"tgt")?;
        vault.put_entity(&actor, actor_entity_type, occurred, 8, b"actor")?;
        vault.put_edge(&src, EdgeKind::Mentions, &tgt, 0.5)?;

        let subject = EdgeRef {
            source: src,
            kind: EdgeKind::Mentions,
            target: tgt,
        };
        let body = EdgeProvenanceClaimBody::new(actor, 0.9, SupersessionStatus::Confirmed);
        vault.put_edge_provenance(&claim_id, &subject, &body, actor_class, 9)?;

        assert!(
            vault.get_raw(&claim_id)?.is_some(),
            "{actor_class:?} edge provenance write should persist under the default policy"
        );
    }
    Ok(())
}

#[test]
fn unknown_and_revoked_connector_refs_fail_closed_to_pending() -> Result<()> {
    let (_unknown_tmp, unknown_vault) = temp_vault();
    let data = encode_first_party_eiri_default_policy_manifest();
    put_policy_manifest_bytes(&unknown_vault, 0xB9, &data)?;

    let unknown_claim = test_id(0xBA);
    let body = source_trust_claim(ClaimSource::ToolOutput);
    let (candidate, envelope) = claim_candidate_write_parts_for_actor(
        &unknown_vault,
        &body,
        test_id(0xBB),
        EdgeActorClass::Agent,
    )?;
    let err = unknown_vault
        .batch()
        .claim_candidate(&unknown_claim, candidate, &envelope, test_time(3), 3)
        .commit()
        .expect_err("unknown connector key must remain pending");
    assert_gate_rejected(err, "pending", &["gate.pending.actor_ceiling"]);
    assert!(unknown_vault.get_raw(&unknown_claim)?.is_none());

    let (_revoked_tmp, revoked_vault) = temp_vault();
    let mut revoked_policy = encode_first_party_eiri_default_policy_manifest();
    append_actor_ceiling(
        &mut revoked_policy,
        actor_ceiling_row_for_ref("agent", &first_party_eiri_connector_actor_ref(), "proposed"),
    );
    put_policy_manifest_bytes(&revoked_vault, 0xBC, &revoked_policy)?;

    let revoked_claim = test_id(0xBD);
    let (candidate, envelope) = claim_candidate_write_parts_for_actor(
        &revoked_vault,
        &body,
        first_party_eiri_connector_actor_id(),
        EdgeActorClass::Agent,
    )?;
    let err = revoked_vault
        .batch()
        .claim_candidate(&revoked_claim, candidate, &envelope, test_time(3), 3)
        .commit()
        .expect_err("revoked connector key must remain pending");
    assert_gate_rejected(err, "pending", &["gate.pending.actor_ceiling"]);
    assert!(revoked_vault.get_raw(&revoked_claim)?.is_none());
    Ok(())
}

#[test]
fn policy_manifest_signature_frontier_covers_first_party_auto_grant() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let data = encode_first_party_eiri_default_policy_manifest();
    put_policy_manifest_bytes(&vault, 0xBE, &data)?;
    let policy = resolve(&vault)?;
    let signed_auto_frontier = policy.read_frontier_hash()?;

    assert_eq!(policy.signatures().len(), 1);
    assert_eq!(
        policy.actor_ceiling("agent", Some(&first_party_eiri_connector_actor_ref())),
        PolicyApprovalCeiling::Auto
    );

    let (_revoked_tmp, revoked_vault) = temp_vault();
    let mut revoked_data = encode_first_party_eiri_default_policy_manifest();
    append_actor_ceiling(
        &mut revoked_data,
        actor_ceiling_row_for_ref("agent", &first_party_eiri_connector_actor_ref(), "proposed"),
    );
    put_policy_manifest_bytes(&revoked_vault, 0xBF, &revoked_data)?;
    let revoked_policy = resolve(&revoked_vault)?;

    assert_eq!(revoked_policy.signatures().len(), 1);
    assert_eq!(
        revoked_policy.actor_ceiling("agent", Some(&first_party_eiri_connector_actor_ref())),
        PolicyApprovalCeiling::Proposed
    );
    assert_ne!(signed_auto_frontier, revoked_policy.read_frontier_hash()?);
    Ok(())
}

#[test]
fn gate_chokepoint_active_policy_source_denial_is_typed_gate_rejection() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut data = encode_policy_manifest(vec![]);
    trust_human_candidate_actor(&mut data);
    put_policy_manifest_bytes(&vault, 0x84, &data)?;

    assert_auto_source_gate_rejected(
        &vault,
        0x85,
        ClaimSource::ToolOutput,
        "pending",
        &["gate.pending.source_trust"],
    )
}

#[test]
fn gate_decision_ledger_survives_rejected_standalone_write() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, 0x90, &encode_policy_manifest(vec![]))?;

    let id = test_id(0x91);
    let body = source_trust_claim(ClaimSource::UserStated);
    let (candidate, envelope) = claim_candidate_write_parts(&vault, &body)?;

    let err = vault
        .batch()
        .claim_candidate(&id, candidate, &envelope, test_time(3), 3)
        .commit()
        .expect_err("pending auto write must be rejected");
    assert_gate_rejected(err, "pending", &["gate.pending.actor_ceiling"]);
    assert!(
        vault.get_raw(&id)?.is_none(),
        "rejected entity write must not stage the claim"
    );

    let decisions = vault.store.gate_decisions(10)?;
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].outcome, "pending");
    assert_eq!(decisions[0].claim_id, Some(*id.as_bytes()));
    assert_eq!(
        decisions[0].reason_codes,
        vec!["gate.pending.actor_ceiling"]
    );
    Ok(())
}

#[test]
fn pending_gate_consent_survives_reopen() -> Result<()> {
    let (tmp, vault) = temp_vault();
    {
        put_policy_manifest_bytes(&vault, 0x92, &encode_policy_manifest(vec![]))?;

        let id = test_id(0x93);
        let mut body = source_trust_claim(ClaimSource::UserStated);
        body.approval = ClaimApprovalStatus::Proposed;
        let (candidate, envelope) = claim_candidate_write_parts(&vault, &body)?;
        vault
            .batch()
            .claim_candidate(&id, candidate, &envelope, test_time(3), 3)
            .commit()?;
    }
    drop(vault);

    let reopened = crate::Vault::open(tmp.path(), crate::config::VaultConfig::default())?;
    let id = test_id(0x93);
    let pending = reopened.with_write_txn(|wtxn| {
        reopened
            .store
            .pending_gate_consent_in_txn(wtxn, &id)?
            .ok_or(Error::CorruptedIndex("pending gate consent"))
    })?;
    assert_eq!(pending.claim_id, *id.as_bytes());
    assert_eq!(pending.reason_codes, vec!["gate.pending.actor_ceiling"]);
    Ok(())
}

#[test]
fn pending_gate_consent_groups_interleaved_dreamer_runs_with_default_lane() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, 0xA0, &encode_policy_manifest(vec![]))?;

    let run_a = "dreamer-run-a";
    let run_b = "dreamer-run-b";
    let run_a_first = test_id(0xA1);
    let run_b_first = test_id(0xA2);
    let default_id = test_id(0xA3);
    let run_a_second = test_id(0xA4);
    let run_b_second = test_id(0xA5);

    let pending_body = |subject_seed: u8, value: &'static str, source: ClaimSource| {
        let mut body = source_trust_claim(source);
        body.subject = ClaimSubject::Entity(test_id(subject_seed));
        body.value = Value::from(value);
        body.approval = ClaimApprovalStatus::Proposed;
        body
    };

    let body_a_first = pending_body(0xB1, "run-a-1", ClaimSource::Generated);
    let body_b_first = pending_body(0xB2, "run-b-1", ClaimSource::Generated);
    let body_default = pending_body(0xB3, "default", ClaimSource::UserStated);
    let body_a_second = pending_body(0xB4, "run-a-2", ClaimSource::Generated);
    let body_b_second = pending_body(0xB5, "run-b-2", ClaimSource::Generated);

    for (claim_id, actor, run_id, body) in [
        (run_a_first, test_id(0xC1), run_a, &body_a_first),
        (run_b_first, test_id(0xC2), run_b, &body_b_first),
    ] {
        let (candidate, envelope) =
            dreamer_claim_candidate_write_parts(&vault, body, actor, run_id)?;
        vault
            .batch()
            .claim_candidate(&claim_id, candidate, &envelope, test_time(3), 3)
            .commit()?;
        std::thread::sleep(Duration::from_millis(2));
    }

    let (candidate, envelope) = claim_candidate_write_parts(&vault, &body_default)?;
    vault
        .batch()
        .claim_candidate(&default_id, candidate, &envelope, test_time(3), 3)
        .commit()?;
    std::thread::sleep(Duration::from_millis(2));

    for (claim_id, actor, run_id, body) in [
        (run_a_second, test_id(0xC4), run_a, &body_a_second),
        (run_b_second, test_id(0xC5), run_b, &body_b_second),
    ] {
        let (candidate, envelope) =
            dreamer_claim_candidate_write_parts(&vault, body, actor, run_id)?;
        vault
            .batch()
            .claim_candidate(&claim_id, candidate, &envelope, test_time(4), 4)
            .commit()?;
        std::thread::sleep(Duration::from_millis(2));
    }

    let pending = vault.pending_gate_consents(10)?;
    assert_eq!(pending.len(), 5);
    assert_eq!(
        pending
            .iter()
            .find(|record| record.claim_id == *run_a_first.as_bytes())
            .and_then(|record| record.dreamer_run_id.as_deref()),
        Some(run_a)
    );
    assert_eq!(
        pending
            .iter()
            .find(|record| record.claim_id == *run_b_first.as_bytes())
            .and_then(|record| record.dreamer_run_id.as_deref()),
        Some(run_b)
    );
    assert_eq!(
        pending
            .iter()
            .find(|record| record.claim_id == *default_id.as_bytes())
            .and_then(|record| record.dreamer_run_id.as_deref()),
        None
    );

    let groups = vault.pending_gate_consent_groups(10)?;
    assert_eq!(groups.len(), 3);
    let group_ids = |run_id: Option<&str>| -> Vec<[u8; ENTITY_ID_LEN]> {
        groups
            .iter()
            .find(|group| group.dreamer_run_id.as_deref() == run_id)
            .expect("group exists")
            .records
            .iter()
            .map(|record| record.claim_id)
            .collect()
    };
    assert_eq!(
        group_ids(Some(run_a)),
        vec![*run_a_first.as_bytes(), *run_a_second.as_bytes()]
    );
    assert_eq!(
        group_ids(Some(run_b)),
        vec![*run_b_first.as_bytes(), *run_b_second.as_bytes()]
    );
    assert_eq!(group_ids(None), vec![*default_id.as_bytes()]);

    let mut approved_a_first = body_a_first;
    approved_a_first.approval = ClaimApprovalStatus::Approved;
    let (candidate, envelope) =
        dreamer_claim_candidate_write_parts(&vault, &approved_a_first, test_id(0xC1), run_a)?;
    vault
        .batch()
        .claim_candidate(&run_a_first, candidate, &envelope, test_time(5), 5)
        .commit()?;

    assert!(!has_pending_gate_consent(&vault, &run_a_first)?);
    assert!(has_pending_gate_consent(&vault, &run_a_second)?);
    assert_eq!(
        vault
            .get_claim(&run_a_first)?
            .expect("approved claim")
            .approval,
        ClaimApprovalStatus::Approved
    );

    let groups = vault.pending_gate_consent_groups(10)?;
    let run_a_after = groups
        .iter()
        .find(|group| group.dreamer_run_id.as_deref() == Some(run_a))
        .expect("run A group remains");
    assert_eq!(run_a_after.records.len(), 1);
    assert_eq!(run_a_after.records[0].claim_id, *run_a_second.as_bytes());
    Ok(())
}

#[test]
fn approved_gate_consent_rejects_drifted_diff() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, 0x94, &encode_policy_manifest(vec![]))?;

    let id = test_id(0x95);
    let mut proposed = source_trust_claim(ClaimSource::UserStated);
    proposed.approval = ClaimApprovalStatus::Proposed;
    let (candidate, envelope) = claim_candidate_write_parts(&vault, &proposed)?;
    vault
        .batch()
        .claim_candidate(&id, candidate, &envelope, test_time(3), 3)
        .commit()?;

    let mut drifted = proposed;
    drifted.value = Value::from("Grace");
    drifted.approval = ClaimApprovalStatus::Approved;
    let (candidate, envelope) = claim_candidate_write_parts(&vault, &drifted)?;
    let err = vault
        .batch()
        .claim_candidate(&id, candidate, &envelope, test_time(4), 4)
        .commit()
        .expect_err("approval must bind to original pending diff");
    assert!(matches!(err, Error::GateConsentStale { claim_id } if claim_id == id));

    let pending = vault.with_write_txn(|wtxn| {
        vault
            .store
            .pending_gate_consent_in_txn(wtxn, &id)?
            .ok_or(Error::CorruptedIndex("pending gate consent"))
    })?;
    assert_eq!(pending.claim_id, *id.as_bytes());
    Ok(())
}

#[test]
fn allowed_gate_consent_resolution_rejects_drifted_source_trust_pending() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut data = encode_policy_manifest(vec![signatures_entry()]);
    append_actor_ceiling(&mut data, actor_ceiling_row("agent", "auto"));
    append_actor_ceiling(
        &mut data,
        actor_ceiling_row(LOCAL_WRITE_ACTOR_CLASS, "auto"),
    );
    put_policy_manifest_bytes(&vault, 0xA6, &data)?;

    let id = test_id(0xA7);
    let mut proposed = source_trust_claim(ClaimSource::Generated);
    proposed.approval = ClaimApprovalStatus::Proposed;
    let (candidate, envelope) =
        dreamer_claim_candidate_write_parts(&vault, &proposed, test_id(0xA8), "run-a")?;
    vault.put_claim_candidate_without_lexical_query_reconcile(
        &id,
        candidate,
        &envelope,
        test_time(3),
        3,
    )?;

    let pending = vault.with_write_txn(|wtxn| {
        vault
            .store
            .pending_gate_consent_in_txn(wtxn, &id)?
            .ok_or(Error::CorruptedIndex("pending gate consent"))
    })?;
    assert_eq!(pending.reason_codes, vec!["gate.pending.source_trust"]);

    let stored = vault.get_claim(&id)?.expect("pending claim");
    let mut drifted = stored.clone();
    drifted.value = Value::from("Grace");
    drifted.approval = ClaimApprovalStatus::Approved;
    let err = vault
        .put_claim(&id, &drifted, test_time(4), 4)
        .expect_err("allow-path approval must bind to original pending diff");
    assert!(matches!(err, Error::GateConsentStale { claim_id } if claim_id == id));
    assert!(has_pending_gate_consent(&vault, &id)?);

    let mut approved = stored;
    approved.approval = ClaimApprovalStatus::Approved;
    vault.put_claim(&id, &approved, test_time(5), 5)?;

    assert!(!has_pending_gate_consent(&vault, &id)?);
    assert_eq!(
        vault.get_claim(&id)?.expect("approved claim").approval,
        ClaimApprovalStatus::Approved
    );
    Ok(())
}

#[test]
fn approved_gate_consent_followup_succeeds_and_clears_pending() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, 0x96, &encode_policy_manifest(vec![]))?;

    let id = test_id(0x97);
    let mut proposed = source_trust_claim(ClaimSource::UserStated);
    proposed.approval = ClaimApprovalStatus::Proposed;
    let (candidate, envelope) = claim_candidate_write_parts(&vault, &proposed)?;
    vault
        .batch()
        .claim_candidate(&id, candidate, &envelope, test_time(3), 3)
        .commit()?;
    assert!(has_pending_gate_consent(&vault, &id)?);

    let mut approved = proposed;
    approved.approval = ClaimApprovalStatus::Approved;
    let (candidate, envelope) = claim_candidate_write_parts(&vault, &approved)?;
    vault
        .batch()
        .claim_candidate(&id, candidate, &envelope, test_time(4), 4)
        .commit()?;

    assert!(!has_pending_gate_consent(&vault, &id)?);
    assert_eq!(
        vault.get_claim(&id)?.expect("approved claim").approval,
        ClaimApprovalStatus::Approved
    );
    Ok(())
}

#[test]
fn same_batch_proposed_then_approved_rejects_without_pending_consent() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, 0x98, &encode_policy_manifest(vec![]))?;

    let id = test_id(0x99);
    let mut proposed = source_trust_claim(ClaimSource::UserStated);
    proposed.approval = ClaimApprovalStatus::Proposed;
    let (proposed_candidate, proposed_envelope) = claim_candidate_write_parts(&vault, &proposed)?;
    let mut approved = proposed;
    approved.approval = ClaimApprovalStatus::Approved;
    let (approved_candidate, approved_envelope) = claim_candidate_write_parts(&vault, &approved)?;

    let err = vault
        .batch()
        .claim_candidate(&id, proposed_candidate, &proposed_envelope, test_time(3), 3)
        .claim_candidate(&id, approved_candidate, &approved_envelope, test_time(4), 4)
        .commit()
        .expect_err("same batch approval must not consume same batch consent");

    assert_gate_rejected(err, "pending", &["gate.pending.actor_ceiling"]);
    assert!(vault.get_raw(&id)?.is_none());
    assert!(!has_pending_gate_consent(&vault, &id)?);
    Ok(())
}

#[test]
fn gate_chokepoint_batch_claim_denial_aborts_without_partial_writes() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut data = encode_policy_manifest(vec![]);
    trust_human_candidate_actor(&mut data);
    put_policy_manifest_bytes(&vault, 0x76, &data)?;

    let prior_id = test_id(0x77);
    let claim_id = test_id(0x78);
    let mut body = source_trust_claim(ClaimSource::UserStated);
    body.predicate = "health.allergy".to_owned();
    let (candidate, envelope) = claim_candidate_write_parts(&vault, &body)?;

    let err = vault
        .batch()
        .put(&prior_id, ENTITY_TYPE_PERSON, test_time(7), 7, b"prior")
        .claim_candidate(&claim_id, candidate, &envelope, test_time(7), 7)
        .commit()
        .expect_err("critical local claim must stop at Gate");

    assert_gate_rejected(err, "pending", &["gate.pending.criticality_floor"]);
    assert!(vault.get_raw(&claim_id)?.is_none());
    assert!(vault.get_raw(&prior_id)?.is_none());
    Ok(())
}

#[test]
fn gate_chokepoint_batch_policy_delete_cannot_weaken_later_claim() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut data = encode_policy_manifest(vec![]);
    trust_human_candidate_actor(&mut data);
    let policy_id = test_id(0x95);
    put_policy_manifest_bytes(&vault, 0x95, &data)?;

    let claim_id = test_id(0x96);
    let mut body = source_trust_claim(ClaimSource::UserStated);
    body.predicate = "health.allergy".to_owned();
    let (candidate, envelope) = claim_candidate_write_parts(&vault, &body)?;

    let err = vault
        .batch()
        .delete(&policy_id)
        .claim_candidate(&claim_id, candidate, &envelope, test_time(7), 7)
        .commit()
        .expect_err("policy delete must not weaken same-batch Gate checks");

    assert_gate_rejected(err, "pending", &["gate.pending.criticality_floor"]);
    assert!(
        vault.get_raw(&policy_id)?.is_some(),
        "failed batch must not delete the active policy manifest"
    );
    assert!(vault.get_raw(&claim_id)?.is_none());
    Ok(())
}

#[test]
fn gate_chokepoint_allows_proposed_claims_for_review_under_pending_policy() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut data = encode_policy_manifest(vec![]);
    trust_human_candidate_actor(&mut data);
    put_policy_manifest_bytes(&vault, 0x97, &data)?;

    let claim_id = test_id(0x98);
    let mut body = source_trust_claim(ClaimSource::ToolOutput);
    body.predicate = "health.allergy".to_owned();
    body.approval = ClaimApprovalStatus::Proposed;
    let (candidate, envelope) = claim_candidate_write_parts(&vault, &body)?;

    vault
        .batch()
        .claim_candidate(&claim_id, candidate, &envelope, test_time(7), 7)
        .commit()?;

    let stored = stored_claim_body(&vault, &claim_id)?;
    assert_eq!(stored.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(stored.predicate, "health.allergy");
    Ok(())
}

#[test]
fn gate_chokepoint_edge_provenance_uses_actor_gate_before_persistence() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let data = encode_policy_manifest(vec![]);
    put_policy_manifest_bytes(&vault, 0x79, &data)?;

    let src = test_id(0x7A);
    let tgt = test_id(0x7B);
    let actor = test_id(0x7C);
    let claim_id = test_id(0x7D);
    let occurred = test_time(8);
    vault.put_entity(&src, ENTITY_TYPE_PERSON, occurred, 8, b"src")?;
    vault.put_entity(&tgt, ENTITY_TYPE_PERSON, occurred, 8, b"tgt")?;
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 8, b"actor")?;
    vault.put_edge(&src, EdgeKind::Mentions, &tgt, 0.5)?;

    let subject = EdgeRef {
        source: src,
        kind: EdgeKind::Mentions,
        target: tgt,
    };
    let body = EdgeProvenanceClaimBody::new(actor, 0.9, SupersessionStatus::Confirmed);
    let err = vault
        .put_edge_provenance(&claim_id, &subject, &body, EdgeActorClass::Human, 9)
        .expect_err("unlisted actor class must stop at Gate");

    assert_gate_rejected(err, "pending", &["gate.pending.actor_ceiling"]);
    assert!(vault.get_raw(&claim_id)?.is_none());
    Ok(())
}

#[test]
fn gate_chokepoint_edge_provenance_retract_uses_gate_before_reserved_reput() -> Result<()> {
    let (_tmp, vault) = temp_vault();

    let src = test_id(0x90);
    let tgt = test_id(0x91);
    let actor = test_id(0x92);
    let claim_id = test_id(0x93);
    let occurred = test_time(8);
    vault.put_entity(&src, ENTITY_TYPE_PERSON, occurred, 8, b"src")?;
    vault.put_entity(&tgt, ENTITY_TYPE_PERSON, occurred, 8, b"tgt")?;
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 8, b"actor")?;
    vault.put_edge(&src, EdgeKind::Mentions, &tgt, 0.5)?;

    let subject = EdgeRef {
        source: src,
        kind: EdgeKind::Mentions,
        target: tgt,
    };
    let body = EdgeProvenanceClaimBody::new(actor, 0.9, SupersessionStatus::Confirmed);
    vault.put_edge_provenance(&claim_id, &subject, &body, EdgeActorClass::Human, 9)?;

    let before_body = stored_claim_body(&vault, &claim_id)?;
    assert_eq!(before_body.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(before_body.valid_to, None);
    assert_eq!(
        edge_provenance_flags(&vault, &src, EdgeKind::Mentions, &tgt)?,
        EdgeProvenanceFlags {
            confirmation_status: EdgeConfirmationStatus::Confirmed,
            actor_class: EdgeActorClass::Human,
        }
    );

    let data = encode_policy_manifest(vec![]);
    put_policy_manifest_bytes(&vault, 0x94, &data)?;

    let err = vault
        .retract_edge_provenance(&claim_id, 10)
        .expect_err("retraction must stop at Gate before reserved re-put");

    assert_gate_rejected(err, "pending", &["gate.pending.actor_ceiling"]);
    let after_body = stored_claim_body(&vault, &claim_id)?;
    assert_eq!(after_body.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(after_body.valid_to, None);
    assert_eq!(
        edge_provenance_flags(&vault, &src, EdgeKind::Mentions, &tgt)?,
        EdgeProvenanceFlags {
            confirmation_status: EdgeConfirmationStatus::Confirmed,
            actor_class: EdgeActorClass::Human,
        }
    );
    Ok(())
}

#[test]
fn gate_chokepoint_edge_provenance_supersede_checks_closed_prior_before_reput() -> Result<()> {
    let (_tmp, vault) = temp_vault();

    let src = test_id(0xA4);
    let tgt = test_id(0xA5);
    let human_actor = test_id(0xA6);
    let agent_actor = test_id(0xA7);
    let prior_claim_id = test_id(0xA8);
    let new_claim_id = test_id(0xA9);
    let occurred = test_time(8);
    vault.put_entity(&src, ENTITY_TYPE_PERSON, occurred, 8, b"src")?;
    vault.put_entity(&tgt, ENTITY_TYPE_PERSON, occurred, 8, b"tgt")?;
    vault.put_entity(&human_actor, ENTITY_TYPE_PERSON, occurred, 8, b"human")?;
    vault.put_entity(&agent_actor, ENTITY_TYPE_PERSON, occurred, 8, b"agent")?;
    vault.put_edge(&src, EdgeKind::Mentions, &tgt, 0.5)?;

    let subject = EdgeRef {
        source: src,
        kind: EdgeKind::Mentions,
        target: tgt,
    };
    let prior_body = EdgeProvenanceClaimBody::new(human_actor, 0.9, SupersessionStatus::Confirmed);
    vault.put_edge_provenance(
        &prior_claim_id,
        &subject,
        &prior_body,
        EdgeActorClass::Human,
        9,
    )?;

    let before_body = stored_claim_body(&vault, &prior_claim_id)?;
    assert_eq!(before_body.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(before_body.valid_to, None);
    assert_eq!(
        edge_provenance_flags(&vault, &src, EdgeKind::Mentions, &tgt)?,
        EdgeProvenanceFlags {
            confirmation_status: EdgeConfirmationStatus::Confirmed,
            actor_class: EdgeActorClass::Human,
        }
    );

    let mut policy = encode_policy_manifest(vec![]);
    replace_actor_ceilings(
        &mut policy,
        vec![
            actor_ceiling_row("first_party", "auto"),
            actor_ceiling_row("agent", "auto"),
        ],
    );
    put_policy_manifest_bytes(&vault, 0xAA, &policy)?;

    let new_body = EdgeProvenanceClaimBody::new(agent_actor, 0.8, SupersessionStatus::Confirmed);
    let err = vault
        .put_edge_provenance(
            &new_claim_id,
            &subject,
            &new_body,
            EdgeActorClass::Agent,
            10,
        )
        .expect_err("superseded prior closure must stop at Gate before reserved re-put");

    assert_gate_rejected(err, "pending", &["gate.pending.actor_ceiling"]);
    assert!(vault.get_raw(&new_claim_id)?.is_none());
    let after_body = stored_claim_body(&vault, &prior_claim_id)?;
    assert_eq!(after_body.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(after_body.valid_to, None);
    assert_eq!(
        edge_provenance_flags(&vault, &src, EdgeKind::Mentions, &tgt)?,
        EdgeProvenanceFlags {
            confirmation_status: EdgeConfirmationStatus::Confirmed,
            actor_class: EdgeActorClass::Human,
        }
    );
    Ok(())
}

#[test]
fn policy_manifest_missing_fixture_fails_closed_where_required() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let policy = resolve(&vault)?;
    assert!(policy.is_fail_closed());
    assert_eq!(
        policy.actor_ceiling("first_party", None),
        PolicyApprovalCeiling::Proposed
    );
    assert_eq!(
        policy.criticality_for_predicate("profile.name"),
        PolicyCriticality::Critical
    );

    assert_auto_source_rejected(&vault, 0x64, ClaimSource::ToolOutput)?;
    assert_auto_source_rejected(&vault, 0x65, ClaimSource::Imported)?;
    assert_auto_source_rejected(&vault, 0x66, ClaimSource::Generated)?;

    let id = test_id(0x67);
    let body = source_trust_claim(ClaimSource::Observed);
    let (candidate, envelope) = claim_candidate_write_parts(&vault, &body)?;
    vault
        .batch()
        .claim_candidate(&id, candidate, &envelope, test_time(4), 4)
        .commit()?;
    assert!(vault.get_raw(&id)?.is_some());
    Ok(())
}

#[test]
fn policy_manifest_malformed_fixture_fails_closed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, 0x52, b"not-msgpack")?;

    let policy = resolve(&vault)?;
    assert!(policy.is_fail_closed());
    assert!(policy.diagnostics().malformed_manifest_seen);
    assert!(policy.scoped_grants().is_empty());
    assert_eq!(
        policy.actor_ceiling("first_party", None),
        PolicyApprovalCeiling::Proposed
    );
    assert_eq!(
        policy.criticality_for_predicate("profile.name"),
        PolicyCriticality::Critical
    );
    assert_auto_source_gate_rejected(
        &vault,
        0x67,
        ClaimSource::ToolOutput,
        "deny",
        &["gate.deny.policy_fail_closed"],
    )
}

#[test]
fn policy_manifest_malformed_source_trust_fails_closed_with_diagnostics() -> Result<()> {
    enum SourceTrustMalformed {
        Duplicate,
        NotAMap,
    }

    let cases = [
        (
            "duplicate_source_trust",
            0xB0,
            SourceTrustMalformed::Duplicate,
        ),
        ("source_trust_not_map", 0xB2, SourceTrustMalformed::NotAMap),
    ];

    for (case_name, seed, malformed) in cases {
        let (_tmp, vault) = temp_vault();
        let mut data = encode_policy_manifest(vec![]);
        rewrite_policy_manifest_entries(&mut data, |entries| match malformed {
            SourceTrustMalformed::Duplicate => {
                let entry = source_trust_entry(ClaimSource::UserStated, 0);
                entries.push(entry.clone());
                entries.push(entry);
            }
            SourceTrustMalformed::NotAMap => {
                entries.push((Value::from(POLICY_SOURCE_TRUST_KEY), Value::from("bad")));
            }
        });
        put_policy_manifest_bytes(&vault, seed, &data)?;

        let policy = resolve(&vault)?;
        assert!(
            policy.diagnostics().malformed_manifest_seen,
            "{case_name}: malformed source_trust must set manifest diagnostics"
        );
        assert!(
            policy.is_fail_closed(),
            "{case_name}: policy must fail closed"
        );
        assert!(
            policy.enforces_write_gate(),
            "{case_name}: loaded malformed manifest must still enforce Gate"
        );

        let claim_id = test_id(seed + 1);
        let mut body = source_trust_claim(ClaimSource::UserStated);
        body.approval = ClaimApprovalStatus::Approved;
        let (candidate, envelope) = claim_candidate_write_parts(&vault, &body)?;
        let err = match vault
            .batch()
            .claim_candidate(&claim_id, candidate, &envelope, test_time(4), 4)
            .commit()
        {
            Ok(()) => {
                panic!("{case_name}: fail-closed policy must reject non-auto normal claim")
            }
            Err(err) => err,
        };

        assert_gate_rejected(err, "deny", &["gate.deny.policy_fail_closed"]);
        assert!(vault.get_raw(&claim_id)?.is_none());
    }

    Ok(())
}

#[test]
fn policy_manifest_missing_schema_fixture_fails_closed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut data = encode_policy_manifest(vec![
        source_trust_entry(ClaimSource::ToolOutput, 0),
        scoped_grants_entry(),
    ]);
    rewrite_policy_manifest_entries(&mut data, |entries| {
        entries.retain(|(key, _)| key.as_str() != Some(POLICY_SCHEMA_VERSION_KEY));
    });
    put_policy_manifest_bytes(&vault, 0x54, &data)?;

    let policy = resolve(&vault)?;
    assert!(policy.is_fail_closed());
    assert!(policy.diagnostics().unsupported_schema_seen);
    assert!(policy.scoped_grants().is_empty());
    assert_eq!(
        policy.actor_ceiling("first_party", None),
        PolicyApprovalCeiling::Proposed
    );
    assert_auto_source_gate_rejected(
        &vault,
        0x69,
        ClaimSource::ToolOutput,
        "deny",
        &["gate.deny.policy_fail_closed"],
    )
}

#[test]
fn policy_manifest_version_fixture_degrades_to_most_restrictive() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut data = encode_policy_manifest(vec![
        source_trust_entry(ClaimSource::ToolOutput, 0),
        scoped_grants_entry(),
    ]);
    rewrite_policy_manifest_entries(&mut data, |entries| {
        for (key, value) in entries {
            if key.as_str() == Some(POLICY_MIN_ENGINE_VERSION_KEY) {
                *value = Value::from("999.0.0");
            }
        }
    });
    put_policy_manifest_bytes(&vault, 0x53, &data)?;

    let policy = resolve(&vault)?;
    assert!(policy.is_fail_closed());
    assert!(policy.diagnostics().engine_version_floor_seen);
    assert!(policy.scoped_grants().is_empty());
    assert_eq!(
        policy.actor_ceiling("first_party", None),
        PolicyApprovalCeiling::Proposed
    );
    assert_eq!(
        policy.criticality_for_predicate("health.allergy"),
        PolicyCriticality::Critical
    );
    assert_auto_source_gate_rejected(
        &vault,
        0x68,
        ClaimSource::ToolOutput,
        "deny",
        &["gate.deny.policy_fail_closed"],
    )
}

#[test]
fn policy_manifest_unknown_axis_fails_closed_and_exposes_no_scoped_grants() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut data = encode_policy_manifest(vec![
        source_trust_entry(ClaimSource::ToolOutput, 0),
        scoped_grants_entry(),
    ]);
    rewrite_policy_manifest_entries(&mut data, |entries| {
        for (key, value) in entries {
            if key.as_str() == Some(POLICY_DEFAULTS_KEY) {
                let Value::Map(defaults) = value else {
                    unreachable!("defaults are a map");
                };
                defaults.push((Value::from("future_axis"), Value::from("permit")));
            }
        }
    });
    put_policy_manifest_bytes(&vault, 0x55, &data)?;

    let policy = resolve(&vault)?;
    assert!(policy.is_fail_closed());
    assert!(policy.diagnostics().unknown_axis_seen);
    assert!(policy.scoped_grants().is_empty());
    assert_eq!(
        policy.sensitivity_for_predicate("profile.name"),
        PolicySensitivity::Sensitive
    );
    assert_auto_source_gate_rejected(
        &vault,
        0x6A,
        ClaimSource::ToolOutput,
        "deny",
        &["gate.deny.policy_fail_closed"],
    )
}

#[test]
fn legacy_source_trust_pack_entity_does_not_relax_policy_inputs() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut legacy = Vec::new();
    rmpv::encode::write_value(
        &mut legacy,
        &Value::Map(vec![
            (
                Value::from("manifest"),
                Value::from("dec_0005_predicate_pack"),
            ),
            source_trust_entry(ClaimSource::ToolOutput, 0),
        ]),
    )
    .expect("legacy source-trust encode");

    vault.put_entity(
        &test_id(0x56),
        crate::registry::ENTITY_TYPE_TASK_LIST,
        test_time(1),
        1,
        &legacy,
    )?;

    let policy = resolve(&vault)?;
    assert!(policy.is_fail_closed());
    assert_eq!(policy.diagnostics().manifest_count, 0);
    assert_auto_source_rejected(&vault, 0x6B, ClaimSource::ToolOutput)
}

#[cfg(feature = "sync")]
#[test]
fn replay_path_skips_policy_source_trust_gate() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let id = test_id(0x81);
    let data = source_trust_claim_data(ClaimSource::ToolOutput);

    vault
        .batch()
        .put_replicated(
            &id,
            crate::registry::ENTITY_TYPE_CLAIM,
            test_time(5),
            5,
            &data,
        )
        .commit()?;

    assert!(
        vault.get_raw(&id)?.is_some(),
        "replicated replay must not re-gate remote source trust"
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn replicated_generated_auto_claim_merges_but_is_not_consolidatable() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let strict_policy = encode_policy_manifest(vec![source_trust_entry(ClaimSource::Imported, 0)]);
    put_policy_manifest_bytes(&vault, 0x87, &strict_policy)?;

    let id = test_id(0x88);
    let data = source_trust_claim_data(ClaimSource::Generated);
    vault
        .batch()
        .put_replicated(
            &id,
            crate::registry::ENTITY_TYPE_CLAIM,
            test_time(5),
            5,
            &data,
        )
        .commit()?;

    let raw = vault
        .get_raw(&id)?
        .expect("foreign-manifest-approved descendant still merges");
    let body = decode_claim_body(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..], false)?;
    assert_eq!(body.source, Some(ClaimSource::Generated));
    assert!(
        crate::claim::claim_surfaceable(&body),
        "foreign-approved Auto/Generated descendant may still surface"
    );
    assert!(
        !crate::claim::claim_consolidatable(&body),
        "strict local consolidation must decline it as corroboration"
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn federated_admission_allows_and_restamps_imported_claim() -> Result<()> {
    use crate::batch::ENTITY_METADATA_HEADER_LEN;
    use crate::sync::loro_support::{import_doc, map_get_bytes};
    use crate::sync::schema::create_window_doc;
    use crate::sync::types::WindowKey;
    use crate::sync::{FederationAdmissionRole, admit_federated_window_update};

    let (_tmp, vault) = temp_vault();
    let data = encode_policy_manifest(vec![source_trust_entry(ClaimSource::Imported, 0)]);
    put_policy_manifest_bytes(&vault, 0x8A, &data)?;

    let id = test_id(0x8B);
    let remote_body = source_trust_claim(ClaimSource::ToolOutput);
    let update = federated_claim_update(&id, &remote_body)?;
    let key = WindowKey::new("2026-03");
    let admitted =
        admit_federated_window_update(&vault, &key, &update, FederationAdmissionRole::Member)?;

    let doc = create_window_doc("receiver", &key);
    import_doc(&doc, &admitted)?;
    let blob = map_get_bytes(&doc.get_map("entities"), &id.to_hex()).ok_or(Error::InvalidKey)?;
    let body = decode_claim_body(&blob[ENTITY_METADATA_HEADER_LEN..], false)?;
    assert_eq!(body.source, Some(ClaimSource::Imported));
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn federated_admission_denies_untrusted_import_with_auditable_reason() -> Result<()> {
    use crate::sync::types::WindowKey;
    use crate::sync::{FederationAdmissionRole, admit_federated_window_update};

    let (_tmp, vault) = temp_vault();
    let id = test_id(0x8C);
    let remote_body = source_trust_claim(ClaimSource::ToolOutput);
    let update = federated_claim_update(&id, &remote_body)?;
    let key = WindowKey::new("2026-03");

    let err = admit_federated_window_update(&vault, &key, &update, FederationAdmissionRole::Guest)
        .expect_err("imported auto claims need an explicit local trust floor");
    assert_gate_rejected(err, "pending", &["gate.pending.source_trust"]);
    assert!(vault.get_raw(&id)?.is_none());
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn federated_admission_denies_preapproved_untrusted_import() -> Result<()> {
    use crate::sync::types::WindowKey;
    use crate::sync::{FederationAdmissionRole, admit_federated_window_update};

    let (_tmp, vault) = temp_vault();
    let id = test_id(0x8F);
    let mut remote_body = source_trust_claim(ClaimSource::ToolOutput);
    remote_body.approval = ClaimApprovalStatus::Approved;
    let update = federated_claim_update(&id, &remote_body)?;
    let key = WindowKey::new("2026-03");

    let err = admit_federated_window_update(&vault, &key, &update, FederationAdmissionRole::Member)
        .expect_err("preapproved federated claims still need local imported trust");
    assert_gate_rejected(err, "pending", &["gate.pending.source_trust"]);
    assert!(vault.get_raw(&id)?.is_none());
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn federated_admission_denial_does_not_regress_own_device_replay() -> Result<()> {
    use crate::sync::types::WindowKey;
    use crate::sync::{FederationAdmissionRole, admit_federated_window_update};

    let (_tmp, vault) = temp_vault();
    let id = test_id(0x8D);
    let remote_body = source_trust_claim(ClaimSource::ToolOutput);
    let update = federated_claim_update(&id, &remote_body)?;
    let key = WindowKey::new("2026-03");
    let err = admit_federated_window_update(&vault, &key, &update, FederationAdmissionRole::Member)
        .expect_err("federated path must enforce local imported trust floor");
    assert_gate_rejected(err, "pending", &["gate.pending.source_trust"]);

    let replay_id = test_id(0x8E);
    let replay_data = crate::claim::encode_claim_body(&remote_body)?;
    vault
        .batch()
        .put_replicated(
            &replay_id,
            crate::registry::ENTITY_TYPE_CLAIM,
            test_time(5),
            5,
            &replay_data,
        )
        .commit()?;
    assert!(
        vault.get_raw(&replay_id)?.is_some(),
        "own-device replicated replay remains trust-blind"
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn gate_chokepoint_replicated_claim_stays_trust_blind() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let data = encode_policy_manifest(vec![]);
    put_policy_manifest_bytes(&vault, 0x80, &data)?;

    let id = test_id(0x83);
    let claim = source_trust_claim_data(ClaimSource::ToolOutput);
    vault
        .batch()
        .put_replicated(
            &id,
            crate::registry::ENTITY_TYPE_CLAIM,
            test_time(5),
            5,
            &claim,
        )
        .commit()?;

    assert!(
        vault.get_raw(&id)?.is_some(),
        "replicated replay must not call the local Gate chokepoint"
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn replicated_policy_manifest_is_rejected_and_cannot_relax_source_trust() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let data = encode_policy_manifest(vec![source_trust_entry(ClaimSource::ToolOutput, 0)]);
    let occurred = test_time(1);

    let batch_id = test_id(0x82);
    let err = vault
        .batch()
        .put_replicated(&batch_id, ENTITY_TYPE_POLICY_MANIFEST, occurred, 1, &data)
        .commit()
        .expect_err("replicated policy manifests must be rejected");
    assert!(
        matches!(err, Error::MaintenanceKindNotWritable(kind) if kind == ENTITY_TYPE_POLICY_MANIFEST),
        "expected policy manifest maintenance rejection, got {err:?}"
    );
    assert!(vault.get_raw(&batch_id)?.is_none());

    let txn_id = test_id(0x83);
    let err = vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .put_replicated(&txn_id, ENTITY_TYPE_POLICY_MANIFEST, occurred, 1, &data)
                .apply(wtxn)
        })
        .expect_err("txn replicated policy manifests must be rejected");
    assert!(
        matches!(err, Error::MaintenanceKindNotWritable(kind) if kind == ENTITY_TYPE_POLICY_MANIFEST),
        "expected policy manifest maintenance rejection, got {err:?}"
    );
    assert!(vault.get_raw(&txn_id)?.is_none());

    assert_auto_source_rejected(&vault, 0x84, ClaimSource::ToolOutput)
}

#[cfg(feature = "sync")]
#[test]
fn replicated_access_grant_is_rejected_and_cannot_mint_local_grant() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let principal = test_id(0x90);
    let person = test_id(0x91);
    let persona = test_id(0x92);
    let data = crate::encode_access_grant_body(&crate::AccessGrant::companion_profile_read(
        principal, person, persona, 1,
    ))?;
    let occurred = test_time(1);

    let batch_id = test_id(0x93);
    let err = vault
        .batch()
        .put_replicated(&batch_id, ENTITY_TYPE_ACCESS_GRANT, occurred, 1, &data)
        .commit()
        .expect_err("replicated access grants must be rejected");
    assert!(
        matches!(err, Error::MaintenanceKindNotWritable(kind) if kind == ENTITY_TYPE_ACCESS_GRANT),
        "expected access grant maintenance rejection, got {err:?}"
    );
    assert!(vault.get_raw(&batch_id)?.is_none());
    assert_eq!(
        vault.companion_profile_access_grant(&principal, &person, &persona)?,
        None
    );

    let txn_id = test_id(0x94);
    let err = vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .put_replicated(&txn_id, ENTITY_TYPE_ACCESS_GRANT, occurred, 1, &data)
                .apply(wtxn)
        })
        .expect_err("txn replicated access grants must be rejected");
    assert!(
        matches!(err, Error::MaintenanceKindNotWritable(kind) if kind == ENTITY_TYPE_ACCESS_GRANT),
        "expected access grant maintenance rejection, got {err:?}"
    );
    assert!(vault.get_raw(&txn_id)?.is_none());
    assert_eq!(
        vault.companion_profile_access_grant(&principal, &person, &persona)?,
        None
    );

    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn forward_rematerialize_quarantines_replicated_policy_manifest() -> Result<()> {
    use crate::sync::bridge::Materializer;
    use crate::sync::loro_support::map_insert_bytes;
    use crate::sync::quarantine::{QuarantineContainer, quarantined_records};
    use crate::sync::schema::create_window_doc;
    use crate::sync::types::WindowKey;
    use crate::sync::window::forward_rematerialize;

    let (_tmp, vault) = temp_vault();
    let data = encode_policy_manifest(vec![source_trust_entry(ClaimSource::ToolOutput, 0)]);
    let id = test_id(0x85);
    let window_key = WindowKey::new("2026-03");
    let doc = create_window_doc("local", &window_key);
    let blob = policy_manifest_blob(&data);
    map_insert_bytes(&doc.get_map("entities"), &id.to_hex(), &blob)
        .expect("insert policy manifest into CRDT");
    doc.commit();

    let materialized = forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
    assert_eq!(materialized, 0);
    assert!(vault.get_raw(&id)?.is_none());
    let records = quarantined_records(&vault)?;
    assert!(
        records.iter().any(|(_, record)| {
            record.container == QuarantineContainer::Entities
                && record.reason_code == "MaintenanceKindNotWritable"
        }),
        "rejected policy manifest replay should be quarantined, got {records:?}"
    );

    assert_auto_source_rejected(&vault, 0x86, ClaimSource::ToolOutput)
}

#[cfg(feature = "sync")]
#[test]
fn forward_rematerialize_quarantines_malformed_authority_log() -> Result<()> {
    use crate::sync::bridge::Materializer;
    use crate::sync::loro_support::map_insert_bytes;
    use crate::sync::quarantine::{QuarantineContainer, quarantined_records};
    use crate::sync::schema::create_window_doc;
    use crate::sync::types::WindowKey;
    use crate::sync::window::forward_rematerialize;

    let (_tmp, vault) = temp_vault();
    let id = test_id(0x87);
    let window_key = WindowKey::new("2026-03");
    let doc = create_window_doc("local", &window_key);
    let blob = authority_log_blob(b"not an authority log body");
    map_insert_bytes(&doc.get_map("entities"), &id.to_hex(), &blob)
        .expect("insert malformed authority log into CRDT");
    doc.commit();

    let materialized = forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
    assert_eq!(materialized, 0);
    assert!(vault.get_raw(&id)?.is_none());
    let records = quarantined_records(&vault)?;
    assert!(
        records.iter().any(|(_, record)| {
            record.container == QuarantineContainer::Entities
                && record.reason_code == "InvalidAuthorityLogBody"
        }),
        "malformed authority log replay should be quarantined, got {records:?}"
    );

    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn forward_rematerialize_quarantines_replicated_access_grant() -> Result<()> {
    use crate::sync::bridge::Materializer;
    use crate::sync::loro_support::map_insert_bytes;
    use crate::sync::quarantine::{QuarantineContainer, quarantined_records};
    use crate::sync::schema::create_window_doc;
    use crate::sync::types::WindowKey;
    use crate::sync::window::forward_rematerialize;

    let (_tmp, vault) = temp_vault();
    let principal = test_id(0x95);
    let person = test_id(0x96);
    let persona = test_id(0x97);
    let data = crate::encode_access_grant_body(&crate::AccessGrant::companion_profile_read(
        principal, person, persona, 1,
    ))?;
    let id = test_id(0x98);
    let window_key = WindowKey::new("2026-03");
    let doc = create_window_doc("local", &window_key);
    let blob = access_grant_blob(&data);
    map_insert_bytes(&doc.get_map("entities"), &id.to_hex(), &blob)
        .expect("insert access grant into CRDT");
    doc.commit();

    let materialized = forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
    assert_eq!(materialized, 0);
    assert!(vault.get_raw(&id)?.is_none());
    assert_eq!(
        vault.companion_profile_access_grant(&principal, &person, &persona)?,
        None
    );
    let records = quarantined_records(&vault)?;
    assert!(
        records.iter().any(|(_, record)| {
            record.container == QuarantineContainer::Entities
                && record.reason_code == "MaintenanceKindNotWritable"
        }),
        "rejected access grant replay should be quarantined, got {records:?}"
    );

    Ok(())
}
