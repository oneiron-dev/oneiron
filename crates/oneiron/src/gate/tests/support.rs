//! Shared fixtures and assertion helpers for the gate test modules.

use super::*;

pub(super) fn test_time(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

pub(super) fn sweep_id(family: u8, lo: u8) -> EntityId {
    EntityId::from_bytes([
        family, lo, family, lo, family, lo, family, lo, family, lo, family, lo, family, lo, family,
        lo,
    ])
    .expect("sweep fixture id")
}

pub(super) fn temp_vault() -> (tempfile::TempDir, crate::Vault) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault =
        crate::Vault::open(tmp.path(), crate::config::VaultConfig::default()).expect("open vault");
    clear_policy_manifests_for_test(&vault);
    (tmp, vault)
}

pub(super) fn clear_policy_manifests_for_test(vault: &crate::Vault) {
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

/// One of the pinned system-agent actor ids, `[0xA1; 16]`..`[0xA6; 16]`.
/// Constructed explicitly (with intent) because `test_util::entity` refuses
/// production-pinned seed bytes.
pub(super) fn pinned_actor_id(byte: u8) -> EntityId {
    assert!(
        (0xA1..=0xA6).contains(&byte),
        "pinned system-agent actor id bytes are 0xA1..=0xA6, got {byte:#04x}"
    );
    EntityId::from_bytes([byte; 16]).expect("pinned system agent actor id is non-reserved")
}

/// A minimal valid AGENT_DEF value carrying `ceiling` and no fork lineage.
pub(super) fn agent_def_fixture(agent_id: &str, ceiling: AgentCeiling) -> AgentDefinition {
    AgentDefinition::new(
        agent_id,
        "gate resolver fixture",
        "1",
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::All,
        ceiling,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        Value::Map(vec![(Value::from("fixture"), Value::from(agent_id))]),
        None,
        true,
        None,
    )
}

/// An encoded AGENT_DEF body, optionally carrying fork lineage. `forked_from`
/// is appended as the pinned wire key rather than set on `AgentDefinition`:
/// the field's authoring type is the preset vocabulary the gate no longer
/// speaks, and the decoder rejects any key outside `AGENT_DEF_BODY_KEYS`, so a
/// key rename fails these fixtures loudly.
pub(super) fn agent_def_body(
    agent_id: &str,
    ceiling: AgentCeiling,
    forked_from: Option<&str>,
) -> Vec<u8> {
    let encoded = encode_agent_definition(&agent_def_fixture(agent_id, ceiling))
        .expect("fixture agent definition encodes");
    let Some(parent) = forked_from else {
        return encoded;
    };
    let mut cursor = encoded.as_slice();
    let Ok(Value::Map(mut entries)) = rmpv::decode::read_value(&mut cursor) else {
        panic!("encoded AGENT_DEF body is a MessagePack map");
    };
    entries.push((Value::from("forkedFrom"), Value::from(parent)));
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Value::Map(entries)).expect("fixture body encodes");
    out
}

/// Writes an entity row straight into the store, bypassing the batch write
/// door — the only way to place a row at a write-door-reserved pinned id.
pub(super) fn put_raw_entity_row(
    vault: &crate::Vault,
    id: &EntityId,
    entity_type: u8,
    body: &[u8],
) -> Result<()> {
    let payload = entity_record(entity_type, test_time(1), 1, body);
    vault.with_write_txn(|wtxn| {
        vault.store.entities.put(wtxn, id.as_bytes(), &payload)?;
        let type_key = Store::encode_type_key(entity_type, id);
        vault.store.type_index.put(wtxn, &type_key, &[])?;
        Ok(())
    })
}

/// Stores an AGENT_DEF row at `id` through the raw store door.
pub(super) fn put_agent_def_row(
    vault: &crate::Vault,
    id: &EntityId,
    agent_id: &str,
    ceiling: AgentCeiling,
    forked_from: Option<&str>,
) -> Result<()> {
    put_raw_entity_row(
        vault,
        id,
        ENTITY_TYPE_AGENT_DEF,
        &agent_def_body(agent_id, ceiling, forked_from),
    )
}

/// The live definition ceiling an agent-class actor at `id` resolves to.
pub(super) fn resolved_ceiling(
    vault: &crate::Vault,
    id: EntityId,
) -> Result<Option<PolicyApprovalCeiling>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(agent_definition_ceiling_for_actor(
        &vault.store,
        &rtxn,
        WriteActor::new(id, EdgeActorClass::Agent),
    ))
}

pub(super) fn check_external_effect_policy_with_budget(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    effect: &ExternalEffectGateInput,
    policy: &PolicyManifestResolution,
    admit_for_execution: bool,
) -> Result<(GateDecisionId, GateDecision, Option<EffectorBudgetCharge>)> {
    let mut governance = evaluate_external_effect_policy(store, wtxn, effect, policy, None)?;
    let mut charge = None;
    let mut exhausted = false;
    if governance.outcome() == GateOutcome::Allow
        && admit_for_execution
        && let Some(target) = governance.budget_target_mut()
    {
        let outcome = crate::connector_key::charge_effector_budgets(
            store,
            wtxn,
            &target.key_id,
            &mut target.key,
            &target.governing_connector,
            effect.send_ref.is_some(),
            crate::unix_seconds_now(),
        )?;
        let mut applied = match outcome {
            EffectorBudgetChargeOutcome::NoRows(charge)
            | EffectorBudgetChargeOutcome::Charged(charge) => charge,
            EffectorBudgetChargeOutcome::Exhausted {
                row_index,
                on_exhaust,
                mut charge,
            } => {
                exhausted = true;
                if on_exhaust == EffectorBudgetOnExhaust::Suspend {
                    crate::connector_key::suspend_connector_key_in_txn(
                        store,
                        wtxn,
                        &target.key_id,
                        &target.key,
                        crate::connector_key::budget_exhausted_reason(row_index),
                        crate::unix_seconds_now(),
                    )?;
                    charge.read.status = ConnectorKeyStatus::Suspended;
                }
                charge
            }
        };
        applied.matched_rows.sort_unstable();
        applied.matched_rows.dedup();
        charge = Some(applied);
    }
    if exhausted {
        governance.deny_budget_exhausted();
    }
    let (decision_id, decision) = record_external_effect_policy(store, wtxn, governance)?;
    Ok((decision_id, decision, charge))
}

pub(super) fn encode_policy_manifest(extra_entries: Vec<(Value, Value)>) -> Vec<u8> {
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

pub(super) fn encode_first_party_eiri_default_policy_manifest() -> Vec<u8> {
    default_policy_manifest()
}

pub(super) fn rewrite_policy_manifest_entries(
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

pub(super) fn source_trust_entry(source: ClaimSource, max_auto_sensitivity: u8) -> (Value, Value) {
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

pub(super) fn source_trust_entry_without_auto_permit(
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

pub(super) fn actor_ceiling_row(actor_class: &str, ceiling: &str) -> Value {
    Value::Map(vec![
        (Value::from(ACTOR_CLASS_KEY), Value::from(actor_class)),
        (Value::from(ACTOR_CEILING_KEY), Value::from(ceiling)),
    ])
}

pub(super) fn actor_ceiling_row_for_ref(
    actor_class: &str,
    actor_ref: &str,
    ceiling: &str,
) -> Value {
    Value::Map(vec![
        (Value::from(ACTOR_CLASS_KEY), Value::from(actor_class)),
        (Value::from(ACTOR_REF_KEY), Value::from(actor_ref)),
        (Value::from(ACTOR_CEILING_KEY), Value::from(ceiling)),
    ])
}

pub(super) fn replace_actor_ceilings(data: &mut Vec<u8>, rows: Vec<Value>) {
    rewrite_policy_manifest_entries(data, |entries| {
        for (key, value) in entries {
            if key.as_str() == Some(POLICY_ACTOR_CEILINGS_KEY) {
                *value = Value::Array(rows);
                return;
            }
        }
    });
}

pub(super) fn append_actor_ceiling(data: &mut Vec<u8>, row: Value) {
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

pub(super) fn trust_human_candidate_actor(data: &mut Vec<u8>) {
    append_actor_ceiling(data, actor_ceiling_row("human", "auto"));
}

pub(super) fn scoped_grants_entry() -> (Value, Value) {
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

pub(super) fn external_effect_scoped_grant_entry(
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

pub(super) fn signatures_entry() -> (Value, Value) {
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

#[cfg(feature = "sync")]
pub(super) fn policy_manifest_blob(data: &[u8]) -> Vec<u8> {
    entity_record(
        ENTITY_TYPE_POLICY_MANIFEST,
        TimeRange { start: 1, end: 1 },
        1,
        data,
    )
}

pub(super) fn access_grant_blob(data: &[u8]) -> Vec<u8> {
    entity_record(
        ENTITY_TYPE_ACCESS_GRANT,
        TimeRange { start: 1, end: 1 },
        1,
        data,
    )
}

#[cfg(feature = "sync")]
pub(super) fn authority_log_blob(data: &[u8]) -> Vec<u8> {
    entity_record(
        crate::registry::ENTITY_TYPE_AUTHORITY_LOG,
        TimeRange { start: 1, end: 1 },
        1,
        data,
    )
}

pub(super) fn put_malformed_access_grant_bytes(
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

pub(super) fn resolve(vault: &crate::Vault) -> Result<PolicyManifestResolution> {
    let rtxn = vault.store.env.read_txn()?;
    resolve_policy_manifest(&vault.store, &rtxn)
}

pub(super) fn first_party_eiri_connector_actor_id() -> EntityId {
    EntityId::from_bytes(FIRST_PARTY_EIRI_CONNECTOR_ACTOR_ID)
        .expect("first-party Eiri actor fixture id")
}

pub(super) fn has_pending_gate_consent(vault: &crate::Vault, id: &EntityId) -> Result<bool> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(vault
        .store
        .pending_gate_consent_in_txn(&rtxn, id)?
        .is_some())
}

pub(super) fn source_trust_claim(source: ClaimSource) -> ClaimBody {
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

/// Stamps `sensitivity: public` (band 0) on a claim body.
///
/// The ONE-1645 provenance floor makes an UNSTAMPED claim read band 2, which
/// exceeds every `max_auto_sensitivity: 0` source-trust row and sends the
/// write to the consent queue. Fixtures whose SUBJECT is some other gate axis
/// — actor ceilings, manifest signatures, connector-ref resolution, federated
/// admission — stamp public here so they keep exercising the axis they exist
/// to test rather than re-testing the floor. The floor itself is pinned
/// directly by `gate_source_trust_unstamped_claim_hits_floor_band`.
pub(super) fn public_stamped(mut body: ClaimBody) -> ClaimBody {
    body.scope = Some(Value::Map(vec![(
        Value::from("sensitivity"),
        Value::from("public"),
    )]));
    body
}

pub(super) fn core_read_scoped_grant_entry(actor_ref: &str, scope: Value) -> (Value, Value) {
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

pub(super) fn receipt_required_core_read_scoped_grant_entry(
    actor_ref: &str,
    scope: Value,
) -> (Value, Value) {
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

pub(super) fn budgeted_core_read_scoped_grant_entry(
    actor_ref: &str,
    scope: Value,
) -> (Value, Value) {
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

pub(super) fn core_read_world_grant_manifest(actor_ref: &str, world: EntityId) -> Vec<u8> {
    encode_policy_manifest(vec![core_read_scoped_grant_entry(
        actor_ref,
        Value::Map(vec![(
            Value::from("world_ref"),
            Value::from(world.to_hex()),
        )]),
    )])
}

pub(super) fn put_claim_body(vault: &crate::Vault, id: &EntityId, body: &ClaimBody) -> Result<()> {
    let data = crate::claim::encode_claim_body(body)?;
    let payload = entity_record(
        crate::registry::ENTITY_TYPE_CLAIM,
        TimeRange { start: 1, end: 1 },
        1,
        &data,
    );

    vault.with_write_txn(|wtxn| {
        vault.store.entities.put(wtxn, id.as_bytes(), &payload)?;
        let type_key = Store::encode_type_key(crate::registry::ENTITY_TYPE_CLAIM, id);
        vault.store.type_index.put(wtxn, &type_key, &[])?;
        Ok(())
    })
}

pub(super) fn put_claim_text_body(
    vault: &crate::Vault,
    id: &EntityId,
    text: &str,
    body: &ClaimBody,
) -> Result<()> {
    put_claim_body(vault, id, body)?;
    vault.batch().text(id, &[("body", text)]).commit()
}

pub(super) fn put_text_entity(
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

pub(super) fn put_vector_entity(vault: &crate::Vault, id: &EntityId, vector: &[f32]) -> Result<()> {
    vault.put_entity(
        id,
        crate::registry::ENTITY_TYPE_PERSON,
        test_time(1),
        1,
        b"vector entity",
    )?;
    vault.put_vector(id, vector)
}

pub(super) fn put_dangling_short_id(
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
pub(super) fn source_trust_claim_data(source: ClaimSource) -> Vec<u8> {
    crate::claim::encode_claim_body(&source_trust_claim(source)).expect("claim encode")
}

#[cfg(feature = "sync")]
pub(super) fn federated_claim_update(id: &EntityId, body: &ClaimBody) -> Result<Vec<u8>> {
    use crate::sync::loro_support::{export_all_updates, map_insert_bytes};
    use crate::sync::schema::create_window_doc;
    use crate::sync::types::WindowKey;

    let data = crate::claim::encode_claim_body(body)?;
    let blob = entity_record(
        crate::registry::ENTITY_TYPE_CLAIM,
        TimeRange { start: 5, end: 5 },
        5,
        &data,
    );

    let key = WindowKey::new("2026-03");
    let doc = create_window_doc("federation-remote", &key);
    map_insert_bytes(&doc.get_map("entities"), &id.to_hex(), &blob)?;
    doc.commit();
    export_all_updates(&doc)
}

pub(super) fn claim_candidate_from_body(body: &ClaimBody) -> ClaimCandidate {
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

pub(super) fn claim_candidate_write_parts(
    vault: &crate::Vault,
    body: &ClaimBody,
) -> Result<(ClaimCandidate, WriteEnvelope)> {
    let actor = test_id(0x20);
    claim_candidate_write_parts_for_actor(vault, body, actor, EdgeActorClass::Human)
}

pub(super) fn claim_candidate_write_parts_for_actor(
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

pub(super) fn dreamer_claim_candidate_write_parts(
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
                Value::from(DREAMER_RUNNER_ATTEMPT_KIND),
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

pub(super) fn gate_evaluator_input(
    actor_class: &str,
    actor_ref: Option<&str>,
    source: ClaimSource,
    criticality: PolicyCriticality,
) -> GateEvaluatorInput {
    GateEvaluatorInput {
        actor: GateActor {
            actor_class: actor_class.to_owned(),
            actor_ref: actor_ref.map(str::to_owned),
            delegation_grant_ref: None,
        },
        source: Some(source),
        content_kind: GateContentKind::Claim,
        sensitivity_band: Some(0),
        criticality,
        policy_manifest_version: POLICY_SCHEMA_VERSION.to_owned(),
        provenance: GateProvenanceHandles {
            actor_entity_ref: Some(test_id(0xA0)),
            substrate_ref: Some(test_id(0x5A)),
            source_revision_ref: Some([0xA2; ENTITY_ID_LEN]),
            body_snapshot_ref: Some([0xA3; ENTITY_ID_LEN]),
            ..GateProvenanceHandles::default()
        },
        external_effect: None,
        agent_definition_ceiling: None,
        consent: None,
    }
}

pub(super) fn external_effect_gate_input(
    actor_ref: &str,
    verb: &str,
    channel: &str,
) -> ExternalEffectGateInput {
    ExternalEffectGateInput {
        actor: GateActor {
            actor_class: "first_party".to_owned(),
            actor_ref: Some(actor_ref.to_owned()),
            delegation_grant_ref: None,
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
        scoped_mcp_call: None,
        counterparty_first_touch: None,
        counterparty_opted_out: false,
        counterparty_opt_out_receipt_reason: None,
        has_opted_in: true,
        has_permission: true,
        policy_risk: ExternalEffectPolicyRisk::Normal,
    }
}

pub(super) fn gate_reason_strs(decision: &GateDecision) -> Vec<&'static str> {
    decision
        .reason_codes()
        .iter()
        .map(|code| code.as_str())
        .collect()
}

pub(super) fn assert_auto_source_rejected(
    vault: &crate::Vault,
    seed: u8,
    source: ClaimSource,
) -> Result<()> {
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

pub(super) fn assert_auto_source_gate_rejected(
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

pub(super) fn assert_gate_rejected(
    err: Error,
    outcome: &'static str,
    reason_codes: &[&'static str],
) {
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

pub(super) fn assert_metric_counter_advanced(
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

pub(super) fn stored_claim_body(vault: &crate::Vault, id: &EntityId) -> Result<ClaimBody> {
    let raw = vault.get_raw(id)?.ok_or(Error::EntityNotFound)?;
    decode_claim_body(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..], true)
}

pub(super) fn edge_provenance_flags(
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
