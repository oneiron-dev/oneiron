use super::*;
use crate::agent_def::{AgentDefinition, AgentScope, encode_agent_definition};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, ScopedReadActorKey,
    claim_body_decode_count, decode_claim_body, reset_claim_body_decode_count,
};
use crate::connector_key::{
    ConnectorKeyStatus, EffectorBudgetChargeOutcome, EffectorBudgetOnExhaust,
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

use crate::test_util::{entity as test_id, entity_record, put_policy_manifest_bytes};

fn test_time(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

fn sweep_id(family: u8, lo: u8) -> EntityId {
    EntityId::from_bytes([
        family, lo, family, lo, family, lo, family, lo, family, lo, family, lo, family, lo, family,
        lo,
    ])
    .expect("sweep fixture id")
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

// ---------------------------------------------------------------------------
// AGENT_DEF resolver fixtures.
//
// The gate resolves agent authority from STORED ROWS only — it has no preset
// vocabulary — so these fixtures have none either: the pinned actor ids appear
// as raw byte literals and fork lineage is written as the pinned wire key.
// ---------------------------------------------------------------------------

/// One of the pinned system-agent actor ids, `[0xA1; 16]`..`[0xA6; 16]`.
/// Constructed explicitly (with intent) because `test_util::entity` refuses
/// production-pinned seed bytes.
fn pinned_actor_id(byte: u8) -> EntityId {
    assert!(
        (0xA1..=0xA6).contains(&byte),
        "pinned system-agent actor id bytes are 0xA1..=0xA6, got {byte:#04x}"
    );
    EntityId::from_bytes([byte; 16]).expect("pinned system agent actor id is non-reserved")
}

/// A minimal valid AGENT_DEF value carrying `ceiling` and no fork lineage.
fn agent_def_fixture(agent_id: &str, ceiling: AgentCeiling) -> AgentDefinition {
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
fn agent_def_body(agent_id: &str, ceiling: AgentCeiling, forked_from: Option<&str>) -> Vec<u8> {
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
fn put_raw_entity_row(
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
fn put_agent_def_row(
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
fn resolved_ceiling(vault: &crate::Vault, id: EntityId) -> Result<Option<PolicyApprovalCeiling>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(agent_definition_ceiling_for_actor(
        &vault.store,
        &rtxn,
        WriteActor::new(id, EdgeActorClass::Agent),
    ))
}

// Connector-budget unit fixtures keep their accounting assertions while the
// production gate remains governance-only. Effect-path tests exercise the
// atomic debit through outbound_chokepoint instead.
fn check_external_effect_policy_with_budget(
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

#[test]
fn companion_profile_access_grants_allow_deny_and_revoke() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // 0x71: [0xA1; 16] is a write-door-reserved system-agent actor id (ONE-1444).
    let grant_id = test_id(0x71);
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
    // 0x72: [0xA2; 16] is a write-door-reserved system-agent actor id (ONE-1444).
    let valid_id = test_id(0x72);
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
    entity_record(
        ENTITY_TYPE_POLICY_MANIFEST,
        TimeRange { start: 1, end: 1 },
        1,
        data,
    )
}

fn access_grant_blob(data: &[u8]) -> Vec<u8> {
    entity_record(
        ENTITY_TYPE_ACCESS_GRANT,
        TimeRange { start: 1, end: 1 },
        1,
        data,
    )
}

#[cfg(feature = "sync")]
fn authority_log_blob(data: &[u8]) -> Vec<u8> {
    entity_record(
        crate::registry::ENTITY_TYPE_AUTHORITY_LOG,
        TimeRange { start: 1, end: 1 },
        1,
        data,
    )
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
    put_policy_manifest_bytes(&vault, test_id(0x81), &encode_policy_manifest(vec![]))?;

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
    put_policy_manifest_bytes(&continue_vault, test_id(0x82), &continue_manifest)?;
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
    put_policy_manifest_bytes(&overdraft_vault, test_id(0x83), &overdraft_manifest)?;
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
        test_id(0x84),
        &encode_policy_manifest(vec![(
            Value::from(POLICY_ON_BUDGET_EXHAUSTED_KEY),
            Value::from("continue_on_local"),
        )]),
    )?;
    put_policy_manifest_bytes(
        &vault,
        test_id(0x85),
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

/// Stamps `sensitivity: public` (band 0) on a claim body.
///
/// The ONE-1645 provenance floor makes an UNSTAMPED claim read band 2, which
/// exceeds every `max_auto_sensitivity: 0` source-trust row and sends the
/// write to the consent queue. Fixtures whose SUBJECT is some other gate axis
/// — actor ceilings, manifest signatures, connector-ref resolution, federated
/// admission — stamp public here so they keep exercising the axis they exist
/// to test rather than re-testing the floor. The floor itself is pinned
/// directly by `gate_source_trust_unstamped_claim_hits_floor_band`.
fn public_stamped(mut body: ClaimBody) -> ClaimBody {
    body.scope = Some(Value::Map(vec![(
        Value::from("sensitivity"),
        Value::from("public"),
    )]));
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
    put_policy_manifest_bytes(&vault, test_id(0x61), &data)?;
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
    let allowed_id = test_id(0x5A);
    let denied_id = test_id(0x5C);

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
    put_policy_manifest_bytes(&vault, test_id(0x6C), &data)?;

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
    put_policy_manifest_bytes(&vault, test_id(0x3B), &data)?;

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
    put_policy_manifest_bytes(&vault, test_id(0x62), &encode_policy_manifest(vec![]))?;

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
    put_policy_manifest_bytes(&vault, test_id(0x6D), &encode_policy_manifest(vec![]))?;
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
        test_id(0x3D),
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
        (0x43, [0.0_f32, 0.0, 1.0, 0.0]),
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
        test_id(0x63),
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
        test_id(0x64),
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
    put_policy_manifest_bytes(&vault, test_id(0x65), &encode_policy_manifest(vec![]))?;

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
        crate::deletion::HydratedShortIdDeletionSource::DanglingShortId
    );
    Ok(())
}

#[test]
fn scoped_read_hydrate_preserves_deleted_claim_short_id_metadata() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x6F), &encode_policy_manifest(vec![]))?;

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
        crate::deletion::HydratedShortIdDeletionSource::Tombstone
            | crate::deletion::HydratedShortIdDeletionSource::PendingTombstone
    ));
    assert_eq!(
        deletion.reason,
        Some(crate::deletion::HydratedShortIdDeletionReason::UserDelete)
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
        test_id(0x66),
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
        test_id(0x70),
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
        test_id(0x75),
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
    let facet = test_id(0x5E);
    put_policy_manifest_bytes(
        &vault,
        test_id(0x6B),
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
        test_id(0x67),
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
    let allowed_world = test_id(0x5D);
    let denied_world = test_id(0xD8);
    put_policy_manifest_bytes(
        &vault,
        test_id(0x69),
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
        test_id(0x6A),
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
        test_id(0x68),
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

fn external_effect_gate_input(
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
    put_policy_manifest_bytes(&allow_vault, test_id(0x40), &allow_policy)?;
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
    put_policy_manifest_bytes(
        &pending_vault,
        test_id(0x5F),
        &encode_policy_manifest(vec![]),
    )?;
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
    put_policy_manifest_bytes(&deny_vault, test_id(0x45), b"not-msgpack")?;
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
    put_policy_manifest_bytes(&vault, test_id(0x71), &data)?;
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
    put_policy_manifest_bytes(&vault, test_id(0x72), &data)?;
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
    put_policy_manifest_bytes(&vault, test_id(0x74), &data)?;
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

/// ONE-1645 write-path consequence, deliberate: a source under a band-capped
/// trust row (`max_auto_sensitivity = 1`) still auto-approves an explicitly
/// public claim, but an UNSTAMPED claim now reads the band-2 floor and
/// exceeds the cap — it queues for consent instead of auto-writing. Hosts
/// restore auto by stamping `public`; that is the floor doing its job, not a
/// regression.
#[test]
fn gate_source_trust_unstamped_claim_hits_floor_band() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let data = encode_policy_manifest(vec![source_trust_entry(ClaimSource::UserStated, 1)]);
    put_policy_manifest_bytes(&vault, test_id(0x77), &data)?;
    let policy = resolve(&vault)?;

    let table: [(&str, Option<Value>, bool); 3] = [
        (
            "explicit public stamp",
            Some(Value::Map(vec![(
                Value::from("sensitivity"),
                Value::from("public"),
            )])),
            true,
        ),
        ("unstamped: no scope map", None, false),
        (
            "unstamped: scope map without a sensitivity key",
            Some(Value::Map(vec![(
                Value::from("federated_original_source"),
                Value::from("user_stated"),
            )])),
            false,
        ),
    ];
    for (label, scope, expect_auto) in table {
        let mut body = source_trust_claim(ClaimSource::UserStated);
        body.scope = scope;
        let allowed = check_claim_source_trust(&body, &policy).is_ok();
        assert_eq!(allowed, expect_auto, "{label}");
    }
    Ok(())
}

#[test]
fn gate_evaluator_source_trust_respects_sensitivity_ceiling() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let data = encode_policy_manifest(vec![source_trust_entry(ClaimSource::ToolOutput, 0)]);
    put_policy_manifest_bytes(&vault, test_id(0x75), &data)?;
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
    put_policy_manifest_bytes(&vault, test_id(0x76), &data)?;
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
    put_policy_manifest_bytes(&vault, test_id(0x77), &data)?;
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
    put_policy_manifest_bytes(&vault, test_id(0x73), &data)?;
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
    put_policy_manifest_bytes(&vault, test_id(0xD0), &data)?;
    let policy = resolve(&vault)?;
    let effect = external_effect_gate_input("sender", "send", "line");

    let (_decision_id, decision, _effector_charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy_with_budget(&vault.store, wtxn, &effect, &policy, true)
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
    put_policy_manifest_bytes(&vault, test_id(0xD8), &encode_policy_manifest(vec![]))?;

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
    let (_decision_id, decision, _effector_charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy_with_budget(&vault.store, wtxn, &effect, &policy, true)
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
    put_policy_manifest_bytes(&vault, test_id(0xDD), &encode_policy_manifest(vec![]))?;

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
    let (_decision_id, decision, _effector_charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &effect, &policy, true)
    })?;

    assert_eq!(decision.outcome(), GateOutcome::Allow);
    Ok(())
}

#[test]
fn forged_standing_grant_ref_does_not_authorize_external_effect() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let default_manifest_id = crate::gate::default_policy_manifest_id()?;
    put_policy_manifest_bytes(&vault, default_manifest_id, &encode_policy_manifest(vec![]))?;
    let policy = resolve(&vault)?;

    let mut effect = external_effect_gate_input("sender", "send", "line");
    effect.has_opted_in = false;
    effect.standing_grant_ref = Some(format!("grant:{}", default_manifest_id.to_hex()));
    let (_decision_id, decision, _effector_charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &effect, &policy, true)
    })?;

    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&decision),
        vec![
            "gate.pending.consent.irreversible_effect",
            "gate.pending.external_effect_authority",
        ]
    );
    let decisions = vault.store.gate_decisions(10)?;
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].grant_ref, None);
    Ok(())
}

#[test]
fn scoped_mcp_grant_is_payload_aware_at_external_effect_gate() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xD8), &encode_policy_manifest(vec![]))?;
    let grant_id = test_id(0xD9);
    vault.mint_scoped_mcp_outbound_grant(
        &grant_id,
        &crate::outbound_grant::ScopedMcpGrantMintIntent {
            principal_ref: test_id(0xE0).to_hex(),
            origin_component_id: "ask-mcp".to_owned(),
            origin_action_id: "grant-scoped-mcp".to_owned(),
            origin_receipt_ref: Some("gate:ask-mcp".to_owned()),
            server: "files".to_owned(),
            tool: "read_file".to_owned(),
            data_class_ceiling: crate::outbound_consent::DataClass::Personal,
            endpoint_allowlist: vec!["https://files.internal.example".to_owned()],
        },
        10,
    )?;
    vault.register_connector_key(
        &test_id(0xDA),
        crate::ConnectorKeyRecord::active(
            scoped_mcp_credential_connector_key("files", &grant_id),
            None,
            Vec::new(),
            10,
        ),
    )?;
    let policy = resolve(&vault)?;
    let in_scope_call = || crate::outbound_consent::ScopedMcpCallContext {
        server: "files".to_owned(),
        tool: "read_file".to_owned(),
        payload_data_class: crate::outbound_consent::DataClass::Personal,
        resolved_endpoint: "https://files.internal.example".to_owned(),
    };

    let mut in_scope = external_effect_gate_input(&test_id(0xE0).to_hex(), "send", "mcp:calendar");
    in_scope.has_opted_in = false;
    in_scope.scoped_mcp_call = Some(in_scope_call());
    let (_, decision, _) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &in_scope, &policy, true)
    })?;
    assert_eq!(decision.outcome(), GateOutcome::Allow);

    let exceeds = [
        crate::outbound_consent::ScopedMcpCallContext {
            server: "calendar".to_owned(),
            ..in_scope_call()
        },
        crate::outbound_consent::ScopedMcpCallContext {
            tool: "write_file".to_owned(),
            ..in_scope_call()
        },
        crate::outbound_consent::ScopedMcpCallContext {
            payload_data_class: crate::outbound_consent::DataClass::Secret,
            ..in_scope_call()
        },
        crate::outbound_consent::ScopedMcpCallContext {
            resolved_endpoint: "https://exfil.example".to_owned(),
            ..in_scope_call()
        },
    ];
    let mut escalations = 0_usize;
    for call in exceeds {
        let mut effect =
            external_effect_gate_input(&test_id(0xE0).to_hex(), "send", "mcp:calendar");
        effect.has_opted_in = false;
        effect.scoped_mcp_call = Some(call);
        let (_, decision, _) = vault.with_write_txn(|wtxn| {
            check_external_effect_policy(&vault.store, wtxn, &effect, &policy, true)
        })?;
        assert_eq!(decision.outcome(), GateOutcome::Pending);
        escalations = escalations.saturating_add(1);
    }
    // Discriminating: presence-only authorization makes at least one of the
    // four scope-exceeds Allow instead of recording all four escalations.
    assert_eq!(escalations, 4);
    Ok(())
}

#[test]
fn scoped_mcp_grant_without_registered_connector_key_stays_pending() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xDC), &encode_policy_manifest(vec![]))?;
    let grant_id = test_id(0xDD);
    vault.mint_scoped_mcp_outbound_grant(
        &grant_id,
        &crate::outbound_grant::ScopedMcpGrantMintIntent {
            principal_ref: test_id(0xE0).to_hex(),
            origin_component_id: "ask-mcp".to_owned(),
            origin_action_id: "grant-scoped-mcp".to_owned(),
            origin_receipt_ref: Some("gate:ask-mcp".to_owned()),
            server: "files".to_owned(),
            tool: "read_file".to_owned(),
            data_class_ceiling: crate::outbound_consent::DataClass::Personal,
            endpoint_allowlist: vec!["https://files.internal.example".to_owned()],
        },
        10,
    )?;
    let policy = resolve(&vault)?;
    let mut effect = external_effect_gate_input(&test_id(0xE0).to_hex(), "send", "mcp:calendar");
    effect.has_opted_in = false;
    effect.scoped_mcp_call = Some(crate::outbound_consent::ScopedMcpCallContext {
        server: "files".to_owned(),
        tool: "read_file".to_owned(),
        payload_data_class: crate::outbound_consent::DataClass::Personal,
        resolved_endpoint: "https://files.internal.example".to_owned(),
    });

    let (_, decision, _) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &effect, &policy, true)
    })?;
    // Discriminating: this exact-principal, in-scope call used to Allow when
    // its synthetic scoped-MCP connector key was not registered.
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.pending.connector_key_unregistered"]
    );
    assert_eq!(decision.receipt_reasons(), &["connector_key_unregistered"]);
    Ok(())
}

#[test]
fn scoped_mcp_grant_budget_matches_its_synthetic_governing_key() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xC0), &encode_policy_manifest(vec![]))?;
    let principal_ref = test_id(0xE0).to_hex();
    let grant_id = test_id(0xC1);
    vault.mint_scoped_mcp_outbound_grant(
        &grant_id,
        &crate::outbound_grant::ScopedMcpGrantMintIntent {
            principal_ref: principal_ref.clone(),
            origin_component_id: "ask-mcp".to_owned(),
            origin_action_id: "grant-scoped-mcp".to_owned(),
            origin_receipt_ref: Some("gate:ask-mcp".to_owned()),
            server: "files".to_owned(),
            tool: "read_file".to_owned(),
            data_class_ceiling: crate::outbound_consent::DataClass::Personal,
            endpoint_allowlist: vec!["https://files.internal.example".to_owned()],
        },
        10,
    )?;
    let governing_connector = scoped_mcp_credential_connector_key("files", &grant_id);
    let key_id = test_id(0xC2);
    vault.register_connector_key(
        &key_id,
        crate::ConnectorKeyRecord::active(
            governing_connector,
            None,
            vec![crate::EffectorBudget::rate(1, 3_600)],
            10,
        ),
    )?;

    let policy = resolve(&vault)?;
    let mut effect = external_effect_gate_input(&principal_ref, "send", "mcp:calendar");
    effect.has_opted_in = false;
    effect.send_ref = Some("intent:scoped".to_owned());
    effect.scoped_mcp_call = Some(crate::outbound_consent::ScopedMcpCallContext {
        server: "files".to_owned(),
        tool: "read_file".to_owned(),
        payload_data_class: crate::outbound_consent::DataClass::Personal,
        resolved_endpoint: "https://files.internal.example".to_owned(),
    });

    // The first in-scope scoped call charges the rate-1 budget on the
    // synthetic per-grant key.
    let (_, decision, charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy_with_budget(&vault.store, wtxn, &effect, &policy, true)
    })?;
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    assert!(charge.is_some(), "the synthetic governing row was enforced");

    // Discriminating: the rate-1 cap lives on the synthetic per-grant key.
    // Comparing against the raw mcp:calendar channel would miss the cap and
    // let this second in-scope scoped call auto-fire instead of exhausting.
    let (_, decision, _) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy_with_budget(&vault.store, wtxn, &effect, &policy, true)
    })?;
    assert_eq!(decision.outcome(), GateOutcome::Deny);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.deny.effector_budget_exhausted"]
    );
    Ok(())
}

#[test]
fn scoped_mcp_grant_dissolves_only_its_proposed_external_effect_fork() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let herald_id = test_id(0xB7);
    vault.put_agent_definition(
        &herald_id,
        &agent_def_fixture("test.proposed.scoped_mcp", AgentCeiling::Proposed),
        test_time(1),
        1,
    )?;
    put_policy_manifest_bytes(&vault, test_id(0xB8), &encode_policy_manifest(vec![]))?;
    let grant_id = test_id(0xB9);
    vault.mint_scoped_mcp_outbound_grant(
        &grant_id,
        &crate::outbound_grant::ScopedMcpGrantMintIntent {
            principal_ref: herald_id.to_hex(),
            origin_component_id: "ask-mcp".to_owned(),
            origin_action_id: "grant-scoped-mcp".to_owned(),
            origin_receipt_ref: Some("gate:ask-mcp".to_owned()),
            server: "files".to_owned(),
            tool: "read_file".to_owned(),
            data_class_ceiling: crate::outbound_consent::DataClass::Personal,
            endpoint_allowlist: vec!["https://files.internal.example".to_owned()],
        },
        10,
    )?;
    vault.register_connector_key(
        &test_id(0xBA),
        crate::ConnectorKeyRecord::active(
            scoped_mcp_credential_connector_key("files", &grant_id),
            None,
            Vec::new(),
            10,
        ),
    )?;
    let policy = resolve(&vault)?;
    let mut effect = external_effect_gate_input(&herald_id.to_hex(), "send", "mcp:calendar");
    effect.actor.actor_class = "agent".to_owned();
    effect.provenance.actor_entity_ref = Some(herald_id);
    effect.has_opted_in = false;
    effect.scoped_mcp_call = Some(crate::outbound_consent::ScopedMcpCallContext {
        server: "files".to_owned(),
        tool: "read_file".to_owned(),
        payload_data_class: crate::outbound_consent::DataClass::Personal,
        resolved_endpoint: "https://files.internal.example".to_owned(),
    });

    let (_, decision, _) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &effect, &policy, true)
    })?;
    // Discriminating: leaving the earlier actor-ceiling branch unchanged
    // adds PendingActorCeiling despite the verified scoped grant.
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    Ok(())
}

#[test]
fn scoped_mcp_grant_does_not_cross_an_unverified_identity_pair() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xBB), &encode_policy_manifest(vec![]))?;
    let caller_id = test_id(0xBC);
    let grant_owner_id = test_id(0xBD);
    let grant_id = test_id(0xBE);
    vault.mint_scoped_mcp_outbound_grant(
        &grant_id,
        &crate::outbound_grant::ScopedMcpGrantMintIntent {
            principal_ref: grant_owner_id.to_hex(),
            origin_component_id: "ask-mcp".to_owned(),
            origin_action_id: "grant-scoped-mcp".to_owned(),
            origin_receipt_ref: Some("gate:ask-mcp".to_owned()),
            server: "files".to_owned(),
            tool: "read_file".to_owned(),
            data_class_ceiling: crate::outbound_consent::DataClass::Personal,
            endpoint_allowlist: vec!["https://files.internal.example".to_owned()],
        },
        10,
    )?;
    vault.register_connector_key(
        &test_id(0xBF),
        crate::ConnectorKeyRecord::active(
            scoped_mcp_credential_connector_key("files", &grant_id),
            None,
            Vec::new(),
            10,
        ),
    )?;
    let policy = resolve(&vault)?;
    let mut effect = external_effect_gate_input(&caller_id.to_hex(), "send", "mcp:calendar");
    effect.actor.actor_class = "agent".to_owned();
    effect.provenance.actor_entity_ref = Some(grant_owner_id);
    effect.has_opted_in = false;
    effect.scoped_mcp_call = Some(crate::outbound_consent::ScopedMcpCallContext {
        server: "files".to_owned(),
        tool: "read_file".to_owned(),
        payload_data_class: crate::outbound_consent::DataClass::Personal,
        resolved_endpoint: "https://files.internal.example".to_owned(),
    });

    let (_, decision, _) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &effect, &policy, true)
    })?;
    // Discriminating: the caller's own actor_ref is paired with a different
    // entity that owns this in-scope grant; matching either identity would
    // dissolve the Proposed clamp and make this call Allow.
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    Ok(())
}

#[test]
fn standing_outbound_grant_reasks_out_of_scope_stale_and_revoked_sends() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xDA), &encode_policy_manifest(vec![]))?;

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
    let (_decision_id, decision, _effector_charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &out_of_scope, &policy, true)
    })?;
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&decision),
        vec![
            "gate.pending.consent.irreversible_effect",
            "gate.pending.external_effect_authority",
        ]
    );

    let mut lifecycle_effect = external_effect_gate_input("sender", "provision", "line");
    lifecycle_effect.has_opted_in = false;
    let (_decision_id, decision, _effector_charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &lifecycle_effect, &policy, true)
    })?;
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&decision),
        vec![
            "gate.pending.consent.irreversible_effect",
            "gate.pending.external_effect_authority",
        ]
    );

    put_policy_manifest_bytes(&vault, test_id(0xDC), &encode_policy_manifest(vec![]))?;
    let stale_policy = resolve(&vault)?;
    let mut in_scope_stale = external_effect_gate_input("sender", "send", "line");
    in_scope_stale.has_opted_in = false;
    let (_decision_id, decision, _effector_charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &in_scope_stale, &stale_policy, true)
    })?;
    assert_eq!(decision.outcome(), GateOutcome::Pending);

    vault.revoke_standing_outbound_grant(&grant_id, 20)?;
    let mut in_scope_revoked = external_effect_gate_input("sender", "send", "line");
    in_scope_revoked.has_opted_in = false;
    let (_decision_id, decision, _effector_charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &in_scope_revoked, &stale_policy, true)
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
    put_policy_manifest_bytes(&vault, test_id(0xD5), &data)?;
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

    let (_decision_id, decision, _effector_charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &effect, &policy, true)
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
    put_policy_manifest_bytes(&vault, test_id(0xD6), &data)?;
    let policy = resolve(&vault)?;
    let identity = test_id(0xCE);

    let mut normal_effect = external_effect_gate_input("sender", "send", "line");
    normal_effect.channel_identity_ref = Some(identity);
    normal_effect.counterparty = Some("unknown@example.com".to_owned());
    let (_decision_id, decision, _effector_charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &normal_effect, &policy, true)
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
    let (_decision_id, decision, _effector_charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &public_effect, &policy, true)
    })?;
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&decision),
        vec![
            "gate.pending.consent.irreversible_effect",
            "gate.pending.external_effect_authority",
        ]
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
        vec![
            "gate.pending.consent.irreversible_effect",
            "gate.pending.external_effect_authority",
        ]
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
            "gate.pending.consent.irreversible_effect",
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
    put_policy_manifest_bytes(&vault, test_id(0xD1), &data)?;
    let policy = resolve(&vault)?;

    let mut missing_opt_in = external_effect_gate_input("sender", "send", "line");
    missing_opt_in.has_opted_in = false;
    let decision = policy.evaluate_gate(&missing_opt_in.gate_input(None, None));
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.pending.external_effect_authority"]
    );

    let mut missing_permission = external_effect_gate_input("sender", "send", "line");
    missing_permission.has_permission = false;
    let decision = policy.evaluate_gate(&missing_permission.gate_input(None, None));
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
    put_policy_manifest_bytes(
        &pending_vault,
        test_id(0xD2),
        &encode_policy_manifest(vec![]),
    )?;
    let pending_policy = resolve(&pending_vault)?;
    let mut risky = external_effect_gate_input("sender", "send", "line");
    risky.policy_risk = ExternalEffectPolicyRisk::HoldToProposal;

    let decision = pending_policy.evaluate_gate(&risky.gate_input(None, None));
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
    put_policy_manifest_bytes(&allowed_vault, test_id(0xD3), &data)?;
    let allowed_policy = resolve(&allowed_vault)?;
    let decision = allowed_policy.evaluate_gate(&risky.gate_input(None, None));
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
    put_policy_manifest_bytes(&vault, test_id(0xD4), &data)?;
    let policy = resolve(&vault)?;
    let effect = external_effect_gate_input("sender", "send", "line");
    let decision = policy.evaluate_gate(&effect.gate_input(None, None));
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

    let (_decision_id, decision, _effector_charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &effect, &policy, true)
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
    put_policy_manifest_bytes(&vault, test_id(0x51), &data)?;

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
    let body = public_stamped(source_trust_claim(ClaimSource::ToolOutput));
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
    put_policy_manifest_bytes(&vault, test_id(0xB4), &data)?;

    let claim_id = test_id(0xB5);
    let body = public_stamped(source_trust_claim(ClaimSource::ToolOutput));
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
    put_policy_manifest_bytes(&vault, test_id(0xC4), &data)?;

    let claim_id = test_id(0xC5);
    let body = public_stamped(source_trust_claim(ClaimSource::Generated));
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
    put_policy_manifest_bytes(&vault, test_id(0xC6), &data)?;

    let claim_id = test_id(0xC7);
    let body = public_stamped(source_trust_claim(ClaimSource::Generated));
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
    put_policy_manifest_bytes(&vault, test_id(0xB6), &data)?;

    let claim_id = test_id(0xB7);
    let body = public_stamped(source_trust_claim(ClaimSource::ToolOutput));
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
    put_policy_manifest_bytes(&vault, test_id(0xC0), &data)?;
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
        put_policy_manifest_bytes(&vault, test_id(seed), &data)?;

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
    put_policy_manifest_bytes(&unknown_vault, test_id(0xB9), &data)?;

    let unknown_claim = test_id(0xBA);
    let body = public_stamped(source_trust_claim(ClaimSource::ToolOutput));
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
    put_policy_manifest_bytes(&revoked_vault, test_id(0xBC), &revoked_policy)?;

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
    put_policy_manifest_bytes(&vault, test_id(0xBE), &data)?;
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
    put_policy_manifest_bytes(&revoked_vault, test_id(0xBF), &revoked_data)?;
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
    put_policy_manifest_bytes(&vault, test_id(0x84), &data)?;

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
    put_policy_manifest_bytes(&vault, test_id(0x90), &encode_policy_manifest(vec![]))?;

    let id = test_id(0x91);
    let body = source_trust_claim(ClaimSource::UserStated);
    let (candidate, envelope) = claim_candidate_write_parts(&vault, &body)?;

    let metric_emissions_before = gate_metric_emission_count_for_test();
    let err = vault
        .batch()
        .claim_candidate(&id, candidate, &envelope, test_time(3), 3)
        .commit()
        .expect_err("pending auto write must be rejected");
    assert_gate_rejected(err, "pending", &["gate.pending.actor_ceiling"]);
    assert_eq!(
        gate_metric_emission_count_for_test(),
        metric_emissions_before + 1,
        "a committed denial receipt must emit exactly one decision metric"
    );
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
        put_policy_manifest_bytes(&vault, test_id(0x92), &encode_policy_manifest(vec![]))?;

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
fn retraction_closes_custom_policy_pending_without_rebinding_or_reparking() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x97), &encode_policy_manifest(vec![]))?;

    let id = test_id(0x98);
    let mut proposed = source_trust_claim(ClaimSource::UserStated);
    proposed.approval = ClaimApprovalStatus::Proposed;
    let (candidate, envelope) = claim_candidate_write_parts(&vault, &proposed)?;
    vault
        .batch()
        .claim_candidate(&id, candidate, &envelope, test_time(3), 3)
        .commit()?;

    let pending = vault.with_write_txn(|wtxn| {
        vault
            .store
            .pending_gate_consent_in_txn(wtxn, &id)?
            .ok_or(Error::CorruptedIndex("pending gate consent"))
    })?;
    vault.retract_claim(&id, 4)?;

    let retracted = vault.get_claim(&id)?.expect("retracted claim remains");
    assert_eq!(retracted.lifecycle, ClaimLifecycleStatus::Retracted);
    assert!(!has_pending_gate_consent(&vault, &id)?);
    let closure = vault
        .store
        .gate_decisions(10)?
        .into_iter()
        .find(|record| record.outcome == "retracted")
        .expect("terminal retraction receipt");
    assert_eq!(closure.claim_id, Some(*id.as_bytes()));
    assert_eq!(closure.reason_codes, vec!["gate.pending.claim_retracted"]);
    assert_eq!(closure.diff_handle, pending.diff_handle);
    assert_eq!(closure.read_frontier_hash, pending.read_frontier_hash);
    Ok(())
}

#[test]
fn pending_gate_consent_groups_interleaved_dreamer_runs_with_default_lane() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xA0), &encode_policy_manifest(vec![]))?;

    let run_a = "dreamer-run-a";
    let run_b = "dreamer-run-b";
    // 0x81..0x85: [0xA1; 16]..[0xA5; 16] are write-door-reserved system-agent
    // actor ids (ONE-1444).
    let run_a_first = test_id(0x81);
    let run_b_first = test_id(0x82);
    let default_id = test_id(0x83);
    let run_a_second = test_id(0x84);
    let run_b_second = test_id(0x85);

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
    put_policy_manifest_bytes(&vault, test_id(0x94), &encode_policy_manifest(vec![]))?;

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
    put_policy_manifest_bytes(&vault, test_id(0xD6), &data)?;

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
    put_policy_manifest_bytes(&vault, test_id(0x96), &encode_policy_manifest(vec![]))?;

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
fn session_bundle_review_merge() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let reviewer_id = test_id(0xC8);
    let mut policy = encode_policy_manifest(vec![]);
    append_actor_ceiling(
        &mut policy,
        actor_ceiling_row_for_ref("human", &reviewer_id.to_hex(), "auto"),
    );
    put_policy_manifest_bytes(&vault, test_id(0xC2), &policy)?;
    vault.put_entity(
        &reviewer_id,
        ENTITY_TYPE_PERSON,
        test_time(1),
        1,
        b"session bundle reviewer",
    )?;
    let reviewer = WriteActor::new(reviewer_id, EdgeActorClass::Human);
    let producer = test_id(0x20);

    let session_tag = "agent:alpha/session:42";
    let first = test_id(0xC3);
    let second = test_id(0xC4);
    for (id, learned_at) in [(first, 3), (second, 4)] {
        let mut proposed = source_trust_claim(ClaimSource::UserStated);
        proposed.approval = ClaimApprovalStatus::Proposed;
        let (candidate, envelope) = claim_candidate_write_parts(&vault, &proposed)?;
        vault
            .batch()
            .claim_candidate(
                &id,
                candidate,
                &envelope.with_session_tag(session_tag),
                test_time(learned_at),
                learned_at,
            )
            .commit()?;
    }

    let review = vault.review_session_bundle(&reviewer, &producer, session_tag)?;
    assert_eq!(review.session_tag, session_tag);
    assert_eq!(
        review
            .claims
            .iter()
            .map(|claim| claim.id)
            .collect::<Vec<_>>(),
        vec![first, second]
    );
    assert!(
        review
            .claims
            .iter()
            .all(|claim| claim.body.approval == ClaimApprovalStatus::Proposed)
    );

    let metric_emissions_before = gate_metric_emission_count_for_test();
    let merged = vault.merge_session_bundle(&reviewer, &producer, session_tag)?;
    assert_eq!(
        gate_metric_emission_count_for_test(),
        metric_emissions_before + 2,
        "committed bundle decisions must emit metrics exactly once per member"
    );
    assert!(
        merged
            .claims
            .iter()
            .all(|claim| claim.body.approval == ClaimApprovalStatus::Approved)
    );
    assert!(
        merged
            .claims
            .iter()
            .all(|claim| claim.body.session_tag.as_deref() == Some(session_tag))
    );
    assert!(
        merged
            .claims
            .iter()
            .all(|claim| crate::claim::session_claim_producer(&claim.body) == Some(producer))
    );
    assert_eq!(
        vault
            .get_claim(&first)?
            .expect("first merged claim")
            .approval,
        ClaimApprovalStatus::Approved
    );
    assert_eq!(
        vault
            .get_claim(&second)?
            .expect("second merged claim")
            .approval,
        ClaimApprovalStatus::Approved
    );
    assert!(!has_pending_gate_consent(&vault, &first)?);
    assert!(!has_pending_gate_consent(&vault, &second)?);
    assert!(
        vault
            .review_session_bundle(&reviewer, &producer, session_tag)?
            .claims
            .is_empty()
    );
    Ok(())
}

#[test]
fn session_bundle_review_and_merge_reject_unauthorized_caller_with_fresh_consent() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let authorized_id = test_id(0xCC);
    let mut policy = encode_policy_manifest(vec![]);
    append_actor_ceiling(
        &mut policy,
        actor_ceiling_row_for_ref("human", &authorized_id.to_hex(), "auto"),
    );
    put_policy_manifest_bytes(&vault, test_id(0xC9), &policy)?;

    let session_tag = "agent:alpha/session:unauthorized";
    let id = test_id(0xCA);
    let mut proposed = source_trust_claim(ClaimSource::UserStated);
    proposed.approval = ClaimApprovalStatus::Proposed;
    let (candidate, envelope) = claim_candidate_write_parts(&vault, &proposed)?;
    let producer = envelope.actor().entity_ref();
    let unauthorized_id = test_id(0xCB);
    vault.put_entity(
        &unauthorized_id,
        ENTITY_TYPE_PERSON,
        test_time(1),
        1,
        b"unrelated valid session bundle caller",
    )?;
    let unauthorized = WriteActor::new(unauthorized_id, EdgeActorClass::Human);
    vault
        .batch()
        .claim_candidate(
            &id,
            candidate,
            &envelope.with_session_tag(session_tag),
            test_time(3),
            3,
        )
        .commit()?;
    assert!(has_pending_gate_consent(&vault, &id)?);

    let err = vault
        .review_session_bundle(&unauthorized, &producer, session_tag)
        .expect_err("proposed claim bodies must not be disclosed to an unauthorized caller");
    assert_gate_rejected(err, "pending", &["gate.pending.actor_ceiling"]);

    let err = vault
        .merge_session_bundle(&unauthorized, &producer, session_tag)
        .expect_err("fresh consent must not elevate an unauthorized caller");
    assert_gate_rejected(err, "pending", &["gate.pending.actor_ceiling"]);
    assert_eq!(
        vault.get_claim(&id)?.expect("proposal").approval,
        ClaimApprovalStatus::Proposed
    );
    assert!(has_pending_gate_consent(&vault, &id)?);
    Ok(())
}

// A forged top-level actor_entity_ref cannot survive any local write path: envelope
// writes rebuild evidence from the envelope (write_envelope_evidence), and raw claim
// puts are rejected before the producer-binding check even runs. The producer==envelope
// check in batch.rs stays as defense-in-depth for future paths that preserve caller
// evidence; the reachable rejection is the raw-put guard asserted here.
#[test]
fn session_tagged_raw_claim_rejects_a_spoofed_producer_stamp() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let id = test_id(0xD6);
    let spoofed_producer = test_id(0x5D);
    let mut body = source_trust_claim(ClaimSource::UserStated);
    body.approval = ClaimApprovalStatus::Proposed;
    body.session_tag = Some("agent:spoofed/session:tag".to_owned());
    body.evidence = Some(Value::Map(vec![(
        Value::from(crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY),
        Value::Binary(spoofed_producer.as_bytes().to_vec()),
    )]));
    let data = crate::claim::encode_claim_body(&body)?;

    let err = vault
        .put_entity(&id, ENTITY_TYPE_CLAIM, test_time(3), 3, &data)
        .expect_err("raw claim writes must not self-assert a session producer");
    assert!(
        matches!(
            err,
            Error::InvalidClaimBody("raw claim put requires WriteEnvelope")
        ),
        "unexpected error: {err:?}"
    );
    assert!(vault.get_raw(&id)?.is_none());
    Ok(())
}

#[test]
fn session_bundle_excludes_same_tag_claims_from_another_producer() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let reviewer_id = test_id(0xD0);
    let producer_a = test_id(0xD1);
    let producer_b = test_id(0xD2);
    let mut policy = encode_policy_manifest(vec![]);
    append_actor_ceiling(
        &mut policy,
        actor_ceiling_row_for_ref("human", &reviewer_id.to_hex(), "auto"),
    );
    put_policy_manifest_bytes(&vault, test_id(0xD3), &policy)?;
    vault.put_entity(
        &reviewer_id,
        ENTITY_TYPE_PERSON,
        test_time(1),
        1,
        b"session bundle reviewer",
    )?;
    let reviewer = WriteActor::new(reviewer_id, EdgeActorClass::Human);

    let session_tag = "agent:shared/session:collision";
    let first = test_id(0xD4);
    let injected = test_id(0xD5);
    for (id, producer, learned_at) in [(first, producer_a, 3), (injected, producer_b, 4)] {
        let mut proposed = source_trust_claim(ClaimSource::UserStated);
        proposed.approval = ClaimApprovalStatus::Proposed;
        let (candidate, envelope) = claim_candidate_write_parts_for_actor(
            &vault,
            &proposed,
            producer,
            EdgeActorClass::Human,
        )?;
        vault
            .batch()
            .claim_candidate(
                &id,
                candidate,
                &envelope.with_session_tag(session_tag),
                test_time(learned_at),
                learned_at,
            )
            .commit()?;
    }

    let review = vault.review_session_bundle(&reviewer, &producer_a, session_tag)?;
    assert_eq!(
        review
            .claims
            .iter()
            .map(|claim| claim.id)
            .collect::<Vec<_>>(),
        vec![first],
        "a raw session-tag collision must not inject another actor's claim"
    );

    let merged = vault.merge_session_bundle(&reviewer, &producer_a, session_tag)?;
    assert_eq!(
        merged
            .claims
            .iter()
            .map(|claim| claim.id)
            .collect::<Vec<_>>(),
        vec![first]
    );
    assert_eq!(
        vault
            .get_claim(&first)?
            .expect("first producer claim")
            .approval,
        ClaimApprovalStatus::Approved
    );
    assert_eq!(
        vault
            .get_claim(&injected)?
            .expect("second producer claim")
            .approval,
        ClaimApprovalStatus::Proposed,
        "the colliding second-producer claim must not be approved"
    );
    Ok(())
}

#[test]
fn atomic_bundle_commit() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let reviewer_id = test_id(0xC9);
    let mut policy = encode_policy_manifest(vec![]);
    append_actor_ceiling(
        &mut policy,
        actor_ceiling_row_for_ref("human", &reviewer_id.to_hex(), "auto"),
    );
    put_policy_manifest_bytes(&vault, test_id(0xC5), &policy)?;
    vault.put_entity(
        &reviewer_id,
        ENTITY_TYPE_PERSON,
        test_time(1),
        1,
        b"session bundle reviewer",
    )?;
    let reviewer = WriteActor::new(reviewer_id, EdgeActorClass::Human);
    let producer = test_id(0x20);

    let session_tag = "agent:alpha/session:atomic";
    let first = test_id(0xC6);
    let second = test_id(0xC7);
    for (id, learned_at) in [(first, 3), (second, 4)] {
        let mut proposed = source_trust_claim(ClaimSource::UserStated);
        proposed.approval = ClaimApprovalStatus::Proposed;
        let (candidate, envelope) = claim_candidate_write_parts(&vault, &proposed)?;
        vault
            .batch()
            .claim_candidate(
                &id,
                candidate,
                &envelope.with_session_tag(session_tag),
                test_time(learned_at),
                learned_at,
            )
            .commit()?;
    }

    vault.with_write_txn(|wtxn| {
        let mut pending = vault
            .store
            .pending_gate_consent_in_txn(wtxn, &second)?
            .ok_or(Error::CorruptedIndex("pending gate consent"))?;
        pending.diff_handle = vec![0xFF];
        vault.store.put_pending_gate_consent_in_txn(wtxn, &pending)
    })?;

    let metric_emissions_before = gate_metric_emission_count_for_test();
    let err = vault
        .merge_session_bundle(&reviewer, &producer, session_tag)
        .expect_err("a stale member must abort the whole session bundle");
    assert!(matches!(err, Error::GateConsentStale { claim_id } if claim_id == second));
    assert_eq!(
        vault.get_claim(&first)?.expect("first proposal").approval,
        ClaimApprovalStatus::Proposed
    );
    assert_eq!(
        vault.get_claim(&second)?.expect("second proposal").approval,
        ClaimApprovalStatus::Proposed
    );
    assert!(has_pending_gate_consent(&vault, &first)?);
    assert!(has_pending_gate_consent(&vault, &second)?);
    assert_eq!(
        gate_metric_emission_count_for_test(),
        metric_emissions_before,
        "rolled-back bundle decisions must not emit gate metrics"
    );
    Ok(())
}

#[test]
fn same_batch_proposed_then_approved_rejects_without_pending_consent() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x98), &encode_policy_manifest(vec![]))?;

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
    let decisions = vault.store.gate_decisions(10)?;
    assert_eq!(
        decisions.len(),
        1,
        "rejected batch must persist only the rejecting gate decision"
    );
    assert_eq!(decisions[0].claim_id, Some(*id.as_bytes()));
    assert_eq!(decisions[0].outcome, "pending");
    Ok(())
}

#[test]
fn gate_chokepoint_batch_claim_denial_aborts_without_partial_writes() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut data = encode_policy_manifest(vec![]);
    trust_human_candidate_actor(&mut data);
    put_policy_manifest_bytes(&vault, test_id(0x76), &data)?;

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
    put_policy_manifest_bytes(&vault, test_id(0x95), &data)?;

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
    put_policy_manifest_bytes(&vault, test_id(0x97), &data)?;

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
    put_policy_manifest_bytes(&vault, test_id(0x79), &data)?;

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
    put_policy_manifest_bytes(&vault, test_id(0x94), &data)?;

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

    // 0x94/0x95: [0xA4; 16]/[0xA5; 16] are write-door-reserved system-agent
    // actor ids (ONE-1444).
    let src = test_id(0x94);
    let tgt = test_id(0x95);
    let human_actor = test_id(0xD6);
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
    put_policy_manifest_bytes(&vault, test_id(0xAA), &policy)?;

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
    put_policy_manifest_bytes(&vault, test_id(0x52), b"not-msgpack")?;

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
        put_policy_manifest_bytes(&vault, test_id(seed), &data)?;

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
    put_policy_manifest_bytes(&vault, test_id(0x54), &data)?;

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
    put_policy_manifest_bytes(&vault, test_id(0x53), &data)?;

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
    put_policy_manifest_bytes(&vault, test_id(0x55), &data)?;

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
    put_policy_manifest_bytes(&vault, test_id(0x87), &strict_policy)?;

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
    put_policy_manifest_bytes(&vault, test_id(0x8A), &data)?;

    let id = test_id(0x8B);
    let remote_body = public_stamped(source_trust_claim(ClaimSource::ToolOutput));
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
    put_policy_manifest_bytes(&vault, test_id(0x80), &data)?;

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

// --- GOV-01 connector-key effector budgets (ONE-1416) ------------------------

fn connector_key_line_send_manifest() -> Vec<u8> {
    encode_policy_manifest(vec![external_effect_scoped_grant_entry(
        "sender",
        "external:send",
        Value::Map(vec![(
            Value::from(EXTERNAL_EFFECT_SCOPE_CHANNEL_KEY),
            Value::from("line"),
        )]),
        None,
    )])
}

fn connector_key_two_verb_manifest(channel: &str) -> Vec<u8> {
    let grant_row = |effector: String| {
        Value::Map(vec![
            (Value::from(ACTOR_REF_KEY), Value::from("sender")),
            (Value::from(GRANT_EFFECTOR_KEY), Value::from(effector)),
            (
                Value::from(GRANT_SCOPE_KEY),
                Value::Map(vec![(
                    Value::from(EXTERNAL_EFFECT_SCOPE_CHANNEL_KEY),
                    Value::from(channel),
                )]),
            ),
        ])
    };
    encode_policy_manifest(vec![(
        Value::from(POLICY_SCOPED_GRANTS_KEY),
        Value::Array(vec![
            grant_row("external:send".to_owned()),
            grant_row("external:provision".to_owned()),
        ]),
    )])
}

fn check_effect(
    vault: &crate::Vault,
    effect: &ExternalEffectGateInput,
    policy: &PolicyManifestResolution,
) -> Result<(GateDecision, Option<crate::EffectorBudgetCharge>)> {
    let (_decision_id, decision, charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy_with_budget(&vault.store, wtxn, effect, policy, true)
    })?;
    Ok((decision, charge))
}

fn day_window() -> crate::EffectorBudgetWindow {
    crate::EffectorBudgetWindow::Calendar {
        period: crate::CalendarPeriod::Day,
        tz: None,
    }
}

#[test]
fn connector_key_unset_is_noop_and_empty_budget_key_is_equivalent() -> Result<()> {
    let run = |with_key: bool| -> Result<(
        GateDecision,
        Option<crate::EffectorBudgetCharge>,
        crate::store::GateDecisionRecord,
    )> {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(&vault, test_id(0xD0), &connector_key_line_send_manifest())?;
        if with_key {
            vault.register_connector_key(
                &test_id(0x77),
                crate::ConnectorKeyRecord::active("line", None, Vec::new(), 1_000),
            )?;
        }
        let policy = resolve(&vault)?;
        let effect = external_effect_gate_input("sender", "send", "line");
        let (decision, charge) = check_effect(&vault, &effect, &policy)?;
        let record = vault
            .store
            .gate_decisions(10)?
            .into_iter()
            .find(|record| record.content_kind == "external_effect")
            .expect("dispatch decision record");
        Ok((decision, charge, record))
    };

    let (no_key_decision, no_key_charge, no_key_record) = run(false)?;
    let (keyed_decision, keyed_charge, keyed_record) = run(true)?;

    // Decision, reason codes, and receipt reasons are identical; the only
    // difference is the (dropped-in-GOV-01) charge: None vs empty NoRows.
    assert_eq!(no_key_decision, keyed_decision);
    assert_eq!(no_key_decision.outcome(), GateOutcome::Allow);
    assert!(no_key_charge.is_none());
    let keyed_charge = keyed_charge.expect("budget stage ran under a governing key");
    assert!(keyed_charge.read.rows.is_empty());
    assert!(keyed_charge.matched_rows.is_empty());
    assert!(keyed_charge.ladder_events.is_empty());
    assert_eq!(keyed_charge.sends_debit, 0);

    assert_eq!(no_key_record.outcome, keyed_record.outcome);
    assert_eq!(no_key_record.reason_codes, keyed_record.reason_codes);
    assert_eq!(no_key_record.receipt_reasons, keyed_record.receipt_reasons);
    Ok(())
}

#[test]
fn connector_key_rate_refuse_denies_third_call_and_keeps_key_active() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xD0), &connector_key_line_send_manifest())?;
    let key_id = test_id(0x71);
    vault.register_connector_key(
        &key_id,
        crate::ConnectorKeyRecord::active(
            "line",
            None,
            vec![crate::EffectorBudget::rate(2, 3_600)],
            1_000,
        ),
    )?;
    let policy = resolve(&vault)?;
    let effect = external_effect_gate_input("sender", "send", "line");

    for _ in 0..2 {
        let (decision, charge) = check_effect(&vault, &effect, &policy)?;
        assert_eq!(decision.outcome(), GateOutcome::Allow);
        assert!(charge.is_some());
    }
    let (decision, charge) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(decision.outcome(), GateOutcome::Deny);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.deny.effector_budget_exhausted"]
    );
    assert!(
        decision
            .receipt_reasons()
            .contains(&"effector_budget_exhausted")
    );
    let charge = charge.expect("exhaustion still returns the charge");
    assert_eq!(charge.read.rows[0].used, 2);
    assert_eq!(charge.read.rows[0].remaining, 0);
    assert_eq!(charge.sends_debit, 0);
    // on_exhaust: refuse leaves the key Active.
    assert_eq!(
        vault.get_connector_key(&key_id)?.expect("key").status,
        crate::ConnectorKeyStatus::Active
    );
    Ok(())
}

#[test]
fn connector_key_lifecycle_effect_debits_rate_not_sends() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0xD0),
        &connector_key_two_verb_manifest("line"),
    )?;
    let key_id = test_id(0x72);
    vault.register_connector_key(
        &key_id,
        crate::ConnectorKeyRecord::active(
            "line",
            None,
            vec![
                crate::EffectorBudget::sends(
                    1,
                    day_window(),
                    crate::EffectorBudgetOnExhaust::Suspend,
                ),
                crate::EffectorBudget::rate(1, 3_600),
            ],
            1_000,
        ),
    )?;
    let policy = resolve(&vault)?;
    // A channel-identity-lifecycle-shaped effect: send_ref None.
    let lifecycle_effect = external_effect_gate_input("sender", "provision", "line");
    assert!(lifecycle_effect.send_ref.is_none());

    let (decision, charge) = check_effect(&vault, &lifecycle_effect, &policy)?;
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    let charge = charge.expect("budget stage ran");
    assert_eq!(
        charge.sends_debit, 0,
        "lifecycle ops never eat a sends budget"
    );
    assert_eq!(charge.read.rows[0].used, 0, "sends row undebited");
    assert_eq!(charge.read.rows[1].used, 1, "rate row debited");

    // The rate row (limit 1) is now exhausted for the next lifecycle op —
    // the sends row (limit 1) is not.
    let (decision, _charge) = check_effect(&vault, &lifecycle_effect, &policy)?;
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.deny.effector_budget_exhausted"]
    );
    assert_eq!(
        vault.get_connector_key(&key_id)?.expect("key").status,
        crate::ConnectorKeyStatus::Active,
        "the exhausted row is the refuse-class rate row, not the suspend-class sends row"
    );
    Ok(())
}

#[test]
fn connector_key_exact_at_limit_admits_then_refuses() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xD0), &connector_key_line_send_manifest())?;
    vault.register_connector_key(
        &test_id(0x73),
        crate::ConnectorKeyRecord::active(
            "line",
            None,
            vec![crate::EffectorBudget::sends(
                1,
                day_window(),
                crate::EffectorBudgetOnExhaust::Refuse,
            )],
            1_000,
        ),
    )?;
    let policy = resolve(&vault)?;
    let mut effect = external_effect_gate_input("sender", "send", "line");
    effect.send_ref = Some("intent:one".to_owned());

    // used + amount == limit admits and exhausts the row.
    let (decision, charge) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    let charge = charge.expect("charged");
    assert_eq!(charge.sends_debit, 1);
    assert_eq!(charge.read.rows[0].used, 1);
    assert_eq!(charge.read.rows[0].remaining, 0);
    assert_eq!(charge.read.rows[0].percent_used, 100);

    let (decision, _charge) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.deny.effector_budget_exhausted"]
    );
    Ok(())
}

#[test]
fn connector_key_exhaustion_and_suspension_increment_effector_budget_metrics() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xD0), &connector_key_line_send_manifest())?;
    let key_id = test_id(0x74);
    vault.register_connector_key(
        &key_id,
        crate::ConnectorKeyRecord::active(
            "line",
            None,
            vec![crate::EffectorBudget::sends(
                1,
                day_window(),
                crate::EffectorBudgetOnExhaust::Suspend,
            )],
            1_000,
        ),
    )?;
    let policy = resolve(&vault)?;
    let mut effect = external_effect_gate_input("sender", "send", "line");
    effect.send_ref = Some("intent:one".to_owned());

    let before =
        gate_metrics_snapshot().count(GateOutcome::Deny, GateMetricReasonClass::EffectorBudget);
    let (allowed, _) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(allowed.outcome(), GateOutcome::Allow);
    // Exhaustion deny (flips the key Suspended) + status-wall deny.
    let (exhausted, _) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(
        gate_reason_strs(&exhausted),
        vec!["gate.deny.effector_budget_exhausted"]
    );
    let (walled, _) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(
        gate_reason_strs(&walled),
        vec!["gate.deny.connector_key_suspended"]
    );
    let after =
        gate_metrics_snapshot().count(GateOutcome::Deny, GateMetricReasonClass::EffectorBudget);
    assert!(
        after >= before + 2,
        "expected >= 2 new EffectorBudget deny counts, before {before} after {after}"
    );
    Ok(())
}

#[test]
fn connector_key_revoked_tuple_resolution_after_reregister() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xD0), &connector_key_line_send_manifest())?;
    // The fixture effect's provenance actor.
    let actor = test_id(0xE0);
    let key_a = test_id(0x75);
    vault.register_connector_key(
        &key_a,
        crate::ConnectorKeyRecord::active(
            "line",
            Some(actor),
            vec![crate::EffectorBudget::sends(
                1,
                day_window(),
                crate::EffectorBudgetOnExhaust::Suspend,
            )],
            1_000,
        ),
    )?;
    vault.revoke_connector_key(&key_a, 1_010)?;
    let key_b = test_id(0x76);
    vault.register_connector_key(
        &key_b,
        crate::ConnectorKeyRecord::active(
            "line",
            Some(actor),
            vec![crate::EffectorBudget::sends(
                2,
                day_window(),
                crate::EffectorBudgetOnExhaust::Suspend,
            )],
            1_011,
        ),
    )?;
    let policy = resolve(&vault)?;
    let mut effect = external_effect_gate_input("sender", "send", "line");
    effect.send_ref = Some("intent:one".to_owned());

    // The non-revoked record wins within the tuple: key B governs and debits.
    let (decision, charge) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    let charge = charge.expect("key B charged");
    assert_eq!(charge.key_ref, key_b);
    assert_eq!(charge.read.rows[0].used, 1);
    assert_eq!(charge.read.rows[0].limit, 2);

    // A revoked-only tuple still resolves to the status wall.
    vault.revoke_connector_key(&key_b, 1_020)?;
    let (decision, charge) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.deny.connector_key_suspended"]
    );
    assert!(
        decision
            .receipt_reasons()
            .contains(&"connector_key_revoked")
    );
    assert!(
        charge.is_none(),
        "the status wall never reaches the budget stage"
    );
    Ok(())
}

#[test]
fn connector_key_normalization_governs_hyphenated_channel() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0xD0),
        &encode_policy_manifest(vec![external_effect_scoped_grant_entry(
            "sender",
            "external:send",
            Value::Map(vec![(
                Value::from(EXTERNAL_EFFECT_SCOPE_CHANNEL_KEY),
                Value::from("slack-chat"),
            )]),
            None,
        )]),
    )?;
    // Registered with the messy owner-typed connector string.
    vault.register_connector_key(
        &test_id(0x78),
        crate::ConnectorKeyRecord::active(
            " Slack-Chat ",
            None,
            vec![crate::EffectorBudget::rate(5, 60)],
            1_000,
        ),
    )?;
    let policy = resolve(&vault)?;
    // The dispatched effect carries the raw hyphenated channel.
    let effect = external_effect_gate_input("sender", "send", "slack-chat");
    let (decision, charge) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    let charge = charge.expect("normalized connector governs the effect");
    assert_eq!(charge.read.rows[0].used, 1);
    Ok(())
}

// --- GOV-02 budget legibility (ONE-1418) --------------------------------------

#[test]
fn exhaustion_charge_carries_history_read_only() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xD0), &connector_key_line_send_manifest())?;
    vault.register_connector_key(
        &test_id(0x79),
        crate::ConnectorKeyRecord::active(
            "line",
            None,
            vec![crate::EffectorBudget::sends(
                1,
                day_window(),
                crate::EffectorBudgetOnExhaust::Refuse,
            )],
            1_000,
        ),
    )?;
    let policy = resolve(&vault)?;
    let mut effect = external_effect_gate_input("sender", "send", "line");
    effect.send_ref = Some("intent:one".to_owned());

    // Limit 1: the single admitted send crosses 50/80/95 at once.
    let (decision, charge) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    let charge = charge.expect("charged");
    let fired: Vec<_> = charge
        .ladder_events
        .iter()
        .map(|event| event.threshold)
        .collect();
    assert_eq!(
        fired,
        vec![
            crate::BudgetThreshold::Silent50,
            crate::BudgetThreshold::Plan80,
            crate::BudgetThreshold::Land95,
        ]
    );

    // The refused retries fire NOTHING new (carry-read-only, M5b): the
    // signal history rides the read's fired_thresholds, so the hard cut is
    // never signal-silent — and never signal-spammy.
    for _ in 0..2 {
        let (decision, charge) = check_effect(&vault, &effect, &policy)?;
        assert_eq!(decision.outcome(), GateOutcome::Deny);
        let charge = charge.expect("exhaustion charge");
        assert!(charge.ladder_events.is_empty());
        assert_eq!(
            charge.read.rows[0].fired_thresholds,
            vec![
                crate::BudgetThreshold::Silent50,
                crate::BudgetThreshold::Plan80,
                crate::BudgetThreshold::Land95,
            ]
        );
    }
    Ok(())
}

#[test]
fn effector_budget_read_is_pure_and_charges_see_unchanged_state() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xD0), &connector_key_line_send_manifest())?;
    vault.register_connector_key(
        &test_id(0x7A),
        crate::ConnectorKeyRecord::active(
            "line",
            None,
            vec![crate::EffectorBudget::sends(
                2,
                day_window(),
                crate::EffectorBudgetOnExhaust::Refuse,
            )],
            1_000,
        ),
    )?;
    let policy = resolve(&vault)?;
    let mut effect = external_effect_gate_input("sender", "send", "line");
    effect.send_ref = Some("intent:one".to_owned());

    // First send debits to 50% and fires Silent50 (persisted).
    let (_, charge) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(charge.expect("charged").ladder_events.len(), 1);

    // Two consecutive reads agree and write nothing.
    let first = vault
        .effector_budget_read("line", None)?
        .expect("governing key");
    let second = vault
        .effector_budget_read("line", None)?
        .expect("governing key");
    assert_eq!(first, second);
    assert_eq!(first.rows[0].used, 1);
    assert_eq!(
        first.rows[0].fired_thresholds,
        vec![crate::BudgetThreshold::Silent50]
    );

    // A subsequent charge sees the fired state unchanged by the reads:
    // Silent50 does NOT re-fire; the 100% crossing fires Plan80 + Land95.
    let (_, charge) = check_effect(&vault, &effect, &policy)?;
    let fired: Vec<_> = charge
        .expect("charged")
        .ladder_events
        .iter()
        .map(|event| event.threshold)
        .collect();
    assert_eq!(
        fired,
        vec![
            crate::BudgetThreshold::Plan80,
            crate::BudgetThreshold::Land95
        ]
    );
    Ok(())
}

#[test]
fn gate_ledger_accepts_only_pinned_receipt_reason_prefix_families() {
    let (_tmp, vault) = temp_vault();
    let append = |reason: &str| -> Result<()> {
        vault.with_write_txn(|wtxn| {
            vault.store.append_gate_decision_in_txn(
                wtxn,
                &GateDecisionRecord {
                    version: 0,
                    decision_id: GateDecisionId::now(),
                    created_at: 1,
                    outcome: "deny".to_owned(),
                    reason_codes: vec!["gate.deny.effector_budget_exhausted".to_owned()],
                    receipt_reasons: vec![reason.to_owned()],
                    system_notices: Vec::new(),
                    actor_class: "first_party".to_owned(),
                    actor_ref: None,
                    content_kind: "external_effect".to_owned(),
                    policy_manifest_version: POLICY_SCHEMA_VERSION.to_owned(),
                    claim_id: None,
                    grant_ref: None,
                    diff_handle: vec![0xAA],
                    read_frontier_hash: [0; 32],
                    redacted_at: None,
                },
            )
        })
    };

    for accepted in [
        "counterparty_opt_out",
        "connector_key_suspended",
        "effector_budget_exhausted",
        "charter_drift",
    ] {
        append(accepted).unwrap_or_else(|error| panic!("{accepted} must be accepted: {error}"));
    }
    for rejected in [
        // Unknown prefix family.
        "foo_bar",
        // Family prefix but charset rules still bind.
        "connector_key_SUSPENDED",
        "charter_drift.extra",
        // Reason-code namespace never leaks into receipt reasons.
        "gate.connector_key.register",
    ] {
        assert!(
            matches!(append(rejected), Err(Error::CorruptedIndex(_))),
            "{rejected} must be rejected"
        );
    }
}

#[test]
fn budget_stage_skips_dispatches_not_admitted_for_execution() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xD0), &connector_key_line_send_manifest())?;
    let key_id = test_id(0x7F);
    vault.register_connector_key(
        &key_id,
        crate::ConnectorKeyRecord::active(
            "line",
            None,
            vec![crate::EffectorBudget::sends(
                1,
                day_window(),
                crate::EffectorBudgetOnExhaust::Suspend,
            )],
            1_000,
        ),
    )?;
    let policy = resolve(&vault)?;
    let mut effect = external_effect_gate_input("sender", "send", "line");
    effect.send_ref = Some("intent:one".to_owned());

    // A dispatch the pipeline will park (window Hold / seat-policy stop)
    // passes the gate but neither debits nor exhausts.
    let (_id, decision, charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy_with_budget(&vault.store, wtxn, &effect, &policy, false)
    })?;
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    assert!(charge.is_none(), "no budget stage without execution");

    // The un-admitted pass left the budget untouched: the one allowed send
    // still fits, and only after IT does the key exhaust.
    let (_id, decision, charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy_with_budget(&vault.store, wtxn, &effect, &policy, true)
    })?;
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    assert_eq!(charge.expect("charged").read.rows[0].used, 1);

    // The status wall is governance, not accounting: it still converts a
    // non-admitted dispatch once the key is suspended.
    vault.suspend_connector_key(&key_id, "owner", 2_000)?;
    let (_id, decision, charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy_with_budget(&vault.store, wtxn, &effect, &policy, false)
    })?;
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.deny.connector_key_suspended"]
    );
    assert!(charge.is_none());
    Ok(())
}

#[test]
fn ladder_events_carry_the_firing_row_identity() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xD0), &connector_key_line_send_manifest())?;
    vault.register_connector_key(
        &test_id(0x81),
        crate::ConnectorKeyRecord::active(
            "line",
            None,
            vec![
                crate::EffectorBudget::sends(
                    10,
                    day_window(),
                    crate::EffectorBudgetOnExhaust::Refuse,
                ),
                crate::EffectorBudget::rate(10, 3_600),
            ],
            1_000,
        ),
    )?;
    let policy = resolve(&vault)?;
    let mut effect = external_effect_gate_input("sender", "send", "line");
    effect.send_ref = Some("intent:one".to_owned());

    let fired_rows = |events: &[crate::BudgetLadderEvent]| {
        let mut rows: Vec<_> = events.iter().map(|event| event.row_index).collect();
        rows.sort_unstable();
        rows
    };

    // Both rows debit every send; the 5th crosses 50% on both. Two events,
    // one per firing row, with DISTINCT row ids — not two indistinguishable
    // duplicates a steering consumer could neither dedupe nor attribute.
    for _ in 0..4 {
        let (_, charge) = check_effect(&vault, &effect, &policy)?;
        assert!(charge.expect("charged").ladder_events.is_empty());
    }
    let (_, charge) = check_effect(&vault, &effect, &policy)?;
    let events = charge.expect("charged").ladder_events;
    assert_eq!(events.len(), 2);
    assert!(
        events
            .iter()
            .all(|event| event.threshold == crate::BudgetThreshold::Silent50)
    );
    assert_eq!(fired_rows(&events), vec![Some(0), Some(1)]);

    // The 8th crosses 80% on both rows — again uniquely attributable.
    for _ in 0..2 {
        let (_, charge) = check_effect(&vault, &effect, &policy)?;
        assert!(charge.expect("charged").ladder_events.is_empty());
    }
    let (_, charge) = check_effect(&vault, &effect, &policy)?;
    let events = charge.expect("charged").ladder_events;
    assert_eq!(events.len(), 2);
    assert!(
        events
            .iter()
            .all(|event| event.threshold == crate::BudgetThreshold::Plan80)
    );
    assert_eq!(fired_rows(&events), vec![Some(0), Some(1)]);
    Ok(())
}

#[test]
fn exhausted_denial_carries_backfilled_ladder_history() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xD0), &connector_key_line_send_manifest())?;
    let key_id = test_id(0x82);
    vault.register_connector_key(
        &key_id,
        crate::ConnectorKeyRecord::active(
            "line",
            None,
            vec![crate::EffectorBudget::spend(
                100,
                "USD",
                day_window(),
                crate::EffectorBudgetOnExhaust::Refuse,
            )],
            1_000,
        ),
    )?;
    // A single settlement jumps the row 0 -> limit WITHOUT any incremental
    // event firing (spend-ladder signals are the M3b v1 non-goal), so the
    // stored `fired` memory is empty when exhaustion is reached.
    vault.settle_connector_spend(&key_id, 0, 100, 1_100, "settle:jump")?;

    let policy = resolve(&vault)?;
    let mut effect = external_effect_gate_input("sender", "send", "line");
    effect.send_ref = Some("intent:one".to_owned());

    // The very first charge is Exhausted — and its denial read still
    // carries the crossed thresholds (not empty), with NO new events
    // (M5b carry-read-only). A retry is identical.
    for _ in 0..2 {
        let (decision, charge) = check_effect(&vault, &effect, &policy)?;
        assert_eq!(
            gate_reason_strs(&decision),
            vec!["gate.deny.effector_budget_exhausted"]
        );
        let charge = charge.expect("exhaustion charge");
        assert!(charge.ladder_events.is_empty(), "no events on the denial");
        assert_eq!(
            charge.read.rows[0].fired_thresholds,
            vec![
                crate::BudgetThreshold::Silent50,
                crate::BudgetThreshold::Plan80,
                crate::BudgetThreshold::Land95,
            ],
            "jump-to-exhausted history is never signal-silent"
        );
    }

    // The self.* meter read reports the same true ladder state.
    let read = vault
        .effector_budget_read("line", None)?
        .expect("governing key");
    assert_eq!(
        read.rows[0].fired_thresholds,
        vec![
            crate::BudgetThreshold::Silent50,
            crate::BudgetThreshold::Plan80,
            crate::BudgetThreshold::Land95,
        ]
    );
    Ok(())
}

// ─── AGENT-2 (ONE-1444): definition-ceiling clamp + pinned actor ids ─────────

// AGENT-2 AC test 9: a Proposed definition ceiling clamps a manifest
// agent-class Auto grant (restrict semantics); Auto or no definition bound
// keeps the grant.
#[test]
fn definition_ceiling_clamps_manifest_auto() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut data = encode_policy_manifest(vec![]);
    append_actor_ceiling(&mut data, actor_ceiling_row("agent", "auto"));
    put_policy_manifest_bytes(&vault, test_id(0xC1), &data)?;
    let policy = resolve(&vault)?;

    let mut input = gate_evaluator_input(
        "agent",
        Some("dispatched-agent"),
        ClaimSource::UserStated,
        PolicyCriticality::Normal,
    );
    assert_eq!(
        policy.evaluate_gate(&input).outcome(),
        GateOutcome::Allow,
        "no definition bound keeps the manifest grant"
    );

    input.agent_definition_ceiling = Some(PolicyApprovalCeiling::Auto);
    assert_eq!(
        policy.evaluate_gate(&input).outcome(),
        GateOutcome::Allow,
        "an Auto definition ceiling does not restrict the grant"
    );

    input.agent_definition_ceiling = Some(PolicyApprovalCeiling::Proposed);
    let decision = policy.evaluate_gate(&input);
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        decision.reason_codes(),
        &[GateReasonCode::PendingActorCeiling]
    );
    Ok(())
}

// --- GOV-10 charter -> compiled policy (ONE-1417) ------------------------------

#[test]
fn charter_enforcement_requires_the_human_stamp() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xD0), &connector_key_line_send_manifest())?;
    let key_id = test_id(0x7B);
    vault.register_connector_key(
        &key_id,
        crate::ConnectorKeyRecord::active("line", None, Vec::new(), 1_000),
    )?;
    let policy = resolve(&vault)?;
    let mut effect = external_effect_gate_input("sender", "send", "line");
    effect.send_ref = Some("intent:one".to_owned());

    // (a) After propose alone, enforcement is unchanged: the matching
    // never-line does not bind.
    let pending = vault.propose_connector_charter(&key_id, "never send on line", 1_001)?;
    let (decision, _) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(decision.outcome(), GateOutcome::Allow);

    // (b) A wrong re-presented hash is rejected and enforcement stays
    // unchanged.
    assert!(matches!(
        vault.approve_connector_charter(&key_id, [0xEE; 32], "owner", 1_002),
        Err(Error::ConnectorCharterApprovalMismatch)
    ));
    let (decision, _) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(decision.outcome(), GateOutcome::Allow);

    // (c) The stamped charter binds: the same dispatch now denies on the
    // never-list and consumes no budget (charge None).
    vault.approve_connector_charter(&key_id, pending.compiled_hash, "owner", 1_003)?;
    let deny_before =
        gate_metrics_snapshot().count(GateOutcome::Deny, GateMetricReasonClass::CharterPolicy);
    let (decision, charge) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(decision.outcome(), GateOutcome::Deny);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.deny.charter_never_list"]
    );
    assert!(decision.receipt_reasons().contains(&"charter_never_list"));
    assert!(charge.is_none(), "a never-list deny never reaches budgets");
    let deny_after =
        gate_metrics_snapshot().count(GateOutcome::Deny, GateMetricReasonClass::CharterPolicy);
    assert!(deny_after > deny_before, "CharterPolicy deny metric counts");

    Ok(())
}

#[test]
fn charter_compiled_caps_enforce_like_key_budgets() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xD0), &connector_key_line_send_manifest())?;
    let key_id = test_id(0x7C);
    vault.register_connector_key(
        &key_id,
        crate::ConnectorKeyRecord::active("line", None, Vec::new(), 1_000),
    )?;
    let pending = vault.propose_connector_charter(&key_id, "cap 2 sends per day on line", 1_001)?;
    vault.approve_connector_charter(&key_id, pending.compiled_hash, "owner", 1_002)?;
    let policy = resolve(&vault)?;
    let mut effect = external_effect_gate_input("sender", "send", "line");
    effect.send_ref = Some("intent:one".to_owned());

    // Sends 1-2 admit and debit the compiled row at index 0x8000; the ladder
    // fires on compiled rows exactly like key rows (Silent50 at 50%, then
    // Plan80 + Land95 at 100%).
    let (decision, charge) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    let charge = charge.expect("charged");
    assert_eq!(charge.matched_rows, vec![0x8000]);
    assert_eq!(charge.read.rows.len(), 1);
    assert_eq!(charge.read.rows[0].row_index, 0x8000);
    assert_eq!(charge.read.rows[0].used, 1);
    assert_eq!(
        charge
            .ladder_events
            .iter()
            .map(|event| event.threshold)
            .collect::<Vec<_>>(),
        vec![crate::BudgetThreshold::Silent50]
    );
    let (decision, charge) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    let plan80_fired = charge
        .expect("charged")
        .ladder_events
        .iter()
        .any(|event| event.threshold == crate::BudgetThreshold::Plan80);
    assert!(plan80_fired, "ladder fires on compiled rows too");

    // The compiled-cap usage row exists at index 0x8000.
    let usage_key = crate::connector_key::connector_key_usage_row_key(&key_id, 0x8000);
    let usage_row_exists = {
        let rtxn = vault.store.env.read_txn()?;
        vault.store.vault_meta.get(&rtxn, &usage_key)?.is_some()
    };
    assert!(usage_row_exists, "compiled-cap usage row at 0x8000");
    // The self.* meter read includes the compiled-cap row (echo property
    // holds post-GOV-10).
    let read = vault
        .effector_budget_read("line", None)?
        .expect("governing key");
    assert_eq!(read.rows.len(), 1);
    assert_eq!(read.rows[0].row_index, 0x8000);
    assert_eq!(read.rows[0].used, 2);

    // The third send exhausts the compiled row: suspend-the-key with the
    // charter-local index in the reason.
    let (decision, _) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.deny.effector_budget_exhausted"]
    );
    let record = vault.get_connector_key(&key_id)?.expect("record");
    assert_eq!(record.status, crate::ConnectorKeyStatus::Suspended);
    assert_eq!(
        record.suspended_reason.as_deref(),
        Some("budget_exhausted:charter_row:0")
    );

    // Approving a REPLACEMENT charter clears the positional 0x8000 usage
    // rows in the same txn.
    let replacement =
        vault.propose_connector_charter(&key_id, "cap 3 sends per day on line", 1_010)?;
    vault.approve_connector_charter(&key_id, replacement.compiled_hash, "owner", 1_011)?;
    let usage_row_exists = {
        let rtxn = vault.store.env.read_txn()?;
        vault.store.vault_meta.get(&rtxn, &usage_key)?.is_some()
    };
    assert!(!usage_row_exists, "re-stamp cleared compiled-cap usage");
    Ok(())
}

#[test]
fn charter_and_key_rows_debit_as_one_atomic_union() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xD0), &connector_key_line_send_manifest())?;
    let key_id = test_id(0x7D);
    vault.register_connector_key(
        &key_id,
        crate::ConnectorKeyRecord::active(
            "line",
            None,
            vec![crate::EffectorBudget::sends(
                10,
                day_window(),
                crate::EffectorBudgetOnExhaust::Suspend,
            )],
            1_000,
        ),
    )?;
    let pending = vault.propose_connector_charter(&key_id, "cap 1 sends per day on line", 1_001)?;
    vault.approve_connector_charter(&key_id, pending.compiled_hash, "owner", 1_002)?;
    let policy = resolve(&vault)?;
    let mut effect = external_effect_gate_input("sender", "send", "line");
    effect.send_ref = Some("intent:one".to_owned());

    // The first send debits BOTH rows of the union in one evaluation.
    let (decision, charge) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    let charge = charge.expect("charged");
    assert_eq!(charge.matched_rows, vec![0, 0x8000]);
    assert_eq!(charge.read.rows[0].used, 1, "key row debited");
    assert_eq!(charge.read.rows[1].used, 1, "charter row debited");

    // The second send is refused by the charter row and the key row's usage
    // stays at 1 — no partial debit leaks from the refused evaluation.
    let (decision, charge) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.deny.effector_budget_exhausted"]
    );
    let charge = charge.expect("exhaustion charge");
    assert_eq!(charge.read.rows[0].used, 1, "key row NOT debited");
    assert_eq!(charge.read.rows[1].used, 1);
    assert_eq!(
        vault
            .get_connector_key(&key_id)?
            .expect("record")
            .suspended_reason
            .as_deref(),
        Some("budget_exhausted:charter_row:0")
    );
    Ok(())
}

// AGENT-2 AC test 10 (B2 resolution): the edge-provenance no-matching-row
// auto exception is suppressed for ANY definition-bound actor — Proposed AND
// Auto — while non-definition actors keep today's exception.
#[test]
fn definition_ceiling_blocks_edge_provenance_exception() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // No agent-class rows: the manifest has only first_party rows.
    put_policy_manifest_bytes(&vault, test_id(0xC2), &encode_policy_manifest(vec![]))?;
    let policy = resolve(&vault)?;

    let mut input = gate_evaluator_input(
        "agent",
        Some("dispatched-agent"),
        ClaimSource::UserStated,
        PolicyCriticality::Normal,
    );
    input.content_kind = GateContentKind::EdgeProvenanceClaim;

    assert_eq!(
        policy.evaluate_gate(&input).outcome(),
        GateOutcome::Allow,
        "a non-definition agent actor keeps today's no-row exception"
    );

    input.agent_definition_ceiling = Some(PolicyApprovalCeiling::Proposed);
    let decision = policy.evaluate_gate(&input);
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        decision.reason_codes(),
        &[GateReasonCode::PendingActorCeiling]
    );

    // Auto means "does not self-limit", not "inherits the no-row exception":
    // with no owner row the definition-bound actor still holds to proposal.
    input.agent_definition_ceiling = Some(PolicyApprovalCeiling::Auto);
    let decision = policy.evaluate_gate(&input);
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        decision.reason_codes(),
        &[GateReasonCode::PendingActorCeiling]
    );
    Ok(())
}

// AGENT-2 AC test 11: a Proposed definition ceiling holds an otherwise
// auto-eligible external effect to PendingExternalEffectAuthority.
#[test]
fn definition_ceiling_blocks_external_effect_auto() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut data = encode_policy_manifest(vec![]);
    append_actor_ceiling(&mut data, actor_ceiling_row("agent", "auto"));
    put_policy_manifest_bytes(&vault, test_id(0xC3), &data)?;
    let policy = resolve(&vault)?;

    let mut effect = external_effect_gate_input("dispatched-agent", "send", "line");
    effect.actor.actor_class = "agent".to_owned();
    effect.standing_grant_ref = Some("grant:test".to_owned());

    assert_eq!(
        policy
            .evaluate_gate(&effect.gate_input(None, None))
            .outcome(),
        GateOutcome::Allow,
        "the effect is auto-eligible without a definition bound"
    );

    let decision =
        policy.evaluate_gate(&effect.gate_input(Some(PolicyApprovalCeiling::Proposed), None));
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert!(
        decision
            .reason_codes()
            .contains(&GateReasonCode::PendingExternalEffectAuthority),
        "a Proposed-ceiling agent can never auto-fire an external effect, got {:?}",
        decision.reason_codes()
    );
    Ok(())
}

// AGENT-2 AC test 12: the live resolver maps every actor shape per the pinned
// table (B3: absent entity fails closed to Proposed).
#[test]
fn resolver_maps_actors() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let store = &vault.store;

    // The fork parent: an Auto definition stored at Scout's pinned actor id.
    let scout_parent_id = pinned_actor_id(0xA1);
    put_agent_def_row(
        &vault,
        &scout_parent_id,
        "sys.scout",
        AgentCeiling::Auto,
        None,
    )?;
    let scout_fork_id = test_id(0x51);
    put_agent_def_row(
        &vault,
        &scout_fork_id,
        "eiri.scout.fork",
        AgentCeiling::Auto,
        Some("sys.scout"),
    )?;
    let person_id = test_id(0x52);
    vault.put_entity(&person_id, ENTITY_TYPE_PERSON, test_time(1), 1, b"person")?;

    {
        let rtxn = store.env.read_txn()?;
        // A stored Scout fork resolves to its effective ceiling (Auto ∧ Auto).
        assert_eq!(
            agent_definition_ceiling_for_actor(
                store,
                &rtxn,
                WriteActor::new(scout_fork_id, EdgeActorClass::Agent),
            ),
            Some(PolicyApprovalCeiling::Auto)
        );
        // Non-agent classes carry no definition bound.
        assert_eq!(
            agent_definition_ceiling_for_actor(
                store,
                &rtxn,
                WriteActor::new(scout_fork_id, EdgeActorClass::Human),
            ),
            None
        );
        // Absent/deleted agent entity fails closed to Proposed (B3).
        assert_eq!(
            agent_definition_ceiling_for_actor(
                store,
                &rtxn,
                WriteActor::new(test_id(0x53), EdgeActorClass::Agent),
            ),
            Some(PolicyApprovalCeiling::Proposed)
        );
        // Present-but-non-type-17 keeps today's semantics.
        assert_eq!(
            agent_definition_ceiling_for_actor(
                store,
                &rtxn,
                WriteActor::new(person_id, EdgeActorClass::Agent),
            ),
            None
        );
    }

    // Narrowing the stored fork bites the next resolution (live authority).
    put_agent_def_row(
        &vault,
        &scout_fork_id,
        "eiri.scout.fork",
        AgentCeiling::Proposed,
        Some("sys.scout"),
    )?;
    assert_eq!(
        resolved_ceiling(&vault, scout_fork_id)?,
        Some(PolicyApprovalCeiling::Proposed)
    );

    // OF-074 symmetry helper: effective = definition ∧ manifest projection.
    assert_eq!(
        dispatched_agent_effective_ceiling(
            PolicyApprovalCeiling::Auto,
            PolicyApprovalCeiling::Auto
        ),
        PolicyApprovalCeiling::Auto
    );
    assert_eq!(
        dispatched_agent_effective_ceiling(
            PolicyApprovalCeiling::Auto,
            PolicyApprovalCeiling::Proposed
        ),
        PolicyApprovalCeiling::Proposed
    );
    assert_eq!(
        dispatched_agent_effective_ceiling(
            PolicyApprovalCeiling::Proposed,
            PolicyApprovalCeiling::Auto
        ),
        PolicyApprovalCeiling::Proposed
    );
    Ok(())
}

// AGENT-2 AC test 13 (integration, N1): a Herald fork writing through the
// envelope door under a manifest granting agent-class Auto lands non-auto —
// the type-17 actor passes validate_actor_class and the live gate holds the
// write to proposal. Control: a Scout fork (effective Auto) is not held.
//
// Discriminating on the GATE-HALF clamp: BOTH forks carry their own `Auto`, so
// only the PARENT ROW's stored ceiling separates them — the Herald parent row
// is Proposed, the Scout parent row is Auto.
#[test]
fn herald_fork_claim_held_to_proposed_under_agent_auto_manifest() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut data = encode_policy_manifest(vec![]);
    append_actor_ceiling(&mut data, actor_ceiling_row("agent", "auto"));
    put_policy_manifest_bytes(&vault, test_id(0xC4), &data)?;

    put_agent_def_row(
        &vault,
        &pinned_actor_id(0xA4),
        "sys.herald",
        AgentCeiling::Proposed,
        None,
    )?;
    let herald_id = test_id(0x61);
    put_agent_def_row(
        &vault,
        &herald_id,
        "eiri.herald.custom",
        AgentCeiling::Auto,
        Some("sys.herald"),
    )?;

    let mut body = source_trust_claim(ClaimSource::UserStated);
    body.approval = ClaimApprovalStatus::Proposed;
    if let ClaimSubject::Entity(subject) = body.subject {
        vault.put_entity(&subject, ENTITY_TYPE_PERSON, test_time(1), 1, b"subject")?;
    }

    let claim_id = test_id(0x62);
    let envelope = WriteEnvelope::new(
        WriteActor::new(herald_id, EdgeActorClass::Agent),
        ClaimSource::UserStated,
        WriteProvenance::new(Value::from("herald-fork-write"))?,
        ClaimApprovalStatus::Proposed,
    );
    vault
        .batch()
        .claim_candidate(
            &claim_id,
            claim_candidate_from_body(&body),
            &envelope,
            test_time(3),
            3,
        )
        .commit()?;

    // Held to proposal: pending consent recorded with the actor-ceiling
    // reason, approval NOT auto-widened.
    assert!(has_pending_gate_consent(&vault, &claim_id)?);
    let pending = vault.with_write_txn(|wtxn| {
        vault
            .store
            .pending_gate_consent_in_txn(wtxn, &claim_id)?
            .ok_or(Error::CorruptedIndex("pending gate consent"))
    })?;
    assert_eq!(pending.reason_codes, vec!["gate.pending.actor_ceiling"]);
    assert_eq!(
        vault.get_claim(&claim_id)?.expect("held claim").approval,
        ClaimApprovalStatus::Proposed
    );

    // Control: a Scout fork's effective ceiling is Auto under the same
    // manifest — the identical write is not held.
    put_agent_def_row(
        &vault,
        &pinned_actor_id(0xA1),
        "sys.scout",
        AgentCeiling::Auto,
        None,
    )?;
    let scout_id = test_id(0x63);
    put_agent_def_row(
        &vault,
        &scout_id,
        "eiri.scout.custom",
        AgentCeiling::Auto,
        Some("sys.scout"),
    )?;
    let control_id = test_id(0x64);
    let control_envelope = WriteEnvelope::new(
        WriteActor::new(scout_id, EdgeActorClass::Agent),
        ClaimSource::UserStated,
        WriteProvenance::new(Value::from("scout-fork-write"))?,
        ClaimApprovalStatus::Proposed,
    );
    vault
        .batch()
        .claim_candidate(
            &control_id,
            claim_candidate_from_body(&body),
            &control_envelope,
            test_time(4),
            4,
        )
        .commit()?;
    assert!(!has_pending_gate_consent(&vault, &control_id)?);
    Ok(())
}

// AGENT-2 security hardening F1/F2: the external-effect door derives the
// definition ceiling only from a BOUND identity pair — a Proposed-ceiling
// agent cannot borrow an Auto identity's ceiling by mixing its own
// `actor_entity_ref` with the Auto identity's `actor_ref` (or vice versa);
// every mismatched/unparsable pair fails closed to a held effect.
#[test]
fn effect_actor_identity_binding_fails_closed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let auto_id = test_id(0x55);
    vault.put_agent_definition(
        &auto_id,
        &agent_def_fixture("eiri.scout.auto", AgentCeiling::Auto),
        test_time(1),
        1,
    )?;
    let herald_id = test_id(0x56);
    vault.put_agent_definition(
        &herald_id,
        &agent_def_fixture("eiri.herald.proposed", AgentCeiling::Proposed),
        test_time(1),
        1,
    )?;

    // Manifest: the AUTO identity gets an agent-class Auto row plus a scoped
    // grant covering the send verb — fully auto-eligible when bound.
    let mut data = encode_policy_manifest(vec![external_effect_scoped_grant_entry(
        &auto_id.to_hex(),
        "external:send",
        Value::Map(vec![(Value::from("channel"), Value::from("email"))]),
        None,
    )]);
    append_actor_ceiling(
        &mut data,
        actor_ceiling_row_for_ref("agent", &auto_id.to_hex(), "auto"),
    );
    put_policy_manifest_bytes(&vault, test_id(0xC5), &data)?;
    let policy = resolve(&vault)?;

    let effect_for = |actor_ref: Option<String>, entity_ref: Option<EntityId>| {
        let mut effect = external_effect_gate_input("unused", "send", "email");
        effect.actor.actor_class = "agent".to_owned();
        effect.actor.actor_ref = actor_ref;
        effect.provenance.actor_entity_ref = entity_ref;
        effect
    };

    let mut wtxn = vault.store.env.write_txn()?;

    // Control: the bound pair on the Auto identity is auto-eligible.
    let (_, decision, _) = check_external_effect_policy(
        &vault.store,
        &mut wtxn,
        &effect_for(Some(auto_id.to_hex()), Some(auto_id)),
        &policy,
        true,
    )?;
    assert_eq!(decision.outcome(), GateOutcome::Allow, "bound Auto pair");

    // Borrow attempt: the Proposed identity's provenance under the Auto
    // identity's actor_ref must NOT reach execution.
    let (_, decision, _) = check_external_effect_policy(
        &vault.store,
        &mut wtxn,
        &effect_for(Some(auto_id.to_hex()), Some(herald_id)),
        &policy,
        true,
    )?;
    assert_eq!(
        decision.outcome(),
        GateOutcome::Pending,
        "mismatched pair (auto ref, proposed identity) must hold"
    );

    // Reverse mismatch fails closed the same way.
    let (_, decision, _) = check_external_effect_policy(
        &vault.store,
        &mut wtxn,
        &effect_for(Some(herald_id.to_hex()), Some(auto_id)),
        &policy,
        true,
    )?;
    assert_eq!(
        decision.outcome(),
        GateOutcome::Pending,
        "mismatched pair (proposed ref, auto identity) must hold"
    );

    // An unparsable actor_ref with a real identity is a disagreement.
    let (_, decision, _) = check_external_effect_policy(
        &vault.store,
        &mut wtxn,
        &effect_for(Some("not-an-entity-id".to_owned()), Some(auto_id)),
        &policy,
        true,
    )?;
    assert_eq!(
        decision.outcome(),
        GateOutcome::Pending,
        "unparsable actor_ref must hold"
    );
    drop(wtxn);
    Ok(())
}

// GATE-HALF: no compiled table confers authority on a pinned system-agent
// actor id. An actor at a pinned id resolves from the ROW stored there — no
// row is the ABSENT arm (fail-closed Proposed), and a stored AGENT_DEF row
// resolves to that row's own ceiling, exactly like any other id.
#[test]
fn pinned_actor_without_row_is_proposed() -> Result<()> {
    let (_tmp, vault) = temp_vault();

    // Delete the ONE-1890 seeded rows so every pinned id is row-less again —
    // including the two whose deleted compiled ceilings were Auto (0xA1 Scout,
    // 0xA2 Keeper) — so nothing can act with preset authority.
    vault.with_write_txn(|wtxn| {
        for byte in 0xA1..=0xA6 {
            crate::batch::deindex_entity_for_test(&vault.store, wtxn, &pinned_actor_id(byte))?;
        }
        Ok(())
    })?;
    for byte in 0xA1..=0xA6 {
        assert_eq!(
            resolved_ceiling(&vault, pinned_actor_id(byte))?,
            Some(PolicyApprovalCeiling::Proposed),
            "pinned id {byte:#04x} without a stored row must fail closed"
        );
    }

    // With a row, the pinned id carries exactly that row's authority — the
    // data-over-rows shape ONE-1890 seeds.
    let scout_id = pinned_actor_id(0xA1);
    put_agent_def_row(&vault, &scout_id, "sys.scout", AgentCeiling::Auto, None)?;
    assert_eq!(
        resolved_ceiling(&vault, scout_id)?,
        Some(PolicyApprovalCeiling::Auto)
    );

    let herald_id = pinned_actor_id(0xA4);
    put_agent_def_row(
        &vault,
        &herald_id,
        "sys.herald",
        AgentCeiling::Proposed,
        None,
    )?;
    assert_eq!(
        resolved_ceiling(&vault, herald_id)?,
        Some(PolicyApprovalCeiling::Proposed)
    );

    // A non-type-17 row at a pinned id is simply not agent-bearing (`None`),
    // the same answer any other non-agent entity gives. Reachable only through
    // the raw store door: the batch.rs write-door lockout still rejects it.
    let keeper_id = pinned_actor_id(0xA2);
    put_raw_entity_row(&vault, &keeper_id, ENTITY_TYPE_PERSON, b"occupant")?;
    assert_eq!(resolved_ceiling(&vault, keeper_id)?, None);
    Ok(())
}

// AGENT-2 security hardening (class spoof): the external-effect door must not
// gate ceiling resolution on the caller-asserted class. Authority is derived
// from what the governing ENTITY is; unrecognized/empty class strings fail
// closed; case cannot be used to dodge the agent path.
#[test]
fn effect_actor_class_spoof_fails_closed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let herald_id = test_id(0x57);
    vault.put_agent_definition(
        &herald_id,
        &agent_def_fixture("eiri.herald.proposed", AgentCeiling::Proposed),
        test_time(1),
        1,
    )?;
    let person_id = test_id(0x58);
    vault.put_entity(&person_id, ENTITY_TYPE_PERSON, test_time(1), 1, b"person")?;

    // Every actor ref below is granted class-wide Auto plus a matching send
    // grant, so nothing but the definition clamp (or the class fail-closed
    // arm) can hold these effects.
    let send_grant = |actor_ref: &str| {
        Value::Map(vec![
            (Value::from(ACTOR_REF_KEY), Value::from(actor_ref)),
            (Value::from(GRANT_EFFECTOR_KEY), Value::from("external:*")),
            (
                Value::from(GRANT_SCOPE_KEY),
                Value::Map(vec![(Value::from("channel"), Value::from("email"))]),
            ),
        ])
    };
    let mut data = encode_policy_manifest(vec![(
        Value::from(POLICY_SCOPED_GRANTS_KEY),
        Value::Array(vec![
            send_grant(&herald_id.to_hex()),
            send_grant(&person_id.to_hex()),
        ]),
    )]);
    replace_actor_ceilings(
        &mut data,
        vec![
            actor_ceiling_row("agent", "auto"),
            actor_ceiling_row("first_party", "auto"),
            actor_ceiling_row("human", "auto"),
        ],
    );
    put_policy_manifest_bytes(&vault, test_id(0xC6), &data)?;
    let policy = resolve(&vault)?;

    let effect_for = |class: &str, id: EntityId| {
        let mut effect = external_effect_gate_input(&id.to_hex(), "send", "email");
        effect.actor.actor_class = class.to_owned();
        effect.provenance.actor_entity_ref = Some(id);
        effect
    };

    let mut wtxn = vault.store.env.write_txn()?;

    // A stored AGENT_DEF is clamped under ANY class string the caller asserts
    // (entity-type-wins), including case variants of "agent" and a class that
    // names something else entirely.
    for spoof in [
        "agent",
        "Agent",
        "AGENT",
        "  AgEnT  ",
        "person",
        "human",
        "system",
        "",
    ] {
        let (_, decision, _) = check_external_effect_policy(
            &vault.store,
            &mut wtxn,
            &effect_for(spoof, herald_id),
            &policy,
            true,
        )?;
        assert_ne!(
            decision.outcome(),
            GateOutcome::Allow,
            "a Proposed-ceiling AGENT_DEF must never auto-fire under class {spoof:?}"
        );
    }

    // An unrecognized class over a NON-agent entity also fails closed rather
    // than skipping the clamp.
    let (_, decision, _) = check_external_effect_policy(
        &vault.store,
        &mut wtxn,
        &effect_for("person", person_id),
        &policy,
        true,
    )?;
    assert_ne!(
        decision.outcome(),
        GateOutcome::Allow,
        "an unrecognized actor class must fail closed"
    );

    // Control: a RECOGNIZED non-agent principal over a non-agent entity keeps
    // today's semantics — the clamp does not over-reach, so the identical
    // request that class "person" fails closed on is auto-allowed here.
    let (_, decision, _) = check_external_effect_policy(
        &vault.store,
        &mut wtxn,
        &effect_for("first_party", person_id),
        &policy,
        true,
    )?;
    assert_eq!(
        decision.outcome(),
        GateOutcome::Allow,
        "a first_party principal over a non-agent entity is not clamped"
    );
    drop(wtxn);
    Ok(())
}

// GATE-HALF: the fork clamp resolves against the PARENT ROW's stored ceiling,
// never a compiled table. Discriminating in BOTH directions — each parent row
// below carries the OPPOSITE ceiling to the compiled entry this seam deleted
// (Scout was compiled Auto, Herald compiled Proposed), so a resolver still
// reading a table answers every case backwards.
#[test]
fn fork_clamp_reads_parent_row() -> Result<()> {
    let (_tmp, vault) = temp_vault();

    // Parent row NARROWER than the deleted compiled entry: the row clamps an
    // otherwise-Auto fork down.
    put_agent_def_row(
        &vault,
        &pinned_actor_id(0xA1),
        "sys.scout",
        AgentCeiling::Proposed,
        None,
    )?;
    let narrowed_fork = test_id(0x71);
    put_agent_def_row(
        &vault,
        &narrowed_fork,
        "fork.of.scout",
        AgentCeiling::Auto,
        Some("sys.scout"),
    )?;
    assert_eq!(
        resolved_ceiling(&vault, narrowed_fork)?,
        Some(PolicyApprovalCeiling::Proposed),
        "the clamp must take the parent ROW's Proposed, not Scout's compiled Auto"
    );

    // Parent row WIDER than the deleted compiled entry: the fork keeps Auto.
    put_agent_def_row(
        &vault,
        &pinned_actor_id(0xA4),
        "sys.herald",
        AgentCeiling::Auto,
        None,
    )?;
    let widened_fork = test_id(0x72);
    put_agent_def_row(
        &vault,
        &widened_fork,
        "fork.of.herald",
        AgentCeiling::Auto,
        Some("sys.herald"),
    )?;
    assert_eq!(
        resolved_ceiling(&vault, widened_fork)?,
        Some(PolicyApprovalCeiling::Auto),
        "the clamp must take the parent ROW's Auto, not Herald's compiled Proposed"
    );

    // The clamp is a MEET, not a replacement: a fork's own Proposed stands
    // against an Auto parent row.
    let self_limited_fork = test_id(0x73);
    put_agent_def_row(
        &vault,
        &self_limited_fork,
        "fork.self.limited",
        AgentCeiling::Proposed,
        Some("sys.herald"),
    )?;
    assert_eq!(
        resolved_ceiling(&vault, self_limited_fork)?,
        Some(PolicyApprovalCeiling::Proposed),
        "min(own, parent-stored): an Auto parent cannot widen a Proposed fork"
    );

    // Live authority: narrowing the PARENT row bites the child's next
    // resolution without the child being touched.
    put_agent_def_row(
        &vault,
        &pinned_actor_id(0xA4),
        "sys.herald",
        AgentCeiling::Proposed,
        None,
    )?;
    assert_eq!(
        resolved_ceiling(&vault, widened_fork)?,
        Some(PolicyApprovalCeiling::Proposed),
        "the parent row is read live, never snapshotted into the fork"
    );
    Ok(())
}

// GATE-HALF fail-closed: every way a parent row can fail to yield a ceiling —
// absent, non-type-17, undecodable body, unparsable header — clamps the fork
// to Proposed (each arm warns). Every fork below carries its own Auto, so the
// only thing that can hold it is the parent arm under test; the control at the
// end shows the fixture itself is not what holds them.
#[test]
fn fork_clamp_fails_closed_without_parent_row() -> Result<()> {
    let (_tmp, vault) = temp_vault();

    // 1. No parent row at all: an ordinary id that was never written.
    let absent_parent = test_id(0x7F);
    assert!(vault.get_raw(&absent_parent)?.is_none());
    let orphan_fork = test_id(0x74);
    put_agent_def_row(
        &vault,
        &orphan_fork,
        "fork.orphan",
        AgentCeiling::Auto,
        Some(&absent_parent.to_hex()),
    )?;
    assert_eq!(
        resolved_ceiling(&vault, orphan_fork)?,
        Some(PolicyApprovalCeiling::Proposed),
        "absent parent row must fail closed"
    );

    // 2. Parent row present but not agent-bearing.
    put_raw_entity_row(
        &vault,
        &pinned_actor_id(0xA2),
        ENTITY_TYPE_PERSON,
        b"occupant",
    )?;
    let keeper_fork = test_id(0x75);
    put_agent_def_row(
        &vault,
        &keeper_fork,
        "fork.of.keeper",
        AgentCeiling::Auto,
        Some("sys.keeper"),
    )?;
    assert_eq!(
        resolved_ceiling(&vault, keeper_fork)?,
        Some(PolicyApprovalCeiling::Proposed),
        "non-type-17 parent row must fail closed"
    );

    // 3. Parent row is type-17 but its body does not decode (0xC1 is the
    //    never-used MessagePack byte).
    put_raw_entity_row(
        &vault,
        &pinned_actor_id(0xA3),
        ENTITY_TYPE_AGENT_DEF,
        &[0xC1],
    )?;
    let creative_fork = test_id(0x76);
    put_agent_def_row(
        &vault,
        &creative_fork,
        "fork.of.creative",
        AgentCeiling::Auto,
        Some("sys.creative"),
    )?;
    assert_eq!(
        resolved_ceiling(&vault, creative_fork)?,
        Some(PolicyApprovalCeiling::Proposed),
        "undecodable parent body must fail closed"
    );

    // 4. Parent record too short to carry an entity metadata header.
    let guide_parent_id = pinned_actor_id(0xA5);
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .entities
            .put(wtxn, guide_parent_id.as_bytes(), &[ENTITY_TYPE_AGENT_DEF])?;
        Ok(())
    })?;
    let guide_fork = test_id(0x77);
    put_agent_def_row(
        &vault,
        &guide_fork,
        "fork.of.guide",
        AgentCeiling::Auto,
        Some("sys.guide"),
    )?;
    assert_eq!(
        resolved_ceiling(&vault, guide_fork)?,
        Some(PolicyApprovalCeiling::Proposed),
        "unparsable parent header must fail closed"
    );

    // Control: the identical fork shape over a READABLE Auto parent row is not
    // held, so the four clamps above come from the parent arm, not the fixture.
    put_agent_def_row(
        &vault,
        &pinned_actor_id(0xA6),
        "sys.default",
        AgentCeiling::Auto,
        None,
    )?;
    let default_fork = test_id(0x78);
    put_agent_def_row(
        &vault,
        &default_fork,
        "fork.of.default",
        AgentCeiling::Auto,
        Some("sys.default"),
    )?;
    assert_eq!(
        resolved_ceiling(&vault, default_fork)?,
        Some(PolicyApprovalCeiling::Auto),
        "a readable Auto parent row leaves the fork Auto"
    );
    Ok(())
}

#[test]
fn charter_drift_degrades_to_pending_without_debits() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xD0), &connector_key_line_send_manifest())?;
    let key_id = test_id(0x7E);
    vault.register_connector_key(
        &key_id,
        crate::ConnectorKeyRecord::active(
            "line",
            None,
            vec![crate::EffectorBudget::sends(
                5,
                day_window(),
                crate::EffectorBudgetOnExhaust::Suspend,
            )],
            1_000,
        ),
    )?;
    let pending = vault.propose_connector_charter(&key_id, "never delete on line", 1_001)?;
    vault.approve_connector_charter(&key_id, pending.compiled_hash, "owner", 1_002)?;
    let policy = resolve(&vault)?;
    let mut effect = external_effect_gate_input("sender", "send", "line");
    effect.send_ref = Some("intent:one".to_owned());

    // Hand-corrupt the stored charter text while keeping the stale stamp.
    let mut record = vault.get_connector_key(&key_id)?.expect("record");
    record.charter.as_mut().expect("charter").text = "never delete on line (edited)".to_owned();
    vault.with_write_txn(|wtxn| {
        crate::connector_key::rewrite_connector_key_in_txn(&vault.store, wtxn, &key_id, &record)
    })?;

    let pending_before =
        gate_metrics_snapshot().count(GateOutcome::Pending, GateMetricReasonClass::CharterPolicy);
    let (decision, charge) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.pending.charter_drift"]
    );
    assert!(decision.receipt_reasons().contains(&"charter_drift"));
    assert!(charge.is_none(), "drift skips ALL debits");
    let read = vault
        .effector_budget_read("line", None)?
        .expect("governing key");
    assert_eq!(read.rows[0].used, 0, "no debit occurred under drift");
    let pending_after =
        gate_metrics_snapshot().count(GateOutcome::Pending, GateMetricReasonClass::CharterPolicy);
    assert!(
        pending_after > pending_before,
        "CharterPolicy pending metric counts"
    );

    // A fresh propose/approve cycle re-stamps and restores enforcement.
    let restamp = vault.propose_connector_charter(&key_id, "never delete on line", 1_010)?;
    vault.approve_connector_charter(&key_id, restamp.compiled_hash, "owner", 1_011)?;
    let (decision, charge) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    assert!(charge.expect("budget stage ran").matched_rows.contains(&0));
    Ok(())
}

#[test]
fn admitted_wrapper_charges_budget_and_denies_exhausted_key() -> Result<()> {
    // Exercises the PRODUCTION `check_external_effect_policy` (not the
    // `_with_budget` test helper): when admit_for_execution is set the caller
    // applies the effect immediately, so the wrapper itself must debit the
    // governing connector key and flip to a budget-exhausted denial. Before the
    // fix the wrapper ignored the flag and never charged, so an exhausted key
    // could not block an immediately-applied lifecycle effect.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0xD0),
        &connector_key_two_verb_manifest("line"),
    )?;
    vault.register_connector_key(
        &test_id(0x7E),
        crate::ConnectorKeyRecord::active(
            "line",
            None,
            vec![crate::EffectorBudget::rate(1, 3_600)],
            1_000,
        ),
    )?;
    let policy = resolve(&vault)?;
    // A lifecycle-shaped effect applied immediately: send_ref None.
    let effect = external_effect_gate_input("sender", "provision", "line");
    assert!(effect.send_ref.is_none());

    // First admitted call charges the rate-1 budget through the wrapper.
    let (_, decision, charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &effect, &policy, true)
    })?;
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    assert!(
        charge.is_some(),
        "the admitted wrapper debited the governing key"
    );

    // The now-exhausted rate row blocks the next admitted lifecycle effect.
    let (_, decision, _) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &effect, &policy, true)
    })?;
    assert_eq!(decision.outcome(), GateOutcome::Deny);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.deny.effector_budget_exhausted"]
    );

    // Governance-only callers (admit_for_execution = false) still never debit.
    let (_, decision, charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &effect, &policy, false)
    })?;
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    assert!(charge.is_none(), "governance-only checks must not debit");
    Ok(())
}

/// FIX-1 (gate chokepoint): both gate-input constructors take a typed consent
/// context, and the PRODUCTION external-effect door composes it from
/// host-observed facts inside its write transaction — no caller re-implements
/// the ladder and no constructor hard-codes `consent: None` at a DEC-0006
/// door. An ungranted irreversible send rides the ladder (pending); an effect
/// covered by remembered state is consent-Auto and its other lanes rule.
#[test]
fn external_effect_gate_input_composes_consent_context() -> Result<()> {
    // Ungranted: the composed context holds the irreversible send at Ask.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xD5), &encode_policy_manifest(vec![]))?;
    let policy = resolve(&vault)?;
    let effect = external_effect_gate_input("sender", "send", "line");
    let consent = external_effect_consent_context(&effect, None, &[])
        .expect("a send effect composes an honest consent context");
    assert_eq!(
        consent.decision,
        crate::consent::ConsentDecision::Ask,
        "an irreversible send with no covering grant must ask"
    );
    let decision = policy.evaluate_gate(&effect.gate_input(None, Some(consent)));
    assert!(
        gate_reason_strs(&decision)
            .iter()
            .any(|code| code.starts_with("gate.pending.consent.")),
        "the typed consent context must reach the decision, got {:?}",
        gate_reason_strs(&decision)
    );

    // Covered: a remembered grant auto-runs INSIDE its bound (invariant 1/3).
    let request = external_effect_action_requirement(&effect).expect("requirement");
    let covering = crate::consent::StandingConsentGrant::from_bound(request)
        .expect("a bound mints a standing grant");
    let consent = external_effect_consent_context(&effect, None, &[covering])
        .expect("covered effect composes");
    assert_eq!(
        consent.decision,
        crate::consent::ConsentDecision::Auto,
        "an effect inside its bound reuses the grant quietly"
    );

    // A constructor caller that does not compose consent keeps the explicit
    // `None` arm — pre-DEC-0006 behaviour, never a hidden Auto.
    let decision = policy.evaluate_gate(&effect.gate_input(None, None));
    assert!(
        !gate_reason_strs(&decision)
            .iter()
            .any(|code| code.starts_with("gate.pending.consent.")),
        "None consent contributes no consent reasons"
    );
    Ok(())
}

/// TARGET A pin: the store marker is spent by the transaction that authorizes
/// delivery, not by minting or by caller-supplied digest equality.
#[test]
fn approve_once_not_atomic_is_closed_for_production_and_public_evaluation() -> Result<()> {
    const EFFECT_RAN_KEY: &[u8] = b"test.approve_once.production_effect";

    let (_tmp, vault) = temp_vault();
    let owner_id = test_id(0xE0);
    vault.put_entity(&owner_id, ENTITY_TYPE_PERSON, test_time(1), 1, b"owner")?;
    let owner =
        vault.authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())?;
    let actor_ref = owner_id.to_hex();
    let policy_data = encode_policy_manifest(vec![external_effect_scoped_grant_entry(
        &actor_ref,
        "external:send",
        Value::Map(vec![(
            Value::from(EXTERNAL_EFFECT_SCOPE_CHANNEL_KEY),
            Value::from("line"),
        )]),
        None,
    )]);
    put_policy_manifest_bytes(&vault, test_id(0xD5), &policy_data)?;
    let policy = resolve(&vault)?;

    let production_effect = external_effect_gate_input(&actor_ref, "send", "line");
    let production_digest = external_effect_composed_effect(&production_effect)
        .expect("production effect composes")
        .digest();
    vault.approve_once(&owner, production_digest)?;

    vault.with_write_txn(|wtxn| {
        let governance =
            evaluate_external_effect_policy(&vault.store, wtxn, &production_effect, &policy, None)?;
        assert_eq!(governance.outcome(), GateOutcome::Allow);
        vault.store.vault_meta.put(wtxn, EFFECT_RAN_KEY, b"once")?;
        record_external_effect_policy(&vault.store, wtxn, governance)?;
        Ok(())
    })?;
    let replay = vault
        .with_write_txn(|wtxn| {
            evaluate_external_effect_policy(&vault.store, wtxn, &production_effect, &policy, None)
                .map(|_| ())
        })
        .expect_err("production replay must stop before a second effect");
    assert_eq!(replay.kind(), ErrorKind::ConsentApproveOnceSpent);
    let rtxn = vault.store.env.read_txn()?;
    let effect_ran = vault.store.vault_meta.get(&rtxn, EFFECT_RAN_KEY)?;
    assert_eq!(
        effect_ran.as_deref(),
        Some(b"once".as_slice()),
        "the production effect marker was written exactly once"
    );
    drop(rtxn);

    let public_effect = external_effect_composed_effect(&external_effect_gate_input(
        &owner_id.to_hex(),
        "send",
        "email",
    ))
    .expect("public effect composes");
    let public_digest = public_effect.digest();
    vault.approve_once(&owner, public_digest)?;
    assert_eq!(
        vault
            .evaluate_consent_for(&public_effect, Some(&public_digest))?
            .decision,
        crate::consent::ConsentDecision::Auto
    );
    assert_eq!(
        vault
            .evaluate_consent_for(&public_effect, Some(&public_digest))
            .expect_err("public replay must reject")
            .kind(),
        ErrorKind::ConsentApproveOnceSpent
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// ONE-1348 `budget_policy` manifest parse / resolution / factory tests.
//
// All fixtures and helpers stay inside this module; the existing
// `on_budget_exhausted`, gate-decision, facet/mask/disclosure, and ONE-1388
// tests above are untouched.
// ---------------------------------------------------------------------------
mod budget_policy {
    use super::*;

    fn row_value(entries: Vec<(&str, Value)>) -> Value {
        Value::Map(
            entries
                .into_iter()
                .map(|(key, value)| (Value::from(key), value))
                .collect(),
        )
    }

    fn purpose_row_value(purpose: &str, floor: Option<u64>, cap: Option<u64>) -> Value {
        let mut entries = vec![("purpose", Value::from(purpose))];
        if let Some(floor) = floor {
            entries.push(("floor", Value::from(floor)));
        }
        if let Some(cap) = cap {
            entries.push(("cap", Value::from(cap)));
        }
        row_value(entries)
    }

    fn actor_row_value(actor_ref: &str, floor: Option<u64>, cap: Option<u64>) -> Value {
        let mut entries = vec![("actor", Value::from(actor_ref))];
        if let Some(floor) = floor {
            entries.push(("floor", Value::from(floor)));
        }
        if let Some(cap) = cap {
            entries.push(("cap", Value::from(cap)));
        }
        row_value(entries)
    }

    fn budget_policy_entry(rows: Vec<Value>) -> (Value, Value) {
        (Value::from(POLICY_BUDGET_POLICY_KEY), Value::Array(rows))
    }

    fn canonical_actor_ref(seed: u8) -> String {
        crate::test_util::entity(seed).to_hex()
    }

    fn resolved_table(
        vault: &crate::Vault,
        seed: u8,
        rows: Vec<Value>,
    ) -> Result<PolicyManifestResolution> {
        put_policy_manifest_bytes(
            vault,
            test_id(seed),
            &encode_policy_manifest(vec![budget_policy_entry(rows)]),
        )?;
        resolve(vault)
    }

    #[test]
    fn budget_policy_absent_and_empty_resolve_identically() -> Result<()> {
        let (_tmp_absent, absent_vault) = temp_vault();
        put_policy_manifest_bytes(
            &absent_vault,
            test_id(0x30),
            &encode_policy_manifest(vec![]),
        )?;
        let (_tmp_empty, empty_vault) = temp_vault();
        put_policy_manifest_bytes(
            &empty_vault,
            test_id(0x30),
            &encode_policy_manifest(vec![budget_policy_entry(vec![])]),
        )?;

        let absent = resolve(&absent_vault)?;
        let empty = resolve(&empty_vault)?;
        assert!(
            absent
                .budget_policy()
                .expect("absent table resolves")
                .is_empty()
        );
        assert!(
            empty
                .budget_policy()
                .expect("explicit empty table resolves")
                .is_empty()
        );
        assert_eq!(absent.read_frontier_hash()?, empty.read_frontier_hash()?);
        Ok(())
    }

    #[test]
    fn budget_policy_parses_canonical_purpose_and_actor_rows_in_order() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let actor_ref = canonical_actor_ref(0x44);
        let policy = resolved_table(
            &vault,
            0x30,
            vec![
                purpose_row_value("consolidation", Some(200_000), None),
                actor_row_value(&actor_ref, Some(50_000), Some(150_000)),
            ],
        )?;
        let table = policy.budget_policy().expect("valid table");
        let rows = table.rows();
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0].selector(),
            &BudgetPolicySelector::Purpose(CallPurpose::Consolidation)
        );
        assert_eq!(rows[0].floor_units(), Some(200_000));
        assert_eq!(rows[0].cap_units(), None);
        let actor_id = EntityId::from_hex(&actor_ref).expect("actor ref round-trips");
        assert_eq!(actor_id.to_hex(), actor_ref);
        assert_eq!(rows[1].selector(), &BudgetPolicySelector::Actor(actor_id));
        assert_eq!(rows[1].floor_units(), Some(50_000));
        assert_eq!(rows[1].cap_units(), Some(150_000));
        Ok(())
    }

    #[test]
    fn budget_policy_other_purpose_matches_by_name() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let policy = resolved_table(
            &vault,
            0x30,
            vec![purpose_row_value("dream_journal", Some(5), None)],
        )?;
        let table = policy.budget_policy().expect("valid table");
        match table.rows()[0].selector() {
            BudgetPolicySelector::Purpose(CallPurpose::Other { name }) => {
                assert_eq!(name, "dream_journal");
            }
            other => panic!("expected an exact-name Other purpose, got {other:?}"),
        }
        assert_ne!(
            table.rows()[0].selector(),
            &BudgetPolicySelector::Purpose(CallPurpose::Voice),
            "an Other name is never a built-in or wildcard"
        );
        Ok(())
    }

    #[test]
    fn budget_policy_requires_selector_xor_and_floor_or_cap() {
        let actor_ref = canonical_actor_ref(0x44);
        for (label, row) in [
            (
                "neither selector",
                row_value(vec![("floor", Value::from(10_u64))]),
            ),
            (
                "both selectors",
                row_value(vec![
                    ("purpose", Value::from("voice")),
                    ("actor", Value::from(actor_ref.as_str())),
                    ("floor", Value::from(10_u64)),
                ]),
            ),
            (
                "neither floor nor cap",
                row_value(vec![("purpose", Value::from("voice"))]),
            ),
        ] {
            let manifest = encode_policy_manifest(vec![budget_policy_entry(vec![row])]);
            assert!(
                decode_policy_manifest(&manifest).is_none(),
                "{label} row must reject the manifest"
            );
        }

        // floor: 0 and cap: 0 are both syntactically valid.
        let floor_zero = decode_policy_manifest(&encode_policy_manifest(vec![
            budget_policy_entry(vec![purpose_row_value("voice", Some(0), None)]),
        ]))
        .expect("floor: 0 stays valid");
        assert_eq!(floor_zero.budget_policy.rows()[0].floor_units(), Some(0));
        let cap_zero =
            decode_policy_manifest(&encode_policy_manifest(vec![budget_policy_entry(vec![
                purpose_row_value("voice", None, Some(0)),
            ])]))
            .expect("cap: 0 stays valid");
        assert_eq!(cap_zero.budget_policy.rows()[0].cap_units(), Some(0));
    }

    #[test]
    fn budget_policy_malformed_row_fails_manifest_closed() -> Result<()> {
        // A letters-bearing ref so `to_uppercase` genuinely de-canonicalizes it.
        let noncanonical_actor_ref = canonical_actor_ref(0xAB).to_uppercase();
        assert_ne!(
            noncanonical_actor_ref,
            noncanonical_actor_ref.to_lowercase()
        );
        let cases: Vec<(&str, Value)> = vec![
            ("non-array table", Value::from(42_u64)),
            ("non-map row", Value::Array(vec![Value::from("not-a-row")])),
            (
                "duplicate row key",
                Value::Array(vec![row_value(vec![
                    ("purpose", Value::from("voice")),
                    ("floor", Value::from(10_u64)),
                    ("floor", Value::from(11_u64)),
                ])]),
            ),
            (
                "wrong integer type",
                Value::Array(vec![row_value(vec![
                    ("purpose", Value::from("voice")),
                    ("floor", Value::from("ten")),
                ])]),
            ),
            (
                "empty purpose",
                Value::Array(vec![purpose_row_value("", Some(10), None)]),
            ),
            (
                "non-canonical actor ref",
                Value::Array(vec![actor_row_value(
                    noncanonical_actor_ref.as_str(),
                    Some(10),
                    None,
                )]),
            ),
            (
                "unknown row key",
                Value::Array(vec![row_value(vec![
                    ("purpose", Value::from("voice")),
                    ("floor", Value::from(10_u64)),
                    ("bogus", Value::from(1_u64)),
                ])]),
            ),
        ];
        for (index, (label, table_value)) in cases.into_iter().enumerate() {
            let (_tmp, vault) = temp_vault();
            put_policy_manifest_bytes(
                &vault,
                test_id(0x30),
                &encode_policy_manifest(vec![(Value::from(POLICY_BUDGET_POLICY_KEY), table_value)]),
            )?;
            let policy = resolve(&vault)?;
            assert!(
                policy.diagnostics().malformed_manifest_seen,
                "{label} must mark the manifest malformed (case {index})"
            );
            assert!(
                policy.diagnostics().loaded_manifest_forces_fail_closed(),
                "{label} must fail the loaded manifest closed (case {index})"
            );
            assert!(
                policy.budget_policy().is_none(),
                "{label} exposes no usable table (case {index})"
            );
        }
        Ok(())
    }

    #[test]
    fn budget_policy_multiple_manifests_preserve_resolved_order() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let actor_ref = canonical_actor_ref(0x44);
        // Type-index order is ascending entity id bytes: 0x30... < 0x31....
        put_policy_manifest_bytes(
            &vault,
            test_id(0x30),
            &encode_policy_manifest(vec![budget_policy_entry(vec![
                purpose_row_value("extraction", Some(1), None),
                actor_row_value(&actor_ref, Some(2), Some(4)),
            ])]),
        )?;
        put_policy_manifest_bytes(
            &vault,
            test_id(0x31),
            &encode_policy_manifest(vec![budget_policy_entry(vec![purpose_row_value(
                "voice",
                None,
                Some(3),
            )])]),
        )?;

        let policy = resolve(&vault)?;
        let table = policy.budget_policy().expect("valid table");
        let rows = table.rows();
        assert_eq!(rows.len(), 3);
        // Rows concatenate in resolved order: manifest scan order, then row
        // order inside each manifest; indices 0..=2 stay stable.
        assert_eq!(
            rows[0].selector(),
            &BudgetPolicySelector::Purpose(CallPurpose::Extraction)
        );
        assert_eq!(
            (rows[0].floor_units(), rows[0].cap_units()),
            (Some(1), None)
        );
        assert_eq!(
            rows[1].selector(),
            &BudgetPolicySelector::Actor(EntityId::from_hex(&actor_ref).expect("actor ref"))
        );
        assert_eq!(
            (rows[1].floor_units(), rows[1].cap_units()),
            (Some(2), Some(4))
        );
        assert_eq!(
            rows[2].selector(),
            &BudgetPolicySelector::Purpose(CallPurpose::Voice)
        );
        assert_eq!(
            (rows[2].floor_units(), rows[2].cap_units()),
            (None, Some(3))
        );
        Ok(())
    }

    #[test]
    fn budget_policy_changes_policy_frontier_hash() -> Result<()> {
        fn frontier_hash_without_entry() -> Result<[u8; 32]> {
            let (_tmp, vault) = temp_vault();
            put_policy_manifest_bytes(&vault, test_id(0x30), &encode_policy_manifest(vec![]))?;
            resolve(&vault)?.read_frontier_hash()
        }
        fn frontier_hash_with(rows: Vec<Value>) -> Result<[u8; 32]> {
            let (_tmp, vault) = temp_vault();
            let policy = resolved_table(&vault, 0x30, rows)?;
            policy.read_frontier_hash()
        }

        let absent = frontier_hash_without_entry()?;
        let explicit_empty = frontier_hash_with(vec![])?;
        assert_eq!(
            absent, explicit_empty,
            "absent and explicit empty hash identically"
        );

        let base = vec![purpose_row_value("consolidation", Some(100), None)];
        let base_hash = frontier_hash_with(base)?;
        assert_ne!(base_hash, absent, "present rows change the hash");

        let selector_changed =
            frontier_hash_with(vec![purpose_row_value("extraction", Some(100), None)])?;
        assert_ne!(
            selector_changed, base_hash,
            "selector change changes the hash"
        );
        let floor_changed =
            frontier_hash_with(vec![purpose_row_value("consolidation", Some(101), None)])?;
        assert_ne!(floor_changed, base_hash, "floor change changes the hash");
        let cap_changed = frontier_hash_with(vec![purpose_row_value(
            "consolidation",
            Some(100),
            Some(500),
        )])?;
        assert_ne!(cap_changed, base_hash, "cap change changes the hash");

        let ordered_ab = frontier_hash_with(vec![
            purpose_row_value("consolidation", Some(100), None),
            purpose_row_value("voice", None, Some(5)),
        ])?;
        let ordered_ba = frontier_hash_with(vec![
            purpose_row_value("voice", None, Some(5)),
            purpose_row_value("consolidation", Some(100), None),
        ])?;
        assert_ne!(ordered_ab, ordered_ba, "row order is frontier-relevant");

        // A malformed table drops its whole manifest from decoded rows; the
        // fail-closed resolution hashes deterministically and differs from
        // the well-formed hash.
        let (_tmp, malformed_vault) = temp_vault();
        put_policy_manifest_bytes(
            &malformed_vault,
            test_id(0x30),
            &encode_policy_manifest(vec![budget_policy_entry(vec![Value::from("not-a-row")])]),
        )?;
        let malformed = resolve(&malformed_vault)?;
        assert!(malformed.diagnostics().malformed_manifest_seen);
        assert!(malformed.budget_policy().is_none());
        let malformed_hash = malformed.read_frontier_hash()?;
        let malformed_again = resolve(&malformed_vault)?.read_frontier_hash()?;
        assert_eq!(
            malformed_hash, malformed_again,
            "fail-closed resolution hashes deterministically"
        );
        assert_ne!(
            malformed_hash, base_hash,
            "malformed table never aliases a well-formed hash"
        );
        Ok(())
    }

    #[test]
    fn budget_policy_row_overflow_fails_resolution_closed() -> Result<()> {
        let overflow_row = || purpose_row_value("extraction", Some(1), None);

        // Exactly u16::MAX + 1 rows stay valid: every index 0..=65535 is
        // addressable.
        let (_tmp_ok, ok_vault) = temp_vault();
        let max_rows: Vec<Value> = (0..=usize::from(u16::MAX))
            .map(|_| overflow_row())
            .collect();
        assert_eq!(max_rows.len(), usize::from(u16::MAX) + 1);
        let ok_policy = resolved_table(&ok_vault, 0x30, max_rows)?;
        let ok_table = ok_policy.budget_policy().expect("65,536 rows stay valid");
        assert_eq!(ok_table.rows().len(), usize::from(u16::MAX) + 1);
        assert_eq!(
            ok_table.rows()[usize::from(u16::MAX)].selector(),
            &BudgetPolicySelector::Purpose(CallPurpose::Extraction),
            "index 65,535 remains addressable"
        );

        // One row more marks the resolution malformed and fails closed.
        let (_tmp_over, over_vault) = temp_vault();
        let overflow_rows: Vec<Value> = (0..=usize::from(u16::MAX))
            .map(|_| overflow_row())
            .chain(std::iter::once_with(overflow_row))
            .collect();
        assert_eq!(overflow_rows.len(), usize::from(u16::MAX) + 2);
        let over_policy = resolved_table(&over_vault, 0x30, overflow_rows)?;
        assert!(over_policy.diagnostics().malformed_manifest_seen);
        assert!(
            over_policy
                .diagnostics()
                .loaded_manifest_forces_fail_closed()
        );
        assert!(over_policy.budget_policy().is_none());
        Ok(())
    }

    #[test]
    fn budget_policy_guard_factory_fails_closed_on_malformed_manifest() -> Result<()> {
        let actor = WriteActor::new(test_id(0x44), EdgeActorClass::Agent);

        // A malformed budget_policy table fails the loaded manifest closed
        // and the factory refuses: production never gets a legacy
        // empty-table guard.
        let (_tmp_bad, bad_vault) = temp_vault();
        put_policy_manifest_bytes(
            &bad_vault,
            test_id(0x30),
            &encode_policy_manifest(vec![budget_policy_entry(vec![Value::from("not-a-row")])]),
        )?;
        let bad = bad_vault
            .policy_budget_guard("job", 100, 10, BudgetExhaustionPolicy::Suspend, actor)
            .expect_err("malformed manifest refuses guard construction");
        assert!(matches!(bad, Error::InvalidConfig(_)));
        assert_eq!(bad.kind(), ErrorKind::InvalidConfig);

        // The missing-schema_version case fail-closes the same way.
        let (_tmp_schema, schema_vault) = temp_vault();
        let mut schema_data =
            encode_policy_manifest(vec![budget_policy_entry(vec![purpose_row_value(
                "consolidation",
                Some(30),
                None,
            )])]);
        rewrite_policy_manifest_entries(&mut schema_data, |entries| {
            entries.retain(|(key, _)| key.as_str() != Some(POLICY_SCHEMA_VERSION_KEY));
        });
        put_policy_manifest_bytes(&schema_vault, test_id(0x30), &schema_data)?;
        let schema_policy = resolve(&schema_vault)?;
        assert!(schema_policy.diagnostics().unsupported_schema_seen);
        let schema_err = schema_vault
            .policy_budget_guard("job", 100, 10, BudgetExhaustionPolicy::Suspend, actor)
            .expect_err("unsupported schema refuses guard construction");
        assert!(matches!(schema_err, Error::InvalidConfig(_)));

        // Control: a valid manifest builds the policy-aware guard, and an
        // absent manifest keeps the bootstrap single-pool guard.
        let (_tmp_ok, ok_vault) = temp_vault();
        put_policy_manifest_bytes(
            &ok_vault,
            test_id(0x30),
            &encode_policy_manifest(vec![budget_policy_entry(vec![purpose_row_value(
                "consolidation",
                Some(30),
                None,
            )])]),
        )?;
        ok_vault
            .policy_budget_guard("job", 100, 10, BudgetExhaustionPolicy::Suspend, actor)
            .expect("valid manifest constructs the policy-aware guard");
        let (_tmp_none, none_vault) = temp_vault();
        none_vault
            .policy_budget_guard("job", 100, 10, BudgetExhaustionPolicy::Suspend, actor)
            .expect("absent manifest keeps the bootstrap guard");
        Ok(())
    }
}

#[test]
fn delegated_manifest_decode_rejects_unknown_keys() -> Result<()> {
    let row = Value::Map(vec![
        (Value::from("op"), Value::from("grant")),
        (Value::from("grant_ref"), Value::from("g")),
        (Value::from(ACTOR_CLASS_KEY), Value::from("agent")),
        (Value::from(ACTOR_CEILING_KEY), Value::from("auto")),
        (Value::from("future_row_key"), Value::Boolean(true)),
    ]);
    assert!(parse_delegated_grants(&Value::Array(vec![row])).is_none());
    let revoke = Value::Map(vec![
        (Value::from("op"), Value::from("revoke_grant")),
        (Value::from("grant_ref"), Value::from("g")),
        (Value::from(ACTOR_CLASS_KEY), Value::from("agent")),
    ]);
    assert!(parse_delegated_grants(&Value::Array(vec![revoke])).is_none());

    let (_tmp, vault) = temp_vault();
    let mut cursor = Cursor::new(encode_policy_manifest(vec![]));
    let Value::Map(mut entries) = rmpv::decode::read_value(&mut cursor).expect("decode") else {
        unreachable!("manifest is a map");
    };
    entries.push((Value::from("future_pack_key"), Value::Boolean(true)));
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &Value::Map(entries)).expect("encode");
    put_policy_manifest_bytes(&vault, test_id(0xF1), &encoded)?;
    let policy = resolve(&vault)?;
    assert!(policy.diagnostics.malformed_manifest_seen);
    assert!(policy.is_fail_closed());
    assert!(policy.delegation_fold.records.is_empty());
    Ok(())
}

#[test]
fn revoke_parent_zeroes_subtree_at_fold() {
    let rows = vec![
        DelegationGrantRecord::Grant {
            grant_ref: "root".into(),
            actor_class: "agent".into(),
            actor_ref: None,
            parent_grant_ref: None,
            ceiling: PolicyApprovalCeiling::Auto,
        },
        DelegationGrantRecord::Grant {
            grant_ref: "child".into(),
            actor_class: "agent".into(),
            actor_ref: None,
            parent_grant_ref: Some("root".into()),
            ceiling: PolicyApprovalCeiling::Auto,
        },
        DelegationGrantRecord::RevokeGrant {
            grant_ref: "root".into(),
        },
    ];
    let cache = fold_delegated_grants(&rows).expect("valid fold");
    assert_eq!(cache.effective_ceiling("root"), None);
    assert_eq!(cache.effective_ceiling("child"), None);
}

#[test]
fn revoke_dominates_grant() {
    let rows = vec![
        DelegationGrantRecord::Grant {
            grant_ref: "g".into(),
            actor_class: "agent".into(),
            actor_ref: None,
            parent_grant_ref: None,
            ceiling: PolicyApprovalCeiling::Auto,
        },
        DelegationGrantRecord::RevokeGrant {
            grant_ref: "g".into(),
        },
    ];
    let cache = fold_delegated_grants(&rows).expect("valid fold");
    assert_eq!(cache.effective_ceiling("g"), None);
    assert!(cache.revoked.contains("g"));
}

#[test]
fn depth_cap_8() {
    let mut rows = Vec::new();
    for i in 0..8 {
        rows.push(DelegationGrantRecord::Grant {
            grant_ref: format!("g{i}"),
            actor_class: "agent".into(),
            actor_ref: None,
            parent_grant_ref: (i > 0).then(|| format!("g{}", i - 1)),
            ceiling: PolicyApprovalCeiling::Auto,
        });
    }
    assert!(fold_delegated_grants(&rows).is_some());
    rows.push(DelegationGrantRecord::Grant {
        grant_ref: "g8".into(),
        actor_class: "agent".into(),
        actor_ref: None,
        parent_grant_ref: Some("g7".into()),
        ceiling: PolicyApprovalCeiling::Auto,
    });
    assert!(fold_delegated_grants(&rows).is_none());
    let cycle = vec![
        DelegationGrantRecord::Grant {
            grant_ref: "a".into(),
            actor_class: "agent".into(),
            actor_ref: None,
            parent_grant_ref: Some("b".into()),
            ceiling: PolicyApprovalCeiling::Auto,
        },
        DelegationGrantRecord::Grant {
            grant_ref: "b".into(),
            actor_class: "agent".into(),
            actor_ref: None,
            parent_grant_ref: Some("a".into()),
            ceiling: PolicyApprovalCeiling::Auto,
        },
    ];
    assert!(fold_delegated_grants(&cycle).is_none());
    let missing = vec![DelegationGrantRecord::Grant {
        grant_ref: "a".into(),
        actor_class: "agent".into(),
        actor_ref: None,
        parent_grant_ref: Some("missing".into()),
        ceiling: PolicyApprovalCeiling::Auto,
    }];
    assert!(fold_delegated_grants(&missing).is_none());
}

#[test]
fn adversarial_long_chain_fail_closed_no_stack_overflow() {
    const CHAIN_LEN: usize = 65_536;
    let rows = (0..CHAIN_LEN)
        .map(|i| DelegationGrantRecord::Grant {
            grant_ref: format!("{i:05}"),
            actor_class: "agent".into(),
            actor_ref: None,
            parent_grant_ref: (i + 1 < CHAIN_LEN).then(|| format!("{:05}", i + 1)),
            ceiling: PolicyApprovalCeiling::Auto,
        })
        .collect::<Vec<_>>();
    assert!(fold_delegated_grants(&rows).is_none());
}

#[test]
fn fold_cache_hit() {
    let rows = vec![DelegationGrantRecord::Grant {
        grant_ref: "g".into(),
        actor_class: "agent".into(),
        actor_ref: None,
        parent_grant_ref: None,
        ceiling: PolicyApprovalCeiling::Auto,
    }];
    let cache = fold_delegated_grants(&rows).expect("valid fold");
    assert_eq!(cache.effective_ceiling("g"), cache.effective_ceiling("g"));
    let rebuilt = fold_delegated_grants(&rows).expect("valid rebuild");
    assert_eq!(cache, rebuilt);
}

#[test]
fn delegated_ceiling_never_raises_proposed_to_auto() {
    let rows = vec![DelegationGrantRecord::Grant {
        grant_ref: "g".into(),
        actor_class: "agent".into(),
        actor_ref: None,
        parent_grant_ref: None,
        ceiling: PolicyApprovalCeiling::Proposed,
    }];
    let cache = fold_delegated_grants(&rows).expect("valid fold");
    assert_eq!(
        cache.effective_ceiling("g"),
        Some(PolicyApprovalCeiling::Proposed)
    );
    assert_eq!(
        PolicyApprovalCeiling::Proposed.restrict(cache.effective_ceiling("g").unwrap()),
        PolicyApprovalCeiling::Proposed
    );
}

#[test]
fn delegated_grants_manifest_hash_deterministic() -> Result<()> {
    let grant = Value::Map(vec![
        (Value::from("op"), Value::from("grant")),
        (Value::from("grant_ref"), Value::from("manifest-grant")),
        (Value::from(ACTOR_CLASS_KEY), Value::from("agent")),
        (Value::from(ACTOR_CEILING_KEY), Value::from("auto")),
    ]);
    let revoke = Value::Map(vec![
        (Value::from("op"), Value::from("revoke_grant")),
        (Value::from("grant_ref"), Value::from("manifest-grant")),
    ]);
    let delegated = |row: Value| {
        vec![(
            Value::from(POLICY_DELEGATED_GRANTS_KEY),
            Value::Array(vec![row]),
        )]
    };

    let (_tmp_a, vault_a) = temp_vault();
    let grant_data = encode_policy_manifest(delegated(grant.clone()));
    put_policy_manifest_bytes(&vault_a, test_id(0xD8), &grant_data)?;
    let grant_policy_a = resolve(&vault_a)?;
    let grant_hash_a = grant_policy_a.read_frontier_hash()?;

    let (_tmp_b, vault_b) = temp_vault();
    let grant_data_b = encode_policy_manifest(delegated(grant));
    put_policy_manifest_bytes(&vault_b, test_id(0xD9), &grant_data_b)?;
    let grant_policy_b = resolve(&vault_b)?;
    assert_eq!(grant_hash_a, grant_policy_b.read_frontier_hash()?);

    let (_tmp_c, vault_c) = temp_vault();
    let revoke_data = encode_policy_manifest(delegated(revoke));
    put_policy_manifest_bytes(&vault_c, test_id(0xDA), &revoke_data)?;
    let revoke_policy = resolve(&vault_c)?;
    assert_ne!(grant_hash_a, revoke_policy.read_frontier_hash()?);

    let (_tmp_d, vault_d) = temp_vault();
    let mut duplicate_data = encode_policy_manifest(vec![(
        Value::from(POLICY_DELEGATED_GRANTS_KEY),
        Value::Array(vec![]),
    )]);
    duplicate_data = {
        let mut cursor = Cursor::new(duplicate_data.as_slice());
        let Value::Map(mut entries) = rmpv::decode::read_value(&mut cursor).expect("decode") else {
            unreachable!("manifest is a map");
        };
        entries.push((
            Value::from(POLICY_DELEGATED_GRANTS_KEY),
            Value::Array(vec![]),
        ));
        let mut encoded = Vec::new();
        rmpv::encode::write_value(&mut encoded, &Value::Map(entries)).expect("re-encode");
        encoded
    };
    put_policy_manifest_bytes(&vault_d, test_id(0xDB), &duplicate_data)?;
    let duplicate_policy = resolve(&vault_d)?;
    assert!(duplicate_policy.diagnostics.malformed_manifest_seen);
    Ok(())
}

fn delegated_manifest_row(
    grant_ref: &str,
    actor_class: &str,
    actor_ref: Option<&str>,
    parent_grant_ref: Option<&str>,
    ceiling: &str,
) -> Value {
    let mut row = vec![
        (Value::from("op"), Value::from("grant")),
        (Value::from("grant_ref"), Value::from(grant_ref)),
        (Value::from(ACTOR_CLASS_KEY), Value::from(actor_class)),
        (Value::from(ACTOR_CEILING_KEY), Value::from(ceiling)),
    ];
    if let Some(actor_ref) = actor_ref {
        row.push((Value::from(ACTOR_REF_KEY), Value::from(actor_ref)));
    }
    if let Some(parent) = parent_grant_ref {
        row.push((Value::from("parent_grant_ref"), Value::from(parent)));
    }
    Value::Map(row)
}

fn delegated_manifest_revoke_row(grant_ref: &str) -> Value {
    Value::Map(vec![
        (Value::from("op"), Value::from("revoke_grant")),
        (Value::from("grant_ref"), Value::from(grant_ref)),
    ])
}

fn delegated_manifest_entry(rows: Vec<Value>) -> (Value, Value) {
    (Value::from(POLICY_DELEGATED_GRANTS_KEY), Value::Array(rows))
}

#[test]
fn cross_manifest_chain_order_independent() -> Result<()> {
    let run = |child_id: u8,
               root_id: u8|
     -> Result<(Option<PolicyApprovalCeiling>, Option<PolicyApprovalCeiling>)> {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(
            &vault,
            test_id(child_id),
            &encode_policy_manifest(vec![delegated_manifest_entry(vec![
                delegated_manifest_row("child", "agent", None, Some("parent"), "proposed"),
            ])]),
        )?;
        put_policy_manifest_bytes(
            &vault,
            test_id(root_id),
            &encode_policy_manifest(vec![delegated_manifest_entry(vec![
                delegated_manifest_row("parent", "agent", None, None, "auto"),
            ])]),
        )?;
        let policy = resolve(&vault)?;
        assert!(!policy.diagnostics.malformed_manifest_seen);
        Ok((
            policy.delegation_fold.effective_ceiling("parent"),
            policy.delegation_fold.effective_ceiling("child"),
        ))
    };
    let expected = (
        Some(PolicyApprovalCeiling::Auto),
        Some(PolicyApprovalCeiling::Proposed),
    );
    assert_eq!(run(0x10, 0xF0)?, expected);
    assert_eq!(run(0xF0, 0x10)?, expected);
    Ok(())
}

#[test]
fn cross_manifest_revoke_dominance() -> Result<()> {
    let run = |grant_id: u8,
               revoke_id: u8|
     -> Result<(Option<PolicyApprovalCeiling>, Option<PolicyApprovalCeiling>)> {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(
            &vault,
            test_id(grant_id),
            &encode_policy_manifest(vec![delegated_manifest_entry(vec![
                delegated_manifest_row("parent", "agent", None, None, "auto"),
                delegated_manifest_row("child", "agent", None, Some("parent"), "auto"),
            ])]),
        )?;
        put_policy_manifest_bytes(
            &vault,
            test_id(revoke_id),
            &encode_policy_manifest(vec![delegated_manifest_entry(vec![
                delegated_manifest_revoke_row("parent"),
            ])]),
        )?;
        let policy = resolve(&vault)?;
        assert!(!policy.diagnostics.malformed_manifest_seen);
        Ok((
            policy.delegation_fold.effective_ceiling("parent"),
            policy.delegation_fold.effective_ceiling("child"),
        ))
    };
    assert_eq!(run(0x20, 0xE0)?, (None, None));
    assert_eq!(run(0xE0, 0x20)?, (None, None));
    Ok(())
}

#[test]
fn evaluate_gate_delegation_binding() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut data = encode_policy_manifest(vec![delegated_manifest_entry(vec![
        delegated_manifest_row("bound-auto", "agent", Some("dispatch"), None, "auto"),
        delegated_manifest_row(
            "bound-proposed",
            "agent",
            Some("dispatch"),
            None,
            "proposed",
        ),
        delegated_manifest_row("other-class", "human", Some("dispatch"), None, "auto"),
    ])]);
    replace_actor_ceilings(&mut data, vec![actor_ceiling_row("agent", "auto")]);
    put_policy_manifest_bytes(&vault, test_id(0x30), &data)?;
    let policy = resolve(&vault)?;

    let mut exact = gate_evaluator_input(
        "agent",
        Some("dispatch"),
        ClaimSource::UserStated,
        PolicyCriticality::Normal,
    );
    exact.actor.delegation_grant_ref = Some("bound-auto".into());
    assert_eq!(policy.evaluate_gate(&exact).outcome(), GateOutcome::Allow);

    for (grant_ref, actor_class, actor_ref) in [
        ("other-class", "agent", "dispatch"),
        ("bound-auto", "agent", "wrong"),
        ("unknown", "agent", "dispatch"),
    ] {
        let mut input = gate_evaluator_input(
            actor_class,
            Some(actor_ref),
            ClaimSource::UserStated,
            PolicyCriticality::Normal,
        );
        input.actor.delegation_grant_ref = Some(grant_ref.into());
        let decision = policy.evaluate_gate(&input);
        assert_eq!(decision.outcome(), GateOutcome::Pending);
        assert!(
            decision
                .reason_codes()
                .contains(&GateReasonCode::PendingActorCeiling)
        );
    }

    let mut revoked = exact;
    revoked.actor.delegation_grant_ref = Some("bound-auto".into());
    // A later revoke dominates the grant, regardless of manifest ordering.
    let (_tmp, revoked_vault) = temp_vault();
    put_policy_manifest_bytes(&revoked_vault, test_id(0x31), &data)?;
    put_policy_manifest_bytes(
        &revoked_vault,
        test_id(0x32),
        &encode_policy_manifest(vec![delegated_manifest_entry(vec![
            delegated_manifest_revoke_row("bound-auto"),
        ])]),
    )?;
    let revoked_policy = resolve(&revoked_vault)?;
    let decision = revoked_policy.evaluate_gate(&revoked);
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert!(
        decision
            .reason_codes()
            .contains(&GateReasonCode::PendingActorCeiling)
    );

    let mut proposed = gate_evaluator_input(
        "agent",
        Some("dispatch"),
        ClaimSource::UserStated,
        PolicyCriticality::Normal,
    );
    proposed.actor.delegation_grant_ref = Some("bound-auto".into());
    proposed.criticality = PolicyCriticality::Normal;
    proposed.source = Some(ClaimSource::UserStated);
    // Proposed ordinary approval must not become Auto through delegation.
    // (The gate input's approval mode is represented by criticality in this fixture.)
    proposed.actor.delegation_grant_ref = Some("bound-proposed".into());
    assert_ne!(
        policy.evaluate_gate(&proposed).outcome(),
        GateOutcome::Allow
    );

    // The ordinary actor ceiling also participates in the meet: a Proposed
    // ordinary ceiling must not be widened by a bound Auto delegation grant.
    let (_tmp, ordinary_proposed_vault) = temp_vault();
    let mut ordinary_data = encode_policy_manifest(vec![delegated_manifest_entry(vec![
        delegated_manifest_row(
            "ordinary-proposed-bound-auto",
            "agent",
            Some("dispatch"),
            None,
            "auto",
        ),
    ])]);
    replace_actor_ceilings(
        &mut ordinary_data,
        vec![actor_ceiling_row("agent", "proposed")],
    );
    put_policy_manifest_bytes(&ordinary_proposed_vault, test_id(0x33), &ordinary_data)?;
    let ordinary_policy = resolve(&ordinary_proposed_vault)?;
    let mut ordinary_input = gate_evaluator_input(
        "agent",
        Some("dispatch"),
        ClaimSource::UserStated,
        PolicyCriticality::Normal,
    );
    ordinary_input.actor.delegation_grant_ref = Some("ordinary-proposed-bound-auto".into());
    let ordinary_decision = ordinary_policy.evaluate_gate(&ordinary_input);
    assert_eq!(ordinary_decision.outcome(), GateOutcome::Pending);
    assert!(
        ordinary_decision
            .reason_codes()
            .contains(&GateReasonCode::PendingActorCeiling)
    );
    Ok(())
}

fn critical_confirm_pending(
    claim: EntityId,
    decision: u8,
    created_at: u64,
) -> PendingGateConsentRecord {
    PendingGateConsentRecord {
        version: 0,
        claim_id: *claim.as_bytes(),
        decision_id: GateDecisionId::from_bytes([decision; 16]),
        created_at,
        diff_handle: vec![decision, decision.wrapping_add(1)],
        read_frontier_hash: [decision.wrapping_add(2); 32],
        reason_codes: vec!["gate.pending.critical_confirm_attached".to_owned()],
        dreamer_run_id: None,
    }
}

#[test]
fn critical_write_confirm_binding_is_deterministic_and_fail_closed_on_non_attachment() {
    let claim = test_id(0x74);
    let pending = critical_confirm_pending(claim, 31, 100);
    let binding = critical_write_confirm_binding(&pending).expect("attached pending row binds");
    assert_eq!(binding.nonce, [31; 16]);
    assert_eq!(
        binding.expires_at,
        100 + CRITICAL_WRITE_CONFIRM_TIMEOUT_SECS
    );
    assert_ne!(binding.confirm_id, [0; 32]);

    let mut stale = pending.clone();
    stale.read_frontier_hash[0] ^= 1;
    assert_ne!(
        binding.confirm_id,
        critical_write_confirm_binding(&stale).unwrap().confirm_id,
        "a frontier mismatch must derive a different confirmation id"
    );
    stale.reason_codes.clear();
    assert!(
        critical_write_confirm_binding(&stale).is_err(),
        "unmarked pending consent must not be interpreted as a critical confirmation"
    );
}

#[test]
fn critical_write_confirm_expiry_is_a_terminal_demotion_only() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0x75);
    let subject = test_id(0x21);
    put_raw_entity_row(
        &vault,
        &subject,
        crate::registry::ENTITY_TYPE_PERSON,
        b"subject",
    )?;
    let mut body = source_trust_claim(ClaimSource::UserStated);
    body.approval = ClaimApprovalStatus::Auto;
    put_claim_body(&vault, &claim, &body)?;
    let pending = critical_confirm_pending(claim, 32, 100);
    vault.with_write_txn(|wtxn| vault.store.put_pending_gate_consent_in_txn(wtxn, &pending))?;

    assert_eq!(vault.expire_critical_write_confirms_at(399)?, 0);
    assert_eq!(
        stored_claim_body(&vault, &claim)?.approval,
        ClaimApprovalStatus::Auto
    );
    assert_eq!(vault.expire_critical_write_confirms_at(400)?, 1);
    assert_eq!(
        stored_claim_body(&vault, &claim)?.approval,
        ClaimApprovalStatus::Proposed,
        "expiry must demote rather than delete or approve the claim"
    );
    let timed_out = vault.with_write_txn(|wtxn| {
        vault
            .store
            .pending_gate_consent_in_txn(wtxn, &claim)?
            .ok_or(Error::CorruptedIndex("timed-out pending gate consent"))
    })?;
    assert_eq!(
        timed_out.reason_codes,
        vec![GATE_REASON_CRITICAL_CONFIRM_TIMEOUT.to_owned()],
        "expiry must replace every pending reason with its sole terminal marker"
    );
    assert_eq!(
        stored_claim_body(&vault, &claim)?.approval,
        ClaimApprovalStatus::Proposed,
        "expiry must demote rather than delete or approve the claim"
    );
    assert!(
        critical_write_confirm_binding(&timed_out).is_ok(),
        "the terminal marker remains a valid binding for audit/replay safety"
    );
    assert!(
        vault.pending_critical_write_confirms(10)?.is_empty(),
        "an expired attachment is not an outstanding confirmation"
    );
    Ok(())
}

#[test]
fn pending_critical_confirms_sweep_bounded_pages_and_demotes_every_expired_claim() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let now = crate::unix_seconds_now();
    let expiring = [sweep_id(0xf0, 1), sweep_id(0xf0, 2), sweep_id(0xf0, 3)];
    let live = [sweep_id(0xf0, 4), sweep_id(0xf0, 5)];
    vault.with_write_txn(|wtxn| {
        // 600 non-critical rows plus five critical rows require more than two pages.
        for ordinal in 0..600u16 {
            let claim = EntityId::from_bytes([
                0x10,
                (ordinal >> 8) as u8,
                ordinal as u8,
                0x5a,
                0x10,
                (ordinal >> 8) as u8,
                ordinal as u8,
                0x5a,
                0x10,
                (ordinal >> 8) as u8,
                ordinal as u8,
                0x5a,
                0x10,
                (ordinal >> 8) as u8,
                ordinal as u8,
                0x5a,
            ])
            .expect("sweep fixture id");
            let ordinary = PendingGateConsentRecord {
                version: 0,
                claim_id: *claim.as_bytes(),
                decision_id: GateDecisionId::from_bytes([(ordinal % 251) as u8 + 1; 16]),
                created_at: now,
                diff_handle: vec![ordinal as u8],
                read_frontier_hash: [((ordinal + 1) & 0xff) as u8; 32],
                reason_codes: vec!["gate.pending.ordinary".to_owned()],
                dreamer_run_id: None,
            };
            vault
                .store
                .put_pending_gate_consent_in_txn(wtxn, &ordinary)?;
        }
        for (ordinal, claim) in expiring.iter().enumerate() {
            vault.store.put_pending_gate_consent_in_txn(
                wtxn,
                &critical_confirm_pending(*claim, 240 + ordinal as u8, 1),
            )?;
        }
        for (ordinal, claim) in live.iter().enumerate() {
            vault.store.put_pending_gate_consent_in_txn(
                wtxn,
                &critical_confirm_pending(*claim, 250 + ordinal as u8, now),
            )?;
        }
        Ok(())
    })?;
    for claim in expiring {
        let mut body = source_trust_claim(ClaimSource::UserStated);
        body.approval = ClaimApprovalStatus::Auto;
        put_claim_body(&vault, &claim, &body)?;
    }

    // Each invocation inspects only a single 256-row page. The two cursors
    // nevertheless reach critical rows after an ordinary first page.
    assert!(vault.pending_critical_write_confirms(1)?.is_empty());
    assert!(vault.pending_critical_write_confirms(1)?.is_empty());
    let outstanding = vault.pending_critical_write_confirms(305)?;
    assert_eq!(outstanding.len(), 2);
    assert_eq!(
        outstanding
            .iter()
            .map(|binding| binding.claim_id)
            .collect::<Vec<_>>(),
        live,
        "live critical rows past the first store page remain discoverable"
    );
    for claim in expiring {
        assert_eq!(
            stored_claim_body(&vault, &claim)?.approval,
            ClaimApprovalStatus::Proposed
        );
    }

    // Re-arm the three already-demoted claims to make the explicit sweep count deterministic.
    for (ordinal, claim) in expiring.iter().enumerate() {
        vault.with_write_txn(|wtxn| {
            vault.store.put_pending_gate_consent_in_txn(
                wtxn,
                &critical_confirm_pending(*claim, 240 + ordinal as u8, 1),
            )
        })?;
        let mut body = source_trust_claim(ClaimSource::UserStated);
        body.approval = ClaimApprovalStatus::Auto;
        put_claim_body(&vault, claim, &body)?;
    }
    assert_eq!(
        vault.expire_critical_write_confirms_at(1 + CRITICAL_WRITE_CONFIRM_TIMEOUT_SECS)?,
        0
    );
    assert_eq!(
        vault.expire_critical_write_confirms_at(1 + CRITICAL_WRITE_CONFIRM_TIMEOUT_SECS)?,
        0
    );
    assert_eq!(
        vault.expire_critical_write_confirms_at(1 + CRITICAL_WRITE_CONFIRM_TIMEOUT_SECS)?,
        3
    );
    Ok(())
}

#[test]
fn timeout_marker_remains_a_valid_critical_confirm_binding() {
    let pending = critical_confirm_pending(test_id(0x76), 33, 100);
    let original = critical_write_confirm_binding(&pending).unwrap();
    let mut timed_out = pending;
    timed_out.reason_codes = vec![GATE_REASON_CRITICAL_CONFIRM_TIMEOUT.to_owned()];
    assert_eq!(
        critical_write_confirm_binding(&timed_out).unwrap(),
        original
    );
}

fn critical_confirm_owner_entry(
    pending: &PendingGateConsentRecord,
    disposition: crate::authority::CriticalWriteConfirmDisposition,
    seed: u8,
) -> (
    crate::authority::AuthorityLogEntry,
    crate::authority::AuthorityLogEntry,
) {
    use crate::authority::{
        AuthorityAttestation, AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature,
        AuthorityTier, CriticalWriteConfirmAction, CriticalWriteConfirmMethod, DeviceAuthority,
        ROLE_ADMIN, ROLE_OWNER,
    };
    use ed25519_dalek::{Signer, SigningKey};

    let signing = SigningKey::from_bytes(&[seed; 32]);
    let key = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let sign = |mut entry: AuthorityLogEntry| {
        let transcript =
            crate::authority::authority_transcript(&entry).expect("authority transcript");
        entry.signer.signature = signing.sign(&transcript).to_bytes().to_vec();
        entry
    };
    let genesis = sign(AuthorityLogEntry {
        schema_version: crate::authority::AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: None,
        seq: 0,
        parent_hashes: Vec::new(),
        op: AuthorityOp::Genesis {
            device: DeviceAuthority {
                key: key.clone(),
                transport_key_binding: [7; 32],
                attestation: AuthorityAttestation {
                    kind: "SoftwareArgon2id".to_owned(),
                    evidence: vec![1, 2, 3],
                },
                tier: AuthorityTier::Software,
                roles: ROLE_OWNER | ROLE_ADMIN,
            },
            genesis_nonce: [seed.wrapping_add(1); 32],
            tier_floor: AuthorityTier::Software,
            pending_widen_delay_secs: crate::authority::DEFAULT_PENDING_WIDEN_DELAY_SECS,
        },
        signer: AuthoritySignature {
            suite: key.suite(),
            public_key: key.clone(),
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: 1,
    });
    let binding = critical_write_confirm_binding(pending).expect("critical pending binding");
    let confirmation = sign(AuthorityLogEntry {
        schema_version: crate::authority::AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(crate::authority::genesis_vault_id(&genesis).expect("vault id")),
        seq: 1,
        parent_hashes: vec![
            crate::authority::authority_entry_hash(&genesis).expect("genesis hash"),
        ],
        op: AuthorityOp::CriticalWriteConfirm(CriticalWriteConfirmAction {
            schema_version: crate::authority::CRITICAL_WRITE_CONFIRM_SCHEMA_VERSION,
            confirm_id: binding.confirm_id,
            gate_decision_id: binding.gate_decision_id.as_bytes(),
            claim_id: binding.claim_id,
            effect_digest: binding.effect_digest,
            read_frontier_hash: binding.read_frontier_hash,
            nonce: binding.nonce,
            expires_at: binding.expires_at,
            disposition,
            method: CriticalWriteConfirmMethod::TokenReauth,
        }),
        signer: AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: 2,
    });
    (genesis, confirmation)
}

fn put_critical_auto_claim(
    vault: &crate::Vault,
    claim: EntityId,
) -> Result<PendingGateConsentRecord> {
    let data = encode_policy_manifest(vec![source_trust_entry(ClaimSource::UserStated, 0)]);
    put_policy_manifest_bytes(vault, test_id(0xee), &data)?;
    let mut body = public_stamped(source_trust_claim(ClaimSource::UserStated));
    body.predicate = "health.allergy".to_owned();
    let (candidate, envelope) = claim_candidate_write_parts(vault, &body)?;
    vault
        .batch()
        .claim_candidate(&claim, candidate, &envelope, test_time(3), 3)
        .commit()?;
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .pending_gate_consent_in_txn(wtxn, &claim)?
            .ok_or(Error::EntityNotFound)
    })
}

#[test]
fn pending_critical_confirms_limit_zero_is_a_true_noop() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    crate::panic_on_unix_seconds_now_for_current_thread(true);
    crate::store::panic_on_active_write_txn_for_current_thread(true);
    let result = vault.pending_critical_write_confirms(0);
    crate::store::panic_on_active_write_txn_for_current_thread(false);
    crate::panic_on_unix_seconds_now_for_current_thread(false);
    assert!(result?.is_empty());
    vault.with_write_txn(|wtxn| {
        assert_eq!(
            vault
                .store
                .critical_confirm_list_sweep_state_in_txn(&*wtxn)?,
            (None, None),
            "limit zero must not create or advance list state",
        );
        assert_eq!(
            vault
                .store
                .critical_confirm_expiry_sweep_state_in_txn(&*wtxn)?,
            (None, None),
            "limit zero must not invoke the expiry sweep",
        );
        Ok(())
    })?;
    Ok(())
}

#[test]
fn pending_critical_confirms_limit_one_advances_through_same_page_matches() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let first = sweep_id(0xd0, 1);
    let second = sweep_id(0xd0, 2);
    vault.with_write_txn(|wtxn| {
        vault.store.put_pending_gate_consent_in_txn(
            wtxn,
            &critical_confirm_pending(first, 1, crate::unix_seconds_now()),
        )?;
        vault.store.put_pending_gate_consent_in_txn(
            wtxn,
            &critical_confirm_pending(second, 2, crate::unix_seconds_now()),
        )
    })?;
    assert_eq!(
        vault.pending_critical_write_confirms(1)?[0].claim_id,
        first,
        "the first returned row is the first inspected key"
    );
    assert_eq!(
        vault.pending_critical_write_confirms(1)?[0].claim_id,
        second,
        "the cursor must not advance past a same-page match withheld by limit"
    );
    Ok(())
}

#[test]
fn critical_auto_batch_write_attaches_pending_confirm_and_allow_receipt() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0x81);
    let pending = put_critical_auto_claim(&vault, claim)?;
    assert_eq!(
        pending.reason_codes,
        vec![GATE_REASON_PENDING_CRITICAL_CONFIRM_ATTACHED.to_owned()]
    );
    let decision = vault
        .store
        .gate_decisions(10)?
        .into_iter()
        .find(|row| row.claim_id == Some(*claim.as_bytes()))
        .expect("write receipt");
    assert_eq!(decision.outcome, "allow");
    assert_eq!(
        decision.receipt_reasons,
        vec![GATE_REASON_ALLOW_CRITICAL_CONFIRM_ATTACHED.to_owned()]
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn rematerialized_critical_claim_overwrite_invalidates_attachment_and_rejects_stale_clear()
-> Result<()> {
    use crate::sync::bridge::Materializer;
    use crate::sync::loro_support::map_insert_bytes;
    use crate::sync::schema::create_window_doc;
    use crate::sync::types::WindowKey;
    use crate::sync::window::forward_rematerialize;

    let (_tmp, vault) = temp_vault();
    let claim = test_id(0xb1);
    let pending = put_critical_auto_claim(&vault, claim)?;
    let binding = critical_write_confirm_binding(&pending)?;
    let window_key = WindowKey::new("2026-04");
    let doc = create_window_doc("peer", &window_key);
    let original = vault.get_raw(&claim)?.expect("attached claim row");

    // An unchanged rematerialization is idempotent: it preserves the live
    // attachment and its original persisted binding.
    map_insert_bytes(&doc.get_map("entities"), &claim.to_hex(), &original)?;
    doc.commit();
    forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
    let unchanged = vault.with_write_txn(|wtxn| {
        vault
            .store
            .pending_gate_consent_in_txn(wtxn, &claim)?
            .ok_or(Error::EntityNotFound)
    })?;
    assert_eq!(critical_write_confirm_binding(&unchanged)?, binding);

    // A peer body change must consume neither the old binding nor its Auto
    // status. Rebinding the changed bytes to the old ceremony would be unsafe.
    let mut replacement = vault.get_claim(&claim)?.expect("claim body");
    replacement.value = Value::from("changed by peer");
    replacement.approval = ClaimApprovalStatus::Auto;
    let replacement_data = crate::claim::encode_claim_body(&replacement)?;
    map_insert_bytes(
        &doc.get_map("entities"),
        &claim.to_hex(),
        &entity_record(ENTITY_TYPE_CLAIM, test_time(3), 3, &replacement_data),
    )?;
    doc.commit();
    forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
    assert!(
        vault
            .with_write_txn(|wtxn| vault.store.pending_gate_consent_in_txn(wtxn, &claim))?
            .is_none(),
        "changed replay must atomically invalidate the persisted attachment"
    );
    assert_eq!(
        vault.get_claim(&claim)?.expect("changed claim").approval,
        ClaimApprovalStatus::Proposed,
        "changed replay must not leave a critical claim Auto"
    );
    // The CRDT continues to carry the peer's Auto bytes, so rematerializing it
    // again must converge on the closed/tombstoned Proposed representation.
    forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
    assert_eq!(
        vault
            .get_claim(&claim)?
            .expect("replayed changed claim")
            .approval,
        ClaimApprovalStatus::Proposed,
        "replaying the same changed peer body must not re-promote Auto"
    );

    let (genesis, clear) = critical_confirm_owner_entry(
        &pending,
        crate::authority::CriticalWriteConfirmDisposition::Clear,
        0xb1,
    );
    vault.put_authority_log_entries(&[(genesis, test_time(1), 1), (clear, test_time(2), 2)])?;
    assert_eq!(
        vault.settle_critical_write_confirm(binding.confirm_id)?,
        CriticalWriteConfirmResolution::AlreadySettled,
        "a stale Clear cannot consume a ceremony for the changed body"
    );
    assert_eq!(
        vault.get_claim(&claim)?.expect("changed claim").approval,
        ClaimApprovalStatus::Proposed
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn replicated_critical_claim_overwrite_invalidates_attachment_before_stale_clear() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0xb2);
    let pending = put_critical_auto_claim(&vault, claim)?;
    let binding = critical_write_confirm_binding(&pending)?;
    let mut replacement = vault.get_claim(&claim)?.expect("attached claim");
    replacement.value = Value::from("replicated replacement");
    replacement.approval = ClaimApprovalStatus::Auto;
    let replacement_data = crate::claim::encode_claim_body(&replacement)?;

    vault
        .batch()
        .put_replicated(
            &claim,
            ENTITY_TYPE_CLAIM,
            test_time(4),
            4,
            &replacement_data,
        )
        .commit()?;
    assert!(
        vault
            .with_write_txn(|wtxn| vault.store.pending_gate_consent_in_txn(wtxn, &claim))?
            .is_none(),
        "the replicated door must invalidate in its overwrite transaction"
    );
    assert!(
        vault
            .store
            .gate_decisions(20)?
            .iter()
            .any(|row| row.claim_id == Some(*claim.as_bytes())
                && row.outcome == "invalidated"
                && row.reason_codes == [GATE_REASON_CRITICAL_CONFIRM_REPLICATED_OVERWRITE]),
        "invalidation leaves a distinct durable closure receipt"
    );
    assert_eq!(
        vault
            .get_claim(&claim)?
            .expect("replacement claim")
            .approval,
        ClaimApprovalStatus::Proposed
    );
    vault
        .batch()
        .put_replicated(
            &claim,
            ENTITY_TYPE_CLAIM,
            test_time(4),
            4,
            &replacement_data,
        )
        .commit()?;
    assert_eq!(
        vault
            .get_claim(&claim)?
            .expect("replayed replacement claim")
            .approval,
        ClaimApprovalStatus::Proposed,
        "a repeated changed replication must remain demoted"
    );

    // A new local ceremony is distinct from the invalidated one. The old Clear
    // must neither settle it nor disturb its pending attachment.
    let fresh = put_critical_auto_claim(&vault, claim)?;
    let fresh_binding = critical_write_confirm_binding(&fresh)?;
    assert_ne!(fresh_binding.confirm_id, binding.confirm_id);

    let (genesis, clear) = critical_confirm_owner_entry(
        &pending,
        crate::authority::CriticalWriteConfirmDisposition::Clear,
        0xb2,
    );
    vault.put_authority_log_entries(&[(genesis, test_time(1), 1), (clear, test_time(2), 2)])?;
    assert_eq!(
        vault.settle_critical_write_confirm(binding.confirm_id)?,
        CriticalWriteConfirmResolution::AlreadySettled
    );
    assert_eq!(
        critical_write_confirm_binding(
            &vault
                .with_write_txn(|wtxn| vault.store.pending_gate_consent_in_txn(wtxn, &claim))?
                .expect("fresh ceremony remains pending"),
        )?,
        fresh_binding,
        "a stale old Clear cannot consume a fresh ceremony"
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn replicated_changed_claim_duplicate_in_one_batch_stays_proposed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0xb3);
    put_critical_auto_claim(&vault, claim)?;
    let mut replacement = vault.get_claim(&claim)?.expect("attached claim");
    replacement.value = Value::from("same batch replacement");
    replacement.approval = ClaimApprovalStatus::Auto;
    let data = crate::claim::encode_claim_body(&replacement)?;
    vault
        .batch()
        .put_replicated(&claim, ENTITY_TYPE_CLAIM, test_time(5), 5, &data)
        .put_replicated(&claim, ENTITY_TYPE_CLAIM, test_time(5), 5, &data)
        .commit()?;
    assert_eq!(
        vault
            .get_claim(&claim)?
            .expect("replacement claim")
            .approval,
        ClaimApprovalStatus::Proposed
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn observer_b_malformed_critical_marker_quarantines_without_prior_mutation() -> Result<()> {
    use crate::sync::bridge::{Materializer, register_observer_b};
    use crate::sync::loro_support::map_insert_bytes;
    use crate::sync::quarantine::quarantined_records;
    use crate::sync::schema::create_window_doc;
    use crate::sync::types::WindowKey;
    use std::sync::Arc;

    let (_tmp, vault) = temp_vault();
    let vault = Arc::new(vault);
    let claim = test_id(0xb4);
    let mut pending = put_critical_auto_claim(&vault, claim)?;
    pending.reason_codes.push("gate.pending.extra".to_owned());
    vault.with_write_txn(|wtxn| vault.store.put_pending_gate_consent_in_txn(wtxn, &pending))?;
    let before = vault.get_raw(&claim)?.expect("claim row");
    let decisions_before = vault.store.gate_decisions(100)?;
    let mut replacement = vault.get_claim(&claim)?.expect("attached claim");
    replacement.value = Value::from("must not land");
    replacement.approval = ClaimApprovalStatus::Auto;
    let data = crate::claim::encode_claim_body(&replacement)?;

    // Observer B catches a remote-classified failure and commits quarantine in
    // the same transaction; this proves rejection preceded every C3 mutation.
    let window_key = WindowKey::new("2026-06");
    let doc = create_window_doc("peer", &window_key);
    let materializer = Arc::new(Materializer::new());
    let _subscriptions = register_observer_b(&doc, &vault, &materializer, window_key.as_str());
    map_insert_bytes(
        &doc.get_map("entities"),
        &claim.to_hex(),
        &entity_record(ENTITY_TYPE_CLAIM, test_time(6), 6, &data),
    )?;
    doc.commit();

    assert_eq!(vault.get_raw(&claim)?.expect("claim row"), before);
    assert_eq!(
        vault.with_write_txn(|wtxn| vault.store.pending_gate_consent_in_txn(wtxn, &claim))?,
        Some(pending),
        "the catch-and-commit path cannot close or rewrite pending/index state"
    );
    assert_eq!(vault.store.gate_decisions(100)?, decisions_before);
    assert!(!vault.with_write_txn(|wtxn| {
        vault
            .store
            .critical_confirm_invalidation_exists_in_txn(wtxn, &claim)
    })?);
    assert!(
        !quarantined_records(&vault)?.is_empty(),
        "Observer B must have committed its quarantine record"
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn replicated_delete_then_recreate_consults_claim_scoped_invalidation() -> Result<()> {
    use crate::sync::bridge::Materializer;
    use crate::sync::loro_support::map_insert_bytes;
    use crate::sync::schema::create_window_doc;
    use crate::sync::types::WindowKey;
    use crate::sync::window::forward_rematerialize;

    let (tmp, vault) = temp_vault();
    let claim = test_id(0xb5);
    put_critical_auto_claim(&vault, claim)?;
    let mut replacement = vault.get_claim(&claim)?.expect("attached claim");
    replacement.value = Value::from("invalidate before delete");
    replacement.approval = ClaimApprovalStatus::Auto;
    let replacement_data = crate::claim::encode_claim_body(&replacement)?;
    vault
        .batch()
        .put_replicated(
            &claim,
            ENTITY_TYPE_CLAIM,
            test_time(7),
            7,
            &replacement_data,
        )
        .commit()?;
    assert!(vault.with_write_txn(|wtxn| {
        vault
            .store
            .critical_confirm_invalidation_exists_in_txn(wtxn, &claim)
    })?);

    vault.delete_entity_with_reason(&claim, crate::deletion::DeleteReason::UserDelete)?;
    assert!(vault.get_claim(&claim)?.is_none());
    // The forward door, starting from the missing logical row, must not
    // resurrect authority from the ceremony closed before deletion.
    let window_key = WindowKey::new("2026-07");
    let doc = create_window_doc("peer", &window_key);
    map_insert_bytes(
        &doc.get_map("entities"),
        &claim.to_hex(),
        &entity_record(ENTITY_TYPE_CLAIM, test_time(8), 8, &replacement_data),
    )?;
    doc.commit();
    forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
    assert_eq!(
        vault
            .get_claim(&claim)?
            .expect("forward replayed claim")
            .approval,
        ClaimApprovalStatus::Proposed
    );
    drop(vault);
    let reopened = crate::Vault::open(tmp.path(), crate::config::VaultConfig::default())?;
    assert!(reopened.with_write_txn(|wtxn| {
        reopened
            .store
            .critical_confirm_invalidation_exists_in_txn(wtxn, &claim)
    })?);
    assert_eq!(
        reopened
            .get_claim(&claim)?
            .expect("reopened claim")
            .approval,
        ClaimApprovalStatus::Proposed
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn ordinary_pending_from_local_gate_survives_direct_and_rematerialized_marker_replays() -> Result<()>
{
    use crate::sync::bridge::Materializer;
    use crate::sync::loro_support::map_insert_bytes;
    use crate::sync::schema::create_window_doc;
    use crate::sync::types::WindowKey;
    use crate::sync::window::forward_rematerialize;

    let (_tmp, vault) = temp_vault();
    let claim = test_id(0xb6);
    put_critical_auto_claim(&vault, claim)?;
    let mut replacement = vault.get_claim(&claim)?.expect("attached claim");
    replacement.value = Value::from("tombstoned replacement");
    replacement.approval = ClaimApprovalStatus::Auto;
    let replacement_data = crate::claim::encode_claim_body(&replacement)?;
    vault
        .batch()
        .put_replicated(
            &claim,
            ENTITY_TYPE_CLAIM,
            test_time(9),
            9,
            &replacement_data,
        )
        .commit()?;

    // Build ordinary Pending through the public local gate, rather than
    // fabricating a renamed critical attachment in the storage helper.
    put_policy_manifest_bytes(&vault, test_id(0xed), &encode_policy_manifest(vec![]))?;
    let mut ordinary_body = replacement.clone();
    ordinary_body.source = Some(ClaimSource::Generated);
    ordinary_body.approval = ClaimApprovalStatus::Proposed;
    let run_id = "dreamer-c3-index-run";
    let (candidate, envelope) =
        dreamer_claim_candidate_write_parts(&vault, &ordinary_body, test_id(0xef), run_id)?;
    vault
        .batch()
        .claim_candidate(&claim, candidate, &envelope, test_time(10), 10)
        .commit()?;
    let ordinary = vault.with_write_txn(|wtxn| {
        vault
            .store
            .pending_gate_consent_in_txn(wtxn, &claim)?
            .ok_or(Error::EntityNotFound)
    })?;
    assert!(
        !ordinary
            .reason_codes
            .iter()
            .any(|reason| reason.contains("critical_confirm")),
        "the local gate must create ordinary Pending, not a disguised attachment"
    );
    assert_eq!(ordinary.dreamer_run_id.as_deref(), Some(run_id));
    let semantic_hash = crate::inbox::inbox_claim_hash(&ordinary_body)?;
    let assert_indexes = |expected: &PendingGateConsentRecord| -> Result<()> {
        assert_eq!(
            vault.store.pending_gate_consents_for_run(run_id)?,
            vec![expected.clone()]
        );
        assert_eq!(
            vault.store.pending_gate_consents_for_group_key(run_id)?,
            vec![expected.clone()]
        );
        assert_eq!(
            vault
                .store
                .pending_gate_consents_for_semantic_claim_hash(&semantic_hash)?,
            vec![expected.clone()]
        );
        Ok(())
    };
    assert_indexes(&ordinary)?;

    vault
        .batch()
        .put_replicated(
            &claim,
            ENTITY_TYPE_CLAIM,
            test_time(11),
            11,
            &replacement_data,
        )
        .commit()?;
    assert_eq!(
        vault.with_write_txn(|wtxn| vault.store.pending_gate_consent_in_txn(wtxn, &claim))?,
        Some(ordinary.clone()),
        "direct replay leaves the real ordinary primary/index state untouched"
    );
    assert_indexes(&ordinary)?;

    let window_key = WindowKey::new("2026-05");
    let doc = create_window_doc("peer", &window_key);
    map_insert_bytes(
        &doc.get_map("entities"),
        &claim.to_hex(),
        &entity_record(ENTITY_TYPE_CLAIM, test_time(11), 11, &replacement_data),
    )?;
    doc.commit();
    forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
    assert_eq!(
        vault.with_write_txn(|wtxn| vault.store.pending_gate_consent_in_txn(wtxn, &claim))?,
        Some(ordinary.clone()),
        "forward rematerialization also preserves ordinary Pending and indexes"
    );
    assert_indexes(&ordinary)?;
    assert_eq!(
        vault.get_claim(&claim)?.expect("tombstoned claim").approval,
        ClaimApprovalStatus::Proposed
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn batch_in_fresh_critical_ceremony_never_reuses_invalidated_decision() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0xb8);
    let old_pending = put_critical_auto_claim(&vault, claim)?;
    let old_binding = critical_write_confirm_binding(&old_pending)?;
    let original = vault.get_claim(&claim)?.expect("original claim");

    let mut replacement = original.clone();
    replacement.value = Value::from("peer replacement");
    replacement.approval = ClaimApprovalStatus::Auto;
    let replacement_data = crate::claim::encode_claim_body(&replacement)?;
    vault
        .batch()
        .put_replicated(
            &claim,
            ENTITY_TYPE_CLAIM,
            test_time(11),
            11,
            &replacement_data,
        )
        .commit()?;

    // This public caller-owned transaction intentionally uses the historical
    // body/policy. It must mint and persist a new identity before marker clear.
    let (candidate, envelope) = claim_candidate_write_parts(&vault, &original)?;
    vault.with_write_txn(|wtxn| {
        vault
            .batch_in()
            .claim_candidate(&claim, candidate, &envelope, test_time(12), 12)
            .apply(wtxn)
    })?;
    let fresh = vault.with_write_txn(|wtxn| {
        vault
            .store
            .pending_gate_consent_in_txn(wtxn, &claim)?
            .ok_or(Error::EntityNotFound)
    })?;
    let fresh_binding = critical_write_confirm_binding(&fresh)?;
    assert_ne!(fresh_binding.gate_decision_id, old_binding.gate_decision_id);
    assert_ne!(fresh_binding.confirm_id, old_binding.confirm_id);
    assert!(
        vault.store.gate_decisions(20)?.iter().any(|decision| {
            decision.decision_id == fresh_binding.gate_decision_id
                && decision.claim_id == Some(*claim.as_bytes())
        }),
        "the fresh pending binding must have a same-transaction ledger row"
    );

    let (genesis, clear) = critical_confirm_owner_entry(
        &old_pending,
        crate::authority::CriticalWriteConfirmDisposition::Clear,
        0xb8,
    );
    vault.put_authority_log_entries(&[(genesis, test_time(1), 1), (clear, test_time(2), 2)])?;
    assert_eq!(
        vault.settle_critical_write_confirm(old_binding.confirm_id)?,
        CriticalWriteConfirmResolution::AlreadySettled
    );
    assert_eq!(
        critical_write_confirm_binding(
            &vault
                .with_write_txn(|wtxn| vault.store.pending_gate_consent_in_txn(wtxn, &claim))?
                .expect("fresh attachment survives old clear"),
        )?,
        fresh_binding
    );
    assert_eq!(
        vault.get_claim(&claim)?.expect("fresh claim").approval,
        ClaimApprovalStatus::Auto
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn fresh_critical_ceremony_transactionally_clears_marker_and_exact_replay_converges() -> Result<()>
{
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0xb7);
    put_critical_auto_claim(&vault, claim)?;
    let mut replacement = vault.get_claim(&claim)?.expect("attached claim");
    replacement.value = Value::from("requires a new ceremony");
    replacement.approval = ClaimApprovalStatus::Auto;
    let replacement_data = crate::claim::encode_claim_body(&replacement)?;
    vault
        .batch()
        .put_replicated(
            &claim,
            ENTITY_TYPE_CLAIM,
            test_time(10),
            10,
            &replacement_data,
        )
        .commit()?;
    assert!(vault.with_write_txn(|wtxn| {
        vault
            .store
            .critical_confirm_invalidation_exists_in_txn(wtxn, &claim)
    })?);

    let fresh = put_critical_auto_claim(&vault, claim)?;
    assert!(vault.with_write_txn(|wtxn| {
        !vault
            .store
            .critical_confirm_invalidation_exists_in_txn(wtxn, &claim)
    })?);
    let fresh_data =
        crate::claim::encode_claim_body(&vault.get_claim(&claim)?.expect("fresh claim"))?;
    vault
        .batch()
        .put_replicated(&claim, ENTITY_TYPE_CLAIM, test_time(3), 3, &fresh_data)
        .commit()?;
    assert_eq!(
        vault.get_claim(&claim)?.expect("fresh replay").approval,
        ClaimApprovalStatus::Auto,
        "an exact replay of the fresh attached body preserves its new ceremony"
    );
    assert_eq!(
        vault.with_write_txn(|wtxn| vault.store.pending_gate_consent_in_txn(wtxn, &claim))?,
        Some(fresh),
        "exact replay converges without replacing the fresh attachment"
    );
    Ok(())
}

#[test]
fn critical_write_confirm_clear_settles_and_deletes_pending_row() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0x82);
    let pending = put_critical_auto_claim(&vault, claim)?;
    let binding = critical_write_confirm_binding(&pending)?;
    let (genesis, clear) = critical_confirm_owner_entry(
        &pending,
        crate::authority::CriticalWriteConfirmDisposition::Clear,
        82,
    );
    vault.put_authority_log_entries(&[(genesis, test_time(1), 1), (clear, test_time(2), 2)])?;
    assert_eq!(
        vault.settle_critical_write_confirm(binding.confirm_id)?,
        CriticalWriteConfirmResolution::Cleared
    );
    assert!(
        vault
            .with_write_txn(|wtxn| vault.store.pending_gate_consent_in_txn(wtxn, &claim))?
            .is_none()
    );
    assert!(vault.with_write_txn(|wtxn| {
        Ok::<_, Error>(
            vault
                .store
                .critical_confirm_claim_id_in_txn(&*wtxn, &binding.confirm_id)?
                .is_none(),
        )
    })?);
    Ok(())
}

#[test]
fn critical_write_confirm_decline_before_timeout_retracts_with_declined_receipt() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0x83);
    let pending = put_critical_auto_claim(&vault, claim)?;
    let binding = critical_write_confirm_binding(&pending)?;
    let (genesis, decline) = critical_confirm_owner_entry(
        &pending,
        crate::authority::CriticalWriteConfirmDisposition::Decline,
        83,
    );
    vault.put_authority_log_entries(&[(genesis, test_time(1), 1), (decline, test_time(2), 2)])?;
    assert_eq!(
        vault.settle_critical_write_confirm(binding.confirm_id)?,
        CriticalWriteConfirmResolution::Retracted
    );
    assert_eq!(
        stored_claim_body(&vault, &claim)?.lifecycle,
        ClaimLifecycleStatus::Retracted
    );
    assert!(vault.with_write_txn(|wtxn| {
        Ok::<_, Error>(
            vault
                .store
                .critical_confirm_claim_id_in_txn(&*wtxn, &binding.confirm_id)?
                .is_none(),
        )
    })?);
    assert!(
        vault
            .store
            .gate_decisions(20)?
            .iter()
            .any(|row| row.claim_id == Some(*claim.as_bytes())
                && row.outcome == "rejected"
                && row.reason_codes == [GATE_REASON_CRITICAL_CONFIRM_DECLINED])
    );
    Ok(())
}

#[test]
fn critical_write_confirm_decline_after_timeout_retracts_with_declined_receipt() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0x84);
    let mut pending = put_critical_auto_claim(&vault, claim)?;
    pending.created_at = 1;
    vault.with_write_txn(|wtxn| vault.store.put_pending_gate_consent_in_txn(wtxn, &pending))?;
    let binding = critical_write_confirm_binding(&pending)?;
    let (genesis, decline) = critical_confirm_owner_entry(
        &pending,
        crate::authority::CriticalWriteConfirmDisposition::Decline,
        84,
    );
    vault.put_authority_log_entries(&[(genesis, test_time(1), 1), (decline, test_time(2), 2)])?;
    // A post-timeout decline remains a terminal retraction once an owner decline is folded.
    assert_eq!(
        vault.settle_critical_write_confirm(binding.confirm_id)?,
        CriticalWriteConfirmResolution::Retracted
    );
    assert_eq!(
        stored_claim_body(&vault, &claim)?.lifecycle,
        ClaimLifecycleStatus::Retracted
    );
    assert!(
        vault
            .store
            .gate_decisions(20)?
            .iter()
            .any(|row| row.claim_id == Some(*claim.as_bytes())
                && row.outcome == "rejected"
                && row.reason_codes == [GATE_REASON_CRITICAL_CONFIRM_DECLINED])
    );
    Ok(())
}

#[test]
fn critical_write_confirm_stale_binding_is_already_settled() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0x85);
    let pending = put_critical_auto_claim(&vault, claim)?;
    let binding = critical_write_confirm_binding(&pending)?;
    let (genesis, mut clear) = critical_confirm_owner_entry(
        &pending,
        crate::authority::CriticalWriteConfirmDisposition::Clear,
        85,
    );
    if let crate::authority::AuthorityOp::CriticalWriteConfirm(action) = &mut clear.op {
        action.nonce[0] ^= 1;
    }
    // Re-sign the deliberately stale authority entry after changing its binding material.
    use ed25519_dalek::{Signer, SigningKey};
    let key = SigningKey::from_bytes(&[85; 32]);
    clear.signer.signature = key
        .sign(&crate::authority::authority_transcript(&clear)?)
        .to_bytes()
        .to_vec();
    vault.put_authority_log_entries(&[(genesis, test_time(1), 1), (clear, test_time(2), 2)])?;
    assert_eq!(
        vault.settle_critical_write_confirm(binding.confirm_id)?,
        CriticalWriteConfirmResolution::AlreadySettled
    );
    Ok(())
}

#[test]
fn critical_confirm_sweep_preserves_ordinary_pending_rows() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let critical = test_id(0x86);
    let ordinary = test_id(0x87);
    let mut pending = put_critical_auto_claim(&vault, critical)?;
    pending.created_at = 1;
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .put_pending_gate_consent_in_txn(wtxn, &pending)?;
        vault.store.put_pending_gate_consent_in_txn(
            wtxn,
            &PendingGateConsentRecord {
                version: 0,
                claim_id: *ordinary.as_bytes(),
                decision_id: GateDecisionId::from_bytes([87; 16]),
                created_at: 1,
                diff_handle: vec![87],
                read_frontier_hash: [88; 32],
                reason_codes: vec!["gate.pending.ordinary".to_owned()],
                dreamer_run_id: None,
            },
        )
    })?;
    assert_eq!(
        vault.expire_critical_write_confirms_at(1 + CRITICAL_WRITE_CONFIRM_TIMEOUT_SECS)?,
        1
    );
    let ordinary_row = vault
        .with_write_txn(|wtxn| vault.store.pending_gate_consent_in_txn(wtxn, &ordinary))?
        .expect("ordinary remains pending");
    assert_eq!(ordinary_row.reason_codes, vec!["gate.pending.ordinary"]);
    Ok(())
}

#[test]
fn critical_write_confirm_double_settle_replay_is_already_settled() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0x88);
    let pending = put_critical_auto_claim(&vault, claim)?;
    let binding = critical_write_confirm_binding(&pending)?;
    let (genesis, clear) = critical_confirm_owner_entry(
        &pending,
        crate::authority::CriticalWriteConfirmDisposition::Clear,
        88,
    );
    vault.put_authority_log_entries(&[(genesis, test_time(1), 1), (clear, test_time(2), 2)])?;
    assert_eq!(
        vault.settle_critical_write_confirm(binding.confirm_id)?,
        CriticalWriteConfirmResolution::Cleared
    );
    assert_eq!(
        vault.settle_critical_write_confirm(binding.confirm_id)?,
        CriticalWriteConfirmResolution::AlreadySettled
    );
    Ok(())
}

#[test]
fn critical_confirm_decline_uses_preauthorized_status_door_after_manifest_fails_closed()
-> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0x89);
    let pending = put_critical_auto_claim(&vault, claim)?;
    let binding = critical_write_confirm_binding(&pending)?;
    let receipts_before = vault.store.gate_decisions(20)?.len();

    // A malformed later manifest makes ordinary local CLAIM writes fail closed.
    put_policy_manifest_bytes(&vault, test_id(0x8a), b"not-a-manifest")?;
    assert!(resolve(&vault)?.is_fail_closed());
    let (genesis, decline) = critical_confirm_owner_entry(
        &pending,
        crate::authority::CriticalWriteConfirmDisposition::Decline,
        89,
    );
    vault.put_authority_log_entries(&[(genesis, test_time(1), 1), (decline, test_time(2), 2)])?;

    assert_eq!(
        vault.settle_critical_write_confirm(binding.confirm_id)?,
        CriticalWriteConfirmResolution::Retracted
    );
    assert_eq!(
        stored_claim_body(&vault, &claim)?.lifecycle,
        ClaimLifecycleStatus::Retracted
    );
    assert!(
        vault
            .with_write_txn(|wtxn| vault.store.pending_gate_consent_in_txn(wtxn, &claim))?
            .is_none(),
        "the original attached row is closed, not replaced"
    );
    let receipts_after = vault.store.gate_decisions(20)?;
    assert_eq!(
        receipts_after.len(),
        receipts_before + 1,
        "settlement creates only its resolution receipt"
    );
    assert!(receipts_after.iter().all(|row| {
        row.receipt_reasons != [GATE_REASON_ALLOW_CRITICAL_CONFIRM_ATTACHED]
            || row.decision_id == pending.decision_id
    }));
    Ok(())
}

#[test]
fn critical_confirm_exact_index_interleaves_absent_and_present_ids() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0xc1);
    let pending = put_critical_auto_claim(&vault, claim)?;
    let binding = critical_write_confirm_binding(&pending)?;
    let (genesis, clear) = critical_confirm_owner_entry(
        &pending,
        crate::authority::CriticalWriteConfirmDisposition::Clear,
        0xc1,
    );
    vault.put_authority_log_entries(&[(genesis, test_time(1), 1), (clear, test_time(2), 2)])?;
    let absent = [0xa5; 32];
    assert_eq!(
        vault.settle_critical_write_confirm(absent)?,
        CriticalWriteConfirmResolution::AlreadySettled,
    );
    assert_eq!(
        vault.settle_critical_write_confirm(binding.confirm_id)?,
        CriticalWriteConfirmResolution::Cleared,
        "an absent lookup must not scan or consume a different live confirmation",
    );
    assert_eq!(
        vault.settle_critical_write_confirm(absent)?,
        CriticalWriteConfirmResolution::AlreadySettled,
    );
    Ok(())
}

#[test]
fn critical_confirm_stale_or_malformed_alias_is_removed_fail_closed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let ordinary = test_id(0xc2);
    let confirm_id = [0x42; 32];
    vault.with_write_txn(|wtxn| {
        vault.store.put_pending_gate_consent_in_txn(
            wtxn,
            &PendingGateConsentRecord {
                version: 0,
                claim_id: *ordinary.as_bytes(),
                decision_id: GateDecisionId::from_bytes([0xc2; 16]),
                created_at: 1,
                diff_handle: vec![0xc2],
                read_frontier_hash: [0xc2; 32],
                reason_codes: vec!["gate.pending.ordinary".to_owned()],
                dreamer_run_id: None,
            },
        )?;
        vault
            .store
            .put_critical_confirm_index_in_txn(wtxn, &confirm_id, ordinary.as_bytes())
    })?;
    assert!(vault.settle_critical_write_confirm(confirm_id).is_err());
    assert!(vault.with_write_txn(|wtxn| {
        Ok::<_, Error>(
            vault
                .store
                .critical_confirm_claim_id_in_txn(&*wtxn, &confirm_id)?
                .is_none(),
        )
    })?);
    Ok(())
}

#[test]
fn preauthorized_status_door_rejects_a_body_not_bound_to_the_attachment() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0x8b);
    let pending = put_critical_auto_claim(&vault, claim)?;
    let mut changed = stored_claim_body(&vault, &claim)?;
    changed.confidence = 0.25;
    let rtxn = vault.store.env.read_txn()?;
    let raw = vault
        .store
        .entities
        .get(&rtxn, claim.as_bytes())?
        .expect("claim");
    let header = EntityMetadataHeader::parse(&raw).expect("header");
    let error = vault
        .with_write_txn(|wtxn| {
            put_preauthorized_claim_status_in_txn(
                &vault,
                wtxn,
                &claim,
                &changed,
                PreauthorizedClaimStatusGrant::test_timeout_demotion(),
                TimeRange {
                    start: header.occurred_start,
                    end: header.occurred_end,
                },
                header.learned_at,
            )
        })
        .expect_err("non-status mutation must not use settlement door");
    assert!(matches!(error, Error::InvariantViolation(_)));
    assert_eq!(
        vault.with_write_txn(|wtxn| vault.store.pending_gate_consent_in_txn(wtxn, &claim))?,
        Some(pending)
    );
    Ok(())
}

#[test]
fn preauthorized_status_door_rejects_wrong_id_and_header_binding() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0x8c);
    let pending = put_critical_auto_claim(&vault, claim)?;
    let body = stored_claim_body(&vault, &claim)?;
    let raw = vault.get_raw(&claim)?.expect("claim");
    let header = EntityMetadataHeader::parse(&raw).expect("header");
    let grant = PreauthorizedClaimStatusGrant::test_timeout_demotion();
    let wrong_id = vault
        .with_write_txn(|wtxn| {
            put_preauthorized_claim_status_in_txn(
                &vault,
                wtxn,
                &test_id(0x8d),
                &body,
                grant,
                TimeRange {
                    start: header.occurred_start,
                    end: header.occurred_end,
                },
                header.learned_at,
            )
        })
        .expect_err("wrong id must not reach the status writer");
    assert!(matches!(wrong_id, Error::EntityNotFound));
    let wrong_header = vault
        .with_write_txn(|wtxn| {
            put_preauthorized_claim_status_in_txn(
                &vault,
                wtxn,
                &claim,
                &body,
                grant,
                TimeRange {
                    start: header.occurred_start + 1,
                    end: header.occurred_end,
                },
                header.learned_at,
            )
        })
        .expect_err("wrong header must not reach the status writer");
    assert!(matches!(wrong_header, Error::InvariantViolation(_)));
    assert_eq!(
        vault.with_write_txn(|wtxn| vault.store.pending_gate_consent_in_txn(wtxn, &claim))?,
        Some(pending)
    );
    Ok(())
}

#[test]
fn critical_confirm_timeout_sweep_ignores_a_later_fail_closed_manifest() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0x8e);
    let mut pending = put_critical_auto_claim(&vault, claim)?;
    pending.created_at = 1;
    vault.with_write_txn(|wtxn| vault.store.put_pending_gate_consent_in_txn(wtxn, &pending))?;
    let receipts_before = vault.store.gate_decisions(20)?;
    put_policy_manifest_bytes(&vault, test_id(0x8f), b"not-a-manifest")?;
    assert!(resolve(&vault)?.is_fail_closed());
    assert_eq!(
        vault.expire_critical_write_confirms_at(1 + CRITICAL_WRITE_CONFIRM_TIMEOUT_SECS)?,
        1
    );
    assert_eq!(
        stored_claim_body(&vault, &claim)?.approval,
        ClaimApprovalStatus::Proposed
    );
    assert_eq!(
        vault.store.gate_decisions(20)?,
        receipts_before,
        "sweep mints no receipt"
    );
    assert_eq!(
        vault.pending_gate_consents(20)?,
        vec![PendingGateConsentRecord {
            reason_codes: vec![GATE_REASON_CRITICAL_CONFIRM_TIMEOUT.to_owned()],
            ..pending
        }]
    );
    Ok(())
}

#[test]
fn critical_confirm_decline_ignores_a_later_narrowed_manifest_without_artifacts() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0x90);
    let pending = put_critical_auto_claim(&vault, claim)?;
    let binding = critical_write_confirm_binding(&pending)?;
    let receipts_before = vault.store.gate_decisions(20)?;
    // This remains a valid manifest but narrows ordinary source writes to Pending.
    put_policy_manifest_bytes(
        &vault,
        test_id(0x91),
        &encode_policy_manifest(vec![source_trust_entry_without_auto_permit(
            ClaimSource::UserStated,
            0,
        )]),
    )?;
    assert!(matches!(
        resolve(&vault)?
            .evaluate_gate(&gate_evaluator_input(
                "first_party",
                None,
                ClaimSource::UserStated,
                PolicyCriticality::Critical
            ))
            .outcome(),
        GateOutcome::Pending
    ));
    let (genesis, decline) =
        critical_confirm_owner_entry(&pending, CriticalWriteConfirmDisposition::Decline, 90);
    vault.put_authority_log_entries(&[(genesis, test_time(1), 1), (decline, test_time(2), 2)])?;
    assert_eq!(
        vault.settle_critical_write_confirm(binding.confirm_id)?,
        CriticalWriteConfirmResolution::Retracted
    );
    assert!(vault.pending_gate_consents(20)?.is_empty());
    let receipts_after = vault.store.gate_decisions(20)?;
    assert_eq!(receipts_after.len(), receipts_before.len() + 1);
    assert!(
        receipts_after
            .iter()
            .filter(|row| row.claim_id == Some(*claim.as_bytes()))
            .all(|row| row.decision_id == pending.decision_id
                || row.reason_codes == [GATE_REASON_CRITICAL_CONFIRM_DECLINED])
    );
    Ok(())
}

#[test]
fn critical_confirm_alias_orphan_mismatch_and_ordinary_replacement_are_removed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0xca);
    let pending = critical_confirm_pending(claim, 1, crate::unix_seconds_now());
    let binding = critical_write_confirm_binding(&pending)?;
    let mismatched = [0x5a; 32];
    let orphan = [0x6a; 32];
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .put_pending_gate_consent_in_txn(wtxn, &pending)?;
        vault
            .store
            .put_critical_confirm_index_in_txn(wtxn, &mismatched, claim.as_bytes())?;
        vault
            .store
            .put_critical_confirm_index_in_txn(wtxn, &orphan, test_id(0xcb).as_bytes())
    })?;
    assert_eq!(
        vault.settle_critical_write_confirm(mismatched)?,
        CriticalWriteConfirmResolution::AlreadySettled,
    );
    assert_eq!(
        vault.settle_critical_write_confirm(orphan)?,
        CriticalWriteConfirmResolution::AlreadySettled,
    );
    vault.with_write_txn(|wtxn| {
        let ordinary = PendingGateConsentRecord {
            version: 0,
            claim_id: *claim.as_bytes(),
            decision_id: GateDecisionId::from_bytes([0xca; 16]),
            created_at: 1,
            diff_handle: vec![0xca],
            read_frontier_hash: [0xca; 32],
            reason_codes: vec!["gate.pending.ordinary".to_owned()],
            dreamer_run_id: None,
        };
        vault
            .store
            .put_pending_gate_consent_in_txn(wtxn, &ordinary)?;
        assert!(
            vault
                .store
                .critical_confirm_claim_id_in_txn(&*wtxn, &binding.confirm_id)?
                .is_none()
        );
        assert!(
            vault
                .store
                .critical_confirm_claim_id_in_txn(&*wtxn, &mismatched)?
                .is_none()
        );
        assert!(
            vault
                .store
                .critical_confirm_claim_id_in_txn(&*wtxn, &orphan)?
                .is_none()
        );
        Ok(())
    })?;
    Ok(())
}

#[test]
fn critical_confirm_index_cursor_and_fence_survive_reopen() -> Result<()> {
    let (tmp, vault) = temp_vault();
    let first = sweep_id(0xc3, 1);
    let second = sweep_id(0xc3, 2);
    let first_pending = critical_confirm_pending(first, 1, crate::unix_seconds_now());
    let second_pending = critical_confirm_pending(second, 2, crate::unix_seconds_now());
    let first_binding = critical_write_confirm_binding(&first_pending)?;
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .put_pending_gate_consent_in_txn(wtxn, &first_pending)?;
        vault
            .store
            .put_pending_gate_consent_in_txn(wtxn, &second_pending)
    })?;
    assert_eq!(vault.pending_critical_write_confirms(1)?[0].claim_id, first);
    drop(vault);

    let reopened = crate::Vault::open(tmp.path(), crate::config::VaultConfig::default())?;
    reopened.with_write_txn(|wtxn| {
        assert_eq!(
            reopened
                .store
                .critical_confirm_list_sweep_state_in_txn(&*wtxn)?,
            (Some(1), Some(2)),
        );
        assert_eq!(
            reopened
                .store
                .critical_confirm_claim_id_in_txn(&*wtxn, &first_binding.confirm_id)?,
            Some(first),
        );
        Ok(())
    })?;
    assert_eq!(
        reopened.pending_critical_write_confirms(1)?[0].claim_id,
        second
    );
    Ok(())
}

#[test]
fn critical_confirm_index_tracks_replace_delete_and_reattach_lifecycle() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0xc4);
    let original = critical_confirm_pending(claim, 1, crate::unix_seconds_now());
    let original_id = critical_write_confirm_binding(&original)?.confirm_id;
    let replacement = critical_confirm_pending(claim, 2, crate::unix_seconds_now());
    let replacement_id = critical_write_confirm_binding(&replacement)?.confirm_id;
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .put_pending_gate_consent_in_txn(wtxn, &original)?;
        vault
            .store
            .put_pending_gate_consent_in_txn(wtxn, &replacement)?;
        assert_eq!(
            vault
                .store
                .critical_confirm_claim_id_in_txn(&*wtxn, &original_id)?,
            None,
            "replacement removes the old exact alias",
        );
        assert_eq!(
            vault
                .store
                .critical_confirm_claim_id_in_txn(&*wtxn, &replacement_id)?,
            Some(claim),
        );
        vault
            .store
            .delete_pending_gate_consent_in_txn(wtxn, &claim)?;
        assert_eq!(
            vault
                .store
                .critical_confirm_claim_id_in_txn(&*wtxn, &replacement_id)?,
            None,
            "delete removes the replacement alias",
        );
        vault
            .store
            .put_pending_gate_consent_in_txn(wtxn, &original)?;
        assert_eq!(
            vault
                .store
                .critical_confirm_claim_id_in_txn(&*wtxn, &original_id)?,
            Some(claim),
            "a reattachment installs a fresh alias",
        );
        Ok(())
    })?;
    Ok(())
}

#[test]
fn critical_confirm_fenced_listing_reaches_captured_rows_before_hostile_inserts() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let now = crate::unix_seconds_now();
    let mut captured = Vec::new();
    vault.with_write_txn(|wtxn| {
        for ordinal in 0..257u16 {
            // Deliberately nonmonotonic caller IDs: encode the full ordinal so
            // every fixture row is unique, while progress follows the
            // store-owned sequence rather than these bytes.
            let high = (ordinal >> 8) as u8;
            let low = ordinal as u8;
            let claim = EntityId::from_bytes([
                !high, low, 0xc5, high, !low, high, 0xc5, low, !high, low, 0xc5, high, !low, high,
                0xc5, low,
            ])?;
            vault.store.put_pending_gate_consent_in_txn(
                wtxn,
                &critical_confirm_pending(claim, (ordinal % 250) as u8 + 1, now),
            )?;
            captured.push(claim);
        }
        Ok(())
    })?;
    let first = vault.pending_critical_write_confirms(1)?;
    assert_eq!(first.len(), 1);
    let hostile = sweep_id(0xc5, 0xfe);
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .put_pending_gate_consent_in_txn(wtxn, &critical_confirm_pending(hostile, 251, now))
    })?;
    let mut seen = first
        .into_iter()
        .map(|binding| binding.claim_id)
        .collect::<Vec<_>>();
    for _ in 1..257 {
        seen.push(vault.pending_critical_write_confirms(1)?[0].claim_id);
    }
    assert_eq!(seen.len(), captured.len());
    assert_eq!(
        seen, captured,
        "the captured fence reaches every pre-fence row"
    );
    assert!(seen.iter().all(|claim| *claim != hostile));
    vault.with_write_txn(|wtxn| {
        assert_eq!(
            vault
                .store
                .critical_confirm_list_sweep_state_in_txn(&*wtxn)?,
            (None, None),
            "reaching the fence completes the captured cycle before a new one begins",
        );
        Ok(())
    })?;
    let next_cycle_first = vault.pending_critical_write_confirms(256)?;
    assert_eq!(next_cycle_first.len(), 256);
    let mut next_cycle_first_ids = next_cycle_first
        .iter()
        .map(|binding| binding.claim_id)
        .collect::<Vec<_>>();
    let mut expected_first_ids = captured[..256].to_vec();
    next_cycle_first_ids.sort_by_key(|claim| *claim.as_bytes());
    expected_first_ids.sort_by_key(|claim| *claim.as_bytes());
    assert_eq!(
        next_cycle_first_ids, expected_first_ids,
        "the sorted page contains exactly the captured head membership",
    );
    let next_cycle_tail = vault.pending_critical_write_confirms(256)?;
    assert_eq!(
        next_cycle_tail
            .iter()
            .map(|binding| binding.claim_id)
            .collect::<Vec<_>>(),
        vec![captured[256], hostile],
        "the hostile row is reached on the bounded second page of the next cycle",
    );
    Ok(())
}
