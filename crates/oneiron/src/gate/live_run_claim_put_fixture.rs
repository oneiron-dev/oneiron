//! The gate fixtures of the live-run claim put test (#6881, review 6881 P1),
//! for its integration test doors (`test_doors::live_run_claim_put`): a vault
//! whose manifest lets the first-party agent land Generated Auto writes and
//! names a host auto checker, and the claim write door with a checker
//! injected. Ported from `gate/tests/support.rs` and
//! `gate/tests/auto_checker.rs` (the oneiron lib test target does not
//! compile). Compiled only under `--cfg oneiron_test_support`; never API.

use std::io::Cursor;

use rmpv::Value;

use super::constants::{
    ACTOR_CEILING_KEY, ACTOR_CLASS_KEY, ACTOR_REF_KEY, AXIS_CRITICALITY_KEY, AXIS_SENSITIVITY_KEY,
    POLICY_ACTOR_CEILINGS_KEY, POLICY_AUTO_CHECKER_KEY, POLICY_DEFAULTS_KEY,
    POLICY_MIN_ENGINE_VERSION_KEY, POLICY_PACK_ID_KEY, POLICY_PACK_VERSION_KEY, POLICY_RULES_KEY,
    POLICY_SCHEMA_VERSION, POLICY_SCHEMA_VERSION_KEY, POLICY_SIGNATURES_KEY,
    POLICY_SOURCE_TRUST_KEY, RULE_AXES_KEY, RULE_PREFIX_KEY, SIGNATURE_ALG_KEY,
    SIGNATURE_KEY_ID_KEY, SIGNATURE_SIG_KEY, SOURCE_TRUST_MAX_AUTO_SENSITIVITY_KEY,
    SOURCE_TRUST_RECEIPTED_KEY, SOURCE_TRUST_WARNED_KEY,
};
// The function itself: gate's re-export of it is `#[cfg(test)]` only.
use super::definition_ceiling::first_party_connector_actor_ref;
use super::{
    ClaimGateWrite, GateWriteMode, check_claim_policy_for_write_with_record,
    default_policy_manifest, default_policy_manifest_id, resolve_policy_manifest,
};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::llm::BoundedAutoChecker;
use crate::registry::ENTITY_TYPE_TURN;
use crate::temporal::TimeRange;
use crate::write_envelope::WriteEnvelope;

/// `[seed; 16]`, as the gate tests' `test_id` builds it.
fn test_id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("test id")
}

/// A fresh vault. It holds one policy manifest, the seeded default;
/// [`checker_vault`] writes its manifest over that row.
fn temp_vault() -> (tempfile::TempDir, crate::Vault) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault =
        crate::Vault::open(tmp.path(), crate::config::VaultConfig::default()).expect("open vault");
    (tmp, vault)
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

fn actor_ceiling_row_for_ref(actor_class: &str, actor_ref: &str, ceiling: &str) -> Value {
    Value::Map(vec![
        (Value::from(ACTOR_CLASS_KEY), Value::from(actor_class)),
        (Value::from(ACTOR_REF_KEY), Value::from(actor_ref)),
        (Value::from(ACTOR_CEILING_KEY), Value::from(ceiling)),
    ])
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

fn signatures_entry() -> (Value, Value) {
    (
        Value::from(POLICY_SIGNATURES_KEY),
        Value::Array(vec![Value::Map(vec![
            (Value::from(SIGNATURE_ALG_KEY), Value::from("ed25519")),
            (Value::from(SIGNATURE_KEY_ID_KEY), Value::from("owner")),
            (
                Value::from(SIGNATURE_SIG_KEY),
                Value::from("first-party-agent-auto"),
            ),
        ])]),
    )
}

/// Copies the shipped teacher-probe policy row into a custom test policy
/// (`test_util::add_default_teacher_probe_policy`).
fn add_default_teacher_probe_policy(entries: &mut Vec<(Value, Value)>) {
    let default = default_policy_manifest().expect("shipped policy");
    let Value::Map(default_entries) =
        rmpv::decode::read_value(&mut default.as_slice()).expect("seeded policy map")
    else {
        panic!("seeded policy map");
    };
    entries.push(
        default_entries
            .into_iter()
            .find(|(key, _)| key.as_str() == Some("teacher_probe"))
            .expect("seeded teacher probe row"),
    );
}

fn checker_entry(value: &str) -> (Value, Value) {
    (
        Value::from(POLICY_AUTO_CHECKER_KEY),
        Value::from(value.to_owned()),
    )
}

/// The precommit vault's manifest: an `agent` actor ceiling of `auto` for the
/// first-party connector, an explicit auto permit for `generated` and a
/// signature, plus whatever `auto_checker` rows the case wants.
fn checker_manifest(extra: Vec<(Value, Value)>) -> Vec<u8> {
    let mut entries = vec![
        source_trust_entry(ClaimSource::Generated, 0),
        signatures_entry(),
    ];
    entries.extend(extra);
    add_default_teacher_probe_policy(&mut entries);
    let mut data = encode_policy_manifest(entries);
    append_actor_ceiling(
        &mut data,
        actor_ceiling_row_for_ref("agent", &first_party_connector_actor_ref(), "auto"),
    );
    data
}

/// A vault whose only policy manifest is [`checker_manifest`], naming the
/// host checker `knob` when one is given.
///
/// The gate tests' `temp_vault` cleared the seeded default and stored this
/// manifest at its own id. The deindex door refuses a policy manifest entity,
/// and every stored manifest folds into the policy, so the seed cannot stay
/// beside it. The manifest is written over the seeded default at its id: a
/// local write there clears the seed mark, so the fold sees one trusted,
/// locally written manifest, as the gate tests did.
pub(crate) fn checker_vault(knob: Option<&str>) -> Result<(tempfile::TempDir, crate::Vault)> {
    let (tmp, vault) = temp_vault();
    let extra = knob.map(checker_entry).into_iter().collect();
    crate::test_support::put_policy_manifest_bytes(
        &vault,
        default_policy_manifest_id()?,
        &checker_manifest(extra),
    )?;
    Ok((tmp, vault))
}

/// The first-party connector's actor id, the agent the checker manifest
/// ceilings at Auto.
pub(crate) fn first_party_connector_actor_id() -> EntityId {
    EntityId::from_bytes(super::constants::FIRST_PARTY_CONNECTOR_ACTOR_ID)
        .expect("first-party connector actor id")
}

/// A Generated `profile.name` claim about `[0x21; 16]`, asking Auto.
fn source_trust_claim(source: ClaimSource) -> ClaimBody {
    let mut body = ClaimBody::new(
        "profile.name",
        ClaimSubject::Entity(test_id(0x21)),
        Value::from("Ada"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("claim body");
    body.source = Some(source);
    body
}

/// Stamps `sensitivity: public` (band 0) on a claim body, so the
/// unstamped-claim provenance floor does not send it to the consent queue.
fn public_stamped(mut body: ClaimBody) -> ClaimBody {
    body.scope = Some(Value::Map(vec![(
        Value::from("sensitivity"),
        Value::from("public"),
    )]));
    body
}

fn precommit_evidence(refs: Vec<EntityId>) -> Value {
    crate::dreamer_consolidation::encode_consolidation_evidence(
        &crate::dreamer_consolidation::ConsolidationEvidenceEnvelope {
            refs,
            chain: Vec::new(),
            source_meet: ClaimSource::Generated,
        },
    )
}

fn precommit_body(value: Value, evidence: Option<Value>) -> ClaimBody {
    let mut body = public_stamped(source_trust_claim(ClaimSource::Generated));
    body.value = value;
    body.evidence = evidence;
    body
}

fn seed_precommit_evidence_entity(vault: &crate::Vault, id: &EntityId) -> Result<()> {
    vault.put_entity(
        id,
        ENTITY_TYPE_TURN,
        TimeRange { start: 1, end: 1 },
        1,
        b"evidence ref",
    )
}

/// A valid Dreamer candidate: non-degenerate value, resolving evidence,
/// public sensitivity band, no isolation-classed predicate.
pub(crate) fn checker_body(
    vault: &crate::Vault,
    approval: ClaimApprovalStatus,
) -> Result<ClaimBody> {
    let evidence_ref = test_id(0x36);
    seed_precommit_evidence_entity(vault, &evidence_ref)?;
    let mut body = precommit_body(
        Value::from("Ada Lovelace"),
        Some(precommit_evidence(vec![evidence_ref])),
    );
    body.approval = approval;
    Ok(body)
}

/// The claim write door itself, with the checker under test injected. The
/// transaction commits either way, so a parked write leaves its receipt and
/// its pending-consent row behind exactly as the write path would.
pub(crate) fn gate_claim_write(
    vault: &crate::Vault,
    claim_id: &EntityId,
    body: &ClaimBody,
    envelope: &WriteEnvelope,
    checker: Option<&BoundedAutoChecker>,
    persist_pending_consent: bool,
) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    let policy = resolve_policy_manifest(&vault.store, &wtxn)?;
    let mut recorded_decision = None;
    let result = check_claim_policy_for_write_with_record(
        &vault.store,
        &mut wtxn,
        claim_id,
        ClaimGateWrite {
            body,
            envelope: Some(envelope),
            auto_checker: checker,
            defer_metrics_until_commit: false,
            transition: None,
            owner_authored: None,
            pending_prompt: None,
        },
        &policy,
        GateWriteMode {
            record_decision: true,
            persist_pending_consent,
            resolve_pending: false,
            can_resolve_pending_consent: true,
            include_source_in_gate_input: true,
        },
        &mut recorded_decision,
    );
    wtxn.commit()?;
    result
}
