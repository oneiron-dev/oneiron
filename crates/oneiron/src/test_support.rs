//! Doors for tests that drive the engine from another crate, such as the
//! seal organ's end-to-end check, which runs the engine's seal task over the
//! real organ host. Hidden and compiled only for tests or with
//! `test-support`; never API. The crate's own tests reach the same helpers
//! through `test_util`.

use crate::authority::HostSlipIssuer;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::blob_artifact::esign::EsignAuditActor;
use crate::entity_id::EntityId;
use crate::registry::ENTITY_TYPE_POLICY_MANIFEST;
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::vault::Vault;

/// Raw stored-entity record: the 25-byte metadata header (type byte,
/// occurred start/end, learned_at — all big-endian u64s, per the
/// `batch::ENTITY_*_OFFSET` layout) followed by `body`.
pub(crate) fn entity_record(
    entity_type: u8,
    occurred: TimeRange,
    learned_at: u64,
    body: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + body.len());
    out.push(entity_type);
    out.extend_from_slice(&occurred.start.to_be_bytes());
    out.extend_from_slice(&occurred.end.to_be_bytes());
    out.extend_from_slice(&learned_at.to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// Stores `data` as a policy-manifest entity at `id` via a raw store put
/// (occurred `1..1`, learned_at `1`), bypassing the batch write path.
/// Seeding the *default* manifest slot must pass
/// `crate::gate::default_policy_manifest_id()` so the intent is explicit.
/// The `graph_fs` test copy deliberately stays local: it exercises the
/// real `apply_ops` write path instead of a raw put.
///
/// # Errors
/// The store's.
#[doc(hidden)]
pub fn put_policy_manifest_bytes(vault: &Vault, id: EntityId, data: &[u8]) -> crate::Result<()> {
    let payload = entity_record(
        ENTITY_TYPE_POLICY_MANIFEST,
        TimeRange { start: 1, end: 1 },
        1,
        data,
    );
    vault.with_write_txn(|wtxn| {
        // This fixture represents local authoring, not replay. Preserve that
        // origin even though it bypasses batch to isolate the tested gate.
        crate::gate::manifest_authenticity::stamp_manifest_origin(
            &vault.store,
            wtxn,
            &id,
            data,
            false,
        )?;
        vault.store.entities.put(wtxn, id.as_bytes(), &payload)?;
        let type_key = Store::encode_type_key(ENTITY_TYPE_POLICY_MANIFEST, &id);
        vault.store.type_index.put(wtxn, &type_key, &[])?;
        Ok(())
    })
}

/// The unit-test host root. Each test vault is its own trust domain, so one
/// fixed secret lets any fixture rebuild the issuer that rooted its vault.
#[doc(hidden)]
pub fn test_host_issuer() -> HostSlipIssuer {
    HostSlipIssuer::from_secret(b"oneiron unit test host root").expect("host issuer")
}

/// Roots the vault under the test host and provisions the engine's MACHINE
/// writers, as a host does at bootstrap. Returns the host issuer so a test can
/// provision its own MACHINE actors with `provision_host_machine_identity`.
#[doc(hidden)]
pub fn provision_engine_machines(vault: &Vault) -> HostSlipIssuer {
    let issuer = test_host_issuer();
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault
        .provision_engine_machine_identities(&issuer)
        .expect("engine machine identities");
    issuer
}

/// Binds `person` as the human owner under the host root, so owner verbs
/// keep working once a fixture roots its vault.
///
/// # Errors
/// The authority log's.
#[doc(hidden)]
pub fn bind_host_owner(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    person: EntityId,
) -> crate::Result<()> {
    vault.bind_host_owner_for_test(issuer, person)
}

/// Appends `Sent` to an esign document's ledger, as sending it does.
///
/// # Errors
/// The ledger's: an unknown document, or a state that cannot be sent.
#[doc(hidden)]
pub fn mark_esign_sent(
    vault: &Vault,
    document: EntityId,
    actor: EsignAuditActor,
    now: u64,
) -> crate::Result<()> {
    crate::blob_artifact::esign::mark_sent_for_test(vault, document, actor, now)
}

/// The scope an effect grant names in a policy manifest.
#[doc(hidden)]
pub fn effect_preset() -> crate::federation::Scope {
    crate::federation::scope_codec::effect_preset()
}

/// Test door: `owner` asks `holder` a question bound to the `outcome.earned`
/// claims about `holder` (or, with `linked_by`, about what `holder` reaches
/// over that edge kind), `holder` answers it, and the live policy lets
/// `owner` read the claims that label it. A host reads calibration pairs end
/// to end this way without a model. Both must be PERSON rows. Returns the
/// ask's handle and the time it was answered.
///
/// # Errors
/// Any write failure, or the ask or its answer being refused.
#[doc(hidden)]
pub fn settle_outcome_ask(
    vault: &Vault,
    owner: EntityId,
    holder: EntityId,
    linked_by: Option<&str>,
) -> crate::memory::MemoryResult<(crate::task_verb::TaskAskHandle, u64)> {
    use crate::task_verb::{
        ConsultPayloadRef, TaskAskDefault, TaskAskQuestion, TaskAskSpec, TaskAskTarget,
        TaskAskWord, TaskAssignee,
    };
    let bytes = crate::gate::default_policy_manifest()?;
    let mut manifest: serde_json::Value =
        rmp_serde::from_slice(&bytes).map_err(|_| crate::Error::CorruptedIndex("policy"))?;
    manifest["scoped_grants"] = serde_json::json!([{
        "actor_ref": owner.to_hex(),
        "effector": "core:read",
        "scope": crate::federation::scope_codec::read_preset(),
        "receipt_required": false,
    }]);
    if let Some(rules) = manifest["rules"].as_array_mut() {
        for predicate in ["outcome.earned", "judgment.answer"] {
            rules.push(serde_json::json!({"prefix": predicate, "exact": true,
                "axes": {"criticality": "normal", "sensitivity": "normal"}}));
        }
    }
    let manifest = rmp_serde::to_vec_named(&manifest)
        .map_err(|_| crate::Error::InvariantViolation("fixture policy"))?;
    put_policy_manifest_bytes(vault, crate::gate::default_policy_manifest_id()?, &manifest)?;

    let turn = EntityId::now();
    let now = crate::unix_seconds_now();
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![("role".into(), "question".into())]),
    )
    .map_err(|_| crate::Error::InvariantViolation("fixture turn"))?;
    vault.put_entity(
        &turn,
        crate::registry::ENTITY_TYPE_TURN,
        TimeRange {
            start: now,
            end: now,
        },
        now,
        &body,
    )?;
    let question = TaskAskQuestion {
        reference: ConsultPayloadRef::parse(vault, &format!("tn_{}", turn.to_hex()))?,
        revision: 1,
        options: Default::default(),
        context_refs: Vec::new(),
        label: None,
        outcome_binding: Some(crate::llm::decision::questions::OutcomeBinding {
            source: crate::llm::decision::questions::OutcomeSource::Claim {
                predicate: "outcome.earned".into(),
            },
            horizon: 60,
            mapping: [("won".into(), true), ("lost".into(), false)].into(),
            noise_weight: 0.8,
            linked_by: linked_by.map(str::to_owned),
        }),
        ladder_answer: None,
        class_key: None,
        commitment: false,
    };
    let spec = TaskAskSpec {
        intent_key: format!("outcome-{}", turn.to_hex()),
        ..TaskAskSpec::shorthand(
            Some(TaskAskTarget::Responder(TaskAssignee::Human {
                actor_ref: holder,
            })),
            question,
            Some(u64::MAX),
            TaskAskDefault::AskMe,
        )
    };
    let handle = vault
        .memory(owner, crate::EdgeActorClass::Human)
        .tasks_ask(&spec)?
        .handle;
    vault
        .memory(holder, crate::EdgeActorClass::Human)
        .tasks_answer(&handle, &TaskAskWord::new(holder))?;
    let answered =
        crate::llm::decision::questions::read_question(vault, owner, handle.group_ref, None)?
            .ok_or(crate::Error::EntityNotFound)?
            .created_at;
    Ok((handle, answered))
}

/// A temporary directory a restore accepts, for tests that restore, rehearse
/// or activate a vault: made under the system temp directory when no other
/// user could move a directory on the way to it (`store::refuse_shared_path`),
/// else under `/tmp`. Panics with the refusals when neither passes, so a test
/// never skips for its host's layout: where another account owns a directory
/// above the temp directory, every restore under it is refused, as it should
/// be, and the test would fail on that refusal instead of its own check.
pub fn restore_tempdir() -> tempfile::TempDir {
    tempfile::tempdir_in(restore_temp_base()).expect("a temporary directory")
}

#[cfg(unix)]
fn restore_temp_base() -> std::path::PathBuf {
    let mut refusals = Vec::new();
    for base in [std::env::temp_dir(), std::path::PathBuf::from("/tmp")] {
        match crate::store::refuse_shared_path(&base) {
            Ok(()) => return base,
            Err(refusal) => refusals.push(refusal.to_string()),
        }
    }
    panic!(
        "no temporary directory a restore accepts: {}",
        refusals.join("; ")
    );
}

#[cfg(not(unix))]
fn restore_temp_base() -> std::path::PathBuf {
    std::env::temp_dir()
}
