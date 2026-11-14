#![cfg(all(oneiron_test_support, feature = "test-support"))]
//! OPUS-T0-F gate pins, PR 7 (Engine NOTE 13 Nov 02:19): green pins for
//! claim and record producer gates of OPUS-TRIAGECENSUS's census
//! (census/TRIAGE.md, class GAP-PASSES: real callers pass these gates
//! today, and no running test drove them from a door). Each test drives
//! the door a real caller uses, with that caller's inputs, through the
//! gate, and reads the write back. A pin that goes red is a live refusal
//! of a real caller (GAP-BROKEN).
//!
//! Each test name starts with the census id, so `-- g277_` runs one gate's
//! pin.
//!
//! - G210 `validate_key_string`: a minted mail thread ref and a normalized
//!   address record a thread event, and the projector lands its member
//!   claim.
//! - G2 `ClaimValueFieldRedaction::new`: the courtesy answer's redaction of
//!   one value field of a stored claim (through `test_doors::
//!   claim_value_redaction`, the answer door's own writer step).
//! - G238 `topology_seal_revision_for_store_in_txn`: an undo of a merge
//!   under the merge's current seal revision.
//! - G240 `put_learning_setting_as_owner`: the owner pins a spawn choice.
//! - G255 `put_attempt_pack_attribution_in_txn`: a leased agent run's
//!   attribution binds.
//! - G266 `admit_surface_event_once_in_txn`: an agent's CC email lands once,
//!   and its exact retry replays it.
//! - G277 `retract_edge_provenance_in_txn`: the Dreamer reverts its evidence
//!   batch and the support record is retracted.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features --test gate_pins_claim_record_producers`.

mod common;

use std::sync::Arc;

use oneiron::agent_dispatch::{AgentDispatchOutcome, AgentDispatcher};
use oneiron::attempt_queue::{AttemptQueue, ClaimAttempt, ClaimOutcome};
use oneiron::channel_identity::{ChannelIdentityBinding, ChannelIdentityState, SelfHeldShape};
use oneiron::comm::{
    count_active_thread_member_claims, record_comm_thread_event, run_comm_projector,
};
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::identity_topology::{
    EngineCause, IdentityOpEvidence, IdentityOpOutcome, IdentityOpWrite, IdentityTopologyOp,
    MergeOp, SurvivorshipPlan, TopologySeal,
};
use oneiron::learning_setting_doors::{
    LearningChoiceValue, LearningSettingMode, LearningSettingPut, put_learning_setting_as_owner,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::skill_attribution::bind_agent_run_attribution;
use oneiron::test_doors::claim_value_redaction::redact_claim_value_fields;
use oneiron::test_doors::consolidation::{consolidate_unbound_turn, open_dreamer_vault};
use oneiron::test_doors::derive::{
    Derived, Evidence, Named, claim_lifecycle, commit, revert, supports, witness_turn,
};
use oneiron::test_doors::steward;
use oneiron::thread_passport::canonical_message_id;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EntityId, InboundSurfaceEventInput, SurfaceCounterpartyStamp,
    SurfaceEventAdmission, TimeRange, Vault, VaultConfig,
};
use rmpv::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Maps any error into the test's error with the step that failed, so a red
/// pin names its door and the refusal's own words.
fn at<E: std::fmt::Debug>(step: &'static str) -> impl FnOnce(E) -> Box<dyn std::error::Error> {
    move |error| format!("{step}: {error:?}").into()
}

const fn range(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

/// A PERSON row at a fresh id.
fn person(vault: &Vault) -> TestResult<EntityId> {
    let id = EntityId::now();
    vault
        .put_entity(&id, ENTITY_TYPE_PERSON, range(100), 100, b"person")
        .map_err(at("put a PERSON"))?;
    Ok(id)
}

/// A vault with no policy manifest yet: the shipped default floors the comm
/// projector's and the CC intake's claim writes before the gate under test
/// is read (tests/it/effect_spine_oracle.rs `es03_`).
fn open_unseeded() -> TestResult<(tempfile::TempDir, Vault)> {
    let dir = tempfile::tempdir()?;
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open_unseeded_for_test(dir.path(), config).map_err(at("open unseeded"))?;
    Ok((dir, vault))
}

/// A device vault whose install signs: an identity op is sealed with this
/// install's machine key (tests/split_assignments_after_merge_undo.rs).
fn open_signing() -> TestResult<(tempfile::TempDir, Vault)> {
    let dir = tempfile::tempdir()?;
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    let vault = Vault::open(dir.path(), config).map_err(at("open"))?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault
        .prepare_install_signing()
        .map_err(at("install signing"))?;
    Ok((dir, vault))
}

#[test]
fn g210_a_mail_thread_event_records_and_projects_its_member() -> TestResult {
    let (_dir, vault) = open_unseeded()?;
    // The CC intake's key shapes (cc_intake.rs): the passport's minted
    // `mail:v1:` thread ref and a normalized address.
    let thread = canonical_message_id("<m1@example.net>")
        .map_err(at("canonical message id"))?
        .minted_thread_ref();
    record_comm_thread_event(&vault, &thread, "owen@example.com", true, 10)
        .map_err(at("record the thread event"))?;
    run_comm_projector(&vault).map_err(at("run the comm projector"))?;
    assert_eq!(
        count_active_thread_member_claims(&vault, &thread, "owen@example.com")
            .map_err(at("count the member claims"))?,
        1
    );
    Ok(())
}

#[test]
fn g2_a_courtesy_redaction_removes_one_value_field() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default()).map_err(at("open"))?;
    let owner = vault
        .ensure_embedded_owner_actor()
        .map_err(at("embedded owner"))?;
    let subject = person(&vault)?;
    // `profile.` is the prefix the default policy manifest rates normal.
    let claim = EntityId::now();
    let value = Value::Map(vec![
        (Value::from("secret_note"), Value::from("the door code")),
        (Value::from("public_note"), Value::from("likes tea")),
    ]);
    vault
        .put_claim(
            &claim,
            &ClaimBody::new(
                "profile.note",
                ClaimSubject::Entity(subject),
                value,
                0.9,
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Active,
            )
            .map_err(at("claim body"))?,
            range(100),
            100,
        )
        .map_err(at("put the claim"))?;
    // The courtesy answer's redact row names one value field (answer.rs).
    let redaction = redact_claim_value_fields(&vault, claim, &["secret_note".to_owned()], owner)
        .map_err(at("redact the value field"))?;
    assert_eq!(redaction.record, claim);
    assert_eq!(redaction.value_fields, ["secret_note"]);
    let body = vault
        .get_claim(&claim)?
        .ok_or("the redacted claim is gone")?;
    let Value::Map(entries) = &body.value else {
        return Err(format!("the claim value is no map: {:?}", body.value).into());
    };
    let keys: Vec<&str> = entries.iter().filter_map(|(key, _)| key.as_str()).collect();
    assert!(!keys.contains(&"secret_note"), "the field stays: {keys:?}");
    assert!(
        keys.contains(&"public_note"),
        "the other field is gone: {keys:?}"
    );
    Ok(())
}

#[test]
fn g238_a_merge_undo_under_its_current_seal_revision_lands() -> TestResult {
    let (_dir, vault) = open_signing()?;
    let source = person(&vault)?;
    let survivor = person(&vault)?;
    let write = IdentityOpWrite::auto(ClaimSource::Inferred);
    let merge = match vault
        .apply_identity_topology_op(
            &IdentityTopologyOp::Merge(MergeOp {
                sources: vec![source],
                survivor,
                evidence: IdentityOpEvidence {
                    refs: Vec::new(),
                    rationale: "gate pin merge".to_owned(),
                },
                survivorship_plan: SurvivorshipPlan::ReadThrough,
            }),
            &write,
            200,
        )
        .map_err(at("merge two PERSONs"))?
    {
        IdentityOpOutcome::Applied { event, .. } => event,
        other => return Err(format!("the merge did not apply: {other:?}").into()),
    };
    // The owner route's undo (verbs/identity_topology/ops.rs) names the
    // revision its surface showed: the seal's `seen`.
    let revision = vault
        .identity_topology_seal_revision(&merge)
        .map_err(at("read the merge's seal revision"))?;
    assert_ne!(revision, [0_u8; 32], "the merge has no seal revision");
    let undo = vault
        .undo_identity_topology_event_as(
            &merge,
            &write,
            &TopologySeal::engine(EngineCause::Unattributed).with_seen(Some(revision)),
            300,
        )
        .map_err(at("undo the merge under its seal"))?;
    assert!(
        matches!(undo, IdentityOpOutcome::Applied { .. }),
        "the undo did not apply: {undo:?}"
    );
    Ok(())
}

#[test]
fn g240_the_owner_pins_a_spawn_width() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = steward::open_owner_carrier_vault(dir.path()).map_err(at("open the carrier"))?;
    let owner = steward::owner(&vault).map_err(at("owner proof"))?;
    // The owner route's put (learning_setting_routes.rs): a choice key with
    // its choice, no number.
    let view = put_learning_setting_as_owner(
        &vault,
        &owner,
        LearningSettingPut {
            key: "width".to_owned(),
            mode: LearningSettingMode::Pin,
            value: None,
            choice: Some(LearningChoiceValue::Width(3)),
            weight_runs: None,
            why: "two reviewers and a writer".to_owned(),
            goal: None,
            project: None,
            task_type: None,
        },
    )
    .map_err(at("pin the spawn width"))?;
    assert!(
        view.rows
            .iter()
            .any(|row| row.key == "width" && row.choice == Some(LearningChoiceValue::Width(3))),
        "no width row of 3 among {} rows",
        view.rows.len()
    );
    Ok(())
}

#[test]
fn g255_a_leased_agent_runs_attribution_binds() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default()).map_err(at("open"))?;
    // A dispatched default-base agent run, leased and stamped with its
    // executor model as the runner does (tests/skill_hub_admission_holds.rs).
    let now = vault.now_recorded_at();
    let AgentDispatchOutcome::Dispatched(dispatched) = AgentDispatcher::new(&vault)
        .dispatch_default_base(None, None, None, now)
        .map_err(at("dispatch an agent run"))?
    else {
        return Err("the agent run was not dispatched".into());
    };
    let attempt = dispatched.attempt.id;
    let queue = AttemptQueue::new(&vault);
    let ClaimOutcome::Claimed(leased) = queue
        .claim_kind(
            DREAMER_RUNNER_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: "gate-pins".to_owned(),
                now: vault.now_recorded_at(),
            },
        )
        .map_err(at("lease the run"))?
    else {
        return Err("the run is not claimable".into());
    };
    assert_eq!(leased.id, attempt);
    queue
        .set_executor_model(
            attempt,
            "gate-pins",
            leased.attempt_count,
            "gate-pins/model@1",
        )
        .map_err(at("stamp the executor model"))?;
    assert!(
        bind_agent_run_attribution(&vault, attempt, "gate-pins")
            .map_err(at("bind the run's attribution"))?,
        "the attribution did not bind"
    );
    // The row stands: a second bind finds it and binds nothing.
    assert!(
        !bind_agent_run_attribution(&vault, attempt, "gate-pins")
            .map_err(at("bind the attribution again"))?
    );
    Ok(())
}

#[test]
fn g266_an_agents_cc_email_lands_once_and_its_retry_replays() -> TestResult {
    let (_dir, vault) = open_unseeded()?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    // The agent's own mail address, Active and bound to it.
    let agent = EntityId::now();
    let address = "yuki@agents.example.net";
    let identity = common::self_held_identity_in_state(
        "email",
        address,
        SelfHeldShape::DedicatedAddress,
        ChannelIdentityBinding::agent(agent),
        ChannelIdentityState::Active,
        100,
    );
    vault
        .create_channel_identity(&EntityId::now(), &identity)
        .map_err(at("create the agent's mail identity"))?;
    // A provider's inbound mail with the agent on CC (native_mail.rs).
    let input = InboundSurfaceEventInput::new(
        "evt-gate-pins-cc",
        "email",
        address,
        SurfaceCounterpartyStamp::unknown("guest@example.net"),
        1_800_000_123,
        true,
    )
    .with_payload_ref("payload:gate-pins-cc");
    let first = vault
        .enqueue_cc_agent_email(input.clone(), "<m1@example.net>", &[], None, 1_800_000_200)
        .map_err(at("the CC email"))?;
    let SurfaceEventAdmission::Accepted(ack) = first.admission else {
        return Err("the CC email was not accepted".into());
    };
    assert!(!ack.replayed);
    // The provider's exact retry of the same delivery.
    let retry = vault
        .enqueue_cc_agent_email(input, "<m1@example.net>", &[], None, 1_800_000_300)
        .map_err(at("the CC email's retry"))?;
    let SurfaceEventAdmission::Accepted(replay) = retry.admission else {
        return Err("the CC email's retry was not accepted".into());
    };
    assert!(replay.replayed, "the retry is a second event");
    assert_eq!(replay.attempt_ref, ack.attempt_ref);
    let status = vault
        .surface_event_handoff_status(&ack.correlation_id)
        .map_err(at("read the handoff status"))?
        .ok_or("the CC email has no handoff")?;
    assert_eq!(status.attempt_ref, ack.attempt_ref);
    Ok(())
}

/// The model's reply: one new person, named in T1, and its name
/// (tests/derive_evidence.rs).
fn reply() -> String {
    serde_json::json!({
        "persons": [{"id": "new:P1", "name": "Owen", "evidence_turn_refs": ["T1"]}],
        "candidates": [{
            "subject": "new:P1",
            "predicate": "profile.name",
            "value": "Owen",
            "confidence": 0.8,
            "evidence_refs": [{"source": "T1", "quote": "Owen"}],
        }],
    })
    .to_string()
}

#[test]
fn g277_reverting_an_evidence_batch_retracts_its_support() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = open_dreamer_vault(dir.path(), "reader").map_err(at("open the Dreamer vault"))?;
    let dreamer = steward::dreamer(&vault).map_err(at("the Dreamer"))?;
    let pass = consolidate_unbound_turn(&vault, "call me Owen", None, None, &reply())
        .map_err(at("one consolidation pass"))?;
    let [claim] = pass.landed.as_slice() else {
        return Err(format!("one landed claim, found {}", pass.landed.len()).into());
    };
    let turn = witness_turn(&vault, "my name is Owen").map_err(at("a TURN"))?;
    let batch = commit(
        &vault,
        dreamer,
        EdgeActorClass::System,
        "run-evidence",
        &[Derived::Evidence(Evidence {
            local: "evidence",
            head: Named::Stored(*claim),
            sources: vec![Named::Stored(turn)],
        })],
    )
    .map_err(at("commit the evidence batch"))?;
    assert!(batch.items[0].landed, "the evidence did not land");
    let [record] = batch.items[0].rows.as_slice() else {
        return Err("the evidence wrote no single support record".into());
    };
    let record = *record;
    assert_eq!(
        claim_lifecycle(&vault, record).map_err(at("read the support"))?,
        Some("active".to_owned())
    );
    let (reverted, left) = revert(&vault, dreamer, EdgeActorClass::System, batch.batch)
        .map_err(at("revert the batch"))?
        .map_err(at("the Dreamer's own batch reverts"))?;
    assert_eq!(reverted, ["evidence"]);
    // An inverse the gate refused would sit here.
    assert!(left.is_empty(), "left unreverted: {left:?}");
    assert_eq!(
        claim_lifecycle(&vault, record).map_err(at("read the retracted support"))?,
        Some("retracted".to_owned())
    );
    // The retraction keeps the edge; only its provenance closes.
    assert!(supports(&vault, turn, *claim).map_err(at("read the edge"))?);
    Ok(())
}
