//! AGENT-3 (ONE-1445) tests, mapped 1:1 to the brief's acceptance criteria:
//! snapshot round-trip, system-preset dispatch, the dispatchability
//! predicate, dedupe, the strict input codec, snapshot-vs-live split, the
//! OF-193 checkpoint/resume contract (AC 7, re-pinned WITH a loaded manifest
//! per B1), and the AGENT-2 live-ceiling integration (AC 9). AC 8 (run-tree
//! surfacing) lives in `run_tree/tests.rs`.

use super::*;
use crate::VaultConfig;
use crate::agent_def::{AgentCeiling, AgentScope};
use crate::attempt_queue::{AttemptQueue, AttemptState, CleanupAttemptLeases};
use crate::claim::ClaimSubject;
use crate::dreamer_runner::{
    AdmitDreamerAttempt, DREAMER_MILESTONE_PREDICATE, DreamerAdmissionOutcome,
    DreamerMilestoneClaim, DreamerMilestoneKind, decode_dreamer_attempt_payload,
    dreamer_milestone_value,
};
use crate::error::ErrorKind;
use crate::registry::{ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use crate::task_verb::{TaskAssignee, TaskCreateSpec, TaskResultInput, TaskTerminalDisposition};
use crate::temporal::TimeRange;
use crate::test_util::{entity as test_id, put_policy_manifest_bytes};
use crate::write_envelope::{ClaimCandidate, WriteEnvelope, WriteProvenance};

fn open_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(VaultConfig::device())
}

fn t(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

/// A stored, dispatchable custom definition fixture.
fn custom_agent(version: &str) -> AgentDefinition {
    AgentDefinition::new(
        "oneiron.agent.custom",
        "Custom dispatch fixture",
        version,
        Some("You are a dispatch fixture.".to_owned()),
        vec![crate::skill::SkillDependency::new("oneiron.skill.search")],
        vec!["web.search".to_owned()],
        Vec::new(),
        None,
        AgentScope::All,
        AgentCeiling::Proposed,
        None,
        crate::claim::ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        crate::claim::ClaimSource::UserStated,
        1.0,
        false,
        true,
        Value::Map(vec![(Value::from("definedVia"), Value::from("test"))]),
        None,
        true,
        None,
    )
}

/// The seeded row a `sys.*` logical id names, plus its stored body.
fn seeded_row(vault: &Vault, logical_id: &str) -> (EntityId, AgentDefinition) {
    vault
        .get_seeded_agent_definition_by_logical_id(logical_id)
        .expect("seeded roster resolves")
        .expect("seeded row exists")
}

/// A persisted PRE-1890 `target="system"` dispatch input, hand-built because
/// encode never emits this shape again.
fn legacy_system_payload(legacy_target_name: &str, definition: &AgentDefinition) -> Value {
    Value::Map(vec![
        (
            Value::from("schema_version"),
            Value::from(AGENT_DISPATCH_INPUT_SCHEMA_VERSION),
        ),
        (Value::from("target"), Value::from("system")),
        (Value::from("preset"), Value::from(legacy_target_name)),
        (
            Value::from("definition"),
            Value::Binary(encode_agent_definition(definition).expect("fixture body encodes")),
        ),
    ])
}

fn actor_ceiling_row(actor_class: &str, ceiling: &str) -> Value {
    Value::Map(vec![
        (Value::from("actor_class"), Value::from(actor_class)),
        (Value::from("ceiling"), Value::from(ceiling)),
    ])
}

/// Minimal valid policy manifest (mirrors the gate-test fixture shape) with
/// caller-supplied `actor_ceilings` rows.
fn put_policy_manifest(vault: &Vault, seed: u8, actor_rows: Vec<Value>) -> Result<()> {
    let manifest = Value::Map(vec![
        (Value::from("schema_version"), Value::from("1.1")),
        (Value::from("pack_id"), Value::from("agent-dispatch-test")),
        (Value::from("pack_version"), Value::from("v1")),
        (
            Value::from("min_engine_version"),
            Value::from(env!("CARGO_PKG_VERSION")),
        ),
        (
            Value::from("defaults"),
            Value::Map(vec![
                (Value::from("criticality"), Value::from("normal")),
                (Value::from("sensitivity"), Value::from("normal")),
            ]),
        ),
        (Value::from("rules"), Value::Array(Vec::new())),
        (Value::from("actor_ceilings"), Value::Array(actor_rows)),
    ]);
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &manifest).expect("encode manifest");

    put_policy_manifest_bytes(vault, test_id(seed), &data)
}

fn dispatch_custom(
    dispatcher: &AgentDispatcher<'_>,
    id: EntityId,
    dedupe_key: Option<&str>,
    now: u64,
) -> Result<AgentDispatchOutcome> {
    dispatcher.dispatch(DispatchAgent {
        target: AgentDispatchTarget::Custom(id),
        parent_attempt: None,
        dedupe_key: dedupe_key.map(str::to_owned),
        run_id: None,
        now,
    })
}

// AC test 1: dispatching a stored definition freezes its composition into the
// queue payload — the durable row round-trips the exact snapshot.
#[test]
fn dispatch_custom_round_trips_snapshot() -> Result<()> {
    let (_dir, vault) = open_vault();
    let def_id = test_id(0x31);
    let def = custom_agent("1.0.0");
    vault.put_agent_definition(&def_id, &def, t(1), 1)?;

    let dispatcher = AgentDispatcher::new(&vault);
    let AgentDispatchOutcome::Dispatched(status) = dispatch_custom(&dispatcher, def_id, None, 10)?
    else {
        panic!("expected fresh dispatch");
    };
    assert_eq!(status.input.target, AgentDispatchTarget::Custom(def_id));
    assert_eq!(status.input.definition, def);

    // The durable queue row carries the same payload.
    let queue = AttemptQueue::new(&vault);
    let record = queue.get(status.attempt.id)?.expect("queued dispatch row");
    let payload = decode_dreamer_attempt_payload(&record.payload)?;
    assert_eq!(payload.attempt_type, AGENT_DISPATCH_ATTEMPT_TYPE);
    let decoded = decode_agent_dispatch_input(&payload.input)?;
    assert_eq!(decoded, status.input);
    assert_eq!(decoded.definition.skills, def.skills);
    assert_eq!(decoded.definition.connectors, def.connectors);
    assert_eq!(decoded.definition.scope, def.scope);
    Ok(())
}

// AC test 2 (ONE-1890 `custom_dispatch_executes_seeded_row_data`): a seeded
// row dispatches from its LIVE stored body — including a user edit that
// differs from the shipped manifest — under its own row id as actor identity.
#[test]
fn custom_dispatch_executes_seeded_row_data() -> Result<()> {
    let (_dir, vault) = open_vault();
    let (scout_id, seeded) = seeded_row(&vault, "sys.scout");

    // The user edits the stored row away from the manifest.
    let mut edited = seeded.clone();
    edited.version = "2".to_owned();
    edited.desc = "user edited scout".to_owned();
    edited.display_name = Some("My Scout".to_owned());
    vault.update_agent_definition(&scout_id, &edited, t(2), 2)?;
    assert_ne!(edited.desc, seeded.desc);

    let dispatcher = AgentDispatcher::new(&vault);
    let AgentDispatchOutcome::Dispatched(status) = dispatcher.dispatch(DispatchAgent {
        target: AgentDispatchTarget::Custom(scout_id),
        parent_attempt: None,
        dedupe_key: None,
        run_id: None,
        now: 10,
    })?
    else {
        panic!("expected fresh dispatch");
    };
    assert_eq!(status.input.target, AgentDispatchTarget::Custom(scout_id));
    assert_eq!(status.input.definition, edited);
    assert_eq!(status.input.definition.desc, "user edited scout");

    let actor = agent_dispatch_actor(&status.input);
    assert_eq!(actor.entity_ref(), scout_id);
    assert_eq!(actor.actor_class(), EdgeActorClass::Agent);
    Ok(())
}

// AC test 3: the dispatchability predicate — three custom rejections with the
// pinned messages, plus the disabled-preset rejection. Nothing is enqueued.
#[test]
fn dispatch_rejections() -> Result<()> {
    let (_dir, vault) = open_vault();
    let dispatcher = AgentDispatcher::new(&vault);

    let superseded_id = test_id(0x62);
    let mut superseded = custom_agent("1.0.0");
    superseded.lifecycle_status = ClaimLifecycleStatus::Superseded;
    vault.put_agent_definition(&superseded_id, &superseded, t(1), 1)?;
    let err = dispatch_custom(&dispatcher, superseded_id, None, 10)
        .expect_err("superseded definition must not dispatch");
    assert!(matches!(
        err,
        Error::AgentNotDispatchable("agent definition is not active")
    ));

    let proposed_id = test_id(0x43);
    let mut proposed = custom_agent("1.0.0");
    proposed.approval_status = crate::claim::ClaimApprovalStatus::Proposed;
    vault.put_agent_definition(&proposed_id, &proposed, t(1), 1)?;
    let err = dispatch_custom(&dispatcher, proposed_id, None, 10)
        .expect_err("unapproved definition must not dispatch");
    assert!(matches!(
        err,
        Error::AgentNotDispatchable("agent definition is not approved")
    ));

    // Nothing was enqueued by any rejection.
    assert!(AttemptQueue::new(&vault).list()?.is_empty());
    Ok(())
}

// ONE-1890 done-means: an explicit dispatch naming an absent row is the typed
// `AgentDefinitionNotFound { id }`, not the generic dispatchability rejection.
#[test]
fn missing_agent_definition_rejects_explicit_dispatch() -> Result<()> {
    let (_dir, vault) = open_vault();
    let dispatcher = AgentDispatcher::new(&vault);
    let missing_id = test_id(0x41);
    assert_eq!(vault.get_agent_definition(&missing_id)?, None);

    let err = dispatch_custom(&dispatcher, missing_id, None, 10)
        .expect_err("missing definition must not dispatch");
    assert!(matches!(
        err,
        Error::AgentDefinitionNotFound { id } if id == missing_id
    ));
    assert!(AttemptQueue::new(&vault).list()?.is_empty());
    Ok(())
}

// ONE-1890 done-means: `enabled` is ROW state, an explicit dispatch to a
// disabled row is the typed `AgentDefinitionDisabled { id }`, and the landed
// lifecycle/approval checks still run BEFORE it (regression).
#[test]
fn disabled_agent_definition_rejects_explicit_dispatch() -> Result<()> {
    let (_dir, vault) = open_vault();
    let dispatcher = AgentDispatcher::new(&vault);
    let dispatch_to = |id| {
        dispatcher.dispatch(DispatchAgent {
            target: AgentDispatchTarget::Custom(id),
            parent_attempt: None,
            dedupe_key: None,
            run_id: None,
            now: 10,
        })
    };

    let (herald_id, herald) = seeded_row(&vault, "sys.herald");
    let mut disabled = herald;
    disabled.version = "2".to_owned();
    disabled.enabled = false;
    vault.update_agent_definition(&herald_id, &disabled, t(2), 2)?;
    let err = dispatch_to(herald_id).expect_err("a disabled row must not dispatch");
    assert!(matches!(
        err,
        Error::AgentDefinitionDisabled { id } if id == herald_id
    ));

    // A disabled row that is ALSO inactive still reports the landed
    // dispatchability rejection first — order is unchanged by ONE-1890.
    let mut disabled_and_retired = disabled;
    disabled_and_retired.version = "3".to_owned();
    disabled_and_retired.lifecycle_status = ClaimLifecycleStatus::Retracted;
    vault.update_agent_definition(&herald_id, &disabled_and_retired, t(3), 3)?;
    let err = dispatch_to(herald_id).expect_err("an inactive row must not dispatch");
    assert!(matches!(
        err,
        Error::AgentNotDispatchable("agent definition is not active")
    ));

    assert!(AttemptQueue::new(&vault).list()?.is_empty());
    Ok(())
}

// AC test 4: the namespaced dedupe key — the same caller key dedupes onto the
// existing agent-dispatch row.
#[test]
fn dispatch_dedupe_existing() -> Result<()> {
    let (_dir, vault) = open_vault();
    let def_id = test_id(0x44);
    vault.put_agent_definition(&def_id, &custom_agent("1.0.0"), t(1), 1)?;

    let dispatcher = AgentDispatcher::new(&vault);
    let AgentDispatchOutcome::Dispatched(first) =
        dispatch_custom(&dispatcher, def_id, Some("morning-run"), 10)?
    else {
        panic!("expected fresh dispatch");
    };
    let AgentDispatchOutcome::Existing(second) =
        dispatch_custom(&dispatcher, def_id, Some("morning-run"), 20)?
    else {
        panic!("expected deduped dispatch");
    };
    assert_eq!(second.attempt.id, first.attempt.id);
    assert_eq!(second.input, first.input);
    assert_eq!(
        second.attempt.dedupe_key.as_deref(),
        Some("agent.dispatch:morning-run"),
        "the queue-level dedupe key is namespaced (M6)"
    );
    Ok(())
}

// AC test 5: the strict pinned-key input codec rejects every structural
// violation with InvalidAgentDispatchInput.
#[test]
fn dispatch_input_codec_strict() -> Result<()> {
    let def = custom_agent("1.0.0");
    let def_id = test_id(0x45);
    let valid = encode_agent_dispatch_input(&AgentDispatchInput::frozen(
        AgentDispatchTarget::Custom(def_id),
        def,
    ))?;
    assert_eq!(
        decode_agent_dispatch_input(&valid)?.target,
        AgentDispatchTarget::Custom(def_id)
    );

    let entries_of = |value: &Value| -> Vec<(Value, Value)> {
        let Value::Map(entries) = value else {
            panic!("dispatch input is a map");
        };
        entries.clone()
    };
    let reject = |entries: Vec<(Value, Value)>, case: &str| {
        let err = decode_agent_dispatch_input(&Value::Map(entries)).expect_err(case);
        assert_eq!(err.kind(), ErrorKind::InvalidAgentDispatchInput, "{case}");
    };

    // Unknown key.
    let mut entries = entries_of(&valid);
    entries.push((Value::from("host_note"), Value::from("smuggled")));
    reject(entries, "unknown key");

    // Duplicate key.
    let mut entries = entries_of(&valid);
    entries.push((Value::from("target"), Value::from("custom")));
    reject(entries, "duplicate key");

    // Wrong schema version.
    let mut entries = entries_of(&valid);
    for (key, value) in &mut entries {
        if key.as_str() == Some("schema_version") {
            *value = Value::from(2_u64);
        }
    }
    reject(entries, "wrong schema_version");

    // target custom with preset present.
    let mut entries = entries_of(&valid);
    entries.push((Value::from("preset"), Value::from("sys.scout")));
    reject(entries, "custom target with preset key");

    // target system with agent_def present.
    // Legacy `target="system"` payloads are hand-built: encode never emits
    // them again (ONE-1890).
    let system = legacy_system_payload("sys.scout", &custom_agent("1.0.0"));
    let mut entries = entries_of(&system);
    entries.push((Value::from("agent_def"), Value::from(def_id.to_hex())));
    reject(entries, "system target with agent_def key");

    // Non-binary definition.
    let mut entries = entries_of(&valid);
    for (key, value) in &mut entries {
        if key.as_str() == Some("definition") {
            *value = Value::from("not binary");
        }
    }
    reject(entries, "non-binary definition");

    // Unknown preset id.
    let mut entries = entries_of(&system);
    for (key, value) in &mut entries {
        if key.as_str() == Some("preset") {
            *value = Value::from("sys.unknown");
        }
    }
    reject(entries, "unknown preset id");

    // Missing target / non-map input.
    let mut entries = entries_of(&valid);
    entries.retain(|(key, _)| key.as_str() != Some("target"));
    reject(entries, "missing target");
    assert_eq!(
        decode_agent_dispatch_input(&Value::from("nope"))
            .expect_err("non-map input")
            .kind(),
        ErrorKind::InvalidAgentDispatchInput
    );
    Ok(())
}

// AC test 6: the snapshot-vs-live split — updating the definition mid-flight
// leaves the dispatched composition frozen while live reads see the update.
#[test]
fn snapshot_survives_definition_update() -> Result<()> {
    let (_dir, vault) = open_vault();
    let def_id = test_id(0x46);
    let original = custom_agent("1.0.0");
    vault.put_agent_definition(&def_id, &original, t(1), 1)?;

    let dispatcher = AgentDispatcher::new(&vault);
    let AgentDispatchOutcome::Dispatched(status) = dispatch_custom(&dispatcher, def_id, None, 10)?
    else {
        panic!("expected fresh dispatch");
    };

    let mut updated = custom_agent("2.0.0");
    updated.skills = vec![crate::skill::SkillDependency::new("oneiron.skill.new")];
    vault.update_agent_definition(&def_id, &updated, t(2), 2)?;

    let queue = AttemptQueue::new(&vault);
    let record = queue.get(status.attempt.id)?.expect("queued dispatch row");
    let payload = decode_dreamer_attempt_payload(&record.payload)?;
    let snapshot = decode_agent_dispatch_input(&payload.input)?.definition;
    assert_eq!(snapshot, original, "composition is frozen at dispatch");
    assert_eq!(
        vault.get_agent_definition(&def_id)?,
        Some(updated),
        "live reads see the update (authority resolves live — AC test 9)"
    );
    Ok(())
}

// AC test 7 (the OF-193 AC, re-pinned 2026-07-10 per B1/N1): checkpoint and
// resume WITH a loaded manifest. Milestones ride the SYSTEM/Dreamer envelope
// with agent attribution in the claim (B1 (a)) so they index as Approved;
// the queue row plus payload survive a vault reopen; an expired lease is
// recoverable and re-admission replays the frozen snapshot.
#[test]
fn dispatch_survives_checkpoint_resume() -> Result<()> {
    let (dir, vault) = open_vault();
    // Loaded manifest (the B1 masking-AC callout): system-class writes get an
    // Auto row so the Dreamer-envelope milestone can land Approved and index.
    put_policy_manifest(&vault, 0x0D, vec![actor_ceiling_row("system", "auto")])?;

    let def_id = test_id(0x67);
    let def = custom_agent("1.0.0");
    vault.put_agent_definition(&def_id, &def, t(1), 1)?;

    let (attempt_id, dispatch_input) = {
        let dispatcher = AgentDispatcher::new(&vault);
        let AgentDispatchOutcome::Dispatched(status) =
            dispatch_custom(&dispatcher, def_id, None, 10)?
        else {
            panic!("expected fresh dispatch");
        };
        (status.attempt.id, status.input)
    };

    // The system/Dreamer bookkeeping envelope: a MACHINE actor, class System,
    // with the agent attribution carried in the provenance payload (B1 (a)).
    let dreamer_actor = test_id(0x2A);
    vault.put_entity(&dreamer_actor, ENTITY_TYPE_MACHINE, t(1), 1, b"dreamer")?;
    // The milestone subject is the attempt id itself (pinned); anchor an entity at
    // those bytes so the claim door's subject-existence check passes.
    // (`EntityId::from_bytes` takes the 16-byte array by value.)
    let subject = EntityId::from_bytes(*attempt_id.as_bytes())?;
    vault.put_entity(
        &subject,
        ENTITY_TYPE_PERSON,
        t(1),
        1,
        b"agent attempt anchor",
    )?;
    let milestone_envelope = WriteEnvelope::new(
        crate::write_envelope::WriteActor::new(dreamer_actor, EdgeActorClass::System),
        crate::claim::ClaimSource::Generated,
        WriteProvenance::new(Value::Map(vec![
            (Value::from("runner"), Value::from("dreamer")),
            (
                Value::from("agent"),
                Value::from(dispatch_input.definition.agent_id.as_str()),
            ),
            (
                Value::from("agentActor"),
                Value::from(agent_dispatch_actor(&dispatch_input).entity_ref().to_hex()),
            ),
        ]))?,
        crate::claim::ClaimApprovalStatus::Approved,
    );

    // Admission co-commits the durable started milestone.
    {
        let runner = DreamerRunnerStore::new(&vault);
        let DreamerAdmissionOutcome::Admitted(admitted) =
            runner.admit_next(AdmitDreamerAttempt {
                lease_owner: "agent-worker".to_owned(),
                now: 20,
                budget_id: "wake".to_owned(),
                budget_total_units: 10,
                reserve_units: 2,
                started_milestone: Some(DreamerMilestoneClaim {
                    claim_id: EntityId::now(),
                    subject,
                    kind: DreamerMilestoneKind::Started,
                    envelope: milestone_envelope.clone(),
                    occurred: t(20),
                    learned_at: 20,
                }),
            })?
        else {
            panic!("expected admission");
        };
        assert_eq!(admitted.status.attempt.id, attempt_id);
        assert_eq!(
            runner
                .latest_durable_milestone(attempt_id)?
                .expect("started milestone")
                .kind,
            DreamerMilestoneKind::Started
        );
    }

    // Mid-run checkpoint: an ordinary gated claim under the same envelope.
    let checkpoint_id = EntityId::now();
    let checkpoint_value =
        dreamer_milestone_value(attempt_id, DreamerMilestoneKind::CheckpointReached, 30);
    vault
        .batch()
        .claim_candidate(
            &checkpoint_id,
            ClaimCandidate::new(
                DREAMER_MILESTONE_PREDICATE,
                ClaimSubject::Entity(subject),
                checkpoint_value,
                1.0,
            ),
            &milestone_envelope,
            t(30),
            30,
        )
        .commit()?;

    // The milestone claim landed Approved (not held to proposal) and carries
    // the agent attribution in its stamped envelope provenance.
    let stored = vault.get_claim(&checkpoint_id)?.expect("checkpoint claim");
    assert_eq!(stored.approval, crate::claim::ClaimApprovalStatus::Approved);
    let Some(Value::Map(evidence)) = stored.evidence else {
        panic!("checkpoint claim carries envelope evidence");
    };
    let provenance = evidence
        .iter()
        .find(|(key, _)| key.as_str() == Some("provenance"))
        .map(|(_, value)| value)
        .expect("envelope provenance in evidence");
    let Value::Map(provenance) = provenance else {
        panic!("envelope provenance is a map");
    };
    assert!(
        provenance.iter().any(|(key, value)| {
            key.as_str() == Some("agent")
                && value.as_str() == Some(dispatch_input.definition.agent_id.as_str())
        }),
        "milestone carries the agent attribution (B1 (a))"
    );

    // Drop and REOPEN the vault: milestone index and queue row are durable.
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("reopen vault");
    let runner = DreamerRunnerStore::new(&vault);
    let milestone = runner
        .latest_durable_milestone(attempt_id)?
        .expect("durable milestone after reopen");
    assert_eq!(milestone.kind, DreamerMilestoneKind::CheckpointReached);
    assert_eq!(milestone.attempt_id, attempt_id);

    // Lease expiry → cleanup → the attempt is claimable again with the same
    // frozen snapshot.
    let report = AttemptQueue::new(&vault).cleanup_leases(CleanupAttemptLeases {
        now: 100,
        lease_timeout_secs: 10,
    })?;
    assert_eq!(report.stale_requeued, 1);
    assert_eq!(
        runner
            .status(attempt_id)?
            .expect("requeued attempt")
            .attempt
            .state,
        AttemptState::Queued
    );
    let DreamerAdmissionOutcome::Admitted(second) = runner.admit_next(AdmitDreamerAttempt {
        lease_owner: "second-worker".to_owned(),
        now: 110,
        budget_id: "wake".to_owned(),
        budget_total_units: 10,
        reserve_units: 2,
        started_milestone: None,
    })?
    else {
        panic!("expected re-admission after lease recovery");
    };
    assert_eq!(second.status.attempt.id, attempt_id);
    assert_eq!(
        decode_agent_dispatch_input(&second.status.payload.input)?,
        dispatch_input,
        "re-admission replays the dispatch-time snapshot"
    );
    Ok(())
}

// AC test 9 (integration with AGENT-2): a dispatched Herald fork's writes are
// clamped by its live definition ceiling even under a manifest granting
// agent-class Auto — the claim is held to proposal, never auto-approved.
#[test]
fn dispatched_agent_runs_under_clamped_ceiling() -> Result<()> {
    let (_dir, vault) = open_vault();
    put_policy_manifest(&vault, 0x0E, vec![actor_ceiling_row("agent", "auto")])?;

    let fork_id = test_id(0x48);
    let (herald_id, herald) = seeded_row(&vault, "sys.herald");
    let mut fork = herald.clone();
    fork.agent_id = "oneiron.agent.herald.custom".to_owned();
    fork.version = "1".to_owned();
    fork.forked_from = Some(herald_id);
    fork.ceiling = herald.ceiling;
    fork.logical_id = None;
    fork.display_name = None;
    fork.source = crate::claim::ClaimSource::UserStated;
    fork.provenance = Value::Map(vec![(
        Value::from("forkOf"),
        Value::from(herald_id.to_hex()),
    )]);
    vault.put_agent_definition(&fork_id, &fork, t(1), 1)?;

    let dispatcher = AgentDispatcher::new(&vault);
    let AgentDispatchOutcome::Dispatched(status) = dispatch_custom(&dispatcher, fork_id, None, 10)?
    else {
        panic!("expected fresh dispatch");
    };
    let actor = agent_dispatch_actor(&status.input);
    assert_eq!(actor.entity_ref(), fork_id);

    let subject = test_id(0x49);
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, t(1), 1, b"subject")?;
    let claim_id = test_id(0x4A);
    let envelope = WriteEnvelope::new(
        actor,
        crate::claim::ClaimSource::UserStated,
        WriteProvenance::new(Value::from("dispatched herald run"))?,
        crate::claim::ClaimApprovalStatus::Proposed,
    );
    vault
        .batch()
        .claim_candidate(
            &claim_id,
            ClaimCandidate::new(
                "profile.name",
                ClaimSubject::Entity(subject),
                Value::from("Ada"),
                1.0,
            ),
            &envelope,
            t(3),
            3,
        )
        .commit()?;

    // Held to proposal with the actor-ceiling reason: the fork's Proposed
    // ceiling out-restricts the manifest's agent-class Auto grant, live.
    let pending = vault.with_write_txn(|wtxn| {
        vault
            .store
            .pending_gate_consent_in_txn(wtxn, &claim_id)?
            .ok_or(Error::CorruptedIndex("pending gate consent"))
    })?;
    assert_eq!(pending.reason_codes, vec!["gate.pending.actor_ceiling"]);
    assert_eq!(
        vault.get_claim(&claim_id)?.expect("held claim").approval,
        crate::claim::ClaimApprovalStatus::Proposed
    );
    Ok(())
}

// Security hardening F4: milestone attribution is BOUND to the dispatched
// attempt — the admission door stamps subject + agent attribution from the attempt's
// own payload (caller-supplied values are overridden), and the durable index
// refuses checkpoint claims whose stamped attribution names another agent.
#[test]
fn milestone_attribution_cannot_be_forged() -> Result<()> {
    let (_dir, vault) = open_vault();
    put_policy_manifest(&vault, 0x0F, vec![actor_ceiling_row("system", "auto")])?;

    let def_id = test_id(0x4B);
    let def = custom_agent("1.0.0");
    vault.put_agent_definition(&def_id, &def, t(1), 1)?;
    let dispatcher = AgentDispatcher::new(&vault);
    let AgentDispatchOutcome::Dispatched(status) = dispatch_custom(&dispatcher, def_id, None, 10)?
    else {
        panic!("expected fresh dispatch");
    };
    let attempt_id = status.attempt.id;

    let dreamer_actor = test_id(0x2B);
    vault.put_entity(&dreamer_actor, ENTITY_TYPE_MACHINE, t(1), 1, b"dreamer")?;
    let subject = EntityId::from_bytes(*attempt_id.as_bytes())?;
    vault.put_entity(
        &subject,
        ENTITY_TYPE_PERSON,
        t(1),
        1,
        b"agent attempt anchor",
    )?;
    // A decoy subject the forging caller supplies instead of the attempt id.
    let decoy_subject = test_id(0x2C);
    vault.put_entity(&decoy_subject, ENTITY_TYPE_PERSON, t(1), 1, b"decoy")?;

    let forged_envelope = WriteEnvelope::new(
        crate::write_envelope::WriteActor::new(dreamer_actor, EdgeActorClass::System),
        crate::claim::ClaimSource::Generated,
        WriteProvenance::new(Value::Map(vec![
            (Value::from("runner"), Value::from("dreamer")),
            (Value::from("agent"), Value::from("mallory.other.agent")),
        ]))?,
        crate::claim::ClaimApprovalStatus::Approved,
    );

    // Admission door: the started milestone arrives with FORGED attribution
    // and a decoy subject — both are overridden by the stamp.
    let started_claim_id = EntityId::now();
    let runner = DreamerRunnerStore::new(&vault);
    let DreamerAdmissionOutcome::Admitted(admitted) = runner.admit_next(AdmitDreamerAttempt {
        lease_owner: "agent-worker".to_owned(),
        now: 20,
        budget_id: "wake".to_owned(),
        budget_total_units: 10,
        reserve_units: 2,
        started_milestone: Some(DreamerMilestoneClaim {
            claim_id: started_claim_id,
            subject: decoy_subject,
            kind: DreamerMilestoneKind::Started,
            envelope: forged_envelope.clone(),
            occurred: t(20),
            learned_at: 20,
        }),
    })?
    else {
        panic!("expected admission");
    };
    assert_eq!(admitted.status.attempt.id, attempt_id);

    let stored = vault.get_claim(&started_claim_id)?.expect("started claim");
    assert_eq!(
        stored.subject,
        ClaimSubject::Entity(subject),
        "milestone subject is stamped to the attempt id, not the caller's decoy"
    );
    let Some(Value::Map(evidence)) = stored.evidence else {
        panic!("started claim carries envelope evidence");
    };
    let provenance = evidence
        .iter()
        .find(|(key, _)| key.as_str() == Some("provenance"))
        .map(|(_, value)| value)
        .expect("envelope provenance in evidence");
    let Value::Map(provenance) = provenance else {
        panic!("envelope provenance is a map");
    };
    assert!(
        provenance.iter().any(|(key, value)| {
            key.as_str() == Some(AGENT_DISPATCH_MILESTONE_AGENT_KEY)
                && value.as_str() == Some(status.input.definition.agent_id.as_str())
        }),
        "attribution is stamped from the dispatched payload, not the caller"
    );
    assert!(
        !provenance
            .iter()
            .any(|(_, value)| value.as_str() == Some("mallory.other.agent")),
        "the forged attribution value is gone"
    );
    assert_eq!(
        runner
            .latest_durable_milestone(attempt_id)?
            .expect("started milestone indexed")
            .kind,
        DreamerMilestoneKind::Started
    );

    // Ordinary-claim door: a forged checkpoint commits as a claim but never
    // enters the durable index.
    let forged_checkpoint_id = EntityId::now();
    vault
        .batch()
        .claim_candidate(
            &forged_checkpoint_id,
            ClaimCandidate::new(
                DREAMER_MILESTONE_PREDICATE,
                ClaimSubject::Entity(subject),
                dreamer_milestone_value(attempt_id, DreamerMilestoneKind::CheckpointReached, 30),
                1.0,
            ),
            &forged_envelope,
            t(30),
            30,
        )
        .commit()?;
    assert_eq!(
        runner
            .latest_durable_milestone(attempt_id)?
            .expect("milestone unchanged")
            .kind,
        DreamerMilestoneKind::Started,
        "a forged checkpoint must not become durable-index visible"
    );

    // A correctly-attributed checkpoint indexes normally.
    let bound_envelope = WriteEnvelope::new(
        crate::write_envelope::WriteActor::new(dreamer_actor, EdgeActorClass::System),
        crate::claim::ClaimSource::Generated,
        WriteProvenance::new(Value::Map(vec![
            (Value::from("runner"), Value::from("dreamer")),
            (
                Value::from(AGENT_DISPATCH_MILESTONE_AGENT_KEY),
                Value::from(status.input.definition.agent_id.as_str()),
            ),
        ]))?,
        crate::claim::ClaimApprovalStatus::Approved,
    );
    let checkpoint_id = EntityId::now();
    vault
        .batch()
        .claim_candidate(
            &checkpoint_id,
            ClaimCandidate::new(
                DREAMER_MILESTONE_PREDICATE,
                ClaimSubject::Entity(subject),
                dreamer_milestone_value(attempt_id, DreamerMilestoneKind::CheckpointReached, 40),
                1.0,
            ),
            &bound_envelope,
            t(40),
            40,
        )
        .commit()?;
    assert_eq!(
        runner
            .latest_durable_milestone(attempt_id)?
            .expect("bound checkpoint indexed")
            .kind,
        DreamerMilestoneKind::CheckpointReached
    );
    Ok(())
}

/// A system/Dreamer bookkeeping envelope with the given agent attribution.
fn dreamer_envelope(actor: EntityId, agent_id: &str) -> Result<WriteEnvelope> {
    Ok(WriteEnvelope::new(
        crate::write_envelope::WriteActor::new(actor, EdgeActorClass::System),
        crate::claim::ClaimSource::Generated,
        WriteProvenance::new(Value::Map(vec![
            (Value::from("runner"), Value::from("dreamer")),
            (
                Value::from(AGENT_DISPATCH_MILESTONE_AGENT_KEY),
                Value::from(agent_id),
            ),
        ]))?,
        crate::claim::ClaimApprovalStatus::Approved,
    ))
}

fn write_milestone_claim(
    vault: &Vault,
    claim_id: &EntityId,
    subject: EntityId,
    attempt_id: crate::attempt_queue::AttemptId,
    kind: DreamerMilestoneKind,
    at: u64,
    envelope: &WriteEnvelope,
) -> Result<()> {
    vault
        .batch()
        .claim_candidate(
            claim_id,
            ClaimCandidate::new(
                DREAMER_MILESTONE_PREDICATE,
                ClaimSubject::Entity(subject),
                dreamer_milestone_value(attempt_id, kind, at),
                1.0,
            ),
            envelope,
            t(at),
            at,
        )
        .commit()
}

// Security hardening F4 round 2: EVERY milestone kind is verified at the
// durable-index door, and all three bindings are enforced — subject, envelope
// actor, and attribution. A forged claim of any kind commits as an ordinary
// claim but never becomes resume-visible.
#[test]
fn milestone_forgery_rejected_for_every_kind_and_binding() -> Result<()> {
    let (_dir, vault) = open_vault();
    put_policy_manifest(
        &vault,
        0x10,
        vec![
            actor_ceiling_row("system", "auto"),
            actor_ceiling_row("agent", "auto"),
        ],
    )?;

    let def_id = test_id(0x4C);
    let def = custom_agent("1.0.0");
    vault.put_agent_definition(&def_id, &def, t(1), 1)?;
    let dispatcher = AgentDispatcher::new(&vault);
    let AgentDispatchOutcome::Dispatched(status) = dispatch_custom(&dispatcher, def_id, None, 10)?
    else {
        panic!("expected fresh dispatch");
    };
    let attempt_id = status.attempt.id;
    let agent_id = status.input.definition.agent_id;

    let dreamer_actor = test_id(0x2D);
    vault.put_entity(&dreamer_actor, ENTITY_TYPE_MACHINE, t(1), 1, b"dreamer")?;
    let subject = EntityId::from_bytes(*attempt_id.as_bytes())?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, t(1), 1, b"attempt anchor")?;
    let decoy_subject = test_id(0x2E);
    vault.put_entity(&decoy_subject, ENTITY_TYPE_PERSON, t(1), 1, b"decoy")?;
    // An Auto-ceiling agent actor, so an agent-envelope milestone still lands
    // Approved and the envelope-actor binding is what rejects it. The gate
    // reads the ceiling off this stored row (SEAM-GATE-PRESET-NEUTRALIZATION),
    // so the fixture is a plain definition rather than a preset fork.
    let auto_agent = test_id(0x2F);
    let mut auto_def = custom_agent("1.0.0");
    auto_def.agent_id = "oneiron.agent.auto".to_owned();
    auto_def.ceiling = AgentCeiling::Auto;
    vault.put_agent_definition(&auto_agent, &auto_def, t(1), 1)?;

    let bound = dreamer_envelope(dreamer_actor, &agent_id)?;
    let runner = DreamerRunnerStore::new(&vault);

    // Seed one legitimately bound milestone so a rejected forgery is visible
    // as "the durable milestone did not move".
    write_milestone_claim(
        &vault,
        &EntityId::now(),
        subject,
        attempt_id,
        DreamerMilestoneKind::Started,
        20,
        &bound,
    )?;
    assert_eq!(
        runner
            .latest_durable_milestone(attempt_id)?
            .expect("started")
            .kind,
        DreamerMilestoneKind::Started
    );

    // (a) Attribution forgery, on EVERY milestone kind — not just the
    // admission/started kind.
    let forged_attribution = dreamer_envelope(dreamer_actor, "mallory.other.agent")?;
    for (offset, kind) in [
        DreamerMilestoneKind::CheckpointReached,
        DreamerMilestoneKind::Done,
        DreamerMilestoneKind::Failed,
    ]
    .into_iter()
    .enumerate()
    {
        let at = 30 + u64::try_from(offset).expect("small offset");
        let claim_id = EntityId::now();
        write_milestone_claim(
            &vault,
            &claim_id,
            subject,
            attempt_id,
            kind,
            at,
            &forged_attribution,
        )?;
        assert!(
            vault.get_claim(&claim_id)?.is_some(),
            "the forged claim still commits as an ordinary claim"
        );
        assert_eq!(
            runner
                .latest_durable_milestone(attempt_id)?
                .expect("milestone")
                .kind,
            DreamerMilestoneKind::Started,
            "a forged {kind:?} milestone must never become resume-visible"
        );
    }

    // (b) Subject forgery: correct attribution, wrong subject.
    write_milestone_claim(
        &vault,
        &EntityId::now(),
        decoy_subject,
        attempt_id,
        DreamerMilestoneKind::Done,
        40,
        &bound,
    )?;
    assert_eq!(
        runner
            .latest_durable_milestone(attempt_id)?
            .expect("milestone")
            .kind,
        DreamerMilestoneKind::Started,
        "a milestone whose subject is not the attempt id must not index"
    );

    // (c) Envelope-actor forgery: correct attribution and subject, but the
    // claim rides the AGENT's own envelope rather than the Dreamer's.
    let agent_envelope = WriteEnvelope::new(
        crate::write_envelope::WriteActor::new(auto_agent, EdgeActorClass::Agent),
        crate::claim::ClaimSource::UserStated,
        WriteProvenance::new(Value::Map(vec![
            (Value::from("runner"), Value::from("dreamer")),
            (
                Value::from(AGENT_DISPATCH_MILESTONE_AGENT_KEY),
                Value::from(agent_id.as_str()),
            ),
        ]))?,
        crate::claim::ClaimApprovalStatus::Approved,
    );
    let agent_claim = EntityId::now();
    write_milestone_claim(
        &vault,
        &agent_claim,
        subject,
        attempt_id,
        DreamerMilestoneKind::Done,
        50,
        &agent_envelope,
    )?;
    assert_eq!(
        vault.get_claim(&agent_claim)?.expect("claim").approval,
        crate::claim::ClaimApprovalStatus::Approved,
        "the agent-envelope claim is Approved — only the envelope binding rejects it"
    );
    assert_eq!(
        runner
            .latest_durable_milestone(attempt_id)?
            .expect("milestone")
            .kind,
        DreamerMilestoneKind::Started,
        "an agent-envelope milestone is not runner bookkeeping and must not index"
    );

    // Control: a fully bound later milestone still advances the frontier.
    write_milestone_claim(
        &vault,
        &EntityId::now(),
        subject,
        attempt_id,
        DreamerMilestoneKind::CheckpointReached,
        60,
        &bound,
    )?;
    assert_eq!(
        runner
            .latest_durable_milestone(attempt_id)?
            .expect("milestone")
            .kind,
        DreamerMilestoneKind::CheckpointReached
    );
    Ok(())
}

// Security hardening F4 round 2: the one-time index BACKFILL is an indexing
// door and runs the same binding check — a forgery written before the index
// existed must not be admitted by the rebuild.
#[test]
fn milestone_forgery_rejected_through_backfill() -> Result<()> {
    let (_dir, vault) = open_vault();
    put_policy_manifest(&vault, 0x14, vec![actor_ceiling_row("system", "auto")])?;

    let def_id = test_id(0x4D);
    vault.put_agent_definition(&def_id, &custom_agent("1.0.0"), t(1), 1)?;
    let dispatcher = AgentDispatcher::new(&vault);
    let AgentDispatchOutcome::Dispatched(status) = dispatch_custom(&dispatcher, def_id, None, 10)?
    else {
        panic!("expected fresh dispatch");
    };
    let attempt_id = status.attempt.id;
    let agent_id = status.input.definition.agent_id;

    let dreamer_actor = test_id(0x3A);
    vault.put_entity(&dreamer_actor, ENTITY_TYPE_MACHINE, t(1), 1, b"dreamer")?;
    let subject = EntityId::from_bytes(*attempt_id.as_bytes())?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, t(1), 1, b"attempt anchor")?;

    // Both claims are written BEFORE any read initializes the index, so the
    // backfill scan — not the put hook — is what must reject the forgery.
    write_milestone_claim(
        &vault,
        &EntityId::now(),
        subject,
        attempt_id,
        DreamerMilestoneKind::Started,
        20,
        &dreamer_envelope(dreamer_actor, &agent_id)?,
    )?;
    write_milestone_claim(
        &vault,
        &EntityId::now(),
        subject,
        attempt_id,
        DreamerMilestoneKind::Done,
        30,
        &dreamer_envelope(dreamer_actor, "mallory.other.agent")?,
    )?;

    // First read triggers the backfill rebuild.
    let runner = DreamerRunnerStore::new(&vault);
    assert_eq!(
        runner
            .latest_durable_milestone(attempt_id)?
            .expect("milestone")
            .kind,
        DreamerMilestoneKind::Started,
        "backfill must not admit the forged Done milestone"
    );
    Ok(())
}

// Security hardening F4 round 2: a milestone claim naming an attempt with NO local
// queue row (the cross-device replay shape — queue rows are private per-device
// runner state and never sync) fails closed: it commits, but never indexes.
#[test]
fn milestone_with_absent_attempt_row_does_not_index() -> Result<()> {
    let (_dir, vault) = open_vault();
    put_policy_manifest(&vault, 0x12, vec![actor_ceiling_row("system", "auto")])?;

    let dreamer_actor = test_id(0x3B);
    vault.put_entity(&dreamer_actor, ENTITY_TYPE_MACHINE, t(1), 1, b"dreamer")?;
    // An attempt id that exists on some other device only.
    let foreign_attempt = crate::attempt_queue::AttemptId::now();
    let subject = EntityId::from_bytes(*foreign_attempt.as_bytes())?;
    vault.put_entity(
        &subject,
        ENTITY_TYPE_PERSON,
        t(1),
        1,
        b"foreign attempt anchor",
    )?;

    let claim_id = EntityId::now();
    write_milestone_claim(
        &vault,
        &claim_id,
        subject,
        foreign_attempt,
        DreamerMilestoneKind::Done,
        20,
        &dreamer_envelope(dreamer_actor, "oneiron.agent.custom")?,
    )?;

    assert!(
        vault.get_claim(&claim_id)?.is_some(),
        "the replicated claim still commits"
    );
    let runner = DreamerRunnerStore::new(&vault);
    assert_eq!(
        runner.latest_durable_milestone(foreign_attempt)?,
        None,
        "a milestone with no local attempt row must not decide this device's resume point"
    );
    Ok(())
}

// Security hardening R2: the envelope binding is RESOLVED from the writer's
// stored entity, not trusted from the stamped class byte. A milestone whose
// writer entity is deleted after the write no longer resolves to a stored
// MACHINE (system) actor, so it drops out of the durable index on the next
// rebuild — the stale System class byte on the record cannot keep it visible.
#[test]
fn milestone_writer_resolved_from_storage_not_class_byte() -> Result<()> {
    let (_dir, vault) = open_vault();
    put_policy_manifest(&vault, 0x13, vec![actor_ceiling_row("system", "auto")])?;

    let def_id = test_id(0x4E);
    vault.put_agent_definition(&def_id, &custom_agent("1.0.0"), t(1), 1)?;
    let dispatcher = AgentDispatcher::new(&vault);
    let AgentDispatchOutcome::Dispatched(status) = dispatch_custom(&dispatcher, def_id, None, 10)?
    else {
        panic!("expected fresh dispatch");
    };
    let attempt_id = status.attempt.id;
    let agent_id = status.input.definition.agent_id;

    let dreamer_actor = test_id(0x3C);
    vault.put_entity(&dreamer_actor, ENTITY_TYPE_MACHINE, t(1), 1, b"dreamer")?;
    let subject = EntityId::from_bytes(*attempt_id.as_bytes())?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, t(1), 1, b"attempt anchor")?;

    // A fully bound milestone: it indexes while its MACHINE writer exists.
    write_milestone_claim(
        &vault,
        &EntityId::now(),
        subject,
        attempt_id,
        DreamerMilestoneKind::CheckpointReached,
        20,
        &dreamer_envelope(dreamer_actor, &agent_id)?,
    )?;
    let runner = DreamerRunnerStore::new(&vault);
    assert_eq!(
        runner
            .latest_durable_milestone(attempt_id)?
            .expect("milestone indexed while writer exists")
            .kind,
        DreamerMilestoneKind::CheckpointReached
    );

    // Delete the writer entity and force an index rebuild. The claim's stamped
    // class byte still reads System, but the writer no longer resolves to a
    // stored MACHINE, so resolve-from-storage drops it.
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .entities
            .delete(wtxn, dreamer_actor.as_bytes())?;
        vault
            .store
            .vault_meta
            .delete(wtxn, b"dreamer.milestone_index.v1.backfilled")?;
        Ok(())
    })?;
    assert_eq!(
        runner.latest_durable_milestone(attempt_id)?,
        None,
        "a milestone whose writer entity no longer exists must not stay indexed"
    );
    Ok(())
}

// ONE-1890 done-means `legacy_system_dispatch_payload_recovers`: a persisted
// pre-1890 `target="system"` payload decodes to the PINNED seeded row id, its
// status/kill paths keep working, and encode of any current input never emits
// `target="system"` again.
#[test]
fn legacy_system_dispatch_payload_recovers() -> Result<()> {
    let (_dir, vault) = open_vault();

    // Every legacy preset string maps to its pinned row.
    for logical_id in [
        "sys.scout",
        "sys.keeper",
        "sys.creative",
        "sys.herald",
        "sys.guide",
        "sys.default",
    ] {
        let (pinned_id, definition) = seeded_row(&vault, logical_id);
        let decoded = decode_agent_dispatch_input(&legacy_system_payload(logical_id, &definition))?;
        assert_eq!(decoded.target, AgentDispatchTarget::Custom(pinned_id));
        // The embedded snapshot decodes unchanged, never preset-derived.
        assert_eq!(decoded.definition, definition);
        // The actor identity is the pinned row id, as before.
        assert_eq!(agent_dispatch_actor(&decoded).entity_ref(), pinned_id);
    }

    // The durable status + kill paths recover through that one arm: enqueue a
    // raw legacy payload and drive both.
    let (scout_id, scout) = seeded_row(&vault, "sys.scout");
    let queue = AttemptQueue::new(&vault);
    let crate::attempt_queue::EnqueueOutcome::Enqueued(legacy_parent) =
        queue.enqueue(crate::attempt_queue::EnqueueAttempt {
            kind: crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND.to_owned(),
            payload: crate::dreamer_runner::encode_dreamer_attempt_payload(
                &crate::dreamer_runner::DreamerAttemptPayload {
                    attempt_type: AGENT_DISPATCH_ATTEMPT_TYPE.to_owned(),
                    input: legacy_system_payload("sys.scout", &scout),
                    parent_attempt: None,
                },
            )?,
            dedupe_key: None,
            run_id: None,
            now: 1,
        })?
    else {
        panic!("expected a fresh legacy parent attempt");
    };
    let crate::attempt_queue::EnqueueOutcome::Enqueued(legacy_child) =
        queue.enqueue(crate::attempt_queue::EnqueueAttempt {
            kind: crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND.to_owned(),
            payload: crate::dreamer_runner::encode_dreamer_attempt_payload(
                &crate::dreamer_runner::DreamerAttemptPayload {
                    attempt_type: AGENT_DISPATCH_ATTEMPT_TYPE.to_owned(),
                    input: legacy_system_payload("sys.keeper", &scout),
                    parent_attempt: Some(legacy_parent.id),
                },
            )?,
            dedupe_key: None,
            run_id: None,
            now: 2,
        })?
    else {
        panic!("expected a fresh legacy child attempt");
    };
    // Status attribution still resolves off the legacy payload.
    assert_eq!(
        agent_dispatch_payload_agent_id(&decode_dreamer_attempt_payload(
            &queue.get(legacy_child.id)?.expect("child row").payload
        )?)
        .as_deref(),
        Some(scout.agent_id.as_str())
    );
    let dispatcher = AgentDispatcher::new(&vault);
    assert_eq!(
        dispatcher.kill_spawn(&legacy_child.id, &legacy_parent.id, 3)?,
        KillOutcome::Killed
    );
    assert_eq!(
        queue.get(legacy_child.id)?.expect("child row").state,
        AttemptState::Cancelled
    );

    // Encode of a current input never emits target="system".
    let encoded = encode_agent_dispatch_input(&AgentDispatchInput::frozen(
        AgentDispatchTarget::Custom(scout_id),
        scout,
    ))?;
    let Value::Map(entries) = &encoded else {
        panic!("encoded dispatch input is a map");
    };
    assert!(
        entries.iter().all(|(key, value)| {
            key.as_str() != Some("target") || value.as_str() == Some("custom")
        }),
        "encode must never emit target=system again"
    );
    assert!(
        entries
            .iter()
            .all(|(key, _)| key.as_str() != Some("preset")),
        "encode must never emit a preset key again"
    );
    Ok(())
}

/// ONE-1700: the TASK-backlinked entry point queues the SAME dispatch row as
/// the public door — same payload codec, same parent, same run-tree record —
/// and additionally stamps `AttemptRecord.task_ref`.
#[test]
fn dispatch_for_task_carries_the_backlink_and_nothing_else_changes() -> Result<()> {
    let (_dir, vault) = open_vault();
    let def_id = test_id(0x2D);
    vault.put_agent_definition(&def_id, &custom_agent("1.0.0"), t(1), 1)?;
    let task_ref = test_id(0x2E);
    let dispatcher = AgentDispatcher::new(&vault);

    let backlinked = vault.with_write_txn(|wtxn| {
        dispatcher.dispatch_for_task_in_txn(
            wtxn,
            task_ref,
            DispatchAgent {
                target: AgentDispatchTarget::Custom(def_id),
                parent_attempt: None,
                dedupe_key: Some("route-backlink".to_owned()),
                run_id: Some("run-backlink".to_owned()),
                now: 10,
            },
        )
    })?;
    let plain = dispatcher.dispatch(DispatchAgent {
        target: AgentDispatchTarget::Custom(def_id),
        parent_attempt: None,
        dedupe_key: Some("route-plain".to_owned()),
        run_id: Some("run-plain".to_owned()),
        now: 11,
    })?;

    let (AgentDispatchOutcome::Dispatched(backlinked) | AgentDispatchOutcome::Existing(backlinked)) =
        backlinked;
    let (AgentDispatchOutcome::Dispatched(plain) | AgentDispatchOutcome::Existing(plain)) = plain;

    assert_eq!(
        backlinked.attempt.task_ref.as_deref(),
        Some(task_ref.to_hex().as_str())
    );
    assert_eq!(plain.attempt.task_ref, None);
    assert_eq!(backlinked.attempt.kind, plain.attempt.kind);
    assert_eq!(backlinked.input, plain.input);
    assert_eq!(backlinked.attempt.run_id.as_deref(), Some("run-backlink"));
    assert_eq!(
        decode_dreamer_attempt_payload(&backlinked.attempt.payload)?.attempt_type,
        AGENT_DISPATCH_ATTEMPT_TYPE
    );
    // The run-tree row is written for the backlinked dispatch too.
    assert_eq!(
        crate::run_tree::RunTreeAdapter::new(&vault)
            .read_run("run-backlink")?
            .roots
            .len(),
        1
    );
    Ok(())
}

/// A backlinked dispatch that rolls its transaction back leaves NO attempt
/// behind: the TASK and its realizing dispatch are one commit.
#[test]
fn a_rolled_back_dispatch_for_task_queues_nothing() -> Result<()> {
    let (_dir, vault) = open_vault();
    let def_id = test_id(0x2F);
    vault.put_agent_definition(&def_id, &custom_agent("1.0.0"), t(1), 1)?;
    let task_ref = test_id(0x30);
    let dispatcher = AgentDispatcher::new(&vault);

    let rolled_back: crate::Result<()> = vault.with_write_txn(|wtxn| {
        dispatcher.dispatch_for_task_in_txn(
            wtxn,
            task_ref,
            DispatchAgent {
                target: AgentDispatchTarget::Custom(def_id),
                parent_attempt: None,
                dedupe_key: Some("route-rollback".to_owned()),
                run_id: None,
                now: 10,
            },
        )?;
        Err(Error::InvariantViolation("deliberate rollback"))
    });

    assert_eq!(usize::from(rolled_back.is_err()), 1);
    assert_eq!(
        AttemptQueue::new(&vault)
            .list()?
            .iter()
            .filter(|record| record.task_ref.as_deref() == Some(task_ref.to_hex().as_str()))
            .count(),
        0
    );
    Ok(())
}

// ════════════════════════════════════════════════════════════════════════
// ONE-1709 — the seeded team lead, live recursive attenuation, and the
//            load-bearing depth budget.
// ════════════════════════════════════════════════════════════════════════

/// The seeded team lead's stable logical id. A DATA lookup key, not a preset
/// enum: `sys.team_lead` names a row in the canonical manifest.
const TEAM_LEAD_LOGICAL_ID: &str = "sys.team_lead";

fn dispatched(outcome: AgentDispatchOutcome) -> AgentDispatchStatus {
    let AgentDispatchOutcome::Dispatched(status) = outcome else {
        panic!("expected a fresh dispatch");
    };
    status
}

/// A stored custom row with the requested ceiling.
fn put_row(vault: &Vault, seed: u8, agent_id: &str, ceiling: AgentCeiling) -> Result<EntityId> {
    let id = test_id(seed);
    let mut definition = custom_agent("1.0.0");
    definition.agent_id = agent_id.to_owned();
    definition.ceiling = ceiling;
    vault.put_agent_definition(&id, &definition, t(1), 1)?;
    Ok(id)
}

fn spawn_child(
    dispatcher: &AgentDispatcher<'_>,
    target: EntityId,
    parent: AttemptId,
    now: u64,
) -> Result<AgentDispatchStatus> {
    dispatcher
        .dispatch(DispatchAgent {
            target: AgentDispatchTarget::Custom(target),
            parent_attempt: Some(parent),
            dedupe_key: None,
            run_id: Some("run-1709".to_owned()),
            now,
        })
        .map(dispatched)
}

/// The ceiling of the row a dispatch actually NAMED, read back live from
/// storage — never the frozen payload snapshot, which carries no authority.
fn dispatched_row_ceiling(vault: &Vault, status: &AgentDispatchStatus) -> AgentCeiling {
    let AgentDispatchTarget::Custom(id) = status.input.target;
    vault
        .get_agent_definition(&id)
        .expect("read the dispatched row")
        .expect("the dispatched row exists")
        .ceiling
}

fn persisted_depth(vault: &Vault, attempt: AttemptId) -> Option<u8> {
    let record = AttemptQueue::new(vault)
        .get(attempt)
        .expect("read attempt")
        .expect("attempt exists");
    let payload = decode_dreamer_attempt_payload(&record.payload).expect("decode payload");
    decode_agent_dispatch_input(&payload.input)
        .expect("decode dispatch input")
        .depth_remaining
}

// ── seeded row ──────────────────────────────────────────────────────────

/// A fresh vault carries exactly ONE `sys.team_lead` row, and reopening the
/// same directory neither duplicates nor rewrites it.
#[test]
fn team_lead_row_is_seeded_once_and_reopen_is_idempotent() -> Result<()> {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device())?;

    let rows: Vec<EntityId> = vault
        .entities_by_type(crate::registry::ENTITY_TYPE_AGENT_DEF)?
        .into_iter()
        .filter(|id| {
            vault
                .get_agent_definition(id)
                .ok()
                .flatten()
                .and_then(|definition| definition.logical_id)
                .as_deref()
                == Some(TEAM_LEAD_LOGICAL_ID)
        })
        .collect();
    assert_eq!(rows.len(), 1);

    let (id, definition) = seeded_row(&vault, TEAM_LEAD_LOGICAL_ID);
    assert_eq!(rows[0], id);
    assert_eq!(definition.agent_id, TEAM_LEAD_LOGICAL_ID);
    // The row's DATA pins the maximum ceiling and the instruction text.
    assert_eq!(definition.ceiling, AgentCeiling::Auto);
    assert_eq!(usize::from(definition.instructions.is_some()), 1);
    assert!(definition.enabled);
    // Narrow composition: no connector, skill, or MCP dependency at all.
    assert_eq!(definition.connectors.len(), 0);
    assert_eq!(definition.skills.len(), 0);
    assert_eq!(definition.code_mode_mcps.len(), 0);

    drop(vault);
    let reopened = Vault::open(dir.path(), VaultConfig::device())?;
    let rows_after = reopened
        .entities_by_type(crate::registry::ENTITY_TYPE_AGENT_DEF)?
        .into_iter()
        .filter(|id| {
            reopened
                .get_agent_definition(id)
                .ok()
                .flatten()
                .and_then(|definition| definition.logical_id)
                .as_deref()
                == Some(TEAM_LEAD_LOGICAL_ID)
        })
        .count();
    assert_eq!(rows_after, 1);
    assert_eq!(seeded_row(&reopened, TEAM_LEAD_LOGICAL_ID).1, definition);
    Ok(())
}

/// The seeded lead is ordinary data: toggleable and forkable through the same
/// APIs a user-created definition uses, with no preset-specific door.
#[test]
fn team_lead_row_is_toggleable_and_forkable_like_any_definition() -> Result<()> {
    let (_dir, vault) = open_vault();
    let (id, definition) = seeded_row(&vault, TEAM_LEAD_LOGICAL_ID);
    let dispatcher = AgentDispatcher::new(&vault);

    // Fork: an ordinary row that points back at the seeded parent.
    let fork_id = test_id(0x71);
    let mut fork = definition.clone();
    fork.logical_id = None;
    fork.forked_from = Some(id);
    fork.ceiling = AgentCeiling::Proposed;
    vault.put_agent_definition(&fork_id, &fork, t(1), 1)?;
    let stored_fork = vault.get_agent_definition(&fork_id)?.expect("fork exists");
    assert_eq!(stored_fork.forked_from, Some(id));
    assert_eq!(stored_fork.ceiling, AgentCeiling::Proposed);
    assert_eq!(
        dispatched(dispatcher.dispatch(DispatchAgent {
            target: AgentDispatchTarget::Custom(fork_id),
            parent_attempt: None,
            dedupe_key: None,
            run_id: None,
            now: 2,
        })?)
        .input
        .definition
        .agent_id,
        TEAM_LEAD_LOGICAL_ID
    );

    // Toggle off through the ordinary update door; dispatch refuses after it.
    let mut disabled = definition;
    disabled.enabled = false;
    disabled.version = "2".to_owned();
    vault.update_agent_definition(&id, &disabled, t(3), 3)?;
    let error = dispatcher
        .dispatch(DispatchAgent {
            target: AgentDispatchTarget::Custom(id),
            parent_attempt: None,
            dedupe_key: None,
            run_id: None,
            now: 4,
        })
        .expect_err("a disabled row is not dispatchable");
    assert_eq!(error.kind(), ErrorKind::AgentDefinitionDisabled);
    Ok(())
}

/// The engine ships NO compiled team-lead preset, pinned actor id, or English
/// instruction paragraph: the row's prose lives in the seed manifest, which is
/// data a host can replace, localize, or fork.
#[test]
fn no_compiled_preset_or_instruction_paragraph_exists_in_rust() {
    let rust_sources = [
        include_str!("../agent_dispatch.rs"),
        include_str!("../context_projection.rs"),
        include_str!("../context_board/agents.rs"),
    ];
    let banned = [
        "SystemAgentPreset",
        "TeamLeadPreset",
        // The seeded row's instruction paragraph, sampled: it must exist only
        // in `data/system_agent_definitions.v1.json`.
        "Plan in code mode",
        "spawn bounded workers",
    ];
    let hits = rust_sources
        .iter()
        .flat_map(|source| {
            banned
                .iter()
                .filter(move |needle| source.contains(**needle))
        })
        .count();
    assert_eq!(hits, 0);

    let manifest = include_str!("../data/system_agent_definitions.v1.json");
    assert!(manifest.contains("sys.team_lead"));
    assert!(manifest.contains("Plan in code mode"));
}

// ── live recursive attenuation ──────────────────────────────────────────

/// Parent Proposed + requested child Auto dispatches an attenuated Proposed
/// row; parent Auto + child Proposed stays Proposed; equal ceilings never
/// widen and never fork.
#[test]
fn parented_dispatch_clamps_the_child_to_the_live_parent_ceiling() -> Result<()> {
    let (_dir, vault) = open_vault();
    let proposed_parent = put_row(&vault, 0x72, "parent.proposed", AgentCeiling::Proposed)?;
    let auto_parent = put_row(&vault, 0x73, "parent.auto", AgentCeiling::Auto)?;
    let auto_child = put_row(&vault, 0x74, "child.auto", AgentCeiling::Auto)?;
    let proposed_child = put_row(&vault, 0x75, "child.proposed", AgentCeiling::Proposed)?;
    let dispatcher = AgentDispatcher::new(&vault);

    let proposed_root = dispatched(dispatcher.dispatch(DispatchAgent {
        target: AgentDispatchTarget::Custom(proposed_parent),
        parent_attempt: None,
        dedupe_key: None,
        run_id: Some("run-1709".to_owned()),
        now: 1,
    })?);
    let auto_root = dispatched(dispatcher.dispatch(DispatchAgent {
        target: AgentDispatchTarget::Custom(auto_parent),
        parent_attempt: None,
        dedupe_key: None,
        run_id: Some("run-1709".to_owned()),
        now: 2,
    })?);

    // WIDER request under a Proposed parent → attenuated fork, not the source.
    let clamped = spawn_child(&dispatcher, auto_child, proposed_root.attempt.id, 3)?;
    assert_ne!(
        clamped.input.target,
        AgentDispatchTarget::Custom(auto_child)
    );
    assert_eq!(
        dispatched_row_ceiling(&vault, &clamped),
        AgentCeiling::Proposed
    );
    let AgentDispatchTarget::Custom(fork_id) = clamped.input.target;
    let fork = vault.get_agent_definition(&fork_id)?.expect("fork exists");
    assert_eq!(fork.forked_from, Some(auto_child));
    assert_eq!(fork.logical_id, None);
    // The requested row is untouched: attenuation forks, it never rewrites.
    assert_eq!(
        vault
            .get_agent_definition(&auto_child)?
            .expect("source")
            .ceiling,
        AgentCeiling::Auto
    );

    // Narrower child under a wider parent keeps its own narrower ceiling.
    let narrower = spawn_child(&dispatcher, proposed_child, auto_root.attempt.id, 4)?;
    assert_eq!(
        narrower.input.target,
        AgentDispatchTarget::Custom(proposed_child)
    );
    assert_eq!(
        dispatched_row_ceiling(&vault, &narrower),
        AgentCeiling::Proposed
    );

    // Equal ceilings: dispatched as-is, with no fork minted.
    let equal = spawn_child(&dispatcher, auto_child, auto_root.attempt.id, 5)?;
    assert_eq!(equal.input.target, AgentDispatchTarget::Custom(auto_child));
    assert_eq!(dispatched_row_ceiling(&vault, &equal), AgentCeiling::Auto);

    assert_eq!(
        restrict_agent_ceiling(AgentCeiling::Auto, AgentCeiling::Proposed),
        AgentCeiling::Proposed
    );
    assert_eq!(
        restrict_agent_ceiling(AgentCeiling::Proposed, AgentCeiling::Auto),
        AgentCeiling::Proposed
    );
    assert_eq!(
        restrict_agent_ceiling(AgentCeiling::Auto, AgentCeiling::Auto),
        AgentCeiling::Auto
    );
    Ok(())
}

/// Attenuation reads the STORED rows. Narrowing the parent's row after it was
/// dispatched — leaving its frozen snapshot wide — still clamps the child.
#[test]
fn attenuation_reads_live_rows_not_payload_snapshots() -> Result<()> {
    let (_dir, vault) = open_vault();
    let parent_id = put_row(&vault, 0x76, "parent.live", AgentCeiling::Auto)?;
    let child_id = put_row(&vault, 0x77, "child.auto", AgentCeiling::Auto)?;
    let dispatcher = AgentDispatcher::new(&vault);

    let parent = dispatched(dispatcher.dispatch(DispatchAgent {
        target: AgentDispatchTarget::Custom(parent_id),
        parent_attempt: None,
        dedupe_key: None,
        run_id: Some("run-1709".to_owned()),
        now: 1,
    })?);
    // The FROZEN snapshot says Auto and keeps saying Auto — it is not authority.
    assert_eq!(parent.input.definition.ceiling, AgentCeiling::Auto);

    let mut narrowed = vault.get_agent_definition(&parent_id)?.expect("parent row");
    narrowed.ceiling = AgentCeiling::Proposed;
    narrowed.version = "2.0.0".to_owned();
    vault.update_agent_definition(&parent_id, &narrowed, t(2), 2)?;

    let child = spawn_child(&dispatcher, child_id, parent.attempt.id, 3)?;

    assert_eq!(
        dispatched_row_ceiling(&vault, &child),
        AgentCeiling::Proposed
    );
    assert_ne!(child.input.target, AgentDispatchTarget::Custom(child_id));
    assert_eq!(
        persisted_depth(&vault, parent.attempt.id),
        Some(AGENT_DISPATCH_ROOT_DEPTH_REMAINING)
    );
    Ok(())
}

/// A retried spawn finds its OWN fork; a foreign row squatting the fork id is
/// a typed failure, and the wider source row is never dispatched instead.
#[test]
fn fork_registration_is_idempotent_and_never_falls_back_to_the_wider_row() -> Result<()> {
    let (_dir, vault) = open_vault();
    let parent_id = put_row(&vault, 0x78, "parent.proposed", AgentCeiling::Proposed)?;
    let child_id = put_row(&vault, 0x79, "child.auto", AgentCeiling::Auto)?;
    let dispatcher = AgentDispatcher::new(&vault);
    let parent = dispatched(dispatcher.dispatch(DispatchAgent {
        target: AgentDispatchTarget::Custom(parent_id),
        parent_attempt: None,
        dedupe_key: None,
        run_id: Some("run-1709".to_owned()),
        now: 1,
    })?);

    let first = spawn_child(&dispatcher, child_id, parent.attempt.id, 2)?;
    let second = spawn_child(&dispatcher, child_id, parent.attempt.id, 3)?;
    assert_eq!(first.input.target, second.input.target);
    let AgentDispatchTarget::Custom(fork_id) = first.input.target;
    assert_eq!(
        vault
            .entities_by_type(crate::registry::ENTITY_TYPE_AGENT_DEF)?
            .iter()
            .filter(|id| **id == fork_id)
            .count(),
        1
    );

    // A foreign occupant at the deterministic fork id fails the spawn closed.
    let squatted_parent = put_row(&vault, 0x7A, "parent.squat", AgentCeiling::Proposed)?;
    let squatted_child = put_row(&vault, 0x7B, "child.squat", AgentCeiling::Auto)?;
    let squat_parent_attempt = dispatched(dispatcher.dispatch(DispatchAgent {
        target: AgentDispatchTarget::Custom(squatted_parent),
        parent_attempt: None,
        dedupe_key: None,
        run_id: Some("run-1709".to_owned()),
        now: 4,
    })?);
    let squat_fork_id = attenuated_fork_id(
        squatted_child,
        &source_content_fingerprint(
            &vault
                .get_agent_definition(&squatted_child)?
                .expect("squatted child row"),
        )?,
        squat_parent_attempt.attempt.id,
        Some("run-1709"),
    )?;
    let mut foreign = custom_agent("9.9.9");
    foreign.agent_id = "foreign.squatter".to_owned();
    foreign.ceiling = AgentCeiling::Auto;
    vault.put_agent_definition(&squat_fork_id, &foreign, t(5), 5)?;

    let failure = dispatcher
        .dispatch(DispatchAgent {
            target: AgentDispatchTarget::Custom(squatted_child),
            parent_attempt: Some(squat_parent_attempt.attempt.id),
            dedupe_key: None,
            run_id: Some("run-1709".to_owned()),
            now: 6,
        })
        .expect_err("a squatted fork id fails the spawn");
    assert_eq!(failure.kind(), ErrorKind::InvalidAgentDispatchInput);
    // Nothing was enqueued at all — no fallback to the wider source row.
    let spawned_under_squat = AttemptQueue::new(&vault)
        .list()?
        .into_iter()
        .filter(|record| {
            decode_dreamer_attempt_payload(&record.payload)
                .ok()
                .and_then(|payload| payload.parent_attempt)
                == Some(squat_parent_attempt.attempt.id)
        })
        .count();
    assert_eq!(spawned_under_squat, 0);
    Ok(())
}

/// A pre-put row at the deterministic fork id with matching ceiling +
/// forked_from but foreign composition (instructions/agent_id/provenance)
/// must fail closed — never silently reuse the squatter.
#[test]
fn attenuated_fork_reuse_rejects_matching_ceiling_and_parent_with_foreign_composition() -> Result<()>
{
    let (_dir, vault) = open_vault();
    let parent_id = put_row(&vault, 0x7C, "parent.foreign", AgentCeiling::Proposed)?;
    let child_id = put_row(&vault, 0x7D, "child.foreign", AgentCeiling::Auto)?;
    let dispatcher = AgentDispatcher::new(&vault);
    let parent = dispatched(dispatcher.dispatch(DispatchAgent {
        target: AgentDispatchTarget::Custom(parent_id),
        parent_attempt: None,
        dedupe_key: None,
        run_id: Some("run-1709".to_owned()),
        now: 1,
    })?);

    let fork_id = attenuated_fork_id(
        child_id,
        &source_content_fingerprint(&vault.get_agent_definition(&child_id)?.expect("child row"))?,
        parent.attempt.id,
        Some("run-1709"),
    )?;
    // Ceiling and forked_from match what register_attenuated_fork will build
    // (parent Proposed clamps child Auto → Proposed), but the body is foreign.
    let mut foreign = custom_agent("9.9.9");
    foreign.agent_id = "foreign.composition.squatter".to_owned();
    foreign.instructions = Some("I am not the attenuated fork body.".to_owned());
    foreign.ceiling = AgentCeiling::Proposed;
    foreign.forked_from = Some(child_id);
    foreign.provenance = Value::Map(vec![(
        Value::from("definedVia"),
        Value::from("foreign-squatter"),
    )]);
    vault.put_agent_definition(&fork_id, &foreign, t(2), 2)?;

    let failure = dispatcher
        .dispatch(DispatchAgent {
            target: AgentDispatchTarget::Custom(child_id),
            parent_attempt: Some(parent.attempt.id),
            dedupe_key: None,
            run_id: Some("run-1709".to_owned()),
            now: 3,
        })
        .expect_err("foreign composition at fork id fails closed");
    assert_eq!(failure.kind(), ErrorKind::InvalidAgentDispatchInput);
    // Nothing enqueued under that parent — no fallback to the wider source row.
    let spawned_under_parent = AttemptQueue::new(&vault)
        .list()?
        .into_iter()
        .filter(|record| {
            decode_dreamer_attempt_payload(&record.payload)
                .ok()
                .and_then(|payload| payload.parent_attempt)
                == Some(parent.attempt.id)
        })
        .count();
    assert_eq!(spawned_under_parent, 0);
    Ok(())
}

/// A facade-minted sibling TASK owned by `owner_row`, settled Completed with
/// a durable result TURN — the exact production mint/settle doors. When
/// `settle` is false the TASK stays unsettled while its result artifact
/// already exists durably (the pre-settlement window).
fn sibling_task(
    vault: &Vault,
    owner_row: EntityId,
    seed: u8,
    settle: Option<TaskTerminalDisposition>,
) -> (EntityId, EntityId) {
    // The first-party connector actor id (0xE1), constructed EXPLICITLY as
    // test_util::entity documents: it is the one actor the default policy
    // admits at Auto ceiling, so `tasks_create` mints instead of parking
    // (the precedent is task_verb tests' `own_agent`). The recorded create
    // OWNER stays `owner_row` via the spec, which is what lineage proves.
    let actor = EntityId::from_bytes([0xE1; 16]).expect("first-party actor id");
    vault
        .put_entity(&actor, ENTITY_TYPE_PERSON, t(1), 1, b"member actor")
        .expect("store member actor");
    let result_ref = test_id(seed + 1);
    vault
        .put_entity(&result_ref, ENTITY_TYPE_TURN, t(1), 1, b"member result")
        .expect("store result artifact");
    let facade = vault.memory_facade(actor, EdgeActorClass::Agent);
    let task_ref = facade
        .tasks_create(
            &TaskCreateSpec::new(Value::from("sibling task"), None, Some(owner_row), Some(1))
                .with_assignee(TaskAssignee::Peer { actor_ref: actor }),
        )
        .expect("sibling task mints")
        .task_ref
        .expect("sibling task is minted, not parked");
    if let Some(disposition) = settle {
        facade
            .land_task_result(
                task_ref,
                &TaskResultInput {
                    result_ref,
                    disposition,
                    finished_at: 2,
                },
            )
            .expect("sibling task settles");
    }
    (task_ref, result_ref)
}

/// `contextFrom` admission at dispatch: a genuinely settled sibling TASK's
/// completed result resolves; a durable-but-UNSETTLED member artifact, a
/// result from a different parent owner or a different run, and a root spawn
/// all fail closed with the typed error and enqueue nothing.
#[test]
fn context_from_requires_settled_sibling_results_with_parent_run_lineage() -> Result<()> {
    let (_dir, vault) = open_vault();
    // The legacy-test vault ships with NO policy manifest, so every facade
    // create would park at Proposed; one agent-Auto row lets the sibling
    // fixture mint through the real `tasks_create` door.
    put_policy_manifest(&vault, 0x15, vec![actor_ceiling_row("agent", "auto")])?;
    // 0xA1/0xA2 are production-pinned seed bytes (PINNED_ID_BYTES roster
    // range 0xA1..=0xA6); 0xA7/0xA8 stay inside the test-local 0xA* block.
    let lead = put_row(&vault, 0xA0, "srv.lead", AgentCeiling::Auto)?;
    let worker = put_row(&vault, 0xA7, "srv.worker", AgentCeiling::Proposed)?;
    let other_owner = put_row(&vault, 0xA8, "srv.other", AgentCeiling::Auto)?;
    let dispatcher = AgentDispatcher::new(&vault);

    let parent = dispatched(dispatcher.dispatch(DispatchAgent {
        target: AgentDispatchTarget::Custom(lead),
        parent_attempt: None,
        dedupe_key: None,
        run_id: Some("run-srv".to_owned()),
        now: 1,
    })?);
    let (sibling, _) = sibling_task(&vault, lead, 0xB0, Some(TaskTerminalDisposition::Completed));
    let (foreign, _) = sibling_task(
        &vault,
        other_owner,
        0xC0,
        Some(TaskTerminalDisposition::Completed),
    );
    let (unsettled, _) = sibling_task(&vault, lead, 0xD0, None);

    let spawn_on = |task_refs: Vec<EntityId>, run_id: Option<&str>, parent_attempt| {
        dispatcher.dispatch_with_context(
            DispatchAgent {
                target: AgentDispatchTarget::Custom(worker),
                parent_attempt,
                dedupe_key: None,
                run_id: run_id.map(str::to_owned),
                now: 2,
            },
            AgentSpawnContext::default().with_context_from(task_refs),
        )
    };
    let parent_id = Some(parent.attempt.id);

    // The genuinely settled sibling resolves under the same parent and run.
    let ok = dispatched(spawn_on(vec![sibling], Some("run-srv"), parent_id)?);
    assert_eq!(ok.input.context_from, vec![sibling]);

    let attempts_before = AttemptQueue::new(&vault).list()?.len();
    for (label, failure) in [
        // A different run than the parent attempt's.
        spawn_on(vec![sibling], Some("run-other"), parent_id).expect_err("run mismatch"),
        // A settled result created by a DIFFERENT parent row.
        spawn_on(vec![foreign], Some("run-srv"), parent_id).expect_err("parent mismatch"),
        // The pre-settlement window: artifact durable, TASK unsettled.
        spawn_on(vec![unsettled], Some("run-srv"), parent_id).expect_err("unsettled rejects"),
        // A root spawn has no siblings to name at all.
        spawn_on(vec![sibling], None, None).expect_err("root names no siblings"),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(
            failure.kind(),
            ErrorKind::InvalidAgentDispatchInput,
            "case {label} must fail typed"
        );
    }
    assert_eq!(
        AttemptQueue::new(&vault).list()?.len(),
        attempts_before,
        "a lineage failure enqueues nothing"
    );
    Ok(())
}

/// The dedupe key names the INTENT: an existing row whose persisted spawn
/// context (descriptor, sibling refs, or depth budget) differs from the
/// retried request is a typed error, and an identical post-normalization
/// retry is still the one Existing row.
#[test]
fn dedupe_existing_row_with_a_different_spawn_context_is_a_typed_error() -> Result<()> {
    let (_dir, vault) = open_vault();
    let row = put_row(&vault, 0xE0, "dedupe.row", AgentCeiling::Auto)?;
    let dispatcher = AgentDispatcher::new(&vault);
    let input = |now: u64| DispatchAgent {
        target: AgentDispatchTarget::Custom(row),
        parent_attempt: None,
        dedupe_key: Some("dedupe-ctx".to_owned()),
        run_id: Some("run-dedupe".to_owned()),
        now,
    };

    let spec = ContextSpec {
        layers: vec!["identity".to_owned()],
        ..ContextSpec::excluded()
    };
    let first = dispatched(
        dispatcher.dispatch_with_context(
            input(1),
            AgentSpawnContext::default()
                .with_context_spec(spec.clone())
                .with_depth_remaining(4),
        )?,
    );
    assert_eq!(first.input.depth_remaining, Some(4));

    let attempts_before = AttemptQueue::new(&vault).list()?.len();
    // Identical post-normalization retry: same dedupe row, still Existing.
    let retry = dispatcher.dispatch_with_context(
        input(2),
        AgentSpawnContext::default()
            .with_context_spec(ContextSpec {
                layers: vec![" identity ".to_owned()],
                ..ContextSpec::excluded()
            })
            .with_depth_remaining(4),
    )?;
    assert!(matches!(retry, AgentDispatchOutcome::Existing(_)));
    assert_eq!(
        AttemptQueue::new(&vault).list()?.len(),
        attempts_before,
        "an identical retry enqueues nothing new"
    );

    // Same key+target+parent, different spawn context: typed error, and still
    // exactly the one queued attempt.
    for (label, spawn) in [
        (
            "narrowed spec",
            AgentSpawnContext::default()
                .with_context_spec(ContextSpec::excluded())
                .with_depth_remaining(4),
        ),
        (
            "different depth",
            AgentSpawnContext::default()
                .with_context_spec(spec.clone())
                .with_depth_remaining(2),
        ),
    ] {
        let failure = dispatcher
            .dispatch_with_context(input(3), spawn)
            .expect_err("mismatched spawn context fails typed");
        assert_eq!(
            failure.kind(),
            ErrorKind::InvalidAgentDispatchInput,
            "{label} mismatch"
        );
    }
    assert_eq!(
        AttemptQueue::new(&vault)
            .list()?
            .iter()
            .filter(|record| record.dedupe_key.is_some())
            .count(),
        1,
        "still exactly one queued attempt under the dedupe key"
    );
    Ok(())
}

/// A root recursion budget above the ancestor-projection cap is clamped at
/// admission, so no persisted lineage can exceed the projection walk.
#[test]
fn root_depth_budget_is_clamped_to_the_ancestor_projection_cap() -> Result<()> {
    let (_dir, vault) = open_vault();
    let row = put_row(&vault, 0xE4, "clamp.row", AgentCeiling::Proposed)?;
    let dispatcher = AgentDispatcher::new(&vault);
    let root = dispatched(dispatcher.dispatch_with_context(
        DispatchAgent {
            target: AgentDispatchTarget::Custom(row),
            parent_attempt: None,
            dedupe_key: None,
            run_id: None,
            now: 1,
        },
        AgentSpawnContext::default().with_depth_remaining(200),
    )?);
    assert_eq!(
        root.input.depth_remaining,
        Some(CONTEXT_PROJECTION_MAX_ANCESTORS as u8)
    );
    assert_eq!(
        dispatcher.child_depth_remaining(root.attempt.id)?,
        CONTEXT_PROJECTION_MAX_ANCESTORS as u8 - 1
    );
    Ok(())
}

/// The attenuated fork id is revision-aware: a retried spawn of the SAME
/// source revision reuses its fork, while a source row updated in place
/// mints a DISTINCT fork instead of dying against the stale occupant.
#[test]
fn updating_the_source_row_mints_a_distinct_fork_without_a_foreign_collision() -> Result<()> {
    let (_dir, vault) = open_vault();
    let parent_id = put_row(&vault, 0xE8, "fork.parent", AgentCeiling::Proposed)?;
    let child_id = put_row(&vault, 0xE9, "fork.child", AgentCeiling::Auto)?;
    let dispatcher = AgentDispatcher::new(&vault);
    let parent = dispatched(dispatcher.dispatch(DispatchAgent {
        target: AgentDispatchTarget::Custom(parent_id),
        parent_attempt: None,
        dedupe_key: None,
        run_id: Some("run-fork".to_owned()),
        now: 1,
    })?);
    let spawn = |now: u64| {
        dispatched(
            dispatcher
                .dispatch(DispatchAgent {
                    target: AgentDispatchTarget::Custom(child_id),
                    parent_attempt: Some(parent.attempt.id),
                    dedupe_key: None,
                    run_id: Some("run-fork".to_owned()),
                    now,
                })
                .expect("spawn dispatches"),
        )
    };

    // Wider request under a Proposed parent mints the attenuated fork.
    let first = spawn(2);
    let AgentDispatchTarget::Custom(first_fork) = first.input.target;
    assert!(first_fork != child_id, "attenuation names the fork row");

    // Retry of the SAME revision: idempotent fork reuse, not an error.
    let retry = spawn(3);
    let AgentDispatchTarget::Custom(retry_fork) = retry.input.target;
    assert_eq!(retry_fork, first_fork, "same revision reuses its fork");

    // A legitimate in-place source update mints a NEW fork; the stale
    // occupant is left alone rather than killing the spawn.
    let mut updated = vault
        .get_agent_definition(&child_id)?
        .expect("child row persists");
    updated.desc = "revised mid-run".to_owned();
    updated.version = "1.0.1".to_owned();
    vault.update_agent_definition(&child_id, &updated, t(4), 4)?;
    let after = spawn(5);
    let AgentDispatchTarget::Custom(updated_fork) = after.input.target;
    assert!(
        updated_fork != child_id && updated_fork != first_fork,
        "an updated source mints a distinct fork"
    );
    Ok(())
}

/// The descriptor is normalized ONCE at admission: the persisted payload is
/// canonical (byte-stable for dedupe) and declared narrowing compares
/// canonical forms, so whitespace-equivalent requests stop
/// false-rejecting.
#[test]
fn spawn_context_descriptor_is_normalized_into_the_persisted_payload() -> Result<()> {
    let (_dir, vault) = open_vault();
    let row = put_row(&vault, 0xEC, "normalize.row", AgentCeiling::Auto)?;
    let dispatcher = AgentDispatcher::new(&vault);
    let parent = dispatched(dispatcher.dispatch_with_context(
        DispatchAgent {
            target: AgentDispatchTarget::Custom(row),
            parent_attempt: None,
            dedupe_key: None,
            run_id: Some("run-norm".to_owned()),
            now: 1,
        },
        AgentSpawnContext::default().with_context_spec(ContextSpec {
            layers: vec![" identity ".to_owned(), "identity".to_owned()],
            ..ContextSpec::excluded()
        }),
    )?);
    // Persisted canonical form: trimmed, deduped, order-preserved.
    let canonical = ContextSpec {
        layers: vec!["identity".to_owned()],
        ..ContextSpec::excluded()
    };
    assert_eq!(parent.input.context_spec, Some(canonical.clone()));
    assert_eq!(
        encode_agent_dispatch_input(&parent.input)?,
        encode_agent_dispatch_input(&AgentDispatchInput {
            context_spec: Some(canonical.clone()),
            ..parent.input.clone()
        })?,
        "the encoded payload is canonical and byte-stable"
    );

    // A child explicitly requesting the same layer in canonical form narrows
    // — before the admission-time normalization this false-rejected.
    let child = dispatched(dispatcher.dispatch_with_context(
        DispatchAgent {
            target: AgentDispatchTarget::Custom(row),
            parent_attempt: Some(parent.attempt.id),
            dedupe_key: None,
            run_id: Some("run-norm".to_owned()),
            now: 2,
        },
        AgentSpawnContext::default().with_context_spec(canonical.clone()),
    )?);
    assert_eq!(child.input.context_spec, Some(canonical));
    Ok(())
}

/// Property: over every Auto/Proposed assignment in a three-level tree, no
/// dispatched node's EFFECTIVE ceiling is wider than its parent's.
#[test]
fn every_dispatched_node_is_no_wider_than_its_parent_at_every_depth() -> Result<()> {
    const CEILINGS: [AgentCeiling; 2] = [AgentCeiling::Auto, AgentCeiling::Proposed];
    let assignments: Vec<(AgentCeiling, AgentCeiling, AgentCeiling)> = CEILINGS
        .iter()
        .flat_map(|root| {
            CEILINGS
                .iter()
                .flat_map(move |middle| CEILINGS.iter().map(move |leaf| (*root, *middle, *leaf)))
        })
        .collect();
    assert_eq!(assignments.len(), 8);
    for (index, (root, middle, leaf)) in assignments.into_iter().enumerate() {
        let (_dir, vault) = open_vault();
        let seed = 0x80 + u8::try_from(index).expect("small index") * 3;
        let root_id = put_row(&vault, seed, "tree.root", root)?;
        let middle_id = put_row(&vault, seed + 1, "tree.middle", middle)?;
        let leaf_id = put_row(&vault, seed + 2, "tree.leaf", leaf)?;
        let dispatcher = AgentDispatcher::new(&vault);

        let root_attempt = dispatched(dispatcher.dispatch(DispatchAgent {
            target: AgentDispatchTarget::Custom(root_id),
            parent_attempt: None,
            dedupe_key: None,
            run_id: Some("run-1709".to_owned()),
            now: 1,
        })?);
        let middle_attempt = spawn_child(&dispatcher, middle_id, root_attempt.attempt.id, 2)?;
        let leaf_attempt = spawn_child(&dispatcher, leaf_id, middle_attempt.attempt.id, 3)?;

        let root_effective = dispatched_row_ceiling(&vault, &root_attempt);
        let middle_effective = dispatched_row_ceiling(&vault, &middle_attempt);
        let leaf_effective = dispatched_row_ceiling(&vault, &leaf_attempt);

        assert_eq!(root_effective, root);
        assert!(!middle_effective.widens_beyond(root_effective));
        assert!(!leaf_effective.widens_beyond(middle_effective));
    }
    Ok(())
}

// ── load-bearing depth ──────────────────────────────────────────────────

/// Stored parent depth 1 yields child depth 0, and that child cannot enqueue
/// another descendant. A caller asking for MORE than the parent allows is
/// clamped, never honoured.
#[test]
fn zero_depth_rejects_before_another_level_can_enqueue() -> Result<()> {
    let (_dir, vault) = open_vault();
    let row = put_row(&vault, 0x91, "depth.row", AgentCeiling::Proposed)?;
    let dispatcher = AgentDispatcher::new(&vault);

    let root = dispatched(dispatcher.dispatch_with_context(
        DispatchAgent {
            target: AgentDispatchTarget::Custom(row),
            parent_attempt: None,
            dedupe_key: None,
            run_id: Some("run-depth".to_owned()),
            now: 1,
        },
        AgentSpawnContext::default().with_depth_remaining(1),
    )?);
    assert_eq!(persisted_depth(&vault, root.attempt.id), Some(1));
    assert_eq!(dispatcher.child_depth_remaining(root.attempt.id)?, 0);

    // A child asking for a WIDER budget than its parent stores is clamped.
    let child = dispatched(dispatcher.dispatch_with_context(
        DispatchAgent {
            target: AgentDispatchTarget::Custom(row),
            parent_attempt: Some(root.attempt.id),
            dedupe_key: None,
            run_id: Some("run-depth".to_owned()),
            now: 2,
        },
        AgentSpawnContext::default().with_depth_remaining(200),
    )?);
    assert_eq!(persisted_depth(&vault, child.attempt.id), Some(0));

    let before = AttemptQueue::new(&vault).list()?.len();
    let exhausted = dispatcher
        .dispatch(DispatchAgent {
            target: AgentDispatchTarget::Custom(row),
            parent_attempt: Some(child.attempt.id),
            dedupe_key: None,
            run_id: Some("run-depth".to_owned()),
            now: 3,
        })
        .expect_err("depth zero cannot enqueue another level");
    assert_eq!(exhausted.kind(), ErrorKind::InvalidAgentDispatchInput);
    assert_eq!(AttemptQueue::new(&vault).list()?.len(), before);
    Ok(())
}

/// Every new ROOT persists a concrete depth, and a schema-v1 parent (whose
/// stored row carries none) resolves the configured compatibility cap once.
#[test]
fn roots_persist_a_depth_and_legacy_parents_resolve_the_compat_cap() -> Result<()> {
    let (_dir, vault) = open_vault();
    let row = put_row(&vault, 0x94, "depth.compat", AgentCeiling::Proposed)?;
    let dispatcher = AgentDispatcher::new(&vault);

    let root = dispatched(dispatcher.dispatch(DispatchAgent {
        target: AgentDispatchTarget::Custom(row),
        parent_attempt: None,
        dedupe_key: None,
        run_id: None,
        now: 1,
    })?);
    assert_eq!(
        persisted_depth(&vault, root.attempt.id),
        Some(AGENT_DISPATCH_ROOT_DEPTH_REMAINING)
    );
    assert_eq!(
        dispatcher.child_depth_remaining(root.attempt.id)?,
        AGENT_DISPATCH_ROOT_DEPTH_REMAINING - 1
    );

    // A parent that is not an agent dispatch at all carries no stored depth.
    let fabricated = AttemptId::from_bytes(&[0xF7; 16])?;
    assert_eq!(
        dispatcher.child_depth_remaining(fabricated)?,
        AGENT_DISPATCH_COMPAT_DEPTH_CAP - 1
    );
    let legacy_child = dispatched(dispatcher.dispatch(DispatchAgent {
        target: AgentDispatchTarget::Custom(row),
        parent_attempt: Some(fabricated),
        dedupe_key: None,
        run_id: None,
        now: 2,
    })?);
    assert_eq!(
        persisted_depth(&vault, legacy_child.attempt.id),
        Some(AGENT_DISPATCH_COMPAT_DEPTH_CAP - 1)
    );
    Ok(())
}

/// The codec bump is ADDITIVE: a persisted schema-v1 row decodes with the
/// three spawn fields absent, and a payload carrying none re-encodes to the
/// same bytes it always did.
#[test]
fn schema_v1_rows_decode_absent_spawn_fields() -> Result<()> {
    let definition = custom_agent("1.0.0");
    let target_id = test_id(0x95);
    let legacy = Value::Map(vec![
        (
            Value::from("schema_version"),
            Value::from(AGENT_DISPATCH_INPUT_SCHEMA_VERSION),
        ),
        (Value::from("target"), Value::from("custom")),
        (Value::from("agent_def"), Value::from(target_id.to_hex())),
        (
            Value::from("definition"),
            Value::Binary(encode_agent_definition(&definition).expect("body encodes")),
        ),
    ]);

    let decoded = decode_agent_dispatch_input(&legacy)?;
    assert_eq!(decoded.context_spec, None);
    assert_eq!(decoded.context_from.len(), 0);
    assert_eq!(decoded.depth_remaining, None);
    // Absent fields are ELIDED on re-encode, so the row is byte-stable.
    assert_eq!(encode_agent_dispatch_input(&decoded)?, legacy);

    // With the spawn fields present the round trip is exact.
    let rich = AgentDispatchInput {
        target: AgentDispatchTarget::Custom(target_id),
        definition,
        context_spec: Some(ContextSpec::excluded()),
        context_from: vec![test_id(0x96), test_id(0x97)],
        depth_remaining: Some(3),
    };
    assert_eq!(
        decode_agent_dispatch_input(&encode_agent_dispatch_input(&rich)?)?,
        rich
    );
    Ok(())
}

// ── context at dispatch ─────────────────────────────────────────────────

/// A spawn whose descriptor widens its parent's is refused, and nothing is
/// enqueued for it. A narrowing spawn rides through onto the payload.
#[test]
fn spawn_context_can_only_narrow_and_rides_the_payload_unresolved() -> Result<()> {
    let (_dir, vault) = open_vault();
    let row = put_row(&vault, 0x98, "context.row", AgentCeiling::Proposed)?;
    let dispatcher = AgentDispatcher::new(&vault);

    let parent_spec = ContextSpec {
        layers: vec!["identity".to_owned(), "project".to_owned()],
        memory: crate::context_projection::MemoryProjection::Exclude,
        chat: crate::context_projection::ChatProjection::Exclude,
        briefing: None,
        annotation: Some("dev only".to_owned()),
    };
    let parent = dispatched(dispatcher.dispatch_with_context(
        DispatchAgent {
            target: AgentDispatchTarget::Custom(row),
            parent_attempt: None,
            dedupe_key: None,
            run_id: Some("run-ctx".to_owned()),
            now: 1,
        },
        AgentSpawnContext::default().with_context_spec(parent_spec.clone()),
    )?);
    // The DESCRIPTOR rides the payload — never a resolved projection.
    assert_eq!(parent.input.context_spec, Some(parent_spec));

    let narrower = ContextSpec {
        layers: vec!["identity".to_owned()],
        ..ContextSpec::excluded()
    };
    let child = dispatched(dispatcher.dispatch_with_context(
        DispatchAgent {
            target: AgentDispatchTarget::Custom(row),
            parent_attempt: Some(parent.attempt.id),
            dedupe_key: None,
            run_id: Some("run-ctx".to_owned()),
            now: 2,
        },
        AgentSpawnContext::default().with_context_spec(narrower.clone()),
    )?);
    assert_eq!(child.input.context_spec, Some(narrower));

    let before = AttemptQueue::new(&vault).list()?.len();
    let widening = ContextSpec {
        layers: vec!["secrets".to_owned()],
        ..ContextSpec::excluded()
    };
    let refused = dispatcher
        .dispatch_with_context(
            DispatchAgent {
                target: AgentDispatchTarget::Custom(row),
                parent_attempt: Some(parent.attempt.id),
                dedupe_key: None,
                run_id: Some("run-ctx".to_owned()),
                now: 3,
            },
            AgentSpawnContext::default().with_context_spec(widening),
        )
        .expect_err("a widening descriptor is refused");
    assert_eq!(refused.kind(), ErrorKind::InvalidAgentDispatchInput);
    assert_eq!(AttemptQueue::new(&vault).list()?.len(), before);
    Ok(())
}
