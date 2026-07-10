//! AGENT-3 (ONE-1445) tests, mapped 1:1 to the brief's acceptance criteria:
//! snapshot round-trip, system-preset dispatch, the dispatchability
//! predicate, dedupe, the strict input codec, snapshot-vs-live split, the
//! OF-193 checkpoint/resume contract (AC 7, re-pinned WITH a loaded manifest
//! per B1), and the AGENT-2 live-ceiling integration (AC 9). AC 8 (run-tree
//! surfacing) lives in `run_tree/tests.rs`.

use super::*;
use crate::VaultConfig;
use crate::agent_def::{AgentCeiling, AgentScope};
use crate::claim::ClaimSubject;
use crate::dreamer_runner::{
    AdmitDreamerJob, DREAMER_MILESTONE_PREDICATE, DreamerAdmissionOutcome, DreamerMilestoneClaim,
    DreamerMilestoneKind, decode_dreamer_job_payload, dreamer_milestone_value,
};
use crate::error::ErrorKind;
use crate::job_queue::{CleanupJobLeases, JobQueue, JobState};
use crate::registry::{ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON, ENTITY_TYPE_POLICY_MANIFEST};
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WriteEnvelope, WriteProvenance};

fn open_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(VaultConfig::device())
}

fn t(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

fn test_id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("non-reserved test id")
}

/// A stored, dispatchable custom definition fixture.
fn custom_agent(version: &str) -> AgentDefinition {
    AgentDefinition::new(
        "eiri.agent.custom",
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
    )
}

fn actor_ceiling_row(actor_class: &str, ceiling: &str) -> Value {
    Value::Map(vec![
        (Value::from("actor_class"), Value::from(actor_class)),
        (Value::from("ceiling"), Value::from(ceiling)),
    ])
}

/// Minimal valid policy manifest (mirrors the gate-test fixture shape) with
/// caller-supplied `actor_ceilings` rows, written through the raw store door.
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

    let id = test_id(seed);
    let mut payload = Vec::with_capacity(crate::batch::ENTITY_METADATA_HEADER_LEN + data.len());
    payload.push(ENTITY_TYPE_POLICY_MANIFEST);
    payload.extend_from_slice(&1_u64.to_be_bytes());
    payload.extend_from_slice(&1_u64.to_be_bytes());
    payload.extend_from_slice(&1_u64.to_be_bytes());
    payload.extend_from_slice(&data);
    vault.with_write_txn(|wtxn| {
        vault.store.entities.put(wtxn, id.as_bytes(), &payload)?;
        let type_key = Store::encode_type_key(ENTITY_TYPE_POLICY_MANIFEST, &id);
        vault.store.type_index.put(wtxn, &type_key, &[])?;
        Ok(())
    })
}

fn dispatch_custom(
    dispatcher: &AgentDispatcher<'_>,
    id: EntityId,
    dedupe_key: Option<&str>,
    now: u64,
) -> Result<AgentDispatchOutcome> {
    dispatcher.dispatch(DispatchAgent {
        target: AgentDispatchTarget::Custom(id),
        parent_job: None,
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
    let queue = JobQueue::new(&vault);
    let record = queue.get(status.job.id)?.expect("queued dispatch row");
    let payload = decode_dreamer_job_payload(&record.payload)?;
    assert_eq!(payload.job_type, AGENT_DISPATCH_JOB_TYPE);
    let decoded = decode_agent_dispatch_input(&payload.input)?;
    assert_eq!(decoded, status.input);
    assert_eq!(decoded.definition.skills, def.skills);
    assert_eq!(decoded.definition.connectors, def.connectors);
    assert_eq!(decoded.definition.scope, def.scope);
    Ok(())
}

// AC test 2: an enabled system preset dispatches with the preset snapshot and
// the pinned actor identity.
#[test]
fn dispatch_system_preset() -> Result<()> {
    let (_dir, vault) = open_vault();
    let dispatcher = AgentDispatcher::new(&vault);
    let AgentDispatchOutcome::Dispatched(status) = dispatcher.dispatch(DispatchAgent {
        target: AgentDispatchTarget::System(SystemAgentPreset::Scout),
        parent_job: None,
        dedupe_key: None,
        run_id: None,
        now: 10,
    })?
    else {
        panic!("expected fresh dispatch");
    };
    assert_eq!(
        status.input.target,
        AgentDispatchTarget::System(SystemAgentPreset::Scout)
    );
    assert_eq!(status.input.definition, SystemAgentPreset::Scout.template());

    let actor = agent_dispatch_actor(&status.input);
    assert_eq!(
        actor.entity_ref(),
        SystemAgentPreset::Scout.actor_entity_id()
    );
    assert_eq!(actor.actor_class(), EdgeActorClass::Agent);
    Ok(())
}

// AC test 3: the dispatchability predicate — three custom rejections with the
// pinned messages, plus the disabled-preset rejection. Nothing is enqueued.
#[test]
fn dispatch_rejections() -> Result<()> {
    let (_dir, vault) = open_vault();
    let dispatcher = AgentDispatcher::new(&vault);

    let err = dispatch_custom(&dispatcher, test_id(0x41), None, 10)
        .expect_err("missing definition must not dispatch");
    assert!(matches!(
        err,
        Error::AgentNotDispatchable("agent definition not found")
    ));

    let superseded_id = test_id(0x42);
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

    vault.set_system_agent_enabled(SystemAgentPreset::Herald, false)?;
    let err = dispatcher
        .dispatch(DispatchAgent {
            target: AgentDispatchTarget::System(SystemAgentPreset::Herald),
            parent_job: None,
            dedupe_key: None,
            run_id: None,
            now: 10,
        })
        .expect_err("disabled preset must not dispatch");
    assert!(matches!(err, Error::SystemAgentDisabled(_)));

    // Nothing was enqueued by any rejection.
    assert!(JobQueue::new(&vault).list()?.is_empty());
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
    assert_eq!(second.job.id, first.job.id);
    assert_eq!(second.input, first.input);
    assert_eq!(
        second.job.dedupe_key.as_deref(),
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
    let valid = encode_agent_dispatch_input(&AgentDispatchInput {
        target: AgentDispatchTarget::Custom(def_id),
        definition: def,
    })?;
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
    let system = encode_agent_dispatch_input(&AgentDispatchInput {
        target: AgentDispatchTarget::System(SystemAgentPreset::Scout),
        definition: SystemAgentPreset::Scout.template(),
    })?;
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

    let queue = JobQueue::new(&vault);
    let record = queue.get(status.job.id)?.expect("queued dispatch row");
    let payload = decode_dreamer_job_payload(&record.payload)?;
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

    let def_id = test_id(0x47);
    let def = custom_agent("1.0.0");
    vault.put_agent_definition(&def_id, &def, t(1), 1)?;

    let (job_id, dispatch_input) = {
        let dispatcher = AgentDispatcher::new(&vault);
        let AgentDispatchOutcome::Dispatched(status) =
            dispatch_custom(&dispatcher, def_id, None, 10)?
        else {
            panic!("expected fresh dispatch");
        };
        (status.job.id, status.input)
    };

    // The system/Dreamer bookkeeping envelope: a MACHINE actor, class System,
    // with the agent attribution carried in the provenance payload (B1 (a)).
    let dreamer_actor = test_id(0x2A);
    vault.put_entity(&dreamer_actor, ENTITY_TYPE_MACHINE, t(1), 1, b"dreamer")?;
    // The milestone subject is the job id itself (pinned); anchor an entity at
    // those bytes so the claim door's subject-existence check passes.
    // (`EntityId::from_bytes` takes the 16-byte array by value.)
    let subject = EntityId::from_bytes(*job_id.as_bytes())?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, t(1), 1, b"agent job anchor")?;
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
        let DreamerAdmissionOutcome::Admitted(admitted) = runner.admit_next(AdmitDreamerJob {
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
        assert_eq!(admitted.status.job.id, job_id);
        assert_eq!(
            runner
                .latest_durable_milestone(job_id)?
                .expect("started milestone")
                .kind,
            DreamerMilestoneKind::Started
        );
    }

    // Mid-run checkpoint: an ordinary gated claim under the same envelope.
    let checkpoint_id = EntityId::now();
    let checkpoint_value =
        dreamer_milestone_value(job_id, DreamerMilestoneKind::CheckpointReached, 30);
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
        .latest_durable_milestone(job_id)?
        .expect("durable milestone after reopen");
    assert_eq!(milestone.kind, DreamerMilestoneKind::CheckpointReached);
    assert_eq!(milestone.job_id, job_id);

    // Lease expiry → cleanup → the job is claimable again with the same
    // frozen snapshot.
    let report = JobQueue::new(&vault).cleanup_leases(CleanupJobLeases {
        now: 100,
        lease_timeout_secs: 10,
    })?;
    assert_eq!(report.stale_requeued, 1);
    assert_eq!(
        runner.status(job_id)?.expect("requeued job").job.state,
        JobState::Queued
    );
    let DreamerAdmissionOutcome::Admitted(second) = runner.admit_next(AdmitDreamerJob {
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
    assert_eq!(second.status.job.id, job_id);
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
    vault.fork_system_agent(
        &fork_id,
        SystemAgentPreset::Herald,
        "eiri.herald.custom",
        t(1),
        1,
    )?;

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
// job — the admission door stamps subject + agent attribution from the job's
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
    let job_id = status.job.id;

    let dreamer_actor = test_id(0x2B);
    vault.put_entity(&dreamer_actor, ENTITY_TYPE_MACHINE, t(1), 1, b"dreamer")?;
    let subject = EntityId::from_bytes(*job_id.as_bytes())?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, t(1), 1, b"agent job anchor")?;
    // A decoy subject the forging caller supplies instead of the job id.
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
    let DreamerAdmissionOutcome::Admitted(admitted) = runner.admit_next(AdmitDreamerJob {
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
    assert_eq!(admitted.status.job.id, job_id);

    let stored = vault.get_claim(&started_claim_id)?.expect("started claim");
    assert_eq!(
        stored.subject,
        ClaimSubject::Entity(subject),
        "milestone subject is stamped to the job id, not the caller's decoy"
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
            .latest_durable_milestone(job_id)?
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
                dreamer_milestone_value(job_id, DreamerMilestoneKind::CheckpointReached, 30),
                1.0,
            ),
            &forged_envelope,
            t(30),
            30,
        )
        .commit()?;
    assert_eq!(
        runner
            .latest_durable_milestone(job_id)?
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
                dreamer_milestone_value(job_id, DreamerMilestoneKind::CheckpointReached, 40),
                1.0,
            ),
            &bound_envelope,
            t(40),
            40,
        )
        .commit()?;
    assert_eq!(
        runner
            .latest_durable_milestone(job_id)?
            .expect("bound checkpoint indexed")
            .kind,
        DreamerMilestoneKind::CheckpointReached
    );
    Ok(())
}
