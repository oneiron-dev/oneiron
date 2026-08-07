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
use crate::registry::{ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON};
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

// AC test 2: an enabled system preset dispatches with the preset snapshot and
// the pinned actor identity.
#[test]
fn dispatch_system_preset() -> Result<()> {
    let (_dir, vault) = open_vault();
    let dispatcher = AgentDispatcher::new(&vault);
    let AgentDispatchOutcome::Dispatched(status) = dispatcher.dispatch(DispatchAgent {
        target: AgentDispatchTarget::System(SystemAgentPreset::Scout),
        parent_attempt: None,
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

    vault.set_system_agent_enabled(SystemAgentPreset::Herald, false)?;
    let err = dispatcher
        .dispatch(DispatchAgent {
            target: AgentDispatchTarget::System(SystemAgentPreset::Herald),
            parent_attempt: None,
            dedupe_key: None,
            run_id: None,
            now: 10,
        })
        .expect_err("disabled preset must not dispatch");
    assert!(matches!(err, Error::SystemAgentDisabled(_)));

    // Nothing was enqueued by any rejection.
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
    auto_def.agent_id = "eiri.agent.auto".to_owned();
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
        &dreamer_envelope(dreamer_actor, "eiri.agent.custom")?,
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
