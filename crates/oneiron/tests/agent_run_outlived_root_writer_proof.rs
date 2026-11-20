//! An outlived root's run TASK counts only behind a writer proof (FIX
//! AGENT-RUN-OUTLIVED-ROOT-BOUND-FROM-REPLICATED-TASK; Engine ASK
//! AGENT-RUN-OUTLIVED-ROOT-UNPROVEN-BOUND = A: fail closed, the rule the
//! handover applies, AGENT-RUN-HANDOVER-SIGNER = A).
//!
//! A child that outlived its root (REVIEW-6638) runs as a root of its own
//! on a machine that holds no row of its settled parent: a taker after a
//! handover, or the minting machine once retention archived that parent.
//! There its run TASK's `outlived_root` flag lets the try run, and the
//! context bound the parent froze into the TASK is what its context
//! resolves under. The TASK rides the shared window and any peer can
//! rewrite it. On main, four reads trust those fields with no check of the
//! writer proof (run_task.rs outlived_root_task_in): a TASK rewritten with
//! no bound resolves the try's context standalone, a fresh scan of its
//! scope past the parent's cut, and the try still runs here.
//!
//! Fixture: an owned vault whose install is profiled as the owner's own
//! machine, with one more machine enrolled as the owner's own, as
//! tests/agent_run_handover_writer_proof.rs builds it, and one memory CLAIM
//! a standalone scan reads. A root dispatch here gives a real frozen
//! payload and its standalone projection, which holds that CLAIM. The child
//! payload is that one with its spawning parent set to an attempt this
//! queue never held. The door `put_peer_outlived_root_run_task` puts the
//! TASK the owner's other machine syncs for that child, promoted when its
//! parent settled there: the bound frozen is the root's projection with its
//! memory cut away, and that machine's proof covers it. The reaper takes it
//! here, so the child's try is queued with its parent gone.
//!
//! Its lease (REVIEW-9863): once the TASK is rewritten unproven, the claim
//! refuses the queued try, so no executor here runs it. A reaper pass that
//! still renewed this machine's lease for it, or took an expired lease for
//! it as a queued try to keep, would hold the run on a machine that never
//! runs it. The door `rewrite_peer_agent_run_lease` lands the lease writes a
//! peer's sync brings.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features --test agent_run_outlived_root_writer_proof`.
#![cfg(all(oneiron_test_support, feature = "sync"))]

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::agent_def::AgentDefinition;
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext,
    DEFAULT_BASE_LOGICAL_ID, DispatchAgent,
};
use oneiron::attempt_queue::{AttemptQueue, AttemptState};
use oneiron::authority::{
    ActSurface, HostSlipIssuer, MACHINE_ENCRYPTION_KEY_LEN, MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
    MachineDeviceClass, MachineEncryptionKey, MachineEnrolmentRequest, MachineOwnership,
    MachineRole, machine_profile_proof_transcript,
};
use oneiron::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::context_projection::ResolvedContextProjection;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::agent_run_handover::{
    PeerWriter, agent_run_task_writer, put_peer_outlived_root_run_task, queue_payload,
    rewrite_peer_agent_run_lease, rewrite_peer_frozen_parent_bound, with_parent_attempt,
};
use oneiron::{AttemptId, EntityId, ErrorKind, TimeRange, Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The client id of the owner's other machine, whose run lease expired.
const PEER_NODE: u64 = 0x5EED_0000_0000_0002;

/// An owned vault, its install the owner's own machine, holding the try of
/// a child that outlived its root, taken over here from the owner's other
/// machine with its parent's row absent.
struct Fixture {
    vault: Vault,
    /// The taken child's try, queued here.
    child: AttemptId,
    /// The bound its settled parent froze into its run TASK.
    bound: ResolvedContextProjection,
    /// The memory section of the CLAIM a standalone scan reads.
    claim_section: String,
}

fn fixture() -> TestResult<(Fixture, tempfile::TempDir)> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), VaultConfig::default())?;
    let person = vault.ensure_embedded_owner_actor()?;
    let issuer = HostSlipIssuer::from_secret(b"agent run outlived root writer proof test host")?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault.ensure_host_root_slip(&issuer)?;
    vault.ensure_serving_install_profile(&issuer, MachineRole::Owned(MachineOwnership::Yours))?;
    vault.prepare_install_signing()?;
    let owner = vault.authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())?;
    let (machine, key) = enroll(
        &vault,
        &owner,
        0xA9,
        MachineRole::Owned(MachineOwnership::Yours),
    )?;
    let claim = put_memory_claim(&vault, person)?;
    let (agent, _) = vault
        .get_seeded_agent_definition_by_logical_id(DEFAULT_BASE_LOGICAL_ID)?
        .ok_or("FIXTURE: the seeded base agent")?;
    let AgentDispatchOutcome::Dispatched(status) = AgentDispatcher::new(&vault)
        .dispatch_with_context(
            DispatchAgent {
                target: AgentDispatchTarget::Custom(agent),
                parent_attempt: None,
                dedupe_key: None,
                run_id: Some("agent-run-outlived-root-writer-proof".to_owned()),
                now: vault.now_recorded_at(),
            },
            AgentSpawnContext::default(),
        )?
    else {
        return Err("FIXTURE: the root run dispatches".into());
    };
    let root = AgentDispatcher::new(&vault).resolve_attempt_context(status.attempt.id)?;
    let claim_section = root
        .memory_sections
        .iter()
        .find(|section| section.ends_with(&format!(":cl_{}", claim.to_hex())))
        .cloned()
        .ok_or_else(|| {
            format!(
                "FIXTURE: a standalone resolve reads the memory CLAIM: {:?}",
                root.memory_sections
            )
        })?;
    // The settled parent's cut: it saw none of the vault's memory.
    let mut bound = root;
    bound.memory_sections.clear();
    let child_payload = with_parent_attempt(
        &queue_payload(&vault, status.attempt.id)?,
        Some(AttemptId::now()),
    )?;
    let child = put_peer_outlived_root_run_task(
        &vault,
        &child_payload,
        PEER_NODE,
        Some(&bound),
        Some(PeerWriter {
            machine,
            key: &key,
            signed_payload: None,
        }),
    )?;
    if agent_run_task_writer(&vault, child)? != Some(machine) {
        return Err(
            "FIXTURE: the outlived root's TASK carries the proof of the owner's machine".into(),
        );
    }
    let reap = vault.reap_agent_run_leases(&|_: &AgentDefinition| true)?;
    if (reap.taken, reap.waiting) != (1, 0) {
        return Err(format!(
            "FIXTURE: the reaper takes the outlived root here: taken {}, waiting {}",
            reap.taken, reap.waiting
        )
        .into());
    }
    if AttemptQueue::new(&vault).get(child)?.is_none() {
        return Err("FIXTURE: the taken child's try is queued here".into());
    }
    Ok((
        Fixture {
            vault,
            child,
            bound,
            claim_section,
        },
        dir,
    ))
}

/// Puts one memory CLAIM about `person` that a context scan surfaces, and
/// answers its id.
fn put_memory_claim(vault: &Vault, person: EntityId) -> TestResult<EntityId> {
    let mut body = ClaimBody::new(
        "preference.tea",
        ClaimSubject::Entity(person),
        rmpv::Value::from("oolong"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::Observed);
    let id = EntityId::now();
    let at = vault.now_recorded_at();
    vault.put_claim(&id, &body, TimeRange { start: at, end: at }, at)?;
    Ok(id)
}

/// Enrols a fresh machine from `seed` in `role`, and answers its id with
/// the install key that signs as it: the enrolment proof its own key signs
/// for this vault, computer class (as test_doors::full_copy_mark does).
fn enroll(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    seed: u8,
    role: MachineRole,
) -> TestResult<(EntityId, SigningKey)> {
    let vault_id = vault
        .authority_fold()?
        .vault_id
        .ok_or("FIXTURE: the vault has a genesis-bound id")?;
    let machine = EntityId::from_bytes([seed; 16])?;
    let key = SigningKey::from_bytes(&[seed; 32]);
    let machine_key = key.verifying_key().to_bytes();
    let device_class = MachineDeviceClass::Computer;
    let encryption_key = MachineEncryptionKey {
        suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
        key: vec![7; MACHINE_ENCRYPTION_KEY_LEN],
    };
    let request = MachineEnrolmentRequest {
        vault_id,
        machine,
        machine_key,
        device_class,
        encryption_key: encryption_key.clone(),
        machine_proof: key
            .sign(&machine_profile_proof_transcript(
                &vault_id,
                machine,
                &machine_key,
                device_class,
                &encryption_key,
            ))
            .to_bytes(),
        restored_from: None,
    };
    vault.enroll_machine(owner, ActSurface::ThisInstall, &request, role, None)?;
    Ok((machine, key))
}

#[test]
fn a_proven_outlived_root_resolves_under_its_frozen_bound() -> TestResult {
    let (fx, _dir) = fixture()?;
    let resolved = AgentDispatcher::new(&fx.vault).resolve_attempt_context(fx.child)?;
    assert!(
        !resolved.memory_sections.contains(&fx.claim_section),
        "the child reads none of the memory its parent's bound cut away: {:?}",
        resolved.memory_sections
    );
    assert_eq!(
        (
            &resolved.layers,
            &resolved.memory_sections,
            &resolved.chat_sections
        ),
        (
            &fx.bound.layers,
            &fx.bound.memory_sections,
            &fx.bound.chat_sections
        ),
        "a Default child resolves exactly the bound its proven TASK froze"
    );
    Ok(())
}

#[test]
fn an_outlived_root_whose_task_a_peer_rewrote_unproven_neither_resolves_nor_runs() -> TestResult {
    let (fx, _dir) = fixture()?;
    rewrite_peer_frozen_parent_bound(&fx.vault, fx.child, None)?;
    assert_eq!(
        agent_run_task_writer(&fx.vault, fx.child)?,
        None,
        "FIXTURE: no proof counts on the rewritten TASK"
    );
    match AgentDispatcher::new(&fx.vault).resolve_attempt_context(fx.child) {
        Err(error) => {
            assert_eq!(
                error.kind(),
                ErrorKind::InvalidAgentDispatchInput,
                "{error}"
            );
            assert!(
                error.to_string().contains("context ancestor is missing"),
                "the walk ends at a child whose parent is gone: {error}"
            );
        }
        Ok(resolved) => panic!(
            "an unproven outlived-root TASK is no outlived root: the context resolve must refuse; \
             on main it resolves standalone, past the parent's cut (memory {:?}, holding {})",
            resolved.memory_sections, fx.claim_section
        ),
    }
    let queued = AttemptQueue::new(&fx.vault)
        .get(fx.child)?
        .ok_or("FIXTURE: the taken child's try is queued here")?
        .state;
    assert!(
        matches!(queued, AttemptState::Queued | AttemptState::Scheduled),
        "FIXTURE: the taken child's try waits for a claim: {queued:?}"
    );
    let claimed = AgentDispatcher::new(&fx.vault).claim_agent_run(
        fx.child,
        "outlived-root-pump",
        fx.vault.now_recorded_at(),
    )?;
    assert!(
        claimed.is_none(),
        "the try of an unproven outlived root does not run here; on main it is claimed"
    );
    let row = AttemptQueue::new(&fx.vault)
        .get(fx.child)?
        .ok_or("the try stays in the queue")?;
    assert_eq!(row.state, queued, "the try stays queued");
    Ok(())
}

/// Rewrites the fixture's run TASK as a peer that holds no proof would (no
/// frozen bound) and answers the state of the child's try, still waiting
/// for a claim here.
fn rewrite_unproven(fx: &Fixture) -> TestResult<AttemptState> {
    rewrite_peer_frozen_parent_bound(&fx.vault, fx.child, None)?;
    if agent_run_task_writer(&fx.vault, fx.child)?.is_some() {
        return Err("FIXTURE: no proof counts on the rewritten TASK".into());
    }
    let state = AttemptQueue::new(&fx.vault)
        .get(fx.child)?
        .ok_or("FIXTURE: the taken child's try is queued here")?
        .state;
    if !matches!(state, AttemptState::Queued | AttemptState::Scheduled) {
        return Err(format!("FIXTURE: the taken child's try waits for a claim: {state:?}").into());
    }
    Ok(state)
}

#[test]
fn the_reaper_renews_no_lease_for_the_queued_try_of_an_unproven_outlived_root() -> TestResult {
    let (fx, _dir) = fixture()?;
    let queued = rewrite_unproven(&fx)?;
    // This machine's own lease from the take, with less than half a hold
    // left: a pass renews it while a try of the run that runs here waits.
    rewrite_peer_agent_run_lease(
        &fx.vault,
        fx.child,
        None,
        fx.vault.now_recorded_at().saturating_add(60),
    )?;
    let reap = fx
        .vault
        .reap_agent_run_leases(&|_: &AgentDefinition| true)?;
    assert_eq!(
        (reap.renewed, reap.taken),
        (0, 0),
        "the claim refuses the queued try of an unproven outlived root, so it holds the run no \
         lease here; with the claim gate alone the reaper renews it at every pass"
    );
    let row = AttemptQueue::new(&fx.vault)
        .get(fx.child)?
        .ok_or("the try stays in the queue")?;
    assert_eq!(row.state, queued, "the try stays queued");
    Ok(())
}

#[test]
fn no_take_keeps_the_queued_try_of_an_unproven_outlived_root() -> TestResult {
    let (fx, _dir) = fixture()?;
    let queued = rewrite_unproven(&fx)?;
    // The owner's other machine took the run back, and its lease lapsed long
    // ago, while the try this machine queued for the run still waits here.
    rewrite_peer_agent_run_lease(&fx.vault, fx.child, Some(PEER_NODE), 0)?;
    let reap = fx
        .vault
        .reap_agent_run_leases(&|_: &AgentDefinition| true)?;
    assert_eq!(
        (reap.taken, reap.waiting),
        (0, 1),
        "an expired lease does not move here for a queued try the claim refuses: the run waits; \
         with the claim gate alone the take keeps that try and moves the lease here"
    );
    let row = AttemptQueue::new(&fx.vault)
        .get(fx.child)?
        .ok_or("the try stays in the queue")?;
    assert_eq!(row.state, queued, "the try stays queued");
    Ok(())
}
