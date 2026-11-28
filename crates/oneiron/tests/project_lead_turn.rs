//! A company lead's turns (FIX NEON-LEAD-TURN-TRIGGER; Engine ACCEPT PLAN-NEON-LEAD-TURN-TRIGGER,
//! 28 Nov 14:15), through the engine doors the host calls:
//!
//! - T1: a GPU job of the company leaving live owes one turn, in the job's own end write; a write
//!   that lost its compare-and-write owes none; another family's job and an unlisted starter's
//!   plain job owe none.
//! - T1b: a plain job by a listed starter owes a turn; one actor is a starter of one project.
//! - A registration that does not decode never stops a job's end (ACCEPT condition 2).
//! - T2: the timer owes a turn `every_secs` after the last turn opened; a job-end turn restarts
//!   it; a lead's `next_turn_at_ms` falls due no sooner than `min_timer_gap_secs` after its turn
//!   opened (condition 3).
//! - T3: causes fold into the one owed turn; past `max_causes` only the count grows.
//! - T4: a hold refuses turns: the owed turn and each later cause become held lines, a claim is
//!   refused, and a release lets the next cause owe a turn.
//! - T5: only the lead, under its own Grant that lists the verb and reaches the project, claims
//!   and finishes; a revoked Grant is refused at the next call.
//! - T6: a finish keeps one line and the named files, and refuses an unlisted name, a JSON file
//!   that is not one object, an oversized file and a succeeded turn missing a file; a failed turn
//!   places the failure hold until the next day.
//! - T7: a claim whose lease ran out ends `lapsed`; a lead with no live Grant stops the timer.
//! - T8: a detached seat accrues one owed turn, however many causes come.
//! - The project's hard delete takes its registration, lines and files (condition 4).
//!
//! On the base (main 7fb5e492) none of this exists, so every test fails to build there; the reds
//! are revert pins of single fixes on the head.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test project_lead_turn`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::DeleteEntityOptions;
use oneiron::federation::{Scope, ScopeAxis, ScopeId, WalletRef};
use oneiron::gpu_job::{GpuEndReason, GpuJobState};
use oneiron::gpu_line::{ClaimState, Draw, DrawSource, UnitClaim, UnitPurpose};
use oneiron::llm::run_admission::AllocationRef;
use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE,
    MEMORY_CODE_NOT_FOUND, MemoryError, MemoryResult,
};
use oneiron::project_lead_turn::{
    LEAD_TURNS_CLAIM_VERB, LEAD_TURNS_FILE_VERB, LEAD_TURNS_FINISH_VERB, LEAD_TURNS_HOLD_VERB,
    LEAD_TURNS_LIST_VERB, LEAD_TURNS_OWED_VERB, LEAD_TURNS_RELEASE_VERB, LeadTurn, LeadTurnCause,
    LeadTurnFailureHold, LeadTurnFileBody, LeadTurnHoldBy, LeadTurnOutcome, LeadTurnRegistration,
    LeadTurnSeatOutcome, LeadTurnSettings, LeadTurnTicket, LeadTurnsClaimRequest,
    LeadTurnsFileRequest, LeadTurnsFinishRequest, LeadTurnsHoldRequest, LeadTurnsListRequest,
    LeadTurnsListView, LeadTurnsOwedView, LeadTurnsProjectRequest, LeadTurnsSetRequest,
};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::project_lead_turn::{
    move_gpu_job, plant_running_gpu_job, plant_undecodable_registration, plant_unit_claim,
    timer_pass,
};
use oneiron::test_doors::room_facet_set::create_owner_project;
use oneiron::verbs::{
    AgentGrantMintRequest, AgentGrantRevokeRequest, mint_agent_grant_as, revoke_agent_grant_as,
};
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

const NOW: u64 = 1_764_000_000_000;
const HOUR: u64 = 3_600_000;
const SIX_HOURS: u64 = 6 * HOUR;
const JST_SECS: i64 = 32_400;

struct Fixture {
    vault: Vault,
    owner: EntityId,
    issuer: HostSlipIssuer,
    owner_proof: AuthenticatedOwner,
    _dir: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("owner bound to host");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let owner_proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    vault
        .sign_owner_project(
            &owner_proof,
            &vault
                .owner_project_signer(&issuer)
                .expect("owner project signer"),
            vault.root_project().expect("root project"),
        )
        .expect("the owner signs the root project");
    Fixture {
        vault,
        owner,
        issuer,
        owner_proof,
        _dir: dir,
    }
}

impl Fixture {
    /// An owner-born project under the root.
    fn project(&self) -> EntityId {
        let root = self.vault.root_project().expect("root project");
        let id = EntityId::now();
        let record = ProjectRecord::new(id, Some(root), root, self.owner).expect("project record");
        create_owner_project(
            &self.vault,
            &self.issuer,
            &self.owner_proof,
            &self
                .vault
                .owner_project_signer(&self.issuer)
                .expect("owner project signer"),
            self.owner,
            id,
            &record,
        )
        .unwrap_or_else(|error| panic!("the owner bears project {id:?}: {error:?}"));
        id
    }

    /// A named agent and the owner's Grant naming it, listing `verbs` (with `read`, which a
    /// Grant needs to confer) over `project`.
    fn agent(&self, name: &str, verbs: &[&str], project: EntityId) -> (EntityId, EntityId) {
        let agent = self
            .vault
            .ensure_agent_principal(name)
            .expect("named agent principal");
        let mut authority_scope = Scope::top();
        authority_scope.verbs = ScopeAxis::Some(
            std::iter::once("read")
                .chain(verbs.iter().copied())
                .map(str::to_owned)
                .collect::<BTreeSet<_>>(),
        );
        authority_scope.audience = ScopeAxis::Some(BTreeSet::from([ScopeId(project)]));
        let minted = mint_agent_grant_as(
            &self.vault,
            &self.owner_proof,
            ActSurface::ThisInstall,
            AgentGrantMintRequest {
                agent,
                authority_scope,
                expires_at: None,
                repo_bounds: None,
                verb_classes: BTreeSet::new(),
                wallet_ref: None,
                working_view_bounds: None,
                check_in_ref: None,
            },
        )
        .expect("the owner mints the agent a Grant");
        assert!(minted.grant.confers, "agent={name}");
        (agent, minted.grant.grant_ref)
    }

    fn revoke(&self, grant: EntityId) {
        revoke_agent_grant_as(
            &self.vault,
            &self.owner_proof,
            ActSurface::ThisInstall,
            AgentGrantRevokeRequest {
                grant_ref: grant,
                seen: None,
            },
        )
        .expect("the owner revokes the Grant");
    }

    fn set(
        &self,
        project: EntityId,
        lead: EntityId,
        starters: Vec<EntityId>,
        settings: LeadTurnSettings,
    ) -> MemoryResult<LeadTurnRegistration> {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .set_project_lead_turns(
                Some(&self.owner_proof),
                &LeadTurnsSetRequest {
                    project,
                    lead,
                    lead_model: "gemini-4-neon-xhigh".to_owned(),
                    plain_job_starters: starters,
                    settings,
                },
                NOW,
            )
    }

    fn list(&self, project: EntityId) -> LeadTurnsListView {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .project_lead_turns(
                Some(&self.owner_proof),
                &LeadTurnsListRequest {
                    project,
                    after: None,
                    limit: None,
                },
            )
            .expect("the owner reads the turn lines")
    }
}

/// The verbs the lead's Grant lists.
const LEAD_VERBS: [&str; 5] = [
    LEAD_TURNS_OWED_VERB,
    LEAD_TURNS_CLAIM_VERB,
    LEAD_TURNS_FINISH_VERB,
    LEAD_TURNS_LIST_VERB,
    LEAD_TURNS_FILE_VERB,
];
/// The verbs the referee's Grant lists.
const REFEREE_VERBS: [&str; 4] = [
    LEAD_TURNS_HOLD_VERB,
    LEAD_TURNS_RELEASE_VERB,
    LEAD_TURNS_LIST_VERB,
    LEAD_TURNS_FILE_VERB,
];

struct Rig {
    f: Fixture,
    project: EntityId,
    lead: EntityId,
    lead_grant: EntityId,
    referee: EntityId,
}

fn rig_with(settings: LeadTurnSettings, starters: &[&str]) -> Rig {
    let f = fixture();
    let project = f.project();
    let (lead, lead_grant) = f.agent("neon-lead", &LEAD_VERBS, project);
    let (referee, _) = f.agent("lane-referee", &REFEREE_VERBS, project);
    let starters = starters
        .iter()
        .map(|name| f.vault.ensure_agent_principal(name).expect("named starter"))
        .collect();
    f.set(project, lead, starters, settings)
        .expect("the owner sets the lead turns");
    Rig {
        f,
        project,
        lead,
        lead_grant,
        referee,
    }
}

fn rig() -> Rig {
    rig_with(LeadTurnSettings::default(), &[])
}

impl Rig {
    fn vault(&self) -> &Vault {
        &self.f.vault
    }

    fn owed(&self) -> LeadTurnsOwedView {
        self.vault()
            .memory(self.lead, EdgeActorClass::Agent)
            .owed_project_lead_turn(
                None,
                &LeadTurnsProjectRequest {
                    project: self.project,
                },
                NOW,
            )
            .expect("the lead reads its owed turn")
    }

    fn registration(&self) -> LeadTurnRegistration {
        self.f.list(self.project).registration
    }

    fn turns(&self) -> Vec<LeadTurn> {
        self.f.list(self.project).turns
    }

    fn claim_as(&self, agent: EntityId, at: u64) -> MemoryResult<LeadTurnTicket> {
        self.vault()
            .memory(agent, EdgeActorClass::Agent)
            .claim_project_lead_turn(
                None,
                &LeadTurnsClaimRequest {
                    project: self.project,
                    turn: None,
                },
                at,
            )
    }

    fn claim(&self, at: u64) -> LeadTurnTicket {
        self.claim_as(self.lead, at)
            .expect("the lead claims its owed turn")
    }

    fn finish_as(
        &self,
        agent: EntityId,
        turn: u64,
        outcome: LeadTurnSeatOutcome,
        files: &[(&str, &str)],
        at: u64,
    ) -> MemoryResult<LeadTurn> {
        self.finish_with(agent, turn, outcome, "SUCCESS", files, None, at)
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_with(
        &self,
        agent: EntityId,
        turn: u64,
        outcome: LeadTurnSeatOutcome,
        status: &str,
        files: &[(&str, &str)],
        next_turn_at_ms: Option<u64>,
        at: u64,
    ) -> MemoryResult<LeadTurn> {
        self.vault()
            .memory(agent, EdgeActorClass::Agent)
            .finish_project_lead_turn(
                None,
                &LeadTurnsFinishRequest {
                    project: self.project,
                    turn,
                    outcome,
                    status: status.to_owned(),
                    rc: Some(0),
                    model: "gemini-4-neon-xhigh".to_owned(),
                    files: files
                        .iter()
                        .map(|(name, body)| LeadTurnFileBody {
                            name: (*name).to_owned(),
                            body: (*body).to_owned(),
                        })
                        .collect(),
                    next_turn_at_ms,
                },
                at,
            )
    }

    fn hold(&self, reason: &str) -> LeadTurnRegistration {
        self.vault()
            .memory(self.referee, EdgeActorClass::Agent)
            .hold_project_lead_turns(
                None,
                &LeadTurnsHoldRequest {
                    project: self.project,
                    reason: reason.to_owned(),
                },
                NOW,
            )
            .expect("the referee holds the turns")
    }

    fn release(&self, at: u64) -> LeadTurnRegistration {
        self.vault()
            .memory(self.referee, EdgeActorClass::Agent)
            .release_project_lead_turns(
                None,
                &LeadTurnsProjectRequest {
                    project: self.project,
                },
                at,
            )
            .expect("the referee releases the turns")
    }

    /// A unit job of `family`'s claim that ends `exited` at `at`.
    fn end_unit_job(&self, family: EntityId, at: u64) -> EntityId {
        let job = EntityId::now();
        let claim = unit_claim(job, family);
        plant_unit_claim(self.vault(), &claim).expect("the unit claim is planted");
        plant_running_gpu_job(self.vault(), job, Some(self.lead), Some(&claim.key()), at)
            .expect("the job is planted running");
        assert!(
            move_gpu_job(self.vault(), job, exited(), false, at).expect("the job ends"),
            "the job's end write lands"
        );
        job
    }

    /// A plain job started by `starter` that ends `exited` at `at`.
    fn end_plain_job(&self, starter: EntityId, at: u64) -> EntityId {
        let job = EntityId::now();
        plant_running_gpu_job(self.vault(), job, Some(starter), None, at)
            .expect("the job is planted running");
        assert!(
            move_gpu_job(self.vault(), job, exited(), false, at).expect("the job ends"),
            "the job's end write lands"
        );
        job
    }

    fn pass(&self, at: u64) -> Option<u64> {
        timer_pass(self.vault(), self.project, at).expect("the timer pass runs")
    }
}

fn exited() -> GpuJobState {
    GpuJobState::Ended {
        reason: GpuEndReason::Exited,
    }
}

fn unit_claim(job: EntityId, family: EntityId) -> UnitClaim {
    UnitClaim {
        id: job,
        arm: EntityId::now(),
        rung: 1,
        unit_key: "inkling-check/shard-0".to_owned(),
        attempt: 1,
        line: EntityId::now(),
        family,
        period: 0,
        purpose: UnitPurpose::Work,
        workload: "ab".repeat(32),
        machine: None,
        code_sha: "c0de".repeat(10),
        contract_sha256: "cd".repeat(32),
        reserved_secs: 600,
        draws: vec![Draw {
            source: DrawSource::FirstAllowance,
            units: 600,
        }],
        wallet: WalletRef {
            issuer: "home".to_owned(),
            id: "gpu".to_owned(),
        },
        allocation: AllocationRef {
            id: "gpu-line-0".to_owned(),
            generation: 0,
        },
        grant: None,
        reserved_by: None,
        reserved_at_ms: NOW,
        ask_digest: "ad".repeat(32),
        state: ClaimState::Started,
        revision: 1,
    }
}

fn job_causes(causes: &[LeadTurnCause]) -> Vec<EntityId> {
    causes
        .iter()
        .filter_map(|cause| match cause {
            LeadTurnCause::JobEnded { job, .. } => Some(*job),
            LeadTurnCause::Timer { .. } => None,
        })
        .collect()
}

fn refused(result: MemoryResult<impl std::fmt::Debug>, code: &str, words: &str) -> MemoryError {
    let error = result.expect_err("the door refuses");
    assert_eq!(error.code, code, "{error:?}");
    assert!(error.message.contains(words), "{error:?}");
    error
}

const FILES: [(&str, &str); 3] = [
    ("DECISION.md", "# Turn\nPromote nothing.\nDONE\n"),
    ("DECISION.json", "{\"company\":\"neon\",\"decisions\":[]}"),
    ("STATE.md", "# State\nGPU minutes: 12\n"),
];

#[test]
fn a_company_job_end_owes_one_lead_turn() {
    let rig = rig();
    assert_eq!(rig.owed().owed, None, "nothing is owed before a cause");
    let job = rig.end_unit_job(rig.project, NOW + 60_000);
    let owed = rig.owed().owed.expect("the job's end owes a turn");
    assert_eq!(owed.turn, 1);
    assert_eq!(owed.cause_count, 1);
    assert_eq!(
        owed.causes,
        vec![LeadTurnCause::JobEnded {
            job,
            end: "exited".to_owned(),
            at_ms: NOW + 60_000,
        }]
    );
    assert_eq!(owed.lead_model, "gemini-4-neon-xhigh");

    // A write that lost its compare-and-write writes nothing, the cause included.
    let lost = EntityId::now();
    let claim = unit_claim(lost, rig.project);
    plant_unit_claim(rig.vault(), &claim).expect("claim");
    plant_running_gpu_job(rig.vault(), lost, None, Some(&claim.key()), NOW).expect("job");
    assert!(!move_gpu_job(rig.vault(), lost, exited(), true, NOW).expect("the stale write"));
    // Another family's job, and a plain job of a starter no registration lists, owe nothing.
    let other = rig.f.project();
    rig.end_unit_job(other, NOW + 120_000);
    rig.end_plain_job(rig.lead, NOW + 180_000);
    let owed = rig.owed().owed.expect("still owed");
    assert_eq!(owed.cause_count, 1, "{owed:?}");
    assert_eq!(job_causes(&owed.causes), vec![job]);
}

#[test]
fn a_plain_job_by_a_listed_starter_owes_a_turn() {
    let rig = rig_with(LeadTurnSettings::default(), &["neon-referee-booker"]);
    let starter = rig.registration().plain_job_starters[0];
    rig.end_plain_job(rig.referee, NOW + 1_000);
    assert_eq!(
        rig.owed().owed,
        None,
        "an unlisted starter's job owes nothing"
    );
    let job = rig.end_plain_job(starter, NOW + 2_000);
    let owed = rig
        .owed()
        .owed
        .expect("the listed starter's job owes a turn");
    assert_eq!(job_causes(&owed.causes), vec![job]);

    // One actor is a plain-job starter of one project.
    let second = rig.f.project();
    let error = refused(
        rig.f
            .set(second, rig.lead, vec![starter], LeadTurnSettings::default()),
        MEMORY_CODE_BAD_REQUEST,
        &rig.project.to_hex(),
    );
    assert!(error.message.contains(&starter.to_hex()), "{error:?}");
}

#[test]
fn a_job_ends_cleanly_with_an_unreadable_registration() {
    let rig = rig();
    plant_undecodable_registration(rig.vault(), rig.project).expect("damaged registration");
    let job = rig.end_unit_job(rig.project, NOW + 1_000);
    let row = rig
        .vault()
        .gpu_job(&job)
        .expect("read")
        .expect("the job row");
    assert_eq!(row.state, exited(), "the job's end landed whole");
}

#[test]
fn the_timer_owes_a_turn_six_hours_after_the_last() {
    let rig = rig();
    assert_eq!(rig.pass(NOW + SIX_HOURS - 1), Some(NOW + SIX_HOURS));
    assert_eq!(rig.owed().owed, None, "not due yet");
    let next = rig.pass(NOW + SIX_HOURS).expect("the timer stays armed");
    assert_eq!(next, NOW + 2 * SIX_HOURS);
    let owed = rig.owed().owed.expect("the timer owes a turn");
    assert_eq!(
        owed.causes,
        vec![LeadTurnCause::Timer {
            due_at_ms: NOW + SIX_HOURS
        }]
    );

    // A job-end turn restarts the six hours.
    let restarted = rig_with(LeadTurnSettings::default(), &[]);
    restarted.end_unit_job(restarted.project, NOW + HOUR);
    assert_eq!(restarted.registration().next_due_ms, NOW + HOUR + SIX_HOURS);
    restarted.pass(NOW + SIX_HOURS);
    let owed = restarted.owed().owed.expect("the job's turn");
    assert_eq!(
        owed.cause_count, 1,
        "the old due time owes nothing: {owed:?}"
    );

    // A lead's next_turn_at_ms falls due no sooner than min_timer_gap_secs after its turn opened.
    let ticket = restarted.claim(NOW + HOUR);
    restarted
        .finish_with(
            restarted.lead,
            ticket.turn,
            LeadTurnSeatOutcome::Succeeded,
            "SUCCESS",
            &FILES,
            Some(NOW + HOUR + 60_000),
            NOW + HOUR + 120_000,
        )
        .expect("the lead finishes");
    assert_eq!(
        restarted.registration().next_due_ms,
        NOW + HOUR + 900_000,
        "the gap of 900 s holds"
    );
}

#[test]
fn causes_fold_into_the_one_owed_turn() {
    let settings = LeadTurnSettings {
        max_causes: 2,
        ..LeadTurnSettings::default()
    };
    let rig = rig_with(settings, &[]);
    let first = rig.end_unit_job(rig.project, NOW + 1_000);
    let second = rig.end_unit_job(rig.project, NOW + 2_000);
    rig.pass(NOW + 1_000 + SIX_HOURS);
    let owed = rig.owed().owed.expect("one owed turn");
    assert_eq!(owed.turn, 1);
    assert_eq!(owed.cause_count, 3, "every cause counts: {owed:?}");
    assert_eq!(
        job_causes(&owed.causes),
        vec![first, second],
        "the cap lists 2"
    );
    assert!(rig.turns().is_empty(), "no line before the claim");
}

#[test]
fn a_hold_refuses_and_records_each_cause() {
    let rig = rig();
    let first = rig.end_unit_job(rig.project, NOW + 1_000);
    let held = rig.hold("referee review");
    assert_eq!(held.owed, None, "the owed turn became a held line");
    let lines = rig.turns();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].outcome, Some(LeadTurnOutcome::Held));
    assert_eq!(job_causes(&lines[0].causes), vec![first]);
    assert!(matches!(
        held.hold.as_ref().map(|hold| hold.by),
        Some(LeadTurnHoldBy::Grant { .. })
    ));

    let second = rig.end_unit_job(rig.project, NOW + 2_000);
    let view = rig.owed();
    assert!(view.held);
    assert_eq!(view.owed, None, "a hold owes nothing");
    refused(
        rig.claim_as(rig.lead, NOW + 3_000),
        MEMORY_CODE_INVALID_STATE,
        "held",
    );
    let due = rig.registration().next_due_ms;
    rig.pass(due);
    let lines = rig.turns();
    assert_eq!(lines.len(), 2, "the refused causes are one held line");
    assert_eq!(lines[1].outcome, Some(LeadTurnOutcome::Held));
    assert_eq!(job_causes(&lines[1].causes), vec![second]);
    assert_eq!(lines[1].cause_count, 2, "the job and the timer");

    rig.release(due + 1_000);
    let third = rig.end_unit_job(rig.project, due + 2_000);
    let owed = rig
        .owed()
        .owed
        .expect("a released project owes turns again");
    assert_eq!(owed.turn, 3);
    assert_eq!(job_causes(&owed.causes), vec![third]);
}

#[test]
fn only_the_lead_under_a_project_grant_claims_and_finishes() {
    let rig = rig();
    rig.end_unit_job(rig.project, NOW + 1_000);
    let (other, _) = rig.f.agent("not-the-lead", &LEAD_VERBS, rig.project);
    refused(
        rig.claim_as(other, NOW + 2_000),
        MEMORY_CODE_FORBIDDEN,
        "not_the_lead",
    );

    // A lead whose Grant reaches another project only.
    let elsewhere = rig.f.project();
    let (far_lead, _) = rig.f.agent("far-lead", &LEAD_VERBS, elsewhere);
    let far = rig.f.project();
    rig.f
        .set(far, far_lead, Vec::new(), LeadTurnSettings::default())
        .expect("set");
    let far_claim = rig
        .vault()
        .memory(far_lead, EdgeActorClass::Agent)
        .claim_project_lead_turn(
            None,
            &LeadTurnsClaimRequest {
                project: far,
                turn: None,
            },
            NOW + 2_000,
        );
    refused(far_claim, MEMORY_CODE_FORBIDDEN, "not_this_project");

    let ticket = rig.claim(NOW + 3_000);
    assert_eq!(ticket.turn, 1);
    assert_eq!(
        rig.claim(NOW + 4_000),
        ticket,
        "a repeat answers the same ticket"
    );
    rig.f.revoke(rig.lead_grant);
    refused(
        rig.finish_as(
            rig.lead,
            ticket.turn,
            LeadTurnSeatOutcome::Succeeded,
            &FILES,
            NOW + 5_000,
        ),
        MEMORY_CODE_FORBIDDEN,
        "",
    );
}

#[test]
fn finish_keeps_one_line_and_the_named_files() {
    let settings = LeadTurnSettings {
        max_file_bytes: 64,
        ..LeadTurnSettings::default()
    };
    let rig = rig_with(settings, &[]);
    rig.end_unit_job(rig.project, NOW + 1_000);
    let ticket = rig.claim(NOW + 2_000);
    let turn = ticket.turn;
    let ok = LeadTurnSeatOutcome::Succeeded;
    let at = NOW + 3_000;
    refused(
        rig.finish_as(rig.lead, turn, ok, &[("NOTES.md", "x")], at),
        MEMORY_CODE_BAD_REQUEST,
        "NOTES.md",
    );
    refused(
        rig.finish_as(
            rig.lead,
            turn,
            ok,
            &[FILES[0], ("DECISION.json", "[1]"), FILES[2]],
            at,
        ),
        MEMORY_CODE_BAD_REQUEST,
        "JSON object",
    );
    let long = "x".repeat(65);
    refused(
        rig.finish_as(
            rig.lead,
            turn,
            ok,
            &[FILES[0], FILES[1], ("STATE.md", long.as_str())],
            at,
        ),
        MEMORY_CODE_BAD_REQUEST,
        "max_file_bytes",
    );
    refused(
        rig.finish_as(rig.lead, turn, ok, &FILES[..2], at),
        MEMORY_CODE_BAD_REQUEST,
        "STATE.md is missing",
    );

    let line = rig
        .finish_as(rig.lead, turn, ok, &FILES, at)
        .expect("the lead finishes its turn");
    assert_eq!(line.outcome, Some(LeadTurnOutcome::Succeeded));
    assert_eq!(line.status.as_deref(), Some("SUCCESS"));
    assert_eq!(line.model_reported.as_deref(), Some("gemini-4-neon-xhigh"));
    assert_eq!(
        line.files
            .iter()
            .map(|file| file.name.as_str())
            .collect::<Vec<_>>(),
        vec!["DECISION.md", "DECISION.json", "STATE.md"]
    );
    assert_eq!(rig.turns(), vec![line.clone()], "one line per turn");
    let state = rig
        .vault()
        .memory(rig.referee, EdgeActorClass::Agent)
        .project_lead_turn_file(
            None,
            &LeadTurnsFileRequest {
                project: rig.project,
                turn,
                name: "STATE.md".to_owned(),
            },
        )
        .expect("the referee reads the kept file");
    assert_eq!(state.body, FILES[2].1);
    assert_eq!(
        Some(&state.blake3),
        line.files.get(2).map(|file| &file.blake3)
    );
    assert_eq!(
        rig.finish_as(rig.lead, turn, ok, &FILES, at + 1_000)
            .expect("a repeat"),
        line,
        "a repeat of the finish answers the line"
    );
    refused(
        rig.finish_with(rig.lead, turn, ok, "OTHER", &FILES, None, at + 2_000),
        MEMORY_CODE_INVALID_STATE,
        "already_ended",
    );

    // A failed turn holds the turns until the next JST day.
    rig.end_unit_job(rig.project, at + 3_000);
    let failed = rig.claim(at + 4_000);
    let line = rig
        .finish_as(
            rig.lead,
            failed.turn,
            LeadTurnSeatOutcome::Failed,
            &[],
            at + 5_000,
        )
        .expect("a failed finish");
    assert!(line.placed_hold);
    let hold = rig.registration().hold.expect("the failure hold");
    assert_eq!(hold.by, LeadTurnHoldBy::Engine);
    assert_eq!(hold.turn, Some(failed.turn));
    let lifts = hold.lifts_at_ms.expect("it lifts by itself");
    assert_eq!(
        (lifts as i64 / 1000 + JST_SECS) % 86_400,
        0,
        "at a JST day boundary"
    );
    assert!(lifts > at + 5_000 && lifts <= at + 5_000 + 24 * HOUR);
    rig.pass(lifts);
    assert_eq!(rig.registration().hold, None, "the timer pass lifted it");
}

#[test]
fn a_lapsed_claim_ends_lapsed_and_a_grantless_lead_disarms() {
    let settings = LeadTurnSettings {
        failure_hold: LeadTurnFailureHold::None,
        ..LeadTurnSettings::default()
    };
    let rig = rig_with(settings, &[]);
    rig.end_unit_job(rig.project, NOW + 1_000);
    let ticket = rig.claim(NOW + 2_000);
    let lease = ticket.lease_until_ms.expect("a lease");
    assert_eq!(lease, NOW + 2_000 + HOUR);
    rig.pass(lease);
    let lines = rig.turns();
    assert_eq!(lines[0].outcome, Some(LeadTurnOutcome::Lapsed));
    assert_eq!(rig.registration().claimed, None);

    rig.end_unit_job(rig.project, lease + 1_000);
    rig.f.revoke(rig.lead_grant);
    assert_eq!(rig.pass(lease + 2_000), None, "the timer stops");
    let registration = rig.registration();
    assert!(!registration.armed);
    assert_eq!(registration.owed, None);
    let last = rig.turns().pop().expect("a last line");
    assert_eq!(last.outcome, Some(LeadTurnOutcome::LeadWithoutGrant));
    assert_eq!(last.cause_count, 1, "the owed turn's cause went with it");
}

#[test]
fn a_detached_seat_accrues_one_owed_turn() {
    let rig = rig();
    let mut at = NOW;
    for _ in 0..3 {
        at += HOUR;
        rig.end_unit_job(rig.project, at);
        at = rig.registration().next_due_ms;
        rig.pass(at);
    }
    let owed = rig.owed().owed.expect("one owed turn");
    assert_eq!(owed.turn, 1);
    assert_eq!(owed.cause_count, 6, "three ends and three timers: {owed:?}");
    assert!(rig.turns().is_empty(), "no line, no retry, no backlog");
}

#[test]
fn a_projects_hard_delete_takes_its_lead_turns() {
    let rig = rig();
    rig.end_unit_job(rig.project, NOW + 1_000);
    let ticket = rig.claim(NOW + 2_000);
    rig.finish_as(
        rig.lead,
        ticket.turn,
        LeadTurnSeatOutcome::Succeeded,
        &FILES,
        NOW + 3_000,
    )
    .expect("finish");
    rig.vault()
        .delete_entity_with_options(&rig.project, DeleteEntityOptions { purge: true })
        .expect("the owner hard-deletes the project");
    let owner = rig.vault().memory(rig.f.owner, EdgeActorClass::Human);
    refused(
        owner.project_lead_turns(
            Some(&rig.f.owner_proof),
            &LeadTurnsListRequest {
                project: rig.project,
                after: None,
                limit: None,
            },
        ),
        MEMORY_CODE_NOT_FOUND,
        "no lead turns",
    );
    refused(
        owner.project_lead_turn_file(
            Some(&rig.f.owner_proof),
            &LeadTurnsFileRequest {
                project: rig.project,
                turn: ticket.turn,
                name: "STATE.md".to_owned(),
            },
        ),
        MEMORY_CODE_NOT_FOUND,
        "kept no file",
    );
}
