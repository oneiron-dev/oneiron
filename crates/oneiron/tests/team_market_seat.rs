//! The seat behind a market submission ([MARKET-SEAT-MODEL-STAMP]; ARCH-0079
//! compares results per model). On the stack below this, a seat the engine
//! spawned had its model on its team receipt, but an attached seat (an
//! external harness such as prime-agent or Claude Code, through `oneiron
//! mcp`) had none: the engine knows the credential, not the model behind it.
//! Now:
//!
//! - the owner declares an agent seat's harness and model on its
//!   credential's pairing link; a malformed seat, or a seat on a link for
//!   anyone but an agent, is refused when the link is made, and redemption
//!   keeps the seat beside the slip's id;
//! - a member's submission through that attached credential freezes the
//!   declared seat: the submit answer, the stored submission and the team's
//!   result carry {harness, model, source} and never the slip's id;
//! - an attached credential paired with no seat submits as unknown, even
//!   when the engine also seated the run: the host did not write that
//!   candidate;
//! - a replayed submission keeps its first seat;
//! - a link and a submission without a seat encode as before.
//!
//! The members call through the public leased host dispatcher, lent the
//! attached credential's slip as the server's action route lends it
//! (`HostSelfDispatcher::with_live_run_slip`). A host-seated member's sealed
//! score is in `tests/team_market_referee.rs`.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features --test team_market_seat`.

#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, CommReach, DispatchAgent,
};
use oneiron::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome};
use oneiron::authority::{HostSlipIssuer, MachineRole, PairingPrincipal, PairingSeat};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::code_run::{HostSelfDispatcher, SelfCall, SelfDispatchOutcome, SelfDispatcher};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::team::market::{InvalidVerdict, ScreenScore, Submission, VerdictEvidence};
use oneiron::team::run::{
    TeamMarketOutcome, TeamMarketSeat, TeamMarketSeatSource, TeamMarketSubmitInput,
};
use oneiron::team::{
    Market, SelfTeamCall, TeamRecordInput, TeamRunAnswer, TeamStartInput, market, team_run_binding,
};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_doors::run_seat_receipt::pin_run_seat;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use rmpv::Value as RmpValue;
use serde::Serialize;
use serde_json::{Value, json};
use tempfile::TempDir;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

// Fixture ids are `[seed; 16]`; every seed here avoids the pinned bytes a
// fresh vault already holds (`0x00 0x11 0x42 0x47 0xA1..=0xA6 0xD7 0xE1
// 0xFF`, the seeded system agents among them).

/// The lease owner this test claims rows as.
const WORKER: &str = "team-market-seat";

/// The run the leader's root attempt serves; its members join it.
const RUN: &str = "run-team-market-seat";

/// The rule a market here records.
const RULE: &str = "suite:granite-eval@4f2a";

/// The challenge a paired agent signs to prove its slip.
const REQUEST_CHALLENGE: &[u8] = b"oneiron-request:team-market-seat";

/// The first tenant's seat and its fallback, as the Orchestrator records
/// them (Engine ACCEPT PLAN-MARKET-SEAT-MODEL-STAMP, condition 5).
fn neon_seat() -> PairingSeat {
    PairingSeat {
        harness: "agy".to_owned(),
        model: "gemini-4-neon-xhigh".to_owned(),
    }
}

fn fallback_seat() -> PairingSeat {
    PairingSeat {
        harness: "claude-code".to_owned(),
        model: "claude-opus-5-5".to_owned(),
    }
}

fn owner_paired(seat: &PairingSeat) -> TeamMarketSeat {
    TeamMarketSeat {
        harness: seat.harness.clone(),
        model: seat.model.clone(),
        source: TeamMarketSeatSource::OwnerPaired,
    }
}

fn candidate(n: u8) -> String {
    format!("{n:02x}").repeat(32)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn definition(name: &str) -> AgentDefinition {
    AgentDefinition::new(
        name,
        "market seat fixture",
        "1",
        Some("Submit carefully.\n".to_owned()),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::Base,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        // The codec requires a non-empty provenance map.
        RmpValue::Map(vec![(
            RmpValue::from("definedVia"),
            RmpValue::from("define_agent"),
        )]),
        None,
        true,
        None,
    )
}

/// A rooted vault this process owns, as a serving start leaves it (the
/// host root, the engine's machines, this install's profile, the embedded
/// owner bound under the root), the leader, one worker definition per
/// member, and the leader's root attempt, leased.
struct Fixture {
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    leader: EntityId,
    /// The definition each member runs as, in start order.
    workers: [EntityId; 2],
    leased: AttemptRecord,
    // Dropped after the vault.
    _dir: TempDir,
}

struct Started {
    team: String,
    members: Vec<AttemptRecord>,
}

fn fixture() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    let (owner, owner_proof) = embedded_owner(&vault)?;
    let now = vault.now_recorded_at();
    let leader = EntityId::from_bytes([0x6C; 16])?;
    let workers = [
        EntityId::from_bytes([0x6D; 16])?,
        EntityId::from_bytes([0x6E; 16])?,
    ];
    for (id, name) in [
        (leader, "fixture.seat.leader"),
        (workers[0], "fixture.seat.worker.one"),
        (workers[1], "fixture.seat.worker.two"),
    ] {
        vault.create_agent_definition_as(
            &owner_proof,
            &id,
            &definition(name),
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )?;
    }
    let AgentDispatchOutcome::Dispatched(status) =
        AgentDispatcher::new(&vault).dispatch(DispatchAgent {
            target: AgentDispatchTarget::Custom(leader),
            parent_attempt: None,
            dedupe_key: None,
            run_id: Some(RUN.to_owned()),
            now,
        })?
    else {
        panic!("the leader dispatches without running a model")
    };
    let leased = claim(&vault, status.attempt.id)?;
    Ok(Fixture {
        vault,
        issuer,
        owner,
        owner_proof,
        leader,
        workers,
        leased,
        _dir: dir,
    })
}

/// Leases `id` to this test's worker. Rows are claimed oldest first, so a
/// row queued before it is claimed past.
fn claim(vault: &Vault, id: AttemptId) -> TestResult<AttemptRecord> {
    let queue = AttemptQueue::new(vault);
    for _ in 0..64 {
        let ClaimOutcome::Claimed(row) = queue.claim_kind(
            DREAMER_RUNNER_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: WORKER.to_owned(),
                now: vault.now_recorded_at(),
            },
        )?
        else {
            break;
        };
        if row.id == id {
            return Ok(row);
        }
    }
    Err("the attempt is ready to claim".into())
}

fn call(
    host: &HostSelfDispatcher<'_>,
    call: SelfTeamCall,
) -> TestResult<Result<TeamRunAnswer, String>> {
    match host.dispatch(SelfCall::Team(call))? {
        SelfDispatchOutcome::Team(result) => Ok(Ok(result.answer)),
        SelfDispatchOutcome::Failed(failed) => Ok(Err(failed.error)),
        other => Err(format!("expected a team answer or a typed failure, got {other:?}").into()),
    }
}

/// The seat a submit answered with.
fn seat_of(answer: &Result<TeamRunAnswer, String>) -> TestResult<Option<TeamMarketSeat>> {
    match answer {
        Ok(TeamRunAnswer::MarketSubmitted { seat, .. }) => Ok(seat.clone()),
        other => Err(format!("expected a submission, got {other:?}").into()),
    }
}

fn recorded_market(answer: Result<TeamRunAnswer, String>) -> TestResult<TeamMarketOutcome> {
    match answer {
        Ok(TeamRunAnswer::Recorded {
            market: Some(market),
            ..
        }) => Ok(market),
        other => Err(format!("expected a market receipt, got {other:?}").into()),
    }
}

impl Fixture {
    fn host(&self) -> oneiron::Result<HostSelfDispatcher<'_>> {
        HostSelfDispatcher::for_leased_agent_attempt(
            &self.vault,
            WriteActor::new(self.leader, EdgeActorClass::Agent),
            &self.leased,
        )
    }

    /// A bounty market under `key`, one member per worker, with its members
    /// leased in start order.
    fn start(&self, key: &str) -> TestResult<Started> {
        let members: Vec<Value> = self
            .workers
            .iter()
            .zip(["m1", "m2"])
            .map(|(worker, member)| json!({"agent": worker.to_hex(), "intentKey": member}))
            .collect();
        let input: TeamStartInput = serde_json::from_value(json!({
            "pattern": "market",
            "intentKey": key,
            "members": members,
            "tournament": null,
            "market": {
                "referee": {"kind": "holdout", "rule": RULE, "digest": "ab".repeat(32)},
                "mode": {"kind": "bounty"},
                "pool": 1_000,
            },
        }))?;
        if let Err(code) = call(&self.host()?, SelfTeamCall::Start(input))? {
            return Err(format!("the market start is refused: {code}").into());
        }
        let team = format!("team:{}:{key}", hex(self.leased.id.as_bytes()));
        let queued = team_run_binding(&self.vault, self.leased.id, &team)?
            .ok_or("the start kept its members")?
            .members;
        let members = queued
            .into_iter()
            .map(|id| claim(&self.vault, id))
            .collect::<TestResult<Vec<_>>>()?;
        Ok(Started { team, members })
    }

    /// The owner's pairing link for `holder` as class `class`, declaring
    /// `seat`.
    fn issue(
        &self,
        holder: EntityId,
        class: &str,
        seat: Option<PairingSeat>,
    ) -> oneiron::Result<oneiron::authority::PairingLink> {
        let mut scope = Scope::top();
        scope.verbs = ScopeAxis::Some(BTreeSet::from(["core:read".to_owned()]));
        self.vault.issue_owner_pairing_link(
            &self.issuer,
            &self.owner_proof,
            scope,
            3_600,
            PairingPrincipal {
                holder_ref: Some(holder.to_hex()),
                actor_class: Some(class.to_owned()),
                seat,
                ..PairingPrincipal::default()
            },
        )
    }

    /// `holder` paired as class `agent` on a link declaring `seat`, redeemed
    /// with a fresh connection key and proven: the slip's id.
    fn pair(
        &self,
        holder: EntityId,
        seat: Option<PairingSeat>,
        binding_seed: u8,
    ) -> TestResult<[u8; 32]> {
        let holder_ref = holder.to_hex();
        let link = self.issue(holder, "agent", seat)?;
        let signing_key = SigningKey::from_bytes(&[binding_seed; 32]);
        let binding_key = signing_key.verifying_key().to_bytes();
        let transcript = oneiron::authority::pairing_binding_transcript_pinned(
            &link.code,
            &binding_key,
            &holder_ref,
            link.pin.as_ref(),
        )?;
        let slip = self.vault.redeem_pairing_link(
            &self.issuer,
            &link.code,
            &holder_ref,
            binding_key,
            &signing_key.sign(&transcript).to_bytes(),
        )?;
        let signature = signing_key
            .sign(&slip.binding_transcript(REQUEST_CHALLENGE)?)
            .to_bytes();
        self.vault.verify_capability_slip(
            &self.issuer.public_key(),
            &slip,
            REQUEST_CHALLENGE,
            &signature,
        )?;
        Ok(slip.claims.slip_id)
    }

    /// Member `index`'s submission, through the attached credential `slip`
    /// when one is named, else by its host.
    fn submit(
        &self,
        started: &Started,
        index: usize,
        slip: Option<[u8; 32]>,
        submission: &str,
        candidate: &str,
    ) -> TestResult<Result<TeamRunAnswer, String>> {
        let input: TeamMarketSubmitInput = serde_json::from_value(json!({
            "teamRef": started.team,
            "submissionRef": submission,
            "candidateSha256": candidate,
        }))?;
        let host = HostSelfDispatcher::for_leased_agent_attempt(
            &self.vault,
            WriteActor::new(self.workers[index], EdgeActorClass::Agent),
            &started.members[index],
        )?;
        let host = match slip {
            Some(slip_id) => host.with_live_run_slip(slip_id),
            None => host,
        };
        call(&host, SelfTeamCall::MarketSubmit(input))
    }

    /// The leader's record of `team`: it closes the market on its referee.
    fn record(&self, team: &str) -> TestResult<Result<TeamRunAnswer, String>> {
        let input: TeamRecordInput = serde_json::from_value(json!({
            "teamRef": team,
            "members": [],
            "axis": "diverge",
            "decidedBy": {"kind": "referee", "rule": RULE, "signedAt": 0},
            "roles": null,
            "coverage": null,
        }))?;
        call(&self.host()?, SelfTeamCall::Record(input))
    }

    fn market(&self, team: &str) -> TestResult<Market> {
        Ok(market(&self.vault, team)?.ok_or("the market is recorded")?)
    }

    /// Pins member `index`'s run on a host seat of `model`.
    fn seat_member(&self, started: &Started, index: usize, model: &str) -> TestResult {
        let run = EntityId::from_bytes(*started.members[index].id.as_bytes())?;
        Ok(pin_run_seat(&self.vault, run, model)?)
    }
}

#[test]
fn an_owner_paired_seat_rides_the_submission_and_the_result_without_its_slip() -> TestResult {
    let f = fixture()?;
    let started = f.start("paired")?;
    let neon_slip = f.pair(f.workers[0], Some(neon_seat()), 0x31)?;
    let fallback_slip = f.pair(f.workers[1], Some(fallback_seat()), 0x32)?;

    let first = f.submit(&started, 0, Some(neon_slip), "m1-a", &candidate(1))?;
    let second = f.submit(&started, 1, Some(fallback_slip), "m2-a", &candidate(2))?;
    let closed = recorded_market(f.record(&started.team)?)?;
    let kept = f.market(&started.team)?;

    assert_eq!(
        seat_of(&first)?,
        Some(owner_paired(&neon_seat())),
        "the submit answer carries the seat the owner declared"
    );
    assert_eq!(seat_of(&second)?, Some(owner_paired(&fallback_seat())));
    assert_eq!(
        kept.submissions
            .iter()
            .map(|submission| submission.seat.clone())
            .collect::<Vec<_>>(),
        vec![
            Some(owner_paired(&neon_seat())),
            Some(owner_paired(&fallback_seat())),
        ],
        "each stored submission froze its seat"
    );
    let listed: Vec<_> = closed
        .submissions
        .iter()
        .map(|view| (view.submission_ref.as_str(), view.seat.clone()))
        .collect();
    assert_eq!(
        listed,
        vec![
            ("m1-a", Some(owner_paired(&neon_seat()))),
            ("m2-a", Some(owner_paired(&fallback_seat()))),
        ],
        "the team's result lists each submission with its seat"
    );

    // Condition 1: no read and no stored row names the slip, in hex or as
    // its bytes.
    let reads = [
        serde_json::to_string(&first.clone()?)?,
        serde_json::to_string(&second.clone()?)?,
        serde_json::to_string(&closed)?,
        serde_json::to_string(&kept)?,
    ];
    for slip in [neon_slip, fallback_slip] {
        let as_hex = hex(&slip);
        let as_bytes = serde_json::to_string(&slip)?;
        for read in &reads {
            assert!(
                !read.contains(&as_hex) && !read.contains(&as_bytes),
                "a read names the slip: {read}"
            );
        }
    }
    Ok(())
}

#[test]
fn an_attached_credential_paired_without_a_seat_stays_unknown() -> TestResult {
    let f = fixture()?;
    let started = f.start("unstamped")?;
    f.seat_member(&started, 0, "provider/host-model@r1")?;
    f.seat_member(&started, 1, "provider/host-model@r1")?;
    let bare = f.pair(f.workers[0], None, 0x33)?;

    let attached = f.submit(&started, 0, Some(bare), "m1-a", &candidate(1))?;
    let hosted = f.submit(&started, 1, None, "m2-a", &candidate(2))?;

    assert_eq!(
        seat_of(&attached)?,
        None,
        "an attached call takes the owner's declaration or nothing, never the host's model"
    );
    assert_eq!(f.market(&started.team)?.submissions[0].seat, None);
    assert_eq!(
        seat_of(&hosted)?,
        Some(TeamMarketSeat {
            harness: "oneiron".to_owned(),
            model: "provider/host-model@r1".to_owned(),
            source: TeamMarketSeatSource::HostSeat,
        }),
        "the same seating, called by its host, reads the host's receipt"
    );
    Ok(())
}

#[test]
fn the_seat_is_the_owners_checked_at_issue_and_frozen_at_the_first_submit() -> TestResult {
    let f = fixture()?;
    let seat = |harness: &str, model: &str| PairingSeat {
        harness: harness.to_owned(),
        model: model.to_owned(),
    };
    let refused = [
        (
            f.owner,
            "human",
            seat("agy", "gemini-4-neon-xhigh"),
            "a seat on a person's link",
        ),
        (
            f.workers[0],
            "agent",
            seat("Prime Agent", "m"),
            "a harness outside [a-z0-9._-]",
        ),
        (
            f.workers[0],
            "agent",
            seat("a".repeat(65).as_str(), "m"),
            "a harness over 64 bytes",
        ),
        (f.workers[0], "agent", seat("agy", ""), "an empty model"),
        (
            f.workers[0],
            "agent",
            seat("agy", "gemini 4"),
            "a model with a space",
        ),
        (
            f.workers[0],
            "agent",
            seat("agy", "m".repeat(129).as_str()),
            "a model over 128 bytes",
        ),
    ];
    for (holder, class, declared, why) in refused {
        assert!(
            f.issue(holder, class, Some(declared)).is_err(),
            "the link is refused: {why}"
        );
    }
    f.issue(
        f.workers[0],
        "agent",
        Some(seat("a".repeat(64).as_str(), "m".repeat(128).as_str())),
    )?;

    let started = f.start("replayed")?;
    let neon_slip = f.pair(f.workers[0], Some(neon_seat()), 0x34)?;
    let fallback_slip = f.pair(f.workers[0], Some(fallback_seat()), 0x35)?;
    let first = f.submit(&started, 0, Some(neon_slip), "m1-a", &candidate(1))?;
    let again = f.submit(&started, 0, Some(fallback_slip), "m1-a", &candidate(1))?;

    assert_eq!(seat_of(&first)?, Some(owner_paired(&neon_seat())));
    match &again {
        Ok(TeamRunAnswer::MarketSubmitted {
            replay: true, seat, ..
        }) => assert_eq!(
            seat.as_ref(),
            Some(&owner_paired(&neon_seat())),
            "a replay answers the seat the first submit froze"
        ),
        other => panic!("expected the same submission again, got {other:?}"),
    }
    assert_eq!(
        f.market(&started.team)?.submissions[0].seat,
        Some(owner_paired(&neon_seat()))
    );
    Ok(())
}

/// Main's `PairingPrincipal`, frozen: a link without a seat keeps its bytes.
#[derive(Serialize)]
struct MainPairingPrincipal {
    holder_ref: Option<String>,
    actor_class: Option<String>,
    org_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    write_facet: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    comm: Option<CommReach>,
}

/// The sealed referee's `Submission` (#10656), frozen: a submission
/// without a seat keeps its bytes.
#[derive(Serialize)]
struct SealedEvalSubmission {
    agent: String,
    submission_ref: String,
    at: u64,
    score: Option<f64>,
    passed: Option<bool>,
    candidate_sha256: Option<String>,
    evidence: Option<VerdictEvidence>,
    screen: Option<ScreenScore>,
    invalid: Option<InvalidVerdict>,
}

#[test]
fn a_link_and_a_submission_without_a_seat_encode_as_before() -> TestResult {
    let facet = EntityId::from_bytes([0x6F; 16])?.to_hex();
    let principal = PairingPrincipal {
        holder_ref: Some("ab".repeat(16)),
        actor_class: Some("agent".to_owned()),
        org_ref: None,
        write_facet: Some(facet.clone()),
        comm: None,
        seat: None,
    };
    let main_principal = MainPairingPrincipal {
        holder_ref: Some("ab".repeat(16)),
        actor_class: Some("agent".to_owned()),
        org_ref: None,
        write_facet: Some(facet),
        comm: None,
    };
    assert_eq!(
        serde_json::to_vec(&principal)?,
        serde_json::to_vec(&main_principal)?,
        "the pending link row (JSON) keeps its bytes"
    );

    let submission = Submission {
        agent: "m1".to_owned(),
        submission_ref: "m1-a".to_owned(),
        at: 1_700_000_000,
        score: Some(0.5),
        passed: Some(true),
        candidate_sha256: Some(candidate(1)),
        evidence: None,
        screen: None,
        invalid: None,
        seat: None,
    };
    let sealed = SealedEvalSubmission {
        agent: "m1".to_owned(),
        submission_ref: "m1-a".to_owned(),
        at: 1_700_000_000,
        score: Some(0.5),
        passed: Some(true),
        candidate_sha256: Some(candidate(1)),
        evidence: None,
        screen: None,
        invalid: None,
    };
    assert_eq!(
        rmp_serde::to_vec_named(&submission)?,
        rmp_serde::to_vec_named(&sealed)?,
        "the market row (MessagePack, named) keeps a seatless submission's bytes"
    );
    Ok(())
}
