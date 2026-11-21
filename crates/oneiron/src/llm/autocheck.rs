//! Auto-check seam: candidate types, fail-closed verdicts and the bounded host wrapper.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::time::{Duration, Instant};

use serde_json::{Value as JsonValue, json};

use super::ModelId;
use super::decision::catalogue::AUTO_CHECK;
use super::decision::{
    AnswerContract, DecisionAnswer, DecisionBandPolicy, DecisionDial, DecisionLadder, HeldLadder,
    Reversibility,
};
use super::manifest::{CalibratedVerdict, ConfidenceBand, VerdictBasis};
use crate::claim::ClaimSource;
use crate::retrieval_depth::RetrievalDeadline;
use crate::work_line::{LinePermit, WorkLine};
use crate::{EntityId, Result};

mod verdict_cache;
use verdict_cache::VerdictCache;

/// The tier an auto check asks for by PURPOSE default: the cheap one. The
/// per-call and vault-policy slots stay empty so a vault that pins its own
/// tier still wins through [`crate::llm::TierPrecedence::resolved`].
#[cfg(test)]
pub(super) const AUTO_CHECK_PURPOSE_DEFAULT_TIER: &str = "cheap";

/// The answer that lets a candidate self-approve.
const ALLOW: &str = "allow";
/// The answer that holds it.
const HOLD: &str = "hold";

/// The host's auto check as one typed decision through its ladder: allow or
/// hold, over the candidate as the call's bounded state, cut when its caller
/// stops waiting (at most [`AUTO_CHECKER_DEADLINE_MS`]). The check is a
/// self-approval, so a cut abstains rather than take an unfinished answer.
///
/// Synchronous by design: the write gate runs inside an LMDB write
/// transaction, which is not a place to hold an async runtime open. Bound it
/// with [`BoundedAutoChecker`] before injecting it.
pub struct AutoCheckDecisions {
    pub ladder: HeldLadder,
    pub principal: EntityId,
    pub dial: DecisionDial,
    pub bands: DecisionBandPolicy,
    pub wording: String,
    pub notes: Arc<dyn AutoCheckNotes>,
    /// The model a vault's verdict binding names, when the host's ladder
    /// answers as that calibrated model: the answer then reaches the gate as
    /// its calibrated verdict, the decision's probability as the confidence,
    /// and the floor decides. `None` answers Allow or Hold.
    pub calibrated: Option<ModelId>,
    /// The judge of each candidate's world, when the host injects one: a
    /// candidate whose world it keeps on this device is asked only of the
    /// rungs whose provider runs on this device. `None` asks every rung.
    pub world_hold: Option<Arc<dyn AutoCheckWorldHold>>,
}

/// Whether a candidate's world keeps its auto check on this device: the
/// world settings keep a model call on that world from a model off this
/// device (DEC-0005 fix 6: the world's model order covers every model call on
/// it). A candidate it keeps is asked only of the rungs that run on this
/// device ([`super::decision::DecisionProvider::runs_on_device`]); with none,
/// the check is [`AutoCheckOutcome::Unavailable`], as a dead checker's is, and
/// the write fails closed (the owner's ruling L9, 2026-07-13).
pub trait AutoCheckWorldHold: Send + Sync {
    /// Whether no model off this device may read a candidate in `world`.
    fn keeps_on_device(&self, world: EntityId) -> Result<bool>;
}

/// The vault's own world settings. A model off this device is a destination
/// no machine proof names, as a hosted seat's model is, so a world kept from
/// any machine, and a world this vault cannot place, keep the check here
/// ([`crate::Vault::model_call_hold_for`]).
impl AutoCheckWorldHold for crate::Vault {
    fn keeps_on_device(&self, world: EntityId) -> Result<bool> {
        Ok(self
            .model_call_hold_for(
                Some(world),
                &crate::settings::CallerLocality::OffDevice.into(),
            )?
            .is_some())
    }
}

/// The rungs one check of a candidate runs on.
struct CheckRungs<'a> {
    ladder: DecisionLadder<'a>,
    /// Whether the candidate's world keeps the check on this device: `ladder`
    /// then holds only the rungs whose provider runs on this device, and no
    /// notes model writes the hold's reasons.
    kept_on_device: bool,
}

impl AutoCheckDecisions {
    /// The rungs this check of `candidate` runs on: every rung, or, when
    /// `world_hold` keeps the candidate's world on this device, only
    /// those whose provider runs on this device
    /// ([`DecisionLadder::on_device_only`]). A hold that cannot be read keeps
    /// the check on this device too.
    fn rungs(&self, candidate: &AutoCheckCandidate<'_>) -> CheckRungs<'_> {
        let ladder = self.ladder.ladder();
        let kept_on_device = self
            .world_hold
            .as_ref()
            .is_some_and(|hold| hold.keeps_on_device(candidate.world).unwrap_or(true));
        CheckRungs {
            ladder: if kept_on_device {
                ladder.on_device_only()
            } else {
                ladder
            },
            kept_on_device,
        }
    }

    /// An error, an abstention or a hold with no reasons is
    /// [`AutoCheckOutcome::Unavailable`], never a third label. `due` is when
    /// the caller stops waiting.
    fn check(
        &self,
        candidate: &AutoCheckCandidate<'_>,
        rungs: &CheckRungs<'_>,
        due: Instant,
    ) -> AutoCheckOutcome {
        self.decide(candidate, rungs, due)
            .unwrap_or(AutoCheckOutcome::Unavailable)
    }

    fn decide(
        &self,
        candidate: &AutoCheckCandidate<'_>,
        rungs: &CheckRungs<'_>,
        due: Instant,
    ) -> Result<AutoCheckOutcome> {
        let question = AUTO_CHECK.question(
            &[],
            self.wording.clone(),
            AnswerContract::Choice {
                options: vec![ALLOW.to_owned(), HOLD.to_owned()],
            },
        )?;
        let decision = rungs.ladder.run(
            &question,
            self.principal,
            &[],
            &candidate_state(candidate),
            self.dial,
            &self.bands,
            Reversibility::OutboundEffect,
            &RetrievalDeadline::hard(
                Instant::now(),
                due.saturating_duration_since(Instant::now()),
            ),
        )?;
        let (DecisionAnswer::Choice(label), Some(probability)) =
            (&decision.answer, decision.probability)
        else {
            return Ok(AutoCheckOutcome::Unavailable);
        };
        let allow = label == ALLOW;
        if let Some(model) = &self.calibrated {
            return Ok(calibrated(model, allow, probability));
        }
        Ok(if allow {
            AutoCheckOutcome::Allow
        } else if rungs.kept_on_device {
            AutoCheckOutcome::Hold {
                reasons: kept_on_device_hold_reasons(candidate),
            }
        } else {
            AutoCheckOutcome::Hold {
                reasons: self.notes.hold_reasons(candidate, due)?,
            }
        })
    }
}

/// A kept candidate's hold reasons, written from the decision itself: no
/// notes model reads a candidate whose world stays on this device, as no
/// rung off it does (DEC-0005 fix 6).
fn kept_on_device_hold_reasons(candidate: &AutoCheckCandidate<'_>) -> Vec<String> {
    vec![format!(
        "a check on this device held this {} write from a {} source",
        candidate.predicate,
        candidate.source.as_str()
    )]
}

/// The answer as `model`'s calibrated verdict, in the band the verdict table
/// puts its confidence in: the producer picks the band once, here.
fn calibrated(model: &ModelId, allow: bool, probability: f64) -> AutoCheckOutcome {
    let confidence_millionths = millionths(probability);
    ConfidenceBand::for_verdict_millionths(confidence_millionths)
        .map(|band| CalibratedVerdict {
            model: model.clone(),
            allow,
            confidence_millionths,
            band,
            basis: VerdictBasis::CalibratedModel,
        })
        .map_or(AutoCheckOutcome::Unavailable, AutoCheckOutcome::Verdict)
}

#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "a unit-interval probability as millionths fits a u32"
)]
fn millionths(probability: f64) -> u32 {
    (probability.clamp(0.0, 1.0) * 1_000_000.0).round() as u32
}

/// The candidate as the call's state. The value is the gate's bounded preview,
/// never the whole value.
fn candidate_state(candidate: &AutoCheckCandidate<'_>) -> JsonValue {
    json!({
        "predicate": candidate.predicate,
        "value_preview": candidate.value_preview,
        "source": candidate.source.as_str(),
        "lineage": candidate
            .lineage
            .map(|lineage| lineage.iter().map(ClaimSource::as_str).collect::<Vec<_>>()),
        "actor_class": candidate.actor_class,
        "sensitivity_band": candidate.sensitivity_band,
        "burst": candidate
            .burst
            .map(|burst| json!({"rate_ratio": burst.rate_ratio, "streak": burst.streak})),
        "signals": {
            "recent_writes": candidate.signals.recent_writes,
            "window_secs": candidate.signals.window_secs,
            "failure_streak": candidate.signals.failure_streak,
        },
    })
}

/// The wrapper that makes the host's auto-check decisions safe to call from
/// the write gate.
///
/// Each wrapper owns one worker, which runs one host call at a time. Clones
/// share that worker and the one fair line in front of it (FIX 8751, 8701):
/// a caller takes its turn there ([`Self::admit`]) BEFORE it opens its write
/// transaction, waiting round-robin across callers and in arrival order
/// within one, for as long as its own deadline ([`Self::with_deadline`]) or,
/// for a direct call with none, [`AUTO_CHECKER_DEADLINE_MS`]. Occupied
/// capacity is waited for, never refused. The turn rides the host call: a
/// caller that stops waiting frees nothing the host still holds, so a stuck
/// host keeps its one worker and later callers wait to their own deadlines,
/// with no extra worker and no growing backlog.
///
/// Inside the write the gate's consult never waits for a turn: it uses the
/// turn its caller brought, or a free one, and waits for the host's answer
/// no longer than its caller's remaining deadline and never past
/// [`AUTO_CHECKER_DEADLINE_MS`]. Candidates are owned off the gate's stack.
/// A deadline spent in line, timeout, panic, spawn failure and malformed
/// verdicts become [`AutoCheckOutcome::Unavailable`].
#[derive(Clone)]
pub struct BoundedAutoChecker {
    sender: Option<mpsc::SyncSender<AutoCheckJob>>,
    /// Set while the worker runs a host call. Behind the line, only a turn's
    /// own earlier call, one its caller stopped waiting for, can hold it.
    pub(super) occupied: Arc<AtomicBool>,
    /// The one line for the worker, shared by every clone.
    line: WorkLine<EntityId>,
    /// When the caller's whole call stops waiting; `None` for a direct call.
    deadline: Option<Instant>,
    /// The turn this handle waited for before its write transaction opened.
    turn: Option<Arc<CheckerTurn>>,
}

/// One caller's turn at the worker, taken in line before any write
/// transaction opened, and shared by every handle cloned from it.
struct CheckerTurn {
    /// `None` when the caller's deadline came before its turn did. A write
    /// whose own earlier call is still with the host gives it up and takes
    /// its place in line again ([`BoundedAutoChecker::admit_for_writes`]).
    permit: Mutex<Option<Arc<LinePermit>>>,
    deadline: Instant,
}

impl CheckerTurn {
    fn new(permit: Option<LinePermit>, deadline: Instant) -> Self {
        Self {
            permit: Mutex::new(permit.map(Arc::new)),
            deadline,
        }
    }

    fn permit(&self) -> std::sync::MutexGuard<'_, Option<Arc<LinePermit>>> {
        self.permit.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

struct AutoCheckJob {
    candidate: AutoCheckCandidateOwned,
    reply: mpsc::SyncSender<AutoCheckOutcome>,
    /// When the caller stops waiting; the host's decision is cut there too.
    due: Instant,
    /// The caller's turn, given back only once the host returned or unwound.
    turn: Arc<LinePermit>,
}

impl BoundedAutoChecker {
    #[must_use]
    pub fn new(decisions: AutoCheckDecisions) -> Self {
        let (sender, receiver) = mpsc::sync_channel::<AutoCheckJob>(1);
        let occupied = Arc::new(AtomicBool::new(false));
        let worker_occupied = Arc::clone(&occupied);
        // One persistent worker, not one detached thread per consult. Dropping
        // the last wrapper closes the channel; an idle worker then exits. A
        // blocked host keeps only this worker, without delaying wrapper drop.
        let worker = std::thread::Builder::new()
            .name("oneiron-auto-check".to_owned())
            .spawn(move || {
                // The worker's decided verdicts, reused for the same candidate
                // under the same effective policy within their TTL (FIX 7816).
                let mut verdicts = VerdictCache::default();
                while let Ok(job) = receiver.recv() {
                    let AutoCheckJob {
                        candidate,
                        reply,
                        due,
                        turn,
                    } = job;
                    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        verdicts.check(&decisions, &candidate.borrowed(), due)
                    }))
                    .unwrap_or_else(|_| {
                        // A host that unwound mid-check leaves no half-kept verdict.
                        verdicts = VerdictCache::default();
                        AutoCheckOutcome::Unavailable
                    });
                    drop(candidate);
                    // Only the worker releases an admitted call's capacity,
                    // after the host has returned or unwound, never on timeout:
                    // first the call, then the caller's turn in the line.
                    worker_occupied.store(false, Ordering::Release);
                    drop(turn);
                    // Capacity one; never wait for a caller that has timed out.
                    let _ = reply.try_send(outcome);
                }
            });
        Self {
            sender: worker.ok().map(|_| sender),
            occupied,
            line: WorkLine::exclusive(Duration::from_millis(AUTO_CHECKER_DEADLINE_MS)),
            deadline: None,
            turn: None,
        }
    }

    /// This checker for a call whose whole wait ends at `deadline`: its wait
    /// for a turn and every consult it makes spend that one deadline (FIX
    /// 8701). A handle with none is a direct call's.
    #[must_use]
    pub fn with_deadline(&self, deadline: Instant) -> Self {
        Self {
            deadline: Some(deadline),
            ..self.clone()
        }
    }

    /// `caller`'s turn at the worker, waited for fairly in the one line until
    /// the call's deadline, or [`AUTO_CHECKER_DEADLINE_MS`] for a direct call
    /// (FIX 8751). Run it BEFORE the write transaction opens: the handle it
    /// returns carries the turn into that write, so the gate never waits for
    /// capacity there. A handle that already holds a turn comes back as it is.
    #[must_use]
    pub fn admit(&self, caller: EntityId) -> Self {
        if self.turn.is_some() || self.sender.is_none() {
            return self.clone();
        }
        let deadline = self.call_deadline();
        let wait = deadline.saturating_duration_since(Instant::now());
        let permit = self.line.admit_blocking_for(caller, wait).ok();
        Self {
            turn: Some(Arc::new(CheckerTurn::new(permit, deadline))),
            ..self.clone()
        }
    }

    /// [`Self::admit`] awaited instead of blocking its thread (FIX 9110): the
    /// same one line, permit ownership, call deadline and turn, its wait ending
    /// at that deadline as the blocking wait does, never sooner. This call
    /// takes the caller's place in line; the future it returns only waits. A
    /// handle that already holds a turn comes back as it is.
    pub fn admit_in_line(&self, caller: EntityId) -> impl Future<Output = Self> + Send + 'static {
        let handle = self.clone();
        let waiting = (self.turn.is_none() && self.sender.is_some()).then(|| {
            let deadline = self.call_deadline();
            let wait = deadline.saturating_duration_since(Instant::now());
            (self.line.admit_in_line_for(caller, wait), deadline)
        });
        async move {
            let Some((permit, deadline)) = waiting else {
                return handle;
            };
            let permit = permit.await.ok();
            Self {
                turn: Some(Arc::new(CheckerTurn::new(permit, deadline))),
                ..handle
            }
        }
    }

    /// [`Self::admit`] when `store`'s vault names a checker its claim door
    /// may consult: its policy manifest's auto checker or its model
    /// manifest's verdict binding, read in a snapshot closed before any wait.
    /// With neither, the write consults no checker, so it takes no turn and
    /// waits for none. A handle that already holds a turn (one whole sealed
    /// write's, FIX 9110) comes back with it, never in line twice; while that
    /// turn's own earlier call is still with the host, the turn is given up
    /// and `caller` waits in line again until the same deadline, as a fresh
    /// turn would, rather than meet that call's occupied worker.
    pub(crate) fn admit_for_writes(
        &self,
        store: &crate::store::Store,
        caller: EntityId,
    ) -> Result<Self> {
        if let Some(turn) = &self.turn {
            if self.occupied.load(Ordering::Acquire) {
                // Give up this write's own hold first, so the line can pass
                // the turn on once the host returns; then wait for it again.
                *turn.permit() = None;
                let wait = turn.deadline.saturating_duration_since(Instant::now());
                let permit = self.line.admit_blocking_for(caller, wait).ok();
                *turn.permit() = permit.map(Arc::new);
            }
            return Ok(self.clone());
        }
        Ok(if names_checker(store)? {
            self.admit(caller)
        } else {
            self.clone()
        })
    }

    /// [`Self::admit_for_writes`] awaited (FIX 9110), through
    /// [`Self::admit_in_line`]: the snapshot is read and closed before this
    /// returns, so the future holds no read while it waits.
    pub(crate) fn admit_for_writes_in_line(
        &self,
        store: &crate::store::Store,
        caller: EntityId,
    ) -> Result<impl Future<Output = Self> + Send + 'static> {
        let admitted =
            (self.turn.is_none() && names_checker(store)?).then(|| self.admit_in_line(caller));
        let handle = self.clone();
        Ok(async move {
            match admitted {
                Some(admitted) => admitted.await,
                None => handle,
            }
        })
    }

    fn call_deadline(&self) -> Instant {
        self.deadline
            .unwrap_or_else(|| Instant::now() + Duration::from_millis(AUTO_CHECKER_DEADLINE_MS))
    }
}

impl fmt::Debug for BoundedAutoChecker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundedAutoChecker").finish_non_exhaustive()
    }
}

impl BoundedAutoChecker {
    pub fn check(&self, candidate: &AutoCheckCandidate<'_>) -> AutoCheckOutcome {
        let Some(sender) = &self.sender else {
            return AutoCheckOutcome::Unavailable;
        };
        // The turn the caller took in line before its write opened; with
        // none, only a free turn, never a wait inside the write.
        let (turn, deadline) = match &self.turn {
            Some(admitted) => match admitted.permit().as_ref() {
                Some(permit) => (Arc::clone(permit), admitted.deadline),
                None => return AutoCheckOutcome::Unavailable,
            },
            None => match self.line.try_admit_background() {
                Some(permit) => (Arc::new(permit), self.call_deadline()),
                None => return AutoCheckOutcome::Unavailable,
            },
        };
        let wait = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(AUTO_CHECKER_DEADLINE_MS));
        if wait.is_zero() {
            return AutoCheckOutcome::Unavailable;
        }
        if self
            .occupied
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            // This turn's own earlier call is still with the host.
            return AutoCheckOutcome::Unavailable;
        }
        let (reply, receiver) = mpsc::sync_channel(1);
        let job = AutoCheckJob {
            candidate: AutoCheckCandidateOwned::from(candidate),
            reply,
            due: Instant::now() + wait,
            turn,
        };
        if sender.try_send(job).is_err() {
            // No worker accepted this call, so there is no live host to await.
            self.occupied.store(false, Ordering::Release);
            return AutoCheckOutcome::Unavailable;
        }
        receiver
            .recv_timeout(wait)
            .unwrap_or(AutoCheckOutcome::Unavailable)
    }
}

/// Whether `store`'s vault names a checker its claim door may consult: its
/// policy manifest's auto checker or its model manifest's verdict binding,
/// read in a snapshot closed before this returns.
fn names_checker(store: &crate::store::Store) -> Result<bool> {
    let txn = store.env.read_txn()?;
    let named = crate::gate::resolve_policy_manifest(store, &txn)?
        .auto_checker()
        .is_some()
        || super::manifest::read_manifest(store, &txn)?
            .is_some_and(|manifest| manifest.verdict.is_some());
    Ok(named)
}

pub(crate) use crate::claim_check::truncate_on_char_boundary;
pub(super) use crate::claim_check::{
    AUTO_CHECK_HOLD_REASON_MAX_BYTES, AUTO_CHECK_MAX_HOLD_REASONS,
};
pub use crate::claim_check::{
    AUTO_CHECK_VALUE_PREVIEW_BYTES, AUTO_CHECKER_DEADLINE_MS, AutoCheckCandidate,
    AutoCheckCandidateOwned, AutoCheckNotes, AutoCheckOutcome, AutoCheckSignals,
};
