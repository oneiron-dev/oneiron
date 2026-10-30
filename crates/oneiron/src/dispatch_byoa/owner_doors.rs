//! The owner's runner seat doors: `vault.runners.seats.quotas` reads the named
//! seats' quotas as their captures last recorded them, `vault.runners.seats.top_up`
//! records the owner's word that a seat's spent credit is topped up (FIX 7451),
//! and `vault.runners.seats.resume` resumes a bound runner work a spend parked
//! (FIX 11067).
//!
//! A spent credit names no reset, so its seat waits for the owner
//! ([`super::SeatSpent::back_at`]): until now only a completed run on that
//! seat cleared it. The top-up clears the one reading the owner names, and
//! only while it is still the seat's last reading and a credit spend. It
//! verifies no payment, calls no vendor, completes no attempt and resumes
//! nothing; a later credit spend on the seat is read as before. Each door
//! rechecks the owner's proof in its own transaction.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::LlmBackend;
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Error;
use crate::memory::{MemoryError, MemoryResult};

use super::connector::ByoEndpointSpec;
use super::dispatcher::{ByoEndpointBackendFactory, ByoaDispatcher};
use super::error::{ByoaError, ByoaResult};
use super::exhaust::{ByoaEgressLease, ByoaEgressPort};
use super::provider::ProviderAdapterRegistry;
use super::seat::{RunnerSeat, RunnerSeatPolicy, SkippedRunnerSeat};
use super::seat_quota::{OwnerTopUp, RunnerSeatQuota, seat_quota_in_txn, top_up_seat_quota_in_txn};
use super::work_binding::{RunnerSeatChoice, RunnerWorkBindingId};
use super::work_resume::{ResumeRunnerWork, RunnerWorkResume};

/// The seats whose quotas the owner reads.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunnerSeatQuotasRequest {
    /// The seats, as a seat policy names them. A seat's quota is keyed by
    /// its runner, its sign-in and its custody handles.
    pub seats: Vec<RunnerSeat>,
}

/// The named seats' quotas.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunnerSeatQuotasView {
    /// Each seat's quota in the request's order; its `seat` is its index
    /// there.
    pub quotas: Vec<RunnerSeatQuota>,
}

/// The owner's word that a seat's spent credit is topped up.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunnerSeatCreditTopUpRequest {
    /// The seat, as a seat policy names it.
    pub seat: RunnerSeat,
    /// The spent capture the owner saw as the seat's last reading
    /// ([`RunnerSeatQuota::last_capture`]), in lower-case hex.
    pub expected_spent_attempt: String,
}

/// What a top-up did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunnerSeatTopUpEffect {
    /// The named credit spend is cleared: the seat may take work again.
    Cleared,
    /// The named reading is no spend: cleared already, by this owner or a
    /// completed run.
    AlreadyClear,
    /// The seat's last reading is not the capture named: a later reading,
    /// or none. Nothing changed.
    ObservationChanged,
    /// The named reading is a spend other than credit (a rate limit or a
    /// usage window), which comes back on its own. Nothing changed.
    NotCredit,
}

/// A top-up's effect and the seat's quota after it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunnerSeatTopUpReceipt {
    /// What the top-up did.
    pub effect: RunnerSeatTopUpEffect,
    /// The seat's quota now; its `seat` is 0.
    pub quota: RunnerSeatQuota,
}

/// Which seat a resume takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunnerWorkResumeChoice {
    /// The seat at this index, spent or not.
    Seat(usize),
    /// The first seat from this index in the policy's order that this
    /// runtime may run and whose quota is not spent.
    NextSeat { from: usize },
}

/// The owner's resume of a bound runner work a spend parked (FIX 11067).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunnerWorkResumeRequest {
    /// The bound work, as lower-case hex.
    pub binding: String,
    /// The spent attempt the owner saw at the work's head, as lower-case
    /// hex: the resume acts only while the work still stands there.
    pub expected_attempt: String,
    /// The seat to resume on. Absent searches the policy's order from the
    /// spent seat, that seat included.
    #[serde(default)]
    pub choice: Option<RunnerWorkResumeChoice>,
    /// The owner's ordered seats the resume searches.
    pub policy: RunnerSeatPolicy,
}

/// A fallback seat a resume passed over, and why, in words.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkippedRunnerSeatView {
    /// The seat's index in the policy's order.
    pub seat: usize,
    /// The runner the seat names.
    pub runner: String,
    /// Why the resume passed it over.
    pub reason: String,
}

/// Where resuming a bound work left it. Each arm is where the work stands,
/// never a refusal; every arm but `resumed` wrote nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunnerWorkResumeView {
    /// A successor on `seat` carries the work now: its attempt, as
    /// lower-case hex, a child of the spent attempt on a fresh checkout.
    /// `existing` when that seat's successor of the spent attempt was
    /// already dispatched.
    Resumed {
        seat: usize,
        attempt: String,
        existing: bool,
        skipped: Vec<SkippedRunnerSeatView>,
    },
    /// The work stands at `attempt` on `seat`: it moved past the attempt
    /// named, or that attempt has not ended.
    Current { seat: usize, attempt: String },
    /// The attempt named ended without a spend: there is nothing to resume.
    Unchanged { seat: usize, attempt: String },
    /// No seat this runtime may run took the work.
    NoSeat { skipped: Vec<SkippedRunnerSeatView> },
    /// Every seat tried is spent or passed over, a spent one among them.
    /// `back_at` is the first time one is back; none waits for the owner.
    Exhausted {
        back_at: Option<u64>,
        skipped: Vec<SkippedRunnerSeatView>,
    },
    /// Nothing holds the work: never bound here, or erased or pruned.
    Gone,
}

impl RunnerWorkResumeView {
    /// The wire view of a resume's outcome: attempts as lower-case hex,
    /// passed-over seats with their reasons in words.
    fn of(outcome: &RunnerWorkResume) -> Self {
        let attempt = |attempt: &AttemptId| bytes_to_hex_lower(attempt.as_bytes());
        match outcome {
            RunnerWorkResume::Resumed {
                seat,
                attempt: resumed,
                existing,
                skipped,
            } => Self::Resumed {
                seat: *seat,
                attempt: attempt(resumed),
                existing: *existing,
                skipped: skipped_views(skipped),
            },
            RunnerWorkResume::Current { seat, attempt: at } => Self::Current {
                seat: *seat,
                attempt: attempt(at),
            },
            RunnerWorkResume::Unchanged { seat, attempt: at } => Self::Unchanged {
                seat: *seat,
                attempt: attempt(at),
            },
            RunnerWorkResume::NoSeat { skipped } => Self::NoSeat {
                skipped: skipped_views(skipped),
            },
            RunnerWorkResume::Exhausted { back_at, skipped } => Self::Exhausted {
                back_at: *back_at,
                skipped: skipped_views(skipped),
            },
            RunnerWorkResume::Gone => Self::Gone,
        }
    }
}

/// The wire views of the seats a resume passed over, in the policy's order.
fn skipped_views(skipped: &[SkippedRunnerSeat]) -> Vec<SkippedRunnerSeatView> {
    skipped
        .iter()
        .map(|skip| SkippedRunnerSeatView {
            seat: skip.seat,
            runner: skip.runner.clone(),
            reason: skip.reason.to_string(),
        })
        .collect()
}

/// A resume reaches no endpoint: it only mints the successor attempt row,
/// and dispatch records the intent without reaching out.
struct ResumeEndpoints;

impl ByoEndpointBackendFactory for ResumeEndpoints {
    fn resolve_backend(&self, _spec: &ByoEndpointSpec) -> ByoaResult<Arc<dyn LlmBackend>> {
        Err(ByoaError::Backend(
            "the resume door serves no endpoint connector".to_owned(),
        ))
    }
}

/// A resume takes no egress lease: it mints a row, and no traffic moves.
struct ResumeEgress;

impl ByoaEgressPort for ResumeEgress {
    fn open(&mut self, profile_ref: &str, _intent_ref: &str) -> ByoaResult<ByoaEgressLease> {
        Err(ByoaError::EgressDenied {
            profile_ref: profile_ref.to_owned(),
            reason: "the resume door leases no egress".to_owned(),
        })
    }
}

impl Vault {
    /// The named seats' quotas as their captures last recorded them, read
    /// in one snapshot with the owner's proof (FIX 7451).
    ///
    /// # Errors
    /// A proof that no longer holds; a record that does not decode; a store
    /// failure.
    pub fn runner_seat_quotas_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &RunnerSeatQuotasRequest,
    ) -> MemoryResult<RunnerSeatQuotasView> {
        let rtxn = self.store.env.read_txn().map_err(Error::from)?;
        owner.revalidate_in_txn(self, &rtxn)?;
        let now = crate::unix_seconds_now();
        let quotas = input
            .seats
            .iter()
            .enumerate()
            .map(|(index, seat)| seat_quota_in_txn(self, &rtxn, index, seat, now))
            .collect::<ByoaResult<Vec<_>>>()
            .map_err(refusal)?;
        Ok(RunnerSeatQuotasView { quotas })
    }

    /// The owner's word that `input.seat`'s spent credit is topped up
    /// (FIX 7451), in one writer that rechecks the owner's proof: it clears
    /// the seat's last reading only while that is the named capture and a
    /// credit spend, keeping the capture and adding the owner, the
    /// authentication and the time. A second top-up, a stale one and a
    /// spend other than credit change nothing and say so.
    ///
    /// # Errors
    /// A capture id that is not an id; a proof that no longer holds; a
    /// record that does not encode or decode; a store failure.
    pub fn top_up_runner_seat_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &RunnerSeatCreditTopUpRequest,
    ) -> MemoryResult<RunnerSeatTopUpReceipt> {
        let expected = *EntityId::from_hex(&input.expected_spent_attempt)?.as_bytes();
        let now = crate::unix_seconds_now();
        self.try_with_write_txn_grouped(|wtxn| -> MemoryResult<RunnerSeatTopUpReceipt> {
            let actor = owner.revalidate_in_txn(self, wtxn)?;
            let top_up = OwnerTopUp {
                owner: *actor.as_bytes(),
                decision: owner.decision_id().as_bytes(),
                at: now,
            };
            let effect = top_up_seat_quota_in_txn(self, wtxn, &input.seat, expected, top_up)
                .map_err(refusal)?;
            let quota = seat_quota_in_txn(self, wtxn, 0, &input.seat, now).map_err(refusal)?;
            Ok(RunnerSeatTopUpReceipt { effect, quota })
        })
    }

    /// The owner's resume of a bound runner work a spend parked (FIX 11067),
    /// over the plain CLI runners ([`ProviderAdapterRegistry::standard`]):
    /// while the work still stands at `input.expected_attempt`, ended with
    /// its spend, it goes to a successor of that attempt on the first seat
    /// of `input.policy` this runtime may run, the spent seat included. A
    /// work that moved on, is running, or ended without a spend is answered
    /// as it stands, with no write. The owner's proof is rechecked in the
    /// writer before the work is read.
    ///
    /// # Errors
    /// A binding or attempt id that is not an id; a proof that no longer
    /// holds; an invalid policy; every refusal a dispatch and a checkout
    /// claim have; a store failure.
    pub fn resume_runner_work_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &RunnerWorkResumeRequest,
    ) -> MemoryResult<RunnerWorkResumeView> {
        let binding =
            RunnerWorkBindingId::from_bytes(*EntityId::from_hex(&input.binding)?.as_bytes())
                .map_err(refusal)?;
        let expected_attempt =
            AttemptId::from_bytes(EntityId::from_hex(&input.expected_attempt)?.as_bytes())?;
        let choice = input.choice.map(|choice| match choice {
            RunnerWorkResumeChoice::Seat(index) => RunnerSeatChoice::Seat(index),
            RunnerWorkResumeChoice::NextSeat { from } => RunnerSeatChoice::NextSeat { from },
        });
        let request = ResumeRunnerWork {
            binding,
            expected_attempt,
            choice,
            now: crate::unix_seconds_now(),
        };
        let dispatcher = ByoaDispatcher::new(self, ResumeEndpoints, ResumeEgress);
        let registry = ProviderAdapterRegistry::standard();
        let outcome = dispatcher
            .resume_runner_work_as_owner(owner, &registry, &input.policy, request)
            .map_err(refusal)?;
        Ok(RunnerWorkResumeView::of(&outcome))
    }
}

/// A seat record door's refusal as a memory door's: a store failure keeps
/// its own code.
fn refusal(error: ByoaError) -> MemoryError {
    match error {
        ByoaError::Store(error) => MemoryError::from(error),
        other => MemoryError::bad_request(other.to_string()),
    }
}
