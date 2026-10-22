//! The owner's runner seat quota doors (FIX 7451): `vault.runners.seats.quotas`
//! reads the named seats' quotas as their captures last recorded them, and
//! `vault.runners.seats.top_up` records the owner's word that a seat's spent
//! credit is topped up.
//!
//! A spent credit names no reset, so its seat waits for the owner
//! ([`super::SeatSpent::back_at`]): until now only a completed run on that
//! seat cleared it. The top-up clears the one reading the owner names, and
//! only while it is still the seat's last reading and a credit spend. It
//! verifies no payment, calls no vendor, completes no attempt and resumes
//! nothing; a later credit spend on the seat is read as before. Each door
//! rechecks the owner's proof in its own transaction.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::memory::{MemoryError, MemoryResult};

use super::error::{ByoaError, ByoaResult};
use super::seat::RunnerSeat;
use super::seat_quota::{OwnerTopUp, RunnerSeatQuota, seat_quota_in_txn, top_up_seat_quota_in_txn};

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
}

/// A seat record door's refusal as a memory door's: a store failure keeps
/// its own code.
fn refusal(error: ByoaError) -> MemoryError {
    match error {
        ByoaError::Store(error) => MemoryError::from(error),
        other => MemoryError::bad_request(other.to_string()),
    }
}
