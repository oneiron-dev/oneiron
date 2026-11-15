//! A spent-credit seat reading for top-up tests: plant the head a spent
//! capture's routing would have appended.

use crate::Vault;
use crate::dispatch_byoa::{ByoaError, RunnerSeat};
use crate::error::{Error, Result};

/// Plants a spent-credit reading for `seat` as `attempt`'s capture.
///
/// # Errors
///
/// A record that does not encode; a store failure.
pub fn plant_spent_seat_credit_for_test(
    vault: &Vault,
    seat: &RunnerSeat,
    attempt: [u8; 16],
) -> Result<()> {
    crate::dispatch_byoa::plant_spent_credit_for_test(vault, seat, attempt).map_err(|error| {
        match error {
            ByoaError::Store(error) => error,
            other => Error::InvalidConfig(other.to_string()),
        }
    })
}

/// Reads the head of `seat`'s quota record: its top-up's owner, decision,
/// time and delegate as hex, when one topped it up.
///
/// # Errors
///
/// A store failure.
pub fn topped_up_by_for_test(
    vault: &Vault,
    seat: &RunnerSeat,
) -> Result<Option<(String, String, u64, Option<String>)>> {
    crate::dispatch_byoa::topped_up_by_for_test(vault, seat)
        .map_err(|error| match error {
            ByoaError::Store(error) => error,
            other => Error::InvalidConfig(other.to_string()),
        })
        .map(|topped| {
            topped.map(|(owner, decision, at, delegate)| {
                (
                    crate::entity_id::bytes_to_hex_lower(&owner),
                    crate::entity_id::bytes_to_hex_lower(&decision),
                    at,
                    delegate
                        .as_ref()
                        .map(|bytes| crate::entity_id::bytes_to_hex_lower(bytes)),
                )
            })
        })
}
