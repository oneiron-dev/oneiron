//! The T1 host delivery adapter (FIX 4313): how a leased grant's bytes reach
//! the run that holds it.
//!
//! A T1 value enters workspace memory (ARCH-0069 S3), but never through a
//! model-facing answer. The engine mints the grant and its lease, writes the
//! materialization receipt, commits, and then hands the bytes to the run's
//! host through [`SecretHostDelivery::deliver`], into a destination that host
//! registered for the run: a process environment variable, a CLI credential
//! slot. What a lifecycle call answers holds only the grant's metadata.
//!
//! The host implements the adapter. [`NoSecretHostDelivery`] is the host with
//! no destinations: every T1 grant through it refuses, by name, and it never
//! claims a delivery or a cleanup it did not make.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_base::error::SecretError;
use oneiron_contracts::entity_id::EntityId;

/// The refusal of a T1 grant whose run host registered no such destination.
pub fn no_destination(destination: &str) -> Error {
    Error::Secret(SecretError::SecretHostDeliveryRefused {
        destination: destination.to_owned(),
        reason: "the caller's run host registered no such destination",
    })
}
