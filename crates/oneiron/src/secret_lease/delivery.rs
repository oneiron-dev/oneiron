//! Core half of `secret_lease::delivery`: its store-layer items live in `oneiron_store::secret_lease::delivery` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::secret_lease::delivery::*;

use super::grant::{SecretCleanup, SecretGrantHolder};
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SecretError};

/// A run host's side of a T1 grant. Implementations never log, return or
/// store the bytes they are handed anywhere but the destination itself.
pub trait SecretHostDelivery {
    /// The effector `destination` presents values for under `holder`'s run,
    /// or `None` when this host registered no such destination for it. The
    /// record's binding for that effector must admit T1.
    fn destination_effector(&self, holder: &SecretGrantHolder, destination: &str)
    -> Option<String>;

    /// Puts `value` into `destination`, replacing what it held.
    /// FIX 7954: `grant` is the delivering grant, so a teardown clears only
    /// its own grant's copy.
    ///
    /// # Errors
    /// Why the bytes did not land. The grant and its lease are then revoked
    /// (a renewal's previous grant stays as the handover rule says).
    fn deliver(
        &mut self,
        holder: &SecretGrantHolder,
        grant: &EntityId,
        destination: &str,
        value: &[u8],
    ) -> Result<()>;

    /// Clears what `destination` holds, at teardown, and says what it found.
    /// Bytes a process already copied are beyond any host's reach.
    /// FIX 7954: clears only what `grant` delivered; a newer grant's copy
    /// stays and reports absent for this grant.
    ///
    /// # Errors
    /// Why it could not clear it; the teardown then reports the copy kept.
    fn withdraw(
        &mut self,
        holder: &SecretGrantHolder,
        grant: &EntityId,
        destination: &str,
    ) -> Result<SecretCleanup>;
}

/// The host with no T1 destinations: it names none, delivers nothing and
/// reports every destination kept, since it can reach none of them.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSecretHostDelivery;

impl SecretHostDelivery for NoSecretHostDelivery {
    fn destination_effector(
        &self,
        _holder: &SecretGrantHolder,
        _destination: &str,
    ) -> Option<String> {
        None
    }

    fn deliver(
        &mut self,
        _holder: &SecretGrantHolder,
        _grant: &EntityId, // FIX 7954: the delivering grant, refused with the rest.
        destination: &str,
        _value: &[u8],
    ) -> Result<()> {
        Err(no_destination(destination))
    }

    fn withdraw(
        &mut self,
        _holder: &SecretGrantHolder,
        _grant: &EntityId, // FIX 7954: no destination held, so no grant's copy can clear.
        _destination: &str,
    ) -> Result<SecretCleanup> {
        Ok(SecretCleanup::Kept)
    }
}
