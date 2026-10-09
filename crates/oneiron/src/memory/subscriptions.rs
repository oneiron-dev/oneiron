//! Transport-neutral subscription verbs. The host owns live delivery, cursors,
//! and cancellation; the facade binds the actor and the typed view before it
//! delegates to that host. This keeps socket state out of the vault.

use super::{Memory, MemoryError};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Scope and retrieval constraints for a live memory view.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScopedView {
    pub world_ref: Option<String>,
    pub facet: Option<String>,
    pub filter: Option<Value>,
    pub query: Option<String>,
}

/// The transport owns subscription IDs, snapshots, delivery, and cleanup.
/// An implementation must bind the same actor and authority to every read.
/// Cursor replay and channel selection are host inputs, not vault state.
pub trait MemorySubscriptionOwner {
    type Delivery;
    type Error: From<MemoryError>;

    fn open(&self, id: u64, view: ScopedView) -> Result<Self::Delivery, Self::Error>;
    fn close(&self, id: u64) -> Result<(), Self::Error>;
}

impl Memory<'_> {
    /// Start a scoped live view through a host-owned subscription. The actor
    /// must exist with its asserted class; the host must enforce read scope.
    pub fn subscribe<O: MemorySubscriptionOwner>(
        &self,
        owner: &O,
        id: u64,
        view: ScopedView,
    ) -> Result<O::Delivery, O::Error> {
        super::verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        owner.open(id, view)
    }

    /// Stop delivery for one host-owned subscription ID. Cancellation remains
    /// available even after the actor has been removed from the vault.
    pub fn unsubscribe<O: MemorySubscriptionOwner>(
        &self,
        owner: &O,
        id: u64,
    ) -> Result<(), O::Error> {
        owner.close(id)
    }
}
