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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::tests::{facade_for, open_vault, put_person};
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct Owner(RefCell<BTreeMap<u64, ScopedView>>);

    impl MemorySubscriptionOwner for Owner {
        type Delivery = ScopedView;
        type Error = MemoryError;

        fn open(&self, id: u64, view: ScopedView) -> Result<Self::Delivery, Self::Error> {
            if self.0.borrow().contains_key(&id) {
                return Err(MemoryError::bad_request("subscription id already open"));
            }
            self.0.borrow_mut().insert(id, view.clone());
            Ok(view)
        }

        fn close(&self, id: u64) -> Result<(), Self::Error> {
            self.0.borrow_mut().remove(&id);
            Ok(())
        }
    }

    #[test]
    fn facade_binds_actor_and_scoped_view_and_close_stops_delivery() {
        let (_dir, vault) = open_vault();
        let actor = put_person(&vault, 121);
        let memory = facade_for(&vault, actor);
        let owner = Owner::default();
        let view = ScopedView {
            world_ref: Some("33333333333333333333333333333333".into()),
            query: Some("solar".into()),
            ..Default::default()
        };
        assert_eq!(memory.subscribe(&owner, 7, view.clone()).unwrap(), view);
        assert_eq!(owner.0.borrow().get(&7), Some(&view));
        assert_eq!(
            memory.subscribe(&owner, 7, view).unwrap_err().code,
            "BAD_REQUEST"
        );
        memory.unsubscribe(&owner, 7).unwrap();
        assert!(!owner.0.borrow().contains_key(&7));
        let missing = vault.memory(
            crate::EntityId::from_bytes([122; 16]).unwrap(),
            memory.actor_class(),
        );
        assert_eq!(
            missing
                .subscribe(&owner, 8, ScopedView::default())
                .unwrap_err()
                .code,
            "FORBIDDEN"
        );
        assert!(!owner.0.borrow().contains_key(&8));
    }
}
