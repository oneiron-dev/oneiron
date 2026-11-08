//! Host-action read authority retained only in engine-owned transcript work.

use super::HostActionAuthority;
use crate::EntityId;
use crate::authority::StoredReadProof;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredHostAction {
    owner: EntityId,
    root: Option<StoredReadProof>,
}

impl StoredHostAction {
    pub(crate) fn of(action: &HostActionAuthority) -> Self {
        Self {
            owner: action.guard.owner,
            root: action.guard.root.as_ref().map(StoredReadProof::of),
        }
    }

    pub(crate) fn restore(&self) -> HostActionAuthority {
        let root = self.root.as_ref().map(StoredReadProof::restore);
        HostActionAuthority::new(self.owner, root.as_ref())
    }
}
