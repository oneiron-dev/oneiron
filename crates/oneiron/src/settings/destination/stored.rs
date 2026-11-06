//! Engine-owned replay of a read destination, never a caller-supplied proof.

use serde::{Deserialize, Serialize};

use super::ReadDestination;
use crate::store::StoredPeerMachine;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredReadDestination {
    off_device: bool,
    proved: Vec<StoredPeerMachine>,
}

impl StoredReadDestination {
    pub(crate) fn of(destination: &ReadDestination) -> Self {
        Self {
            off_device: destination.off_device,
            proved: destination.proved.iter().copied().map(Into::into).collect(),
        }
    }

    pub(crate) fn restore(&self) -> ReadDestination {
        ReadDestination {
            off_device: self.off_device,
            proved: self.proved.iter().copied().map(Into::into).collect(),
        }
    }
}
