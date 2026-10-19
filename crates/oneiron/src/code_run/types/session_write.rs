//! What a run bound to an off-record session writes its room under (WILL
//! L11-01, S01-2a): the answer of its door's
//! [`admit_session_write`](super::AgentVerbDoor::admit_session_write).
//!
//! A run's `vault.notes.create` and `vault.claims.upsert` stage in its room.
//! A run whose host binds a door writes there only as that door admits the
//! write for its caller at each call, and the door's ceiling is checked again
//! inside the transaction that lands the write, so a credential that stopped
//! holding between the admission and the landing writes nothing. The
//! caller's key, when its credential grants a read, opens the room's view a
//! claim's subject resolves in. A read's key is no write permit: only this
//! admission is.
//!
//! Nothing here asks where the caller or the vault runs.

use std::sync::Arc;

use super::AgentVerbRefusal;
use crate::claim::ScopedReadActorKey;

/// The live half of a room write's admission: the door's own check of its
/// caller, run again in the transaction that lands the write.
pub trait SessionWriteCeiling: Send + Sync {
    /// Whether the door's caller still holds the write in `txn`, the write's
    /// own transaction; its refusal is the code the run's guest reads.
    ///
    /// # Errors
    ///
    /// The door's refusal of its caller, as a stable code.
    fn holds_in(&self, txn: &heed::RwTxn<'_>) -> std::result::Result<(), AgentVerbRefusal>;
}

/// What a room write lands under: the door's caller, as its credential and
/// ceiling bind them now.
pub struct SessionWriteAdmission {
    key: Option<ScopedReadActorKey>,
    ceiling: Arc<dyn SessionWriteCeiling>,
}

impl SessionWriteAdmission {
    /// The write of a caller held to `ceiling` where it lands, who reads as
    /// `key` when its credential grants a read.
    #[must_use]
    pub fn new(key: Option<ScopedReadActorKey>, ceiling: Arc<dyn SessionWriteCeiling>) -> Self {
        Self { key, ceiling }
    }

    /// The caller's key, which opens the room's view a claim's subject
    /// resolves in; `None` for a credential that grants no read.
    pub(crate) fn key(&self) -> Option<&ScopedReadActorKey> {
        self.key.as_ref()
    }

    /// The door's ceiling, checked again in `txn`, the write's own
    /// transaction.
    pub(crate) fn holds_in(
        &self,
        txn: &heed::RwTxn<'_>,
    ) -> std::result::Result<(), AgentVerbRefusal> {
        self.ceiling.holds_in(txn)
    }
}
