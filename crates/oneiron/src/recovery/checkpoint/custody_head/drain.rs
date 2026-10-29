//! The owner's custody member drain doors (FIX 5843, ruled 10-20): the one
//! way a member leaves the required set, after its deletion ack and with a
//! set-history row at a new revision; never a forced unpin. A folder member
//! drains here; any other member's own adapter takes the ticket on its own
//! authenticated channel and answers the ack the commit checks.

use crate::consent::AuthenticatedOwner;
use crate::store::custody_protocol::{DrainAck, DrainTicket, TargetId, TargetSpec};
use crate::{Result, Vault};

impl Vault {
    /// Begins the drain of custody member `target`, approved by `owner`:
    /// the member is fenced at once (no head goes to it and no publication
    /// ack of it is accepted) and the ticket its ack must name is returned.
    /// A retry before the set changes returns the same ticket.
    ///
    /// # Errors
    /// The owner's standing lapsed; `target` is no member; custody faults.
    pub fn begin_custody_member_drain_as(
        &self,
        owner: &AuthenticatedOwner,
        target: &TargetId,
    ) -> Result<DrainTicket> {
        owner.revalidate_in_txn(self, &self.store.env.read_txn()?)?;
        self.store.begin_custody_drain(target)
    }

    /// Commits the drain the member's `ack` names, approved by `owner`: the
    /// member leaves the set at the next revision, returned, with its
    /// history row and evidence in the same write.
    ///
    /// # Errors
    /// The owner's standing lapsed; an ack that does not name exactly its
    /// begun drain, or a drain the set moved past since it began (ruled
    /// 10-20: the owner begins it again); custody faults.
    pub fn commit_custody_member_drain_as(
        &self,
        owner: &AuthenticatedOwner,
        ack: &DrainAck,
    ) -> Result<u64> {
        owner.revalidate_in_txn(self, &self.store.env.read_txn()?)?;
        self.store.commit_custody_drain(ack)
    }

    /// Drains folder member `target`, approved by `owner`, this install
    /// being its adapter: begun, the folder emptied of the lineage's heads
    /// and committed on its ack. The set's new revision.
    ///
    /// # Errors
    /// As [`Self::commit_custody_member_drain_as`], and a folder that still
    /// holds a head.
    pub fn drain_custody_folder_member_as(
        &self,
        owner: &AuthenticatedOwner,
        target: &TargetId,
    ) -> Result<u64> {
        owner.revalidate_in_txn(self, &self.store.env.read_txn()?)?;
        self.store.drain_custody_folder(target)
    }

    /// Re-enrols `spec`, a member `owner` drained, at the next revision,
    /// returned: a publication pass never adds a drained member back.
    ///
    /// # Errors
    /// The owner's standing lapsed; custody faults.
    pub fn reenrol_custody_member_as(
        &self,
        owner: &AuthenticatedOwner,
        spec: &TargetSpec,
    ) -> Result<u64> {
        owner.revalidate_in_txn(self, &self.store.env.read_txn()?)?;
        self.store.reenrol_custody_member(spec)
    }
}
