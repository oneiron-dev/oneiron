//! Exact-revision output admission for the existing `self.team.submit` run row.

mod entity;
mod output;
mod revision;

pub(crate) use self::entity::OutputReader;
pub(crate) use self::output::{OutputDescriptor, Read};
pub(crate) use self::revision::OutputRevision;

/// A prepared output read: the vault and the run's read lane, its grant
/// clock prepared before the caller's transaction opens. `None` for a blob
/// or code output, which reads on the vault alone.
pub(crate) struct PreparedOutput<'v> {
    vault: &'v crate::Vault,
    lane: Option<crate::claim::ScopedRead<'v>>,
}

impl PreparedOutput<'_> {
    /// Reads `output` in `txn`: proves it exists as pinned, then reads the
    /// scope the review of it stands in. A refusal is the guest's failure
    /// code.
    pub(crate) fn descriptor_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        output: OutputRevision,
    ) -> crate::Result<Read<OutputDescriptor>> {
        output::output_descriptor_in_txn(self.vault, txn, self.lane.as_ref(), output)
    }
}
