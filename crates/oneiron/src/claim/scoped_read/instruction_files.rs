//! A context pack's instruction-file handles, resolved under this read.
use super::*;
use crate::codebase::CodeInstructionHandle;
use crate::disclosure::DisclosureContext;

impl ScopedRead<'_> {
    /// The instruction files on the ancestor paths of `units`, the code
    /// units a pack returns, resolved in one snapshot through the content
    /// this read sees. Each unit and each CODE_ARTIFACT that may hold its
    /// files is admitted by this read and by `disclosure` before any of its
    /// metadata is read; a unit with no admitted owner brings no file. Call
    /// it after the pack's last row filter and cut.
    pub fn context_pack_instruction_files_under(
        &self,
        units: &[EntityId],
        disclosure: Option<&DisclosureContext>,
    ) -> Result<Vec<CodeInstructionHandle>> {
        let rtxn = self.grant_read_txn()?;
        self.context_pack_instruction_files_in(&rtxn, units, disclosure)
    }

    /// [`Self::context_pack_instruction_files_under`] in the caller's
    /// snapshot `txn`, opened after this read's grant clock was persisted.
    pub(crate) fn context_pack_instruction_files_in(
        &self,
        txn: &heed::RoTxn<'_>,
        units: &[EntityId],
        disclosure: Option<&DisclosureContext>,
    ) -> Result<Vec<CodeInstructionHandle>> {
        let policy = self.live_policy_manifest_in(txn)?;
        let content = self.store_read();
        crate::codebase::code_instruction_handles_in(&content, txn, units, |id| {
            Ok(self.is_ref_readable_with_policy_in(txn, &policy, id)?
                && crate::context_pack::disclosure_admits_target(&content, txn, disclosure, id)?)
        })
    }
}
