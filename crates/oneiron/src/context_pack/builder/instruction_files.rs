//! A pack's instruction-file handles, resolved in its assembly snapshot.

use std::collections::BTreeSet;

use heed::RoTxn;

use crate::codebase::CodeInstructionHandle;
use crate::disclosure::DisclosureContext;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::StoreRead;

use super::super::types::ContextEntity;
use super::super::validation::disclosure_admits_target;

/// The instruction files of the code units among `results` and `neighbors`,
/// read in the assembly's snapshot `rtxn` (FIX 9761). A pack given a scoped
/// `reader` resolves them under it. Any other pack resolves them under its
/// own content `read` and admits each unit and owner as its edge walk admits
/// a neighbor: visible, admitted by the disclosure `clamp`, and kept by no
/// device-local world off this device.
pub(super) fn pack_instruction_files(
    read: &StoreRead<'_>,
    reader: Option<&crate::claim::ScopedRead<'_>>,
    rtxn: &RoTxn<'_>,
    results: &[ContextEntity],
    neighbors: &[ContextEntity],
    clamp: Option<&DisclosureContext>,
    device_local: Option<&BTreeSet<EntityId>>,
) -> Result<Vec<CodeInstructionHandle>> {
    let units: Vec<EntityId> = results.iter().chain(neighbors).map(|row| row.id).collect();
    if let Some(reader) = reader {
        return reader.context_pack_instruction_files_in(rtxn, &units, clamp);
    }
    crate::codebase::code_instruction_handles_in(read, rtxn, &units, |id| {
        Ok(crate::note::ordinary_entity_visible(read, rtxn, id)?
            && disclosure_admits_target(read, rtxn, clamp, id)?
            && match device_local {
                Some(flagged) => {
                    !crate::settings::device_local_keeps_among(read, rtxn, flagged, id)?
                }
                None => true,
            })
    })
}
