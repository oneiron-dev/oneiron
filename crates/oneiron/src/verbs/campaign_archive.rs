//! Typed output-archive doors under the existing research-controller gate.
use super::research::controller_in_txn;
use crate::autoreason_campaign::archive::records::{self, attempt};
use crate::autoreason_campaign::archive::{
    CampaignArchiveAdmission, CampaignArchiveCoverage, CampaignArchiveInstall,
    CampaignArchiveOutput, CampaignArchiveRecord, CampaignArchiveReproposal,
    CampaignArchiveRequest, CampaignArchiveView,
};
use crate::memory::{Memory, MemoryResult};

pub fn research_archive_install(
    memory: &Memory<'_>,
    input: CampaignArchiveInstall,
) -> MemoryResult<CampaignArchiveView> {
    memory.vault().try_with_write_txn_grouped(|txn| {
        controller_in_txn(memory, txn, Some(attempt(input.root)?))?;
        Ok(records::install_in_txn(memory.vault(), txn, input)?)
    })
}

pub fn research_archive_record(
    memory: &Memory<'_>,
    input: CampaignArchiveOutput,
) -> MemoryResult<CampaignArchiveView> {
    memory.vault().try_with_write_txn_grouped(|txn| {
        controller_in_txn(memory, txn, Some(attempt(input.root)?))?;
        Ok(records::record_in_txn(memory.vault(), txn, input)?)
    })
}

pub fn research_archive_get(
    memory: &Memory<'_>,
    input: CampaignArchiveRequest,
) -> MemoryResult<CampaignArchiveRecord> {
    let txn = memory
        .vault()
        .store
        .env
        .read_txn()
        .map_err(crate::Error::from)?;
    let root = attempt(input.root)?;
    controller_in_txn(memory, &txn, Some(root))?;
    Ok(records::read_in_txn(memory.vault(), &txn, root)?)
}

pub fn research_archive_best(
    memory: &Memory<'_>,
    input: CampaignArchiveRequest,
) -> MemoryResult<CampaignArchiveView> {
    Ok(records::view(&research_archive_get(memory, input)?)?)
}

pub fn research_archive_repropose(
    memory: &Memory<'_>,
    input: CampaignArchiveReproposal,
) -> MemoryResult<CampaignArchiveView> {
    memory.vault().try_with_write_txn_grouped(|txn| {
        controller_in_txn(memory, txn, Some(attempt(input.root)?))?;
        controller_in_txn(memory, txn, Some(attempt(input.new_root)?))?;
        Ok(records::repropose_in_txn(memory.vault(), txn, input)?)
    })
}

pub fn research_archive_coverage(
    memory: &Memory<'_>,
    input: CampaignArchiveCoverage,
) -> MemoryResult<CampaignArchiveAdmission> {
    memory.vault().try_with_write_txn_grouped(|txn| {
        controller_in_txn(memory, txn, Some(attempt(input.root)?))?;
        Ok(records::coverage_in_txn(memory.vault(), txn, input)?)
    })
}
