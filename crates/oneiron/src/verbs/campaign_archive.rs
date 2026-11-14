//! Typed output-archive doors under the existing research-controller gate.
use super::research::controller_in_txn;
use crate::EntityId;
use crate::autoreason_campaign::archive::axes_job;
use crate::autoreason_campaign::archive::records::{self, attempt};
use crate::autoreason_campaign::archive::{
    CampaignArchiveAdmission, CampaignArchiveAxesQueued, CampaignArchiveCoverage,
    CampaignArchiveInstall, CampaignArchiveOutput, CampaignArchiveProposalRequest,
    CampaignArchiveProposalState, CampaignArchiveProposeAxes, CampaignArchiveRecord,
    CampaignArchiveReproposal, CampaignArchiveRequest, CampaignArchiveView,
};
use crate::claim::ClaimReadStatus;
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

/// Queues one request for the Coach's archive axes (ARM05 P2) and wakes the
/// host's Coach. The controller asks; the Coach answers on its own seat, and
/// the engine records the proposal under the Coach's authority: the caller
/// never supplies its own. The caller must read every sample it names, since
/// the axes are drawn from their words.
pub fn research_archive_propose_axes(
    memory: &Memory<'_>,
    input: CampaignArchiveProposeAxes,
) -> MemoryResult<CampaignArchiveAxesQueued> {
    let lane = memory.read_lane(ClaimReadStatus::Recorded)?;
    let vault = memory.vault();
    let request = vault.try_with_write_txn_grouped(|txn| -> MemoryResult<EntityId> {
        match &input {
            CampaignArchiveProposeAxes::First { root, .. } => {
                controller_in_txn(memory, txn, Some(attempt(*root)?))?;
            }
            CampaignArchiveProposeAxes::Reproposal { root, from } => {
                controller_in_txn(memory, txn, Some(attempt(*from)?))?;
                controller_in_txn(memory, txn, Some(attempt(*root)?))?;
            }
        }
        let record = axes_job::request_in_txn(vault, txn, &input)?;
        if lane
            .entities_readable_in_txn(txn, &record.sample_entities())?
            .contains(&false)
        {
            return Err(crate::Error::EntityNotFound.into());
        }
        Ok(axes_job::queue_in_txn(
            vault,
            txn,
            &record,
            vault.now_recorded_at(),
        )?)
    })?;
    vault.wake_coach_host();
    Ok(CampaignArchiveAxesQueued { request })
}

/// One axes request's state, for its campaign's controller. The axes are
/// drawn from the samples' words, so the state serves only a caller who
/// reads every sample now, as the caller who queued the request had to: a
/// read grant revoked since the request withholds its answer (#7966 review
/// round 1).
pub fn research_archive_proposal(
    memory: &Memory<'_>,
    input: CampaignArchiveProposalRequest,
) -> MemoryResult<CampaignArchiveProposalState> {
    let lane = memory.read_lane(ClaimReadStatus::Recorded)?;
    let txn = memory
        .vault()
        .store
        .env
        .read_txn()
        .map_err(crate::Error::from)?;
    let record = axes_job::request_record_in_txn(memory.vault(), &txn, input.request)?;
    controller_in_txn(memory, &txn, Some(attempt(record.root())?))?;
    if lane
        .entities_readable_in_txn(&txn, &record.sample_entities())?
        .contains(&false)
    {
        return Err(crate::Error::EntityNotFound.into());
    }
    Ok(record.into_state())
}
