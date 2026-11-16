//! Typed output-archive doors under the existing research-controller gate.
use super::research::controller_in_txn;
use crate::EntityId;
use crate::autoreason_campaign::archive::axes_job;
use crate::autoreason_campaign::archive::records::{self, attempt};
use crate::autoreason_campaign::archive::{
    CampaignArchiveAdmission, CampaignArchiveAxesQueued, CampaignArchiveCoverage,
    CampaignArchiveInstall, CampaignArchiveOutput, CampaignArchivePin,
    CampaignArchiveProposalRequest, CampaignArchiveProposalState, CampaignArchiveProposeAxes,
    CampaignArchiveRecord, CampaignArchiveReproposal, CampaignArchiveRequest, CampaignArchiveView,
};
use crate::claim::{ClaimReadStatus, ScopedRead};
use crate::memory::{Memory, MemoryResult};

/// Refuses a caller who does not read every row of `rows` now, as rows it
/// cannot see. An archive's axes and bins carry the words of the rows they
/// were drawn from, the campaign's goal claim and each sample, so a door
/// that queues a request, serves its answer, or serves a pin, a view of one
/// or a cell under one serves only a caller who reads them all: a read grant
/// revoked since the request withholds the archive too (#7966 review rounds
/// 1 and 2; the goal claim, #8786 review round 2).
fn sources_read_in_txn(
    lane: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    rows: &[EntityId],
) -> MemoryResult<()> {
    if lane.entities_readable_in_txn(txn, rows)?.contains(&false) {
        return Err(crate::Error::EntityNotFound.into());
    }
    Ok(())
}

/// [`sources_read_in_txn`] for an installed pin: its goal claim and every
/// sample it was drawn from.
fn pin_sources_read_in_txn(
    lane: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    pin: &CampaignArchivePin,
) -> MemoryResult<()> {
    let mut rows = vec![pin.goal_ref()];
    rows.extend(pin.sample_outputs().iter().map(|output| output.entity));
    sources_read_in_txn(lane, txn, &rows)
}

pub fn research_archive_install(
    memory: &Memory<'_>,
    input: CampaignArchiveInstall,
) -> MemoryResult<CampaignArchiveView> {
    let lane = memory.read_lane(ClaimReadStatus::Recorded)?;
    memory.vault().try_with_write_txn_grouped(|txn| {
        controller_in_txn(memory, txn, Some(attempt(input.root)?))?;
        let view = records::install_in_txn(memory.vault(), txn, input)?;
        pin_sources_read_in_txn(&lane, txn, &view.pin)?;
        Ok(view)
    })
}

pub fn research_archive_record(
    memory: &Memory<'_>,
    input: CampaignArchiveOutput,
) -> MemoryResult<CampaignArchiveView> {
    let lane = memory.read_lane(ClaimReadStatus::Recorded)?;
    memory.vault().try_with_write_txn_grouped(|txn| {
        controller_in_txn(memory, txn, Some(attempt(input.root)?))?;
        let view = records::record_in_txn(memory.vault(), txn, input)?;
        pin_sources_read_in_txn(&lane, txn, &view.pin)?;
        Ok(view)
    })
}

pub fn research_archive_get(
    memory: &Memory<'_>,
    input: CampaignArchiveRequest,
) -> MemoryResult<CampaignArchiveRecord> {
    let lane = memory.read_lane(ClaimReadStatus::Recorded)?;
    let txn = memory
        .vault()
        .store
        .env
        .read_txn()
        .map_err(crate::Error::from)?;
    let root = attempt(input.root)?;
    controller_in_txn(memory, &txn, Some(root))?;
    let record = records::read_in_txn(memory.vault(), &txn, root)?;
    pin_sources_read_in_txn(&lane, &txn, &record.pin)?;
    Ok(record)
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
    let lane = memory.read_lane(ClaimReadStatus::Recorded)?;
    memory.vault().try_with_write_txn_grouped(|txn| {
        let root = attempt(input.root)?;
        controller_in_txn(memory, txn, Some(root))?;
        controller_in_txn(memory, txn, Some(attempt(input.new_root)?))?;
        let held = records::read_in_txn(memory.vault(), txn, root)?;
        pin_sources_read_in_txn(&lane, txn, &held.pin)?;
        let view = records::repropose_in_txn(memory.vault(), txn, input)?;
        pin_sources_read_in_txn(&lane, txn, &view.pin)?;
        Ok(view)
    })
}

pub fn research_archive_coverage(
    memory: &Memory<'_>,
    input: CampaignArchiveCoverage,
) -> MemoryResult<CampaignArchiveAdmission> {
    let lane = memory.read_lane(ClaimReadStatus::Recorded)?;
    memory.vault().try_with_write_txn_grouped(|txn| {
        let root = attempt(input.root)?;
        controller_in_txn(memory, txn, Some(root))?;
        let held = records::read_in_txn(memory.vault(), txn, root)?;
        pin_sources_read_in_txn(&lane, txn, &held.pin)?;
        Ok(records::coverage_in_txn(memory.vault(), txn, input)?)
    })
}

/// Queues one request for the Coach's archive axes (ARM05 P2) and wakes the
/// host's Coach. The controller asks; the Coach answers on its own seat, and
/// the engine records the proposal under the Coach's authority: the caller
/// never supplies its own. The caller must read the goal claim and every
/// sample it names, since the Coach draws the axes from their words.
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
        sources_read_in_txn(&lane, txn, &record.source_rows())?;
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
/// drawn from the goal's and the samples' words, so the state serves only a
/// caller who reads the goal claim and every sample now, as the caller who
/// queued the request had to: a read grant revoked since the request
/// withholds its answer (#7966 review round 1; the goal claim, #8786 review
/// round 2).
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
    sources_read_in_txn(&lane, &txn, &record.source_rows())?;
    Ok(record.into_state())
}
