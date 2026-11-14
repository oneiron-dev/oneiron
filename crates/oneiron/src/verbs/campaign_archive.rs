//! Typed output-archive doors under the existing research-controller gate.
use super::research::controller_in_txn;
use crate::EntityId;
use crate::autoreason_campaign::archive::axes_job;
use crate::autoreason_campaign::archive::judge::{self, ArchiveJudgeBrief};
use crate::autoreason_campaign::archive::records::{self, attempt};
use crate::autoreason_campaign::archive::{
    ArchiveJudgeHost, CampaignArchiveAdmission, CampaignArchiveAxesQueued, CampaignArchiveCoverage,
    CampaignArchiveInstall, CampaignArchiveJudge, CampaignArchiveJudged, CampaignArchiveOutput,
    CampaignArchiveProposalRequest, CampaignArchiveProposalState, CampaignArchiveProposeAxes,
    CampaignArchiveRecord, CampaignArchiveReproposal, CampaignArchiveRequest, CampaignArchiveView,
};
use crate::claim::ClaimReadStatus;
use crate::memory::{MEMORY_CODE_MODEL_UNAVAILABLE, Memory, MemoryError, MemoryResult};

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

/// One output revision's placement and quality score for its campaign's
/// controller (ARM05 P3): the owner, or the agent running the root attempt.
/// `host` asks its decision ladder on the caller's own line, outside any
/// writer: one typed choice per pinned axis and one typed score under the
/// pinned judge rubric (an embedding-cluster campaign is placed by its
/// pinned on-device embedder instead). The engine records the placement and
/// score producer records the answer names; the caller never supplies its
/// own. The caller must read the output and the task, since their words go
/// to the ladder. An answer the archive does not take records nothing and is
/// refused with its reason.
pub fn research_archive_judge(
    memory: &Memory<'_>,
    input: CampaignArchiveJudge,
    host: &dyn ArchiveJudgeHost,
) -> MemoryResult<CampaignArchiveJudged> {
    let lane = memory.read_lane(ClaimReadStatus::Recorded)?;
    let vault = memory.vault();
    let brief = {
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        controller_in_txn(memory, &txn, Some(attempt(input.root)?))?;
        let (pin, output_text, rubric) = judge::premises_in_txn(vault, &txn, &input)?;
        if lane
            .entities_readable_in_txn(&txn, &[input.output.entity, pin.task()])?
            .contains(&false)
        {
            return Err(crate::Error::EntityNotFound.into());
        }
        let task = memory
            .get_entity_in_txn(&lane, &txn, pin.task())?
            .value
            .and_then(|view| view.body)
            .ok_or(crate::Error::EntityNotFound)?;
        ArchiveJudgeBrief {
            pin,
            task,
            output_text,
            rubric,
        }
    };
    // Outside any writer: the ladder and the embedder.
    let (basis, score) = judge::judgment(&brief, &input, host)?.map_err(|reason| {
        MemoryError::new(
            MEMORY_CODE_MODEL_UNAVAILABLE,
            format!("vault.research.archive.judge recorded nothing: {reason}"),
            &["Ask again once the decision ladder can answer; no placement or score was kept."],
        )
    })?;
    let principal = memory.actor();
    vault.try_with_write_txn_grouped(|txn| {
        controller_in_txn(memory, txn, Some(attempt(input.root)?))?;
        Ok(judge::mint_in_txn(
            vault, txn, input, basis, score, principal,
        )?)
    })
}
