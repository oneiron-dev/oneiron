//! What a code fix reads of the real failure behind its source: the text
//! and every world it touched, a failure no world of which can be proved, or
//! one whose run never gave this engine a model request (FIX 2343). A
//! blocked report whose run is no agent dispatch's attempt reads the source
//! its run's host kept with it.

use super::{CodeFixWithheld, FailureSource, failure_source_in};
use crate::attempt_queue::AttemptRecord;
use crate::self_heal::blocked_reports::{RunWorlds, blocked_source_in};
use crate::{EntityId, Result, Vault};

/// The real failure as a code fix reads it.
pub(crate) enum SubjectFailure {
    /// Its text and every world it touched.
    Read(FailureSource, Vec<EntityId>),
    /// The attempt is no agent dispatch this can read, or a world it touched
    /// cannot be proved.
    Unproved,
    /// No model request of the failing run ever reached this engine (FIX
    /// 2343): its caller ran the call outside it, so there is nothing to
    /// replay, and nothing stands in for it.
    Unavailable,
}

impl SubjectFailure {
    /// The text and worlds, or why a door withholds for want of them.
    pub(crate) fn read(
        self,
    ) -> std::result::Result<(FailureSource, Vec<EntityId>), CodeFixWithheld> {
        match self {
            Self::Read(failure, worlds) => Ok((failure, worlds)),
            Self::Unproved => Err(CodeFixWithheld::PrivateWorld),
            Self::Unavailable => Err(CodeFixWithheld::ReplayUnavailable),
        }
    }
}

/// A blocked report's failure from the source its run's host kept with it
/// (FIX 2343): the request's text, and the worlds the run's host scoped it
/// to. A run scoped to no dispatch may have read any world, so every world
/// the vault withholds from an unknown destination counts as touched, and a
/// conflicted vault root proves none. No source, or one with no request,
/// leaves the replay unavailable.
pub(super) fn blocked_source_failure_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    receipt: &EntityId,
) -> Result<SubjectFailure> {
    let Some(source) = blocked_source_in(vault, txn, receipt)? else {
        return Ok(SubjectFailure::Unavailable);
    };
    let Some(request) = source.request else {
        return Ok(SubjectFailure::Unavailable);
    };
    let worlds = match source.worlds {
        RunWorlds::Scoped { worlds } => worlds,
        RunWorlds::Unscoped => {
            let fold = vault.authority_view_readonly_in_txn(txn)?;
            let Ok(withheld) = fold.worlds_withheld_from(crate::authority::Destination::Unknown)
            else {
                return Ok(SubjectFailure::Unproved);
            };
            std::iter::once(crate::claim::base_world_id())
                .chain(withheld)
                .collect()
        }
        RunWorlds::Unproved => return Ok(SubjectFailure::Unproved),
    };
    Ok(SubjectFailure::Read(
        FailureSource {
            instructions: request.instructions,
            briefing: request.briefing,
            task: request.task,
        },
        worlds,
    ))
}

/// The worlds the agent dispatch `attempt` touched: its scope's and its
/// task's. `None` when it is no agent dispatch this can read, or a world
/// cannot be proved.
pub(crate) fn dispatch_worlds_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: &AttemptRecord,
) -> Result<Option<Vec<EntityId>>> {
    Ok(
        failure_source_in(vault, txn, attempt.task_ref.as_deref(), attempt)?
            .map(|(_, worlds)| worlds),
    )
}
