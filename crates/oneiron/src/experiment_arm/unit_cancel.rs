//! `vault.arms.units.cancel` (design pass 32 r2, sections 5.2 and 5.3): the owner, or the agent
//! that reserved a unit, withdraws it while its job has not started, or cancels its started job
//! through a scoped path: the door judges the lead role and "the reserver, or the owner", and
//! the caller needs no `vault.gpu.jobs.cancel` Grant.

use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::gpu_line::claim::release_claim_in_txn;
use crate::gpu_line::doors_caller::{self, LineCaller};
use crate::gpu_line::{ClaimKey, ClaimState, UnitEnd, UnitTerminal, claim_in_txn, line_in_txn};
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::{EntityId, Vault};

use super::reserve::{check_unit_shape, invalid_state, not_found, role_for};
use super::unit_view::UnitView;

/// The verb that withdraws a unit, or cancels its started job.
pub const ARMS_UNITS_CANCEL_VERB: &str = "vault.arms.units.cancel";

/// What `vault.arms.units.cancel` decided in its write.
#[derive(Debug)]
pub enum UnitCancel {
    /// The unit was withdrawn before its job started (or this is a repeat of that).
    Withdrawn(UnitView),
    /// The unit's job has started, and the caller may cancel it: the door ends the job with
    /// [`Vault::cancel_unit_gpu_job`]. The claim ends at the job's terminal.
    JobStarted(StartedUnitCancel),
}

/// The door's admission of a cancel of a unit whose job started. Only
/// [`unit_cancel_as`] makes one, after the line, the role and the reserver were judged, and only
/// [`Vault::cancel_unit_gpu_job`] spends it.
#[derive(Debug)]
pub struct StartedUnitCancel {
    pub(crate) claim: ClaimKey,
    pub(crate) job: EntityId,
    view: UnitView,
}

impl StartedUnitCancel {
    /// The unit's job: the claim's id.
    #[must_use]
    pub fn job(&self) -> EntityId {
        self.job
    }

    /// The unit as the cancel read it, its claim still started.
    #[must_use]
    pub fn view(&self) -> &UnitView {
        &self.view
    }
}

/// The release reason of a unit its lead or the owner withdrew before its job started.
const WITHDRAWN: &str = "withdrawn";

/// `vault.arms.units.cancel`: the unit to withdraw, by its logical key.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UnitCancelRequest {
    /// The lane project the line is set on.
    pub line: EntityId,
    pub arm: EntityId,
    pub rung: u8,
    pub unit_key: String,
    pub attempt: u16,
}

/// `vault.arms.units.cancel` as `memory`'s caller, with the owner's own proof when its
/// credential is owner-grade: withdraws the unit the request names while its job has not
/// started, ending its claim `Released("withdrawn")` and returning its draws, or admits the
/// cancel of its started job ([`UnitCancel::JobStarted`]). The owner may cancel any unit; an
/// agent only one it reserved, under the role it reserved it with.
///
/// # Errors
///
/// `bad_request` for a malformed ask; `forbidden` for a caller whose Grant does not reach the
/// line, holds no lead (reviewer) role on it, or did not reserve the unit
/// (`not_the_reserver`); `not_found` for an unknown line or unit; `invalid_state` for a unit
/// that ended otherwise (`claim_ended`); a store failure. A repeat of a withdrawal answers the
/// withdrawn claim, `replayed`.
pub fn unit_cancel_as(
    memory: &Memory<'_>,
    owner: Option<&AuthenticatedOwner>,
    request: &UnitCancelRequest,
    now_ms: u64,
) -> MemoryResult<UnitCancel> {
    check_unit_shape(request.rung, &request.unit_key, request.attempt)?;
    let vault = memory.vault();
    vault.try_with_write_txn_grouped(|wtxn| {
        cancel_in_txn(vault, wtxn, memory, owner, request, now_ms)
    })
}

fn cancel_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    memory: &Memory<'_>,
    owner: Option<&AuthenticatedOwner>,
    request: &UnitCancelRequest,
    now_ms: u64,
) -> MemoryResult<UnitCancel> {
    let caller =
        doors_caller::admit_in_txn(memory, wtxn, owner, ARMS_UNITS_CANCEL_VERB, request.line)?;
    let line = line_in_txn(vault, wtxn, &request.line)?
        .ok_or_else(|| not_found("no GPU line is set for this project"))?;
    let key = ClaimKey::of(
        request.arm,
        request.rung,
        &request.unit_key,
        request.attempt,
    );
    let claim = claim_in_txn(vault, wtxn, &key)?
        .filter(|claim| claim.line == request.line)
        .ok_or_else(|| {
            not_found("no unit claim of this line has this arm, rung, unit key and attempt")
        })?;
    if let LineCaller::Agent { .. } = caller {
        caller.require_role(&line, &[role_for(claim.purpose)], ARMS_UNITS_CANCEL_VERB)?;
        if claim.reserved_by != Some(memory.actor()) {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "vault.arms.units.cancel: not_the_reserver: only the caller who reserved this unit, or the owner, cancels it",
                &["Ask the unit's reserver or the owner to cancel it."],
            ));
        }
    }
    match &claim.state {
        ClaimState::Claimed => {
            let ended =
                release_claim_in_txn(vault, wtxn, &claim, WITHDRAWN, now_ms)?.ok_or_else(|| {
                    invalid_state("the claim changed under this cancel; read it and ask again")
                })?;
            Ok(UnitCancel::Withdrawn(UnitView::of(&ended, None, false)))
        }
        ClaimState::Started => Ok(UnitCancel::JobStarted(StartedUnitCancel {
            claim: key,
            job: claim.id,
            view: UnitView::of(&claim, None, false),
        })),
        ClaimState::Ended(UnitTerminal {
            end: UnitEnd::Released(reason),
            ..
        }) if reason == WITHDRAWN => Ok(UnitCancel::Withdrawn(UnitView::of(&claim, None, true))),
        ClaimState::Ended(_) => Err(invalid_state(
            "claim_ended: the unit has already ended; its terminal stands",
        )),
    }
}
