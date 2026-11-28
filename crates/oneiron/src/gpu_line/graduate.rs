//! `vault.gpu.lines.families.graduate` (design pass 32 r2, sections 4.1
//! graduation and 5.2 row 2b; LE-6; row M2-E): after one independently
//! confirmed promote on an arm of a new-idea seat, a lead moves the family
//! to demand, or the owner moves it to interest.
//!
//! - The seat changes in place. It keeps its id, `replaces`, its late floor
//!   and its history; `graduated` names the confirmed promote it rests on.
//!   The verb never adds a seat, so one project never holds two kinds.
//! - The period already minted stays as it is: the seat keeps its slot's
//!   floor for the rest of the period. Its new kind's floor and, for demand,
//!   its market ceiling start with the next mint, which must fund them.
//! - A confirmed promote is a rung closed `Promoted` by a `confirmed` review
//!   (`vault.arms.review` judges the reviewer's independence). A promote
//!   still awaiting review, a kill, or a promote on another seat of the same
//!   family does not qualify.
//!
//! The mint's lapse reads [`promoted_seats_in_txn`] too: a new idea with a
//! confirmed promote does not lapse (4.1: "a seat with no confirmed promote
//! lapses"), so it can still graduate after its funded periods. It draws
//! nothing until it does (`FamilySeat::funded_in`).
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::doors::{
    GpuLineError, lead_seat_cap, live_seats, next_mint_index, track_name, view_in_txn,
};
use super::doors_caller::{admit_in_txn, refused_owner_act};
use super::fold::{Graduation, LineRole, Track};
use super::intent::{IntentAsk, IntentStand};
use super::mint::LineInvalid;
use super::store::{line_in_txn, mint_first_in_txn, put_line_in_txn};
use super::wire::GpuLineView;
use crate::consent::AuthenticatedOwner;
use crate::experiment_arm::{ArmReviewVerdict, ExperimentArm, RungEnd, RungState};
use crate::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult,
};
use crate::{EntityId, Vault};

/// Moves a new-idea family of a lane's GPU line to demand or interest.
pub const VAULT_GPU_LINES_FAMILIES_GRADUATE: &str = "vault.gpu.lines.families.graduate";

/// The ask of `vault.gpu.lines.families.graduate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GpuLineFamilyGraduateRequest {
    /// As in [`super::GpuLineSetRequest::intent_key`].
    pub intent_key: String,
    /// The lane project.
    pub project: EntityId,
    /// The family: the project of the new-idea seat.
    pub family: EntityId,
    /// `demand` (a lead) or `interest` (the owner).
    pub to: Track,
}

/// The lowest rung of `arm` that closed on an independently confirmed
/// promote, with the review's time.
fn confirmed_promote(arm: &ExperimentArm) -> Option<(u8, u64)> {
    arm.rungs.iter().find_map(|rung| {
        let promoted = matches!(
            rung.state,
            RungState::Closed {
                end: RungEnd::Promoted
            }
        ) && rung.outcome.as_ref().is_some_and(|outcome| outcome.success);
        let review = rung
            .review
            .as_ref()
            .filter(|review| review.verdict == ArmReviewVerdict::Confirmed)?;
        promoted.then_some((rung.rung, review.at_ms))
    })
}

/// The arm and rung of the earliest confirmed promote on an arm of seat
/// `seat` of `line`'s line.
fn seat_promote_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    line: &EntityId,
    seat: &EntityId,
) -> crate::Result<Option<(EntityId, u8)>> {
    let mut earliest: Option<(u64, EntityId, u8)> = None;
    for arm in vault
        .experiment_arms_in_txn(txn)?
        .iter()
        .filter(|arm| arm.line == *line && arm.seat == *seat)
    {
        if let Some((rung, at_ms)) = confirmed_promote(arm)
            && earliest.is_none_or(|(first, ..)| at_ms < first)
        {
            earliest = Some((at_ms, arm.id, rung));
        }
    }
    Ok(earliest.map(|(_, arm, rung)| (arm, rung)))
}

/// The seats of `line`'s line with a confirmed promote on one of their arms.
///
/// # Errors
///
/// A store read failure.
pub(super) fn promoted_seats_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    line: &EntityId,
) -> crate::Result<BTreeSet<EntityId>> {
    Ok(vault
        .experiment_arms_in_txn(txn)?
        .into_iter()
        .filter(|arm| arm.line == *line && confirmed_promote(arm).is_some())
        .map(|arm| arm.seat)
        .collect())
}

impl Memory<'_> {
    /// `vault.gpu.lines.families.graduate`: moves the new-idea seat of
    /// `request.family` on `request.project`'s line to `request.to`.
    ///
    /// # Errors
    ///
    /// `bad_request` for a malformed ask (a `to` of `new_idea`) or a blank
    /// intent key; `forbidden` for a caller the door does not admit, a Grant
    /// that holds no lead role on this line, a graduation to interest asked
    /// without the owner's proof, or a lead's graduation past the line's
    /// seat cap for the kind; `not_found` for no line; `invalid_state` for a
    /// family with no seat in force (`seat_lapsed`), a seat that is not a new
    /// idea (`not_new_idea`), no confirmed promote on an arm of the seat
    /// (`no_confirmed_promote`), an intent key that names another ask, a
    /// period that cannot be minted, or a floor the next mint could not fund.
    /// The current period is minted first and stays minted.
    pub fn graduate_gpu_line_family(
        &self,
        owner: Option<&AuthenticatedOwner>,
        request: &GpuLineFamilyGraduateRequest,
        now_ms: u64,
    ) -> MemoryResult<GpuLineView> {
        if request.to == Track::NewIdea {
            return Err(bad_request(
                "a new-idea seat graduates to demand or interest",
            ));
        }
        let verb = VAULT_GPU_LINES_FAMILIES_GRADUATE;
        let vault = self.vault();
        let ask = IntentAsk::new(
            self.actor(),
            verb,
            &request.intent_key,
            &(request.project, request.family, request.to),
        )?;
        vault.with_write_txn_grouped(|txn| -> crate::Result<MemoryResult<GpuLineView>> {
            let caller = match admit_in_txn(self, txn, owner, verb, request.project) {
                Ok(caller) => caller,
                Err(refusal) => return Ok(Err(refusal)),
            };
            // The role is judged on the stored line before anything else: a
            // replay answers, and a mint writes, only for a caller who holds
            // it now. Interest is the owner's alone (LE-6).
            let Some(stored) = line_in_txn(vault, txn, &request.project)? else {
                return Ok(Err(GpuLineError::NoLine.into()));
            };
            if request.to == Track::Interest {
                if caller.owner().is_none() {
                    return Ok(Err(refused_owner_act(
                        verb,
                        "graduating a new idea to interest",
                    )));
                }
            } else if let Err(refusal) = caller.require_role(&stored, &[LineRole::Lead], verb) {
                return Ok(Err(refusal));
            }
            match ask.stand_in_txn(vault, txn)? {
                Err(refused) => return Ok(Err(refused.into())),
                Ok(IntentStand::Replayed(_)) => {
                    return Ok(view_in_txn(vault, txn, stored, now_ms, true)?.map_err(Into::into));
                }
                Ok(IntentStand::New) => {}
            }
            let minted = match mint_first_in_txn(vault, txn, &request.project, now_ms)? {
                Ok(Some(minted)) => minted,
                Ok(None) => return Ok(Err(GpuLineError::NoLine.into())),
                Err(refusal) => return Ok(Err(GpuLineError::Mint(refusal).into())),
            };
            let mut line = minted.line.clone();
            let Some(seat) = line.seat(&request.family) else {
                return Ok(Err(invalid_state(
                    "seat_lapsed: the family holds no seat in force on this line",
                )));
            };
            // The logical key is the family: a seat already graduated to the
            // asked kind answers again under any intent key.
            if seat.graduated.is_some() && seat.track == request.to {
                ask.keep_in_txn(vault, txn, request.family.as_bytes().to_vec(), now_ms)?;
                return Ok(view_in_txn(vault, txn, line, now_ms, true)?.map_err(Into::into));
            }
            if seat.track != Track::NewIdea {
                return Ok(Err(invalid_state(&format!(
                    "not_new_idea: only a new-idea seat graduates; this family holds a {} seat",
                    track_name(seat.track)
                ))));
            }
            let seat_id = seat.seat;
            let Some((arm, rung)) = seat_promote_in_txn(vault, txn, &request.project, &seat_id)?
            else {
                return Ok(Err(invalid_state(
                    "no_confirmed_promote: no arm of this seat holds an independently confirmed promote",
                )));
            };
            // A lead's cap is the policy in force, as at admission: the
            // minted period's, or the line's before period 0.
            let in_force = minted
                .period
                .as_ref()
                .map_or(&line.budget, |period| &period.policy);
            if caller.owner().is_none()
                && let Some(cap) = lead_seat_cap(in_force, request.to)
                && live_seats(&line, request.to) >= cap as usize
            {
                return Ok(Err(refused_owner_act(
                    verb,
                    &format!(
                        "graduating a family to {} past the line's cap of {cap} such seats",
                        track_name(request.to)
                    ),
                )));
            }
            let next = match next_mint_index(&minted) {
                Ok(next) => next,
                Err(refusal) => return Ok(Err(refusal.into())),
            };
            let by = caller.owner().unwrap_or_else(|| self.actor());
            for seat in line.families.iter_mut().filter(|seat| seat.seat == seat_id) {
                seat.graduated = Some(Graduation {
                    from: Track::NewIdea,
                    by: Some(by),
                    at_ms: now_ms,
                    arm,
                    rung,
                });
                seat.track = request.to;
            }
            // The new kind is listed from the next mint: it must fund it.
            match line.validate(next) {
                Ok(()) => {}
                Err(LineInvalid::Unfunded { side }) => {
                    return Ok(Err(GpuLineError::SeatFloorUnfunded { side }.into()));
                }
                Err(invalid) => return Ok(Err(GpuLineError::Invalid(invalid).into())),
            }
            line.revision += 1;
            put_line_in_txn(vault, txn, &line)?;
            ask.keep_in_txn(vault, txn, request.family.as_bytes().to_vec(), now_ms)?;
            Ok(view_in_txn(vault, txn, line, now_ms, false)?.map_err(Into::into))
        })?
    }
}

fn bad_request(why: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_BAD_REQUEST,
        why,
        &["Name demand (a lead) or interest (the owner) in `to`."],
    )
}

fn invalid_state(why: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        why,
        &["Read the line with vault.gpu.lines.get and its arms with vault.arms.list."],
    )
}
