//! `vault.arms.units.reserve` (design pass 32 r2, sections 3.4, 3.5 and 5.2): one unit claim
//! on an open arm's rung, checked and written in one write transaction, so two reserves never
//! both take the last room. The cancel is [`super::unit_cancel`]; both answer a
//! [`super::unit_view::UnitView`].
//!
//! The intent key names the call; the logical key (arm, rung, unit key, attempt) names the
//! claim. The same logical key with the same ask answers the stored claim under any intent
//! key, so a retry after a lost answer makes no second claim. Attempt `n + 1` needs attempt
//! `n` ended: an unconfirmed unit admits no successor.
//!
//! Refusals: a precondition writes nothing; a budget refusal (`over_rung_cap`,
//! `budget_denied`) writes one `GPU_LINE_REFUSAL` row and nothing else. A claim still
//! `Claimed` past its custody (`claim_custody_secs` of its period's policy) is released by a
//! compare-and-set on its revision, here or by a late start; one of them wins.
//!
//! The quote, the start through the one gate in `start_gpu_job` and the cancel of a started
//! unit's job are row M2-C's second part.

use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::gpu_line::claim::release_claim_in_txn;
use crate::gpu_line::doors_caller::{self, LineCaller};
use crate::gpu_line::{
    Bucket, ClaimAdmissionRefused, ClaimKey, ClaimState, DrawAsk, DrawPurpose, IntentAsk,
    IntentStand, LineRefusal, LineRole, PeriodRoom, Track, UnitClaim, UnitEnd, UnitPurpose,
    UnitTerminal, claim_in_txn, claims_at_rung_in_txn, custody_lapsed_in_txn, gpu_seconds,
    mint_first_in_txn, open_claim_in_txn, plan_draws, record_line_refusal_in_txn,
};
use crate::job_workload::{WorkloadStartAsk, WorkloadStarter};
use crate::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_BUDGET_SPENT, MEMORY_CODE_INVALID_STATE,
    MEMORY_CODE_NOT_FOUND, Memory, MemoryError, MemoryResult,
};
use crate::{EntityId, Vault};

use super::unit_view::UnitView;
use super::{ExperimentArm, RungState};

/// The verb that reserves one unit of an arm's rung.
pub const ARMS_UNITS_RESERVE_VERB: &str = "vault.arms.units.reserve";
/// The release reason of a unit whose job did not start within its custody.
const CUSTODY_LAPSED: &str = "custody_lapsed";
/// The longest unit key, in bytes.
const UNIT_KEY_MAX_BYTES: usize = 256;
/// The longest offer name, workload digest or code revision, in bytes.
const UNIT_TEXT_MAX_BYTES: usize = 512;

/// `vault.arms.units.reserve`: one unit of an arm's rung, under the caller's intent key.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UnitReserveRequest {
    /// The caller's key for this call: the same key and ask answer the stored claim.
    pub intent_key: String,
    /// The lane project the line is set on.
    pub line: EntityId,
    pub arm: EntityId,
    /// The arm's current rung; 1 is the first.
    pub rung: u8,
    /// The unit's name within the rung, the caller's choice.
    pub unit_key: String,
    /// 1 is the first attempt; attempt `n + 1` needs attempt `n` ended.
    pub attempt: u16,
    /// `work` (the lead's) or `review_check` (the reviewer's, while the rung awaits review).
    pub purpose: UnitPurpose,
    /// The offer the unit runs on: one the line names.
    pub offer: String,
    /// The approved workload's digest (pass 33 `JOB_WORKLOAD`).
    pub workload: String,
    /// A machine of the line, or none for any of them.
    #[serde(default)]
    pub machine: Option<EntityId>,
    /// The code revision the workload pin carries.
    pub code_sha: String,
    /// The contract sha256 the arm pins.
    pub contract_sha256: String,
    /// The unit's seconds: exactly the workload pin's maximum, so the machine's own limit is
    /// the reservation.
    pub secs: u64,
}

/// What a reserve compares under its logical key: the ask without its intent key.
#[derive(Serialize)]
struct UnitAsk<'a> {
    line: EntityId,
    arm: EntityId,
    rung: u8,
    unit_key: &'a str,
    attempt: u16,
    purpose: UnitPurpose,
    offer: &'a str,
    workload: &'a str,
    machine: Option<EntityId>,
    code_sha: &'a str,
    contract_sha256: &'a str,
    secs: u64,
}

impl UnitReserveRequest {
    fn ask(&self) -> UnitAsk<'_> {
        UnitAsk {
            line: self.line,
            arm: self.arm,
            rung: self.rung,
            unit_key: &self.unit_key,
            attempt: self.attempt,
            purpose: self.purpose,
            offer: &self.offer,
            workload: &self.workload,
            machine: self.machine,
            code_sha: &self.code_sha,
            contract_sha256: &self.contract_sha256,
            secs: self.secs,
        }
    }

    fn check_shape(&self) -> MemoryResult<()> {
        check_unit_shape(self.rung, &self.unit_key, self.attempt)?;
        for (field, text) in [
            ("offer", &self.offer),
            ("workload", &self.workload),
            ("code_sha", &self.code_sha),
        ] {
            if text.trim().is_empty() || text.len() > UNIT_TEXT_MAX_BYTES {
                return Err(bad_request(&format!(
                    "{field}: name it, in at most {UNIT_TEXT_MAX_BYTES} bytes"
                )));
            }
        }
        if !is_sha256_hex(&self.contract_sha256) {
            return Err(bad_request(
                "contract_sha256: 64 lower-case hex digits, the arm's pinned contract",
            ));
        }
        if self.secs == 0 {
            return Err(bad_request(
                "secs: a unit reserves at least one second, its workload pin's maximum",
            ));
        }
        Ok(())
    }
}

/// `vault.arms.units.reserve` as `memory`'s caller, with the owner's own proof when its
/// credential is owner-grade: the claim of one unit of an arm's current rung, at `now_ms`
/// on the host's clock, after the checks of design 5.2 in its order. The caller is judged
/// in the write: the line cover, then the lead role (the reviewer role for a review check).
///
/// # Errors
///
/// `bad_request` for a malformed ask or a blank intent key; `forbidden` for a caller whose
/// Grant does not reach the line or holds no lead (reviewer) role on it (`not_this_line`);
/// `not_found` for an unknown line or arm; `invalid_state` for a period not begun, a family
/// with no seat in force (`seat_lapsed`), another ask under the same logical attempt
/// (`attempt_conflict`) or intent key, attempt `n + 1` while attempt `n` is open
/// (`attempt_open`) or was never reserved (`attempt_not_next`), a closed arm or rung, a rung
/// not promoted (`rung_not_promoted`), a new idea past rung 1 (`new_idea_rung_one_only`), a
/// contract other than the pin (`contract_changed`), a workload that is not pinned, approved
/// or bound to the arm's contract and code (`workload_mismatch`), seconds other than the
/// pin's maximum (`maximum_mismatch`), a missing forecast (`forecast_missing`), an offer or
/// machine the line does not name (`offer_not_managed`, `machine_not_allowed`), a family at
/// its running cap (`family_running_cap`), a review check past the rung's seconds
/// (`over_review_check`) or a machine of the line that has not answered since this start
/// (`nodes_unanswered`); `budget_spent` for `over_rung_cap` and `budget_denied`, each after
/// its `GPU_LINE_REFUSAL` row is written; a store failure.
pub fn unit_reserve_as(
    memory: &Memory<'_>,
    owner: Option<&AuthenticatedOwner>,
    request: &UnitReserveRequest,
    now_ms: u64,
) -> MemoryResult<UnitView> {
    request.check_shape()?;
    let vault = memory.vault();
    // An outer `Err` discards the write; an inner one commits it: a budget refusal keeps its
    // refusal row (and the period record a first touch minted).
    vault.try_with_write_txn_grouped(|wtxn| {
        reserve_in_txn(vault, wtxn, memory, owner, request, now_ms)
    })?
}

fn reserve_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    memory: &Memory<'_>,
    owner: Option<&AuthenticatedOwner>,
    request: &UnitReserveRequest,
    now_ms: u64,
) -> MemoryResult<MemoryResult<UnitView>> {
    // 1. The line, the caller's role, the family's seat, the period.
    let caller =
        doors_caller::admit_in_txn(memory, wtxn, owner, ARMS_UNITS_RESERVE_VERB, request.line)?;
    let minted = match mint_first_in_txn(vault, wtxn, &request.line, now_ms)? {
        Ok(Some(minted)) => minted,
        Ok(None) => return Err(not_found("no GPU line is set for this project")),
        Err(refusal) => {
            return Err(invalid_state(&format!(
                "the line's period cannot be minted: {refusal}"
            )));
        }
    };
    let line = minted.line;
    caller.require_role(&line, &[role_for(request.purpose)], ARMS_UNITS_RESERVE_VERB)?;
    let period = minted.period.ok_or_else(|| {
        invalid_state(
            "period_not_begun: the line's first period has not begun; reserve once it starts",
        )
    })?;
    let asker = memory.actor();
    let intent = IntentAsk::new(
        asker,
        ARMS_UNITS_RESERVE_VERB,
        &request.intent_key,
        &request.ask(),
    )?;
    if let IntentStand::Replayed(written) = intent.stand_in_txn(vault, wtxn)?? {
        let claim = match ClaimKey::from_key_bytes(&written) {
            Some(key) => claim_in_txn(vault, wtxn, &key)?,
            None => None,
        }
        .ok_or_else(|| not_found("the claim this intent key reserved is gone"))?;
        return Ok(Ok(answer_again(vault, wtxn, claim, now_ms)?));
    }

    let arm = vault
        .experiment_arm_in_txn(wtxn, &request.arm)?
        .filter(|arm| arm.line == request.line)
        .ok_or_else(|| not_found("no experiment arm of this line has this id"))?;
    let seat = line.seat(&arm.family).ok_or_else(|| {
        invalid_state(
            "seat_lapsed: the arm's family holds no seat in force on this line; seat it with vault.gpu.lines.families.admit",
        )
    })?;

    // 2. The logical attempt.
    let key = ClaimKey::of(arm.id, request.rung, &request.unit_key, request.attempt);
    if let Some(claim) = claim_in_txn(vault, wtxn, &key)? {
        if claim.ask_digest != intent.ask_digest() {
            return Err(invalid_state(
                "attempt_conflict: this attempt of this unit is already reserved under another ask; reserve the next attempt once it ends",
            ));
        }
        intent.keep_in_txn(vault, wtxn, key.key_bytes(), now_ms)?;
        return Ok(Ok(answer_again(vault, wtxn, claim, now_ms)?));
    }
    if request.attempt > 1 {
        let before = ClaimKey::of(arm.id, request.rung, &request.unit_key, request.attempt - 1);
        match claim_in_txn(vault, wtxn, &before)? {
            None => {
                return Err(invalid_state(
                    "attempt_not_next: the attempt before this one was never reserved; attempts of a unit count up from 1",
                ));
            }
            Some(prior) if prior.is_open() => {
                // A claim whose job never started within its custody is released here, by
                // the same compare-and-set a late start uses.
                let released = custody_lapsed_in_txn(vault, wtxn, &prior, now_ms)?
                    && release_claim_in_txn(vault, wtxn, &prior, CUSTODY_LAPSED, now_ms)?.is_some();
                if !released {
                    return Err(invalid_state(
                        "attempt_open: the attempt before this one has not ended; an unconfirmed unit admits no successor",
                    ));
                }
            }
            Some(_) => {}
        }
    }

    // 3. The arm, its rung and the rung's state.
    if !arm.is_open() {
        return Err(invalid_state(
            "arm_closed: the arm has ended; it reserves no unit",
        ));
    }
    if seat.track == Track::NewIdea && request.rung > 1 {
        return Err(invalid_state(
            "new_idea_rung_one_only: a new idea's arm reserves at rung 1 only until its family graduates",
        ));
    }
    let current = arm.current_rung();
    if request.rung > current {
        return Err(invalid_state(
            "rung_not_promoted: the rung has no promotion record; a reviewer's confirm opens it",
        ));
    }
    let rung = arm
        .rungs
        .iter()
        .find(|rung| rung.rung == request.rung)
        .filter(|_| request.rung == current)
        .ok_or_else(|| invalid_state("rung_closed: the arm has moved past this rung"))?;
    if request.rung > 1 && rung.promotion.is_none() {
        return Err(invalid_state(
            "rung_not_promoted: the rung has no promotion record; a reviewer's confirm opens it",
        ));
    }
    match (request.purpose, &rung.state) {
        (UnitPurpose::Work, RungState::Open)
        | (UnitPurpose::ReviewCheck, RungState::AwaitingReview) => {}
        (UnitPurpose::Work, _) => {
            return Err(invalid_state(
                "rung_not_open: the rung awaits its review or has closed; it takes no work unit",
            ));
        }
        (UnitPurpose::ReviewCheck, _) => {
            return Err(invalid_state(
                "rung_not_under_review: a review check runs only while the rung awaits its review",
            ));
        }
    }

    // 4. The contract and the workload.
    if request.contract_sha256 != arm.contract.sha256 {
        return Err(invalid_state(
            "contract_changed: the contract sha256 is not the arm's pin; a changed contract is a new arm",
        ));
    }
    let workload = vault
        .job_workload_in_txn(wtxn, &request.workload)?
        .ok_or_else(|| {
            invalid_state("workload_mismatch: no workload is pinned under this digest")
        })?;
    if workload.pin.contract_sha256 != arm.contract.sha256
        || workload.pin.commit != request.code_sha
    {
        return Err(invalid_state(
            "workload_mismatch: the workload's pin does not carry the arm's contract sha256 and this code revision",
        ));
    }
    if request.secs != workload.pin.request.maximum_secs {
        return Err(invalid_state(&format!(
            "maximum_mismatch: the unit asks {} s and its workload pin's maximum is {} s; they must be equal",
            request.secs, workload.pin.request.maximum_secs
        )));
    }
    approved_on_a_machine(vault, wtxn, caller, request, &line.machines, now_ms)?;

    // 5. The forecast.
    if request.purpose == UnitPurpose::Work
        && period.policy.forecast_required
        && rung.forecast.is_none()
    {
        return Err(invalid_state(
            "forecast_missing: the line asks a runner's forecast before a rung's first unit; write it with vault.arms.forecast",
        ));
    }

    // 6. The offer and the machine, then the family's running cap (pass 34, 4.5).
    if !line.offers.contains(&request.offer) {
        return Err(invalid_state(
            "offer_not_managed: the line does not name this offer; reserve on one of the line's offers",
        ));
    }
    if request
        .machine
        .is_some_and(|machine| !line.machines.contains(&machine))
    {
        return Err(invalid_state(
            "machine_not_allowed: the machine is not one of the line's; name one of them or none",
        ));
    }
    let running_cap = period.policy.max_running_per_family;
    if running_cap > 0 && open_family_units(vault, wtxn, &arm)? >= u64::from(running_cap) {
        return Err(invalid_state(&format!(
            "family_running_cap: the family already holds {running_cap} open units, the line's cap; reserve once one ends"
        )));
    }

    // 7. The rung cap, or a review check's own seconds.
    let budget_ask = BudgetAsk {
        request,
        arm: &arm,
        period: period.index,
        asker,
        now_ms,
    };
    match request.purpose {
        UnitPurpose::Work => {
            let cap = period
                .policy
                .rung_caps_secs
                .get(usize::from(request.rung) - 1)
                .copied()
                .unwrap_or(0);
            let used = experiment_rung_secs(vault, wtxn, &arm, request.rung)?;
            if used.saturating_add(request.secs) > cap {
                let room = cap.saturating_sub(used);
                let refusal = MemoryError::new(
                    MEMORY_CODE_BUDGET_SPENT,
                    format!(
                        "over_rung_cap: rung {} holds or spent {used} s of its {cap} s cap over every attempt, period and superseded arm, and {} s more does not fit; {room} s do",
                        request.rung, request.secs
                    ),
                    &["Reserve a smaller unit, or ask for a verdict on the rung."],
                );
                return refused_for_budget(
                    vault,
                    wtxn,
                    &budget_ask,
                    BudgetShort {
                        short: None,
                        room,
                        reason: "over_rung_cap",
                        refusal,
                    },
                );
            }
        }
        UnitPurpose::ReviewCheck => {
            let used: u64 = claims_at_rung_in_txn(vault, wtxn, &arm.id, request.rung)?
                .iter()
                .filter(|claim| claim.purpose == UnitPurpose::ReviewCheck)
                .map(spent_secs)
                .sum();
            let bound = period.policy.review_check_secs;
            if used.saturating_add(request.secs) > bound {
                return Err(invalid_state(&format!(
                    "over_review_check: the rung's review checks hold or spent {used} s of the line's {bound} s, and {} s more does not fit",
                    request.secs
                )));
            }
        }
    }

    // 8. The draw plan of 4.2.
    let rows = vault.spend_rows_in_txn(wtxn, &request.line, &period, now_ms)?;
    let room = PeriodRoom::fold(&period, &line.families, &rows);
    let draws = match plan_draws(
        &room,
        &DrawAsk {
            arm: arm.id,
            family: arm.family,
            track: seat.track,
            purpose: DrawPurpose::Unit { rung: request.rung },
            units: request.secs,
        },
    ) {
        Ok(draws) => draws,
        Err(denied) => {
            let left = denied
                .room
                .iter()
                .map(|(bucket, left)| format!("{bucket:?} {left} s"))
                .collect::<Vec<_>>()
                .join(", ");
            let refusal = MemoryError::new(
                MEMORY_CODE_BUDGET_SPENT,
                format!(
                    "budget_denied: a unit of {} s does not fit; {:?} ran out ({left}); {} s fit now",
                    request.secs, denied.short, denied.fits
                ),
                &["Reserve a smaller unit, or wait for the next period."],
            );
            return refused_for_budget(
                vault,
                wtxn,
                &budget_ask,
                BudgetShort {
                    short: denied.short,
                    room: denied.fits,
                    reason: "budget_denied",
                    refusal,
                },
            );
        }
    };

    // 9. The claim, `Claimed`, with its fixed job id, draws, allocation and Grant.
    let claim = UnitClaim {
        id: EntityId::now(),
        arm: arm.id,
        rung: request.rung,
        unit_key: request.unit_key.clone(),
        attempt: request.attempt,
        line: request.line,
        family: arm.family,
        period: period.index,
        purpose: request.purpose,
        workload: request.workload.clone(),
        machine: request.machine,
        code_sha: request.code_sha.clone(),
        contract_sha256: request.contract_sha256.clone(),
        reserved_secs: request.secs,
        draws,
        wallet: period.allocation.wallet.clone(),
        allocation: period.allocation.allocation(gpu_seconds()).reference,
        grant: match caller {
            LineCaller::Owner(_) => None,
            LineCaller::Agent { grant } => Some(grant),
        },
        reserved_by: Some(asker),
        reserved_at_ms: now_ms,
        ask_digest: intent.ask_digest().to_owned(),
        state: ClaimState::Claimed,
        revision: 1,
    };
    let allocation = period.allocation.allocation(gpu_seconds());
    match open_claim_in_txn(vault, wtxn, &allocation, &line.machines, &claim)? {
        Ok(standing) => {
            intent.keep_in_txn(vault, wtxn, key.key_bytes(), now_ms)?;
            Ok(Ok(UnitView::of(&claim, Some(standing.room()), false)))
        }
        Err(ClaimAdmissionRefused::Exhausted { room }) => {
            let refusal = MemoryError::new(
                MEMORY_CODE_BUDGET_SPENT,
                format!(
                    "budget_denied: the period's allocation has {room} s left and the unit asks {} s",
                    request.secs
                ),
                &["Reserve a smaller unit, or wait for the next period."],
            );
            refused_for_budget(
                vault,
                wtxn,
                &budget_ask,
                BudgetShort {
                    short: None,
                    room,
                    reason: "budget_denied",
                    refusal,
                },
            )
        }
        Err(ClaimAdmissionRefused::NodesUnanswered { machines }) => Err(invalid_state(&format!(
            "nodes_unanswered: {} machine(s) of the line have not answered since this engine started; reserve once they have",
            machines.len()
        ))),
        Err(other) => Err(invalid_state(&format!(
            "claim_refused: the period's allocation refused the claim: {other:?}"
        ))),
    }
}

/// The stored claim, answered again. A claim still `Claimed` past its custody is released
/// first, so the caller learns to reserve the next attempt.
fn answer_again(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    claim: UnitClaim,
    now_ms: u64,
) -> MemoryResult<UnitView> {
    let claim = if custody_lapsed_in_txn(vault, wtxn, &claim, now_ms)? {
        release_claim_in_txn(vault, wtxn, &claim, CUSTODY_LAPSED, now_ms)?.unwrap_or(claim)
    } else {
        claim
    };
    Ok(UnitView::of(&claim, None, true))
}

/// The role a unit's purpose needs on the line.
pub(super) fn role_for(purpose: UnitPurpose) -> LineRole {
    match purpose {
        UnitPurpose::Work => LineRole::Lead,
        UnitPurpose::ReviewCheck => LineRole::Reviewer,
    }
}

/// Refuses the ask unless the workload is approved for the caller on the ask's machine, or,
/// with none named, on one of the line's machines. The start checks again on the machine it
/// places the job on.
fn approved_on_a_machine(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    caller: LineCaller,
    request: &UnitReserveRequest,
    line_machines: &[EntityId],
    now_ms: u64,
) -> MemoryResult<()> {
    let machines = match request.machine {
        Some(machine) => vec![machine],
        None => line_machines.to_vec(),
    };
    let mut refused = None;
    for machine in machines {
        let ask = WorkloadStartAsk {
            workload: &request.workload,
            machine,
            maximum_secs: request.secs,
            starter: match caller {
                LineCaller::Owner(actor) => WorkloadStarter::Owner(actor),
                LineCaller::Agent { grant } => WorkloadStarter::Grant(grant),
            },
        };
        match vault.workload_approval_in_txn(txn, &ask, now_ms)? {
            Ok(_) => return Ok(()),
            Err(refusal) => refused = Some(refusal),
        }
    }
    Err(invalid_state(&match refused {
        Some(refusal) => format!(
            "workload_mismatch: the workload is not approved for this caller on the unit's machine: {}",
            refusal.code()
        ),
        None => {
            "workload_mismatch: the line names no machine to approve the workload on".to_owned()
        }
    }))
}

/// Seconds a claim holds or spent: its reservation while it is open, what it was charged
/// once settled, nothing for any other end (design 7.3).
fn spent_secs(claim: &UnitClaim) -> u64 {
    match &claim.state {
        ClaimState::Claimed | ClaimState::Started => claim.reserved_secs,
        ClaimState::Ended(UnitTerminal {
            end: UnitEnd::Settled,
            charged_secs,
            ..
        }) => *charged_secs,
        ClaimState::Ended(_) => 0,
    }
}

/// The work seconds of the experiment at `rung`, the rung cap's measure: over every attempt
/// and period, on `arm` and every arm it supersedes, back to the first.
fn experiment_rung_secs(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    arm: &ExperimentArm,
    rung: u8,
) -> MemoryResult<u64> {
    let mut total = 0_u64;
    let mut next = Some(arm.clone());
    let mut seen = Vec::new();
    while let Some(arm) = next {
        if seen.contains(&arm.id) {
            break;
        }
        seen.push(arm.id);
        total = claims_at_rung_in_txn(vault, txn, &arm.id, rung)?
            .iter()
            .filter(|claim| claim.purpose == UnitPurpose::Work)
            .map(spent_secs)
            .fold(total, u64::saturating_add);
        next = match arm.supersedes {
            Some(id) => vault.experiment_arm_in_txn(txn, &id)?,
            None => None,
        };
    }
    Ok(total)
}

/// The family's open work units on the line: claimed or started, on any of its arms.
fn open_family_units(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    arm: &ExperimentArm,
) -> MemoryResult<u64> {
    let mut open = 0_u64;
    for family_arm in vault
        .experiment_arms_in_txn(txn)?
        .into_iter()
        .filter(|other| other.line == arm.line && other.family == arm.family)
    {
        for rung in 1..=family_arm.current_rung() {
            open = open.saturating_add(
                claims_at_rung_in_txn(vault, txn, &family_arm.id, rung)?
                    .iter()
                    .filter(|claim| claim.purpose == UnitPurpose::Work && claim.is_open())
                    .fold(0_u64, |count, _| count.saturating_add(1)),
            );
        }
    }
    Ok(open)
}

/// Who asked for what, as a budget refusal's row records it.
struct BudgetAsk<'a> {
    request: &'a UnitReserveRequest,
    arm: &'a ExperimentArm,
    period: u32,
    asker: EntityId,
    now_ms: u64,
}

/// What ran short, and the answer the caller gets.
struct BudgetShort {
    short: Option<Bucket>,
    room: u64,
    reason: &'static str,
    refusal: MemoryError,
}

/// Writes the budget refusal's `GPU_LINE_REFUSAL` row, then answers its refusal: the write
/// commits the row and nothing the ask would have written.
fn refused_for_budget(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    ask: &BudgetAsk<'_>,
    short: BudgetShort,
) -> MemoryResult<MemoryResult<UnitView>> {
    record_line_refusal_in_txn(
        vault,
        wtxn,
        ask.request.line,
        ask.period,
        &LineRefusal {
            family: ask.arm.family,
            arm: Some(ask.arm.id),
            rung: ask.request.rung,
            cohort: ask.arm.cohort,
            asked_secs: ask.request.secs,
            short: short.short,
            room: short.room,
            reason: short.reason.to_owned(),
            by: Some(ask.asker),
            at_ms: ask.now_ms,
        },
    )?;
    Ok(Err(short.refusal))
}

pub(super) fn check_unit_shape(rung: u8, unit_key: &str, attempt: u16) -> MemoryResult<()> {
    if rung == 0 {
        return Err(bad_request("rung: 1 is the first rung"));
    }
    if attempt == 0 {
        return Err(bad_request("attempt: 1 is the first attempt"));
    }
    if unit_key.trim().is_empty() || unit_key.len() > UNIT_KEY_MAX_BYTES {
        return Err(bad_request(&format!(
            "unit_key: name the unit, in at most {UNIT_KEY_MAX_BYTES} bytes"
        )));
    }
    Ok(())
}

fn is_sha256_hex(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn bad_request(why: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_BAD_REQUEST,
        why,
        &["Correct the ask and send it again."],
    )
}

pub(super) fn not_found(why: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_NOT_FOUND,
        why,
        &["Read the arm with vault.arms.get."],
    )
}

pub(super) fn invalid_state(why: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        why,
        &["Read the arm with vault.arms.get and the line with vault.gpu.lines.get."],
    )
}
