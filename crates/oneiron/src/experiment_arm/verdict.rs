//! `vault.arms.verdict` (design pass 32 r2, sections 4.5 and 4.6; verb 8 of
//! section 5.2): the lane lead's verdict on the arm's current rung.
//!
//! - `kill` closes the rung and the arm, and scores the rung at once
//!   (`success = false`, anchor `HeldOut`) with its receipt projection.
//! - `promote` sends the rung to its independent review (`AwaitingReview`);
//!   nothing is scored until the review confirms it.
//! - `hold` keeps the rung open, once, and gives no new room.
//! - `invalid { reason }` closes the rung and the arm with no outcome and no
//!   receipt, ever; the reason must be one the rung's rows support.
//!
//! The verdict is one write: the compare-and-set on the arm's revision, the
//! checks, the rung's new state, `work_done_at_ms`, the outcome, the end of
//! the rung-1 hold, the receipt projection and the intent row. A refusal
//! writes nothing. The engine does not judge the bar: whether the numbers
//! pass is the lead's reading.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::gpu_line::{IntentAsk, IntentStand, LineRole, doors_caller, line_in_txn};
use crate::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_NOT_FOUND, Memory, MemoryError, MemoryResult,
};
use crate::{EntityId, Vault};

use super::admit::is_sha256_hex;
use super::outcome::{
    RungClaims, invalid_state, kill_outcome, result_scored_in_txn, rung_won_before_in_txn,
    score_rung_in_txn,
};
use super::{
    ARM_EVIDENCE_MAX, ArmDecision, ArmEvidenceDigest, ArmInvalidReason, ArmState, ArmVerdict,
    ArmView, EXPERIMENT_ARMS, HoldEndCause, LedgerRowRef, RungEnd, RungState, VERDICT_NUMBERS_MAX,
    VERDICT_TEXT_MAX_BYTES,
};

/// The verb that writes a rung's verdict.
pub const ARMS_VERDICT_VERB: &str = "vault.arms.verdict";

/// The longest name of a verdict number or of an evidence digest, in bytes.
pub const EVIDENCE_NAME_MAX_BYTES: usize = 256;

/// `vault.arms.verdict`: the lead's verdict on one rung of one arm, at the
/// arm revision the lead read, under the caller's intent key.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArmVerdictRequest {
    /// Names this write: a repeat of the same ask under it answers the arm,
    /// marked `replayed`.
    pub intent_key: String,
    /// The arm.
    pub arm: EntityId,
    /// The rung: the arm's current rung, `Open`.
    pub rung: u8,
    /// The arm's revision as the lead read it: the verdict's compare-and-set.
    pub arm_revision: u64,
    pub decision: ArmDecision,
    /// The claims at this rung the verdict rests on.
    #[serde(default)]
    pub units: Vec<EntityId>,
    /// Required for `promote` and `kill`: an output digest of a named
    /// measured claim.
    #[serde(default)]
    pub result: Option<ArmEvidenceDigest>,
    /// The lead's numbers, at most [`VERDICT_NUMBERS_MAX`]; an absent number
    /// stays absent, never zero.
    #[serde(default)]
    pub numbers: BTreeMap<String, f64>,
    /// At most [`VERDICT_TEXT_MAX_BYTES`].
    #[serde(default)]
    pub text: String,
    /// At most [`ARM_EVIDENCE_MAX`] digests, by hash: never a body.
    #[serde(default)]
    pub evidence: Vec<ArmEvidenceDigest>,
    #[serde(default)]
    pub ledger_row: Option<LedgerRowRef>,
    /// The arm's contract sha256 as the lead read it: it must be the pin.
    pub contract_sha256: String,
}

impl ArmVerdictRequest {
    /// The ask its intent key digests: everything but the key itself.
    fn ask(&self) -> Self {
        Self {
            intent_key: String::new(),
            ..self.clone()
        }
    }

    /// The checks that read nothing.
    fn check_shape(&self) -> MemoryResult<()> {
        if self.rung == 0 {
            return Err(bad_request("rungs count from 1"));
        }
        if !is_sha256_hex(&self.contract_sha256) {
            return Err(bad_request(
                "a verdict's contract sha256 is 64 lower hex characters",
            ));
        }
        match (&self.decision, &self.result) {
            (ArmDecision::Promote | ArmDecision::Kill, None) => {
                return Err(bad_request(
                    "promote and kill name their result: an output digest of a measured claim",
                ));
            }
            (ArmDecision::Hold | ArmDecision::Invalid { .. }, Some(_)) => {
                return Err(bad_request(
                    "only promote and kill name a result; hold and invalid score nothing",
                ));
            }
            _ => {}
        }
        if let ArmDecision::Invalid {
            reason: ArmInvalidReason::Other(why),
        } = &self.decision
            && (why.trim().is_empty() || why.len() > EVIDENCE_NAME_MAX_BYTES)
        {
            return Err(bad_request(
                "an invalid reason of kind other is 1 to 256 bytes",
            ));
        }
        check_verdict_text(&self.numbers, &self.text)?;
        check_digests(
            self.result.iter().chain(&self.evidence),
            self.evidence.len(),
        )?;
        check_ledger_row(self.ledger_row.as_ref())
    }

    /// The verdict this ask writes, by `by` at `at_ms`.
    fn verdict(&self, by: EntityId, at_ms: u64) -> ArmVerdict {
        ArmVerdict {
            decision: self.decision.clone(),
            units: self.units.clone(),
            result: self.result.clone(),
            numbers: self.numbers.clone(),
            text: self.text.clone(),
            evidence: self.evidence.clone(),
            ledger_row: self.ledger_row.clone(),
            contract_sha256: self.contract_sha256.clone(),
            by: Some(by),
            at_ms,
            arm_revision: self.arm_revision,
        }
    }

    /// Whether the stored verdict `stored` is what this ask wrote.
    fn written_as(&self, stored: &ArmVerdict) -> bool {
        stored.arm_revision == self.arm_revision
            && stored.decision == self.decision
            && stored.units == self.units
            && stored.result == self.result
            && stored.numbers == self.numbers
            && stored.text == self.text
            && stored.evidence == self.evidence
            && stored.ledger_row == self.ledger_row
            && stored.contract_sha256 == self.contract_sha256
    }
}

/// `vault.arms.verdict` as `memory`'s caller, with the owner's own proof
/// when its credential is owner-grade: the lead's verdict on the arm's
/// current rung, in one write at `now_ms` on the host's clock. The caller is
/// judged again in the write: the line cover and the lead role on the arm's
/// line.
///
/// # Errors
///
/// `bad_request` for a malformed ask or a blank intent key; `forbidden` for
/// a caller whose Grant does not reach the arm's line or holds no lead role
/// on it (`not_this_line`); `not_found` for an unknown arm, a rung the arm
/// has not opened, or a line that is gone; `invalid_state` for an arm
/// revision that is not the stored one (`stale_revision`), a rung that
/// already holds another verdict at that revision (`verdict_set`), a closed
/// arm or rung (`rung_closed`), a rung awaiting its review
/// (`rung_awaiting_review`), a contract sha256 that is not the pin
/// (`contract_changed`), a claim at the rung that has not ended
/// (`units_live`), a named unit that is no claim at the rung
/// (`unit_not_on_rung`), a promote or kill with no measured unit
/// (`no_measured_unit`) or a result that is none of its outputs
/// (`result_not_an_output`), a result that backs another scored rung on the
/// line (`result_scored`), a rung the arm's experiment already won
/// (`rung_won`), a second hold (`hold_once`), an invalid reason the rows do
/// not support (`invalid_unsupported`), or an intent key that names another
/// ask; a store failure.
pub fn arm_verdict_as(
    memory: &Memory<'_>,
    owner: Option<&AuthenticatedOwner>,
    request: &ArmVerdictRequest,
    now_ms: u64,
) -> MemoryResult<ArmView> {
    request.check_shape()?;
    let vault = memory.vault();
    vault.try_with_write_txn_grouped(|wtxn| {
        verdict_in_txn(vault, wtxn, memory, owner, request, now_ms)
    })
}

fn verdict_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    memory: &Memory<'_>,
    owner: Option<&AuthenticatedOwner>,
    request: &ArmVerdictRequest,
    now_ms: u64,
) -> MemoryResult<ArmView> {
    let Some(mut arm) = vault.experiment_arm_in_txn(wtxn, &request.arm)? else {
        return Err(not_found("no experiment arm has this id"));
    };
    let caller = doors_caller::admit_in_txn(memory, wtxn, owner, ARMS_VERDICT_VERB, arm.line)?;
    let line = line_in_txn(vault, wtxn, &arm.line)?
        .ok_or_else(|| not_found("the arm's GPU line is gone"))?;
    caller.require_role(&line, &[LineRole::Lead], ARMS_VERDICT_VERB)?;
    let asker = memory.actor();
    let intent = IntentAsk::new(
        asker,
        ARMS_VERDICT_VERB,
        &request.intent_key,
        &request.ask(),
    )?;
    if let IntentStand::Replayed(_) = intent.stand_in_txn(vault, wtxn)?? {
        // The ask names the arm, so the row this key wrote is this arm's.
        return Ok(ArmView::of(arm, true));
    }
    let Some(index) = arm.rungs.iter().position(|rung| rung.rung == request.rung) else {
        return Err(not_found("the arm has not opened this rung"));
    };
    // The logical key (section 5.2): one verdict on (arm, rung) at an arm
    // revision. The same ask answers it under any intent key; another ask at
    // that revision is a conflict.
    if let Some(stored) = &arm.rungs[index].verdict
        && stored.arm_revision == request.arm_revision
    {
        if !request.written_as(stored) {
            return Err(invalid_state(
                "verdict_set: the rung already holds another verdict given at this arm revision",
            ));
        }
        intent.keep_in_txn(vault, wtxn, arm.id.as_bytes().to_vec(), now_ms)?;
        return Ok(ArmView::of(arm, true));
    }
    if request.arm_revision != arm.revision {
        return Err(invalid_state(&format!(
            "stale_revision: the arm is at revision {}, not {}; read it again with vault.arms.get",
            arm.revision, request.arm_revision
        )));
    }
    match &arm.rungs[index].state {
        RungState::Open if arm.is_open() && request.rung == arm.current_rung() => {}
        RungState::AwaitingReview => {
            return Err(invalid_state(
                "rung_awaiting_review: the rung's promote waits for its independent review",
            ));
        }
        _ => {
            return Err(invalid_state(
                "rung_closed: a verdict goes on an open arm's current rung while it is open",
            ));
        }
    }
    if request.contract_sha256 != arm.contract.sha256 {
        return Err(invalid_state(
            "contract_changed: the contract sha256 is not the arm's pin; read the arm with vault.arms.get",
        ));
    }
    let claims = RungClaims::read_in_txn(vault, wtxn, &arm, request.rung)?;
    if claims.any_live() {
        return Err(invalid_state(
            "units_live: a claim at this rung has not ended; a verdict waits for every unit's end",
        ));
    }
    if let Some(unit) = claims.first_foreign(&request.units) {
        return Err(invalid_state(&format!(
            "unit_not_on_rung: {} is no claim at this rung of this arm",
            unit.to_hex()
        )));
    }
    if let Some(result) = &request.result {
        claims.check_result(&request.units, &arm.contract.sha256, result)?;
        if result_scored_in_txn(vault, wtxn, &arm, request.rung, result)? {
            return Err(invalid_state(
                "result_scored: this result digest already backs a scored rung on the line; a result backs one outcome",
            ));
        }
    }
    let leaves_open = !matches!(request.decision, ArmDecision::Hold);
    match &request.decision {
        ArmDecision::Hold => {
            if arm.rungs[index].holds > 0 {
                return Err(invalid_state(
                    "hold_once: the rung was held once; give it promote, kill or invalid",
                ));
            }
            arm.rungs[index].holds += 1;
        }
        ArmDecision::Promote => {
            if rung_won_before_in_txn(vault, wtxn, &arm, request.rung)? {
                return Err(invalid_state(
                    "rung_won: an arm this one supersedes already won this rung; an experiment wins a rung once",
                ));
            }
            arm.rungs[index].state = RungState::AwaitingReview;
        }
        ArmDecision::Kill => {
            arm.rungs[index].state = RungState::Closed {
                end: RungEnd::Killed,
            };
            arm.state = ArmState::Killed;
        }
        ArmDecision::Invalid { reason } => {
            if !claims.supports_invalid(reason, &request.text, &request.evidence) {
                return Err(invalid_state(
                    "invalid_unsupported: the rung's rows do not support this reason (contract_changed needs a contract refusal, timed_out a unit ended at its limit, withdrawn no charged seconds, could_not_measure and other a text and an evidence digest)",
                ));
            }
            arm.rungs[index].state = RungState::Closed {
                end: RungEnd::Invalid {
                    reason: reason.clone(),
                },
            };
            arm.state = if *reason == ArmInvalidReason::Withdrawn {
                ArmState::Withdrawn
            } else {
                ArmState::Invalid
            };
        }
    }
    if leaves_open {
        arm.rungs[index].work_done_at_ms = claims.work_done_at_ms();
        if request.rung == 1 {
            let cause = match request.decision {
                ArmDecision::Invalid {
                    reason: ArmInvalidReason::Withdrawn,
                } => HoldEndCause::Withdrawn,
                _ => HoldEndCause::RungClosed,
            };
            arm.end_hold(now_ms, cause);
        }
    }
    arm.rungs[index].verdict = Some(request.verdict(asker, now_ms));
    if matches!(request.decision, ArmDecision::Kill) {
        let policy = claims.policy_in_txn(vault, wtxn, &line, &arm)?;
        let cap = policy
            .rung_caps_secs
            .get(usize::from(request.rung) - 1)
            .copied();
        score_rung_in_txn(
            vault,
            wtxn,
            &mut arm,
            index,
            kill_outcome(now_ms),
            &claims,
            cap,
        )?;
    }
    arm.revision += 1;
    EXPERIMENT_ARMS.put(&vault.store, wtxn, &arm.id, &arm)?;
    intent.keep_in_txn(vault, wtxn, arm.id.as_bytes().to_vec(), now_ms)?;
    Ok(ArmView::of(arm, false))
}

/// The bounds of a verdict's numbers and text.
fn check_verdict_text(numbers: &BTreeMap<String, f64>, text: &str) -> MemoryResult<()> {
    if numbers.len() > VERDICT_NUMBERS_MAX {
        return Err(bad_request("a verdict carries at most 32 numbers"));
    }
    if numbers.iter().any(|(name, value)| {
        name.trim().is_empty()
            || name.len() > EVIDENCE_NAME_MAX_BYTES
            || name.contains('\0')
            || !value.is_finite()
    }) {
        return Err(bad_request(
            "a verdict number has a 1 to 256 byte name and a finite value",
        ));
    }
    if text.len() > VERDICT_TEXT_MAX_BYTES || text.contains('\0') {
        return Err(bad_request(
            "a verdict's text is at most 2,000 bytes, without NUL",
        ));
    }
    Ok(())
}

/// The bounds of evidence digests: `listed` of them in the evidence list,
/// each with a name and a lower hex sha256.
pub(super) fn check_digests<'a>(
    digests: impl IntoIterator<Item = &'a ArmEvidenceDigest>,
    listed: usize,
) -> MemoryResult<()> {
    if listed > ARM_EVIDENCE_MAX {
        return Err(bad_request("at most 32 evidence digests"));
    }
    for digest in digests {
        if digest.name.trim().is_empty()
            || digest.name.len() > EVIDENCE_NAME_MAX_BYTES
            || digest.name.contains('\0')
            || !is_sha256_hex(&digest.sha256)
        {
            return Err(bad_request(
                "an evidence digest has a 1 to 256 byte name and a 64 lower hex sha256",
            ));
        }
    }
    Ok(())
}

/// The shape of a lab ledger handle.
pub(super) fn check_ledger_row(row: Option<&LedgerRowRef>) -> MemoryResult<()> {
    match row {
        Some(row)
            if row.id.trim().is_empty()
                || row.id.len() > EVIDENCE_NAME_MAX_BYTES
                || !is_sha256_hex(&row.sha256) =>
        {
            Err(bad_request(
                "a ledger row has a 1 to 256 byte id and a 64 lower hex sha256",
            ))
        }
        _ => Ok(()),
    }
}

pub(super) fn bad_request(why: &str) -> MemoryError {
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
        &["List the arms with vault.arms.list."],
    )
}
