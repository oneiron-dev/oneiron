//! `vault.arms.admit` (design pass 32 r2, section 5.2 row 4): the lane lead
//! admits one arm into a seated family of a GPU line. In one write, the
//! engine mints the period record at its first touch, judges the caller
//! again (the line cover and the lead role, section 5.1), reads the intent
//! key and the arm's logical key, and plans the arm's first allowance (one
//! rung-1 cap, `period.policy.first_rung_secs()`) in the draw order of
//! section 4.2. The hold is an earmark on named pools: no other arm can take
//! that room while it lives. It ends at the first of: rung 1 leaves `Open`,
//! the arm is withdrawn ([`ExperimentArm::end_hold`]), the period ends, or
//! `hold_ttl_secs` pass with no claim ever made
//! ([`ExperimentArm::hold_ended_at`]); the fold then charges its pools only
//! what the arm's units took. A re-run of an experiment (the same contract
//! sha256 as a closed arm it supersedes) gets no hold and keeps its
//! predecessor's cohort. A precondition refusal discards the whole write:
//! no arm, no intent, no period record. A budget refusal (`budget_denied`)
//! writes one `GPU_LINE_REFUSAL` row (design pass 32 r2, 3.5 and 5.2), with
//! the period record a first touch minted, and nothing else.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::consent::AuthenticatedOwner;
use crate::gpu_line::doors_caller;
use crate::gpu_line::{
    AllowanceHold, BudgetDenied, DrawAsk, DrawPurpose, GpuLinePeriod, IntentAsk, IntentStand,
    LineRefusal, LineRole, PeriodRoom, SpendRow, claims_at_rung_in_txn, mint_first_in_txn,
    plan_draws, record_line_refusal_in_txn,
};
use crate::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_BUDGET_SPENT, MEMORY_CODE_INVALID_STATE,
    MEMORY_CODE_NOT_FOUND, Memory, MemoryError, MemoryResult,
};
use crate::receipt::task_type_ref::TypeRef;
use crate::{EntityId, Vault};

use super::{
    ARM_TITLE_MAX_BYTES, ArmRung, ArmState, ArmView, ContractPin, EXPERIMENT_ARMS, ExperimentArm,
    LedgerRowRef, RunnerRef,
};

/// The verb that admits an arm.
pub const ARMS_ADMIT_VERB: &str = "vault.arms.admit";

/// The longest contract path or runner model, in bytes.
const ARM_TEXT_MAX_BYTES: usize = 512;
/// The most lab ledger handles one arm carries.
const ARM_LEDGER_ROWS_MAX: usize = 32;
/// The longest planner card digest, in bytes.
const CARD_DIGEST_MAX_BYTES: usize = 128;

/// `vault.arms.admit`: the arm to admit, under the caller's intent key.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArmAdmitRequest {
    /// Names this write: a repeat of the same ask under it answers the arm
    /// it admitted, marked `replayed`.
    pub intent_key: String,
    /// The GPU line: the lane project's id.
    pub line: EntityId,
    /// The family: a project seated on the line.
    pub family: EntityId,
    /// The task type the arm is placed in (the root when unsure).
    pub type_ref: TypeRef,
    pub title: String,
    pub contract: ArmContractAsk,
    pub runner: RunnerRef,
    /// The closed arm of the same family this one re-runs (same contract
    /// sha256) or corrects (a new contract).
    #[serde(default)]
    pub supersedes: Option<EntityId>,
    /// The lab ledger lines that mirror the arm, by handle.
    #[serde(default)]
    pub ledger_rows: Vec<LedgerRowRef>,
    /// The digest of the planner card the lead read before admitting.
    #[serde(default)]
    pub card_digest: Option<String>,
}

/// The contract an admission pins; the engine stamps the pin time.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArmContractAsk {
    pub path: String,
    /// SHA-256 of the contract text, lower hex.
    pub sha256: String,
    /// A sealed NOTE whose text hashes to `sha256`.
    #[serde(default)]
    pub note: Option<EntityId>,
    /// The lane's own freeze time, kept as its claim.
    #[serde(default)]
    pub claimed_frozen_at_ms: Option<u64>,
}

impl ArmAdmitRequest {
    /// The ask its intent key digests: everything but the key itself.
    fn ask(&self) -> Self {
        Self {
            intent_key: String::new(),
            ..self.clone()
        }
    }

    /// The checks that read nothing.
    fn check_shape(&self) -> MemoryResult<()> {
        let bad = |why: &str| Err(bad_request(why));
        if self.title.trim().is_empty() || self.title.len() > ARM_TITLE_MAX_BYTES {
            return bad("an arm's title is 1 to 200 bytes");
        }
        if self.contract.path.trim().is_empty() || self.contract.path.len() > ARM_TEXT_MAX_BYTES {
            return bad("an arm's contract path is 1 to 512 bytes");
        }
        if !is_sha256_hex(&self.contract.sha256) {
            return bad("an arm's contract sha256 is 64 lower hex characters");
        }
        if self.runner.model.trim().is_empty() || self.runner.model.len() > ARM_TEXT_MAX_BYTES {
            return bad("an arm's runner model is 1 to 512 bytes");
        }
        if self.type_ref.validate().is_err() {
            return bad("an arm's type is a node id and a tree version");
        }
        if self.ledger_rows.len() > ARM_LEDGER_ROWS_MAX
            || self
                .ledger_rows
                .iter()
                .any(|row| row.id.trim().is_empty() || !is_sha256_hex(&row.sha256))
        {
            return bad("an arm carries at most 32 lab ledger handles, each an id and a sha256");
        }
        if self.card_digest.as_deref().is_some_and(|digest| {
            digest.is_empty()
                || digest.len() > CARD_DIGEST_MAX_BYTES
                || !digest.bytes().all(|b| b.is_ascii_graphic())
        }) {
            return bad("a planner card digest is 1 to 128 printable ASCII bytes");
        }
        if self.family == self.line {
            return bad("a family is a project seated on the line, not the line itself");
        }
        Ok(())
    }

    /// Whether the stored arm `arm` is what this ask would admit: the same
    /// logical key (family and contract sha256) asked the same way.
    fn admitted_as(&self, arm: &ExperimentArm) -> bool {
        arm.line == self.line
            && arm.family == self.family
            && arm.type_ref == self.type_ref
            && arm.title == self.title
            && arm.contract.path == self.contract.path
            && arm.contract.sha256 == self.contract.sha256
            && arm.contract.note == self.contract.note
            && arm.contract.claimed_frozen_at_ms == self.contract.claimed_frozen_at_ms
            && arm.runner == self.runner
            && arm.supersedes == self.supersedes
            && arm.ledger_rows == self.ledger_rows
            && arm.card_digest == self.card_digest
    }
}

/// `vault.arms.admit` as `memory`'s caller, with the owner's own proof when
/// its credential is owner-grade: admits the arm `request` names, with its
/// first allowance held, at `now_ms` on the host's clock. The caller is
/// judged again in the write: the line cover and the lead role on the line.
///
/// # Errors
///
/// `bad_request` for a malformed ask or a blank intent key; `forbidden`
/// for a caller whose Grant does not reach the line or holds no lead role
/// on it (`not_this_line`); `not_found` for an unknown line or supersedes
/// target; `invalid_state` for a period not begun or not mintable, a family
/// with no seat in force, a contract an open arm of the family pins under
/// another ask (`contract_conflict`), a closed arm's contract without
/// `supersedes`, a supersedes target that is open, in another family or
/// already superseded, a contract NOTE that is not sealed or whose text
/// does not hash to the pin, or an intent key that names another ask;
/// `budget_spent` (`budget_denied`) when no first allowance fits now, after
/// its `GPU_LINE_REFUSAL` row is written; a
/// store failure.
pub fn arm_admit_as(
    memory: &Memory<'_>,
    owner: Option<&AuthenticatedOwner>,
    request: &ArmAdmitRequest,
    now_ms: u64,
) -> MemoryResult<ArmView> {
    request.check_shape()?;
    let vault = memory.vault();
    // An outer `Err` discards the write, the period record the mint wrote at
    // this first touch included; an inner one commits it: a budget refusal
    // keeps its refusal row (and that period record).
    vault.try_with_write_txn_grouped(|wtxn| {
        admit_in_txn(vault, wtxn, memory, owner, request, now_ms)
    })?
}

fn admit_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    memory: &Memory<'_>,
    owner: Option<&AuthenticatedOwner>,
    request: &ArmAdmitRequest,
    now_ms: u64,
) -> MemoryResult<MemoryResult<ArmView>> {
    let caller = doors_caller::admit_in_txn(memory, wtxn, owner, ARMS_ADMIT_VERB, request.line)?;
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
    caller.require_role(&line, &[LineRole::Lead], ARMS_ADMIT_VERB)?;
    let period = minted.period.ok_or_else(|| {
        invalid_state(
            "period_not_begun: the line's first period has not begun; admit the arm once it starts",
        )
    })?;
    let asker = memory.actor();
    let intent = IntentAsk::new(asker, ARMS_ADMIT_VERB, &request.intent_key, &request.ask())?;
    if let IntentStand::Replayed(written) = intent.stand_in_txn(vault, wtxn)?? {
        let arm = match written_arm(&written) {
            Some(id) => vault.experiment_arm_in_txn(wtxn, &id)?,
            None => None,
        }
        .ok_or_else(|| not_found("the arm this intent key admitted is gone"))?;
        return Ok(Ok(ArmView::of(arm, true)));
    }
    let family_arms: Vec<ExperimentArm> = vault
        .experiment_arms_in_txn(wtxn)?
        .into_iter()
        .filter(|arm| arm.line == request.line && arm.family == request.family)
        .collect();
    // The logical key (section 5.2): an open arm of the family already pins
    // this contract. The same ask answers it under any intent key, which
    // then names it too; another ask is a conflict.
    if let Some(open) = family_arms
        .iter()
        .find(|arm| arm.is_open() && arm.contract.sha256 == request.contract.sha256)
    {
        if !request.admitted_as(open) {
            return Err(invalid_state(
                "contract_conflict: an open arm of this family already pins this contract under another ask",
            ));
        }
        intent.keep_in_txn(vault, wtxn, open.id.as_bytes().to_vec(), now_ms)?;
        return Ok(Ok(ArmView::of(open.clone(), true)));
    }
    // The live seat: the mint above marked a new idea it no longer funds as
    // lapsed. A seat that counts from a later mint and took no late floor
    // has no room this period, which the draw plan below refuses.
    let seat = line.seat(&request.family).ok_or_else(|| {
        invalid_state(
            "seat_lapsed: the family holds no seat in force on this line; seat it with vault.gpu.lines.families.admit",
        )
    })?;
    let target = match request.supersedes {
        Some(id) => Some(supersedes_target(vault, wtxn, request, &family_arms, id)?),
        None => None,
    };
    let rerun = target
        .as_ref()
        .is_some_and(|target| target.contract.sha256 == request.contract.sha256);
    if !rerun
        && family_arms
            .iter()
            .any(|arm| arm.contract.sha256 == request.contract.sha256)
    {
        return Err(invalid_state(
            "a closed arm of this family pins this contract; a re-run names the experiment's last closed arm in supersedes",
        ));
    }
    if let Some(note) = request.contract.note {
        contract_note_matches(vault, wtxn, note, &request.contract.sha256)?;
    }
    let id = EntityId::now();
    let (first_allowance, cohort) = match &target {
        // A re-run gets no hold and keeps its predecessor's cohort (3.3, 4.4).
        Some(target) if rerun => (None, target.cohort),
        _ => {
            let rows = vault.spend_rows_in_txn(wtxn, &request.line, &period, now_ms)?;
            let room = PeriodRoom::fold(&period, &line.families, &rows);
            let units = period.policy.first_rung_secs();
            let draws = match plan_draws(
                &room,
                &DrawAsk {
                    arm: id,
                    family: request.family,
                    track: seat.track,
                    purpose: DrawPurpose::FirstAllowanceHold,
                    units,
                },
            ) {
                Ok(draws) => draws,
                Err(denied) => {
                    // Unmet demand (3.5): one row, at admission, with no arm.
                    record_line_refusal_in_txn(
                        vault,
                        wtxn,
                        request.line,
                        period.index,
                        &LineRefusal {
                            family: request.family,
                            arm: None,
                            rung: 1,
                            cohort: None,
                            asked_secs: units,
                            short: denied.short,
                            room: denied.fits,
                            reason: "budget_denied".to_owned(),
                            by: Some(asker),
                            at_ms: now_ms,
                        },
                    )?;
                    return Ok(Err(budget_denied(units, &denied)));
                }
            };
            let hold = AllowanceHold {
                period: period.index,
                units,
                draws,
            };
            // The comparison's cohort (two rules in force) is row M2-G's.
            (Some(hold), None)
        }
    };
    let arm = ExperimentArm {
        id,
        line: request.line,
        family: request.family,
        seat: seat.seat,
        track: seat.track,
        type_ref: request.type_ref.clone(),
        title: request.title.clone(),
        contract: ContractPin {
            path: request.contract.path.clone(),
            sha256: request.contract.sha256.clone(),
            pinned_at_ms: now_ms,
            claimed_frozen_at_ms: request.contract.claimed_frozen_at_ms,
            note: request.contract.note,
        },
        runner: request.runner.clone(),
        supersedes: request.supersedes,
        cohort,
        cohort_block: None,
        card_digest: request.card_digest.clone(),
        first_allowance,
        hold_end: None,
        rungs: vec![ArmRung::open(1, None)],
        state: ArmState::Open,
        ledger_rows: request.ledger_rows.clone(),
        admitted_by: Some(asker),
        admitted_at_ms: now_ms,
        revision: 1,
    };
    EXPERIMENT_ARMS.put(&vault.store, wtxn, &id, &arm)?;
    intent.keep_in_txn(vault, wtxn, id.as_bytes().to_vec(), now_ms)?;
    Ok(Ok(ArmView::of(arm, false)))
}

/// The arm `id` a request supersedes: a closed arm of the request's own
/// family that no arm supersedes yet.
fn supersedes_target(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    request: &ArmAdmitRequest,
    family_arms: &[ExperimentArm],
    id: EntityId,
) -> MemoryResult<ExperimentArm> {
    let target = vault
        .experiment_arm_in_txn(txn, &id)?
        .ok_or_else(|| not_found("no experiment arm has the supersedes id"))?;
    if target.line != request.line || target.family != request.family {
        return Err(invalid_state(
            "an arm supersedes only an arm of its own family",
        ));
    }
    if target.is_open() {
        return Err(invalid_state(
            "an arm supersedes only a closed arm; close the open one with its verdict first",
        ));
    }
    if family_arms.iter().any(|arm| arm.supersedes == Some(id)) {
        return Err(invalid_state(
            "the supersedes target already has a successor; name the newest arm of the experiment",
        ));
    }
    Ok(target)
}

/// Refuses a contract NOTE that is not sealed, or whose sealed text does
/// not hash to the pinned `sha256`. A sealed NOTE takes no edit, so its
/// text now is its sealed text.
fn contract_note_matches(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
    sha256: &str,
) -> MemoryResult<()> {
    if crate::note::note_seal_in_txn(&vault.store, txn, note)?.is_none() {
        return Err(invalid_state(
            "the contract NOTE is not sealed; seal it with vault.notes.seal first",
        ));
    }
    let text = vault.note_text_in_txn(txn, note)?;
    if format!("{:x}", Sha256::digest(text.as_bytes())) != sha256 {
        return Err(invalid_state(
            "the contract NOTE's sealed text does not hash to the contract sha256",
        ));
    }
    Ok(())
}

impl Vault {
    /// Every row the fold reads for `period` of the line `line` at `now_ms`:
    /// each arm's first-allowance hold made in that period (held in full
    /// while it lives, else only what the arm's units took from it), and each
    /// unit claim reserved in that period. A hold that no claim ever drew
    /// lies dormant once the period policy's `hold_ttl_secs` pass. The
    /// reserve door (row M2-C) folds the same rows.
    pub(crate) fn spend_rows_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        line: &EntityId,
        period: &GpuLinePeriod,
        now_ms: u64,
    ) -> crate::Result<Vec<SpendRow>> {
        let mut rows = Vec::new();
        for arm in self
            .experiment_arms_in_txn(txn)?
            .into_iter()
            .filter(|arm| arm.line == *line)
        {
            let mut claimed = false;
            for rung in 1..=arm.current_rung() {
                for claim in claims_at_rung_in_txn(self, txn, &arm.id, rung)? {
                    if claim.arm != arm.id || claim.rung != rung {
                        continue;
                    }
                    claimed |= rung == 1;
                    if claim.period == period.index {
                        rows.push(claim.spend_row());
                    }
                }
            }
            let Some(hold) = &arm.first_allowance else {
                continue;
            };
            if hold.period != period.index {
                continue;
            }
            let lives = arm
                .hold_ended_at(now_ms, period.end_ms, period.policy.hold_ttl_secs, claimed)
                .is_none();
            rows.push(SpendRow::Hold {
                arm: arm.id,
                family: arm.family,
                hold: hold.clone(),
                arm_open: lives,
            });
        }
        Ok(rows)
    }
}

/// The arm id an intent row keeps.
fn written_arm(written: &[u8]) -> Option<EntityId> {
    <[u8; 16]>::try_from(written)
        .ok()
        .and_then(|bytes| EntityId::from_bytes(bytes).ok())
}

pub(super) fn is_sha256_hex(text: &str) -> bool {
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

fn not_found(why: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_NOT_FOUND,
        why,
        &["List the arms with vault.arms.list."],
    )
}

fn invalid_state(why: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        why,
        &["Read the line with vault.gpu.lines.get."],
    )
}

/// The design's `budget_denied`: the bucket that ran out, what each bucket
/// of the order had left, and the largest first allowance that fits now.
fn budget_denied(units: u64, denied: &BudgetDenied) -> MemoryError {
    let room = denied
        .room
        .iter()
        .map(|(bucket, left)| format!("{bucket:?} {left} s"))
        .collect::<Vec<_>>()
        .join(", ");
    MemoryError::new(
        MEMORY_CODE_BUDGET_SPENT,
        format!(
            "budget_denied: the first allowance of {units} s does not fit; {:?} ran out ({room}); {} s fit now",
            denied.short, denied.fits
        ),
        &["Wait for the next period, or ask the owner to raise the line's allowance."],
    )
}
