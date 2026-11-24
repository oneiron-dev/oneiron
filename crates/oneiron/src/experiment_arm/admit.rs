//! `vault.arms.admit` (design pass 32 section 5, row 4): the lane lead admits
//! one arm into a seated family of a GPU line. In one write, after every
//! check and before anything is written, the engine judges the caller again
//! against the line, reads the intent key, mints the period record at its
//! first touch, folds the period's spend and plans the arm's first allowance
//! (one rung-1 cap) in the draw order of section 4.2. The arm then holds
//! that room for as long as it stays open in that period: no other arm can
//! take it. The hold names the buckets it sits on, and the fold charges
//! them once: in full while the arm is open, then only what the arm's units
//! took. It lapses at the period's end and never funds a later period. A
//! refusal discards the whole write: no arm, no intent, no period record.
use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::gpu_line::{
    AllowanceHold, BudgetDenied, DrawAsk, DrawPurpose, IntentAsk, IntentStand, PeriodRoom,
    SpendRow, plan_draws,
};
use crate::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_BUDGET_SPENT, MEMORY_CODE_INVALID_STATE,
    MEMORY_CODE_NOT_FOUND, Memory, MemoryError, MemoryResult,
};
use crate::receipt::task_type_ref::TypeRef;
use crate::{EntityId, Vault};

use super::{
    ARM_TITLE_MAX_BYTES, ArmRung, ArmView, ContractPin, EXPERIMENT_ARMS, ExperimentArm,
    LedgerRowRef, RunnerRef,
};

/// The verb that admits an arm.
pub const ARMS_ADMIT_VERB: &str = "vault.arms.admit";

/// The longest contract path or runner model, in bytes.
const ARM_TEXT_MAX_BYTES: usize = 512;
/// The most lab ledger handles one arm carries.
const ARM_LEDGER_ROWS_MAX: usize = 32;

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
    /// The arm this one corrects, in the same family.
    #[serde(default)]
    pub supersedes: Option<EntityId>,
    /// The lab ledger lines that mirror the arm, by handle.
    #[serde(default)]
    pub ledger_rows: Vec<LedgerRowRef>,
}

/// The frozen contract an admission names; the engine stamps its freeze
/// time.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArmContractAsk {
    pub path: String,
    /// SHA-256 of the contract text, lower hex.
    pub sha256: String,
    /// The sealed NOTE that mirrors the contract text; its seal time is the
    /// freeze time.
    #[serde(default)]
    pub note: Option<EntityId>,
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
        if self.family == self.line {
            return bad("a family is a project seated on the line, not the line itself");
        }
        Ok(())
    }
}

/// `vault.arms.admit` as `memory`'s caller, with the owner's own proof when
/// its credential is owner-grade: admits the arm `request` names, with its
/// first allowance held, at `now_ms` on the host's clock. The caller is
/// judged again in the write, against the line (`verb_grant_caller` with the
/// line cover).
///
/// # Errors
///
/// `bad_request` for a malformed ask or a blank intent key; `forbidden`
/// for a caller whose Grant does not reach the line; `not_found` for an
/// unknown line or supersedes target; `invalid_state` for an unseated
/// family, a target in another family, an unsealed contract NOTE, a
/// period not open, or an intent key that names another ask;
/// `budget_spent` (`budget_denied`) when no first allowance fits now; a
/// store failure.
pub fn arm_admit_as(
    memory: &Memory<'_>,
    owner: Option<&AuthenticatedOwner>,
    request: &ArmAdmitRequest,
    now_ms: u64,
) -> MemoryResult<ArmView> {
    request.check_shape()?;
    let vault = memory.vault();
    // An `Err` discards the write, the period record the mint wrote at this
    // first touch included.
    vault.try_with_write_txn_grouped(|wtxn| {
        admit_in_txn(vault, wtxn, memory, owner, request, now_ms)
    })
}

fn admit_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    memory: &Memory<'_>,
    owner: Option<&AuthenticatedOwner>,
    request: &ArmAdmitRequest,
    now_ms: u64,
) -> MemoryResult<ArmView> {
    let line = crate::gpu_line::line_in_txn(vault, wtxn, &request.line)?
        .ok_or_else(|| not_found("no GPU line is set for this project"))?;
    memory.verb_grant_caller_admits_over_in_txn(wtxn, owner, ARMS_ADMIT_VERB, line.project)?;
    let asker = memory.actor();
    let intent = IntentAsk::new(asker, ARMS_ADMIT_VERB, &request.intent_key, &request.ask())?;
    if let IntentStand::Replayed(written) = intent.stand_in_txn(vault, wtxn)?? {
        let arm = match written_arm(&written) {
            Some(id) => vault.experiment_arm_in_txn(wtxn, &id)?,
            None => None,
        }
        .ok_or_else(|| not_found("the arm this intent key admitted is gone"))?;
        return Ok(ArmView::of(arm, true));
    }
    let seat = line.seat(&request.family).ok_or_else(|| {
        invalid_state(
            "the family is not seated on this line; seat it with vault.gpu.lines.families.admit",
        )
    })?;
    if let Some(target) = request.supersedes {
        let target = vault
            .experiment_arm_in_txn(wtxn, &target)?
            .ok_or_else(|| not_found("no experiment arm has the supersedes id"))?;
        if target.line != request.line || target.family != request.family {
            return Err(invalid_state(
                "an arm supersedes only an arm of its own family",
            ));
        }
    }
    let frozen_at_ms = match request.contract.note {
        Some(note) => {
            crate::note::note_seal_in_txn(&vault.store, wtxn, note)?
                .ok_or_else(|| {
                    invalid_state(
                        "the contract NOTE is not sealed; seal it with vault.notes.seal first",
                    )
                })?
                .sealed_at
        }
        None => now_ms,
    };
    let period = match crate::gpu_line::period_in_txn(vault, wtxn, &line, now_ms)? {
        Ok(Some(period)) => period,
        Ok(None) => {
            return Err(invalid_state(
                "the line's first period has not begun; admit the arm once it starts",
            ));
        }
        Err(refusal) => {
            return Err(invalid_state(&format!(
                "the line's period cannot be minted: {refusal}"
            )));
        }
    };
    let id = EntityId::now();
    let rows = vault.hold_rows_in_txn(wtxn, &request.line, period.index)?;
    let room = PeriodRoom::fold(&period, &rows);
    let units = line.first_rung_secs();
    let draws = plan_draws(
        &room,
        &DrawAsk {
            arm: id,
            family: request.family,
            track: seat.track,
            purpose: DrawPurpose::FirstAllowanceHold,
            units,
        },
    )
    .map_err(|denied| budget_denied(units, &denied))?;
    let arm = ExperimentArm {
        id,
        line: request.line,
        family: request.family,
        track: seat.track,
        type_ref: request.type_ref.clone(),
        title: request.title.clone(),
        contract: ContractPin {
            path: request.contract.path.clone(),
            sha256: request.contract.sha256.clone(),
            frozen_at_ms,
            note: request.contract.note,
        },
        runner: request.runner.clone(),
        supersedes: request.supersedes,
        first_allowance: Some(AllowanceHold {
            period: period.index,
            units,
            draws,
        }),
        rungs: vec![ArmRung::open(1, None)],
        ledger_rows: request.ledger_rows.clone(),
        admitted_by: Some(asker),
        admitted_at_ms: now_ms,
        revision: 1,
    };
    EXPERIMENT_ARMS.put(&vault.store, wtxn, &id, &arm)?;
    intent.keep_in_txn(vault, wtxn, id.as_bytes().to_vec(), now_ms)?;
    Ok(ArmView::of(arm, false))
}

impl Vault {
    /// Every arm's first-allowance hold in period `period` of the line
    /// `line`, as the fold reads it: an open arm holds its full units, a
    /// closed one only what its units took. Reserved units join these rows
    /// when the reserve door lands (rows M2-C and M2-D).
    pub(crate) fn hold_rows_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        line: &EntityId,
        period: u32,
    ) -> crate::Result<Vec<SpendRow>> {
        Ok(self
            .experiment_arms_in_txn(txn)?
            .into_iter()
            .filter(|arm| arm.line == *line)
            .filter_map(|arm| {
                let open = arm.is_open();
                let hold = arm.first_allowance?;
                (hold.period == period).then_some(SpendRow::Hold {
                    arm: arm.id,
                    family: arm.family,
                    hold,
                    arm_open: open,
                })
            })
            .collect())
    }
}

/// The arm id an intent row keeps.
fn written_arm(written: &[u8]) -> Option<EntityId> {
    <[u8; 16]>::try_from(written)
        .ok()
        .and_then(|bytes| EntityId::from_bytes(bytes).ok())
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
