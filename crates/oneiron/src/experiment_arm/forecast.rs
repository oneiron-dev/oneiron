//! `vault.arms.forecast` (design pass 32 r2, sections 3.3 and 4.7; verb 5 of
//! section 5.2): the lane lead writes the rung's one forecast, the chance the
//! rung passes, before the rung's first claim. The forecast is the arm's own
//! runner's: the engine copies the runner from the arm, and the ask has no
//! field that names another author. It is one field on the rung, written
//! once; it survives retries, releases, holds and restarts unchanged.
//!
//! In one write the door judges the caller again (the line cover and the
//! lead role, section 5.1), reads the intent key and the logical key (arm,
//! rung), and refuses a forecast once any claim was made at the rung
//! (`forecast_late`): a claim row stays after it is released or ended, and
//! the reserve door (row M2-C) runs in the same serialized writer, so one of
//! the two is first. A refusal writes nothing.
use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::gpu_line::{
    IntentAsk, IntentStand, LineRole, claims_at_rung_in_txn, doors_caller, line_in_txn,
};
use crate::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_INVALID_STATE, MEMORY_CODE_NOT_FOUND, Memory,
    MemoryError, MemoryResult,
};
use crate::{EntityId, Vault};

use super::admit::is_sha256_hex;
use super::{ArmView, EXPERIMENT_ARMS, RungState, RunnerForecast};

/// The verb that writes a rung's forecast.
pub const ARMS_FORECAST_VERB: &str = "vault.arms.forecast";

/// The most a forecast says, in thousandths: the rung passes for certain.
pub const PASS_PER_MILLE_MAX: u16 = 1_000;

/// `vault.arms.forecast`: the forecast for one rung of one arm, under the
/// caller's intent key. The author is the arm's runner, never a field here.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArmForecastRequest {
    /// Names this write: a repeat of the same ask under it answers the arm,
    /// marked `replayed`.
    pub intent_key: String,
    /// The arm.
    pub arm: EntityId,
    /// The rung the forecast is for: the arm's current rung, still `Open`.
    pub rung: u8,
    /// The chance the rung passes, in thousandths (0 to 1000).
    pub pass_per_mille: u16,
    /// The arm's contract sha256 as the caller read it: it must be the pin.
    pub contract_sha256: String,
}

impl ArmForecastRequest {
    /// The ask its intent key digests: everything but the key itself.
    fn ask(&self) -> Self {
        Self {
            intent_key: String::new(),
            ..self.clone()
        }
    }

    /// The checks that read nothing.
    fn check_shape(&self) -> MemoryResult<()> {
        if self.pass_per_mille > PASS_PER_MILLE_MAX {
            return Err(bad_request(
                "a forecast's pass_per_mille is 0 to 1000 (thousandths of a pass)",
            ));
        }
        if self.rung == 0 {
            return Err(bad_request("rungs count from 1"));
        }
        if !is_sha256_hex(&self.contract_sha256) {
            return Err(bad_request(
                "a forecast's contract sha256 is 64 lower hex characters",
            ));
        }
        Ok(())
    }

    /// Whether the stored forecast `stored` is what this ask would write.
    fn written_as(&self, stored: &RunnerForecast) -> bool {
        stored.pass_per_mille == self.pass_per_mille
            && stored.contract_sha256 == self.contract_sha256
    }
}

/// `vault.arms.forecast` as `memory`'s caller, with the owner's own proof
/// when its credential is owner-grade: writes the rung's one forecast, for
/// the arm's runner, at `now_ms` on the host's clock. The caller is judged
/// again in the write: the line cover and the lead role on the arm's line.
///
/// # Errors
///
/// `bad_request` for a malformed ask or a blank intent key; `forbidden` for
/// a caller whose Grant does not reach the arm's line or holds no lead role
/// on it (`not_this_line`); `not_found` for an unknown arm, a rung the arm
/// has not opened, or a line that is gone; `invalid_state` for a rung that
/// already holds another forecast (`forecast_set`), an arm that is not open,
/// a rung that is not the arm's current one or not `Open`, a contract sha256
/// that is not the pin (`contract_changed`), a rung that ever had a claim
/// (`forecast_late`), or an intent key that names another ask; a store
/// failure.
pub fn arm_forecast_as(
    memory: &Memory<'_>,
    owner: Option<&AuthenticatedOwner>,
    request: &ArmForecastRequest,
    now_ms: u64,
) -> MemoryResult<ArmView> {
    request.check_shape()?;
    let vault = memory.vault();
    vault.try_with_write_txn_grouped(|wtxn| {
        forecast_in_txn(vault, wtxn, memory, owner, request, now_ms)
    })
}

fn forecast_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    memory: &Memory<'_>,
    owner: Option<&AuthenticatedOwner>,
    request: &ArmForecastRequest,
    now_ms: u64,
) -> MemoryResult<ArmView> {
    let Some(mut arm) = vault.experiment_arm_in_txn(wtxn, &request.arm)? else {
        return Err(not_found("no experiment arm has this id"));
    };
    let caller =
        doors_caller::admit_in_txn(memory, wtxn, owner, ARMS_FORECAST_VERB, arm.line)?;
    let line = line_in_txn(vault, wtxn, &arm.line)?
        .ok_or_else(|| not_found("the arm's GPU line is gone"))?;
    caller.require_role(&line, &[LineRole::Lead], ARMS_FORECAST_VERB)?;
    let asker = memory.actor();
    let intent = IntentAsk::new(asker, ARMS_FORECAST_VERB, &request.intent_key, &request.ask())?;
    if let IntentStand::Replayed(_) = intent.stand_in_txn(vault, wtxn)?? {
        // The ask names the arm, so the row this key wrote is this arm's.
        return Ok(ArmView::of(arm, true));
    }
    let Some(index) = arm.rungs.iter().position(|rung| rung.rung == request.rung) else {
        return Err(not_found("the arm has not opened this rung"));
    };
    // The logical key (section 5.2): the rung holds one forecast. The same
    // ask answers it under any intent key, which then names it too; another
    // value is a conflict, whatever happened at the rung since.
    if let Some(stored) = &arm.rungs[index].forecast {
        if !request.written_as(stored) {
            return Err(invalid_state(
                "forecast_set: the rung already holds its one forecast, of another value; a forecast is written once",
            ));
        }
        intent.keep_in_txn(vault, wtxn, arm.id.as_bytes().to_vec(), now_ms)?;
        return Ok(ArmView::of(arm, true));
    }
    if !arm.is_open() {
        return Err(invalid_state(
            "the arm is closed; a forecast goes on an open arm's current rung",
        ));
    }
    if request.rung != arm.current_rung() || arm.rungs[index].state != RungState::Open {
        return Err(invalid_state(
            "a forecast goes on the arm's current rung while it is open",
        ));
    }
    if request.contract_sha256 != arm.contract.sha256 {
        return Err(invalid_state(
            "contract_changed: the contract sha256 is not the arm's pin; read the arm with vault.arms.get",
        ));
    }
    if !claims_at_rung_in_txn(vault, wtxn, &arm.id, request.rung)?.is_empty() {
        return Err(invalid_state(
            "forecast_late: a claim was made at this rung; a forecast is written before the rung's first claim",
        ));
    }
    arm.rungs[index].forecast = Some(RunnerForecast {
        pass_per_mille: request.pass_per_mille,
        runner: arm.runner.clone(),
        contract_sha256: request.contract_sha256.clone(),
        written_by: Some(asker),
        written_at_ms: now_ms,
    });
    arm.revision += 1;
    EXPERIMENT_ARMS.put(&vault.store, wtxn, &arm.id, &arm)?;
    intent.keep_in_txn(vault, wtxn, arm.id.as_bytes().to_vec(), now_ms)?;
    Ok(ArmView::of(arm, false))
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
        &["Read the arm with vault.arms.get."],
    )
}
