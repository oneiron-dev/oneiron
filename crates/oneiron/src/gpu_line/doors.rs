//! The `vault.gpu.lines.*` doors' acts (design pass 32, section 5). The
//! engine attests: it stamps every time, mints the period record at the
//! period's first write, and keeps each write under its intent key.
//!
//! - `vault.gpu.lines.set`: the owner's own act. A changed policy takes
//!   effect at the next mint (the current period's record is minted first,
//!   from the line as it stood, and freezes its caps, rules and forecast
//!   rule), except `hosts`, which units read at once. A schedule edit may not
//!   put the vault clock behind a period already minted.
//! - `vault.gpu.lines.get`: a read, for the owner or an agent whose Grant
//!   names the verb. Before the period's first write it shows the mint's
//!   preview of the record.
//! - `vault.gpu.lines.families.admit`: seats a child project of the lane as a
//!   family. An agent whose Grant names the verb seats a demand family; an
//!   interest seat is the owner's own act (the owner names the interest
//!   topics). The seat counts from the next mint, and every seat's floor must
//!   fit its own side of the allowance.
use super::doors_caller::{admit_in_txn, refused_owner_act};
use super::fold::{FamilySeat, GpuLine, Track};
use super::intent::{IntentAsk, IntentRefused, IntentStand};
use super::mint::{LineInvalid, MintError};
use super::store::{
    gpu_seconds, line_in_txn, newest_minted_in_txn, period_in_txn, period_view_in_txn,
    put_line_in_txn,
};
use super::wire::{GpuLineFamilyAdmitRequest, GpuLineSetRequest, GpuLineView};
use crate::EntityId;
use crate::consent::AuthenticatedOwner;
use crate::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE,
    MEMORY_CODE_NOT_FOUND, Memory, MemoryError,
};

/// The owner sets a lane's GPU line.
pub const VAULT_GPU_LINES_SET: &str = "vault.gpu.lines.set";
/// A lane's GPU line and its current period record.
pub const VAULT_GPU_LINES_GET: &str = "vault.gpu.lines.get";
/// Seats a family on a lane's GPU line.
pub const VAULT_GPU_LINES_FAMILIES_ADMIT: &str = "vault.gpu.lines.families.admit";

/// Why a GPU line door refused; nothing was written.
#[derive(Debug, thiserror::Error)]
pub enum GpuLineError {
    #[error(transparent)]
    Vault(#[from] crate::Error),
    /// The caller may not do this act.
    #[error(transparent)]
    Caller(MemoryError),
    #[error(transparent)]
    Intent(IntentRefused),
    #[error(transparent)]
    Invalid(#[from] LineInvalid),
    #[error(transparent)]
    Mint(#[from] MintError),
    #[error("no GPU line is set for this project")]
    NoLine,
    #[error("no such project")]
    NoProject,
    #[error("a family is a child project of its lane")]
    NotChild,
    #[error("this family already holds a seat on the line")]
    SeatTaken,
    /// One more seat's floor would not fit its own side of the allowance:
    /// the pinned share for the pinned track, the rest for the other.
    #[error("one more floor on this track does not fit its side of the allowance")]
    FloorDoesNotFit,
    /// A schedule edit that puts the vault clock before a period the line
    /// already minted, or before the new period 0: a past period would
    /// reopen.
    #[error("the new schedule puts the vault clock before period {newest}, which the line minted")]
    ScheduleBehindMint { newest: u32 },
}

impl From<GpuLineError> for MemoryError {
    fn from(error: GpuLineError) -> Self {
        let refusal = match error {
            GpuLineError::Vault(error) => return error.into(),
            GpuLineError::Caller(error) => return error,
            GpuLineError::Intent(refused) => return refused.into(),
            refusal => refusal,
        };
        let code = match &refusal {
            GpuLineError::Invalid(_) | GpuLineError::NotChild => MEMORY_CODE_BAD_REQUEST,
            GpuLineError::Mint(_)
            | GpuLineError::SeatTaken
            | GpuLineError::FloorDoesNotFit
            | GpuLineError::ScheduleBehindMint { .. } => MEMORY_CODE_INVALID_STATE,
            GpuLineError::NoLine | GpuLineError::NoProject => MEMORY_CODE_NOT_FOUND,
            GpuLineError::Vault(_) | GpuLineError::Caller(_) | GpuLineError::Intent(_) => {
                MEMORY_CODE_FORBIDDEN
            }
        };
        MemoryError::new(code, refusal.to_string(), &[])
    }
}

/// The view of `line` at `now_ms` in `txn`: its period record, minted or
/// previewed.
fn view_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    line: GpuLine,
    now_ms: u64,
    replayed: bool,
) -> crate::Result<Result<GpuLineView, GpuLineError>> {
    Ok(match period_view_in_txn(vault, txn, &line, now_ms)? {
        Ok(period) => Ok(GpuLineView {
            period_minted: period.as_ref().is_some_and(|(_, minted)| *minted),
            period: period.map(|(record, _)| record),
            line,
            replayed,
        }),
        Err(refusal) => Err(GpuLineError::Mint(refusal)),
    })
}

impl Memory<'_> {
    /// `vault.gpu.lines.set`: the owner sets the policy of `request.project`'s
    /// line. The seats stay as `families.admit` wrote them.
    ///
    /// # Errors
    ///
    /// [`GpuLineError`]: a caller who is not the owner under their own
    /// proof (an agent's Grant naming the verb is refused here), a reused
    /// intent key, an unknown project, a policy that breaks a rule of
    /// [`GpuLine::validate`] (the seated families' floors included), a
    /// schedule under which the vault clock falls before a minted period.
    /// Every refusal comes before the first write.
    pub fn set_gpu_line(
        &self,
        owner: Option<&AuthenticatedOwner>,
        request: &GpuLineSetRequest,
        now_ms: u64,
    ) -> Result<GpuLineView, GpuLineError> {
        let vault = self.vault();
        let ask = IntentAsk::new(
            self.actor(),
            VAULT_GPU_LINES_SET,
            &request.intent_key,
            &(request.project, &request.policy),
        )
        .map_err(GpuLineError::Intent)?;
        vault.with_write_txn_grouped(|txn| -> crate::Result<Result<GpuLineView, GpuLineError>> {
            let set_by = match admit_in_txn(self, txn, owner, VAULT_GPU_LINES_SET, request.project)
            {
                Ok(Some(owner)) => owner,
                Ok(None) => {
                    return Ok(Err(GpuLineError::Caller(refused_owner_act(
                        VAULT_GPU_LINES_SET,
                        "setting a GPU line",
                    ))));
                }
                Err(refusal) => return Ok(Err(GpuLineError::Caller(refusal))),
            };
            match ask.stand_in_txn(vault, txn)? {
                Err(refused) => return Ok(Err(GpuLineError::Intent(refused))),
                Ok(IntentStand::Replayed(_)) => {
                    let Some(line) = line_in_txn(vault, txn, &request.project)? else {
                        return Ok(Err(GpuLineError::NoLine));
                    };
                    return view_in_txn(vault, txn, line, now_ms, true);
                }
                Ok(IntentStand::New) => {}
            }
            if vault.project_in_txn(txn, request.project)?.is_none() {
                return Ok(Err(GpuLineError::NoProject));
            }
            let current = line_in_txn(vault, txn, &request.project)?;
            let policy = &request.policy;
            let line = GpuLine {
                project: request.project,
                unit: gpu_seconds(),
                wallet: policy.wallet.clone(),
                fleet_who: policy.fleet_who.clone(),
                period_secs: policy.period_secs,
                period_anchor_ms: policy.period_anchor_ms,
                allowance_units: policy.allowance_units,
                pinned_track: policy.pinned_track,
                pinned_parts: (policy.pinned_parts[0], policy.pinned_parts[1]),
                pinned_mode: policy.pinned_mode,
                floor_arms: policy.floor_arms,
                rung_caps_secs: policy.rung_caps_secs.clone(),
                forecast_required: policy.forecast_required,
                rules: policy.rules.clone(),
                invalid_cost: policy.invalid_cost,
                window_periods: policy.window_periods,
                hosts: policy.hosts.clone(),
                families: current
                    .as_ref()
                    .map(|line| line.families.clone())
                    .unwrap_or_default(),
                set_by: Some(set_by),
                set_at_ms: now_ms,
                revision: current.as_ref().map_or(1, |line| line.revision + 1),
            };
            if let Err(invalid) = line.validate() {
                return Ok(Err(GpuLineError::Invalid(invalid)));
            }
            // The newest period minted once the current one is: a schedule
            // edit that puts the clock before it would reopen a past period.
            let newest = newest_minted_in_txn(vault, txn, &request.project)?.max(
                current
                    .as_ref()
                    .and_then(|current| current.period_index(now_ms)),
            );
            if let Some(newest) = newest
                && line.period_index(now_ms).is_none_or(|index| index < newest)
            {
                return Ok(Err(GpuLineError::ScheduleBehindMint { newest }));
            }
            // The current period is minted first, from the line as it stood.
            if let Some(current) = &current
                && let Err(refusal) = period_in_txn(vault, txn, current, now_ms)?
            {
                return Ok(Err(GpuLineError::Mint(refusal)));
            }
            put_line_in_txn(vault, txn, &line)?;
            // A new line's current period is minted now, from this line; an
            // existing one's record stands.
            if let Err(refusal) = period_in_txn(vault, txn, &line, now_ms)? {
                return Ok(Err(GpuLineError::Mint(refusal)));
            }
            ask.keep_in_txn(vault, txn, request.project.as_bytes().to_vec(), now_ms)?;
            view_in_txn(vault, txn, line, now_ms, false)
        })?
    }

    /// `vault.gpu.lines.get`: `project`'s line and the record of the period
    /// that holds `now_ms`. Writes nothing.
    ///
    /// # Errors
    ///
    /// [`GpuLineError`]: a caller the door does not admit, no line.
    pub fn gpu_line_view(
        &self,
        owner: Option<&AuthenticatedOwner>,
        project: &EntityId,
        now_ms: u64,
    ) -> Result<GpuLineView, GpuLineError> {
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        if let Err(refusal) = admit_in_txn(self, &txn, owner, VAULT_GPU_LINES_GET, *project) {
            return Err(GpuLineError::Caller(refusal));
        }
        let Some(line) = line_in_txn(vault, &txn, project)? else {
            return Err(GpuLineError::NoLine);
        };
        view_in_txn(vault, &txn, line, now_ms, false)?
    }

    /// `vault.gpu.lines.families.admit`: seats `request.family` on
    /// `request.project`'s line. The family is a child project of the lane
    /// and holds no seat yet. The seat counts from the next mint: its floor
    /// and its market ceiling start there, never in the period already
    /// minted.
    ///
    /// # Errors
    ///
    /// [`GpuLineError`]: a caller the door does not admit, an interest seat
    /// asked by an agent, a reused intent key, no line, a family that is not
    /// a child of the lane or already holds a seat, a seed past its bounds,
    /// one floor more than the seat's side holds. Every refusal comes before
    /// the first write.
    pub fn admit_gpu_line_family(
        &self,
        owner: Option<&AuthenticatedOwner>,
        request: &GpuLineFamilyAdmitRequest,
        now_ms: u64,
    ) -> Result<GpuLineView, GpuLineError> {
        let vault = self.vault();
        let ask = IntentAsk::new(
            self.actor(),
            VAULT_GPU_LINES_FAMILIES_ADMIT,
            &request.intent_key,
            &(
                request.project,
                request.family,
                request.track,
                &request.seed,
            ),
        )
        .map_err(GpuLineError::Intent)?;
        vault.with_write_txn_grouped(|txn| -> crate::Result<Result<GpuLineView, GpuLineError>> {
            let by_owner = match admit_in_txn(
                self,
                txn,
                owner,
                VAULT_GPU_LINES_FAMILIES_ADMIT,
                request.project,
            ) {
                Ok(owner) => owner,
                Err(refusal) => return Ok(Err(GpuLineError::Caller(refusal))),
            };
            if request.track == Track::Interest && by_owner.is_none() {
                return Ok(Err(GpuLineError::Caller(refused_owner_act(
                    VAULT_GPU_LINES_FAMILIES_ADMIT,
                    "seating a family on the interest track",
                ))));
            }
            match ask.stand_in_txn(vault, txn)? {
                Err(refused) => return Ok(Err(GpuLineError::Intent(refused))),
                Ok(IntentStand::Replayed(_)) => {
                    let Some(line) = line_in_txn(vault, txn, &request.project)? else {
                        return Ok(Err(GpuLineError::NoLine));
                    };
                    return view_in_txn(vault, txn, line, now_ms, true);
                }
                Ok(IntentStand::New) => {}
            }
            let Some(mut line) = line_in_txn(vault, txn, &request.project)? else {
                return Ok(Err(GpuLineError::NoLine));
            };
            let Some(family) = vault.project_in_txn(txn, request.family)? else {
                return Ok(Err(GpuLineError::NoProject));
            };
            if !family.parents.contains(&request.project.to_hex()) {
                return Ok(Err(GpuLineError::NotChild));
            }
            if line.seat(&request.family).is_some() {
                return Ok(Err(GpuLineError::SeatTaken));
            }
            if request.seed.as_ref().is_some_and(|seed| !seed.is_bounded()) {
                return Ok(Err(GpuLineError::Invalid(LineInvalid::Seed)));
            }
            let seat = FamilySeat {
                project: request.family,
                track: request.track,
                seed: request.seed.clone(),
                admitted_by: Some(by_owner.unwrap_or_else(|| self.actor())),
                admitted_at_ms: now_ms,
            };
            let mut seated = line.clone();
            seated.families.push(seat.clone());
            if !seated.floors_fit() {
                return Ok(Err(GpuLineError::FloorDoesNotFit));
            }
            // The period's record is minted before the seat, from the line
            // as it stood.
            if let Err(refusal) = period_in_txn(vault, txn, &line, now_ms)? {
                return Ok(Err(GpuLineError::Mint(refusal)));
            }
            line.families.push(seat);
            line.revision += 1;
            put_line_in_txn(vault, txn, &line)?;
            ask.keep_in_txn(vault, txn, request.family.as_bytes().to_vec(), now_ms)?;
            view_in_txn(vault, txn, line, now_ms, false)
        })?
    }
}
