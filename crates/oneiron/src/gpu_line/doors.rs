//! The `vault.gpu.lines.*` doors' acts (design pass 32, sections 4.1 and 5).
//! The engine attests: it stamps every time, mints the period record at the
//! period's first write, and keeps each write under its intent key. Every
//! write door mints first, so an edit never reaches a period that has begun.
//!
//! - `vault.gpu.lines.set`: the owner's own act. The budget applies from the
//!   next mint; the offers, machines and role lists at once. The schedule is
//!   fixed once a period is minted.
//! - `vault.gpu.lines.get`: a read for the owner, or a Grant that holds a
//!   role on the line. Before the period's first write it shows the mint's
//!   preview of the record.
//! - `vault.gpu.lines.families.admit`: seats a child project of the lane. A
//!   lead seats a demand family inside `seat_cap` and a pinned-track family
//!   inside `pinned_seat_cap`; a lead or a planner seats a new idea; any other
//!   seat is the owner's own act. A seat asked after its period began counts from
//!   the next mint; it takes a floor at once from its side's reserve while
//!   one is left, and a new idea takes a free slot of the new-idea pool or is
//!   refused.
use super::doors_caller::{admit_in_txn, refused_owner_act};
use super::fold::{FamilySeat, GpuLine, LineRole, PeriodClockError, PeriodRoom, Side, Track};
use super::intent::{IntentAsk, IntentRefused, IntentStand};
use super::mint::{LineInvalid, MintError};
use super::store::{
    MintedLine, line_in_txn, mint_first_in_txn, newest_minted_in_txn, other_line_in_txn,
    period_view_in_txn, put_line_in_txn, seated_elsewhere_in_txn,
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

/// Why a GPU line door refused.
#[derive(Debug, thiserror::Error)]
pub enum GpuLineError {
    #[error(transparent)]
    Vault(#[from] crate::Error),
    /// The caller may not do this act, on this line.
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
    /// The family holds a live seat on this line under another ask, or on
    /// another line.
    #[error("this family already holds a seat")]
    SeatTaken,
    #[error("one_line_per_account: this vault already holds a GPU line for another project")]
    OneLinePerAccount,
    /// One more seat's floor would not fit its side at the next mint.
    #[error("seat_floor_unfunded: one more floor does not fit the {side:?} side")]
    SeatFloorUnfunded { side: Side },
    #[error("new_idea_slots_full: this period has given all {slots} of its new-idea slots")]
    NewIdeaSlotsFull { slots: u32 },
    #[error("schedule_fixed: the period length and anchor are fixed once a period is minted")]
    ScheduleFixed,
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
            | GpuLineError::OneLinePerAccount
            | GpuLineError::SeatFloorUnfunded { .. }
            | GpuLineError::NewIdeaSlotsFull { .. }
            | GpuLineError::ScheduleFixed => MEMORY_CODE_INVALID_STATE,
            GpuLineError::NoLine | GpuLineError::NoProject => MEMORY_CODE_NOT_FOUND,
            GpuLineError::Vault(_) | GpuLineError::Caller(_) | GpuLineError::Intent(_) => {
                MEMORY_CODE_FORBIDDEN
            }
        };
        MemoryError::new(code, refusal.to_string(), &[])
    }
}

/// The view of `line` at `now_ms` in `txn`: its period record, minted or
/// previewed, with the cohort seed withheld until the period ends.
fn view_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    line: GpuLine,
    now_ms: u64,
    replayed: bool,
) -> crate::Result<Result<GpuLineView, GpuLineError>> {
    Ok(match period_view_in_txn(vault, txn, &line, now_ms)? {
        Ok(period) => Ok(GpuLineView {
            preview: period.as_ref().is_some_and(|(_, preview)| *preview),
            period: period.map(|(mut record, _)| {
                if now_ms < record.end_ms {
                    record.cohort_seed = None;
                }
                record
            }),
            line,
            replayed,
        }),
        Err(refusal) => Err(GpuLineError::Mint(refusal)),
    })
}

/// Where a seat asked now takes its first floor: `None` before period 0
/// (the seat is listed from period 0's mint), else from the next mint, with
/// a floor taken at once from the period's reserve, or for a new idea its
/// slot of the new-idea pool.
fn seat_timing(
    line: &GpuLine,
    minted: &MintedLine,
    family: &EntityId,
    track: Track,
) -> Result<(u32, Option<(u32, u64)>), GpuLineError> {
    let Some(period) = &minted.period else {
        return Ok((0, None));
    };
    let next = period
        .index
        .checked_add(1)
        .ok_or(GpuLineError::Mint(MintError::PeriodOutOfRange))?;
    let room = PeriodRoom::fold(period, &line.families, &[]);
    let floor = period.floor_secs();
    if track == Track::NewIdea {
        let slots = period.policy.new_idea_slots_per_period;
        if room.new_idea_slots_taken() >= slots as usize {
            return Err(GpuLineError::NewIdeaSlotsFull { slots });
        }
        return Ok((next, Some((period.index, floor))));
    }
    // A seat that replaces one which held a floor this period gets no
    // second floor in it.
    if room.holds_floor(family) || room.reserve_left(period.policy.side_of(track)) < floor {
        return Ok((next, None));
    }
    Ok((next, Some((period.index, floor))))
}

/// The seats of `track` a lead may fill without the owner's proof: the
/// pinned track's `pinned_seat_cap`, demand's `seat_cap`, none on an interest
/// track the line does not pin (LE-6: interest seats are the owner's), and
/// no cap for new ideas, which the period's slots bound.
fn lead_seat_cap(line: &GpuLine, track: Track) -> Option<u32> {
    let budget = &line.budget;
    match track {
        Track::NewIdea => None,
        track if track == budget.pinned_track => Some(budget.pinned_seat_cap),
        Track::Demand => Some(budget.seat_cap),
        Track::Interest => Some(0),
    }
}

/// The name a refusal gives `track`.
fn track_name(track: Track) -> &'static str {
    match track {
        Track::Demand => "demand",
        Track::Interest => "interest",
        Track::NewIdea => "new-idea",
    }
}

/// The live seats of `track` on `line`.
fn live_seats(line: &GpuLine, track: Track) -> usize {
    line.families
        .iter()
        .filter(|seat| seat.lapsed_from_period.is_none() && seat.track == track)
        .count()
}

impl Memory<'_> {
    /// `vault.gpu.lines.set`: the owner sets the policy of `request.project`'s
    /// line. The seats stay as `families.admit` wrote them.
    ///
    /// # Errors
    ///
    /// [`GpuLineError`]: a caller who is not the owner under their own proof
    /// (an agent's Grant naming the verb is refused here), a reused intent
    /// key, an unknown project, a line for another project already in the
    /// vault, a policy that breaks a bound of [`GpuLine::validate`] or that
    /// the seated families cannot fund, a schedule change once a period is
    /// minted. The current period is minted first and stays minted.
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
            let caller = match admit_in_txn(self, txn, owner, VAULT_GPU_LINES_SET, request.project)
            {
                Ok(caller) => caller,
                Err(refusal) => return Ok(Err(GpuLineError::Caller(refusal))),
            };
            let Some(set_by) = caller.owner() else {
                return Ok(Err(GpuLineError::Caller(refused_owner_act(
                    VAULT_GPU_LINES_SET,
                    "setting a GPU line",
                ))));
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
            if other_line_in_txn(vault, txn, &request.project)? {
                return Ok(Err(GpuLineError::OneLinePerAccount));
            }
            // The current period is minted first, from the line as it stood.
            let current = match mint_first_in_txn(vault, txn, &request.project, now_ms)? {
                Ok(minted) => minted.map(|minted| minted.line),
                Err(refusal) => return Ok(Err(GpuLineError::Mint(refusal))),
            };
            let policy = &request.policy;
            let line = GpuLine {
                project: request.project,
                unit: policy.unit.clone(),
                wallet: policy.wallet.clone(),
                offers: policy.offers.clone(),
                machines: policy.machines.clone(),
                leads: policy.leads.clone(),
                reviewers: policy.reviewers.clone(),
                planners: policy.planners.clone(),
                period_secs: policy.period_secs,
                period_anchor_ms: policy.period_anchor_ms,
                budget: policy.budget.clone(),
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
            if let Some(current) = &current
                && (current.period_secs, current.period_anchor_ms)
                    != (line.period_secs, line.period_anchor_ms)
                && newest_minted_in_txn(vault, txn, &request.project)?.is_some()
            {
                return Ok(Err(GpuLineError::ScheduleFixed));
            }
            if let Err(PeriodClockError::OutOfRange) = line.period_index(now_ms) {
                return Ok(Err(GpuLineError::Mint(MintError::PeriodOutOfRange)));
            }
            put_line_in_txn(vault, txn, &line)?;
            // A new line's current period is minted now, from this line; an
            // existing one's record stands.
            let line = match mint_first_in_txn(vault, txn, &request.project, now_ms)? {
                Ok(Some(minted)) => minted.line,
                Ok(None) => line,
                Err(refusal) => return Ok(Err(GpuLineError::Mint(refusal))),
            };
            ask.keep_in_txn(vault, txn, request.project.as_bytes().to_vec(), now_ms)?;
            view_in_txn(vault, txn, line, now_ms, false)
        })?
    }

    /// `vault.gpu.lines.get`: `project`'s line and the record of the period
    /// that holds `now_ms`. Writes nothing.
    ///
    /// # Errors
    ///
    /// [`GpuLineError`]: a caller the door does not admit or whose Grant
    /// holds no role on this line (`not_this_line`), no line.
    pub fn gpu_line_view(
        &self,
        owner: Option<&AuthenticatedOwner>,
        project: &EntityId,
        now_ms: u64,
    ) -> Result<GpuLineView, GpuLineError> {
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        let caller = admit_in_txn(self, &txn, owner, VAULT_GPU_LINES_GET, *project)
            .map_err(GpuLineError::Caller)?;
        let Some(line) = line_in_txn(vault, &txn, project)? else {
            return Err(GpuLineError::NoLine);
        };
        caller
            .require_role(
                &line,
                &[LineRole::Lead, LineRole::Reviewer, LineRole::Planner],
                VAULT_GPU_LINES_GET,
            )
            .map_err(GpuLineError::Caller)?;
        view_in_txn(vault, &txn, line, now_ms, false)?
    }

    /// `vault.gpu.lines.families.admit`: seats `request.family` on
    /// `request.project`'s line (sections 4.1 and 5.1).
    ///
    /// # Errors
    ///
    /// [`GpuLineError`]: a caller the door does not admit or whose Grant
    /// holds no fitting role on this line; a seat past the lead's cap for its
    /// track asked without the owner's proof; a reused
    /// intent key; no line; a family that is not a child of the lane or holds
    /// a seat under another ask or on another line; a full new-idea count
    /// this period; a floor the next mint could not fund. The current period
    /// is minted first and stays minted.
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
            &(request.project, request.family, request.track),
        )
        .map_err(GpuLineError::Intent)?;
        vault.with_write_txn_grouped(|txn| -> crate::Result<Result<GpuLineView, GpuLineError>> {
            let caller = match admit_in_txn(
                self,
                txn,
                owner,
                VAULT_GPU_LINES_FAMILIES_ADMIT,
                request.project,
            ) {
                Ok(caller) => caller,
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
            let minted = match mint_first_in_txn(vault, txn, &request.project, now_ms)? {
                Ok(Some(minted)) => minted,
                Ok(None) => return Ok(Err(GpuLineError::NoLine)),
                Err(refusal) => return Ok(Err(GpuLineError::Mint(refusal))),
            };
            let mut line = minted.line.clone();
            let roles: &[LineRole] = match request.track {
                Track::NewIdea => &[LineRole::Lead, LineRole::Planner],
                Track::Demand | Track::Interest => &[LineRole::Lead],
            };
            if let Err(refusal) = caller.require_role(&line, roles, VAULT_GPU_LINES_FAMILIES_ADMIT)
            {
                return Ok(Err(GpuLineError::Caller(refusal)));
            }
            // The seat's logical key is its family: the same ask answers
            // with the seat already made, under any intent key.
            if let Some(seat) = line.seat(&request.family) {
                if seat.track != request.track {
                    return Ok(Err(GpuLineError::SeatTaken));
                }
                ask.keep_in_txn(vault, txn, request.family.as_bytes().to_vec(), now_ms)?;
                return view_in_txn(vault, txn, line, now_ms, true);
            }
            let Some(family) = vault.project_in_txn(txn, request.family)? else {
                return Ok(Err(GpuLineError::NoProject));
            };
            if !family.parents.contains(&request.project.to_hex()) {
                return Ok(Err(GpuLineError::NotChild));
            }
            if seated_elsewhere_in_txn(vault, txn, &request.project, &request.family)? {
                return Ok(Err(GpuLineError::SeatTaken));
            }
            if caller.owner().is_none()
                && let Some(cap) = lead_seat_cap(&line, request.track)
                && live_seats(&line, request.track) >= cap as usize
            {
                return Ok(Err(GpuLineError::Caller(refused_owner_act(
                    VAULT_GPU_LINES_FAMILIES_ADMIT,
                    &format!(
                        "seating a {} family past the line's cap of {cap} such seats",
                        track_name(request.track)
                    ),
                ))));
            }
            let (effective_from_period, late_floor) =
                match seat_timing(&line, &minted, &request.family, request.track) {
                    Ok(timing) => timing,
                    Err(refusal) => return Ok(Err(refusal)),
                };
            let replaces = line.last_seat(&request.family).map(|seat| seat.seat);
            line.families.push(FamilySeat {
                seat: EntityId::now(),
                project: request.family,
                track: request.track,
                replaces,
                graduated: None,
                lapsed_from_period: None,
                effective_from_period,
                late_floor,
                admitted_by: Some(caller.owner().unwrap_or_else(|| self.actor())),
                admitted_at_ms: now_ms,
            });
            match line.validate() {
                Ok(()) => {}
                Err(LineInvalid::Unfunded { side }) => {
                    return Ok(Err(GpuLineError::SeatFloorUnfunded { side }));
                }
                Err(LineInvalid::NewIdeaSlots) => {
                    return Ok(Err(GpuLineError::NewIdeaSlotsFull {
                        slots: line.budget.new_idea_slots_per_period,
                    }));
                }
                Err(invalid) => return Ok(Err(GpuLineError::Invalid(invalid))),
            }
            line.revision += 1;
            put_line_in_txn(vault, txn, &line)?;
            ask.keep_in_txn(vault, txn, request.family.as_bytes().to_vec(), now_ms)?;
            view_in_txn(vault, txn, line, now_ms, false)
        })?
    }
}
