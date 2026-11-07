//! A verb call a count-bound budget window paced, held in its caller's fair
//! line until its turn (FIX 8753; ARCH-0044 C5, a fair queue with a
//! deadline). The hold keeps what a hook's ask keeps for its drain: the
//! args the verb ran with, its ids fixed, and the reference to the exact
//! instrument and door the call came in by, with the instrument's witness
//! pinned beside the row in the hold's own write ([`super::credential`]).
//! Nothing here is authority: on the call's turn the host's check verifies
//! the witness again and runs the call through its door, whose own
//! admission and Gate run again. A managed vault's attested owner keeps only
//! his person; his door proves his live standing again.
//!
//! Each principal's calls run in the order they arrived, and the turns go
//! round the principals, one call each, from the one after the last served.
//! A call runs no earlier than its window lets it, and ends expired, unrun,
//! once its deadline passes: the hold's time plus the host's wait, 7 days
//! unless the host sets another. Any housekeeping pass expires; only the
//! host's admitted settler runs a turn. A retry of the call's invocation
//! reads the row: still held, or what its turn came to.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;
use std::sync::atomic::Ordering;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::memory::{
    MEMORY_CODE_INVALID_STATE, MEMORY_CODE_PACED_HOLD, MEMORY_CODE_PENDING_ASK, Memory,
    MemoryError, MemoryResult,
};
use crate::receipt::CallReceiptInput;
use crate::receipt::admission::{ADMISSION_INTENT_ACTIVE, refuse_held_intent_in_txn};
use crate::runtime_hooks::filter;
use crate::side_table::{self, Named, SideTable};
use crate::skill_hub::pack_catalog::HookActorClass;
use crate::task_verb::sdk::AgentVerb;
use crate::{EntityId, Error, Result, Vault};

use super::ask::{self, SavedOutcome};
use super::credential::{
    RefusalReceipt, VerbAskCredentialRef, VerbAskCredentialWitness, VerbAskDrainPermit,
    VerbAskRefusal, VerbAskResumed, VerbAskSavedCall,
};
use super::state::DrainScope;
use super::{InvocationId, hook_class, run_failed_transient};

/// The verbs a budget window's pace holds in the line: share creation and
/// the channel identity lifecycle requests the Gate paces (Engine 14:34 B).
pub(crate) const PACED_VERBS: [&str; 6] = [
    AgentVerb::VaultSharesCreate.as_str(),
    AgentVerb::VaultChannelIdentitiesProvision.as_str(),
    AgentVerb::VaultChannelIdentitiesBind.as_str(),
    AgentVerb::VaultChannelIdentitiesRotate.as_str(),
    AgentVerb::VaultChannelIdentitiesRelease.as_str(),
    AgentVerb::VaultChannelIdentitiesRouteInbound.as_str(),
];
/// How long a paced call waits for its turn when the host sets no wait.
pub const PACED_VERB_WAIT_DEFAULT_SECS: u64 = 7 * 24 * 60 * 60;
/// How long an ended call's row stays for its caller's retry.
const PACED_VERB_KEEP_SECS: u64 = 7 * 24 * 60 * 60;
/// How long a turn that failed on a passing fault waits before its next try.
const PACED_VERB_RETRY_SECS: u64 = 60;
/// The most rows one expiry pass ends or deletes.
const PACED_VERB_EXPIRE_MAX: usize = 256;
/// What a call whose deadline passed before its turn ends with.
const EXPIRED: &str = "this paced call's deadline passed before its turn; it never ran";

/// Held calls, by invocation.
const CALLS: SideTable<[u8; 16], PacedVerbCall, Named> =
    SideTable::new(&side_table::HOOKS_PACED_VERB);
/// The line's last arrival and last served principal.
const LINE: SideTable<(), PacedLine, Named> = SideTable::new(&side_table::HOOKS_PACED_VERB_LINE);
/// Each held call's pinned witness, by invocation.
const WITNESSES: SideTable<[u8; 16], PacedWitness, Named> =
    SideTable::new(&side_table::HOOKS_PACED_VERB_WITNESS);

thread_local! {
    /// The invocation whose paced turn runs on this thread, while it runs.
    static TURN: Cell<Option<InvocationId>> = const { Cell::new(None) };
}

/// One held call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PacedVerbCall {
    verb: String,
    #[serde(with = "crate::serialize::entity_ref")]
    actor: EntityId,
    class: HookActorClass,
    /// The args the verb ran with, its ids fixed, as JSON.
    args: String,
    /// The instrument and door the call runs again through; no authority.
    reference: VerbAskCredentialRef,
    /// The held call's handle: the drain's in-flight hold names it.
    #[serde(with = "crate::serialize::entity_ref")]
    work: EntityId,
    /// Its place in the line, from 1: within a principal, earlier runs
    /// first.
    arrival: u64,
    held_at: u64,
    /// Fixed at the hold: the call ends expired, unrun, once it passes.
    deadline: u64,
    /// The earliest its budget window lets it run, Unix seconds.
    next_eligible_at: u64,
    state: PacedState,
    /// The verb's effect committed on a turn, in its own write: the call
    /// never runs again, whatever its turn's end saves.
    landed: bool,
    /// What the call came to, once ended.
    outcome: Option<SavedOutcome>,
    ended_at: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PacedState {
    /// In its principal's line.
    Waiting,
    /// A turn took it and has not saved what it came to. A crash can leave
    /// it set: a turn then takes it again, under the drain's hold.
    Running,
    /// Ran, refused or expired: its outcome says which.
    Ended,
}

/// The line's bookkeeping.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct PacedLine {
    last_arrival: u64,
    /// The principal whose call took the last turn.
    last_served: Option<EntityId>,
}

/// One held call's pinned witness: the call it backs, the reference and the
/// instrument itself. No secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PacedWitness {
    #[serde(with = "crate::serialize::entity_ref")]
    work: EntityId,
    reference: VerbAskCredentialRef,
    binding: VerbAskCredentialWitness,
}

/// Marks this thread as one paced call's turn while held: the verb runs
/// its call instead of holding it again.
pub(super) struct PacedTurnScope(Option<InvocationId>, PhantomData<*const ()>);

impl PacedTurnScope {
    pub(super) fn enter(invocation: InvocationId) -> Self {
        Self(
            TURN.with(|turn| turn.replace(Some(invocation))),
            PhantomData,
        )
    }
}

impl Drop for PacedTurnScope {
    fn drop(&mut self) {
        TURN.with(|turn| turn.set(self.0));
    }
}

/// Whether this thread runs `invocation`'s paced turn.
#[must_use]
pub(crate) fn runs_paced_turn(invocation: InvocationId) -> bool {
    TURN.with(Cell::get) == Some(invocation)
}

/// The refusal a held call answers: it waits in its caller's line to run
/// at `next_eligible_at` or later, and ends unrun at `deadline`.
fn held(next_eligible_at: u64, deadline: u64) -> MemoryError {
    MemoryError {
        resets_at: vec![next_eligible_at],
        ..MemoryError::new(
            MEMORY_CODE_PACED_HOLD,
            format!(
                "a budget window paced this call: it waits in its caller's line to run at \
                 {next_eligible_at} or later, and ends unrun at {deadline}"
            ),
            &[
                "Send nothing again: the call runs on its turn. Retry with the same invocation to read what it came to.",
            ],
        )
    }
}

/// The refusal a paced call's turn answers when its window paces it again:
/// the drain puts it back in line, not before `next_eligible_at`.
pub(crate) fn paced_turn_again(next_eligible_at: u64) -> MemoryError {
    MemoryError {
        resets_at: vec![next_eligible_at],
        ..MemoryError::new(
            MEMORY_CODE_PACED_HOLD,
            format!(
                "a budget window paced this call's turn; it runs at {next_eligible_at} or later"
            ),
            &["Send nothing again: the call runs on its next turn."],
        )
    }
}

/// Holds `memory`'s call of `verb` with `args` in its principal's paced
/// line, to run no earlier than `next_eligible_at`: the refusal its caller
/// gets. `None` when the call cannot be held, so it answers as it did: no
/// invocation the host bound, no credential its host can run again, no
/// check installed or one that would not keep it, a hook's ask saved for
/// the invocation, or an ended call under it.
///
/// # Errors
///
/// Storage errors as they occur.
pub(crate) fn hold_paced_verb_call(
    memory: &Memory<'_>,
    verb: &str,
    args: &Value,
    next_eligible_at: u64,
) -> Result<Option<MemoryError>> {
    let vault = memory.vault();
    let Some(invocation) = memory.invocation() else {
        return Ok(None);
    };
    let Some(check) = vault.verb_hook_state.credential_check() else {
        return Ok(None);
    };
    let Some(credential) = memory.verb_ask_credential() else {
        return Ok(None);
    };
    // A call a hook's ask stopped resumes through that ask, never twice.
    if ask::saved(vault, invocation)? {
        return Ok(None);
    }
    let args = serde_json::to_string(args)
        .map_err(|_| Error::InvariantViolation("paced verb call args encode"))?;
    let reference = credential.reference().clone();
    let binding = credential.into_witness();
    let (actor, class) = (memory.actor(), hook_class(memory.actor_class()));
    let wait = vault.paced_verb_wait_secs();
    let key = invocation.0;
    vault.with_write_txn_grouped(|txn| {
        if let Some(row) = CALLS.get(&vault.store, txn, &key)? {
            return Ok(
                (row.state != PacedState::Ended).then(|| held(row.next_eligible_at, row.deadline))
            );
        }
        if !check.retain_in_txn(vault, txn, &reference, &binding) {
            return Ok(None);
        }
        let now = vault.store.clock.now_recorded_at();
        let mut line = LINE.get(&vault.store, txn, &())?.unwrap_or_default();
        line.last_arrival = line.last_arrival.saturating_add(1);
        let work = EntityId::now();
        let row = PacedVerbCall {
            verb: verb.to_owned(),
            actor,
            class,
            args,
            reference: reference.clone(),
            work,
            arrival: line.last_arrival,
            held_at: now,
            deadline: now.saturating_add(wait),
            next_eligible_at: next_eligible_at.max(now),
            state: PacedState::Waiting,
            landed: false,
            outcome: None,
            ended_at: None,
        };
        let witness = PacedWitness {
            work,
            reference,
            binding,
        };
        CALLS.put(&vault.store, txn, &key, &row)?;
        WITNESSES.put(&vault.store, txn, &key, &witness)?;
        LINE.put(&vault.store, txn, &(), &line)?;
        Ok(Some(held(row.next_eligible_at, row.deadline)))
    })
}

/// What a retry of `memory`'s call of `verb` meets when a budget window
/// paced an earlier try of its invocation: still held, or what its turn
/// came to. `None` when nothing of it is held, or this thread runs its turn.
/// Another caller naming the invocation is refused, never answered.
pub(crate) fn paced_verb_reply(memory: &Memory<'_>, verb: &str) -> Option<MemoryResult<Value>> {
    if !PACED_VERBS.contains(&verb) {
        return None;
    }
    let invocation = memory.invocation()?;
    if runs_paced_turn(invocation) {
        return None;
    }
    let vault = memory.vault();
    let read = || -> Result<Option<PacedVerbCall>> {
        let rtxn = vault.store.env.read_txn()?;
        CALLS.get(&vault.store, &rtxn, &invocation.0)
    };
    let row = match read() {
        Ok(row) => row?,
        Err(error) => return Some(Err(error.into())),
    };
    let same = row.verb == verb
        && row.actor == memory.actor()
        && row.class == hook_class(memory.actor_class())
        && memory
            .verb_ask_credential()
            .is_some_and(|credential| row.reference.same_caller(credential.reference()));
    if !same {
        return Some(Err(MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            "this invocation names another caller's paced call",
            &["Call again with a new invocation."],
        )));
    }
    Some(match (row.state, row.outcome) {
        (PacedState::Ended, Some(SavedOutcome::Ok { result })) => serde_json::from_str(&result)
            .map_err(|_| Error::CorruptedIndex("paced verb call outcome").into()),
        (PacedState::Ended, Some(SavedOutcome::Err { code, message, .. })) => {
            Err(MemoryError::new(
                &code,
                message,
                &["This invocation's paced call ended; call again with a new invocation."],
            ))
        }
        (PacedState::Ended, None) => Err(Error::CorruptedIndex("paced verb call outcome").into()),
        _ => Err(held(row.next_eligible_at, row.deadline)),
    })
}

impl Memory<'_> {
    /// What a retry of this handle's call of `verb` meets once a budget
    /// window held an earlier try of its invocation and the drain ran it to
    /// its end: the saved result, or the saved refusal (FIX 8753). A
    /// transport answers it before it starts the call again, so the effect
    /// never runs twice. `None` while the call still waits in line, when
    /// nothing of it was held, and on the drain's own run of it.
    #[must_use]
    pub fn ended_paced_verb_reply(&self, verb: &str) -> Option<MemoryResult<Value>> {
        match paced_verb_reply(self, verb)? {
            Err(error) if error.code == MEMORY_CODE_PACED_HOLD => None,
            reply => Some(reply),
        }
    }
}

/// Marks the paced call `invocation`'s turn runs as landed, in the verb's
/// own effect write, so the effect and the mark commit together: the call
/// never runs again, and its witness goes. What it came to is saved at the
/// turn's end, as its caller's view after every post hook, never the
/// verb's own result.
///
/// # Errors
///
/// Storage errors as they occur.
pub(crate) fn land_paced_verb_call_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    invocation: InvocationId,
) -> Result<()> {
    let key = invocation.0;
    let Some(mut row) = CALLS.get(&vault.store, txn, &key)? else {
        return Ok(());
    };
    if row.state != PacedState::Running {
        return Ok(());
    }
    row.landed = true;
    CALLS.put(&vault.store, txn, &key, &row)?;
    WITNESSES.delete(&vault.store, txn, &key).map(drop)
}

/// What a landed call whose turn kept no answer saves: it ran, and must not
/// be sent again.
fn not_retained() -> SavedOutcome {
    SavedOutcome::error(
        super::HOOK_RESULT_NOT_RETAINED.to_owned(),
        "this paced call ran on its turn, but its answer was not kept; do not send it again",
    )
}

/// What a turn's claim found.
enum Claim {
    /// The call is the turn's to run.
    Taken,
    /// Its effect had landed: it ended without running.
    Ended,
    /// Another took it, it ended, or its window or deadline moved.
    Skipped,
}

/// How a turn's run left its call.
enum TurnEnd {
    /// It ran or was refused: what it came to, and the refusal receipt a
    /// failure leaves. A refusal before its door also settles its held
    /// admission intent, which no door run settles.
    Ended(SavedOutcome, Option<CallReceiptInput>),
    /// Its window paced it again, or a passing fault stopped it: back in
    /// line, not before this time.
    Back(u64),
    /// A hook asked on its turn: the ask holds the call now.
    HandedToAsk,
}

impl Vault {
    /// Sets how long a paced call waits for its turn before it ends unrun,
    /// counted from its hold; 0 keeps the default, 7 days. The host sets it
    /// from its limits before its settler starts.
    pub fn set_paced_verb_wait_secs(&self, secs: u64) {
        self.verb_hook_state
            .paced_wait
            .store(secs, Ordering::Release);
    }

    fn paced_verb_wait_secs(&self) -> u64 {
        match self.verb_hook_state.paced_wait.load(Ordering::Acquire) {
            0 => PACED_VERB_WAIT_DEFAULT_SECS,
            secs => secs,
        }
    }

    /// The earliest `actor`'s held calls of `verb` may run, while any is in
    /// line: a new call of theirs joins the line behind them, never ahead.
    ///
    /// # Errors
    ///
    /// Reading the line.
    pub(crate) fn paced_verb_line_waits(&self, actor: EntityId, verb: &str) -> Result<Option<u64>> {
        let rtxn = self.store.env.read_txn()?;
        Ok(CALLS
            .scan(&self.store, &rtxn)?
            .into_iter()
            .filter(|(_, row)| {
                row.actor == actor && row.verb == verb && row.state != PacedState::Ended
            })
            .map(|(_, row)| row.next_eligible_at)
            .min())
    }

    /// Runs at most `limit` held calls' turns, after expiring the calls
    /// whose deadline passed. A turn takes the head of one principal's line
    /// whose window opened, from the principal after the last served,
    /// round the principals. The call runs through the host's check as its
    /// credential stands then; it ends with what it returned, or refused,
    /// with one receipt; a window that paces it again puts it back in line.
    /// A call whose retry is in flight now waits for the next pass. The
    /// host's admitted settler calls this; with no check installed, every
    /// turn ends refused. Returns how many turns ran.
    ///
    /// # Errors
    ///
    /// Reading the line. A storage error on one turn leaves its call in
    /// line, its witness kept.
    pub fn drain_paced_verb_calls(&self, limit: usize) -> Result<usize> {
        self.expire_paced_verb_calls(PACED_VERB_EXPIRE_MAX)?;
        let mut ran = 0;
        let mut passed = BTreeSet::new();
        while ran < limit {
            let Some((key, row)) = self.next_paced_turn(&passed)? else {
                break;
            };
            let actor = row.actor;
            if self.run_paced_turn(key, row)? {
                ran += 1;
            } else {
                passed.insert(actor);
            }
        }
        Ok(ran)
    }

    /// The next turn: each principal's head of line, the first whose window
    /// opened and whose deadline holds, taken from the principal after the
    /// last served, round the principals. `passed` principals wait for the
    /// next pass.
    fn next_paced_turn(
        &self,
        passed: &BTreeSet<EntityId>,
    ) -> Result<Option<([u8; 16], PacedVerbCall)>> {
        let rtxn = self.store.env.read_txn()?;
        let now = self.store.clock.now_recorded_at();
        let last = LINE.get(&self.store, &rtxn, &())?.unwrap_or_default();
        let mut heads: BTreeMap<EntityId, ([u8; 16], PacedVerbCall)> = BTreeMap::new();
        for (key, row) in CALLS.scan(&self.store, &rtxn)? {
            if row.state == PacedState::Ended {
                continue;
            }
            match heads.get(&row.actor) {
                Some((_, head)) if head.arrival <= row.arrival => {}
                _ => {
                    heads.insert(row.actor, (key, row));
                }
            }
        }
        let ready = |(actor, (key, row)): (&EntityId, &([u8; 16], PacedVerbCall))| {
            (!passed.contains(actor)
                && row.next_eligible_at <= now
                && row.deadline > now
                && !self.verb_hook_state.drain_holds(InvocationId(*key)))
            .then(|| (*key, row.clone()))
        };
        let after = last.last_served.map_or_else(
            || heads.iter().find_map(ready),
            |served| {
                heads
                    .range((
                        std::ops::Bound::Excluded(served),
                        std::ops::Bound::Unbounded,
                    ))
                    .find_map(ready)
                    .or_else(|| heads.range(..=served).find_map(ready))
            },
        );
        Ok(after)
    }

    /// Runs one turn and saves what its call came to; false when it did not
    /// run. The invocation is held for the drain from before the call until
    /// its end is saved, and the row is marked running meanwhile.
    fn run_paced_turn(&self, key: [u8; 16], row: PacedVerbCall) -> Result<bool> {
        let invocation = InvocationId(key);
        let Some(_held) = self
            .verb_hook_state
            .hold_for_drain(invocation, row.actor, row.work)
        else {
            return Ok(false);
        };
        let claimed = self.with_write_txn_grouped(|txn| {
            let now = self.store.clock.now_recorded_at();
            let Some(mut current) = CALLS.get(&self.store, txn, &key)? else {
                return Ok(Claim::Skipped);
            };
            if current.work != row.work || current.state == PacedState::Ended {
                return Ok(Claim::Skipped);
            }
            // A call whose effect landed before its turn's end was saved (a
            // crash between them) never runs again.
            if current.landed {
                current.state = PacedState::Ended;
                current.outcome = Some(not_retained());
                current.ended_at = Some(now);
                CALLS.put(&self.store, txn, &key, &current)?;
                return Ok(Claim::Ended);
            }
            if current.deadline <= now || current.next_eligible_at > now {
                return Ok(Claim::Skipped);
            }
            current.state = PacedState::Running;
            CALLS.put(&self.store, txn, &key, &current)?;
            let mut line = LINE.get(&self.store, txn, &())?.unwrap_or_default();
            line.last_served = Some(current.actor);
            LINE.put(&self.store, txn, &(), &line)?;
            Ok(Claim::Taken)
        })?;
        match claimed {
            Claim::Taken => {}
            Claim::Ended => return Ok(true),
            Claim::Skipped => return Ok(false),
        }
        let class = filter::edge_class(row.class);
        let Ok(args) = serde_json::from_str::<Value>(&row.args) else {
            let outcome = SavedOutcome::error(
                MEMORY_CODE_INVALID_STATE.to_owned(),
                "this paced call's saved args do not decode; it never ran",
            );
            self.end_paced_turn(key, row.work, TurnEnd::Ended(outcome, None))?;
            return Ok(true);
        };
        let receipt = RefusalReceipt::new(&row.reference, &row.verb, row.actor, class, &args, None);
        let ran = match self.resume_paced_turn(key, &row, class, args)? {
            VerbAskResumed::Ran(ran) => ran,
            VerbAskResumed::Refused(refusal) => Err(refusal.error()),
        };
        let now = self.store.clock.now_recorded_at();
        let end = match ran {
            Ok(value) => TurnEnd::Ended(SavedOutcome::result(&value)?, None),
            Err(error) if error.code == MEMORY_CODE_PACED_HOLD => TurnEnd::Back(
                error
                    .resets_at
                    .first()
                    .copied()
                    .unwrap_or_else(|| now.saturating_add(PACED_VERB_RETRY_SECS)),
            ),
            Err(error) if error.code == MEMORY_CODE_PENDING_ASK => TurnEnd::HandedToAsk,
            // A retry of its invocation holds the admission intent now: the
            // turn waits for it, never ends the call.
            Err(error)
                if error
                    .reason_codes
                    .iter()
                    .any(|code| code == ADMISSION_INTENT_ACTIVE) =>
            {
                TurnEnd::Back(now.saturating_add(PACED_VERB_RETRY_SECS))
            }
            Err(error) if run_failed_transient(&error) => {
                TurnEnd::Back(now.saturating_add(PACED_VERB_RETRY_SECS))
            }
            Err(error) => {
                let receipt = receipt.refused(&error.code, &error.message);
                TurnEnd::Ended(
                    SavedOutcome::error(error.code, &error.message),
                    Some(receipt),
                )
            }
        };
        self.end_paced_turn(key, row.work, end)?;
        Ok(true)
    }

    /// Hands one turn's call to the host's check, the call's thread marked
    /// as the drain's run of its paced turn. No check installed, or no
    /// witness pinned for this call and reference, refuses it before
    /// anything runs.
    fn resume_paced_turn(
        &self,
        key: [u8; 16],
        row: &PacedVerbCall,
        class: crate::EdgeActorClass,
        args: Value,
    ) -> Result<VerbAskResumed> {
        let Some(check) = self.verb_hook_state.credential_check() else {
            return Ok(VerbAskResumed::Refused(
                VerbAskRefusal::CredentialUnavailable,
            ));
        };
        let witness = {
            let rtxn = self.store.env.read_txn()?;
            WITNESSES.get_lenient(&self.store, &rtxn, &key)?
        };
        let Some(witness) = witness
            .filter(|witness| witness.work == row.work && witness.reference == row.reference)
        else {
            return Ok(VerbAskResumed::Refused(VerbAskRefusal::CredentialMissing));
        };
        let invocation = InvocationId(key);
        let call = VerbAskSavedCall {
            invocation,
            verb: row.verb.clone(),
            actor: row.actor,
            class,
            args,
            reference: row.reference.clone(),
            witness: witness.binding,
        };
        let _draining = DrainScope::enter(invocation);
        let _turn = PacedTurnScope::enter(invocation);
        let drain =
            VerbAskDrainPermit::paced(invocation).with_credential_door(call.reference.door.clone());
        Ok(check.resume(call, drain))
    }

    /// Saves how turn `work` left its call, unless the verb's own effect
    /// write ended it first. An ended call's witness goes with it.
    fn end_paced_turn(&self, key: [u8; 16], work: EntityId, end: TurnEnd) -> Result<()> {
        self.with_write_txn_grouped(|txn| {
            let Some(mut row) = CALLS.get(&self.store, txn, &key)? else {
                return Ok(());
            };
            if row.work != work || row.state != PacedState::Running {
                return Ok(());
            }
            // A call whose effect landed keeps its caller's answer, or that
            // it ran: it never goes back in line or to an ask.
            let end = match end {
                TurnEnd::Ended(SavedOutcome::Err { .. }, _)
                | TurnEnd::Back(_)
                | TurnEnd::HandedToAsk
                    if row.landed =>
                {
                    TurnEnd::Ended(not_retained(), None)
                }
                end => end,
            };
            match end {
                TurnEnd::Back(at) => {
                    row.state = PacedState::Waiting;
                    row.next_eligible_at = at;
                    return CALLS.put(&self.store, txn, &key, &row);
                }
                TurnEnd::HandedToAsk => {
                    CALLS.delete(&self.store, txn, &key)?;
                }
                TurnEnd::Ended(mut outcome, receipt) => {
                    if let SavedOutcome::Err {
                        code,
                        message,
                        receipt: saved,
                    } = &mut outcome
                    {
                        if let Some(receipt) = receipt {
                            *saved = Some(self.record_call_receipt_in_txn(txn, receipt)?);
                        }
                        // A call refused before its door left its admission
                        // intent held; no door run settles it.
                        refuse_held_intent_in_txn(
                            self,
                            txn,
                            row.actor,
                            filter::edge_class(row.class),
                            InvocationId(key),
                            code,
                            message,
                        )?;
                    }
                    row.state = PacedState::Ended;
                    row.outcome = Some(outcome);
                    row.ended_at = Some(self.store.clock.now_recorded_at());
                    CALLS.put(&self.store, txn, &key, &row)?;
                }
            }
            WITNESSES.delete(&self.store, txn, &key).map(drop)
        })
    }

    /// Ends each held call whose deadline passed, unrun, its witness
    /// dropped, and deletes ended rows past their keep; at most `limit`
    /// rows. A call a turn runs now is left to that turn. It charges,
    /// spends and runs nothing, so any housekeeping pass may call it.
    /// Returns how many rows it ended or deleted.
    ///
    /// # Errors
    ///
    /// Storage errors as they occur.
    pub fn expire_paced_verb_calls(&self, limit: usize) -> Result<usize> {
        self.with_write_txn_grouped(|txn| {
            let now = self.store.clock.now_recorded_at();
            let mut touched = 0;
            for (key, mut row) in CALLS.scan(&self.store, txn)? {
                if touched >= limit {
                    break;
                }
                if row.state == PacedState::Ended {
                    if row
                        .ended_at
                        .is_some_and(|at| at.saturating_add(PACED_VERB_KEEP_SECS) <= now)
                    {
                        CALLS.delete(&self.store, txn, &key)?;
                        touched += 1;
                    }
                    continue;
                }
                if row.deadline > now || self.verb_hook_state.drain_holds(InvocationId(key)) {
                    continue;
                }
                row.outcome = Some(if row.landed {
                    not_retained()
                } else {
                    refuse_held_intent_in_txn(
                        self,
                        txn,
                        row.actor,
                        filter::edge_class(row.class),
                        InvocationId(key),
                        MEMORY_CODE_INVALID_STATE,
                        EXPIRED,
                    )?;
                    SavedOutcome::error(MEMORY_CODE_INVALID_STATE.to_owned(), EXPIRED)
                });
                row.state = PacedState::Ended;
                row.ended_at = Some(now);
                CALLS.put(&self.store, txn, &key, &row)?;
                WITNESSES.delete(&self.store, txn, &key)?;
                touched += 1;
            }
            Ok(touched)
        })
    }

    /// When the line next owes work: the earliest a held call's window
    /// opens or its deadline passes. `None` while nothing waits.
    ///
    /// # Errors
    ///
    /// Reading the line.
    pub fn paced_verb_wake_at(&self) -> Result<Option<u64>> {
        let rtxn = self.store.env.read_txn()?;
        Ok(CALLS
            .scan(&self.store, &rtxn)?
            .into_iter()
            .filter(|(_, row)| row.state != PacedState::Ended)
            .map(|(_, row)| row.next_eligible_at.min(row.deadline))
            .min())
    }
}
