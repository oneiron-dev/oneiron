//! The durable Wait handle (ARCH-0082 #ladder and #waits; ROLES-CHECKIN P2.2,
//! pieces 2b and 2d; Engine ruling P22-SHAPE).
//!
//! When [`check_in`](super::check_in) answers `Wait`, the caller opens a
//! pending check-in: one `CHECK_IN_PENDING` row on the node that opened it
//! (Q1 = A), with its asker, grant, verb, act class, scope, effect digest,
//! rungs and state, and one `check_in` receipt per transition in the same
//! transaction (Q8 = A). Opening it never runs the act; nothing in this
//! module runs one.
//!
//! The ladder above rung 1 is rungs 2 to 4: the grantor, the next holders up
//! the grant chain, the Owner role. A [`RungResolver`] names each rung's
//! holders from verified records when the ask enters it, and they are pinned
//! there (Q3, Q9). The same resolver says whether a pinned holder may still
//! answer (its live grant and its own check-in, re-read at each answer) and
//! carries the agent holders' verdicts (Q4). `VerifiedChain` is the
//! resolver over the verified records (2c). The host that wakes a due row is
//! 2e; the agent verbs are 2f and 2l.

use serde::{Deserialize, Serialize};

use super::act_class::{ActClass, ProofKind};
use super::mode::CheckInMode;
use super::policy::{CheckInScope, ClassWait};
use super::receipt::{CheckInOutcome, ReceiptFields, write_check_in_receipt_in_txn};
use super::resolve::WaitReason;
use super::waits::{enter_next_rung, refuse};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

/// Pending check-in id → its row.
pub(super) const PENDING: SideTable<EntityId, PendingCheckIn, Named> =
    SideTable::new(&side_table::CHECK_IN_PENDING);

/// Each open pending check-in by its next due time (2e): the housekeeping
/// pass reads it in order (`wake`), and the vault's wake reads its first row.
pub(super) const DUE: SideTable<(u64, EntityId), (), Named> =
    SideTable::new(&side_table::CHECK_IN_DUE);

/// Writes `row` and moves its `DUE` entry to the row's next due time, or
/// drops it once the row is final. Every write of a pending row comes here,
/// so the index holds each open row once, at its due time; a row written
/// before the index existed gains its entry at its next write.
///
/// # Errors
///
/// Storage errors.
pub(super) fn store_pending_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    row: &PendingCheckIn,
) -> Result<()> {
    let stored_due = PENDING
        .get(store, txn, &row.id)?
        .and_then(|stored| stored.next_due_at());
    let due = row.next_due_at();
    if let Some(at) = stored_due.filter(|at| Some(*at) != due) {
        DUE.delete(store, txn, &(at, row.id))?;
    }
    if let Some(at) = due {
        DUE.put(store, txn, &(at, row.id), &())?;
    }
    PENDING.put(store, txn, &row.id, row)
}

/// Deletes the row `id` and its `DUE` entry.
fn delete_pending_in_txn(store: &Store, txn: &mut heed::RwTxn<'_>, id: &EntityId) -> Result<()> {
    if let Some(at) = PENDING
        .get(store, txn, id)?
        .and_then(|stored| stored.next_due_at())
    {
        DUE.delete(store, txn, &(at, *id))?;
    }
    PENDING.delete(store, txn, id)?;
    Ok(())
}

/// A rung of the ladder above rung 1 (ARCH-0082 #ladder).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rung {
    /// Rung 2: the parent of a spawned child, the person behind a companion,
    /// the binder of a house agent.
    Grantor,
    /// Rung 3: the next holders up the grant chain, all holders of a role at
    /// once.
    ChainHolders,
    /// Rung 4: the Owner role, where the chain ends.
    Owner,
}

impl Rung {
    /// The rung's number on canon's ladder.
    #[must_use]
    pub const fn number(self) -> u8 {
        match self {
            Self::Grantor => 2,
            Self::ChainHolders => 3,
            Self::Owner => 4,
        }
    }

    /// The rung above this one; `None` above the Owner.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self {
            Self::Grantor => Some(Self::ChainHolders),
            Self::ChainHolders => Some(Self::Owner),
            Self::Owner => None,
        }
    }

    /// The receipt token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Grantor => "grantor",
            Self::ChainHolders => "chain_holders",
            Self::Owner => "owner",
        }
    }
}

/// Whether a holder is a person or an agent. Only a person rung waits; an
/// agent answers at once or passes up (ARCH-0082 #waits, ruling R2).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HolderKind {
    Person,
    Agent,
}

/// One holder a rung asks, pinned when the ask enters the rung.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RungHolder {
    pub principal: EntityId,
    pub kind: HolderKind,
}

/// Who a rung asks, as a [`RungResolver`] reads the verified records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RungMembers {
    Holders(Vec<RungHolder>),
    /// No verified record names a holder; the text names the missing link
    /// (for example the spawn parent's principal). The rung is skipped at
    /// once with a receipt that names it (P22-SHAPE Q3 = A).
    Missing(String),
}

/// Names the holders of one rung of one pending check-in, from verified
/// records only, when the ask enters that rung; says whether a holder may
/// still answer; and carries the agent holders' verdicts.
pub(crate) trait RungResolver {
    /// # Errors
    ///
    /// Storage errors. A rung with no verified holder is
    /// [`RungMembers::Missing`], not an error.
    fn members(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        pending: &PendingCheckIn,
        rung: Rung,
    ) -> Result<RungMembers>;

    /// Whether `holder` may answer `pending` at `now`: read when the ask
    /// pins the holder, and again at each answer and extension (P22-SHAPE
    /// Q9), so a holder whose grant lapsed since cannot answer.
    ///
    /// # Errors
    ///
    /// Storage errors.
    fn may_answer(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        pending: &PendingCheckIn,
        holder: &RungHolder,
        now: u64,
    ) -> Result<bool>;

    /// An agent holder's verdict on `pending`, asked once when the ask
    /// enters the agent's rung (P22-SHAPE Q4 = A). `None`: no verdict, and
    /// the agent passes the ask up.
    fn agent_verdict(&self, pending: &PendingCheckIn, holder: &RungHolder) -> Option<HolderAnswer>;
}

/// The wait a person rung captured when the ask entered it (P22-SHAPE Q5).
/// A policy change applies only to rungs entered after it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapturedWait {
    /// The act class's effective wait per person rung, and its source.
    pub floor: ClassWait,
    /// The wait this rung runs: the floor, or the asker's longer wait.
    pub secs: u64,
    pub due_at: u64,
}

/// A holder's "give me until <time>" on one rung, receipted. `by` is `None`
/// once the holder's erase scrubbed it; the extension stands.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Extension {
    pub until: u64,
    pub by: Option<EntityId>,
    pub at: u64,
}

/// One rung the ask entered.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RungEntry {
    pub rung: Rung,
    pub entered_at: u64,
    /// The holders pinned on entry; empty on a skipped rung.
    pub holders: Vec<RungHolder>,
    /// The missing link of a skipped rung.
    pub skipped: Option<String>,
    /// The person wait; `None` on a rung with no person holder.
    pub wait: Option<CapturedWait>,
    /// The latest extension a holder gave on this rung.
    pub extension: Option<Extension>,
}

impl RungEntry {
    /// When the rung's wait ends: the extension, else the captured wait. A
    /// rung with no person holder is due when it is entered.
    #[must_use]
    pub fn due_at(&self) -> u64 {
        match (&self.extension, &self.wait) {
            (Some(extension), _) => extension.until,
            (None, Some(wait)) => wait.due_at,
            (None, None) => self.entered_at,
        }
    }
}

/// An objection to a delay window, admitted by canon's PR 4 producer. `by`
/// is `None` once the objector's erase scrubbed it; the objection stands.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Objection {
    pub by: Option<EntityId>,
    pub at: u64,
}

/// A delay window the act's proof is (ARCH-0082 #no-answer): silence at its
/// end is the proof, and an objection holds it. Its notice and objections
/// come from canon's PR 4 producer; this row keeps them.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DelayWindow {
    pub notice_at: u64,
    pub ends_at: u64,
    pub objections: Vec<Objection>,
}

/// A holder's answer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HolderAnswer {
    Approve,
    Deny,
}

impl HolderAnswer {
    /// The receipt token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Deny => "deny",
        }
    }
}

/// A holder's answer and the effect it is over: it settles the ask only
/// over the exact effect digest the ask waits on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HolderReply {
    pub effect_digest: [u8; 32],
    pub answer: HolderAnswer,
}

/// Where a pending check-in stands. Every state but `Open` is final, and
/// each is receipted (canon's table "When nobody answers").
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingState {
    /// On a rung, or past the last rung while its delay window runs.
    Open,
    /// The first valid answer landed; every other holder reads who gave it
    /// (`None` once that holder's erase scrubbed it).
    Answered {
        answer: HolderAnswer,
        by: Option<EntityId>,
        rung: Rung,
        at: u64,
    },
    /// The asker's `until` passed: the ask let go, and nothing happens.
    LetGo { at: u64 },
    /// The chain is exhausted and the act may not proceed on silence: it
    /// holds, and the agent goes on with other work.
    Held { at: u64 },
    /// The chain is exhausted, the act is undoable and its mode is
    /// `AskWhenUnsure`: it may proceed with this undo plan (ARCH-0076, a
    /// reversible step takes the answer). Running it is 2e.
    ProceedWithUndo { at: u64, undo_plan: String },
    /// The delay window ended in silence: that is the proof.
    WindowPassed { at: u64 },
    /// The delay window ended with an objection standing: it holds.
    ObjectionHeld { at: u64 },
}

/// A pending check-in.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PendingCheckIn {
    pub id: EntityId,
    pub asker: EntityId,
    /// The asker's grant on this vault link, by its ref.
    pub grant_ref: String,
    /// The exact verb that waits.
    pub verb: String,
    pub act: ActClass,
    pub scope: CheckInScope,
    /// The digest of the exact effect; an answer over any other settles
    /// nothing.
    pub effect_digest: [u8; 32],
    /// The mode the check-in resolved to.
    pub mode: CheckInMode,
    pub reason: WaitReason,
    pub opened_at: u64,
    /// The asker's longer wait per person rung, beside `until`.
    pub asker_wait_secs: Option<u64>,
    /// The asker's cutoff: at it the ask lets go.
    pub until: Option<u64>,
    /// The domain undo the caller gave at open; without one an exhausted
    /// chain holds.
    pub undo_plan: Option<String>,
    pub delay_window: Option<DelayWindow>,
    /// Every rung the ask entered, in order; the last is the current one.
    pub rungs: Vec<RungEntry>,
    /// When the ask passed the last rung while its delay window still ran.
    pub chain_exhausted_at: Option<u64>,
    pub state: PendingState,
    /// The receipts written so far; the next receipt's sequence.
    pub transitions: u32,
}

impl PendingCheckIn {
    /// The rung the ask is on.
    #[must_use]
    pub fn current_rung(&self) -> Option<&RungEntry> {
        self.rungs.last()
    }

    /// The next instant a transition is due, for the host that wakes it:
    /// the earliest of `until`, the window's end and the current rung's
    /// end. `None` once the state is final.
    #[must_use]
    pub fn next_due_at(&self) -> Option<u64> {
        if self.state != PendingState::Open {
            return None;
        }
        let rung = if self.chain_exhausted_at.is_some() {
            None
        } else {
            self.current_rung().map(RungEntry::due_at)
        };
        [
            self.until,
            self.delay_window.as_ref().map(|window| window.ends_at),
            rung,
        ]
        .into_iter()
        .flatten()
        .min()
    }
}

/// The window an asker's caller opens with, from canon's PR 4 producer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DelayWindowOpen {
    pub notice_at: u64,
    pub ends_at: u64,
}

/// What a caller opens a pending check-in with, after `check_in` answered
/// `Wait` for this act.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenPendingCheckIn {
    pub asker: EntityId,
    pub grant_ref: String,
    pub verb: String,
    pub act: ActClass,
    pub scope: CheckInScope,
    pub effect_digest: [u8; 32],
    pub mode: CheckInMode,
    pub reason: WaitReason,
    pub asker_wait_secs: Option<u64>,
    pub until: Option<u64>,
    pub undo_plan: Option<String>,
    pub delay_window: Option<DelayWindowOpen>,
}

impl Vault {
    /// The pending check-in `id`, as it stands.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn pending_check_in(&self, id: &EntityId) -> Result<Option<PendingCheckIn>> {
        let txn = self.store.env.read_txn()?;
        pending_check_in_in_txn(&self.store, &txn, id)
    }
}

/// The pending check-in `id`, as it stands in `txn`: for a caller that
/// reads it in the writer that changes it.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn pending_check_in_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<PendingCheckIn>> {
    PENDING.get(store, txn, id)
}

/// Opens a pending check-in at `now` and enters its first rung that has a
/// verified holder, in `txn`. Nothing runs the act.
///
/// # Errors
///
/// A `NeverAsk` mode, an empty verb or grant ref, an `until` not after
/// `now`, an asker wait below the class's floor, an undo plan for an act
/// that is not undoable, or a delay window for an act that does not accept
/// one or that is not open at `now`; storage errors.
#[cfg_attr(
    not(oneiron_test_support),
    allow(
        dead_code,
        reason = "2e and 2f open it; until then only the test door does"
    )
)]
pub(crate) fn open_pending_check_in_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    request: OpenPendingCheckIn,
    chain: &dyn RungResolver,
    now: u64,
) -> Result<PendingCheckIn> {
    validate_open(&request, now)?;
    let floor = super::waits::class_wait_in_txn(vault, txn, request.act, &request.scope)?;
    if request
        .asker_wait_secs
        .is_some_and(|secs| secs < floor.secs)
    {
        return Err(refuse(
            "the asker's wait is shorter than the act class's floor",
        ));
    }
    let mut row = PendingCheckIn {
        id: vault.store.clock.entity_id()?,
        asker: request.asker,
        grant_ref: request.grant_ref,
        verb: request.verb,
        act: request.act,
        scope: request.scope,
        effect_digest: request.effect_digest,
        mode: request.mode,
        reason: request.reason,
        opened_at: now,
        asker_wait_secs: request.asker_wait_secs,
        until: request.until,
        undo_plan: request.undo_plan,
        delay_window: request.delay_window.map(|window| DelayWindow {
            notice_at: window.notice_at,
            ends_at: window.ends_at,
            objections: Vec::new(),
        }),
        rungs: Vec::new(),
        chain_exhausted_at: None,
        state: PendingState::Open,
        transitions: 0,
    };
    let fields = ReceiptFields::new(&row)
        .with("verb", row.verb.clone())
        .with("mode", row.mode.as_str().to_owned())
        .with("reason", row.reason.as_str().to_owned())
        .with(
            "effect_digest",
            crate::receipt::hex_lower(&row.effect_digest),
        );
    let asker = row.asker;
    write_check_in_receipt_in_txn(
        &vault.store,
        txn,
        &mut row,
        CheckInOutcome::Opened,
        Some(asker),
        fields,
        now,
    )?;
    enter_next_rung(vault, txn, &mut row, chain, now)?;
    store_pending_in_txn(&vault.store, txn, &row)?;
    Ok(row)
}

fn validate_open(request: &OpenPendingCheckIn, now: u64) -> Result<()> {
    if request.mode == CheckInMode::NeverAsk {
        return Err(refuse("a NeverAsk act does not wait"));
    }
    if request.verb.is_empty() || request.grant_ref.is_empty() {
        return Err(refuse("a pending check-in names its verb and grant"));
    }
    if request.until.is_some_and(|until| until <= now) {
        return Err(refuse("the asker's until has passed"));
    }
    if request.asker_wait_secs == Some(0) {
        return Err(refuse(
            "the asker's wait is shorter than the act class's floor",
        ));
    }
    let row = request.act.row();
    if request.undo_plan.as_deref().is_some_and(str::is_empty)
        || (request.undo_plan.is_some() && !super::waits::is_undoable(request.act))
    {
        return Err(refuse("an undo plan needs an undoable act"));
    }
    if let Some(window) = request.delay_window {
        if !row.accepted_proofs.contains(&ProofKind::DelayWindow) {
            return Err(refuse("the act does not accept a delay window"));
        }
        if window.notice_at > now || window.ends_at <= now {
            return Err(refuse("the delay window is not open"));
        }
    }
    Ok(())
}

/// A holder's answer to a pending check-in, in `txn` at `now`. The person is
/// revalidated in `txn`; the answer lands only while the ask is open, before
/// `until`, before its delay window's end, before the current rung's wait
/// ends, from a person pinned on the current rung who `chain` says may still
/// answer (their live grant and own check-in, P22-SHAPE Q9), over the exact
/// effect digest. The first valid answer lands and every other holder reads
/// who gave it. The public answer verb is 2l.
///
/// # Errors
///
/// A dead or foreign proof; no such row; a final state; `until`, the delay
/// window's end or the rung's wait passed; a mismatched digest; a person not
/// pinned on the current rung, or one who may no longer answer; storage
/// errors.
#[cfg_attr(
    not(oneiron_test_support),
    allow(
        dead_code,
        reason = "2l answers through it; until then only the test door does"
    )
)]
pub(crate) fn answer_pending_check_in_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    person: &AuthenticatedOwner,
    id: &EntityId,
    reply: HolderReply,
    chain: &dyn RungResolver,
    now: u64,
) -> Result<PendingCheckIn> {
    let HolderReply {
        effect_digest,
        answer,
    } = reply;
    let by = person.revalidate_person_in_txn(vault, txn)?;
    let mut row = open_row_in_txn(&vault.store, txn, id, now)?;
    if row.effect_digest != effect_digest {
        return Err(refuse("the answer is over another effect"));
    }
    let rung = pinned_person_rung(&row, by, now)?;
    require_may_answer(vault, txn, &row, by, chain, now)?;
    row.state = PendingState::Answered {
        answer,
        by: Some(by),
        rung,
        at: now,
    };
    let fields = ReceiptFields::new(&row)
        .with("rung", rung.as_str().to_owned())
        .with("by", by.to_hex())
        .with("answer", answer.as_str().to_owned());
    write_check_in_receipt_in_txn(
        &vault.store,
        txn,
        &mut row,
        CheckInOutcome::Answered,
        Some(by),
        fields,
        now,
    )?;
    store_pending_in_txn(&vault.store, txn, &row)?;
    Ok(row)
}

/// A holder's "give me until `until`" on the current rung, in `txn` at
/// `now`, receipted. It only lengthens the rung's wait, never past the
/// asker's `until` (P22-SHAPE Q5, Q6).
///
/// # Errors
///
/// A dead or foreign proof; no such row; a final state; `until`, the delay
/// window's end or the rung's wait passed; a person not pinned on the
/// current rung, or one who may no longer answer; an extension that does not
/// lengthen the wait or passes the asker's `until`; storage errors.
#[cfg_attr(
    not(oneiron_test_support),
    allow(
        dead_code,
        reason = "2l extends through it; until then only the test door does"
    )
)]
pub(crate) fn extend_pending_check_in_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    person: &AuthenticatedOwner,
    id: &EntityId,
    until: u64,
    chain: &dyn RungResolver,
    now: u64,
) -> Result<PendingCheckIn> {
    let by = person.revalidate_person_in_txn(vault, txn)?;
    let mut row = open_row_in_txn(&vault.store, txn, id, now)?;
    let rung = pinned_person_rung(&row, by, now)?;
    require_may_answer(vault, txn, &row, by, chain, now)?;
    if row.until.is_some_and(|cutoff| until > cutoff) {
        return Err(refuse("an extension may not pass the asker's until"));
    }
    let entry = row
        .rungs
        .last_mut()
        .ok_or(Error::InvariantViolation("an open check-in is on a rung"))?;
    if until <= entry.due_at() {
        return Err(refuse("an extension only lengthens the rung's wait"));
    }
    entry.extension = Some(Extension {
        until,
        by: Some(by),
        at: now,
    });
    let fields = ReceiptFields::new(&row)
        .with("rung", rung.as_str().to_owned())
        .with("by", by.to_hex())
        .with("due_at", until.to_string());
    write_check_in_receipt_in_txn(
        &vault.store,
        txn,
        &mut row,
        CheckInOutcome::Extended,
        Some(by),
        fields,
        now,
    )?;
    store_pending_in_txn(&vault.store, txn, &row)?;
    Ok(row)
}

/// Keeps an objection to the row's delay window that canon's PR 4 producer
/// admitted, in `txn` at `now`. Who may object is that producer's check.
///
/// # Errors
///
/// No such row; a final state; no delay window, or one already ended;
/// storage errors.
#[cfg_attr(
    not(oneiron_test_support),
    allow(
        dead_code,
        reason = "canon's PR 4 producer admits objections; until then only the test door does"
    )
)]
pub(crate) fn record_objection_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    by: EntityId,
    now: u64,
) -> Result<PendingCheckIn> {
    let mut row = open_row_in_txn(store, txn, id, now)?;
    let window = row
        .delay_window
        .as_mut()
        .filter(|window| now < window.ends_at)
        .ok_or_else(|| refuse("no open delay window"))?;
    window.objections.push(Objection {
        by: Some(by),
        at: now,
    });
    store_pending_in_txn(store, txn, &row)?;
    Ok(row)
}

/// The row `id`, open at `now`: not final, its `until` not passed and its
/// delay window not ended. From either instant on, only the tick
/// (`advance_pending_check_in_in_txn`) moves the row, in its order: let-go
/// at `until`, then the window's end (an objection holds the act, silence is
/// the proof). No answer, extension or objection lands there.
fn open_row_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    now: u64,
) -> Result<PendingCheckIn> {
    let row = PENDING.get(store, txn, id)?.ok_or(Error::EntityNotFound)?;
    if row.state != PendingState::Open {
        return Err(Error::ConcurrentWrite("the check-in is settled"));
    }
    if row.until.is_some_and(|until| now >= until) {
        return Err(refuse("the asker's until has passed: the ask let go"));
    }
    if row
        .delay_window
        .as_ref()
        .is_some_and(|window| now >= window.ends_at)
    {
        return Err(refuse(
            "the delay window has ended: its end settles the ask",
        ));
    }
    Ok(row)
}

/// The current rung, when `by` is a person pinned on it and its wait has
/// not ended at `now`. Past the last rung, while a delay window still runs,
/// the Owner rung's holders may still answer.
fn pinned_person_rung(row: &PendingCheckIn, by: EntityId, now: u64) -> Result<Rung> {
    let entry = row
        .current_rung()
        .ok_or(Error::InvariantViolation("an open check-in is on a rung"))?;
    if row.chain_exhausted_at.is_none() && now >= entry.due_at() {
        return Err(refuse("the rung's wait has ended"));
    }
    let pinned = entry
        .holders
        .iter()
        .any(|holder| holder.principal == by && holder.kind == HolderKind::Person);
    if !pinned {
        return Err(refuse("only a person pinned on the current rung answers"));
    }
    Ok(entry.rung)
}

/// Refuses a pinned person `by` whom `chain` no longer lets answer.
fn require_may_answer(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    row: &PendingCheckIn,
    by: EntityId,
    chain: &dyn RungResolver,
    now: u64,
) -> Result<()> {
    let holder = RungHolder {
        principal: by,
        kind: HolderKind::Person,
    };
    if chain.may_answer(vault, txn, row, &holder, now)? {
        Ok(())
    } else {
        Err(refuse(
            "the holder's live grant or own check-in no longer admits this act",
        ))
    }
}

/// The table's actor scrub (an actor's erase, and a restore's rerun of it):
/// a pending check-in the actor asked is removed, since no act of theirs
/// waits any more; every other row drops the actor from its pinned holders
/// and from a skipped rung's missing link, and names nobody where it named
/// the actor as the one who answered, extended or objected. The answer, the
/// extension, the objection and the skip stand. The receipts stand,
/// scrubbed by their own table's scrub, which takes the actor out of the
/// same `missing_link` value the same way.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_pending_check_in_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let mut removed = Vec::new();
    let mut changed = Vec::new();
    for (key, mut row) in PENDING.scan(&vault.store, wtxn)? {
        if row.asker == *actor {
            removed.push(key);
            continue;
        }
        if scrub_row(&mut row, actor) {
            changed.push(row);
        }
    }
    for key in removed {
        delete_pending_in_txn(&vault.store, wtxn, &key)?;
    }
    for row in changed {
        store_pending_in_txn(&vault.store, wtxn, &row)?;
    }
    Ok(())
}

fn scrub_row(row: &mut PendingCheckIn, actor: &EntityId) -> bool {
    let mut changed = false;
    let mut scrub = |by: &mut Option<EntityId>| {
        if by.as_ref() == Some(actor) {
            *by = None;
            changed = true;
        }
    };
    if let PendingState::Answered { by, .. } = &mut row.state {
        scrub(by);
    }
    for entry in &mut row.rungs {
        if let Some(extension) = entry.extension.as_mut() {
            scrub(&mut extension.by);
        }
    }
    if let Some(window) = row.delay_window.as_mut() {
        for objection in &mut window.objections {
            scrub(&mut objection.by);
        }
    }
    let hex = actor.to_hex();
    for entry in &mut row.rungs {
        let before = entry.holders.len();
        entry.holders.retain(|holder| holder.principal != *actor);
        changed |= entry.holders.len() != before;
        if let Some(link) = entry.skipped.as_mut()
            && link.split(',').any(|part| part == hex)
        {
            *link = link
                .split(',')
                .filter(|part| *part != hex)
                .collect::<Vec<_>>()
                .join(",");
            changed = true;
        }
    }
    changed
}
