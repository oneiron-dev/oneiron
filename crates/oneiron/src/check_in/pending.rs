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

use super::act_class::{ActClass, ProofKind};
use super::mode::CheckInMode;
use super::policy::CheckInScope;
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

/// A natural key ([`PendingCheckIn::open_key`]) → the pending check-in a
/// keyed open opened for it (2f): a repeat open reads it.
const OPEN_KEY: SideTable<[u8; 32], EntityId, Named> =
    SideTable::new(&side_table::CHECK_IN_OPEN_KEY);

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

/// Deletes the row `id`, its `DUE` entry and the `OPEN_KEY` entry that
/// names it.
fn delete_pending_in_txn(store: &Store, txn: &mut heed::RwTxn<'_>, id: &EntityId) -> Result<()> {
    if let Some(stored) = PENDING.get(store, txn, id)? {
        if let Some(at) = stored.next_due_at() {
            DUE.delete(store, txn, &(at, *id))?;
        }
        let key = stored.open_key();
        if OPEN_KEY.get(store, txn, &key)? == Some(*id) {
            OPEN_KEY.delete(store, txn, &key)?;
        }
    }
    PENDING.delete(store, txn, id)?;
    Ok(())
}

#[doc(hidden)]
use oneiron_records::check_in::pending::open_key_of;
#[doc(hidden)]
pub use oneiron_records::check_in::pending::{
    CapturedWait, DelayWindow, EligibleBasis, Extension, HolderAnswer, Objection, PendingCheckIn,
    PendingState, Rung, RungEntry, RungHolder,
};

#[doc(hidden)]
pub use oneiron_verb_wire::check_in::pending::HolderKind;

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

/// A holder's answer and the effect it is over: it settles the ask only
/// over the exact effect digest the ask waits on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HolderReply {
    pub effect_digest: [u8; 32],
    pub answer: HolderAnswer,
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
        consumed_at: None,
        invocation: None,
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

/// The row a repeat open of the ask with this natural key returns, in
/// `txn`: the row the key names while it [answers a
/// repeat](PendingCheckIn::answers_a_repeat).
///
/// # Errors
///
/// Storage errors.
pub(crate) fn keyed_pending_check_in_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    asker: EntityId,
    verb: &str,
    act: ActClass,
    scope: &CheckInScope,
    effect_digest: &[u8; 32],
) -> Result<Option<PendingCheckIn>> {
    let key = open_key_of(asker, verb, act, scope, effect_digest);
    let Some(id) = OPEN_KEY.get(store, txn, &key)? else {
        return Ok(None);
    };
    Ok(PENDING
        .get(store, txn, &id)?
        .filter(PendingCheckIn::answers_a_repeat))
}

/// [`open_pending_check_in_in_txn`] under the ask's natural key (2f;
/// P23-SHAPE Q2 = A): a repeat of the same saved call returns the row it
/// opened (`true`: opened now; `false`: a repeat), with no new receipt; a
/// let-go or spent row gives way to a new one, which the key then names.
/// The new row records `invocation`, the logical call that opened it.
///
/// # Errors
///
/// As [`open_pending_check_in_in_txn`].
pub(crate) fn open_keyed_pending_check_in_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    request: OpenPendingCheckIn,
    invocation: Option<[u8; 16]>,
    chain: &dyn RungResolver,
    now: u64,
) -> Result<(PendingCheckIn, bool)> {
    if let Some(row) = keyed_pending_check_in_in_txn(
        &vault.store,
        txn,
        request.asker,
        &request.verb,
        request.act,
        &request.scope,
        &request.effect_digest,
    )? {
        return Ok((row, false));
    }
    let mut row = open_pending_check_in_in_txn(vault, txn, request, chain, now)?;
    if invocation.is_some() {
        row.invocation = invocation;
        store_pending_in_txn(&vault.store, txn, &row)?;
    }
    OPEN_KEY.put(&vault.store, txn, &row.open_key(), &row.id)?;
    Ok((row, true))
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

/// Spends the settled row `id` for the act it held, in the act's own `txn`
/// at `now` (Engine ruling P23-SHAPE Q2 = A): the commit that runs the
/// effect is the commit that marks the row used, so a replay or a second
/// worker finds it used, and an abort leaves it eligible. Only the exact
/// effect digest spends it, on an eligible basis
/// ([`PendingCheckIn::eligible_basis`]). Writes a `consumed` receipt naming
/// the basis. The membership doors spend it through `effect` (P2.4b); PR
/// 3's act gate spends it for the act verbs.
///
/// # Errors
///
/// No such row; another effect; a state that makes nothing eligible; a row
/// already used; storage errors.
pub(crate) fn consume_pending_check_in_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    effect_digest: &[u8; 32],
    now: u64,
) -> Result<EligibleBasis> {
    let mut row = PENDING
        .get(&vault.store, txn, id)?
        .ok_or(Error::EntityNotFound)?;
    if row.effect_digest != *effect_digest {
        return Err(refuse("the act is another effect than the one asked"));
    }
    let basis = row
        .eligible_basis()
        .ok_or_else(|| refuse("the check-in did not make the act eligible"))?;
    if row.consumed_at.is_some() {
        return Err(refuse("the act this check-in held already ran"));
    }
    row.consumed_at = Some(now);
    let fields = ReceiptFields::new(&row).with("basis", basis.as_str().to_owned());
    let asker = row.asker;
    write_check_in_receipt_in_txn(
        &vault.store,
        txn,
        &mut row,
        CheckInOutcome::Consumed,
        Some(asker),
        fields,
        now,
    )?;
    store_pending_in_txn(&vault.store, txn, &row)?;
    Ok(basis)
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
