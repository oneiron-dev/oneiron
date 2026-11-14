//! The waitlist on full slots (ARCH-0062 §7, census L3-13; RULINGs L3-13
//! OFFER = A and WINDOW = B, owner 15 Nov 01:01).
//!
//! A visitor waits on a window of one event type. A join that finds the
//! window open answers its slots and writes nothing; otherwise it writes one
//! entry, in join order per page and event type. When a booking is cancelled
//! or moved, its slot goes to the first waiting entry whose window holds it:
//! the engine holds the slot for that waiter for [`WAITLIST_OFFER_TTL_SECS`],
//! ended sooner by the event type's notice cutoff, and the waiter claims it
//! with the entry token.
//!
//! An offer is an ordinary soft-hold row, so the slot vanishes for everyone
//! else through the solver's own hold step. Its row is keyed by a session
//! derived from the entry token, never by the waiter's browser session, so an
//! offer never replaces a hold the waiter is making elsewhere, and a claim
//! books through the same writer path as `booking.confirm`.
//!
//! Nothing wakes for a lapsed offer (canon R3: lazy expiry, no timers). Its
//! slot is back in availability for everyone at once, and it passes to the
//! next waiter the next time a waitlist, cancel or move writer runs on that
//! page and event type, unless someone holds or booked it by then.
//!
//! Offers are made in their own writer, after the writer that freed the slot
//! has committed: the solver reads committed state, so inside the cancel's
//! own writer the cancelled booking would still occupy its slot.

use serde::{Deserialize, Serialize};

use super::claim::{read_booking_facts, read_booking_facts_to_cancel};
use super::occurrence::{inclusive_occurrence, offers_slot};
use super::storage::{
    HOLD, booking_writer, confirm_receipt_key, engine_failure, read_receipt, read_txn, refused,
};
use super::token::{
    OpaqueLifecycleToken, SessionKey, digest_with, hex_lower, hold_digest, mint_raw_token,
    resolve_token_event, session_digest, token_digest,
};
use super::transition::{ConfirmOutcome, confirm_in_writer};
use super::types::{
    ConfirmReceipt, ConfirmSpec, LifecycleTokenScope, SoftHoldRow, WAITLIST_OFFER_TTL_SECS,
    WaitlistAction, WaitlistClaim, WaitlistJoin, WaitlistReceipt, WaitlistSpec,
};
use super::{digest_serde, time_range_serde};
use crate::booking::{BookingError, EventTypeKey, RankedSlot, SlotOracle, SolveRequest};
use crate::side_table::{self, SideTable, VersionedNamed};
use crate::temporal::TimeRange;
use crate::{EntityId, Vault};

const ENTRY_TOKEN_DOMAIN: &[u8] = b"oneiron.booking.waitlist.entry_token.v1\0";

const EVENT_TYPE_DOMAIN: &[u8] = b"oneiron.booking.waitlist.event_type.v1\0";

const OFFER_SESSION_DOMAIN: &[u8] = b"oneiron.booking.waitlist.offer_session.v1\0";

const CLAIM_HOLD_DOMAIN: &[u8] = b"oneiron.booking.waitlist.claim_hold.v1\0";

const NO_ENTRY: &str = "no waitlist entry on this page matches this token";

/// `((page, event type digest), joined at, entry token digest)`: one prefix
/// seek per page and event type gives its entries in join order.
type WaitlistKey = ((EntityId, [u8; 32]), u64, [u8; 32]);

/// One waiter. Key: [`WaitlistKey`].
const WAITLIST: SideTable<
    WaitlistKey,
    WaitlistEntryRow,
    VersionedNamed<{ super::types::LIFECYCLE_ROW_VERSION }>,
> = SideTable::new(&side_table::BOOKING_WAITLIST);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WaitlistEntryRow {
    event_type: EventTypeKey,
    #[serde(with = "time_range_serde")]
    window: TimeRange,
    /// The joining session, only ever compared: one live entry per session.
    #[serde(with = "digest_serde")]
    session_hash: [u8; 32],
    visitor_tz: String,
    /// The digest of the hold token a claim derives from the entry token,
    /// which an offer's hold row carries.
    #[serde(with = "digest_serde")]
    claim_hold_hash: [u8; 32],
    /// The slot held for this entry, while an offer stands.
    offer: Option<WaitlistOffer>,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WaitlistOffer {
    #[serde(with = "time_range_serde")]
    slot: TimeRange,
    offered_until: u64,
}

/// What one waitlist stage decided inside its writer.
pub(super) enum WaitlistOutcome {
    Stage(WaitlistReceipt),
    /// A claim booked: the dispatcher indexes its UID and sends its invite,
    /// as for a confirm.
    Booked(ConfirmReceipt),
    Taken(Vec<RankedSlot>),
}

/// A stage's outcome, and the slot it gave up, which passes to the next
/// waiter after the stage commits.
pub(super) struct WaitlistStaged {
    pub(super) outcome: WaitlistOutcome,
    pub(super) freed: Option<(EventTypeKey, TimeRange)>,
}

fn entry_token_digest(token: &OpaqueLifecycleToken) -> [u8; 32] {
    digest_with(ENTRY_TOKEN_DOMAIN, token.0.as_bytes())
}

fn event_type_digest(event_type: &EventTypeKey) -> [u8; 32] {
    digest_with(EVENT_TYPE_DOMAIN, event_type.0.as_bytes())
}

/// The session an entry's offer hold is keyed by. Derived from the entry, so
/// no visitor session can hold it, and a claim reaches it from the token.
fn offer_session_key(entry_token_hash: &[u8; 32]) -> SessionKey {
    SessionKey(digest_with(OFFER_SESSION_DOMAIN, entry_token_hash))
}

/// The hold token a claim confirms with, derived from the entry token as a
/// booking's revision tokens are from its hold token, so a claim retry lands
/// on the receipt the first claim recorded.
fn claim_hold_token(token: &OpaqueLifecycleToken) -> OpaqueLifecycleToken {
    OpaqueLifecycleToken(hex_lower(&digest_with(
        CLAIM_HOLD_DOMAIN,
        token.0.as_bytes(),
    )))
}

fn fifo_prefix(page_ref: &EntityId, event_hash: &[u8; 32]) -> Vec<u8> {
    let mut prefix = page_ref.as_bytes().to_vec();
    prefix.extend_from_slice(event_hash);
    prefix
}

const fn holds_slot(window: TimeRange, slot: TimeRange) -> bool {
    window.start <= slot.start && slot.end <= window.end
}

const fn overlaps(left: TimeRange, right: TimeRange) -> bool {
    left.start < right.end && right.start < left.end
}

/// The session whose live hold the stage's solves must not count: a joiner's
/// own hold, or the offer a claim books.
pub(super) fn waitlist_oracle_exclusion(action: &WaitlistAction) -> Option<SessionKey> {
    match action {
        WaitlistAction::Join(join) => Some(join.session_key),
        WaitlistAction::Leave { .. } => None,
        WaitlistAction::Claim(claim) => Some(offer_session_key(&entry_token_digest(&claim.token))),
    }
}

/// The page and event type a waitlist stage acts on, read the way its writer
/// reads them, so the page's publication check binds every stage.
///
/// # Errors
///
/// [`BookingError::InvalidConstraint`] when a leave or claim token names no
/// entry on the page and no booking a claim already made.
pub(super) fn waitlist_publication_scope(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    spec: &WaitlistSpec,
) -> Result<(EntityId, EventTypeKey), BookingError> {
    match &spec.action {
        WaitlistAction::Join(join) => Ok((spec.page_ref, join.event_type.clone())),
        WaitlistAction::Leave { token } => entry_scope(vault, txn, spec.page_ref, token),
        WaitlistAction::Claim(claim) => {
            let receipt_key = confirm_receipt_key(&token_digest(&claim_hold_token(&claim.token)));
            if let Some(receipt) = read_receipt(vault, txn, &receipt_key)? {
                let facts = read_booking_facts(vault, txn, &receipt.event_ref)?;
                return Ok((facts.page_ref, facts.event_type));
            }
            entry_scope(vault, txn, spec.page_ref, &claim.token)
        }
    }
}

fn entry_scope(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    page_ref: EntityId,
    token: &OpaqueLifecycleToken,
) -> Result<(EntityId, EventTypeKey), BookingError> {
    find_entry(vault, txn, &page_ref, &entry_token_digest(token))?
        .map(|(_, entry)| (page_ref, entry.event_type))
        .ok_or_else(|| refused(NO_ENTRY))
}

/// The page and event type whose waitlist a stage settles before it runs,
/// from committed state; `None` when a token names no entry (its writer gives
/// the typed refusal).
///
/// # Errors
///
/// [`BookingError::SlotOracle`] when committed state cannot be read.
pub(super) fn waitlist_settle_scope(
    vault: &Vault,
    spec: &WaitlistSpec,
) -> Result<Option<EventTypeKey>, BookingError> {
    let token = match &spec.action {
        WaitlistAction::Join(join) => return Ok(Some(join.event_type.clone())),
        WaitlistAction::Leave { token } => token,
        WaitlistAction::Claim(claim) => &claim.token,
    };
    let rtxn = read_txn(vault)?;
    Ok(
        find_entry(vault, &rtxn, &spec.page_ref, &entry_token_digest(token))?
            .map(|(_, entry)| entry.event_type),
    )
}

/// The event type of the entry an entry token names on `page_ref`, or of the
/// booking a claim with that token already made on it, from committed state.
/// The transports read it before admission: a leave or claim is bound to the
/// page whose route carried it, and its admission is scoped by event type.
/// `None` when the token names neither on this page; its writer then gives
/// the typed refusal.
///
/// # Errors
///
/// [`BookingError::SlotOracle`] when committed state cannot be read.
pub fn waitlist_entry_event_type(
    vault: &Vault,
    page_ref: EntityId,
    token: &OpaqueLifecycleToken,
) -> Result<Option<EventTypeKey>, BookingError> {
    let rtxn = read_txn(vault)?;
    let receipt_key = confirm_receipt_key(&token_digest(&claim_hold_token(token)));
    if let Some(receipt) = read_receipt(vault, &rtxn, &receipt_key)? {
        let facts = read_booking_facts(vault, &rtxn, &receipt.event_ref)?;
        return Ok((facts.page_ref == page_ref).then_some(facts.event_type));
    }
    Ok(
        find_entry(vault, &rtxn, &page_ref, &entry_token_digest(token))?
            .map(|(_, entry)| entry.event_type),
    )
}

/// A slot a committed transition gave up: its page, event type and interval.
pub(super) type FreedSlot = (EntityId, EventTypeKey, TimeRange);

/// The page, event type and slot of the booking a cancel or move token names,
/// read before its writer runs: the slot that writer frees. `None` when the
/// token names no booking; the writer gives the typed refusal.
pub(super) fn slot_freed_by(
    vault: &Vault,
    token: &OpaqueLifecycleToken,
    scope: LifecycleTokenScope,
) -> Option<FreedSlot> {
    let rtxn = read_txn(vault).ok()?;
    let event_ref = resolve_token_event(vault, &rtxn, token, scope).ok()?;
    let facts = read_booking_facts_to_cancel(vault, &rtxn, &event_ref).ok()?;
    Some((facts.page_ref, facts.event_type, facts.slot))
}

fn find_entry(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    page_ref: &EntityId,
    token_hash: &[u8; 32],
) -> Result<Option<(WaitlistKey, WaitlistEntryRow)>, BookingError> {
    let rows = WAITLIST
        .iter_from(&vault.store, txn, page_ref.as_bytes())
        .map_err(|error| engine_failure("waitlist read", error))?;
    for row in rows {
        let (key, entry) = row.map_err(|error| engine_failure("waitlist read", error))?;
        if key.2 == *token_hash {
            return Ok(Some((key, entry)));
        }
    }
    Ok(None)
}

fn fifo(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    page_ref: &EntityId,
    event_hash: &[u8; 32],
) -> Result<Vec<(WaitlistKey, WaitlistEntryRow)>, BookingError> {
    WAITLIST
        .scan_from(&vault.store, txn, &fifo_prefix(page_ref, event_hash))
        .map_err(|error| engine_failure("waitlist read", error))
}

/// Runs one stage inside the publication-checked writer.
pub(super) fn waitlist_in_writer(
    vault: &Vault,
    oracle: &dyn SlotOracle,
    spec: &WaitlistSpec,
    wtxn: &mut heed::RwTxn<'_>,
    now_utc: u64,
) -> Result<WaitlistStaged, BookingError> {
    match &spec.action {
        WaitlistAction::Join(join) => {
            join_in_writer(vault, oracle, spec.page_ref, join, wtxn, now_utc)
        }
        WaitlistAction::Leave { token } => leave_in_writer(vault, spec.page_ref, token, wtxn),
        WaitlistAction::Claim(claim) => {
            claim_in_writer(vault, oracle, spec.page_ref, claim, wtxn, now_utc)
        }
    }
}

/// A join re-solves its window as availability does. An open window answers
/// its slots; a closed one, whatever closed it, gets an entry.
fn join_in_writer(
    vault: &Vault,
    oracle: &dyn SlotOracle,
    page_ref: EntityId,
    join: &WaitlistJoin,
    wtxn: &mut heed::RwTxn<'_>,
    now_utc: u64,
) -> Result<WaitlistStaged, BookingError> {
    if join.window.end <= now_utc {
        return Err(refused("the waitlist window has already passed"));
    }
    let solved = oracle.solve(&SolveRequest {
        event_type: join.event_type.clone(),
        window: inclusive_occurrence(join.window)?,
        constraint: None,
        visitor_tz: join.visitor_tz.clone(),
    })?;
    // A join lists no read set: it writes no booking.
    let _ = oracle.take_read_rows();
    let open: Vec<RankedSlot> = solved
        .slots
        .into_iter()
        .filter(|ranked| {
            holds_slot(
                join.window,
                TimeRange {
                    start: ranked.start_utc,
                    end: ranked.end_utc,
                },
            )
        })
        .collect();
    if !open.is_empty() {
        return Ok(WaitlistStaged {
            outcome: WaitlistOutcome::Stage(WaitlistReceipt::Open { alternatives: open }),
            freed: None,
        });
    }

    let event_hash = event_type_digest(&join.event_type);
    let session_hash = session_digest(&join.session_key);
    let entries = fifo(vault, &*wtxn, &page_ref, &event_hash)?;
    // One live entry per session: a second join replaces the first, and an
    // offer the first held passes on.
    let mut freed = None;
    for (key, entry) in &entries {
        if entry.session_hash == session_hash {
            let dropped = drop_entry(vault, wtxn, key, entry)?;
            freed = freed.or(dropped);
        }
    }
    let token = OpaqueLifecycleToken(mint_raw_token());
    let token_hash = entry_token_digest(&token);
    WAITLIST
        .put(
            &vault.store,
            wtxn,
            &((page_ref, event_hash), now_utc, token_hash),
            &WaitlistEntryRow {
                event_type: join.event_type.clone(),
                window: join.window,
                session_hash,
                visitor_tz: join.visitor_tz.clone(),
                claim_hold_hash: token_digest(&claim_hold_token(&token)),
                offer: None,
            },
        )
        .map_err(|error| engine_failure("waitlist write", error))?;
    let ahead = entries
        .iter()
        .filter(|(key, entry)| {
            entry.session_hash != session_hash
                && entry.window.end > now_utc
                && overlaps(entry.window, join.window)
                && (key.1, key.2) < (now_utc, token_hash)
        })
        .count();
    Ok(WaitlistStaged {
        outcome: WaitlistOutcome::Stage(WaitlistReceipt::Joined {
            token,
            position: u32::try_from(ahead).unwrap_or(u32::MAX).saturating_add(1),
        }),
        freed: freed.map(|slot| (join.event_type.clone(), slot)),
    })
}

fn leave_in_writer(
    vault: &Vault,
    page_ref: EntityId,
    token: &OpaqueLifecycleToken,
    wtxn: &mut heed::RwTxn<'_>,
) -> Result<WaitlistStaged, BookingError> {
    let Some((key, entry)) = find_entry(vault, &*wtxn, &page_ref, &entry_token_digest(token))?
    else {
        return Err(refused(NO_ENTRY));
    };
    let freed = drop_entry(vault, wtxn, &key, &entry)?;
    Ok(WaitlistStaged {
        outcome: WaitlistOutcome::Stage(WaitlistReceipt::Left),
        freed: freed.map(|slot| (entry.event_type, slot)),
    })
}

/// A claim books the offered slot through confirm's own writer steps, under
/// the offer's derived session and hold token.
fn claim_in_writer(
    vault: &Vault,
    oracle: &dyn SlotOracle,
    page_ref: EntityId,
    claim: &WaitlistClaim,
    wtxn: &mut heed::RwTxn<'_>,
    now_utc: u64,
) -> Result<WaitlistStaged, BookingError> {
    let token_hash = entry_token_digest(&claim.token);
    let session_key = offer_session_key(&token_hash);
    let confirm = ConfirmSpec {
        hold_token: claim_hold_token(&claim.token),
        session_key,
        booker_contact: claim.booker_contact,
        intake: claim.intake.clone(),
        idempotency_key: None,
    };
    let staged = |outcome| WaitlistStaged {
        outcome,
        freed: None,
    };
    // A retry of a claim that booked: confirm answers it from its receipt.
    let receipt_key = confirm_receipt_key(&token_digest(&confirm.hold_token));
    if read_receipt(vault, &*wtxn, &receipt_key)?.is_some() {
        return Ok(staged(confirm_outcome(confirm_in_writer(
            vault, oracle, &confirm, wtxn, now_utc,
        )?)));
    }
    let Some((key, mut entry)) = find_entry(vault, &*wtxn, &page_ref, &token_hash)? else {
        return Err(refused(NO_ENTRY));
    };
    if entry.offer.is_none() {
        return Err(refused("this waitlist entry holds no offered slot"));
    }
    match confirm_in_writer(vault, oracle, &confirm, wtxn, now_utc)? {
        ConfirmOutcome::Booked(receipt) => {
            WAITLIST
                .delete(&vault.store, wtxn, &key)
                .map_err(|error| engine_failure("waitlist delete", error))?;
            Ok(staged(WaitlistOutcome::Booked(receipt)))
        }
        ConfirmOutcome::Taken { alternatives } => {
            // Something else took the slot first: the offer ends, and the
            // entry keeps its place in the line.
            HOLD.delete(&vault.store, wtxn, &hold_digest(&session_key))
                .map_err(|error| engine_failure("meta delete", error))?;
            entry.offer = None;
            WAITLIST
                .put(&vault.store, wtxn, &key, &entry)
                .map_err(|error| engine_failure("waitlist write", error))?;
            Ok(staged(WaitlistOutcome::Taken(alternatives)))
        }
    }
}

fn confirm_outcome(outcome: ConfirmOutcome) -> WaitlistOutcome {
    match outcome {
        ConfirmOutcome::Booked(receipt) => WaitlistOutcome::Booked(receipt),
        ConfirmOutcome::Taken { alternatives } => WaitlistOutcome::Taken(alternatives),
    }
}

/// Deletes an entry and its offer's hold, and gives back the offered slot so
/// it can pass on.
fn drop_entry(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    key: &WaitlistKey,
    entry: &WaitlistEntryRow,
) -> Result<Option<TimeRange>, BookingError> {
    WAITLIST
        .delete(&vault.store, wtxn, key)
        .map_err(|error| engine_failure("waitlist delete", error))?;
    let Some(offer) = entry.offer else {
        return Ok(None);
    };
    HOLD.delete(&vault.store, wtxn, &hold_digest(&offer_session_key(&key.2)))
        .map_err(|error| engine_failure("meta delete", error))?;
    Ok(Some(offer.slot))
}

/// Whether the offer hold an entry's offer wrote still stands.
fn offer_stands(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &WaitlistKey,
    entry: &WaitlistEntryRow,
    offer: WaitlistOffer,
    now_utc: u64,
) -> Result<bool, BookingError> {
    let hold: Option<SoftHoldRow> = HOLD
        .get(&vault.store, txn, &hold_digest(&offer_session_key(&key.2)))
        .map_err(|error| engine_failure("meta read", error))?;
    Ok(hold.is_some_and(|hold| {
        hold.is_live_at(now_utc)
            && hold.slot == offer.slot
            && hold.expires_at == offer.offered_until
            && hold.token_hash == entry.claim_hold_hash
    }))
}

/// Whether any live hold on the page, the writer's own included, overlaps
/// `slot`: someone who saw the slot free first keeps it.
fn slot_is_held(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    page_ref: EntityId,
    slot: TimeRange,
    now_utc: u64,
) -> Result<bool, BookingError> {
    let holds = HOLD
        .scan(&vault.store, txn)
        .map_err(|error| engine_failure("hold scan", error))?;
    Ok(holds.into_iter().any(|(_, hold)| {
        hold.page_ref == page_ref && hold.is_live_at(now_utc) && overlaps(hold.slot, slot)
    }))
}

/// Settles one page and event type's waitlist in its own writer: drops each
/// entry whose window has passed, ends each offer that lapsed, and offers each
/// lapsed slot and `freed` to the first waiting entry whose window holds it,
/// when the slot is still bookable and nobody holds it.
///
/// # Errors
///
/// [`BookingError::SlotOracle`] on a store or solver failure.
pub(super) fn run_waitlist_offer_pass(
    vault: &Vault,
    oracle: &dyn SlotOracle,
    page_ref: EntityId,
    event_type: &EventTypeKey,
    freed: Option<TimeRange>,
    now_utc: u64,
) -> Result<(), BookingError> {
    booking_writer(vault, |wtxn| {
        offer_pass_in_writer(vault, oracle, page_ref, event_type, freed, wtxn, now_utc)
    })?;
    // The pass lists no read set: the stage after it lists its own.
    let _ = oracle.take_read_rows();
    Ok(())
}

fn offer_pass_in_writer(
    vault: &Vault,
    oracle: &dyn SlotOracle,
    page_ref: EntityId,
    event_type: &EventTypeKey,
    freed: Option<TimeRange>,
    wtxn: &mut heed::RwTxn<'_>,
    now_utc: u64,
) -> Result<(), BookingError> {
    let event_hash = event_type_digest(event_type);
    let mut waiting = Vec::new();
    let mut slots = Vec::new();
    for (key, entry) in fifo(vault, &*wtxn, &page_ref, &event_hash)? {
        if entry.window.end <= now_utc {
            // Its window has passed, and so has any slot inside it.
            drop_entry(vault, wtxn, &key, &entry)?;
            continue;
        }
        match entry.offer {
            None => waiting.push((key, entry)),
            Some(offer) => {
                if !offer_stands(vault, &*wtxn, &key, &entry, offer, now_utc)? {
                    // The waiter let the offer lapse: the entry ends, and the
                    // slot passes on.
                    slots.extend(drop_entry(vault, wtxn, &key, &entry)?);
                }
            }
        }
    }
    slots.extend(freed);
    if slots.is_empty() || waiting.is_empty() {
        return Ok(());
    }
    let notice = oracle.minimum_notice_secs(event_type)?;
    for slot in slots {
        let Some(at) = waiting
            .iter()
            .position(|(_, entry)| holds_slot(entry.window, slot))
        else {
            continue;
        };
        let offered_until = now_utc
            .saturating_add(WAITLIST_OFFER_TTL_SECS)
            .min(slot.start.saturating_sub(notice));
        if offered_until <= now_utc || slot_is_held(vault, &*wtxn, page_ref, slot, now_utc)? {
            continue;
        }
        let (key, mut entry) = waiting.remove(at);
        let solved = oracle.solve(&SolveRequest {
            event_type: event_type.clone(),
            window: inclusive_occurrence(slot)?,
            constraint: None,
            visitor_tz: entry.visitor_tz.clone(),
        })?;
        if !offers_slot(&solved.slots, slot) {
            // Still busy for another reason: nobody can take it, so the
            // waiter keeps its place.
            waiting.insert(at, (key, entry));
            continue;
        }
        let session_key = offer_session_key(&key.2);
        HOLD.put(
            &vault.store,
            wtxn,
            &hold_digest(&session_key),
            &SoftHoldRow {
                page_ref,
                event_type: event_type.clone(),
                slot,
                session_key,
                visitor_tz: entry.visitor_tz.clone(),
                constraint: None,
                token_hash: entry.claim_hold_hash,
                expires_at: offered_until,
                checkout_lease_hash: None,
            },
        )
        .map_err(|error| engine_failure("meta write", error))?;
        entry.offer = Some(WaitlistOffer {
            slot,
            offered_until,
        });
        WAITLIST
            .put(&vault.store, wtxn, &key, &entry)
            .map_err(|error| engine_failure("waitlist write", error))?;
    }
    Ok(())
}
