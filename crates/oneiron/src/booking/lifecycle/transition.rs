//! The four ordinary transitions inside the writer lease: hold, confirm,
//! reschedule, cancel.

use super::claim::{
    BookingConfirmationContext, calendar_status_value, encode_event_body, read_booking_facts,
    supersede_exact_claim, write_booking_event,
};
use super::occurrence::{confirm_solve_window, inclusive_occurrence, offers_slot};
use super::passport::{mint_booking_uid, supersede_outbound_passport, write_outbound_passport};
use super::public_authority::booking_writer_with_publication;
use super::storage::{
    calendar_wrap, confirm_receipt_key, decode_row, delete_meta, encode_claim_value, encode_row,
    engine_failure, hold_key, put_meta, read_meta, read_meta_bytes, read_receipt, read_txn,
    refused, revision_receipt_key, write_receipt,
};
use super::token::{
    HoldLeaseSpec, OpaqueLifecycleToken, SessionKey, lease_digest, mint_raw_token,
    resolve_token_event, revision_token, session_digest, token_digest, write_revision_tokens,
};
use super::types::{
    BOOKING_STATUS_PREDICATE, BOOKING_TOKEN_META_PREFIX, BookingLifecycleAttempt, BookingStatus,
    BookingStatusValue, BookingVerbReceipt, BookingVerbRequest, CalendarRevision, CancelSpec,
    ConfirmReceipt, ConfirmSpec, DEFAULT_HOLD_TTL_SECS, HoldReceipt, HoldSpec, LifecycleTokenScope,
    MAX_CHECKOUT_HOLD_TTL_SECS, RescheduleSpec, RevisionReceipt, SoftHoldRow,
};
use super::{BookingContent, CheckoutLeaseRow, LifecycleReceiptRow};
use crate::booking::invite_grant::dispatch_confirm_booking_invite;
use crate::booking::{BookingError, RankedSlot, SlotOracle, SolveRequest};
use crate::calendar::claims::{CalendarStatus, PREDICATE_CALENDAR_STATUS};
use crate::calendar::passport::index_passport_uid;
use crate::outbound::OutboundExecutionSink;
use crate::registry::ENTITY_TYPE_EVENT;
use crate::{EntityId, Vault};

/// Dispatches one decoded attempt.
///
/// Called only by the home-node consumer while it owns serialization.
///
/// `invite_actor` and `invite_sink` are the BK-03 confirm-invite context and
/// ride here as explicit trailing arguments rather than on [`ConfirmSpec`]:
/// the spec is `Serialize`/`Deserialize` wire data, a sink is not
/// serializable, and an actor field on the wire would be caller-asserted
/// identity. `None` on either leaves every verb's behavior unchanged.
pub(super) fn execute_booking_lifecycle_attempt<S: OutboundExecutionSink>(
    vault: &Vault,
    oracle: &dyn SlotOracle,
    attempt: &BookingLifecycleAttempt,
    now_utc: u64,
    invite_actor: Option<EntityId>,
    invite_sink: Option<&mut S>,
) -> Result<BookingVerbReceipt, BookingError> {
    match &attempt.request {
        BookingVerbRequest::Hold(spec) => {
            execute_hold(vault, spec, now_utc, attempt.public_authority.as_ref())
                .map(BookingVerbReceipt::Held)
        }
        BookingVerbRequest::Confirm(spec) => execute_confirm(
            vault,
            oracle,
            spec,
            now_utc,
            invite_actor,
            invite_sink,
            attempt.public_authority.as_ref(),
        ),
        BookingVerbRequest::Reschedule(spec) => execute_reschedule(
            vault,
            oracle,
            spec,
            now_utc,
            attempt.public_authority.as_ref(),
        )
        .map(BookingVerbReceipt::Rescheduled),
        BookingVerbRequest::Cancel(spec) => {
            execute_cancel(vault, spec, now_utc, attempt.public_authority.as_ref())
                .map(BookingVerbReceipt::Cancelled)
        }
    }
}

/// Resolves a hold's expiry and, for an extension, the lease it is bound to.
///
/// Ordinary expiry is the server default, which is also its cap. A
/// [`HoldLeaseSpec::CheckoutExtension`] is accepted only after the opaque token
/// verifies against a server-issued lease bound to THIS session, and its expiry
/// is clamped to both that lease and [`MAX_CHECKOUT_HOLD_TTL_SECS`]. Caller
/// TTLs are structurally absent on both arms.
///
/// # Errors
///
/// [`BookingError::InvalidConstraint`] when a claimed extension has no live,
/// session-bound lease behind it.
fn resolve_hold_expiry(
    vault: &Vault,
    session_key: &SessionKey,
    lease: &HoldLeaseSpec,
    now_utc: u64,
) -> Result<(u64, Option<[u8; 32]>), BookingError> {
    match lease {
        HoldLeaseSpec::Ordinary => Ok((now_utc.saturating_add(DEFAULT_HOLD_TTL_SECS), None)),
        HoldLeaseSpec::CheckoutExtension {
            server_issued_lease,
        } => {
            let digest = lease_digest(server_issued_lease);
            let rtxn = read_txn(vault)?;
            let row: CheckoutLeaseRow =
                read_meta(vault, &rtxn, BOOKING_TOKEN_META_PREFIX, &digest)?
                    .ok_or_else(|| refused("checkout extension names no server-issued lease"))?;
            if row.session_hash != session_digest(session_key) {
                return Err(refused("checkout lease is bound to another session"));
            }
            if row.expires_at <= now_utc {
                return Err(refused("checkout lease has expired"));
            }
            let capped = now_utc.saturating_add(MAX_CHECKOUT_HOLD_TTL_SECS);
            Ok((row.expires_at.min(capped), Some(digest)))
        }
    }
}

/// Replaces this session's hold row with a fresh one over `spec.slot`.
///
/// # Errors
///
/// [`BookingError::InvalidConstraint`] on an unverifiable checkout extension;
/// [`BookingError::SlotOracle`] on a store failure.
pub(crate) fn execute_hold(
    vault: &Vault,
    spec: &HoldSpec,
    now_utc: u64,
    public_authority: Option<&crate::booking::publication::PublicBookingAuthority>,
) -> Result<HoldReceipt, BookingError> {
    let (expires_at, checkout_lease_hash) =
        resolve_hold_expiry(vault, &spec.session_key, &spec.lease, now_utc)?;
    let token = OpaqueLifecycleToken(mint_raw_token());
    let row = SoftHoldRow {
        page_ref: spec.page_ref,
        event_type: spec.event_type.clone(),
        slot: spec.slot,
        session_key: spec.session_key,
        visitor_tz: spec.visitor_tz.clone(),
        constraint: spec.constraint.clone(),
        token_hash: token_digest(&token),
        expires_at,
        checkout_lease_hash,
    };
    let key = hold_key(&spec.session_key);
    let encoded = encode_row(&row)?;
    booking_writer_with_publication(
        vault,
        public_authority,
        &BookingVerbRequest::Hold(spec.clone()),
        now_utc,
        |wtxn| put_meta(vault, wtxn, &key, &encoded),
    )?;
    Ok(HoldReceipt {
        token,
        slot: spec.slot,
        expires_at,
    })
}

/// Turns a live hold into a booking, inside the single writer.
///
/// The write transaction is acquired first and retained through the commit, so
/// the availability re-solve and the EVENT write cannot be interleaved with a
/// competing confirm.
///
/// # Errors
///
/// [`BookingError::InvalidConstraint`] when the hold is absent, dead, or bound
/// to another session; [`BookingError::SlotOracle`] on store or calendar
/// failures.
pub(crate) fn execute_confirm<S: OutboundExecutionSink>(
    vault: &Vault,
    oracle: &dyn SlotOracle,
    spec: &ConfirmSpec,
    now_utc: u64,
    invite_actor: Option<EntityId>,
    invite_sink: Option<&mut S>,
    public_authority: Option<&crate::booking::publication::PublicBookingAuthority>,
) -> Result<BookingVerbReceipt, BookingError> {
    let decided = booking_writer_with_publication(
        vault,
        public_authority,
        &BookingVerbRequest::Confirm(spec.clone()),
        now_utc,
        |wtxn| confirm_in_writer(vault, oracle, spec, wtxn, now_utc),
    )?;
    match decided {
        ConfirmOutcome::Taken { alternatives } => {
            Ok(BookingVerbReceipt::SlotTaken { alternatives })
        }
        ConfirmOutcome::Booked(receipt) => {
            // The UID index is node-local cache CAL-02 repairs from synced truth
            // on any miss, so it is maintained after the commit rather than
            // inside it: CAL-02's index door opens its OWN write transaction,
            // and nesting one inside this writer would deadlock LMDB.
            index_passport_uid(vault, &receipt.calendar.uid, &receipt.calendar.event_ref)
                .map_err(calendar_wrap)?;
            // BK-03 (ONE-1814): with a live booking-page grant this confirm
            // carries ONE `calendar.invite` REQUEST through the ordinary
            // outbound door. It runs here for the same reason the UID index
            // does — the writer has returned, and dispatch opens its own
            // transactions, which nesting would deadlock.
            //
            // A dispatch failure MUST NOT fail the confirm: the EVENT, the
            // four booking claims, the sequence-0 passport, the revision
            // tokens, and the durable receipt are already committed, so
            // erroring here would fail a booking that exists and re-mint a
            // second cancel token on the retry. The absence of the
            // intent-ledger record is the observable, and nothing retries: a
            // second REQUEST would threaten the once-minted UID law. A replay
            // resolves to the intent the first pass recorded rather than
            // enqueueing another.
            if let (Some(actor), Some(sink)) = (invite_actor, invite_sink) {
                let _ = dispatch_confirm_booking_invite(vault, actor, &receipt, sink, now_utc);
            }
            Ok(BookingVerbReceipt::Confirmed(receipt))
        }
    }
}

/// What confirm decided inside the writer.
enum ConfirmOutcome {
    Booked(ConfirmReceipt),
    Taken { alternatives: Vec<RankedSlot> },
}

/// The ratified confirm order, all inside one writer:
///
/// 1. Return the durable receipt if this hold token already confirmed.
/// 2. Resolve the session's hold row and verify its token and liveness.
/// 3. Re-solve fresh availability, excluding only this session's own hold.
/// 4. On a taken slot, return `SlotTaken` plus alternatives and write nothing.
/// 5. Otherwise create the EVENT, the four exact booking claims, the outbound
///    passport at sequence 0, the token digests, and the durable receipt, and
///    consume the hold.
fn confirm_in_writer(
    vault: &Vault,
    oracle: &dyn SlotOracle,
    spec: &ConfirmSpec,
    wtxn: &mut heed::RwTxn<'_>,
    now_utc: u64,
) -> Result<ConfirmOutcome, BookingError> {
    let hold_hash = token_digest(&spec.hold_token);
    let session_hash = session_digest(&spec.session_key);
    let receipt_key = confirm_receipt_key(&hold_hash);

    // (1) A retry re-presents the same hold token. The receipt is keyed by its
    // digest — never by an advisory idempotency key — so a caller that omits or
    // changes that key still lands on the recorded booking.
    if let Some(recorded) = read_receipt(vault, &*wtxn, &receipt_key)? {
        if recorded.session_hash != Some(session_hash) {
            return Err(refused("recorded booking belongs to another session"));
        }
        // The recorded receipt pins the EVENT, the UID, and the sequence, and
        // the revision credentials are DERIVED from the hold token this retry
        // just presented — so the caller is handed back the very pair the first
        // confirm issued. Nothing is minted and nothing is written: a retry that
        // minted a second cancel token would hand out a second, independent
        // authority over one booking, and two authorities cancel twice.
        return Ok(ConfirmOutcome::Booked(ConfirmReceipt {
            calendar: recorded.into_revision(),
            reschedule_token: revision_token(&spec.hold_token, LifecycleTokenScope::Reschedule),
            cancel_token: revision_token(&spec.hold_token, LifecycleTokenScope::Cancel),
        }));
    }

    // (2) Holds are session-keyed, so a token stolen from another session finds
    // no row at all.
    let hold_row_key = hold_key(&spec.session_key);
    let Some(raw) = read_meta_bytes(vault, &*wtxn, &hold_row_key)? else {
        return Err(refused("no hold exists for this session"));
    };
    let hold: SoftHoldRow = decode_row(&raw)?;
    if !hold.is_live_at(now_utc) {
        // Opportunistic cleanup, not a scheduler: correctness already came from
        // the liveness test above.
        delete_meta(vault, wtxn, &hold_row_key)?;
        return Err(refused("hold has expired"));
    }
    if hold.token_hash != hold_hash {
        return Err(refused("hold token does not match this session's hold"));
    }

    // (3) Fresh availability, read while we hold the writer.
    let solved = oracle.solve(&SolveRequest {
        event_type: hold.event_type.clone(),
        window: confirm_solve_window(hold.slot)?,
        constraint: hold.constraint.clone(),
        visitor_tz: hold.visitor_tz.clone(),
    })?;
    // (4) Someone else took it. No EVENT, no claim, no passport.
    if !offers_slot(&solved.slots, hold.slot) {
        return Ok(ConfirmOutcome::Taken {
            alternatives: solved.slots,
        });
    }

    // (5) One atomic commit.
    let event_ref = EntityId::now();
    let uid = mint_booking_uid(&event_ref);
    let mut bindings = solved
        .host_bindings
        .iter()
        .filter(|binding| binding.start_utc == hold.slot.start && binding.end_utc == hold.slot.end);
    let owner_refs = bindings
        .next()
        .ok_or_else(|| refused("oracle did not bind the selected slot's hosts"))?
        .host_refs
        .clone();
    if owner_refs.is_empty()
        || bindings.next().is_some()
        || owner_refs.windows(2).any(|pair| pair[0] >= pair[1])
        || owner_refs
            .iter()
            .any(|owner| !EntityId::from_hex(owner).is_ok_and(|id| id.to_hex() == *owner))
    {
        return Err(refused(
            "oracle returned an invalid or competing selected-host binding",
        ));
    }
    let context = BookingConfirmationContext {
        owner_refs,
        booker_ref: spec.booker_contact.to_hex(),
        visitor_tz: hold.visitor_tz.clone(),
        constraint: hold.constraint.clone(),
    };
    write_booking_event(vault, wtxn, &event_ref, &hold, spec.booker_contact, now_utc)?;
    write_outbound_passport(vault, wtxn, &event_ref, &uid, &hold, now_utc)?;
    let (reschedule_token, cancel_token) =
        write_revision_tokens(vault, wtxn, event_ref, &spec.hold_token)?;
    let revision = CalendarRevision {
        event_ref,
        uid,
        sequence: 0,
    };
    write_receipt(
        vault,
        wtxn,
        &receipt_key,
        &LifecycleReceiptRow {
            event_ref,
            uid: revision.uid.clone(),
            sequence: revision.sequence,
            session_hash: Some(session_hash),
            confirmation: Some(context),
            invite_identity: None,
        },
    )?;
    delete_meta(vault, wtxn, &hold_row_key)?;
    Ok(ConfirmOutcome::Booked(ConfirmReceipt {
        calendar: revision,
        reschedule_token,
        cancel_token,
    }))
}

/// Moves a booking to `spec.new_slot`, keeping its EVENT and UID.
///
/// The same solver rules that admitted the original slot admit the new one, and
/// the passport is superseded exactly once at `last_sequence + 1`. A retry of
/// the same `(token, slot)` returns the recorded receipt rather than a second
/// increment.
///
/// # Errors
///
/// [`BookingError::InvalidConstraint`] on an unknown or wrongly-scoped token or
/// an unavailable slot; [`BookingError::SlotOracle`] on store or calendar
/// failures.
pub(crate) fn execute_reschedule(
    vault: &Vault,
    oracle: &dyn SlotOracle,
    spec: &RescheduleSpec,
    now_utc: u64,
    public_authority: Option<&crate::booking::publication::PublicBookingAuthority>,
) -> Result<RevisionReceipt, BookingError> {
    booking_writer_with_publication(
        vault,
        public_authority,
        &BookingVerbRequest::Reschedule(spec.clone()),
        now_utc,
        |wtxn| {
            let event_ref =
                resolve_token_event(vault, &*wtxn, &spec.token, LifecycleTokenScope::Reschedule)?;
            let booking = read_booking_facts(vault, &*wtxn, &event_ref)?;

            // A cancelled booking is not a booking sitting at an inconvenient time.
            // Its slot is already back in the host's availability and its calendar
            // status says cancelled, so moving it would attest a Confirmed passport
            // over a cancelled booking and silently re-occupy a slot someone else
            // may already hold. Un-cancelling is a different transition, and this
            // lane does not have one.
            if booking.status == BookingStatus::Cancelled {
                return Err(refused("a cancelled booking cannot be rescheduled"));
            }

            // A retry re-presents a move that already happened — which is only true
            // while the booking still SITS at the target. Once it has moved on, a
            // request naming that same target is a fresh move back, not a replay:
            // the old receipt is history, and returning it would report a sequence
            // the booking left behind while leaving the EVENT where it was.
            let receipt_key = revision_receipt_key(&event_ref, Some(spec.new_slot));
            if booking.slot == spec.new_slot
                && let Some(recorded) = read_receipt(vault, &*wtxn, &receipt_key)?
            {
                return Ok(RevisionReceipt {
                    calendar: recorded.into_revision(),
                });
            }

            let context = booking
                .context
                .as_ref()
                .ok_or_else(|| refused("booking has no immutable host binding"))?;
            let solved = oracle.solve_bound(
                &SolveRequest {
                    event_type: booking.event_type.clone(),
                    window: inclusive_occurrence(spec.new_slot)?,
                    constraint: spec.constraint.clone(),
                    visitor_tz: spec.visitor_tz.clone(),
                },
                &context.owner_refs,
            )?;
            if !offers_slot(&solved.slots, spec.new_slot) {
                return Err(refused("the requested slot is no longer available"));
            }

            // The EVENT's structural row carries the occurrence, so moving the
            // booking is a re-put of the same id at the new interval — the shape
            // CAL's feed-drift rewrite uses.
            vault
                .batch_in()
                .put(
                    &event_ref,
                    ENTITY_TYPE_EVENT,
                    inclusive_occurrence(spec.new_slot)?,
                    now_utc,
                    &encode_event_body(&booking.event_type)?,
                )
                .apply(wtxn)
                .map_err(|error| engine_failure("booking event rewrite", error))?;
            let revision = supersede_outbound_passport(
                vault,
                wtxn,
                &event_ref,
                &BookingContent {
                    page_ref: booking.page_ref,
                    event_type: booking.event_type,
                    slot: spec.new_slot,
                    status: BookingStatus::Confirmed,
                    emergency_content_hash: None,
                },
                now_utc,
            )?;
            write_receipt(
                vault,
                wtxn,
                &receipt_key,
                &LifecycleReceiptRow {
                    event_ref,
                    uid: revision.uid.clone(),
                    sequence: revision.sequence,
                    session_hash: None,
                    confirmation: None,
                    invite_identity: None,
                },
            )?;
            Ok(RevisionReceipt { calendar: revision })
        },
    )
}

/// Cancels a booking, keeping its EVENT and UID.
///
/// Supersedes `booking.status` to cancelled and increments the passport
/// sequence once. It also supersedes CAL's `calendar.status` with basis
/// [`CalendarStatusBasis::Booking`] — the basis CAL-00 minted for this writer —
/// because a cancelled booking whose EVENT still carried occupancy would keep
/// the freed slot unbookable forever.
///
/// # Errors
///
/// [`BookingError::InvalidConstraint`] on an unknown or wrongly-scoped token;
/// [`BookingError::SlotOracle`] on store or calendar failures.
pub(crate) fn execute_cancel(
    vault: &Vault,
    spec: &CancelSpec,
    now_utc: u64,
    public_authority: Option<&crate::booking::publication::PublicBookingAuthority>,
) -> Result<RevisionReceipt, BookingError> {
    booking_writer_with_publication(
        vault,
        public_authority,
        &BookingVerbRequest::Cancel(spec.clone()),
        now_utc,
        |wtxn| {
            let event_ref =
                resolve_token_event(vault, &*wtxn, &spec.token, LifecycleTokenScope::Cancel)?;
            // Keyed by the BOOKING, so every credential that can cancel it lands on
            // the same receipt: one logical cancel, one increment, however many
            // cancel tokens exist.
            let receipt_key = revision_receipt_key(&event_ref, None);
            if let Some(recorded) = read_receipt(vault, &*wtxn, &receipt_key)? {
                return Ok(RevisionReceipt {
                    calendar: recorded.into_revision(),
                });
            }
            let booking = read_booking_facts(vault, &*wtxn, &event_ref)?;

            supersede_exact_claim(
                vault,
                wtxn,
                &event_ref,
                BOOKING_STATUS_PREDICATE,
                encode_claim_value(&BookingStatusValue {
                    status: BookingStatus::Cancelled,
                    recorded_at: now_utc,
                })?,
                now_utc,
            )?;
            supersede_exact_claim(
                vault,
                wtxn,
                &event_ref,
                PREDICATE_CALENDAR_STATUS,
                calendar_status_value(CalendarStatus::Cancelled, now_utc),
                now_utc,
            )?;
            let revision = supersede_outbound_passport(
                vault,
                wtxn,
                &event_ref,
                &BookingContent {
                    page_ref: booking.page_ref,
                    event_type: booking.event_type,
                    slot: booking.slot,
                    status: BookingStatus::Cancelled,
                    emergency_content_hash: None,
                },
                now_utc,
            )?;
            write_receipt(
                vault,
                wtxn,
                &receipt_key,
                &LifecycleReceiptRow {
                    event_ref,
                    uid: revision.uid.clone(),
                    sequence: revision.sequence,
                    session_hash: None,
                    confirmation: None,
                    invite_identity: None,
                },
            )?;
            Ok(RevisionReceipt { calendar: revision })
        },
    )
}
