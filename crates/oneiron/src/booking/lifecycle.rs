//! ONE-1813 [BK-02] booking lifecycle verbs.
//!
//! The four typed verbs — `booking.hold`, `booking.confirm`,
//! `booking.reschedule`, `booking.cancel` — plus the state they need: session
//! keyed soft-hold rows, opaque bearer tokens, durable lifecycle receipts, and
//! the home-node macro attempt that executes them.
//!
//! # Shape
//!
//! A public verb entry point only validates, encodes, and enqueues
//! [`BOOKING_LIFECYCLE_ATTEMPT_KIND`] on the generic attempt queue
//! ([`enqueue_booking_verb`]). Execution happens in exactly one place:
//! [`run_booking_lifecycle_once`], the home-node consumer that claims that
//! attempt kind ([`AttemptQueue::claim_kind`], mirroring `task_verb.rs`'s
//! realization consumer) and runs the transition. There is no public door onto
//! any `execute_*` function, so a caller cannot confirm a booking outside the
//! writer.
//!
//! # Mutual exclusion (r9)
//!
//! Confirm's correctness rests on ONE thing: the final availability read and
//! the write commit sit inside the SAME LMDB write transaction, which is the
//! engine's single-writer lease ([`booking_writer`]). The transaction is
//! acquired BEFORE the availability read and retained through the commit, so a
//! competing confirm either committed already — and is therefore visible as
//! busy in the fresh solve — or has not yet acquired the writer and will
//! observe our EVENT when it does. Advisory idempotency keys never participate:
//! they are attempt-queue dedupe hygiene, not a lock.
//!
//! Cross-node exclusion is the persisted MACRO home-node designation
//! ([`crate::dreamer_runner::DreamerHomeNodeDesignation`]): a node that is not
//! the home node refuses to claim the attempt at all.
//!
//! # Holds are not entities
//!
//! A hold is one `vault_meta` row under [`BOOKING_HOLD_META_PREFIX`], keyed by
//! the derived session key, so a session has at most one active hold. Expiry is
//! lazy: a row is live only while `expires_at > now`, and an expired row is
//! opportunistically deleted by whatever read next walks past it. No timer,
//! wake, expiry daemon, or recurrence primitive exists here, and correctness
//! never depends on the cleanup running at all.
//!
//! # UID truth is CAL's
//!
//! A booking is an existing EVENT plus claims — never a new entity kind, and
//! never a `booking.uid` claim. The outbound calendar identity is CAL-00's
//! [`CalendarPassportValue`] written on the EVENT at sequence 0, indexed
//! through CAL-02's [`index_passport_uid`], and superseded at `last_sequence +
//! 1` by reschedule and cancel. [`BookingError`] wraps calendar failures
//! opaquely; no `CalendarError` variant is matched or restated here.

use rand_core::{OsRng, RngCore};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome, CompleteAttempt,
    EnqueueAttempt, EnqueueOutcome, FailAttempt,
};
use crate::booking::config::ClaimClassDescriptorRow;
use crate::booking::constraint::validate_visitor_tz;
use crate::booking::{
    ActiveHoldSource, BookingError, ConstraintObject, EventTypeKey, RankedSlot, SlotOracle,
    SolveRequest, SolveResult,
};
use crate::calendar::claims::{
    CalendarPassportPresence, CalendarStatus, CalendarStatusBasis, PREDICATE_CALENDAR_PASSPORT,
    PREDICATE_CALENDAR_STATUS,
};
use crate::calendar::passport::{
    encode_passport_value, index_passport_uid, live_passports_for_event,
};
use crate::calendar::{CalendarPassportDirection, CalendarPassportValue};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::dreamer_runner::DreamerRunnerStore;
use crate::registry::ENTITY_TYPE_EVENT;
use crate::temporal::TimeRange;
use crate::{EntityId, Vault};

// -------------------------------------------------------------------------
// Ratified constants
// -------------------------------------------------------------------------

/// Attempt kind the home-node lifecycle consumer claims.
pub const BOOKING_LIFECYCLE_ATTEMPT_KIND: &str = "booking.lifecycle.macro";

/// `vault_meta` prefix for session-keyed soft-hold rows.
pub const BOOKING_HOLD_META_PREFIX: &[u8] = b"booking.hold.v1:";

/// `vault_meta` prefix for opaque-token digest rows.
pub const BOOKING_TOKEN_META_PREFIX: &[u8] = b"booking.token.v1:";

/// `vault_meta` prefix for durable lifecycle receipts.
pub const BOOKING_RECEIPT_META_PREFIX: &[u8] = b"booking.lifecycle.receipt.v1:";

/// The ordinary hold lifetime, and its own server cap: a caller has no TTL
/// input at all, so this is both the default and the maximum for an ordinary
/// hold.
pub const DEFAULT_HOLD_TTL_SECS: u64 = 5 * 60;

/// Server cap on an extended (checkout) hold. An extension can only ever
/// shorten to its verified lease; it can never exceed this.
pub const MAX_CHECKOUT_HOLD_TTL_SECS: u64 = 30 * 60;

/// The closed verb table, sorted so the wire spellings live in one place.
pub const BOOKING_VERBS: [&str; 4] = [
    "booking.cancel",
    "booking.confirm",
    "booking.hold",
    "booking.reschedule",
];

/// Exact predicate: which host event type this booking realizes.
pub const BOOKING_EVENT_TYPE_REF_PREDICATE: &str = "booking.event_type_ref";

/// Exact predicate: who booked.
pub const BOOKING_BOOKER_CONTACT_PREDICATE: &str = "booking.booker_contact";

/// Exact predicate: which page the booking came from.
pub const BOOKING_SOURCE_PAGE_PREDICATE: &str = "booking.source_page";

/// Exact predicate: the booking's live status.
pub const BOOKING_STATUS_PREDICATE: &str = "booking.status";

/// The lifecycle claim family, as an exact table. A `booking.` prefix would
/// silently adopt every future booking predicate into this validator.
pub const BOOKING_LIFECYCLE_PREDICATES: [&str; 4] = [
    BOOKING_BOOKER_CONTACT_PREDICATE,
    BOOKING_EVENT_TYPE_REF_PREDICATE,
    BOOKING_SOURCE_PAGE_PREDICATE,
    BOOKING_STATUS_PREDICATE,
];

/// The passport `system` a booking's outbound calendar identity carries. One
/// live passport per `(system × UID)` is CAL-02's invariant; this is the
/// engine's own outbound system name.
pub const BOOKING_PASSPORT_SYSTEM: &str = "oneiron.booking";

/// Bound on an advisory idempotency key.
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;

/// Bound on the failure reason stamped onto a failed attempt row.
const MAX_ATTEMPT_FAILURE_REASON_BYTES: usize = 512;

/// How far either side of a held slot confirm's re-solve looks.
///
/// Confirm must answer a taken slot with the SAME solver's nearest
/// alternatives, which a window equal to the held slot cannot contain. The
/// solver still clips every solve to the page's own booking horizon, so this
/// widens the ANSWER, never the work bound.
const CONFIRM_ALTERNATIVES_PAD_SECS: u64 = 24 * 60 * 60;

/// Row-format byte on every lifecycle `vault_meta` value.
const LIFECYCLE_ROW_VERSION: u8 = 1;

/// Raw opaque-token width, and therefore the bearer secret's entropy.
const TOKEN_RAW_BYTES: usize = 32;

// Domain separators. Every digest this module persists is domain-tagged, so a
// hold token digest can never be replayed as a lease digest or a session key.
const HOLD_KEY_DOMAIN: &[u8] = b"oneiron.booking.hold_key.v1\0";
const SESSION_DIGEST_DOMAIN: &[u8] = b"oneiron.booking.session.v1\0";
const TOKEN_DIGEST_DOMAIN: &[u8] = b"oneiron.booking.token.v1\0";
const LEASE_DIGEST_DOMAIN: &[u8] = b"oneiron.booking.checkout_lease.v1\0";
const SESSION_KEY_DOMAIN: &[u8] = b"oneiron.booking.session_key.v1\0";
const CONTENT_HASH_DOMAIN: &[u8] = b"oneiron.booking.content.v1\0";
const RECEIPT_KEY_DOMAIN: &[u8] = b"oneiron.booking.receipt.v1\0";

// -------------------------------------------------------------------------
// Verbs
// -------------------------------------------------------------------------

/// The closed booking verb enum, mirroring `task_verb.rs`'s typed verb shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BookingVerb {
    Cancel,
    Confirm,
    Hold,
    Reschedule,
}

impl BookingVerb {
    /// The pinned wire spelling, read out of [`BOOKING_VERBS`] so the enum and
    /// the sorted table cannot drift apart.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cancel => BOOKING_VERBS[0],
            Self::Confirm => BOOKING_VERBS[1],
            Self::Hold => BOOKING_VERBS[2],
            Self::Reschedule => BOOKING_VERBS[3],
        }
    }

    /// Parses a wire spelling, rejecting anything outside the closed set.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "booking.cancel" => Some(Self::Cancel),
            "booking.confirm" => Some(Self::Confirm),
            "booking.hold" => Some(Self::Hold),
            "booking.reschedule" => Some(Self::Reschedule),
            _ => None,
        }
    }
}

/// Whether `predicate` is an exact member of the lifecycle claim family.
#[must_use]
pub fn is_booking_lifecycle_claim_predicate(predicate: &str) -> bool {
    BOOKING_LIFECYCLE_PREDICATES.contains(&predicate)
}

// -------------------------------------------------------------------------
// Opaque credentials
// -------------------------------------------------------------------------

/// A random bearer credential, returned to the caller exactly once. It encodes
/// nothing: not an EVENT id, a UID, an email address, an action, or a
/// timestamp. Only its digest is ever persisted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueLifecycleToken(pub String);

/// A server-issued, session-bound checkout lease. Same opacity contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueCheckoutLeaseToken(pub String);

/// The derived visitor session key. Deriving it is the server's job; this type
/// is the 32-byte result, and holds are keyed by it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionKey(pub [u8; 32]);

impl SessionKey {
    /// Derives a session key from opaque server-side session material.
    ///
    /// Domain-separated, so session material can never collide with a token or
    /// lease digest computed over the same bytes.
    #[must_use]
    pub fn derive(material: &[u8]) -> Self {
        Self(digest_with(SESSION_KEY_DOMAIN, material))
    }
}

/// What a hold's lifetime is grounded in.
///
/// There is deliberately no caller TTL on either arm: `Ordinary` takes the
/// server default, and `CheckoutExtension` is capped by the verified lease AND
/// by [`MAX_CHECKOUT_HOLD_TTL_SECS`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HoldLeaseSpec {
    Ordinary,
    CheckoutExtension {
        server_issued_lease: OpaqueCheckoutLeaseToken,
    },
}

/// Mints a fresh bearer credential from the OS CSPRNG.
fn mint_raw_token() -> String {
    let mut raw = [0_u8; TOKEN_RAW_BYTES];
    OsRng.fill_bytes(&mut raw);
    hex_lower(&raw)
}

fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0F)]));
    }
    out
}

fn digest_with(domain: &[u8], material: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(material);
    *hasher.finalize().as_bytes()
}

/// The persisted digest of a lifecycle bearer token.
fn token_digest(token: &OpaqueLifecycleToken) -> [u8; 32] {
    digest_with(TOKEN_DIGEST_DOMAIN, token.0.as_bytes())
}

/// The persisted digest of a checkout lease.
fn lease_digest(lease: &OpaqueCheckoutLeaseToken) -> [u8; 32] {
    digest_with(LEASE_DIGEST_DOMAIN, lease.0.as_bytes())
}

/// The session binding stored on lease and receipt rows, where the session is
/// only ever compared and never re-read.
fn session_digest(session_key: &SessionKey) -> [u8; 32] {
    digest_with(SESSION_DIGEST_DOMAIN, &session_key.0)
}

// -------------------------------------------------------------------------
// Requests
// -------------------------------------------------------------------------

/// Ask to soft-hold one solved slot.
///
/// `slot` is the half-open UTC interval `[start, end)` the oracle emitted — the
/// solver's convention, carried in the one [`TimeRange`] import path booking
/// uses.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HoldSpec {
    #[serde(with = "entity_ref_serde")]
    pub page_ref: EntityId,
    pub event_type: EventTypeKey,
    #[serde(with = "time_range_serde")]
    pub slot: TimeRange,
    pub session_key: SessionKey,
    pub visitor_tz: String,
    pub constraint: Option<ConstraintObject>,
    pub lease: HoldLeaseSpec,
    /// Retry hygiene only. It becomes the attempt-queue dedupe string and takes
    /// no part in mutual exclusion or in receipt identity.
    pub idempotency_key: Option<String>,
}

/// Ask to convert a live hold into a booking.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfirmSpec {
    pub hold_token: OpaqueLifecycleToken,
    pub session_key: SessionKey,
    #[serde(with = "entity_ref_serde")]
    pub booker_contact: EntityId,
    /// Retry hygiene only.
    pub idempotency_key: Option<String>,
}

/// Ask to move a booking, proving authority with its reschedule token.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RescheduleSpec {
    pub token: OpaqueLifecycleToken,
    #[serde(with = "time_range_serde")]
    pub new_slot: TimeRange,
    pub visitor_tz: String,
    pub constraint: Option<ConstraintObject>,
    pub idempotency_key: Option<String>,
}

/// Ask to cancel a booking, proving authority with its cancel token.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CancelSpec {
    pub token: OpaqueLifecycleToken,
    pub idempotency_key: Option<String>,
}

/// The closed request union one attempt carries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BookingVerbRequest {
    Hold(HoldSpec),
    Confirm(ConfirmSpec),
    Reschedule(RescheduleSpec),
    Cancel(CancelSpec),
}

impl BookingVerbRequest {
    /// Which verb this request is.
    #[must_use]
    pub const fn verb(&self) -> BookingVerb {
        match self {
            Self::Hold(_) => BookingVerb::Hold,
            Self::Confirm(_) => BookingVerb::Confirm,
            Self::Reschedule(_) => BookingVerb::Reschedule,
            Self::Cancel(_) => BookingVerb::Cancel,
        }
    }

    /// The advisory idempotency key, if the caller supplied one.
    #[must_use]
    pub fn idempotency_key(&self) -> Option<&str> {
        match self {
            Self::Hold(spec) => spec.idempotency_key.as_deref(),
            Self::Confirm(spec) => spec.idempotency_key.as_deref(),
            Self::Reschedule(spec) => spec.idempotency_key.as_deref(),
            Self::Cancel(spec) => spec.idempotency_key.as_deref(),
        }
    }
}

// -------------------------------------------------------------------------
// Persisted rows
// -------------------------------------------------------------------------

/// One session's active soft hold.
///
/// Stored under [`BOOKING_HOLD_META_PREFIX`] keyed by the session, so a new
/// hold for the same session replaces the prior row by construction. ONE-1817
/// owns HTTP/IP/email abuse policy; this row is only the storage invariant that
/// one active hold per session needs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SoftHoldRow {
    #[serde(with = "entity_ref_serde")]
    pub page_ref: EntityId,
    pub event_type: EventTypeKey,
    #[serde(with = "time_range_serde")]
    pub slot: TimeRange,
    pub session_key: SessionKey,
    pub visitor_tz: String,
    pub constraint: Option<ConstraintObject>,
    #[serde(with = "digest_serde")]
    pub token_hash: [u8; 32],
    pub expires_at: u64,
    #[serde(with = "opt_digest_serde")]
    pub checkout_lease_hash: Option<[u8; 32]>,
}

impl SoftHoldRow {
    /// Lazy expiry: `expires_at == now` is already dead. Nothing wakes to
    /// enforce this — a read that sees a dead row simply does not see a hold.
    #[must_use]
    pub const fn is_live_at(&self, now_utc: u64) -> bool {
        self.expires_at > now_utc
    }
}

/// What one opaque token is allowed to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleTokenScope {
    Reschedule,
    Cancel,
}

/// The digest row a lifecycle token resolves through. The token carries no
/// state; this row is where the EVENT and the permitted action live.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LifecycleTokenRow {
    #[serde(with = "entity_ref_serde")]
    event_ref: EntityId,
    scope: LifecycleTokenScope,
}

/// A server-issued checkout lease, bound to one session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckoutLeaseRow {
    #[serde(with = "digest_serde")]
    session_hash: [u8; 32],
    expires_at: u64,
}

/// The durable lifecycle receipt one transition recorded.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LifecycleReceiptRow {
    #[serde(with = "entity_ref_serde")]
    event_ref: EntityId,
    uid: String,
    sequence: u32,
    /// Present on confirm receipts: the session that owned the consumed hold,
    /// so a retry from another session cannot read this receipt back.
    #[serde(with = "opt_digest_serde")]
    session_hash: Option<[u8; 32]>,
}

impl LifecycleReceiptRow {
    fn into_revision(self) -> CalendarRevision {
        CalendarRevision {
            event_ref: self.event_ref,
            uid: self.uid,
            sequence: self.sequence,
        }
    }
}

// -------------------------------------------------------------------------
// Claim values
// -------------------------------------------------------------------------

/// A booking's live status. Changes go through supersession, never mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BookingStatus {
    Confirmed,
    Cancelled,
}

impl BookingStatus {
    const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Confirmed => b"confirmed",
            Self::Cancelled => b"cancelled",
        }
    }
}

/// The `{event_ref, uid, sequence}` triple a lifecycle receipt exposes. BK-03
/// turns this into `calendar.invite`; this ticket dispatches nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalendarRevision {
    #[serde(with = "entity_ref_serde")]
    pub event_ref: EntityId,
    pub uid: String,
    pub sequence: u32,
}

/// Value of a `booking.event_type_ref` claim.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BookingEventTypeRefValue {
    pub event_type: EventTypeKey,
}

/// Value of a `booking.booker_contact` claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BookingBookerContactValue {
    #[serde(with = "entity_ref_serde")]
    pub contact_ref: EntityId,
}

/// Value of a `booking.source_page` claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BookingSourcePageValue {
    #[serde(with = "entity_ref_serde")]
    pub page_ref: EntityId,
}

/// Value of a `booking.status` claim. Calendar UID and sequence are
/// deliberately absent: passport claims are their only home.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BookingStatusValue {
    pub status: BookingStatus,
    pub recorded_at: u64,
}

// -------------------------------------------------------------------------
// Receipts
// -------------------------------------------------------------------------

/// What a successful hold returns. The bearer token appears here and never
/// again.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HoldReceipt {
    pub token: OpaqueLifecycleToken,
    #[serde(with = "time_range_serde")]
    pub slot: TimeRange,
    pub expires_at: u64,
}

/// What a successful confirm returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfirmReceipt {
    pub calendar: CalendarRevision,
    pub reschedule_token: OpaqueLifecycleToken,
    pub cancel_token: OpaqueLifecycleToken,
}

/// What a successful reschedule or cancel returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevisionReceipt {
    pub calendar: CalendarRevision,
}

/// The closed receipt union.
///
/// `SlotTaken` is a receipt, not an error: the transition ran, decided nothing
/// was writable, and returned the same solver's nearest alternatives with no
/// EVENT, claim, or passport written.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BookingVerbReceipt {
    Held(HoldReceipt),
    Confirmed(ConfirmReceipt),
    Rescheduled(RevisionReceipt),
    Cancelled(RevisionReceipt),
    SlotTaken { alternatives: Vec<RankedSlot> },
}

/// The typed attempt payload the generic queue row carries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BookingLifecycleAttempt {
    pub request: BookingVerbRequest,
    pub requested_at: u64,
}

// -------------------------------------------------------------------------
// Public verb door
// -------------------------------------------------------------------------

/// Validates, encodes, and enqueues one booking verb.
///
/// This is the whole public surface of a verb: it never solves, never writes an
/// EVENT, and never touches a hold. The transition happens in
/// [`run_booking_lifecycle_once`] on the home node.
///
/// An advisory `idempotency_key` becomes the queue's dedupe string, so a
/// double-submit coalesces onto one attempt row. That is hygiene: correctness
/// comes from the writer and from the durable receipt.
///
/// # Errors
///
/// [`BookingError::InvalidConstraint`] on a malformed request;
/// [`BookingError::SlotOracle`] when the queue cannot be written.
pub fn enqueue_booking_verb(
    vault: &Vault,
    request: BookingVerbRequest,
    now_utc: u64,
) -> Result<AttemptId, BookingError> {
    validate_request(&request)?;
    let attempt = BookingLifecycleAttempt {
        request,
        requested_at: now_utc,
    };
    let dedupe_key = attempt.request.idempotency_key().map(str::to_owned);
    let payload = encode_row(&attempt)?;

    let outcome = AttemptQueue::new(vault)
        .enqueue(EnqueueAttempt {
            kind: BOOKING_LIFECYCLE_ATTEMPT_KIND.to_owned(),
            payload,
            dedupe_key,
            run_id: None,
            now: now_utc,
        })
        .map_err(|error| engine_failure("verb enqueue", error))?;
    Ok(match outcome {
        EnqueueOutcome::Enqueued(record) | EnqueueOutcome::Existing(record) => record.id,
    })
}

/// Issues a server-side checkout lease bound to `session_key`.
///
/// This is the server's own door, not a visitor door: the only thing that
/// satisfies [`HoldLeaseSpec::CheckoutExtension`] is a token minted here, so a
/// public caller cannot fabricate an extension binding. Payment stays
/// note-only — there is no provider, checkout API, or payment state machine
/// behind this, only a session-bound expiry the hold door verifies.
///
/// The lease's own lifetime is capped at [`MAX_CHECKOUT_HOLD_TTL_SECS`], so
/// even a mis-configured caller cannot mint an unbounded extension.
///
/// # Errors
///
/// [`BookingError::SlotOracle`] when the lease row cannot be written.
pub fn issue_checkout_lease(
    vault: &Vault,
    session_key: &SessionKey,
    requested_ttl_secs: u64,
    now_utc: u64,
) -> Result<(OpaqueCheckoutLeaseToken, u64), BookingError> {
    let lease = OpaqueCheckoutLeaseToken(mint_raw_token());
    let expires_at = now_utc.saturating_add(requested_ttl_secs.min(MAX_CHECKOUT_HOLD_TTL_SECS));
    let row = CheckoutLeaseRow {
        session_hash: session_digest(session_key),
        expires_at,
    };
    let key = meta_key(BOOKING_TOKEN_META_PREFIX, &lease_digest(&lease));
    let encoded = encode_row(&row)?;
    booking_writer(vault, |wtxn| put_meta(vault, wtxn, &key, &encoded))?;
    Ok((lease, expires_at))
}

/// What the home-node consumer needs in order to build the availability oracle
/// for one claimed attempt.
///
/// `exclude_session_key` is the load-bearing field: [`crate::booking::BookingSolver`]
/// asks its [`ActiveHoldSource`] for every live hold and passes `None` for the
/// trait's own exclusion argument, so a confirm whose oracle does not exclude
/// its own session's hold would be blocked by the very hold it is redeeming.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BookingOracleRequest {
    /// The page whose configuration and holds scope the solve, when it could be
    /// resolved from committed state.
    pub page_ref: Option<EntityId>,
    /// The session whose own hold must not block its own confirm.
    pub exclude_session_key: Option<SessionKey>,
}

/// Node identity and lease identity for one consumer turn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BookingLifecycleConsumerInput {
    /// This node's id, compared against the persisted MACRO home-node
    /// designation.
    pub local_node_id: u64,
    /// Attempt-queue lease owner for this worker.
    pub lease_owner: String,
    pub now_utc: u64,
}

/// What one consumer turn did.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum BookingLifecycleTurn {
    /// No home node is elected, so no node may write bookings.
    NoHomeNode,
    /// Another node holds the designation.
    NotHomeNode { home_node_id: u64 },
    /// Nothing of this kind was ready.
    Empty,
    /// One attempt ran to a receipt.
    Executed(BookingVerbReceipt),
}

/// Claims and executes at most one booking lifecycle attempt on the home node.
///
/// This is the ONLY public execution door. It refuses on a node that does not
/// hold the MACRO home-node designation, claims strictly
/// [`BOOKING_LIFECYCLE_ATTEMPT_KIND`] so it never steals another consumer's
/// work, and finalizes the attempt row either way.
///
/// `make_oracle` builds the availability oracle for the claimed attempt. It is
/// a callback rather than a parameter because the page and the session to
/// exclude are properties of the attempt, which is not known until it is
/// claimed.
///
/// # Errors
///
/// [`BookingError`] from the transition itself, or [`BookingError::SlotOracle`]
/// on a queue failure.
pub fn run_booking_lifecycle_once<F, O>(
    vault: &Vault,
    make_oracle: F,
    input: &BookingLifecycleConsumerInput,
) -> Result<BookingLifecycleTurn, BookingError>
where
    F: FnOnce(&BookingOracleRequest) -> Result<O, BookingError>,
    O: SlotOracle,
{
    // Cross-node serialization, read before anything is claimed: a node that is
    // not the home node must not even lease the attempt, or the row would sit
    // leased on a node that may not write.
    let designation = DreamerRunnerStore::new(vault)
        .home_node_designation()
        .map_err(|error| engine_failure("home node designation read", error))?;
    let Some(designation) = designation else {
        return Ok(BookingLifecycleTurn::NoHomeNode);
    };
    if designation.node_id != input.local_node_id {
        return Ok(BookingLifecycleTurn::NotHomeNode {
            home_node_id: designation.node_id,
        });
    }

    let queue = AttemptQueue::new(vault);
    let claimed = queue
        .claim_kind(
            BOOKING_LIFECYCLE_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: input.lease_owner.clone(),
                now: input.now_utc,
            },
        )
        .map_err(|error| engine_failure("lifecycle attempt claim", error))?;
    let ClaimOutcome::Claimed(record) = claimed else {
        return Ok(BookingLifecycleTurn::Empty);
    };

    let outcome = execute_claimed_attempt(vault, make_oracle, &record, input.now_utc);
    finalize_attempt(&queue, &record, &outcome, input)?;
    outcome.map(BookingLifecycleTurn::Executed)
}

/// Decodes one claimed row and runs it, with the oracle built from its request.
fn execute_claimed_attempt<F, O>(
    vault: &Vault,
    make_oracle: F,
    record: &AttemptRecord,
    now_utc: u64,
) -> Result<BookingVerbReceipt, BookingError>
where
    F: FnOnce(&BookingOracleRequest) -> Result<O, BookingError>,
    O: SlotOracle,
{
    let attempt: BookingLifecycleAttempt = decode_row(&record.payload)?;
    let request = oracle_request(vault, &attempt.request)?;
    // An unresolvable page means the hold or token this request names is not in
    // committed state. The authoritative path rejects it before any solve, so
    // there is nothing to build an oracle from and nothing that needs one.
    let built = if request.page_ref.is_some() {
        Some(make_oracle(&request)?)
    } else {
        None
    };
    let oracle: &dyn SlotOracle = match &built {
        Some(oracle) => oracle,
        None => &UnresolvedPageOracle,
    };
    execute_booking_lifecycle_attempt(vault, oracle, &attempt, now_utc)
}

/// Completes or fails the attempt row, whatever the transition returned.
///
/// A `SlotTaken` receipt is a SUCCESSFUL attempt: the transition ran and
/// decided. Only a typed failure fails the row.
fn finalize_attempt(
    queue: &AttemptQueue<'_>,
    record: &AttemptRecord,
    outcome: &Result<BookingVerbReceipt, BookingError>,
    input: &BookingLifecycleConsumerInput,
) -> Result<(), BookingError> {
    match outcome {
        Ok(_) => queue
            .complete(CompleteAttempt {
                id: record.id,
                lease_owner: input.lease_owner.clone(),
                attempt_count: record.attempt_count,
                now: input.now_utc,
            })
            .map(|_| ())
            .map_err(|error| engine_failure("lifecycle attempt complete", error)),
        Err(failure) => queue
            .fail(FailAttempt {
                id: record.id,
                lease_owner: input.lease_owner.clone(),
                attempt_count: record.attempt_count,
                reason: attempt_failure_reason(failure),
                now: input.now_utc,
            })
            .map(|_| ())
            .map_err(|error| engine_failure("lifecycle attempt fail", error)),
    }
}

/// A non-empty, bounded failure reason for the attempt row.
fn attempt_failure_reason(failure: &BookingError) -> String {
    let mut reason = failure.to_string();
    if reason.is_empty() {
        return "booking lifecycle transition failed".to_owned();
    }
    if reason.len() > MAX_ATTEMPT_FAILURE_REASON_BYTES {
        let mut cut = MAX_ATTEMPT_FAILURE_REASON_BYTES;
        while cut > 0 && !reason.is_char_boundary(cut) {
            cut -= 1;
        }
        reason.truncate(cut);
    }
    reason
}

/// Resolves the oracle inputs one request needs from committed state.
///
/// Advisory only: every binding read here is re-verified inside the writer.
fn oracle_request(
    vault: &Vault,
    request: &BookingVerbRequest,
) -> Result<BookingOracleRequest, BookingError> {
    Ok(match request {
        BookingVerbRequest::Hold(spec) => BookingOracleRequest {
            page_ref: Some(spec.page_ref),
            exclude_session_key: Some(spec.session_key),
        },
        BookingVerbRequest::Confirm(spec) => BookingOracleRequest {
            page_ref: read_hold_row(vault, &spec.session_key)?.map(|row| row.page_ref),
            exclude_session_key: Some(spec.session_key),
        },
        BookingVerbRequest::Reschedule(spec) => BookingOracleRequest {
            page_ref: token_page_ref(vault, &spec.token)?,
            exclude_session_key: None,
        },
        BookingVerbRequest::Cancel(spec) => BookingOracleRequest {
            page_ref: token_page_ref(vault, &spec.token)?,
            exclude_session_key: None,
        },
    })
}

/// An oracle that exists only to satisfy the dispatcher's signature when no
/// page could be resolved. It is never solved: the transition rejects the
/// unknown hold or token first.
struct UnresolvedPageOracle;

impl SlotOracle for UnresolvedPageOracle {
    fn solve(&self, _req: &SolveRequest) -> Result<SolveResult, BookingError> {
        Err(BookingError::SlotOracle(
            "no booking page resolved for this request".to_owned(),
        ))
    }
}

// -------------------------------------------------------------------------
// Transitions
// -------------------------------------------------------------------------

/// Dispatches one decoded attempt.
///
/// Called only by the home-node consumer while it owns serialization.
pub(crate) fn execute_booking_lifecycle_attempt(
    vault: &Vault,
    oracle: &dyn SlotOracle,
    attempt: &BookingLifecycleAttempt,
    now_utc: u64,
) -> Result<BookingVerbReceipt, BookingError> {
    match &attempt.request {
        BookingVerbRequest::Hold(spec) => {
            execute_hold(vault, spec, now_utc).map(BookingVerbReceipt::Held)
        }
        BookingVerbRequest::Confirm(spec) => execute_confirm(vault, oracle, spec, now_utc),
        BookingVerbRequest::Reschedule(spec) => {
            execute_reschedule(vault, oracle, spec, now_utc).map(BookingVerbReceipt::Rescheduled)
        }
        BookingVerbRequest::Cancel(spec) => {
            execute_cancel(vault, spec, now_utc).map(BookingVerbReceipt::Cancelled)
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
pub(crate) fn resolve_hold_expiry(
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
    booking_writer(vault, |wtxn| put_meta(vault, wtxn, &key, &encoded))?;
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
pub(crate) fn execute_confirm(
    vault: &Vault,
    oracle: &dyn SlotOracle,
    spec: &ConfirmSpec,
    now_utc: u64,
) -> Result<BookingVerbReceipt, BookingError> {
    let decided = booking_writer(vault, |wtxn| {
        confirm_in_writer(vault, oracle, spec, wtxn, now_utc)
    })?;
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
        // The recorded receipt pins the EVENT, the UID, and the sequence, so
        // nothing is re-minted and nothing is incremented. The bearer tokens
        // cannot be replayed from storage — only their digests are persisted —
        // so a retry is issued fresh credentials for the SAME booking.
        let event_ref = recorded.event_ref;
        let (reschedule_token, cancel_token) = write_revision_tokens(vault, wtxn, event_ref)?;
        return Ok(ConfirmOutcome::Booked(ConfirmReceipt {
            calendar: recorded.into_revision(),
            reschedule_token,
            cancel_token,
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
    write_booking_event(vault, wtxn, &event_ref, &hold, spec.booker_contact, now_utc)?;
    write_outbound_passport(vault, wtxn, &event_ref, &uid, &hold, now_utc)?;
    let (reschedule_token, cancel_token) = write_revision_tokens(vault, wtxn, event_ref)?;
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
) -> Result<RevisionReceipt, BookingError> {
    let receipt_key = revision_receipt_key(&token_digest(&spec.token), Some(spec.new_slot));
    booking_writer(vault, |wtxn| {
        if let Some(recorded) = read_receipt(vault, &*wtxn, &receipt_key)? {
            return Ok(RevisionReceipt {
                calendar: recorded.into_revision(),
            });
        }
        let event_ref =
            resolve_token_event(vault, &*wtxn, &spec.token, LifecycleTokenScope::Reschedule)?;
        let booking = read_booking_facts(vault, &*wtxn, &event_ref)?;

        let solved = oracle.solve(&SolveRequest {
            event_type: booking.event_type.clone(),
            window: inclusive_occurrence(spec.new_slot)?,
            constraint: spec.constraint.clone(),
            visitor_tz: spec.visitor_tz.clone(),
        })?;
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
            },
        )?;
        Ok(RevisionReceipt { calendar: revision })
    })
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
) -> Result<RevisionReceipt, BookingError> {
    let receipt_key = revision_receipt_key(&token_digest(&spec.token), None);
    booking_writer(vault, |wtxn| {
        if let Some(recorded) = read_receipt(vault, &*wtxn, &receipt_key)? {
            return Ok(RevisionReceipt {
                calendar: recorded.into_revision(),
            });
        }
        let event_ref =
            resolve_token_event(vault, &*wtxn, &spec.token, LifecycleTokenScope::Cancel)?;
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
            },
        )?;
        Ok(RevisionReceipt { calendar: revision })
    })
}

// -------------------------------------------------------------------------
// Hold source
// -------------------------------------------------------------------------

/// BK-00's [`ActiveHoldSource`], backed by the session-keyed hold rows.
///
/// `exclude_session_key` is not a convenience: [`crate::booking::BookingSolver`]
/// passes `None` for the trait's own exclusion argument on every solve, so the
/// confirming session's exclusion has to be bound into the source the caller
/// builds. Both exclusions are honored, so either door works.
pub struct VaultActiveHoldSource<'a> {
    pub vault: &'a Vault,
    /// The session whose own hold this source hides — the confirming session.
    pub exclude_session_key: Option<SessionKey>,
}

impl<'a> VaultActiveHoldSource<'a> {
    /// A source that hides nothing: every live hold blocks.
    #[must_use]
    pub const fn new(vault: &'a Vault) -> Self {
        Self {
            vault,
            exclude_session_key: None,
        }
    }

    /// A source that hides one session's own hold.
    #[must_use]
    pub const fn excluding(vault: &'a Vault, session_key: SessionKey) -> Self {
        Self {
            vault,
            exclude_session_key: Some(session_key),
        }
    }
}

impl ActiveHoldSource for VaultActiveHoldSource<'_> {
    fn active_holds(
        &self,
        page_ref: EntityId,
        window: TimeRange,
        now_utc: u64,
        exclude_session_key: Option<&[u8; 32]>,
    ) -> Result<Vec<TimeRange>, BookingError> {
        let bound = self.exclude_session_key.map(|key| key.0);
        let rtxn = read_txn(self.vault)?;
        let mut holds = Vec::new();
        let rows = self
            .vault
            .store
            .vault_meta
            .prefix_iter(&rtxn, BOOKING_HOLD_META_PREFIX)
            .map_err(|error| engine_failure("hold scan", error))?;
        for entry in rows {
            let (_, raw) = entry.map_err(|error| engine_failure("hold scan", error))?;
            let row: SoftHoldRow = decode_row(&raw)?;
            if row.page_ref != page_ref || !row.is_live_at(now_utc) {
                continue;
            }
            if bound == Some(row.session_key.0) || exclude_session_key == Some(&row.session_key.0) {
                continue;
            }
            if row.slot.start < window.end && window.start < row.slot.end {
                holds.push(row.slot);
            }
        }
        Ok(holds)
    }
}

// -------------------------------------------------------------------------
// Calendar passport
// -------------------------------------------------------------------------

/// Constructs the CAL-00-owned outbound passport value.
///
/// Persistence and index maintenance are CAL-02's; this only builds the value,
/// so no parallel passport type exists in booking.
pub(crate) fn outbound_passport_value(
    system: String,
    uid: String,
    sequence: u32,
    content_hash: [u8; 32],
    recorded_at: u64,
) -> CalendarPassportValue {
    CalendarPassportValue {
        system,
        uid,
        last_sequence: sequence,
        content_hash,
        direction: CalendarPassportDirection::Outbound,
        last_seen_at: recorded_at,
        presence: CalendarPassportPresence::Live,
    }
}

/// The booking content one passport revision attests.
struct BookingContent {
    page_ref: EntityId,
    event_type: EventTypeKey,
    slot: TimeRange,
    status: BookingStatus,
}

impl BookingContent {
    /// Content hash over the fields a revision can move, so passport drift is
    /// detectable without restating any calendar payload.
    fn hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(CONTENT_HASH_DOMAIN);
        hasher.update(self.page_ref.as_bytes());
        hasher.update(self.event_type.0.as_bytes());
        hasher.update(&self.slot.start.to_be_bytes());
        hasher.update(&self.slot.end.to_be_bytes());
        hasher.update(self.status.as_bytes());
        *hasher.finalize().as_bytes()
    }
}

/// Mints the outbound UID. Globally unique, and it carries no booker identity.
fn mint_booking_uid(event_ref: &EntityId) -> String {
    format!("{}@{BOOKING_PASSPORT_SYSTEM}", event_ref.to_hex())
}

/// Writes the sequence-0 outbound passport claim for a new booking.
fn write_outbound_passport(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    event_ref: &EntityId,
    uid: &str,
    hold: &SoftHoldRow,
    now_utc: u64,
) -> Result<(), BookingError> {
    let content = BookingContent {
        page_ref: hold.page_ref,
        event_type: hold.event_type.clone(),
        slot: hold.slot,
        status: BookingStatus::Confirmed,
    };
    let value = outbound_passport_value(
        BOOKING_PASSPORT_SYSTEM.to_owned(),
        uid.to_owned(),
        0,
        content.hash(),
        now_utc,
    );
    put_claim(
        vault,
        wtxn,
        event_ref,
        PREDICATE_CALENDAR_PASSPORT,
        encode_passport_value(&value),
        now_utc,
    )
    .map(|_| ())
}

/// Supersedes this booking's outbound passport at `last_sequence + 1`.
///
/// CAL-02's `supersede_calendar_passport` opens its OWN write transaction, so
/// calling it from inside the home-node writer would deadlock LMDB. This
/// composes CAL-02's own live-passport resolution with the engine's
/// transaction-composable supersession instead — the same transition without
/// the nested transaction.
fn supersede_outbound_passport(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    event_ref: &EntityId,
    content: &BookingContent,
    now_utc: u64,
) -> Result<CalendarRevision, BookingError> {
    let (old_id, current) = live_passports_for_event(vault, event_ref)
        .map_err(calendar_wrap)?
        .into_iter()
        .find(|(_, value)| value.system == BOOKING_PASSPORT_SYSTEM)
        .ok_or_else(|| refused("booking carries no outbound calendar passport"))?;
    let sequence = current
        .last_sequence
        .checked_add(1)
        .ok_or_else(|| refused("booking passport sequence is exhausted"))?;
    let value = outbound_passport_value(
        BOOKING_PASSPORT_SYSTEM.to_owned(),
        current.uid.clone(),
        sequence,
        content.hash(),
        now_utc,
    );
    let new_id = put_claim(
        vault,
        wtxn,
        event_ref,
        PREDICATE_CALENDAR_PASSPORT,
        encode_passport_value(&value),
        now_utc,
    )?;
    vault
        .supersede_claim_in_txn(wtxn, &new_id, &old_id, now_utc)
        .map_err(|error| engine_failure("passport supersession", error))?;
    Ok(CalendarRevision {
        event_ref: *event_ref,
        uid: current.uid,
        sequence,
    })
}

// -------------------------------------------------------------------------
// Claim writes
// -------------------------------------------------------------------------

/// The booking facts a revision needs from its EVENT.
struct BookingFacts {
    page_ref: EntityId,
    event_type: EventTypeKey,
    slot: TimeRange,
}

/// Creates the EVENT and its four exact booking claims.
fn write_booking_event(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    event_ref: &EntityId,
    hold: &SoftHoldRow,
    booker_contact: EntityId,
    now_utc: u64,
) -> Result<(), BookingError> {
    vault
        .batch_in()
        .put(
            event_ref,
            ENTITY_TYPE_EVENT,
            inclusive_occurrence(hold.slot)?,
            now_utc,
            &encode_event_body(&hold.event_type)?,
        )
        .apply(wtxn)
        .map_err(|error| engine_failure("booking event write", error))?;

    let values = [
        (
            BOOKING_EVENT_TYPE_REF_PREDICATE,
            encode_claim_value(&BookingEventTypeRefValue {
                event_type: hold.event_type.clone(),
            })?,
        ),
        (
            BOOKING_BOOKER_CONTACT_PREDICATE,
            encode_claim_value(&BookingBookerContactValue {
                contact_ref: booker_contact,
            })?,
        ),
        (
            BOOKING_SOURCE_PAGE_PREDICATE,
            encode_claim_value(&BookingSourcePageValue {
                page_ref: hold.page_ref,
            })?,
        ),
        (
            BOOKING_STATUS_PREDICATE,
            encode_claim_value(&BookingStatusValue {
                status: BookingStatus::Confirmed,
                recorded_at: now_utc,
            })?,
        ),
    ];
    for (predicate, value) in values {
        put_claim(vault, wtxn, event_ref, predicate, value, now_utc)?;
    }
    Ok(())
}

/// Writes one engine-recorded claim into the caller's transaction.
///
/// `Auto` approval with an `Observed` source is `calendar/outcome.rs`'s stance
/// for a family projector: the engine recorded a fact it witnessed, and the
/// shared write door still rules on source trust.
fn put_claim(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    subject: &EntityId,
    predicate: &str,
    value: rmpv::Value,
    now_utc: u64,
) -> Result<EntityId, BookingError> {
    let id = EntityId::now();
    let mut body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(*subject),
        value,
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.source = Some(ClaimSource::Observed);
    body.valid_from = Some(now_utc);
    vault
        .put_claim_in_txn(wtxn, &id, &body, at(now_utc), now_utc)
        .map_err(|error| engine_failure("booking claim write", error))?;
    Ok(id)
}

/// Writes a replacement head and supersedes every live claim it replaces, in
/// one transaction, so the EVENT can never carry two live heads.
fn supersede_exact_claim(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    subject: &EntityId,
    predicate: &str,
    value: rmpv::Value,
    now_utc: u64,
) -> Result<(), BookingError> {
    let prior = live_claims_with_predicate(vault, &*wtxn, subject, predicate)?;
    let new_id = put_claim(vault, wtxn, subject, predicate, value, now_utc)?;
    for old_id in prior {
        vault
            .supersede_claim_in_txn(wtxn, &new_id, &old_id, now_utc)
            .map_err(|error| engine_failure("booking claim supersession", error))?;
    }
    Ok(())
}

/// Every live claim on `subject` carrying exactly `predicate`.
fn live_claims_with_predicate(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    subject: &EntityId,
    predicate: &str,
) -> Result<Vec<EntityId>, BookingError> {
    let mut out = Vec::new();
    for claim_id in claims_for_subject(vault, rtxn, subject)? {
        let Ok(Some(body)) = vault.get_claim_in_txn(rtxn, &claim_id) else {
            continue;
        };
        if body.predicate == predicate && body.lifecycle == ClaimLifecycleStatus::Active {
            out.push(claim_id);
        }
    }
    Ok(out)
}

/// Reads the booking facts one EVENT's live claims and structural row carry.
fn read_booking_facts(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    event_ref: &EntityId,
) -> Result<BookingFacts, BookingError> {
    let mut page_ref = None;
    let mut event_type = None;
    for claim_id in claims_for_subject(vault, rtxn, event_ref)? {
        let Ok(Some(body)) = vault.get_claim_in_txn(rtxn, &claim_id) else {
            continue;
        };
        if body.lifecycle != ClaimLifecycleStatus::Active {
            continue;
        }
        match body.predicate.as_str() {
            BOOKING_SOURCE_PAGE_PREDICATE => {
                page_ref = Some(
                    decode_claim_value::<BookingSourcePageValue>(&body.value, "source page")?
                        .page_ref,
                );
            }
            BOOKING_EVENT_TYPE_REF_PREDICATE => {
                event_type = Some(
                    decode_claim_value::<BookingEventTypeRefValue>(&body.value, "event type ref")?
                        .event_type,
                );
            }
            _ => {}
        }
    }
    Ok(BookingFacts {
        page_ref: page_ref.ok_or_else(|| refused("booking carries no source page claim"))?,
        event_type: event_type.ok_or_else(|| refused("booking carries no event type claim"))?,
        slot: occurrence_in(vault, rtxn, event_ref)?,
    })
}

/// The EVENT's stored occurrence, read through the CALLER's transaction.
///
/// Deliberately not `Vault::read_entity_header`: that door opens a transaction
/// of its own, and LMDB gives a thread one read transaction at a time, so a
/// nested read would fail whenever this runs under a caller-owned read txn.
fn occurrence_in(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    event_ref: &EntityId,
) -> Result<TimeRange, BookingError> {
    let raw = vault
        .store
        .entities
        .get(rtxn, event_ref.as_bytes())
        .map_err(|error| engine_failure("booking event header read", error))?
        .ok_or_else(|| refused("booking EVENT no longer exists"))?;
    let header = crate::batch::EntityMetadataHeader::parse(&raw)
        .ok_or_else(|| refused("booking EVENT header did not parse"))?;
    Ok(half_open_occurrence(
        header.occurred_start,
        header.occurred_end,
    ))
}

/// The EVENT body a booking stores: the event type key and nothing else. No
/// booker identity, contact, or note travels in the structural row.
fn encode_event_body(event_type: &EventTypeKey) -> Result<Vec<u8>, BookingError> {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![(
            rmpv::Value::from("name"),
            rmpv::Value::from(event_type.0.as_str()),
        )]),
    )
    .map_err(|_| refused("booking event body did not encode"))?;
    Ok(body)
}

/// The `calendar.status` wire map, keyed exactly as CAL-00's decoder reads it.
/// The shared write door validates it, so a misspelled key fails loud.
fn calendar_status_value(status: CalendarStatus, recorded_at: u64) -> rmpv::Value {
    rmpv::Value::Map(vec![
        (
            rmpv::Value::from("status"),
            rmpv::Value::from(status.as_str()),
        ),
        (
            rmpv::Value::from("basis"),
            rmpv::Value::from(CalendarStatusBasis::Booking.as_str()),
        ),
        (
            rmpv::Value::from("recorded_at"),
            rmpv::Value::from(recorded_at),
        ),
    ])
}

// -------------------------------------------------------------------------
// Family validator + descriptor rows
// -------------------------------------------------------------------------

/// Validates one lifecycle claim body's subject and value shape.
///
/// Exact and structural: an unknown `booking.*` predicate is rejected here
/// rather than accepted as a family member, and every value must match its
/// pinned schema with no extra keys.
///
/// # Errors
///
/// [`crate::Error::InvalidClaimBody`] naming the defect.
pub(crate) fn validate_lifecycle_claim(body: &ClaimBody) -> crate::Result<()> {
    let ClaimSubject::Entity(_) = body.subject else {
        return Err(crate::Error::InvalidClaimBody(
            "booking lifecycle claim subject must be an entity",
        ));
    };
    let defect = match body.predicate.as_str() {
        BOOKING_EVENT_TYPE_REF_PREDICATE => claim_value::<BookingEventTypeRefValue>(&body.value)
            .map(|_| ())
            .ok_or("booking.event_type_ref value does not match the pinned schema"),
        BOOKING_BOOKER_CONTACT_PREDICATE => claim_value::<BookingBookerContactValue>(&body.value)
            .map(|_| ())
            .ok_or("booking.booker_contact value does not match the pinned schema"),
        BOOKING_SOURCE_PAGE_PREDICATE => claim_value::<BookingSourcePageValue>(&body.value)
            .map(|_| ())
            .ok_or("booking.source_page value does not match the pinned schema"),
        BOOKING_STATUS_PREDICATE => claim_value::<BookingStatusValue>(&body.value)
            .map(|_| ())
            .ok_or("booking.status value does not match the pinned schema"),
        _ => Err("unknown booking lifecycle claim predicate"),
    };
    defect.map_err(crate::Error::InvalidClaimBody)
}

/// Descriptor rows for the lifecycle family, one per exact predicate.
///
/// All four are `recorded` and `projector_only`: the engine writes them from the
/// home-node transition as facts about a transaction that happened, and no human
/// or agent authors them by hand. No descriptor runtime or registry exists —
/// this is pure data, ready to register when one lands.
#[must_use]
pub fn claim_class_descriptors() -> Vec<ClaimClassDescriptorRow> {
    BOOKING_LIFECYCLE_PREDICATES
        .into_iter()
        .map(|predicate| ClaimClassDescriptorRow {
            predicate,
            write_class: "recorded",
            enforcement: false,
            restrictive: false,
            projector_only: true,
        })
        .collect()
}

// -------------------------------------------------------------------------
// Request validation
// -------------------------------------------------------------------------

fn validate_request(request: &BookingVerbRequest) -> Result<(), BookingError> {
    validate_idempotency_key(request.idempotency_key())?;
    match request {
        BookingVerbRequest::Hold(spec) => validate_hold_spec(spec),
        BookingVerbRequest::Confirm(spec) => validate_token_shape(&spec.hold_token.0),
        BookingVerbRequest::Reschedule(spec) => {
            validate_token_shape(&spec.token.0)?;
            validate_visitor_tz(&spec.visitor_tz)?;
            validate_slot(spec.new_slot)?;
            validate_optional_constraint(spec.constraint.as_ref())
        }
        BookingVerbRequest::Cancel(spec) => validate_token_shape(&spec.token.0),
    }
}

fn validate_hold_spec(spec: &HoldSpec) -> Result<(), BookingError> {
    validate_visitor_tz(&spec.visitor_tz)?;
    validate_slot(spec.slot)?;
    validate_optional_constraint(spec.constraint.as_ref())?;
    if let HoldLeaseSpec::CheckoutExtension {
        server_issued_lease,
    } = &spec.lease
    {
        validate_token_shape(&server_issued_lease.0)?;
    }
    Ok(())
}

fn validate_optional_constraint(constraint: Option<&ConstraintObject>) -> Result<(), BookingError> {
    constraint.map_or(Ok(()), ConstraintObject::validate)
}

fn validate_idempotency_key(key: Option<&str>) -> Result<(), BookingError> {
    match key {
        Some(key) if key.is_empty() || key.len() > MAX_IDEMPOTENCY_KEY_BYTES => Err(refused(
            "idempotency key must be 1..=128 bytes when supplied",
        )),
        _ => Ok(()),
    }
}

/// A slot is a half-open UTC interval, so an empty or inverted one is refused
/// before it can become a hold nobody could confirm.
fn validate_slot(slot: TimeRange) -> Result<(), BookingError> {
    if slot.start >= slot.end {
        return Err(refused("booking slot must satisfy start < end"));
    }
    Ok(())
}

/// A bearer credential is exactly the lowercase hex of [`TOKEN_RAW_BYTES`]
/// random bytes. Anything else cannot have come from this module and is refused
/// before it reaches a digest lookup.
fn validate_token_shape(token: &str) -> Result<(), BookingError> {
    let well_formed = token.len() == TOKEN_RAW_BYTES * 2
        && token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if well_formed {
        Ok(())
    } else {
        Err(refused("opaque token is not a well-formed bearer value"))
    }
}

// -------------------------------------------------------------------------
// Token + hold reads
// -------------------------------------------------------------------------

/// Resolves a token to its EVENT, refusing a token whose recorded scope does not
/// permit `expected`. Scope lives on the row, never in the token.
fn resolve_token_event(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    token: &OpaqueLifecycleToken,
    expected: LifecycleTokenScope,
) -> Result<EntityId, BookingError> {
    let row = read_token_row(vault, rtxn, token)?
        .ok_or_else(|| refused("token does not resolve to a booking"))?;
    if row.scope != expected {
        return Err(refused("token scope does not permit this action"));
    }
    Ok(row.event_ref)
}

fn read_token_row(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    token: &OpaqueLifecycleToken,
) -> Result<Option<LifecycleTokenRow>, BookingError> {
    read_meta(vault, rtxn, BOOKING_TOKEN_META_PREFIX, &token_digest(token))
}

/// Mints and records this booking's reschedule and cancel credentials.
fn write_revision_tokens(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    event_ref: EntityId,
) -> Result<(OpaqueLifecycleToken, OpaqueLifecycleToken), BookingError> {
    let reschedule = OpaqueLifecycleToken(mint_raw_token());
    let cancel = OpaqueLifecycleToken(mint_raw_token());
    for (token, scope) in [
        (&reschedule, LifecycleTokenScope::Reschedule),
        (&cancel, LifecycleTokenScope::Cancel),
    ] {
        let encoded = encode_row(&LifecycleTokenRow { event_ref, scope })?;
        let key = meta_key(BOOKING_TOKEN_META_PREFIX, &token_digest(token));
        put_meta(vault, wtxn, &key, &encoded)?;
    }
    Ok((reschedule, cancel))
}

/// This session's hold row, from committed state.
fn read_hold_row(
    vault: &Vault,
    session_key: &SessionKey,
) -> Result<Option<SoftHoldRow>, BookingError> {
    let rtxn = read_txn(vault)?;
    let Some(raw) = read_meta_bytes(vault, &rtxn, &hold_key(session_key))? else {
        return Ok(None);
    };
    decode_row(&raw).map(Some)
}

/// The page a token's booking came from, for oracle construction only.
///
/// A token that resolves to no booking, or a booking missing its source-page
/// claim, yields `None` here; the authoritative path produces the typed refusal.
fn token_page_ref(
    vault: &Vault,
    token: &OpaqueLifecycleToken,
) -> Result<Option<EntityId>, BookingError> {
    let rtxn = read_txn(vault)?;
    let Some(row) = read_token_row(vault, &rtxn, token)? else {
        return Ok(None);
    };
    Ok(read_booking_facts(vault, &rtxn, &row.event_ref)
        .ok()
        .map(|facts| facts.page_ref))
}

// -------------------------------------------------------------------------
// Storage helpers
// -------------------------------------------------------------------------

/// Acquires the home-node single writer.
///
/// This IS the lifecycle's mutual exclusion: LMDB admits one writer per
/// environment, so everything the closure reads and writes is serialized
/// against every other booking transition. Dropping the transaction on an early
/// return aborts it, so a refusal leaves no partial state.
fn booking_writer<T, F>(vault: &Vault, apply: F) -> Result<T, BookingError>
where
    F: FnOnce(&mut heed::RwTxn<'_>) -> Result<T, BookingError>,
{
    let mut wtxn = vault
        .store
        .env
        .write_txn()
        .map_err(|error| engine_failure("writer acquisition", error))?;
    let value = {
        let _active_write_txn = crate::store::active_write_txn_guard();
        apply(&mut wtxn)?
    };
    wtxn.commit()
        .map_err(|error| engine_failure("writer commit", error))?;
    Ok(value)
}

fn read_txn(vault: &Vault) -> Result<heed::RoTxn<'_>, BookingError> {
    vault
        .store
        .env
        .read_txn()
        .map_err(|error| engine_failure("read transaction", error))
}

fn claims_for_subject(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    subject: &EntityId,
) -> Result<Vec<EntityId>, BookingError> {
    vault
        .claims_for_subject_in_txn(rtxn, subject)
        .map_err(|error| engine_failure("claim subject scan", error))
}

fn meta_key(prefix: &[u8], digest: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + digest.len());
    key.extend_from_slice(prefix);
    key.extend_from_slice(digest);
    key
}

fn hold_key(session_key: &SessionKey) -> Vec<u8> {
    meta_key(
        BOOKING_HOLD_META_PREFIX,
        &digest_with(HOLD_KEY_DOMAIN, &session_key.0),
    )
}

/// Receipt identity for a confirm: the hold token's digest, so the retry key is
/// something only the holder can present and never an advisory input.
fn confirm_receipt_key(hold_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(RECEIPT_KEY_DOMAIN);
    hasher.update(b"confirm\0");
    hasher.update(hold_hash);
    *hasher.finalize().as_bytes()
}

/// Receipt identity for a revision.
///
/// Cancel is keyed by the token alone, so cancelling twice is one receipt. A
/// reschedule is keyed by the token AND the requested slot, because the same
/// token legitimately moves a booking more than once — only a repeat of the SAME
/// move is a retry.
fn revision_receipt_key(token_hash: &[u8; 32], slot: Option<TimeRange>) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(RECEIPT_KEY_DOMAIN);
    match slot {
        Some(slot) => {
            hasher.update(b"reschedule\0");
            hasher.update(&slot.start.to_be_bytes());
            hasher.update(&slot.end.to_be_bytes());
        }
        None => {
            hasher.update(b"cancel\0");
        }
    }
    hasher.update(token_hash);
    *hasher.finalize().as_bytes()
}

fn encode_row<T: Serialize>(value: &T) -> Result<Vec<u8>, BookingError> {
    let mut out = vec![LIFECYCLE_ROW_VERSION];
    out.extend(
        rmp_serde::to_vec_named(value)
            .map_err(|error| refused(format!("lifecycle row does not encode: {error}")))?,
    );
    Ok(out)
}

fn decode_row<T: DeserializeOwned>(raw: &[u8]) -> Result<T, BookingError> {
    let Some((&version, body)) = raw.split_first() else {
        return Err(refused("lifecycle row is empty"));
    };
    if version != LIFECYCLE_ROW_VERSION {
        return Err(refused("lifecycle row version is unsupported"));
    }
    rmp_serde::from_slice(body)
        .map_err(|error| refused(format!("lifecycle row does not decode: {error}")))
}

fn read_meta<T: DeserializeOwned>(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    prefix: &[u8],
    digest: &[u8; 32],
) -> Result<Option<T>, BookingError> {
    let Some(raw) = read_meta_bytes(vault, rtxn, &meta_key(prefix, digest))? else {
        return Ok(None);
    };
    decode_row(&raw).map(Some)
}

fn read_meta_bytes(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    key: &[u8],
) -> Result<Option<Vec<u8>>, BookingError> {
    Ok(vault
        .store
        .vault_meta
        .get(rtxn, key)
        .map_err(|error| engine_failure("meta read", error))?
        .map(std::borrow::Cow::into_owned))
}

fn put_meta(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    key: &[u8],
    value: &[u8],
) -> Result<(), BookingError> {
    vault
        .store
        .vault_meta
        .put(wtxn, key, value)
        .map_err(|error| engine_failure("meta write", error))
}

fn delete_meta(vault: &Vault, wtxn: &mut heed::RwTxn<'_>, key: &[u8]) -> Result<(), BookingError> {
    vault
        .store
        .vault_meta
        .delete(wtxn, key)
        .map(|_| ())
        .map_err(|error| engine_failure("meta delete", error))
}

fn read_receipt(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    receipt_key: &[u8; 32],
) -> Result<Option<LifecycleReceiptRow>, BookingError> {
    read_meta(vault, rtxn, BOOKING_RECEIPT_META_PREFIX, receipt_key)
}

fn write_receipt(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    receipt_key: &[u8; 32],
    row: &LifecycleReceiptRow,
) -> Result<(), BookingError> {
    let encoded = encode_row(row)?;
    put_meta(
        vault,
        wtxn,
        &meta_key(BOOKING_RECEIPT_META_PREFIX, receipt_key),
        &encoded,
    )
}

// -------------------------------------------------------------------------
// Claim value codec
//
// The same `rmp_serde` ↔ `rmpv` bridge `config.rs` uses, rather than a
// hand-rolled nested walk per value.
// -------------------------------------------------------------------------

fn encode_claim_value<T: Serialize>(value: &T) -> Result<rmpv::Value, BookingError> {
    let bytes = rmp_serde::to_vec_named(value)
        .map_err(|error| refused(format!("booking claim value does not encode: {error}")))?;
    rmpv::decode::read_value(&mut std::io::Cursor::new(bytes.as_slice()))
        .map_err(|error| refused(format!("booking claim value does not encode: {error}")))
}

fn claim_value<T: DeserializeOwned>(value: &rmpv::Value) -> Option<T> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).ok()?;
    rmp_serde::from_slice(&bytes).ok()
}

fn decode_claim_value<T: DeserializeOwned>(
    value: &rmpv::Value,
    what: &str,
) -> Result<T, BookingError> {
    claim_value(value).ok_or_else(|| refused(format!("stored booking {what} claim did not decode")))
}

// -------------------------------------------------------------------------
// Interval algebra
// -------------------------------------------------------------------------

/// Half-open `[start, end)` → the engine's inclusive occurrence row.
fn inclusive_occurrence(slot: TimeRange) -> Result<TimeRange, BookingError> {
    let end = slot
        .end
        .checked_sub(1)
        .filter(|end| *end >= slot.start)
        .ok_or_else(|| refused("booking slot must satisfy start < end"))?;
    Ok(TimeRange {
        start: slot.start,
        end,
    })
}

/// The inclusive solve window confirm asks over: the held slot padded far
/// enough on both sides to carry nearest alternatives.
fn confirm_solve_window(slot: TimeRange) -> Result<TimeRange, BookingError> {
    let held = inclusive_occurrence(slot)?;
    Ok(TimeRange {
        start: held.start.saturating_sub(CONFIRM_ALTERNATIVES_PAD_SECS),
        end: held.end.saturating_add(CONFIRM_ALTERNATIVES_PAD_SECS),
    })
}

/// The engine's inclusive occurrence row → half-open `[start, end)`.
const fn half_open_occurrence(start: u64, end: u64) -> TimeRange {
    TimeRange {
        start,
        end: end.saturating_add(1),
    }
}

const fn at(now: u64) -> TimeRange {
    TimeRange {
        start: now,
        end: now,
    }
}

/// Whether the solver still offers exactly this interval. Equality, not
/// containment: the oracle's UTC bounds are authoritative, and nothing here
/// rounds or widens them.
fn offers_slot(slots: &[RankedSlot], slot: TimeRange) -> bool {
    slots
        .iter()
        .any(|ranked| ranked.start_utc == slot.start && ranked.end_utc == slot.end)
}

// -------------------------------------------------------------------------
// Errors
// -------------------------------------------------------------------------

/// A refused request. [`BookingError`] is ONE-1816's, and this lane adds no
/// variant to it: a lifecycle refusal is request data that failed validation.
fn refused(detail: impl Into<String>) -> BookingError {
    BookingError::InvalidConstraint(detail.into())
}

/// Wraps an engine failure without restating the engine's error taxonomy.
fn engine_failure<E: Into<crate::Error>>(what: &str, error: E) -> BookingError {
    let error = error.into();
    BookingError::SlotOracle(format!("booking lifecycle {what} failed: {error}"))
}

/// Wraps a calendar failure OPAQUELY: no `CalendarError` variant is matched, and
/// none is restated in booking's own taxonomy. This is the same stance
/// `solver.rs` takes on `freebusy`.
fn calendar_wrap(error: crate::calendar::CalendarError) -> BookingError {
    BookingError::SlotOracle(format!("booking lifecycle calendar step failed: {error}"))
}

// -------------------------------------------------------------------------
// serde adapters
//
// `TimeRange` and `EntityId` carry no serde impls, and neither is widened for
// booking: the wire shapes live here, exactly as `constraint.rs` and `config.rs`
// keep theirs.
// -------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TimeRangeWire {
    start: u64,
    end: u64,
}

mod time_range_serde {
    use super::{Deserialize, Deserializer, Serialize, Serializer, TimeRange, TimeRangeWire};

    pub(super) fn serialize<S: Serializer>(
        value: &TimeRange,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        TimeRangeWire {
            start: value.start,
            end: value.end,
        }
        .serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<TimeRange, D::Error> {
        let wire = TimeRangeWire::deserialize(deserializer)?;
        Ok(TimeRange {
            start: wire.start,
            end: wire.end,
        })
    }
}

/// Digests cross the wire as lowercase hex — fixed width, and a compact byte
/// string rather than the 32-element integer array `[u8; 32]` would otherwise
/// serialize into.
mod digest_serde {
    use super::{Deserialize, Deserializer, Serializer, hex_lower};

    pub(super) fn serialize<S: Serializer>(
        value: &[u8; 32],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex_lower(value))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u8; 32], D::Error> {
        let hex = String::deserialize(deserializer)?;
        super::digest_from_hex(&hex)
            .ok_or_else(|| serde::de::Error::custom("booking digest is not 32 lowercase hex bytes"))
    }
}

mod opt_digest_serde {
    use super::{Deserialize, Deserializer, Serialize, Serializer, hex_lower};

    pub(super) fn serialize<S: Serializer>(
        value: &Option<[u8; 32]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value.map(|bytes| hex_lower(&bytes)).serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<[u8; 32]>, D::Error> {
        match Option::<String>::deserialize(deserializer)? {
            None => Ok(None),
            Some(hex) => super::digest_from_hex(&hex).map(Some).ok_or_else(|| {
                serde::de::Error::custom("booking digest is not 32 lowercase hex bytes")
            }),
        }
    }
}

/// Parses exactly 32 lowercase hex bytes.
fn digest_from_hex(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0_u8; 32];
    for (slot, pair) in out.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        *slot = (high << 4) | low;
    }
    Some(out)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

mod entity_ref_serde {
    use super::{Deserialize, Deserializer, EntityId, Serializer};

    pub(super) fn serialize<S: Serializer>(
        value: &EntityId,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_hex())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<EntityId, D::Error> {
        let hex = String::deserialize(deserializer)?;
        EntityId::from_hex(&hex).map_err(serde::de::Error::custom)
    }
}

// -------------------------------------------------------------------------
// Crate-internal invariants
//
// These three assertions need to read `vault_meta` bytes and to call the
// family validator directly, neither of which crosses the public API. Every
// BEHAVIOURAL oracle lives in `tests/booking_lifecycle.rs`; only what a
// black-box test structurally cannot see is asserted here.
// -------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::entity as id;

    const PAGE: u8 = 0x51;
    const NOW: u64 = 1_772_409_600;

    fn open_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().expect("temp dir");
        let vault =
            Vault::open(dir.path(), crate::VaultConfig::default()).expect("open booking vault");
        (dir, vault)
    }

    fn hold_spec(session_key: SessionKey) -> HoldSpec {
        HoldSpec {
            page_ref: id(PAGE),
            event_type: EventTypeKey("intro-call".to_owned()),
            slot: TimeRange {
                start: NOW + 3_600,
                end: NOW + 5_400,
            },
            session_key,
            visitor_tz: "UTC".to_owned(),
            constraint: None,
            lease: HoldLeaseSpec::Ordinary,
            idempotency_key: None,
        }
    }

    /// Every byte in `vault_meta`, so a search for a raw secret cannot miss a
    /// row by looking under the wrong prefix.
    fn all_meta_bytes(vault: &Vault) -> Vec<u8> {
        let rtxn = read_txn(vault).expect("read txn");
        let mut bytes = Vec::new();
        for entry in vault.store.vault_meta.iter(&rtxn).expect("meta scan") {
            let (key, value) = entry.expect("meta row");
            bytes.extend_from_slice(&key);
            bytes.extend_from_slice(&value);
        }
        bytes
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty() && haystack.windows(needle.len()).any(|slice| slice == needle)
    }

    #[test]
    fn raw_bearer_tokens_never_enter_vault_meta() {
        let (_dir, vault) = open_vault();
        let session = SessionKey::derive(b"session-one");
        let receipt = execute_hold(&vault, &hold_spec(session), NOW).expect("hold");
        let (lease, _) = issue_checkout_lease(&vault, &session, 600, NOW).expect("lease");

        let stored = all_meta_bytes(&vault);
        assert!(
            !contains(&stored, receipt.token.0.as_bytes()),
            "the raw hold token must never be at rest; only its digest is stored"
        );
        assert!(
            !contains(&stored, lease.0.as_bytes()),
            "the raw checkout lease must never be at rest; only its digest is stored"
        );
        // The digests, by contrast, ARE there — otherwise the assertions above
        // would pass on an empty store. The hold token's digest sits in the row
        // as hex; the lease's digest is also the row's key.
        assert!(contains(
            &stored,
            hex_lower(&token_digest(&receipt.token)).as_bytes()
        ));
        assert!(contains(&stored, &lease_digest(&lease)));
    }

    #[test]
    fn hold_rows_key_on_the_session_and_never_on_the_token() {
        let (_dir, vault) = open_vault();
        let session = SessionKey::derive(b"session-one");
        let receipt = execute_hold(&vault, &hold_spec(session), NOW).expect("hold");

        let rtxn = read_txn(&vault).expect("read txn");
        let key = hold_key(&session);
        assert!(
            read_meta_bytes(&vault, &rtxn, &key)
                .expect("hold row read")
                .is_some(),
            "the row is reachable from the session alone"
        );
        assert!(
            !contains(&key, &token_digest(&receipt.token)),
            "the hold key is derived from the session, not from the credential"
        );
        assert_eq!(
            key.len(),
            BOOKING_HOLD_META_PREFIX.len() + 32,
            "prefix + one 32-byte digest"
        );
        assert!(key.starts_with(BOOKING_HOLD_META_PREFIX));
    }

    #[test]
    fn booking_lifecycle_validator_is_exact_at_the_family_door() {
        let subject = ClaimSubject::Entity(id(0x52));
        let body = |predicate: &str, value: rmpv::Value| {
            ClaimBody::new(
                predicate,
                subject,
                value,
                1.0,
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Active,
            )
        };
        let status = encode_claim_value(&BookingStatusValue {
            status: BookingStatus::Confirmed,
            recorded_at: NOW,
        })
        .expect("encode status");

        validate_lifecycle_claim(&body(BOOKING_STATUS_PREDICATE, status.clone()))
            .expect("a well-formed status value passes");
        // A value from a sibling predicate is refused: the validator routes on
        // the exact predicate and then checks THAT predicate's schema.
        assert!(
            validate_lifecycle_claim(&body(BOOKING_SOURCE_PAGE_PREDICATE, status)).is_err(),
            "one family member's value must not satisfy another's schema"
        );
        // An unknown `booking.*` predicate is never adopted by the family.
        assert!(
            validate_lifecycle_claim(&body(
                "booking.something_new",
                rmpv::Value::from("whatever")
            ))
            .is_err()
        );
        // An edge subject is refused before any value is decoded.
        let mut edge_subject = body(
            BOOKING_STATUS_PREDICATE,
            encode_claim_value(&BookingStatusValue {
                status: BookingStatus::Cancelled,
                recorded_at: NOW,
            })
            .expect("encode status"),
        );
        edge_subject.subject = ClaimSubject::Edge {
            source: id(0x52),
            kind: crate::edge::EdgeKind::ClaimOf,
            target: id(0x53),
        };
        assert!(validate_lifecycle_claim(&edge_subject).is_err());
    }
}
