//! The public verb door and the home-node consumer turn: enqueue, checkout
//! lease, and one claimed attempt run to a receipt.

use super::CheckoutLeaseRow;
use super::storage::{booking_writer, decode_row, encode_row, engine_failure, meta_key, put_meta};
use super::token::{
    OpaqueCheckoutLeaseToken, SessionKey, lease_digest, mint_raw_token, read_hold_row,
    session_digest, token_page_ref,
};
use super::transition::execute_booking_lifecycle_attempt;
use super::types::{
    BOOKING_LIFECYCLE_ATTEMPT_KIND, BOOKING_TOKEN_META_PREFIX, BookingLifecycleAttempt,
    BookingVerbReceipt, BookingVerbRequest, MAX_ATTEMPT_FAILURE_REASON_BYTES,
    MAX_CHECKOUT_HOLD_TTL_SECS, validate_request,
};
use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome, CompleteAttempt,
    EnqueueAttempt, EnqueueOutcome, FailAttempt,
};
use crate::booking::invite_grant::NoConfirmInviteSink;
use crate::booking::{BookingError, SlotOracle, SolveRequest, SolveResult};
use crate::dreamer_runner::DreamerRunnerStore;
use crate::{EntityId, Vault};

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
    enqueue_booking_verb_with_publication(vault, request, now_utc, None)
}

/// Enqueue with a public-authority restriction that survives queue delay.
/// The writer, not this supplied snapshot, decides whether authority is live.
pub fn enqueue_booking_verb_with_publication(
    vault: &Vault,
    request: BookingVerbRequest,
    now_utc: u64,
    public_authority: Option<crate::booking::publication::PublicBookingAuthority>,
) -> Result<AttemptId, BookingError> {
    validate_request(&request)?;
    let attempt = BookingLifecycleAttempt {
        request,
        requested_at: now_utc,
        public_authority,
    };
    let public_scope = attempt
        .public_authority
        .as_ref()
        .map(encode_row)
        .transpose()?;
    let dedupe_key = match public_scope {
        Some(snapshot) => attempt
            .request
            .idempotency_key()
            .map(|key| format!("public:{}:{key}", blake3::hash(&snapshot).to_hex())),
        // Namespace both arms: a caller's literal key may otherwise equal
        // a public key and coalesce onto an unrestricted queued attempt.
        None => attempt
            .request
            .idempotency_key()
            .map(|key| format!("private:{key}")),
    };
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
/// satisfies [`HoldLeaseSpec::CheckoutExtension`](super::HoldLeaseSpec::CheckoutExtension) is a token minted here, so a
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
/// asks its [`ActiveHoldSource`](crate::booking::ActiveHoldSource) for every live hold and passes `None` for the
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
    // No invite dispatch context: the consumer seam that owns the
    // server-authenticated actor and the real connector sink supplies both
    // trailing arguments, and a turn without them confirms exactly as before.
    execute_booking_lifecycle_attempt::<NoConfirmInviteSink>(
        vault, oracle, &attempt, now_utc, None, None,
    )
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
