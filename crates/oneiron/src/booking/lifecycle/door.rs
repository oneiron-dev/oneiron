//! The public verb door and the home-node consumer turn: enqueue, checkout
//! lease, and one claimed attempt run to a receipt.

use super::storage::{booking_writer, decode_row, encode_row, engine_failure};
use super::token::{
    OpaqueCheckoutLeaseToken, SessionKey, lease_digest, mint_raw_token, read_hold_row,
    session_digest, token_page_ref,
};
use super::transition::execute_booking_lifecycle_attempt;
use super::types::{
    BOOKING_LIFECYCLE_ATTEMPT_KIND, BookingLifecycleAttempt, BookingVerbReceipt,
    BookingVerbRequest, MAX_ATTEMPT_FAILURE_REASON_BYTES, MAX_CHECKOUT_HOLD_TTL_SECS,
    validate_request,
};
use super::{CHECKOUT_LEASE, CheckoutLeaseRow};
use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, AttemptState, ClaimAttempt, ClaimOutcome,
    CompleteAttempt, EnqueueAttempt, EnqueueOutcome, FailAttempt,
};
use crate::booking::invite_grant::NoConfirmInviteSink;
use crate::booking::{BookingError, SlotOracle, SolveRequest, SolveResult};
use crate::dreamer_runner::DreamerRunnerStore;
use crate::outbound::OutboundExecutionSink;
use crate::{EntityId, Vault};

/// Validates, encodes, and enqueues one booking verb.
///
/// This is the whole public surface of a verb: it never solves, never writes an
/// EVENT, and never touches a hold. The transition happens on the home node,
/// in [`run_booking_lifecycle_attempt`] or [`run_booking_lifecycle_once`].
///
/// An advisory `idempotency_key` becomes the queue's dedupe string, so a
/// double-submit coalesces onto one attempt row. That is hygiene: correctness
/// comes from the writer and from the durable receipt. The key is the
/// caller's own choice, so it coalesces only the same request: another
/// request under a reused key gets its own attempt rather than the first
/// caller's, whose receipt carries that caller's tokens.
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
    // Sixteen bytes of digest are plenty to tell two requests apart.
    let request_hex = blake3::hash(&encode_row(&attempt.request)?).to_hex();
    let request_digest = &request_hex[..32];
    let dedupe_key = match public_scope {
        Some(snapshot) => attempt.request.idempotency_key().map(|key| {
            format!(
                "public:{}:{request_digest}:{key}",
                blake3::hash(&snapshot).to_hex()
            )
        }),
        // Namespace both arms: a caller's literal key may otherwise equal
        // a public key and coalesce onto an unrestricted queued attempt.
        None => attempt
            .request
            .idempotency_key()
            .map(|key| format!("private:{request_digest}:{key}")),
    };
    let payload = encode_row(&attempt)?;

    let outcome = vault
        .with_write_txn_grouped(|txn| {
            crate::ports::JobQueue::port_job_enqueue(
                vault,
                txn,
                EnqueueAttempt {
                    kind: BOOKING_LIFECYCLE_ATTEMPT_KIND.to_owned(),
                    payload,
                    dedupe_key,
                    run_id: None,
                    now: now_utc,
                },
            )
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
    booking_writer(vault, |wtxn| {
        CHECKOUT_LEASE
            .put(&vault.store, wtxn, &lease_digest(&lease), &row)
            .map_err(|error| engine_failure("meta write", error))
    })?;
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
/// This is the queue drain. It refuses on a node that does not hold the MACRO
/// home-node designation, claims strictly [`BOOKING_LIFECYCLE_ATTEMPT_KIND`]
/// so it never steals another consumer's work, and finalizes the attempt row
/// either way. The attempt it claims is the oldest ready one, whoever enqueued
/// it, so a caller answering one request runs
/// [`run_booking_lifecycle_attempt`] instead.
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
    if let Some(refusal) = home_node_refusal(vault, input)? {
        return Ok(refusal);
    }
    let claimed = vault
        .with_write_txn_grouped(|txn| {
            crate::ports::JobQueue::port_job_claim(
                vault,
                txn,
                Some(BOOKING_LIFECYCLE_ATTEMPT_KIND),
                ClaimAttempt {
                    lease_owner: input.lease_owner.clone(),
                    now: input.now_utc,
                },
            )
        })
        .map_err(|error| engine_failure("lifecycle attempt claim", error))?;
    run_claimed::<F, O, NoConfirmInviteSink>(vault, make_oracle, claimed, input, None)
}

/// Claims and executes exactly the attempt `id` on the home node.
///
/// The door for a caller that enqueued `id` and answers for it: the receipt
/// this returns, and the action tokens inside it, are that attempt's and no
/// other's. A drain would hand back whichever attempt was oldest, which on a
/// public page is another visitor's booking.
///
/// [`BookingLifecycleTurn::Empty`] when `id` is not claimable here: another
/// worker leased or settled it (a double submit coalesced onto it), it is not
/// ready yet, or it is not a booking lifecycle attempt.
///
/// # Errors
///
/// [`BookingError`] from the transition itself, or [`BookingError::SlotOracle`]
/// on a queue failure.
pub fn run_booking_lifecycle_attempt<F, O>(
    vault: &Vault,
    id: AttemptId,
    make_oracle: F,
    input: &BookingLifecycleConsumerInput,
) -> Result<BookingLifecycleTurn, BookingError>
where
    F: FnOnce(&BookingOracleRequest) -> Result<O, BookingError>,
    O: SlotOracle,
{
    run_attempt::<F, O, NoConfirmInviteSink>(vault, id, make_oracle, input, None)
}

/// [`run_booking_lifecycle_attempt`], carrying each committed revision's
/// invite on `invite_sink` (FIX 7850): a confirm's first `REQUEST`, a move's
/// revised one and a cancel's `CANCEL`, sent as the page's verified live
/// publisher through the page's standing invite grant, the gate and the
/// intent ledger. A page with no live publisher sends nothing, and a send
/// that fails never fails the committed revision.
///
/// # Errors
///
/// As [`run_booking_lifecycle_attempt`].
pub fn run_booking_lifecycle_attempt_with_invites<F, O, S>(
    vault: &Vault,
    id: AttemptId,
    make_oracle: F,
    input: &BookingLifecycleConsumerInput,
    invite_sink: &mut S,
) -> Result<BookingLifecycleTurn, BookingError>
where
    F: FnOnce(&BookingOracleRequest) -> Result<O, BookingError>,
    O: SlotOracle,
    S: OutboundExecutionSink,
{
    run_attempt(vault, id, make_oracle, input, Some(invite_sink))
}

fn run_attempt<F, O, S>(
    vault: &Vault,
    id: AttemptId,
    make_oracle: F,
    input: &BookingLifecycleConsumerInput,
    invite_sink: Option<&mut S>,
) -> Result<BookingLifecycleTurn, BookingError>
where
    F: FnOnce(&BookingOracleRequest) -> Result<O, BookingError>,
    O: SlotOracle,
    S: OutboundExecutionSink,
{
    if let Some(refusal) = home_node_refusal(vault, input)? {
        return Ok(refusal);
    }
    let claimed = vault
        .with_write_txn_grouped(|txn| {
            // The point claim refuses a row that is not ready with an error,
            // so a row someone else holds is screened out first and reads as
            // nothing to run, the same answer a drain gives.
            let claimable = AttemptQueue::new(vault)
                .get_in_write_txn(txn, id)?
                .is_some_and(|row| {
                    row.kind == BOOKING_LIFECYCLE_ATTEMPT_KIND
                        && matches!(row.state, AttemptState::Queued | AttemptState::Scheduled)
                });
            if !claimable {
                return Ok(ClaimOutcome::Empty);
            }
            crate::ports::JobQueue::port_job_claim_id(
                vault,
                txn,
                id,
                ClaimAttempt {
                    lease_owner: input.lease_owner.clone(),
                    now: input.now_utc,
                },
            )
        })
        .map_err(|error| engine_failure("lifecycle attempt claim", error))?;
    run_claimed(vault, make_oracle, claimed, input, invite_sink)
}

/// Cross-node serialization, read before anything is claimed: a node that is
/// not the home node must not even lease the attempt, or the row would sit
/// leased on a node that may not write.
fn home_node_refusal(
    vault: &Vault,
    input: &BookingLifecycleConsumerInput,
) -> Result<Option<BookingLifecycleTurn>, BookingError> {
    let designation = DreamerRunnerStore::new(vault)
        .home_node_designation()
        .map_err(|error| engine_failure("home node designation read", error))?;
    Ok(match designation {
        None => Some(BookingLifecycleTurn::NoHomeNode),
        Some(designation) if designation.node_id != input.local_node_id => {
            Some(BookingLifecycleTurn::NotHomeNode {
                home_node_id: designation.node_id,
            })
        }
        Some(_) => None,
    })
}

/// Runs one claimed attempt to a receipt and finalizes its row.
fn run_claimed<F, O, S>(
    vault: &Vault,
    make_oracle: F,
    claimed: ClaimOutcome,
    input: &BookingLifecycleConsumerInput,
    invite_sink: Option<&mut S>,
) -> Result<BookingLifecycleTurn, BookingError>
where
    F: FnOnce(&BookingOracleRequest) -> Result<O, BookingError>,
    O: SlotOracle,
    S: OutboundExecutionSink,
{
    let ClaimOutcome::Claimed(record) = claimed else {
        return Ok(BookingLifecycleTurn::Empty);
    };
    let outcome = execute_claimed_attempt(vault, make_oracle, &record, input.now_utc, invite_sink);
    finalize_attempt(vault, &record, &outcome, input)?;
    outcome.map(BookingLifecycleTurn::Executed)
}

/// Decodes one claimed row and runs it, with the oracle built from its request.
fn execute_claimed_attempt<F, O, S>(
    vault: &Vault,
    make_oracle: F,
    record: &AttemptRecord,
    now_utc: u64,
    invite_sink: Option<&mut S>,
) -> Result<BookingVerbReceipt, BookingError>
where
    F: FnOnce(&BookingOracleRequest) -> Result<O, BookingError>,
    O: SlotOracle,
    S: OutboundExecutionSink,
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
    // Invites go out as the page's verified live publisher, the principal
    // its standing grant is bound to, and only on a sink the consumer seam
    // supplied; a turn without one commits exactly as before.
    let invite_actor = match (&invite_sink, request.page_ref) {
        (Some(_), Some(page_ref)) => {
            crate::booking::publication::live_booking_page_publisher(vault, page_ref, now_utc)
                .map_err(|error| engine_failure("booking page publisher read", error))?
        }
        _ => None,
    };
    execute_booking_lifecycle_attempt(vault, oracle, &attempt, now_utc, invite_actor, invite_sink)
}

/// Completes or fails the attempt row, whatever the transition returned.
///
/// A `SlotTaken` receipt is a SUCCESSFUL attempt: the transition ran and
/// decided. Only a typed failure fails the row.
fn finalize_attempt(
    vault: &Vault,
    record: &AttemptRecord,
    outcome: &Result<BookingVerbReceipt, BookingError>,
    input: &BookingLifecycleConsumerInput,
) -> Result<(), BookingError> {
    match outcome {
        Ok(_) => vault
            .with_write_txn_grouped(|txn| {
                crate::ports::JobQueue::port_job_complete(
                    vault,
                    txn,
                    CompleteAttempt {
                        id: record.id,
                        lease_owner: input.lease_owner.clone(),
                        attempt_count: record.attempt_count,
                        now: input.now_utc,
                    },
                )
            })
            .map(|_| ())
            .map_err(|error| engine_failure("lifecycle attempt complete", error)),
        Err(failure) => vault
            .with_write_txn_grouped(|txn| {
                crate::ports::JobQueue::port_job_fail(
                    vault,
                    txn,
                    FailAttempt {
                        id: record.id,
                        lease_owner: input.lease_owner.clone(),
                        attempt_count: record.attempt_count,
                        reason: attempt_failure_reason(failure),
                        now: input.now_utc,
                    },
                )
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
