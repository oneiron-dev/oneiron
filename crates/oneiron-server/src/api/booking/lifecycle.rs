use std::sync::Arc;

use oneiron::booking::{
    BookingError, BookingLifecycleConsumerInput, BookingLifecycleTurn, BookingOracleRequest,
    BookingSolver, BookingVerbReceipt, BookingVerbRequest, SessionKey, SlotOracle, SolveRequest,
    SolveResult, VaultActiveHoldSource, enqueue_booking_verb, run_booking_lifecycle_once,
};
use oneiron::dreamer_runner::DreamerHomeNodeClass;
use oneiron::{CalendarSel, DreamerRunnerStore, EntityId, Vault};

use super::constants::BOOKING_LIFECYCLE_LEASE_OWNER;
use super::helpers::engine_read_error;
use super::page_token::page_event_type_configs_engine;
use crate::error::ApiError;
use crate::server::SyncServer;

// -------------------------------------------------------------------------
// Lifecycle drive
// -------------------------------------------------------------------------

/// Enqueues one verb and drains exactly one home-node consumer turn.
///
/// The verb door and the writer door are the merged lifecycle's, not a second
/// implementation: this function only enqueues, builds the per-attempt oracle,
/// and reports the receipt. Correctness — slot revalidation, mutual exclusion,
/// receipt identity — belongs to the writer.
pub(super) async fn run_booking_verb(
    server: &Arc<SyncServer>,
    request: BookingVerbRequest,
    exclude_session: Option<SessionKey>,
    now: u64,
) -> Result<BookingVerbReceipt, ApiError> {
    let vault: &Vault = &server.vault;
    let local_node_id = local_booking_node_id(server)?;
    enqueue_booking_verb(vault, request, now)?;
    let turn = run_booking_lifecycle_once(
        vault,
        |oracle_request: &BookingOracleRequest| {
            let page_ref = oracle_request.page_ref.ok_or_else(|| {
                BookingError::SlotOracle(
                    "booking attempt names no page in committed state".to_owned(),
                )
            })?;
            Ok(ServerBookingOracle {
                vault,
                page_ref,
                exclude_session_key: oracle_request.exclude_session_key.or(exclude_session),
                now_utc: now,
                calendars: page_calendar_bindings(vault, page_ref)?,
            })
        },
        &BookingLifecycleConsumerInput {
            local_node_id,
            lease_owner: BOOKING_LIFECYCLE_LEASE_OWNER.to_owned(),
            now_utc: now,
        },
    )?;
    match turn {
        BookingLifecycleTurn::Executed(receipt) => Ok(receipt),
        BookingLifecycleTurn::NoHomeNode => {
            Err(ApiError::invalid_state(Some("booking_no_home_node_writer")))
        }
        BookingLifecycleTurn::NotHomeNode { .. } => Err(ApiError::invalid_state(Some(
            "booking_writer_is_another_node",
        ))),
        // The attempt this call enqueued was drained by another worker before
        // this turn claimed it. The write may still land; the caller retries
        // with the same idempotency key and coalesces onto the same attempt.
        BookingLifecycleTurn::Empty => Err(ApiError::invalid_state(Some(
            "booking_attempt_claimed_elsewhere",
        ))),
        other => {
            tracing::error!(turn = ?other, "booking lifecycle returned an unknown turn");
            Err(ApiError::internal_server_error(
                "booking lifecycle returned an unknown turn",
            ))
        }
    }
}

/// This daemon's node id for the booking home-node check.
///
/// A hosted deployment gives each tenant daemon a nonzero `lease_vault_id`,
/// which IS its node identity. A single-vault local deployment leaves it at
/// zero, and there the operator's own always-on-local designation names this
/// device — the one class that means "the machine holding this vault". A
/// cloud-attached or primary-device designation names some OTHER node, so
/// this daemon reports no id and the lifecycle refuses to write, which is the
/// correct fail-closed answer rather than a claim of authority.
fn local_booking_node_id(server: &SyncServer) -> Result<u64, ApiError> {
    if server.config.lease_vault_id != 0 {
        return Ok(server.config.lease_vault_id);
    }
    let designation = DreamerRunnerStore::new(&server.vault)
        .home_node_designation()
        .map_err(engine_read_error)?;
    designation
        .filter(|designation| designation.class == DreamerHomeNodeClass::AlwaysOnLocal)
        .map(|designation| designation.node_id)
        .ok_or_else(|| ApiError::invalid_state(Some("booking_no_home_node_writer")))
}

/// The merged production oracle, bound to this page and to committed holds.
///
/// It implements [`SlotOracle`] rather than reimplementing one: availability
/// and every lifecycle revalidation see the same solver, the same
/// configuration claim, and the same live-hold view.
pub(super) struct ServerBookingOracle<'a> {
    vault: &'a Vault,
    page_ref: EntityId,
    exclude_session_key: Option<SessionKey>,
    now_utc: u64,
    calendars: Vec<(EntityId, Vec<CalendarSel>)>,
}

impl SlotOracle for ServerBookingOracle<'_> {
    fn solve(&self, request: &SolveRequest) -> Result<SolveResult, BookingError> {
        let holds = match self.exclude_session_key {
            Some(key) => VaultActiveHoldSource::excluding(self.vault, key),
            None => VaultActiveHoldSource::new(self.vault),
        };
        BookingSolver {
            vault: self.vault,
            page_ref: self.page_ref,
            calendars_by_host: &self.calendars,
            holds: &holds,
            now_utc: self.now_utc,
            // `None` means "resolve the live `booking.event_type` claim on
            // this page". The synthetic arm belongs to page-less companion
            // presets, and a booking page is never page-less.
            synthetic_config: None,
        }
        .solve(request)
    }
}

/// Builds the oracle for one page outside the lifecycle, for availability.
pub(super) fn booking_oracle<'a>(
    server: &'a SyncServer,
    page_ref: EntityId,
    exclude_session_key: Option<SessionKey>,
    now: u64,
) -> Result<ServerBookingOracle<'a>, ApiError> {
    Ok(ServerBookingOracle {
        vault: &server.vault,
        page_ref,
        exclude_session_key,
        now_utc: now,
        calendars: page_calendar_bindings(&server.vault, page_ref)?,
    })
}

/// The request-time host to calendar binding the solver asks CAL through.
///
/// One entry per configured host, so a host's availability is never
/// contaminated by another host's feed. The selector stays unfiltered because
/// the passport-index selector is CAL-02's and is ignored on this baseline; a
/// host with no configured calendar is a configuration defect the solver
/// refuses, not a free host.
fn page_calendar_bindings(
    vault: &Vault,
    page_ref: EntityId,
) -> Result<Vec<(EntityId, Vec<CalendarSel>)>, BookingError> {
    let mut bindings: Vec<(EntityId, Vec<CalendarSel>)> = Vec::new();
    for config in page_event_type_configs_engine(vault, page_ref)? {
        for host in &config.hosts {
            if bindings.iter().any(|(id, _)| *id == host.host_ref) {
                continue;
            }
            bindings.push((host.host_ref, vec![CalendarSel { system: None }]));
        }
    }
    Ok(bindings)
}
