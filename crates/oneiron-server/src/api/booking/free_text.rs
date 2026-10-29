//! A booking page's free-text constraint (ONE-1816), parsed on the cheap seat
//! `[models.decisions.booking_parse]` names: the off-topic question through
//! the host's ladder, then one extraction call, each sent on the seat as the
//! vault's live model policy admits it. The sentence never reaches the oracle:
//! only the canonical object and a validated timezone do.
//!
//! An authenticated caller's parse is paid on its principal's line; an
//! anonymous visitor's on the vault owner's, who publishes the page.
use std::sync::Arc;

use oneiron::booking::ConstraintObject;
use oneiron::booking::constraint::{
    CONSTRAINT_PARSE_CALL_PURPOSE, ConstraintParseConfig, ConstraintParseDisposition,
    ConstraintParseRequest, parse_constraint_with_backend,
};
use oneiron::llm::manifest::ModelRole;
use oneiron::llm::run_admission::RunAdmission;
use oneiron::store::GateDecisionId;
use oneiron::{
    BudgetExhaustionPolicy, BudgetLease, CallPurpose, EdgeActorClass, EntityId, FatalLlmError,
    LlmBackend, LlmCapability, LlmGenerateFuture, LlmRequest, LlmStreamResult, ModelId,
    ModelTierRef, TierPrecedence, WriteActor,
};

use super::BookingAdmissionContext;
use super::helpers::booking_error;
use crate::config::models::{BookingParseSettings, role_key};
use crate::error::ApiError;
use crate::ladder_poll::block_on;
use crate::models::OfferLadder;
use crate::server::SyncServer;

/// Parses `free_text` into the object the oracle solves, and the visitor
/// timezone the text names, if any. Without a configured seat free text is
/// refused, never forwarded. `sponsor` is the page's publication-time payer
/// (FIX 5288), read from the publication the request already loaded; an
/// anonymous visitor's parse pays on it while it is still live, else on the
/// vault owner as before. An authenticated caller pays as itself either way.
pub(super) async fn parse_free_text(
    server: &Arc<SyncServer>,
    transport: &BookingAdmissionContext,
    sponsor: Option<EntityId>,
    free_text: String,
    visitor_tz: String,
    now: u64,
) -> Result<(ConstraintObject, Option<String>), ApiError> {
    let settings = parse_seat_settings(server)?;
    let server = Arc::clone(server);
    let transport = transport.clone();
    // The ladder's model rungs block on the server's runtime.
    tokio::task::spawn_blocking(move || {
        // Who pays, judged again just before the seat spends (FIX 5327).
        let principal = transport.payer_now(server.vault());
        parse_on_seat(
            &server, &settings, principal, sponsor, free_text, visitor_tz, now,
        )
    })
    .await
    .map_err(|_| ApiError::internal_server_error("booking free-text parse stopped"))?
}

/// The configured parse seat. Without one, free text is refused, never
/// forwarded, on every door that parses it.
pub(super) fn parse_seat_settings(server: &SyncServer) -> Result<BookingParseSettings, ApiError> {
    server
        .decision_host()
        .booking_parse()
        .cloned()
        .ok_or_else(|| {
            ApiError::not_implemented(
                "booking free-text constraint parsing requires [models.decisions.booking_parse]",
            )
        })
}

fn parse_on_seat(
    server: &SyncServer,
    settings: &BookingParseSettings,
    principal: Option<WriteActor>,
    sponsor: Option<EntityId>,
    free_text: String,
    visitor_tz: String,
    now: u64,
) -> Result<(ConstraintObject, Option<String>), ApiError> {
    let request = ConstraintParseRequest {
        free_text,
        detected_visitor_tz: visitor_tz,
        now_utc: now,
    };
    on_parse_seat(
        server,
        settings,
        principal,
        sponsor,
        now,
        |backend, lease, config| match block_on(parse_constraint_with_backend(
            backend, lease, &request, config,
        ))
        .map_err(booking_error)?
        {
            ConstraintParseDisposition::Constraint {
                object,
                visitor_tz_override,
            } => Ok((object, visitor_tz_override)),
            ConstraintParseDisposition::OffTopic => Err(ApiError::bad_request(
                "the constraint text is not a scheduling preference",
                Some("constraint"),
            )),
        },
    )
}

/// Runs one admitted parse on the seat: `parse` gets the seat's backend, the
/// carrier lease and the parse config, called from a blocking thread. The
/// payer is `principal`, or, for an anonymous visitor, the page's
/// publication-time `sponsor` while one is stored and still live, else the
/// vault owner who publishes the page, as before.
pub(super) fn on_parse_seat<T>(
    server: &SyncServer,
    settings: &BookingParseSettings,
    principal: Option<WriteActor>,
    sponsor: Option<EntityId>,
    now: u64,
    parse: impl FnOnce(&dyn LlmBackend, &BudgetLease, &ConstraintParseConfig) -> Result<T, ApiError>,
) -> Result<T, ApiError> {
    let unserved = || ApiError::internal_server_error("the booking parse seat is not served");
    let vault = server.vault();
    let payer = match principal {
        Some(actor) => actor,
        None => anonymous_payer(vault, sponsor).map_err(|_| unserved())?,
    };
    let models = server.ai.models();
    let seat = models.seat(settings.role).ok_or_else(unserved)?;
    let route = models
        .route_role(vault, settings.role, seat)
        .map_err(|_| unserved())?;
    let run_id = format!("booking_parse:{}:{now}", payer.entity_ref().to_hex());
    let line = |run: String| {
        let units = server.ai.chat_settings().turn_budget_units;
        vault
            .policy_budget_guard(
                run,
                units,
                oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS.min(units),
                BudgetExhaustionPolicy::Suspend,
                payer,
            )
            .map_err(|_| ApiError::invalid_state(Some("booking_parse_not_admitted")))
    };
    let backend = SeatBackend {
        server,
        role: settings.role,
        model: route.model.clone(),
        ladder: route.ladder,
        run: server
            .ai
            .undeclared_run(run_id.clone(), line(run_id.clone())?),
    };
    // The lease is a carrier only: each send is admitted on the run's own
    // permits, and the carrier is released unspent.
    let carrier = line(format!("{run_id}/carrier"))?;
    let lease = carrier
        .admit()
        .map_err(|_| ApiError::invalid_state(Some("booking_parse_not_admitted")))?
        .lease;
    let purpose = CallPurpose::Other {
        name: CONSTRAINT_PARSE_CALL_PURPOSE.to_owned(),
    };
    let config = ConstraintParseConfig {
        model: route.model,
        locality: route.locality,
        tier: TierPrecedence::for_purpose(&purpose, ModelTierRef(role_key(settings.role))),
        max_input_bytes: settings.max_input_bytes,
        decisions: server.decision_host().booking_decisions(payer.entity_ref()),
    };
    let parsed = parse(&backend, &lease, &config);
    let _ = carrier.abort(&lease);
    parsed
}

/// Who pays an anonymous visitor's parse (FIX 4372, Engine ruling A 10-19):
/// the page's publication-time `sponsor` while one is stored and still a
/// live person (FIX 5288), else the vault that published the page, as its
/// embedded owner, on every substrate. The sponsor's liveness is the FIX
/// 5327 person check, the payer half `BookingAdmissionContext::payer_now`
/// rechecks before a spend: authenticated and revalidated as a live person,
/// with no grant of its own to stand on. No sponsor, a sponsor no longer
/// live, or a liveness read that faults pays exactly as before. An
/// authenticated caller, a managed vault's live attested owner included,
/// pays as itself (`transport.rs`). An attested holder the vault no longer
/// records as its live owner pays as himself while a live grant here names
/// him, and here, as an anonymous visitor, otherwise or once that grant no
/// longer stands (FIX 5327, `BookingAdmissionContext::payer_now`).
fn anonymous_payer(
    vault: &oneiron::Vault,
    sponsor: Option<EntityId>,
) -> Result<WriteActor, oneiron::MemoryError> {
    if let Some(sponsor) = sponsor
        && let Ok(person) =
            vault.authenticate_owner(sponsor, &sponsor.to_hex(), true, GateDecisionId::now())
        && let Ok(live) = person.revalidate_person(vault)
    {
        return Ok(WriteActor::new(live, EdgeActorClass::Human));
    }
    let owner = vault.ensure_embedded_owner_actor()?;
    Ok(WriteActor::new(owner, EdgeActorClass::Human))
}

/// The parse seat under one run: each request the parse builds is admitted
/// as a call of the seat's role, and sent only while the admitted model is
/// still the one the parse's pins name.
struct SeatBackend<'s> {
    server: &'s SyncServer,
    role: ModelRole,
    model: ModelId,
    ladder: Arc<OfferLadder>,
    run: RunAdmission,
}

impl LlmBackend for SeatBackend<'_> {
    fn supports(&self, model: &ModelId, capability: LlmCapability) -> bool {
        self.ladder.supports(model, &capability)
    }

    fn generate<'a>(&'a self, request: LlmRequest, _: &'a BudgetLease) -> LlmGenerateFuture<'a> {
        let admitted = self
            .server
            .ai
            .admit_role(self.server.vault(), self.role, request)
            .ok()
            .filter(|admitted| admitted.request.model == self.model);
        Box::pin(async move {
            let admitted = admitted.ok_or(FatalLlmError::InvalidRequest)?;
            admitted
                .ladder
                .generate(&self.run, admitted.request, None)
                .await
        })
    }

    /// The parse never streams.
    fn stream<'a>(&'a self, _: LlmRequest, _: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}
