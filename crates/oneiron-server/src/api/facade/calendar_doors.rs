//! Owner-authorized calendar file imports through the credential's own handle.
use std::sync::Arc;

use oneiron::EdgeActorClass;
use oneiron::calendar::ingest::door::{
    CalendarIcsImportReceipt, CalendarIcsImportRequest, CalendarInstanceMoveRequest,
    import_ics_as_owner, move_instance_as_owner,
};

use super::host_doors::{Listed, credential_listing, owner_proof, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_calendar_ics_import(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CalendarIcsImportRequest,
) -> Listed<CalendarIcsImportReceipt> {
    const VERB: &str = "vault.calendar.ics.import";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    let actor = match owner.actor_for_read(server.vault()) {
        Ok(actor) => actor,
        Err(error) => return refused(error.into()),
    };
    credential_listing(
        server,
        auth,
        (actor, EdgeActorClass::Human),
        VERB,
        move |_, _, memory| import_ics_as_owner(&memory, &owner, &input),
    )
    .await
}

pub(crate) async fn vault_calendar_instances_move(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CalendarInstanceMoveRequest,
) -> Listed<CalendarIcsImportReceipt> {
    const VERB: &str = "vault.calendar.instances.move";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    let actor = match owner.actor_for_read(server.vault()) {
        Ok(actor) => actor,
        Err(error) => return refused(error.into()),
    };
    credential_listing(
        server,
        auth,
        (actor, EdgeActorClass::Human),
        VERB,
        move |_, _, memory| move_instance_as_owner(&memory, &owner, &input),
    )
    .await
}

use oneiron::calendar::connectors::door::{
    self as connector, CalendarConnectorConfigureRequest, CalendarConnectorKillRequest,
    CalendarConnectorRegistration, CalendarConnectorRequest, CalendarConnectorWriteRequest,
    CalendarImipTransportConfig,
};
use oneiron::calendar::{CalDavConnector, CalendarSyncOutcome, RemoteWriteReceipt};
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{Memory, MemoryError, MemoryResult};

async fn as_owner<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&SyncServer, Memory<'_>, AuthenticatedOwner) -> MemoryResult<T> + Send + 'static,
) -> Listed<T> {
    let owner = match owner_proof(auth, server, verb) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    let actor = match owner.actor_for_read(server.vault()) {
        Ok(actor) => actor,
        Err(error) => return refused(error.into()),
    };
    credential_listing(
        server,
        auth,
        (actor, EdgeActorClass::Human),
        verb,
        move |server, _, memory| act(server, memory, owner),
    )
    .await
}

pub(crate) async fn calendar_connector_configure(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CalendarConnectorConfigureRequest,
) -> Listed<CalendarConnectorRegistration> {
    as_owner(
        server,
        auth,
        "calendar.connector.configure",
        move |_, memory, owner| connector::configure(&memory, &owner, &input),
    )
    .await
}

pub(crate) async fn calendar_connector_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CalendarConnectorRequest,
) -> Listed<Option<CalendarConnectorRegistration>> {
    as_owner(
        server,
        auth,
        "calendar.connector.get",
        move |_, memory, owner| connector::get(&memory, &owner, &input),
    )
    .await
}

pub(crate) async fn calendar_connector_kill(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CalendarConnectorKillRequest,
) -> Listed<CalendarConnectorRegistration> {
    as_owner(
        server,
        auth,
        "calendar.connector.kill",
        move |_, memory, owner| connector::kill(&memory, &owner, &input),
    )
    .await
}

pub(crate) async fn calendar_connector_pull(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CalendarConnectorRequest,
) -> Listed<CalendarSyncOutcome> {
    as_owner(
        server,
        auth,
        "calendar.connector.pull",
        move |server, memory, owner| {
            let row = connector::get(&memory, &owner, &input)?
                .ok_or_else(|| MemoryError::not_found("calendar seat is not configured"))?;
            let wire = crate::calendar_host::HttpCalDav::new(
                Arc::clone(server.vault()),
                owner.clone(),
                row.clone(),
            )
            .map_err(|error| MemoryError::bad_request(error.to_string()))?;
            let now = server.vault().now_recorded_at();
            let seed = now;
            let outcome = oneiron::calendar::run_calendar_connector_sync(
                server.vault(),
                &row.seat,
                &CalDavConnector::new(wire),
                now,
                seed,
            )
            .map_err(|error| MemoryError::bad_request(error.to_string()))?;
            connector::observe_sync(&memory, &owner, &row, &outcome)?;
            Ok(outcome)
        },
    )
    .await
}

pub(crate) async fn calendar_connector_write(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CalendarConnectorWriteRequest,
) -> Listed<RemoteWriteReceipt> {
    as_owner(
        server,
        auth,
        "calendar.connector.write",
        move |server, memory, owner| {
            let view = memory.calendar_read(&oneiron::calendar::CalendarReadRequest {
                event_ref: input.event_ref.clone(),
            })?;
            if view.value.is_none() {
                return Err(
                    MemoryError::not_found("calendar EVENT is absent or withheld")
                        .with_read_receipt(view.receipt),
                );
            }
            let event = oneiron::EntityId::from_hex(&input.event_ref)?;
            let row = connector::get(
                &memory,
                &owner,
                &CalendarConnectorRequest {
                    seat_ref: input.seat_ref,
                },
            )?
            .ok_or_else(|| MemoryError::not_found("calendar seat is not configured"))?;
            let wire = crate::calendar_host::HttpCalDav::new(
                Arc::clone(server.vault()),
                owner,
                row.clone(),
            )
            .map_err(|error| MemoryError::bad_request(error.to_string()))?;
            oneiron::calendar::write_calendar_event(
                server.vault(),
                &row.seat,
                &CalDavConnector::new(wire),
                event,
                server.vault().now_recorded_at(),
            )
            .map_err(|error| MemoryError::bad_request(error.to_string()))
        },
    )
    .await
}

pub(crate) async fn calendar_imip_configure(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CalendarImipTransportConfig,
) -> Listed<CalendarImipTransportConfig> {
    as_owner(
        server,
        auth,
        "calendar.imip.configure",
        move |_, memory, owner| connector::configure_imip(&memory, &owner, &input),
    )
    .await
}

pub(crate) async fn calendar_imip_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: oneiron::task_verb::sdk::EmptyRequest,
) -> Listed<Option<CalendarImipTransportConfig>> {
    as_owner(
        server,
        auth,
        "calendar.imip.get",
        move |_, memory, owner| connector::get_imip(&memory, &owner),
    )
    .await
}

use oneiron::calendar::ingest::feed_door::{
    self as feed, CalendarIcsFeedConfigureRequest, CalendarIcsFeedRegistration,
    CalendarIcsFeedRequest, CalendarIcsFeedStatus, CalendarIcsPollCompletion,
};
use oneiron::calendar::ingest::{CustodyDoorIcsFeedFetcher, run_ics_feed_poll};

pub(crate) async fn calendar_ics_configure(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CalendarIcsFeedConfigureRequest,
) -> Listed<CalendarIcsFeedRegistration> {
    as_owner(
        server,
        auth,
        "calendar.ics.configure",
        move |_, memory, owner| feed::configure(&memory, &owner, &input),
    )
    .await
}

pub(crate) async fn calendar_ics_status(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CalendarIcsFeedRequest,
) -> Listed<Option<CalendarIcsFeedStatus>> {
    as_owner(
        server,
        auth,
        "calendar.ics.status",
        move |_, memory, owner| feed::status(&memory, &owner, &input),
    )
    .await
}

pub(crate) async fn calendar_ics_poll(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CalendarIcsFeedRequest,
) -> Listed<CalendarIcsPollCompletion> {
    as_owner(
        server,
        auth,
        "calendar.ics.poll",
        move |server, memory, owner| {
            let row = feed::get(&memory, &owner, &input)?
                .ok_or_else(|| MemoryError::not_found("ICS feed is not configured"))?;
            let transport = crate::calendar_host::HttpIcsFeed::new(
                Arc::clone(server.vault()),
                owner.clone(),
                row.config.clone(),
            )
            .map_err(MemoryError::bad_request)?;
            let fetcher =
                CustodyDoorIcsFeedFetcher::new(server.vault(), "calendar.ics.poll", transport);
            let poll_ref = oneiron::EntityId::now().to_hex();
            let now = server.vault().now_recorded_at();
            let outcome = run_ics_feed_poll(server.vault(), &fetcher, &row.config, now, now)
                .map_err(|error| MemoryError::bad_request(error.to_string()))?;
            feed::observe_poll(&memory, &owner, &row.config, poll_ref, outcome)
        },
    )
    .await
}

use oneiron::calendar::meeting::{
    self as meeting, CalendarCheckInDue, CalendarCheckInReceipt, CalendarCheckInRequest,
    CalendarMeetingRequest, CalendarOutcomePolicy,
};
use oneiron::claim::ScopedReadResult;

pub(crate) async fn vault_calendar_outcome_policy_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: oneiron::task_verb::sdk::EmptyRequest,
) -> Listed<CalendarOutcomePolicy> {
    as_owner(
        server,
        auth,
        "vault.calendar.outcome_policy.get",
        move |_, memory, owner| meeting::outcome_policy_get(&memory, &owner),
    )
    .await
}

pub(crate) async fn vault_calendar_outcome_policy_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CalendarOutcomePolicy,
) -> Listed<CalendarOutcomePolicy> {
    as_owner(
        server,
        auth,
        "vault.calendar.outcome_policy.set",
        move |_, memory, owner| meeting::outcome_policy_set(&memory, &owner, &input),
    )
    .await
}

pub(crate) async fn vault_calendar_check_in_due(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CalendarMeetingRequest,
) -> Listed<ScopedReadResult<Option<CalendarCheckInDue>>> {
    as_owner(
        server,
        auth,
        "vault.calendar.check_in.due",
        move |_, memory, owner| meeting::check_in_due(&memory, &owner, &input),
    )
    .await
}

pub(crate) async fn vault_calendar_check_in_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CalendarCheckInRequest,
) -> Listed<CalendarCheckInReceipt> {
    as_owner(
        server,
        auth,
        "vault.calendar.check_in.answer",
        move |_, memory, owner| meeting::check_in_answer(&memory, &owner, &input),
    )
    .await
}
