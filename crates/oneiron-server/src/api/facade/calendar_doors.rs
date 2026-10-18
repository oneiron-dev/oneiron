//! Owner-authorized calendar file imports through the credential's own handle.
use std::sync::Arc;

use oneiron::calendar::ingest::door::{
    CalendarIcsImportReceipt, CalendarIcsImportRequest, CalendarInstanceMoveRequest,
    import_ics_as_owner, move_instance_as_owner,
};
use oneiron::EdgeActorClass;

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
    credential_listing(server, auth, (actor, EdgeActorClass::Human), VERB, move |_, _, memory| {
        import_ics_as_owner(&memory, &owner, &input)
    }).await
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
    credential_listing(server, auth, (actor, EdgeActorClass::Human), VERB, move |_, _, memory| {
        move_instance_as_owner(&memory, &owner, &input)
    }).await
}
