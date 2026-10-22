//! Profile request answers and mode-A copy edits under the owner's own proof.

use std::sync::Arc;

use oneiron::persona_snapshot::{PersonaSnapshotCopyEditRequest, PersonaSnapshotCopyRequest};
use oneiron::task_verb::sdk::{
    self, CompanionAccessRequestAnswerRequest, CompanionAccessRequestAnswered,
    PersonaSnapshotExportedCopy, PersonaSnapshotPreview, PersonaSnapshotPreviewRequest,
};

use super::host_doors::support::{MaybeListed, owner_proof};
use super::shared_act_doors::as_person_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_companions_access_requests_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CompanionAccessRequestAnswerRequest,
) -> MaybeListed<CompanionAccessRequestAnswered> {
    const VERB: &str = "vault.companions.access_requests.answer";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| sdk::answer_companion_access_request_as(server.vault(), &owner, input),
        |answer| Some(answer.grant_ref.into_iter().collect()),
    )
    .await
}

pub(crate) async fn vault_personas_preview(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: PersonaSnapshotPreviewRequest,
) -> MaybeListed<PersonaSnapshotPreview> {
    const VERB: &str = "vault.personas.preview";
    let destination = auth.destination();
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| {
            sdk::preview_persona_snapshot_as(server.vault(), &owner, input, destination)
        },
        // The compile reads claims as well as its subject. The owner's existing
        // persona surface owns that projection; it is not a one-row listing.
        |_| None,
    )
    .await
}

pub(crate) async fn vault_personas_export(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: PersonaSnapshotCopyRequest,
) -> MaybeListed<PersonaSnapshotExportedCopy> {
    const VERB: &str = "vault.personas.export";
    let destination = auth.destination();
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| {
            sdk::export_persona_snapshot_copy_as(server.vault(), &owner, input, destination)
        },
        |_| None,
    )
    .await
}

pub(crate) async fn vault_personas_edit(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: PersonaSnapshotCopyEditRequest,
) -> MaybeListed<PersonaSnapshotExportedCopy> {
    const VERB: &str = "vault.personas.edit";
    let destination = auth.destination();
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| {
            sdk::edit_persona_snapshot_copy_as(server.vault(), &owner, input, destination)
        },
        |_| None,
    )
    .await
}
