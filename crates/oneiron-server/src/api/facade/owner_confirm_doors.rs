//! The host door of the shared owner-checked preview (DEC-0006 #undo-class):
//! `vault.owner_confirm.preview`. `host_doors` re-exports it, so the
//! generated HTTP facade handler and the MCP dispatcher call it by the name
//! every host door has. The door takes the gated verb's own proof from
//! `OWNER_CONFIRM_ROWS`, so a shared-vault person never previews an
//! owner-only act: an owner-only verb runs under the owner's proof, as
//! `/v1/owner` takes it, and a shared-person verb under the person's own
//! proof, exactly as the record erase preview did. The engine retains the
//! caller's own row; the gated verb admits it.
use std::sync::Arc;

use oneiron::EdgeActorClass;
use oneiron::memory::MemoryError;
use oneiron::task_verb::sdk::{self, OwnerConfirmPreview, OwnerConfirmPreviewRequest};

use super::host_doors::support::{Listed, off_runtime_listing, refused};
use super::legal_hold_doors::as_owner_naming;
use super::shared_act_doors::person;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// The rows a preview answer names: the records the legal-hold lift shows.
/// A record erase previews under the shared-person proof, whose handles
/// list the record itself; every other preview names none.
fn named_rows(preview: &OwnerConfirmPreview) -> Vec<oneiron::EntityId> {
    if preview.verb != "vault.legal_holds.lift_and_erase" {
        return Vec::new();
    }
    preview
        .takes
        .as_ref()
        .and_then(|takes| {
            serde_json::from_value::<oneiron::deletion::LiftAndEraseShownState>(takes.clone()).ok()
        })
        .map(|shown| shown.records)
        .unwrap_or_default()
}

/// `vault.owner_confirm.preview`: the owner's preview of one one-way act.
/// A verb with no row is refused. An owner-only verb previews under the
/// owner's proof; a shared-person verb under the person's own. Beside it,
/// the record for a record erase and the records for a legal-hold lift.
pub(crate) async fn vault_owner_confirm_preview(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OwnerConfirmPreviewRequest,
) -> Listed<OwnerConfirmPreview> {
    const VERB: &str = "vault.owner_confirm.preview";
    let Some(row) = sdk::owner_confirm_row(&input.verb) else {
        let verb = input.verb.as_str();
        return refused(MemoryError::bad_request(format!(
            "{verb} takes no owner confirm"
        )));
    };
    match row.proof {
        sdk::OwnerConfirmProof::Owner => {
            let locality = auth.locality();
            as_owner_naming(
                server,
                auth,
                VERB,
                move |server, owner| {
                    let memory = server
                        .vault()
                        .memory(
                            owner.revalidate_person(server.vault())?,
                            EdgeActorClass::Human,
                        )
                        .at(locality);
                    sdk::preview_owner_confirm(&memory, owner, input)
                },
                named_rows,
            )
            .await
        }
        sdk::OwnerConfirmProof::SharedPerson => {
            let caller = match person(server, auth, VERB) {
                Ok(caller) => caller,
                Err(refusal) => return refused(refusal),
            };
            let server = Arc::clone(server);
            let locality = auth.locality();
            off_runtime_listing(VERB, move |producers| {
                let memory = server
                    .vault()
                    .memory(
                        caller.revalidate_person(server.vault())?,
                        EdgeActorClass::Human,
                    )
                    .at(locality)
                    .listing_producers(producers);
                sdk::preview_owner_confirm(&memory, &caller, input)
            })
            .await
        }
    }
}
