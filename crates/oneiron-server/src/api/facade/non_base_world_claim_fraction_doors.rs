//! Typed doors over the owner's non-base world claim fraction (ARCH-0004
//! #world-scope; FIX WORLD-SHARE-FRACTION-NO-OWNER-DOOR): the most of a
//! context pack's claims that worlds other than base may hold. The set is the
//! owner's, under the owner's proof, and a change records the owner's act with
//! where it was said (the surface the call itself carried, through
//! `host_door_surface`). The read answers the owner under the owner's proof,
//! or a person or agent on a verified slip of its own that holds any
//! `engine.controls` class, which the engine checks at the read (untangle
//! 6.6f; S66F-READ = C).
use std::sync::Arc;

use oneiron::authority::ActSurface;
use oneiron::settings::non_base_world_claim_fraction::{
    NonBaseWorldClaimFraction, non_base_world_claim_fraction_as_holder,
};
use oneiron::task_verb::sdk::EmptyRequest;

use super::host_doors::support::Listed;
use super::legal_hold_doors::as_owner_naming;
use super::substrate_read_doors::{as_reader, substrate_reader};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_settings_non_base_world_claim_fraction(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<NonBaseWorldClaimFraction> {
    const VERB: &str = "vault.settings.non_base_world_claim_fraction";
    match substrate_reader(server, auth, VERB) {
        Ok(Some(_)) => {
            as_owner_naming(
                server,
                auth,
                VERB,
                |server, owner| {
                    Ok(server
                        .vault()
                        .non_base_world_claim_fraction_as_owner(owner)?)
                },
                |_| Vec::new(),
            )
            .await
        }
        Ok(None) => {
            let answer = as_reader(server, auth, VERB, |server, reader| {
                non_base_world_claim_fraction_as_holder(server.vault(), reader)
            })
            .await;
            (answer, Vec::new())
        }
        Err(refusal) => (Err(refusal), Vec::new()),
    }
}

pub(crate) async fn vault_settings_non_base_world_claim_fraction_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    surface: ActSurface,
    input: NonBaseWorldClaimFraction,
) -> Listed<NonBaseWorldClaimFraction> {
    as_owner_naming(
        server,
        auth,
        "vault.settings.non_base_world_claim_fraction.set",
        move |server, owner| {
            Ok(server
                .vault()
                .set_non_base_world_claim_fraction(owner, Some(surface), input)?)
        },
        |_| Vec::new(),
    )
    .await
}
