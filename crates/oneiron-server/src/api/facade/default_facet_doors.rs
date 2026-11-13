//! Typed doors over the vault default facet (ARCH-0022 #facets: "Every vault
//! has one default facet ... the owner may set another"): the FACET a write
//! with no active mask is born under. The set is the owner's, under the
//! owner's proof, to a stored FACET, and a change records the owner's act
//! with where it was said (the surface the call itself carried, through
//! `host_door_surface`). The read answers the owner under the owner's proof,
//! or a person or agent on a verified slip of its own that holds any
//! `engine.controls` class, which the engine checks at the read (untangle
//! 6.6f; S66F-READ = C).
use std::sync::Arc;

use oneiron::authority::ActSurface;
use oneiron::settings::default_facet::{DefaultFacet, default_facet_as_holder};
use oneiron::task_verb::sdk::EmptyRequest;

use super::host_doors::support::Listed;
use super::legal_hold_doors::as_owner_naming;
use super::substrate_read_doors::{as_reader, substrate_reader};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_settings_default_facet(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<DefaultFacet> {
    const VERB: &str = "vault.settings.default_facet";
    match substrate_reader(server, auth, VERB) {
        Ok(Some(_)) => {
            as_owner_naming(
                server,
                auth,
                VERB,
                |server, owner| Ok(server.vault().default_facet_as_owner(owner)?),
                |_| Vec::new(),
            )
            .await
        }
        Ok(None) => {
            let answer = as_reader(server, auth, VERB, |server, reader| {
                default_facet_as_holder(server.vault(), reader)
            })
            .await;
            (answer, Vec::new())
        }
        Err(refusal) => (Err(refusal), Vec::new()),
    }
}

pub(crate) async fn vault_settings_default_facet_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    surface: ActSurface,
    input: DefaultFacet,
) -> Listed<DefaultFacet> {
    as_owner_naming(
        server,
        auth,
        "vault.settings.default_facet.set",
        move |server, owner| {
            Ok(server
                .vault()
                .set_default_facet_as_owner(owner, Some(surface), input)?)
        },
        |_| Vec::new(),
    )
    .await
}
