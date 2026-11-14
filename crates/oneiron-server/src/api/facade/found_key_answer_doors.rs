//! The host doors of the two answers to a found key that the person who
//! wrote its value may give, as the owner may (Engine RULING 08:35 C, 14
//! Nov; L6-03-WRITER-MARK-MANAGED-MEMBER): `vault.secrets.found.not_a_secret`
//! and `vault.secrets.found.keep_as_text`. `host_doors` re-exports them, so
//! the generated HTTP facade handler and the MCP dispatcher call each by the
//! name every host door has.
//!
//! Each takes a live person's own proof (`shared_act_doors::person`): the
//! owner's, a person's own on their verified human slip, or a managed
//! member's on the person action his supervisor signed for the request
//! (`auth::MANAGED_PERSON_DOORS`). An agent is refused there. Each runs the
//! engine door its `/v1/owner/secrets/found/*` route runs, with the surface
//! the call itself carried (`host_door_surface`), and the engine admits only
//! the owner or the key's recorded writer, in its own transaction. The
//! answer lives in the found-key side table and the authority log, which
//! hold no row, so each door lists none, as `vault.secrets.revoke` does.

use std::sync::Arc;

use oneiron::authority::ActSurface;
use oneiron::task_verb::sdk::{
    FoundKeyAnswerRequest, FoundKeySettledReply, keep_found_key_as_text_as,
    rule_found_key_not_a_secret_as,
};

use super::host_doors::support::MaybeListed;
use super::shared_act_doors::{as_person_naming, person};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.secrets.found.not_a_secret`: the owner, or the key's writer,
/// rules the key no secret.
pub(crate) async fn vault_secrets_found_not_a_secret(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    surface: ActSurface,
    input: FoundKeyAnswerRequest,
) -> MaybeListed<FoundKeySettledReply> {
    const VERB: &str = "vault.secrets.found.not_a_secret";
    as_person_naming(
        server,
        VERB,
        person(server, auth, VERB),
        move |server, person| {
            rule_found_key_not_a_secret_as(server.vault(), &person, surface, input)
        },
        |_| Some(Vec::new()),
    )
    .await
}

/// `vault.secrets.found.keep_as_text`: the owner, or the key's writer,
/// keeps the value as text.
pub(crate) async fn vault_secrets_found_keep_as_text(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    surface: ActSurface,
    input: FoundKeyAnswerRequest,
) -> MaybeListed<FoundKeySettledReply> {
    const VERB: &str = "vault.secrets.found.keep_as_text";
    as_person_naming(
        server,
        VERB,
        person(server, auth, VERB),
        move |server, person| keep_found_key_as_text_as(server.vault(), &person, surface, input),
        |_| Some(Vec::new()),
    )
    .await
}
