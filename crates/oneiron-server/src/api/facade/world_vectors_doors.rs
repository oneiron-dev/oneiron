//! The typed door of `vault.worlds.vectors` (DEC-0005 #private-world-vectors;
//! FIX [WORLD-VECTORS-FACT]): where each world's text vectors are made on this
//! server's install, as its own embedding worker makes them. It answers the
//! owner under the owner's proof, or a person or agent on a verified slip of
//! its own that holds a Steward grant naming `read` that reaches the whole
//! vault, which the engine checks at the read (lead RULING
//! WORLD-VECTORS-INTENT = B). The answer names worlds by ref and reads no
//! row's content, so it lists none.
use std::sync::Arc;

use oneiron::embed::world_vectors::{
    WorldVectorsAnswer, WorldVectorsRequest, read_world_vectors_as_owner,
    read_world_vectors_as_reader,
};

use super::host_doors::support::Listed;
use super::legal_hold_doors::as_owner_naming;
use super::substrate_read_doors::{as_reader, substrate_reader};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.worlds.vectors`: the owner under its proof, or a whole-vault
/// Steward `read` holder.
pub(crate) async fn vault_worlds_vectors(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WorldVectorsRequest,
) -> Listed<WorldVectorsAnswer> {
    const VERB: &str = "vault.worlds.vectors";
    match substrate_reader(server, auth, VERB) {
        Ok(Some(_)) => {
            as_owner_naming(
                server,
                auth,
                VERB,
                move |server, owner| {
                    Ok(read_world_vectors_as_owner(server.vault(), owner, &input)?)
                },
                |_| Vec::new(),
            )
            .await
        }
        Ok(None) => {
            let answer = as_reader(server, auth, VERB, move |server, reader| {
                read_world_vectors_as_reader(server.vault(), reader, &input)
            })
            .await;
            (answer, Vec::new())
        }
        Err(refusal) => (Err(refusal), Vec::new()),
    }
}
