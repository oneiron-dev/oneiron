//! The credential-bound host projection of the typed per-model code-run heal
//! count door (DOOR-093). HTTP, SDK, MCP and code mode all take the owner's
//! proof here, through the gate `door_admits` runs before any hook; the
//! engine door revalidates it before the model id is read. The tally is a
//! model-keyed side row with no entity, so the credential's collector lists
//! every row its reads touched beside it (`host_door_lists`): a complete
//! list, empty when the read named no entity row.
use std::sync::Arc;

use oneiron::memory::code_run_doors::{CodeRunModelHealCountRequest, CodeRunModelHealCountView};

use super::host_doors::{Listed, credential_listing, owner_proof, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// The CALL behind the door's public spelling (DOOR-093): a count read
/// beside the other code doors, never named a correction receipt.
const MODEL_HEAL_COUNT_VERB: &str = "vault.code.model_heal_count";

pub(crate) async fn vault_code_model_heal_count(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeRunModelHealCountRequest,
) -> Listed<CodeRunModelHealCountView> {
    let owner = match owner_proof(auth, server, MODEL_HEAL_COUNT_VERB) {
        Ok(owner) => owner,
        Err(refusal) => return refused(refusal),
    };
    let caller = match super::facade_actor(server, auth) {
        Ok(caller) => caller,
        Err(error) => return refused(error.into_memory_error()),
    };
    credential_listing(
        server,
        auth,
        caller,
        MODEL_HEAL_COUNT_VERB,
        move |_, _, memory| memory.code_run_model_heal_count_as(&owner, input),
    )
    .await
}
