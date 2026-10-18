//! The credential-bound host projection of the typed per-model code-run heal
//! count door (DOOR-093). HTTP, SDK, MCP and code mode all take the owner's
//! proof here, through the gate `door_admits` runs before any hook; the
//! engine door revalidates it before the model id is read. The tally is a
//! side row with no entity, so the answer lists no row and the facade
//! answers it unlisted.
use std::sync::Arc;

use oneiron::memory::MemoryResult;
use oneiron::memory::code_run_doors::{CodeRunModelHealCountRequest, CodeRunModelHealCountView};

use super::FacadeApiError;
use super::host_doors::{credential_listing, owner_proof};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// The CALL behind the door's public spelling (DOOR-093): a count read
/// beside the other code doors, never named a correction receipt.
const MODEL_HEAL_COUNT_VERB: &str = "vault.code.model_heal_count";

pub(crate) async fn vault_code_model_heal_count(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeRunModelHealCountRequest,
) -> MemoryResult<CodeRunModelHealCountView> {
    let owner = owner_proof(auth, server, MODEL_HEAL_COUNT_VERB)?;
    let caller = super::facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)?;
    credential_listing(
        server,
        auth,
        caller,
        MODEL_HEAL_COUNT_VERB,
        move |_, _, memory| memory.code_run_model_heal_count_as(&owner, input),
    )
    .await
    .0
}
