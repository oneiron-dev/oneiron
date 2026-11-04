//! The owner's code-result secret lift list and proposal-only dismissal.

use std::sync::Arc;

use oneiron::code_run::{CodeRunSecretLiftRequest, CodeRunSecretLiftStatus};
use oneiron::memory::MemoryError;

use super::host_doors::support::{Listed, internal, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

const VERB: &str = "vault.secrets.code_run_lifts";

/// The host preflight checks owner proof before hooks; this door obtains
/// the proof again and the engine rechecks it in the deciding transaction.
/// A proposal names no entity row and contains no secret value.
pub(crate) async fn vault_secrets_code_run_lifts(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeRunSecretLiftRequest,
) -> Listed<CodeRunSecretLiftStatus> {
    let owner = match super::owner_binding::facade_owner(server, auth, VERB) {
        Ok(owner) => owner,
        Err(refusal) => return refused(refusal),
    };
    let server = Arc::clone(server);
    let answer = super::clock_ingress::run_blocking(move || {
        server
            .vault()
            .code_run_secret_lifts_as_owner(&owner, &input)
            .map_err(MemoryError::from)
    })
    .await
    .unwrap_or_else(|_| Err(internal(VERB)));
    (answer, Vec::new())
}
