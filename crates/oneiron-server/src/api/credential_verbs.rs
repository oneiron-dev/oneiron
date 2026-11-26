//! The server's gate of a credential's verb list
//! (AGENT-CREDENTIAL-VERB-ALLOWLIST): a credential the owner minted with a
//! verb list calls every read verb, each verb the list names and each verb
//! a Grant for its holder names, and nothing else, on every transport. Each
//! door that runs a verb for a presented credential asks
//! [`require_listed_verb`] with the verb's verb-table name before its own
//! checks: the facade's one generated dispatch (HTTP, the held socket,
//! action rows, credential resume, skills), the MCP verb table (tools,
//! code-mode programs, resume), the code-mode program door, and each REST
//! route that runs a verb's door itself.

use oneiron::MemoryError;

use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// Admits a call of `verb` for `auth`'s caller. A caller with no verified
/// slip (an owner-grade secret, an attested owner) and a slip with no verb
/// list call every verb, as before.
///
/// # Errors
///
/// `forbidden` for a verb the slip's list leaves out and no Grant of its
/// holder names; a store read failure.
pub(crate) fn require_listed_verb(
    server: &SyncServer,
    auth: Option<&CoreAuth>,
    verb: &str,
) -> Result<(), MemoryError> {
    match auth.and_then(CoreAuth::verified_slip) {
        Some(slip) => server.vault().credential_admits_verb(slip.claims(), verb),
        None => Ok(()),
    }
}

/// [`require_listed_verb`] for one call a code-mode program makes: its
/// refusal as the program reads it, by its code alone.
pub(crate) fn code_mode_listed_verb(
    server: &SyncServer,
    auth: Option<&CoreAuth>,
    verb: &str,
) -> Result<(), oneiron::code_run::AgentVerbRefusal> {
    require_listed_verb(server, auth, verb).map_err(|error| oneiron::code_run::AgentVerbRefusal {
        hook_notice: None,
        code: if error.code == oneiron::memory::MEMORY_CODE_FORBIDDEN {
            "forbidden"
        } else {
            "engine_error"
        }
        .to_owned(),
    })
}

/// [`code_mode_listed_verb`] for a run row a program's bridge call makes,
/// known there by its effect alone: every run row that makes `effect` must
/// be one the credential calls, so a read row that shares its effect with a
/// write row never opens the write.
pub(crate) fn code_mode_listed_effect(
    server: &SyncServer,
    auth: Option<&CoreAuth>,
    effect: oneiron::code_run::SelfEffect,
) -> Result<(), oneiron::code_run::AgentVerbRefusal> {
    oneiron::task_verb::sdk::RunVerb::ALL
        .iter()
        .filter(|verb| verb.effect() == effect)
        .try_for_each(|verb| code_mode_listed_verb(server, auth, verb.as_str()))
}
