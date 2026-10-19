//! A room write a session-bound code run stages, at this connector's door
//! (WILL L11-01, S01-2a).
//!
//! It meets the door as the run's session reads do: the verb's own binding,
//! then `execute_code`'s credential gate (the credential the run was
//! admitted on, live now, holding what a run commits over the whole record
//! scope), then that credential's lane from where its caller sits, which
//! opens the room's view the write resolves in. The same credential is
//! checked again in the write's own transaction. Nothing here asks where
//! the caller or the vault runs.

use std::sync::Arc;

use oneiron::code_run::{AgentVerbRefusal, SessionWriteAdmission, SessionWriteCeiling};
use oneiron::task_verb::sdk::AgentVerb;

use super::super::McpGatewayError;
use super::super::actor_dispatch::{mcp_execute_code_gate, mcp_proof_error};
use super::super::admission::mcp_admit_host_verb;
use super::McpCodeModeVerbs;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// [`McpCodeModeVerbs`]'s admission of one room write: the bound-tool and
/// `execute_code` checks of its session reads, then the credential's lane
/// and its live ceiling.
pub(super) fn admit(
    verbs: &McpCodeModeVerbs,
    verb: AgentVerb,
) -> Result<SessionWriteAdmission, AgentVerbRefusal> {
    let refused = |error: McpGatewayError| AgentVerbRefusal {
        code: error.kind.to_owned(),
    };
    mcp_admit_host_verb(&verbs.actor, verb)
        .and_then(|()| mcp_execute_code_gate(&verbs.server, &verbs.actor))
        .map_err(refused)?;
    let key = verbs.credential_lane()?;
    let caller = verbs
        .actor
        .auth
        .clone()
        .ok_or_else(|| refused(mcp_proof_error()))?;
    Ok(SessionWriteAdmission::new(
        Some(key),
        Arc::new(LiveConnector {
            server: Arc::clone(&verbs.server),
            caller,
        }),
    ))
}

/// The ceiling a room write of an MCP run lands under: the credential
/// `execute_code` was admitted on, live in the write's own transaction.
struct LiveConnector {
    server: Arc<SyncServer>,
    caller: CoreAuth,
}

impl SessionWriteCeiling for LiveConnector {
    fn holds_in(&self, txn: &heed::RwTxn<'_>) -> Result<(), AgentVerbRefusal> {
        if self
            .caller
            .credential_is_live_in_write_txn(self.server.vault(), txn)
        {
            return Ok(());
        }
        Err(AgentVerbRefusal {
            code: mcp_proof_error().kind.to_owned(),
        })
    }
}
