//! A room write a session-bound code run stages, at this connector's door
//! (WILL L11-01, S01-2a).
//!
//! It meets the door as the run's session reads do: the verb's own binding,
//! then the session `execute_code` was admitted on, live now, and the row's
//! own grant (`mcp_host_verb_gate`): an off-record room write has no
//! Proposed lifecycle, so it needs Write over the whole record scope. Then
//! that credential's lane from where its caller sits, which opens the room's
//! view the write resolves in. The same credential and its Write are checked
//! again in the write's own transaction. Nothing here asks where the caller
//! or the vault runs.

use std::sync::Arc;

use oneiron::code_run::{AgentVerbRefusal, SessionWriteAdmission, SessionWriteCeiling};
use oneiron::task_verb::sdk::AgentVerb;

use super::super::McpGatewayError;
use super::super::actor_dispatch::{mcp_host_verb_gate, mcp_proof_error};
use super::super::admission::mcp_admit_host_verb;
use super::McpCodeModeVerbs;
use crate::auth::{CoreAuth, CoreScope};
use crate::server::SyncServer;

/// [`McpCodeModeVerbs`]'s admission of one room write: the bound-tool,
/// session and Write checks of its row, then the credential's lane and its
/// live ceiling.
pub(super) fn admit(
    verbs: &McpCodeModeVerbs,
    verb: AgentVerb,
) -> Result<SessionWriteAdmission, AgentVerbRefusal> {
    let refused = |error: McpGatewayError| AgentVerbRefusal {
        code: error.kind.to_owned(),
    };
    mcp_admit_host_verb(&verbs.actor, verb)
        .and_then(|()| mcp_host_verb_gate(&verbs.server, &verbs.actor, verb))
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
/// `execute_code` was admitted on, live in the write's own transaction and
/// holding Write over the whole record scope there.
struct LiveConnector {
    server: Arc<SyncServer>,
    caller: CoreAuth,
}

impl SessionWriteCeiling for LiveConnector {
    fn holds_in(&self, txn: &heed::RwTxn<'_>) -> Result<(), AgentVerbRefusal> {
        if self
            .caller
            .credential_is_live_in_write_txn(self.server.vault(), txn)
            && self.caller.require(CoreScope::Write).is_ok()
        {
            return Ok(());
        }
        Err(AgentVerbRefusal {
            code: mcp_proof_error().kind.to_owned(),
        })
    }
}
