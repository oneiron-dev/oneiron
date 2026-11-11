//! The admitted caller an MCP `execute_code` run is bound for (FIX 4606).
//!
//! Each entry of a run binds its caller's origin on the run, read from the
//! request the gateway admitted and nothing else: the run's handle, the
//! exact instrument the caller's credential was admitted on, the door it
//! came in by, and where the caller sat. A code consent wait the run mints
//! keeps it under the wait's binding digest, so the wait's seal binds the
//! caller a later re-entry is made for. The origin keeps no credential, no
//! verified auth, no drain permit and no whole call context: it names the
//! caller, and a re-entry verifies the instrument again before anything
//! runs. A caller it cannot name gets no origin, and its parked run waits
//! for its own next call.

use oneiron::authority::PeerMachine;
use oneiron::claim::CallerLocality;
use oneiron::code_run::{CodeConsentRunEndpoint, CodeConsentRunOrigin, CodeConsentRunPeer};
use oneiron::runtime_hooks::verb::{VerbAskCredentialRef, VerbAskDoor};

use super::super::McpCallContext;
use crate::mcp::McpSurfaceMode;
use crate::server::SyncServer;

/// The origin `caller`'s entry of the run `run_ref` names binds on the run
/// (FIX 4606). The door is the registration's STREAM connection and the
/// ceiling the call was admitted at, as a verb hook's ask names it; for a
/// managed vault's attested owner it is his own STREAM connection, which no
/// registration stands behind. `None` for a caller with no verified auth,
/// one whose auth keeps no instrument (a slip its request kept no
/// fingerprint for, or the owner while the vault's authority id does not
/// read), and a session reference that names no entity: nothing stands in
/// for what is missing.
pub(in crate::api::mcp_gateway) fn mcp_code_consent_origin(
    server: &SyncServer,
    caller: &McpCallContext,
    run_ref: &str,
) -> Option<CodeConsentRunOrigin> {
    let auth = caller.auth.as_ref()?;
    let instrument = crate::api::scoped_auth::verb_ask_instrument(&server.vault, auth)?;
    let connection = caller.stream_connection.0.clone();
    let door = match crate::api::scoped_auth::attested_owner_holder(auth) {
        Some(_) => VerbAskDoor::McpOwner { connection },
        None => VerbAskDoor::Mcp {
            connection,
            ceiling: super::super::verb_hooks::mcp_adapter_ceiling(caller),
        },
    };
    let session = match caller.off_record_session.as_deref() {
        Some(session) => Some(oneiron::EntityId::from_hex(session).ok()?),
        None => None,
    };
    let peer = match auth.peer() {
        PeerMachine::Proven { machine, key } => Some(CodeConsentRunPeer { machine, key }),
        PeerMachine::Unknown => None,
    };
    Some(CodeConsentRunOrigin {
        handle: run_ref.to_owned(),
        credential: VerbAskCredentialRef {
            instrument,
            door,
            on_device: caller.locality() == CallerLocality::OnDevice,
        },
        endpoint: match caller.mode {
            McpSurfaceMode::Primary => CodeConsentRunEndpoint::Primary,
            McpSurfaceMode::ToolFirst => CodeConsentRunEndpoint::ToolFirst,
        },
        peer,
        session,
        room_turn: caller.room_turn,
        forwarded_caller: caller.forwarded.is_some(),
    })
}
