//! The server's check for a credential caller's call a verb hook's ask
//! stopped (ARCH-0080 §3 Ask, OF-580). Once the ask settles proceed, the hook
//! runner's drain hands the saved call here. The instrument the caller's
//! request was admitted on is verified again against current authority, the
//! caller is rebuilt from it alone, and the call runs through the door it came
//! in by, whose own admission runs again: the facade's generated dispatch, or
//! the MCP registration it named. A task's answer is never the credential;
//! any failure refuses the call, and the engine ends it with one receipt.

use std::sync::{Arc, Weak};

use oneiron::authority::InvocationSlipBinding;
use oneiron::claim::CallerLocality;
use oneiron::memory::MemoryResult;
use oneiron::runtime_hooks::verb::{
    VerbAskCredentialCheck, VerbAskCredentialRef, VerbAskCredentialSource, VerbAskDoor,
    VerbAskDrainPermit, VerbAskRefusal, VerbAskResumed, VerbAskSavedCall,
};
use serde_json::Value;

use crate::api::{FacadeApiError, FacadeCall, McpCallContext, facade_call_verb};
use crate::auth::CoreAuth;
// The kept-instrument check is shared with the code consent host, which runs
// whatever the hook sandbox feature (DOOR-079 1a).
pub(crate) use crate::code_consent_host::ceiling_holds;
use crate::code_consent_host::kept_instrument_auth;
use crate::mcp::McpConnectorActorResolutionError;
use crate::server::SyncServer;

/// The server's credential check for the drain. It holds the server weakly,
/// as the verdict host does, and the runtime its doors' async work runs on:
/// the drain calls it on the hook runner's blocking thread.
pub(crate) struct ServerVerbAskCredentialCheck {
    server: Weak<SyncServer>,
    runtime: tokio::runtime::Handle,
}

impl ServerVerbAskCredentialCheck {
    pub(crate) fn new(server: &Arc<SyncServer>, runtime: tokio::runtime::Handle) -> Self {
        Self {
            server: Arc::downgrade(server),
            runtime,
        }
    }

    /// Runs `call` again through its door, under its credential as it
    /// stands now; the refusal when it does not.
    fn resumed(
        &self,
        call: VerbAskSavedCall,
        drain: VerbAskDrainPermit,
    ) -> Result<MemoryResult<Value>, VerbAskRefusal> {
        let server = self
            .server
            .upgrade()
            .ok_or(VerbAskRefusal::CredentialUnavailable)?;
        match call.reference.door.clone() {
            VerbAskDoor::Facade { room } => {
                let auth = kept_auth(&server, &call, Some(&call.verb))?;
                // The facade binds its writes to the credential's own holder.
                if auth.principal_ref() != Some(call.actor.to_hex().as_str())
                    || auth.actor_class() != Some(call.class.gate_actor_class())
                {
                    return Err(VerbAskRefusal::CredentialChanged);
                }
                let resumed = FacadeCall::resumed(&auth, room, call.invocation, drain);
                let ran = self.runtime.block_on(facade_call_verb(
                    &server,
                    &resumed,
                    &call.verb,
                    Ok(call.args),
                ));
                Ok(ran
                    .map(|output| output.value)
                    .map_err(FacadeApiError::into_memory_error))
            }
            VerbAskDoor::Mcp {
                connection,
                ceiling,
            } => {
                let auth = kept_auth(&server, &call, None)?;
                self.runtime.block_on(McpCallContext::resume_verb_ask(
                    &server,
                    auth,
                    &connection,
                    &ceiling,
                    call,
                    drain,
                ))
            }
        }
    }
}

impl VerbAskCredentialCheck for ServerVerbAskCredentialCheck {
    fn retain_in_txn(
        &self,
        vault: &oneiron::Vault,
        txn: &heed::RoTxn<'_>,
        reference: &VerbAskCredentialRef,
        _witness: &InvocationSlipBinding,
    ) -> bool {
        // A slip live in the ask's own write; the drain verifies the whole
        // instrument again before anything runs.
        match reference.instrument.source {
            VerbAskCredentialSource::Slip => vault
                .capability_slip_id_is_live_in_txn(txn, &reference.instrument.slip)
                .unwrap_or(false),
        }
    }

    fn resume(&self, call: VerbAskSavedCall, drain: VerbAskDrainPermit) -> VerbAskResumed {
        match self.resumed(call, drain) {
            Ok(ran) => VerbAskResumed::Ran(ran),
            Err(refusal) => VerbAskResumed::Refused(refusal),
        }
    }
}

/// The caller's credential as it stands now, rebuilt from the instrument its
/// request was admitted on and nothing else, where the caller sat: the
/// witness verified again in a current snapshot, the same slip in the same
/// vault, and the same authority projected from it. `door` is the facade verb
/// an invitee's slip is admitted at.
fn kept_auth(
    server: &SyncServer,
    call: &VerbAskSavedCall,
    door: Option<&str>,
) -> Result<CoreAuth, VerbAskRefusal> {
    let locality = if call.reference.on_device {
        CallerLocality::OnDevice
    } else {
        CallerLocality::OffDevice
    };
    Ok(kept_instrument_auth(server, &call.reference.instrument, &call.witness, door)?.at(locality))
}

/// Why a connector call's registration no longer stands (OF-580 defaults).
/// One this process does not hold, as after a restart, is unavailable: it is
/// never rebuilt from a saved copy.
pub(crate) const fn adapter_refusal(error: McpConnectorActorResolutionError) -> VerbAskRefusal {
    match error {
        McpConnectorActorResolutionError::UnknownCredential => {
            VerbAskRefusal::CredentialUnavailable
        }
        McpConnectorActorResolutionError::RevokedCredential => VerbAskRefusal::CredentialRevoked,
        McpConnectorActorResolutionError::ExpiredCredential => VerbAskRefusal::CredentialExpired,
        McpConnectorActorResolutionError::MissingActorCeiling => VerbAskRefusal::ScopeRefused,
    }
}
