//! The server's check for a credential caller's call a verb hook's ask
//! stopped (ARCH-0080 §3 Ask, OF-580). Once the ask settles proceed, the hook
//! runner's drain hands the saved call here. The instrument the caller's
//! request was admitted on is verified again against current authority, the
//! caller is rebuilt from it alone, and the call runs through the door it came
//! in by, whose own admission runs again: the facade's generated dispatch, or
//! the MCP registration it named. A task's answer is never the credential;
//! any failure refuses the call, and the engine ends it with one receipt.
//!
//! A managed vault's attested owner kept no slip (FIX 11063): his caller is
//! built again as the owner the vault records as live now, and his console
//! MCP call runs again on his own owner stream (FIX 5204).
//!
//! A self-hosted root's own call kept its recorded host action, not a signed
//! binding (FIX 4744): the action is proved again and the root this host
//! retains is verified as that same root, in one snapshot, and the call runs
//! as the owner its door's own resolver names.

use std::sync::{Arc, Weak};

use oneiron::ErrorKind;
use oneiron::authority::HostActionIdentity;
use oneiron::claim::CallerLocality;
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MEMORY_CODE_OWNER_BINDING_REQUIRED, MemoryError};
use oneiron::runtime_hooks::verb::{
    VerbAskCredentialCheck, VerbAskCredentialRef, VerbAskCredentialSource,
    VerbAskCredentialWitness, VerbAskDoor, VerbAskDrainPermit, VerbAskInstrument, VerbAskRefusal,
    VerbAskResumed, VerbAskSavedCall,
};

use crate::api::{FacadeApiError, FacadeCall, McpCallContext, facade_call_verb};
use crate::auth::CoreAuth;
// The kept-instrument check is shared with the code consent host, which runs
// whatever the hook sandbox feature (DOOR-079 1a).
pub(crate) use crate::code_consent_host::ceiling_holds;
use crate::code_consent_host::{kept_instrument_auth, standing};
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
    /// stands now; the refusal when it does not. An MCP door lists the rows
    /// its answer was derived from beside it (FIX 1435, FIX 21054).
    fn resumed(
        &self,
        call: VerbAskSavedCall,
        drain: VerbAskDrainPermit,
    ) -> Result<VerbAskResumed, CallerRefusal> {
        let server = self
            .server
            .upgrade()
            .ok_or(VerbAskRefusal::CredentialUnavailable)?;
        match call.reference.door.clone() {
            VerbAskDoor::Facade { room } => {
                let auth = kept_auth(&server, &call, Some(&call.verb))?;
                require_saved_facade_caller(&server, &auth, &call)?;
                let resumed = FacadeCall::resumed(&auth, room, call.invocation, drain);
                let ran = self.runtime.block_on(facade_call_verb(
                    &server,
                    &resumed,
                    &call.verb,
                    Ok(call.args),
                ));
                Ok(VerbAskResumed::Ran(
                    ran.map(|output| output.value)
                        .map_err(FacadeApiError::into_memory_error),
                ))
            }
            VerbAskDoor::Mcp {
                connection,
                ceiling,
            } => {
                let auth = kept_auth(&server, &call, None)?;
                self.runtime
                    .block_on(McpCallContext::resume_verb_ask(
                        &server,
                        auth,
                        &connection,
                        &ceiling,
                        call,
                        drain,
                    ))
                    .map_err(CallerRefusal::from)
            }
            VerbAskDoor::McpOwner { connection } => {
                // Only the attested owner comes back by his own stream.
                if !matches!(
                    call.reference.instrument.source,
                    VerbAskCredentialSource::AttestedOwner { .. }
                ) {
                    return Err(VerbAskRefusal::CredentialChanged.into());
                }
                let auth = kept_auth(&server, &call, None)?;
                self.runtime
                    .block_on(McpCallContext::resume_owner_verb_ask(
                        &server,
                        auth,
                        &connection,
                        call,
                        drain,
                    ))
                    .map_err(CallerRefusal::from)
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
        witness: &VerbAskCredentialWitness,
    ) -> bool {
        if !witness.backs(&reference.instrument.source) {
            return false;
        }
        // A self-hosted root's recorded host action acts under this very
        // root, in this vault, and still holds in the ask's own write (FIX
        // 4744); the drain proves it again and verifies the retained root.
        if let VerbAskCredentialWitness::HostAction(recorded) = witness {
            let instrument = &reference.instrument;
            return instrument
                .slip()
                .is_some_and(|slip| recorded.acts_under(&slip, &instrument.vault))
                && recorded.holds_in(vault, txn).is_ok();
        }
        // A slip live in the ask's own write; the drain verifies the whole
        // instrument again before anything runs. The attested owner keeps
        // only his person: settlement checks his standing then.
        match reference.instrument.source {
            VerbAskCredentialSource::Slip { slip, .. } => vault
                .capability_slip_id_is_live_in_txn(txn, &slip)
                .unwrap_or(false),
            VerbAskCredentialSource::AttestedOwner { .. } => true,
        }
    }

    fn resume(&self, call: VerbAskSavedCall, drain: VerbAskDrainPermit) -> VerbAskResumed {
        match self.resumed(call, drain) {
            Ok(resumed) => resumed,
            Err(CallerRefusal::Credential(refusal)) => VerbAskResumed::Refused(refusal),
            Err(CallerRefusal::HostAction(error)) => VerbAskResumed::Ran(Err(error)),
        }
    }
}

/// Why the drain did not rebuild a saved call's caller: a credential
/// refusal, or a host action's own refusal, which the call ends with as its
/// door answers it (FIX 4744).
enum CallerRefusal {
    Credential(VerbAskRefusal),
    HostAction(MemoryError),
}

impl From<VerbAskRefusal> for CallerRefusal {
    fn from(refusal: VerbAskRefusal) -> Self {
        Self::Credential(refusal)
    }
}

/// The caller's credential as it stands now, rebuilt from the instrument its
/// request was admitted on and nothing else, where the caller sat: the
/// witness verified again in a current snapshot, the same slip in the same
/// vault, and the same authority projected from it. `door` is the facade verb
/// an invitee's slip is admitted at. The attested owner's witness is the
/// person the call was saved for, a human, and he is rebuilt as the vault's
/// live owner now, never from a header or the host. A self-hosted root's
/// recorded host action rebuilds its root ([`kept_host_root_auth`], FIX
/// 4744).
fn kept_auth(
    server: &SyncServer,
    call: &VerbAskSavedCall,
    door: Option<&str>,
) -> Result<CoreAuth, CallerRefusal> {
    let source = &call.reference.instrument.source;
    if !call.witness.backs(source) {
        return Err(VerbAskRefusal::CredentialChanged.into());
    }
    if let VerbAskCredentialSource::AttestedOwner { holder } = source
        && (*holder != call.actor || call.class != oneiron::EdgeActorClass::Human)
    {
        return Err(VerbAskRefusal::CredentialChanged.into());
    }
    let locality = if call.reference.on_device {
        CallerLocality::OnDevice
    } else {
        CallerLocality::OffDevice
    };
    if let VerbAskCredentialWitness::HostAction(recorded) = &call.witness {
        return Ok(kept_host_root_auth(server, call, recorded)?.at(locality));
    }
    let witness = call.witness.slip();
    Ok(kept_instrument_auth(server, &call.reference.instrument, witness, door)?.at(locality))
}

/// A self-hosted root's caller, rebuilt from the host action its call
/// recorded (FIX 4744). The action acts as the owner the call was saved
/// for, a human, under the root slip and vault the reference names. In one
/// snapshot the action is proved again and the root this host retains is
/// verified as that same slip, vault and binding key; the same authority is
/// then projected from that root, under the token fingerprint the request
/// presented. Nothing opens a writer, and nothing mints, renews or
/// bootstraps a root: a host that holds no root issuer, or retains no root
/// for it, cannot establish the credential.
fn kept_host_root_auth(
    server: &SyncServer,
    call: &VerbAskSavedCall,
    recorded: &HostActionIdentity,
) -> Result<CoreAuth, CallerRefusal> {
    let instrument = &call.reference.instrument;
    let VerbAskCredentialSource::Slip { slip, fingerprint } = instrument.source else {
        return Err(VerbAskRefusal::CredentialChanged.into());
    };
    if recorded.owner() != call.actor
        || call.class != oneiron::EdgeActorClass::Human
        || !recorded.acts_under(&slip, &instrument.vault)
    {
        return Err(VerbAskRefusal::CredentialChanged.into());
    }
    let issuer = server
        .host_root_issuer
        .as_deref()
        .ok_or(VerbAskRefusal::CredentialUnavailable)?;
    let verified = server
        .vault
        .verified_recorded_host_root_slip(issuer, recorded)
        .map_err(|error| host_action_refusal(&server.vault, instrument, error))?
        .ok_or(VerbAskRefusal::CredentialUnavailable)?;
    let auth = CoreAuth::from_recorded_host_root(verified, fingerprint, server.vault.as_ref())
        .map_err(|_| VerbAskRefusal::CredentialChanged)?;
    if !ceiling_holds(&instrument.ceiling, &auth.authority_ceiling()) {
        return Err(VerbAskRefusal::ScopeRefused.into());
    }
    Ok(auth)
}

/// Whether the rebuilt `auth` is the caller `call` was saved for, as the
/// facade binds its writes: the credential's own holder; for a self-hosted
/// root's recorded host action, which names no principal, the owner the
/// door's own resolver names now, which must be the saved owner, a human
/// (FIX 4744).
fn require_saved_facade_caller(
    server: &SyncServer,
    auth: &CoreAuth,
    call: &VerbAskSavedCall,
) -> Result<(), CallerRefusal> {
    let holds = match &call.witness {
        VerbAskCredentialWitness::HostAction(_) => {
            match crate::api::host_action::host_action_of(server.vault(), auth) {
                Some(Ok(action)) => {
                    let actor = action.actor();
                    actor.entity_ref() == call.actor && actor.actor_class() == call.class
                }
                Some(Err(error)) => {
                    return Err(host_action_refusal(
                        server.vault(),
                        &call.reference.instrument,
                        error,
                    ));
                }
                None => false,
            }
        }
        _ => {
            auth.principal_ref() == Some(call.actor.to_hex().as_str())
                && auth.actor_class() == Some(call.class.gate_actor_class())
        }
    };
    if holds {
        Ok(())
    } else {
        Err(VerbAskRefusal::CredentialChanged.into())
    }
}

/// How a self-hosted root's host action that no longer stands ends its call
/// (FIX 4744), as far as the current snapshot proves it. A vault no longer
/// self-hosted answers the typed host-action refusal, and a root whose key
/// no longer binds the live owner the owner-binding refusal, each as its
/// door answers it. A root that is no longer this vault's live, full root,
/// or that the root this host retains does not match, ends as its slip's
/// standing ([`root_standing`]). Authority that cannot be judged, or a
/// store that did not read, is unavailable, never a refusal of the
/// credential.
fn host_action_refusal(
    vault: &oneiron::Vault,
    instrument: &VerbAskInstrument,
    error: oneiron::Error,
) -> CallerRefusal {
    match error {
        oneiron::Error::HostActionRequiresSupportGrant => {
            CallerRefusal::HostAction(MemoryError::from(error))
        }
        oneiron::Error::Claim(oneiron::error::ClaimError::ScopedReadOwnerNotLive(refusal)) => {
            if refusal.code == MEMORY_CODE_OWNER_BINDING_REQUIRED {
                CallerRefusal::HostAction(*refusal)
            } else if refusal.code == MEMORY_CODE_FORBIDDEN {
                root_standing(vault, instrument).into()
            } else {
                VerbAskRefusal::CredentialUnavailable.into()
            }
        }
        _ if matches!(
            error.kind(),
            ErrorKind::Storage | ErrorKind::Io | ErrorKind::MapFull
        ) =>
        {
            VerbAskRefusal::CredentialUnavailable.into()
        }
        _ => root_standing(vault, instrument).into(),
    }
}

/// The standing of the root slip `instrument` names ([`standing`]):
/// missing, revoked, expired, else changed, and unavailable when the fold
/// does not read.
fn root_standing(vault: &oneiron::Vault, instrument: &VerbAskInstrument) -> VerbAskRefusal {
    instrument
        .slip()
        .map_or(VerbAskRefusal::CredentialChanged, |slip| {
            standing(vault, &slip)
        })
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
