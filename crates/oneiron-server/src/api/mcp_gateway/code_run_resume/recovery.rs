//! A served MCP `execute_code` run a restart left parked on a code consent
//! wait, entered again for its original caller (FIX 4606).
//!
//! The registry of parked runs is memory, and so is the MCP actor registry,
//! so a restart forgets both. The wait kept what a re-entry needs: the
//! admitted caller's origin, sealed with the wait, the slip witness its
//! request was admitted on, and the run's own caller-task body. Each settler
//! pass lists the parked runs whose reply was delivered
//! ([`oneiron::Vault::parked_code_consent_runs`]) and builds each one's
//! continuation again from these alone: never from a renewed slip, the
//! answerer's credential or the owner.
//!
//! The caller is the same instrument, verified again now, placed where it
//! sat and toward the machine its connection proved. A live paired slip
//! resolves its registration again as its own next call would, so the
//! registry records it again if a restart lost it, and it must name the
//! same STREAM connection, the same registration ceiling and the same run.
//! The attested owner must still be this vault's live owner, on his own
//! STREAM. The saved ceiling is evidence, never registration authority: a
//! custom registration a restart lost is not made again from it, and its
//! run stays parked, its caller unavailable. A caller whose forwarded
//! holder proof was fresh for one request is not built again.
//!
//! A refusal for good is kept on the wait once, so no later pass tries it
//! again; the caller's own next call still enters the run through its own
//! gates. A credential the host could not judge now, a store error, a
//! freeze or a permit wait writes nothing, and a later pass tries again. An
//! automatic re-entry that ran and failed is not made again for its wait in
//! this process, so a failing run is not run and spent again on every pass.

use std::collections::HashSet;
use std::sync::{Arc, MutexGuard, PoisonError};

use oneiron::authority::{InvocationSlipBinding, PeerMachine};
use oneiron::claim::CallerLocality;
use oneiron::code_run::{
    CodeConsentParkedRun, CodeConsentRunEndpoint, CodeRunReplayGeneration, WaitKey,
};
use oneiron::runtime_hooks::verb::{VerbAskDoor, VerbAskMcpCeiling, VerbAskRefusal};

use super::super::McpCallContext;
use super::super::actor_dispatch::{
    RegistryRefusal, admitted_context, mcp_execute_code_gate, registry_actor_reading_ceiling,
};
use super::super::owner_call::owner_code_run_context;
use super::super::verb_hooks::mcp_adapter_ceiling;
use super::{
    McpCodeRunContinuation, McpCodeRunContinuations, McpCodeRunSlot, precedes, reenter_if_ready,
};
use crate::auth::CoreAuth;
use crate::mcp::{McpConnectorActorResolutionError, McpSurfaceMode};
use crate::server::SyncServer;

/// Enters again, for its original caller, each run a restart left parked
/// whose wait's reply was delivered (FIX 4606), on the settler's blocking
/// worker inside its admitted pass, after the runs this process registered.
/// A run an entry holds, or whose slot already registers its wait or a
/// newer state of it, is left to that.
pub(super) fn reenter_recovered_mcp_code_runs(server: &Arc<SyncServer>) {
    let parked = match server.vault.parked_code_consent_runs() {
        Ok(parked) => parked,
        Err(error) => {
            tracing::warn!(
                %error,
                "the parked MCP code runs did not read; a later pass lists them again"
            );
            return;
        }
    };
    let continuations = &server.mcp_code_run_continuations;
    for run in parked {
        if !continuations.admits_recovered(&run.key, &run.generation) {
            continue;
        }
        let key = run.key;
        match McpCodeRunContinuation::from_durable(server, run) {
            Ok(continuation) => {
                if continuations.register_recovered(&continuation) {
                    reenter_if_ready(server, continuation);
                }
            }
            Err(refusal) => refuse_recovered(server, &key, refusal),
        }
    }
}

impl McpCodeRunContinuations {
    /// Whether a run recovered from wait `key` at `generation` may take its
    /// slot: no automatic re-entry for that wait ran and failed in this
    /// process, and the slot leaves the run to it ([`vacant`]).
    fn admits_recovered(&self, key: &WaitKey, generation: &CodeRunReplayGeneration) -> bool {
        let failed = self.failed_waits().contains(key);
        !failed
            && self
                .slots()
                .get(&key.run)
                .is_none_or(|slot| vacant(slot, key, generation))
    }

    /// Registers `continuation`, a run recovered from its wait, while its
    /// slot still admits it. `true` when this call registered it.
    fn register_recovered(&self, continuation: &McpCodeRunContinuation) -> bool {
        let mut slots = self.slots();
        if self.failed_waits().contains(&continuation.wait) {
            return false;
        }
        let slot = slots.entry(continuation.wait.run).or_default();
        if !vacant(slot, &continuation.wait, &continuation.generation) {
            return false;
        }
        slot.generation = Some(continuation.generation);
        slot.continuation = Some(continuation.clone());
        true
    }

    /// Keeps `wait`, whose automatic re-entry ran and failed, from another
    /// recovered re-entry in this process (FIX 4606).
    pub(super) fn fail(&self, wait: WaitKey) {
        self.failed_waits().insert(wait);
    }

    fn failed_waits(&self) -> MutexGuard<'_, HashSet<WaitKey>> {
        self.failed.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Whether `slot` leaves its run to a continuation recovered from wait
/// `key` at `generation`: no entry of the run is under way, and the slot
/// registers neither that wait at that generation nor a newer state of the
/// run.
fn vacant(slot: &McpCodeRunSlot, key: &WaitKey, generation: &CodeRunReplayGeneration) -> bool {
    slot.entries == 0
        && !slot
            .continuation
            .as_ref()
            .is_some_and(|held| held.wait == *key && held.generation == *generation)
        && !slot
            .generation
            .is_some_and(|newest| precedes(generation, &newest))
}

/// Where a run's caller sat, as its origin keeps it.
struct CallerPlacement {
    mode: McpSurfaceMode,
    request_id: String,
    session: Option<oneiron::EntityId>,
    room_turn: Option<oneiron::EntityId>,
}

impl McpCodeRunContinuation {
    /// The continuation of `run`, a parked run a restart left, built again
    /// for its original caller from its wait alone (FIX 4606). The caller's
    /// fresh auth comes from the very instrument the wait kept
    /// ([`crate::code_consent_host::kept_instrument_auth`]), placed where it
    /// sat and toward the machine its connection proved. Its door is then
    /// built again, must name the same run, and `execute_code`'s own gate
    /// must admit it. Blocking: it locks the MCP actor registry, so call it
    /// on a blocking worker.
    ///
    /// # Errors
    ///
    /// The [`VerbAskRefusal`] the caller meets now. A forwarded caller's
    /// door is unavailable; `CredentialUnavailable` says the host could not
    /// judge the caller now.
    fn from_durable(
        server: &Arc<SyncServer>,
        run: CodeConsentParkedRun,
    ) -> Result<Self, VerbAskRefusal> {
        let origin = &run.origin;
        // A narrower caller's forwarded holder proof was fresh for its one
        // request, and is not kept.
        if origin.forwarded_caller {
            return Err(VerbAskRefusal::ContextUnavailable);
        }
        let reference = &origin.credential;
        let locality = if reference.on_device {
            CallerLocality::OnDevice
        } else {
            CallerLocality::OffDevice
        };
        let peer = origin
            .peer
            .map_or(PeerMachine::Unknown, |peer| PeerMachine::Proven {
                machine: peer.machine,
                key: peer.key,
            });
        let auth = crate::code_consent_host::kept_instrument_auth(
            server,
            &reference.instrument,
            run.witness.as_ref(),
            None,
        )?
        .at(locality)
        .toward(peer);
        let placement = CallerPlacement {
            mode: match origin.endpoint {
                CodeConsentRunEndpoint::Primary => McpSurfaceMode::Primary,
                CodeConsentRunEndpoint::ToolFirst => McpSurfaceMode::ToolFirst,
            },
            request_id: format!("code-consent-resume-{}", run.key.wait_id.to_hex()),
            session: origin.session,
            room_turn: origin.room_turn,
        };
        let (caller, registration) = match &reference.door {
            VerbAskDoor::Mcp {
                connection,
                ceiling,
            } => {
                let witness = run
                    .witness
                    .as_ref()
                    .ok_or(VerbAskRefusal::CredentialMissing)?;
                let caller = paired_caller(server, auth, witness, connection, ceiling, &placement)?;
                if caller.actor_ref != run.actor || caller.actor_class != run.actor_class {
                    return Err(VerbAskRefusal::CredentialChanged);
                }
                (caller, Some(ceiling.clone()))
            }
            VerbAskDoor::McpOwner { connection } => {
                (owner_caller(server, auth, connection, &placement)?, None)
            }
            // A facade's door is no MCP caller's.
            VerbAskDoor::Facade { .. } => return Err(VerbAskRefusal::ContextUnavailable),
        };
        if crate::mcp::mcp_code_run_id(&origin.handle, &caller) != run.key.run {
            return Err(VerbAskRefusal::ContextUnavailable);
        }
        // The gate folds a credential the store could not read into a
        // refusal. A refused gate is judged again here: only a credential
        // read as dead, or a scope the live credential does not hold,
        // refuses for good (FIX 4606).
        mcp_execute_code_gate(server, &caller).map_err(|_| {
            credential_liveness(server, &caller)
                .err()
                .unwrap_or(VerbAskRefusal::ScopeRefused)
        })?;
        Ok(Self {
            run_ref: origin.handle.clone(),
            task: run.task,
            wait: run.key,
            generation: run.generation,
            caller,
            instrument: Some(reference.instrument.clone()),
            witness: run.witness,
            registration,
        })
    }
}

/// Whether the rebuilt `caller`'s credential reads live now, with a store
/// read that fails kept apart from a dead credential (FIX 4606): the first
/// is unavailable and a later pass tries again, the second is revoked. The
/// attested owner's standing is read again as his context reads it.
fn credential_liveness(server: &SyncServer, caller: &McpCallContext) -> Result<(), VerbAskRefusal> {
    let Some(auth) = caller.auth.as_ref() else {
        return Err(VerbAskRefusal::CredentialMissing);
    };
    if let Some(owner) = auth.managed_owner() {
        return crate::code_consent_host::attested_owner_standing(server, owner).map(|_| ());
    }
    let Some(verified) = auth.verified_slip() else {
        return Ok(());
    };
    match server.vault.capability_slip_is_live(verified) {
        Ok(true) => Ok(()),
        Ok(false) => Err(VerbAskRefusal::CredentialRevoked),
        Err(_) => Err(VerbAskRefusal::CredentialUnavailable),
    }
}

/// A paired slip's call through its MCP registration, built again under
/// `auth`, its kept instrument verified again now (FIX 4606). The
/// registration is the one its witness's own credential resolves now,
/// recorded again by the same rule as its own next call if the registry
/// lost it, never a saved copy. It must sit on the same STREAM
/// `connection` and carry the `ceiling` the call was admitted at: a changed
/// ceiling is refused, never narrowed or widened.
fn paired_caller(
    server: &Arc<SyncServer>,
    auth: CoreAuth,
    witness: &InvocationSlipBinding,
    connection: &str,
    ceiling: &VerbAskMcpCeiling,
    placement: &CallerPlacement,
) -> Result<McpCallContext, VerbAskRefusal> {
    let credential = witness
        .credential_token()
        .map_err(|_| VerbAskRefusal::CredentialMissing)?;
    let now = server
        .vault
        .capability_slip_now()
        .map_err(|_| VerbAskRefusal::CredentialUnavailable)?;
    let mut registry = server.mcp_registry.blocking_lock();
    let resolved = registry_actor_reading_ceiling(&mut registry, server, &credential, &auth, now);
    drop(registry);
    let actor = resolved.map_err(registration_refusal)?;
    if actor.stream_connection.0 != connection {
        return Err(VerbAskRefusal::ContextUnavailable);
    }
    if ceiling != &mcp_adapter_ceiling(&actor) {
        return Err(VerbAskRefusal::ScopeRefused);
    }
    admitted_context(
        server,
        actor,
        auth,
        placement.mode,
        &placement.request_id,
        placement.session,
        placement.room_turn,
    )
    .map_err(|_| VerbAskRefusal::CredentialChanged)
}

/// The attested owner's own call of the run, built again under `auth`, the
/// owner as he stands now (FIX 4606): on his own STREAM `connection`, while
/// this vault records him as its live owner.
fn owner_caller(
    server: &Arc<SyncServer>,
    auth: CoreAuth,
    connection: &str,
    placement: &CallerPlacement,
) -> Result<McpCallContext, VerbAskRefusal> {
    let owner = auth
        .managed_owner()
        .ok_or(VerbAskRefusal::CredentialChanged)?;
    owner_code_run_context(
        server,
        auth,
        connection,
        placement.mode,
        &placement.request_id,
        placement.session,
        placement.room_turn,
    )
    .ok_or(VerbAskRefusal::CredentialChanged)?
    // His standing changed since it was read: as it reads now.
    .map_err(|_| {
        crate::code_consent_host::attested_owner_standing(server, owner)
            .err()
            .unwrap_or(VerbAskRefusal::CredentialUnavailable)
    })
}

/// Why a caller's registration does not stand now. One this process does
/// not hold, and does not record again from the caller's own slip, as a
/// custom registration a restart lost, is unavailable: it is never made
/// again from a saved copy. A ceiling the store could not read is
/// unavailable too, so a later pass tries again; only a ceiling read as
/// absent refuses the scope for good (FIX 4606).
const fn registration_refusal(refused: RegistryRefusal) -> VerbAskRefusal {
    if refused.ceiling_unread {
        return VerbAskRefusal::CredentialUnavailable;
    }
    match refused.error {
        McpConnectorActorResolutionError::UnknownCredential => {
            VerbAskRefusal::CredentialUnavailable
        }
        McpConnectorActorResolutionError::RevokedCredential => VerbAskRefusal::CredentialRevoked,
        McpConnectorActorResolutionError::ExpiredCredential => VerbAskRefusal::CredentialExpired,
        McpConnectorActorResolutionError::MissingActorCeiling => VerbAskRefusal::ScopeRefused,
    }
}

/// Keeps `refusal` of the automatic re-entry of the run parked on `key` on
/// its wait, once (FIX 4606): no later pass tries it again, and the
/// caller's own next call still enters the run through its own gates. A
/// credential the host could not judge now writes nothing, and a later
/// pass tries again.
fn refuse_recovered(server: &SyncServer, key: &WaitKey, refusal: VerbAskRefusal) {
    let run = key.run.to_hex();
    let code = refusal.code();
    match server
        .vault
        .refuse_code_consent_run_resume(key.wait_id, refusal)
    {
        Ok(true) => tracing::info!(
            %run,
            code,
            "a parked MCP code run is not entered again for its original caller: refused for good"
        ),
        Ok(false) => tracing::debug!(
            %run,
            code,
            "a parked MCP code run is not entered again now; a later pass tries again"
        ),
        Err(error) => tracing::warn!(
            %run,
            %error,
            "a parked MCP code run's refusal was not kept; a later pass tries again"
        ),
    }
}
