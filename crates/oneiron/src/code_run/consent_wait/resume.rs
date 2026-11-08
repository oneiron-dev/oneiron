//! The MCP caller a code run parked on a code consent wait was admitted for,
//! kept with the wait, and the parked runs a host may enter again for that
//! caller after a restart (FIX 4606).
//!
//! A served MCP `execute_code` run that parks on a code consent wait has no
//! parked attempt for a trap to wake. Its host kept what a re-entry needs in
//! memory only, so a restart lost it. Now the host binds the admitted
//! caller's origin on the run, and the held call's mint stamps it into the
//! wait's binding, under the binding digest. The parked step's commit seals
//! it with the wait. Nothing here is authority: the origin names the exact
//! instrument the caller was admitted on and where the caller sat, never a
//! credential, a session's keys or a permit. A host verifies the instrument
//! again before it enters anything, and a host that cannot refuses.
//!
//! [`Vault::parked_code_consent_runs`] lists the runs a host may enter
//! again: a wait with an admitted origin, sealed and not consumed, whose
//! reply was delivered, and a run record still parked on that exact wait at
//! the generation its seal names. Nothing is picked by a prompt, a label or
//! an answer. The task is the run's own caller-task body, which its first
//! entry kept from the admitted request: an MCP run captures no step
//! capsule. A body that is erased or missing authorizes nothing.
//!
//! An automatic re-entry its host refused for good keeps that refusal on the
//! wait, written once ([`Vault::refuse_code_consent_run_resume`]), so no
//! later pass tries it again. The caller's own call still enters the run
//! through its own gates.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::authority::InvocationSlipBinding;
use crate::code_run::{
    CodeRunReplayGeneration, CodeRunReplayRecord, ExecutorStorage, WaitDeliveries, WaitKey,
};
use crate::edge::EdgeActorClass;
use crate::engine_executor::{EngineExecutorError, caller_task_in_txn, parked_wait_now};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::runtime_hooks::verb::{
    VerbAskCredentialRef, VerbAskCredentialSource, VerbAskDoor, VerbAskRefusal,
};

use super::binding::{
    code_consent_wait_rows_in_txn, put_code_consent_wait_in_txn, read_code_consent_wait_in_txn,
};
use super::replay::verify_parked_code_consent;
use super::types::{CodeConsentPrincipal, CodeConsentWaitRow};

/// The hash domain of an origin's digest inside a binding digest.
const CODE_CONSENT_RUN_ORIGIN_DOMAIN: &[u8] = b"oneiron:code-consent-run-origin:v1";

/// The MCP endpoint a run's caller came in by (FIX 4606).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeConsentRunEndpoint {
    /// The primary MCP surface.
    Primary,
    /// The tool-first MCP surface.
    ToolFirst,
}

impl CodeConsentRunEndpoint {
    /// The stable word.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::ToolFirst => "tool_first",
        }
    }
}

/// The machine a caller's connection proved, as the request's binding door
/// verified it: its id and the key it proved (FIX 4606). Every read judges
/// that machine again in its own snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeConsentRunPeer {
    pub machine: EntityId,
    pub key: [u8; 32],
}

/// The admitted MCP caller of a code run, as its host bound it on the run
/// (FIX 4606): the run's handle, the exact instrument and door, and where
/// the caller sat. Only a host binds it, from the request it admitted; no
/// guest value reaches it. It is no authority: a host verifies the
/// instrument again before anything runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeConsentRunOrigin {
    /// The caller's handle onto the run: its MCP `run_ref`.
    pub handle: String,
    /// The exact instrument the caller was admitted on, the door it came in
    /// by and whether it sat on this device. The door is the MCP
    /// registration's STREAM connection and ceiling, or the attested owner's
    /// own STREAM connection.
    pub credential: VerbAskCredentialRef,
    /// The MCP endpoint the call came in by.
    pub endpoint: CodeConsentRunEndpoint,
    /// The machine the caller's connection proved; `None` when none was
    /// proved.
    pub peer: Option<CodeConsentRunPeer>,
    /// The off-record session the request named.
    pub session: Option<EntityId>,
    /// The room the request's room turn named.
    pub room_turn: Option<EntityId>,
    /// Whether the request carried a narrower caller's forwarded holder
    /// proof. That proof is fresh for one request only and is not kept, so
    /// no automatic re-entry is made for such a caller.
    pub forwarded_caller: bool,
}

impl CodeConsentRunOrigin {
    /// BLAKE3 over every field, for the binding digest the wait is sealed
    /// with (FIX 4606).
    pub(super) fn digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        let mut field = |bytes: &[u8]| {
            hasher.update(&(bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
        };
        let optional = |id: Option<EntityId>| id.map_or([0; 17], |id| present(id.as_bytes()));
        field(CODE_CONSENT_RUN_ORIGIN_DOMAIN);
        field(self.handle.as_bytes());
        let instrument = &self.credential.instrument;
        field(&instrument.vault);
        match &instrument.source {
            VerbAskCredentialSource::Slip { slip, fingerprint } => {
                field(b"slip");
                field(slip);
                field(fingerprint);
            }
            VerbAskCredentialSource::AttestedOwner { holder } => {
                field(b"attested_owner");
                field(holder.as_bytes());
            }
        }
        field(&instrument.ceiling);
        match &self.credential.door {
            VerbAskDoor::Facade { room } => {
                field(b"facade");
                field(&optional(*room));
            }
            VerbAskDoor::Mcp {
                connection,
                ceiling,
            } => {
                field(b"mcp");
                field(connection.as_bytes());
                // The saved registration ceiling is a typed record on main
                // (#6407), sealed by its named encoding as binding.rs seals
                // a hook snapshot.
                field(&rmp_serde::to_vec_named(ceiling).unwrap_or_default());
            }
            VerbAskDoor::McpOwner { connection } => {
                field(b"mcp_owner");
                field(connection.as_bytes());
            }
        }
        field(&[u8::from(self.credential.on_device)]);
        field(self.endpoint.as_str().as_bytes());
        field(&optional(self.peer.map(|peer| peer.machine)));
        field(self.peer.as_ref().map_or(&[][..], |peer| &peer.key[..]));
        field(&optional(self.session));
        field(&optional(self.room_turn));
        field(&[u8::from(self.forwarded_caller)]);
        *hasher.finalize().as_bytes()
    }

    /// Whether this origin names the caller the wait's binding keeps: a
    /// slip through its MCP registration, the very instrument the wait kept
    /// beside its witness; or the attested owner on his own STREAM, a human
    /// the wait kept no slip for. Any other pairing names no caller.
    fn names(&self, original: &CodeConsentPrincipal) -> bool {
        let instrument = &self.credential.instrument;
        match (&instrument.source, &self.credential.door) {
            (VerbAskCredentialSource::Slip { .. }, VerbAskDoor::Mcp { .. }) => original
                .credential
                .as_ref()
                .is_some_and(|saved| saved.instrument.as_ref() == Some(instrument)),
            (VerbAskCredentialSource::AttestedOwner { holder }, VerbAskDoor::McpOwner { .. }) => {
                original.credential.is_none()
                    && *holder == original.actor_ref
                    && original.actor_class == EdgeActorClass::Human as u8
            }
            _ => false,
        }
    }
}

/// `bytes` behind a presence byte, for an optional id in a digest.
fn present(bytes: &[u8; 16]) -> [u8; 17] {
    let mut out = [1; 17];
    out[1..].copy_from_slice(bytes);
    out
}

/// Why its host refused a parked run's automatic re-entry for good (FIX
/// 4606): a [`VerbAskRefusal`] code. Written once on the wait's row, apart
/// from its answer, settlement and consumption, and never cleared.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CodeConsentResumeRefusal {
    pub(crate) code: String,
    pub(crate) refused_at_ms: u64,
}

/// One parked run a host may enter again for its original caller (FIX
/// 4606), as the vault's committed rows hold it now.
#[derive(Debug, Clone)]
pub struct CodeConsentParkedRun {
    /// The wait the run is parked on, as its reply was delivered.
    pub key: WaitKey,
    /// The run's replay generation, the one the wait's seal names.
    pub generation: CodeRunReplayGeneration,
    /// The caller the run was admitted for.
    pub origin: CodeConsentRunOrigin,
    /// The signed slip the caller's request was admitted on, as the wait
    /// kept it; `None` for the attested owner, who presents none.
    pub witness: Option<InvocationSlipBinding>,
    /// The run's actor and class, as the wait's binding keeps them.
    pub actor: EntityId,
    pub actor_class: EdgeActorClass,
    /// The task the run carries out, as the run's own caller-task body
    /// keeps it.
    pub task: String,
}

impl Vault {
    /// The runs parked on a code consent wait that a host may enter again
    /// for their original caller (FIX 4606). Each one's wait has an
    /// admitted origin that names the caller its binding keeps, is sealed,
    /// not consumed and carries no refusal of an automatic re-entry, and a
    /// reply was delivered to it. The run's record is parked on that exact
    /// wait, at the generation the seal names, and the seal verifies. The
    /// task is the one the run's first entry kept as its own caller-task
    /// body, from the admitted request's task its host declared the
    /// caller's own; it is read through the run's own held occurrence, so a
    /// run whose body is erased, withheld or missing is not listed. On entry
    /// that task must still be the config marker's, and the host's executor
    /// config and interpreter checks still run: readiness is not authority.
    /// A row or record that does not read lists nothing.
    ///
    /// # Errors
    ///
    /// Storage errors reading the wait rows.
    pub fn parked_code_consent_runs(&self) -> Result<Vec<CodeConsentParkedRun>> {
        let rows = {
            let txn = self.store.env.read_txn()?;
            code_consent_wait_rows_in_txn(self, &txn)?
        };
        let mut parked = Vec::new();
        for row in rows {
            let wait = row.binding.wait_id;
            match parked_run(self, row) {
                Ok(Some(run)) => parked.push(run),
                Ok(None) => {}
                Err(error) => tracing::debug!(
                    wait = %wait.to_hex(),
                    %error,
                    "a parked code run did not read; it is not entered again"
                ),
            }
        }
        Ok(parked)
    }

    /// Records, once, why the host refused to enter the run parked on wait
    /// `wait_id` again for its original caller (FIX 4606), so no later pass
    /// tries it. Only a refusal for good is kept: `CredentialUnavailable`
    /// says the host could not judge the credential now, and writes nothing.
    /// The wait's answer, settlement, delivered reply and consumption stay
    /// as they are, and the caller's own call still enters the run. `true`
    /// when this call wrote the refusal.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn refuse_code_consent_run_resume(
        &self,
        wait_id: EntityId,
        refusal: VerbAskRefusal,
    ) -> Result<bool> {
        if refusal == VerbAskRefusal::CredentialUnavailable {
            return Ok(false);
        }
        self.with_write_txn(|txn| {
            let Some(mut row) = read_code_consent_wait_in_txn(self, txn, wait_id)? else {
                return Ok(false);
            };
            if row.resume_refusal.is_some() || row.consumption.is_some() {
                return Ok(false);
            }
            row.resume_refusal = Some(CodeConsentResumeRefusal {
                code: refusal.code().to_owned(),
                refused_at_ms: super::settle::now_ms(),
            });
            put_code_consent_wait_in_txn(self, txn, &mut row)?;
            Ok(true)
        })
    }
}

/// The parked run `row` binds, when a host may enter it again.
fn parked_run(vault: &Vault, row: CodeConsentWaitRow) -> Result<Option<CodeConsentParkedRun>> {
    let binding = row.binding;
    let (Some(origin), Some(sealed), None, None) = (
        binding.origin,
        row.checkpoint,
        row.consumption,
        row.resume_refusal,
    ) else {
        return Ok(None);
    };
    let Some(actor_class) = EdgeActorClass::try_from_u8(binding.original.actor_class) else {
        return Ok(None);
    };
    if !origin.names(&binding.original) {
        return Ok(None);
    }
    let key = WaitKey {
        run: binding.run_id,
        wait_id: binding.wait_id,
        generation: sealed.wait_generation,
    };
    let Some(record) = vault.get_code_run_replay_record(&key.run)? else {
        return Ok(None);
    };
    let generation = record.generation()?;
    let parked = parked_wait_now(&ExecutorStorage::Canonical(vault), &record)
        .map_err(executor_error)?
        .map(|(parked, _)| parked);
    if parked != Some(key)
        || generation.bridge_call_count != sealed.bridge_call_count
        || generation.step_checkpoint_count != sealed.step_checkpoint_count
        || generation.output_count != sealed.output_count
        || generation.last_state_hash != sealed.last_state_hash
    {
        return Ok(None);
    }
    verify_parked_code_consent(vault, &record, &key)?;
    if WaitDeliveries::canonical(vault).delivery(&key)?.is_none() {
        return Ok(None);
    }
    let Some(task) = parked_run_task(vault, &record)? else {
        return Ok(None);
    };
    Ok(Some(CodeConsentParkedRun {
        key,
        generation,
        origin,
        witness: binding
            .original
            .credential
            .map(|credential| credential.witness),
        actor: binding.original.actor_ref,
        actor_class,
        task,
    }))
}

/// The task `record`'s run carries out, as the run's own caller-task body
/// keeps it (FIX 4606), read in a snapshot of its own under the custody
/// guard. `None` when the run keeps none, or the body is erased, withheld,
/// drifted or does not decode.
fn parked_run_task(vault: &Vault, record: &CodeRunReplayRecord) -> Result<Option<String>> {
    let _custody = vault.store.gate_custody_read_guard()?;
    let txn = vault.store.env.read_txn()?;
    caller_task_in_txn(vault, &txn, record)
}

/// An executor read's error as the engine's own.
fn executor_error(error: EngineExecutorError) -> Error {
    match error {
        EngineExecutorError::Engine(error) => error,
        other => Error::InvalidConfig(other.to_string()),
    }
}
