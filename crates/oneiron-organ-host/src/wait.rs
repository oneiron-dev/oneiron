//! Organ calls that wait for a node, held in the vault (OF-575, owner ruling
//! MESH: "one node is too weak, means another node helps"). A call for an
//! artifact that no node can run now is held beside it with the reason; a
//! redrive runs every held call that a node can now take, and its export
//! files land as proposals waiting for Keep, as if it had run at once.

use oneiron::edit_settle::{OrganWait, OrganWaitView, PendingProposalView};
use oneiron::provenance::made_by::MadeByTrigger;
use oneiron::secret_custody::SecretSight;
use oneiron::{EntityId, Vault, WriteActor};
use oneiron_organ_protocol::{ByteBuf, TypedBody, Value};
use serde::{Deserialize, Serialize};

use crate::error::HostError;
use crate::handlers::AskHandlers;
use crate::landing::propose_organ_outputs;
use crate::route::{OrganRouter, RanOn, Routed};
use crate::spec::{CallClass, LentInput, OrganCall, OrganInput, SightedInput};

/// One organ call whose export files are for an artifact's proposal
/// landing.
#[derive(Debug, Clone)]
pub struct OrganJob {
    pub artifact: EntityId,
    /// The run ref the proposals take; a call that made several files
    /// names them `<run_ref>/<n>`.
    pub run_ref: String,
    pub call: OrganCall,
    pub lent: Vec<LentInput>,
    pub trigger: Option<MadeByTrigger>,
}

/// What became of a submitted job.
#[derive(Debug)]
pub enum Submitted {
    /// It ran; its files wait beside the artifact for Keep.
    Landed {
        proposals: Vec<PendingProposalView>,
        ran_on: RanOn,
    },
    /// No node can run it now: it is held, and says why.
    Waiting(OrganWaitView),
}

/// What one redrive did with one held call.
#[derive(Debug)]
pub struct Redriven {
    pub artifact: EntityId,
    pub run_ref: String,
    pub state: Redrive,
}

#[derive(Debug)]
pub enum Redrive {
    /// It ran; its files wait for Keep and the hold is released.
    Landed(Vec<PendingProposalView>),
    /// Still no node; the reason is on its row.
    Waiting(String),
    /// A node ran it and it failed there, or its landing was refused; the
    /// row keeps the failure until released.
    Failed(String),
}

/// A call as a held row keeps it: the engine stores the bytes, this crate
/// reads them.
#[derive(Debug, Serialize, Deserialize)]
struct HeldCall {
    organ: String,
    verb: String,
    schema: u32,
    args: Value,
    body: Option<TypedBody>,
    /// A version never changes, so a redrive reads the bytes the call named.
    inputs: Vec<HeldInput>,
    class: CallClass,
    deadline_ms: u64,
    grant: String,
    lent: Vec<(String, ByteBuf)>,
}

/// One vault input of a held call.
#[derive(Debug, Serialize, Deserialize)]
struct HeldInput {
    /// The artifact, in hex.
    artifact: String,
    version: u64,
    /// Whether the call was admitted with the owner's sight of it; a redrive
    /// reads it as [`redrive_sight`] says.
    owner: bool,
}

/// The sight a held call's vault input is read under when it is redriven
/// (FIX 6508): the owner's only when the call was admitted with it, else
/// the masked copy's. A granted agent's sight is never kept: its grant and
/// its read receipt are for the one read they were given for.
const fn redrive_sight(admitted_as_owner: bool) -> SecretSight {
    if admitted_as_owner {
        SecretSight::Owner
    } else {
        SecretSight::Masked
    }
}

impl HeldCall {
    fn of(call: &OrganCall, lent: &[LentInput]) -> Self {
        Self {
            organ: call.organ.clone(),
            verb: call.verb.clone(),
            schema: call.schema,
            args: call.args.clone(),
            body: call.body.clone(),
            inputs: call
                .inputs
                .iter()
                .map(|sighted| HeldInput {
                    artifact: sighted.input.artifact.to_hex(),
                    version: sighted.input.version,
                    owner: sighted.sight == SecretSight::Owner,
                })
                .collect(),
            class: call.class,
            deadline_ms: u64::try_from(call.deadline.as_millis()).unwrap_or(u64::MAX),
            grant: call.grant.clone(),
            lent: lent
                .iter()
                .map(|input| (input.media_type.clone(), ByteBuf::from(input.bytes.clone())))
                .collect(),
        }
    }

    fn into_call(self) -> Result<(OrganCall, Vec<LentInput>), String> {
        let inputs = self
            .inputs
            .iter()
            .map(|held| {
                EntityId::from_hex(&held.artifact)
                    .map(|artifact| SightedInput {
                        input: OrganInput {
                            artifact,
                            version: held.version,
                        },
                        sight: redrive_sight(held.owner),
                    })
                    .map_err(|_| "a held call names no artifact".to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let call = OrganCall {
            organ: self.organ,
            verb: self.verb,
            schema: self.schema,
            args: self.args,
            body: self.body,
            inputs,
            class: self.class,
            deadline: std::time::Duration::from_millis(self.deadline_ms),
            grant: self.grant,
        };
        let lent = self
            .lent
            .into_iter()
            .map(|(media_type, bytes)| LentInput {
                media_type,
                bytes: bytes.into_vec(),
            })
            .collect();
        Ok((call, lent))
    }
}

impl OrganRouter {
    /// Runs a job where it can run and lands its files as proposals; with
    /// no node able to now, holds it beside its artifact, saying why.
    ///
    /// # Errors
    /// The call ran and failed, an input could not be read, the vault
    /// refused the landing or the hold (a ref already settled or waiting).
    pub fn submit(
        &self,
        vault: &Vault,
        job: OrganJob,
        actor: WriteActor,
        asks: &AskHandlers<'_>,
    ) -> Result<Submitted, HostError> {
        let OrganJob {
            artifact,
            run_ref,
            call,
            lent,
            trigger,
        } = job;
        let held = oneiron_organ_protocol::to_vec(&HeldCall::of(&call, &lent))
            .map_err(|err| HostError::ReplyInvalid(format!("the call does not encode: {err}")))?;
        match self.call_with(vault, call, lent, asks)? {
            Routed::Done { outcome, ran_on } => {
                let proposals =
                    propose_organ_outputs(vault, &artifact, &outcome, &run_ref, trigger, actor)?;
                Ok(Submitted::Landed { proposals, ran_on })
            }
            Routed::Waiting(wait) => {
                let row = OrganWait {
                    artifact_id: artifact,
                    run_ref,
                    organ: wait.organ,
                    verb: wait.verb,
                    call: held,
                    trigger,
                    held_by: actor,
                    held_at: vault.now_recorded_at(),
                };
                Ok(Submitted::Waiting(
                    vault.hold_organ_wait(&row, &wait.reason)?,
                ))
            }
        }
    }

    /// Tries every held call again. One a node can take now runs, its
    /// files land as proposals made by the actor who asked, and its hold is
    /// released; one no node can take notes why; one that fails keeps its
    /// failure on its row. Run it when a node may have come back (a peer
    /// connected, a tick), from a blocking thread.
    ///
    /// # Errors
    /// The held calls could not be read or a row could not be written.
    pub fn redrive_waiting(
        &self,
        vault: &Vault,
        asks: &AskHandlers<'_>,
    ) -> Result<Vec<Redriven>, HostError> {
        let mut redriven = Vec::new();
        for (wait, _) in vault.waiting_organ_calls()? {
            let artifact = wait.artifact_id;
            let run_ref = wait.run_ref.clone();
            let state = self.redrive_one(vault, wait, asks)?;
            redriven.push(Redriven {
                artifact,
                run_ref,
                state,
            });
        }
        Ok(redriven)
    }

    fn redrive_one(
        &self,
        vault: &Vault,
        wait: OrganWait,
        asks: &AskHandlers<'_>,
    ) -> Result<Redrive, HostError> {
        let artifact = wait.artifact_id;
        let now = vault.now_recorded_at();
        let failed = |detail: String| -> Result<Redrive, HostError> {
            vault.fail_organ_wait(&artifact, &wait.run_ref, &detail, now)?;
            Ok(Redrive::Failed(detail))
        };
        let held = match oneiron_organ_protocol::from_slice::<HeldCall>(&wait.call)
            .map_err(|err| err.to_string())
            .and_then(HeldCall::into_call)
        {
            Ok(held) => held,
            Err(detail) => return failed(format!("the held call does not decode: {detail}")),
        };
        let (call, lent) = held;
        match self.call_with(vault, call, lent, asks) {
            Ok(Routed::Done { outcome, .. }) => match propose_organ_outputs(
                vault,
                &artifact,
                &outcome,
                &wait.run_ref,
                wait.trigger.clone(),
                wait.held_by,
            ) {
                Ok(proposals) => {
                    vault.release_organ_wait(&artifact, &wait.run_ref)?;
                    Ok(Redrive::Landed(proposals))
                }
                Err(err) => failed(format!("the landing refused its files: {err}")),
            },
            Ok(Routed::Waiting(still)) => {
                vault.note_organ_wait(&artifact, &wait.run_ref, &still.reason, now)?;
                Ok(Redrive::Waiting(still.reason))
            }
            Err(err) => failed(err.to_string()),
        }
    }
}
