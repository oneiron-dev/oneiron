//! Organ calls that wait for a node, held in the vault (OF-575, owner ruling
//! MESH: "one node is too weak, means another node helps"). A call for an
//! artifact that no node can run now is held beside it with the reason; a
//! redrive runs every held call that a node can now take, and its export
//! files land as proposals waiting for Keep, as if it had run at once.

use std::cell::RefCell;

use oneiron::edit_settle::{OrganWait, OrganWaitRef, OrganWaitView, PendingProposalView};
use oneiron::provenance::made_by::MadeByTrigger;
use oneiron::secret_custody::SecretSight;
use oneiron::{EntityId, Vault, WriteActor};
use oneiron_organ_protocol::codec::{CodecError, EncodeScratch};
use oneiron_organ_protocol::{ByteBuf, TypedBody, Value};
use serde::{Deserialize, Serialize};

use crate::error::HostError;
use crate::handlers::AskHandlers;
use crate::landing::propose_organ_outputs;
use crate::route::{OrganRouter, RanOn, Routed};
use crate::shutdown;
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
    /// The authenticated principal who submitted the job, when one did: its
    /// files' made_by is admitted through that principal's own read when
    /// they land, now or at a redrive (FIX 9310). None for a host's own job.
    pub submitter: Option<EntityId>,
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
    /// The held call stopped being current before dispatch, a node failed,
    /// or its landing was refused. A failed run's row keeps the failure
    /// until released.
    Failed(String),
    /// The host's mesh stop cut it short (FIX 4755): its row stays held, as
    /// it was, for the next start.
    Interrupted,
    /// The host's mesh stop came before it was tried: its row stays held,
    /// as it was.
    Deferred,
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

/// The same held-call shape, borrowing the live job before routing consumes it.
#[derive(Serialize)]
struct HeldCallRef<'a> {
    organ: &'a str,
    verb: &'a str,
    schema: u32,
    args: HeldValue<'a>,
    body: HeldBody<'a>,
    inputs: HeldInputs<'a>,
    class: CallClass,
    deadline_ms: u64,
    grant: &'a str,
    lent: HeldLent<'a>,
}

struct HeldValue<'a> {
    value: &'a Value,
    encoding: &'a RefCell<WaitEncoding>,
}

impl Serialize for HeldValue<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.value
            .serialize_with_scratch(serializer, &mut *self.encoding.borrow_mut())
    }
}

struct HeldBody<'a> {
    body: &'a Option<TypedBody>,
    encoding: &'a RefCell<WaitEncoding>,
}

#[derive(Serialize)]
struct HeldTypedBody<'a> {
    kind: &'a str,
    schema: u32,
    value: HeldValue<'a>,
}

impl Serialize for HeldBody<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.body {
            None => serializer.serialize_none(),
            Some(body) => serializer.serialize_some(&HeldTypedBody {
                kind: &body.kind,
                schema: body.schema,
                value: HeldValue {
                    value: &body.value,
                    encoding: self.encoding,
                },
            }),
        }
    }
}

struct WaitEncoding {
    room: Option<Box<dyn crate::resource_memory::FloorLease>>,
    refused: Option<crate::resource_memory::FloorRefusal>,
}

impl EncodeScratch for WaitEncoding {
    fn grow(&mut self, bytes: u64) -> Result<(), CodecError> {
        if let Some(room) = &mut self.room
            && let Err(refused) = room.grow_untimed(bytes, &shutdown::stopping)
        {
            self.refused = Some(refused);
            return Err(CodecError::Invalid("held-call encoding admission failed"));
        }
        Ok(())
    }

    fn materialized(&mut self, reserved: u64, actual: u64) {
        if let Some(room) = &mut self.room {
            room.materialized(reserved, actual);
        }
    }

    fn shrink(&mut self, bytes: u64) {
        if let Some(room) = &mut self.room {
            room.shrink(bytes);
        }
    }
}

impl WaitEncoding {
    fn error(&mut self, error: CodecError) -> HostError {
        match self.refused.take() {
            Some(crate::resource_memory::FloorRefusal::Floor { needed, available }) => {
                HostError::Io(std::io::Error::new(
                    std::io::ErrorKind::OutOfMemory,
                    format!("held-call encoding needs {needed} bytes, {available} available"),
                ))
            }
            Some(crate::resource_memory::FloorRefusal::Deadline) => HostError::Interrupted,
            None => HostError::ReplyInvalid(format!("the call does not encode: {error}")),
        }
    }
}

#[derive(Serialize)]
struct HeldInputRef<'a> {
    artifact: &'a str,
    version: u64,
    owner: bool,
}

struct HeldInputs<'a>(&'a [SightedInput]);

impl Serialize for HeldInputs<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for sighted in self.0 {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            let mut artifact = [0u8; 32];
            for (source, output) in sighted
                .input
                .artifact
                .as_bytes()
                .iter()
                .zip(artifact.chunks_exact_mut(2))
            {
                output[0] = HEX[(source >> 4) as usize];
                output[1] = HEX[(source & 0x0f) as usize];
            }
            sequence.serialize_element(&HeldInputRef {
                artifact: std::str::from_utf8(&artifact).expect("hex digits are ASCII"),
                version: sighted.input.version,
                owner: sighted.sight == SecretSight::Owner,
            })?;
        }
        sequence.end()
    }
}

struct HeldLent<'a>(&'a [LentInput]);

impl Serialize for HeldLent<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for input in self.0 {
            sequence.serialize_element(&(input.media_type.as_str(), HeldBytes(&input.bytes)))?;
        }
        sequence.end()
    }
}

struct HeldBytes<'a>(&'a [u8]);

impl Serialize for HeldBytes<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.0)
    }
}

impl<'a> HeldCallRef<'a> {
    fn of(call: &'a OrganCall, lent: &'a [LentInput], encoding: &'a RefCell<WaitEncoding>) -> Self {
        Self {
            organ: &call.organ,
            verb: &call.verb,
            schema: call.schema,
            args: HeldValue {
                value: &call.args,
                encoding,
            },
            body: HeldBody {
                body: &call.body,
                encoding,
            },
            inputs: HeldInputs(&call.inputs),
            class: call.class,
            deadline_ms: u64::try_from(call.deadline.as_millis()).unwrap_or(u64::MAX),
            grant: &call.grant,
            lent: HeldLent(lent),
        }
    }
}

impl HeldCall {
    fn allocated_bytes(&self) -> u64 {
        let mut bytes = self.organ.capacity() as u64
            + self.verb.capacity() as u64
            + self.grant.capacity() as u64;
        bytes = bytes.saturating_add(self.args.allocated_bytes());
        if let Some(body) = &self.body {
            bytes = bytes
                .saturating_add(body.kind.capacity() as u64)
                .saturating_add(body.value.allocated_bytes());
        }
        bytes = bytes
            .saturating_add(
                (self.inputs.capacity() as u64)
                    .saturating_mul(std::mem::size_of::<HeldInput>() as u64),
            )
            .saturating_add(
                (self.lent.capacity() as u64)
                    .saturating_mul(std::mem::size_of::<(String, ByteBuf)>() as u64),
            );
        for input in &self.inputs {
            bytes = bytes.saturating_add(input.artifact.capacity() as u64);
        }
        for (media_type, body) in &self.lent {
            bytes = bytes
                .saturating_add(media_type.capacity() as u64)
                .saturating_add(body.capacity() as u64);
        }
        bytes
    }

    fn into_call(self) -> Result<(OrganCall, Vec<LentInput>), String> {
        let mut inputs = Vec::with_capacity(self.inputs.len());
        for held in &self.inputs {
            inputs.push(SightedInput {
                input: OrganInput {
                    artifact: EntityId::from_hex(&held.artifact)
                        .map_err(|_| "a held call names no artifact".to_owned())?,
                    version: held.version,
                },
                sight: redrive_sight(held.owner),
            });
        }
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
        let mut lent = Vec::with_capacity(self.lent.len());
        for (media_type, bytes) in self.lent {
            lent.push(LentInput {
                media_type,
                bytes: bytes.into_vec(),
            });
        }
        Ok((call, lent))
    }
}

struct DecodedWaitCall {
    call: OrganCall,
    lent: Vec<LentInput>,
    _room: Option<Box<dyn crate::resource_memory::FloorLease>>,
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
            submitter,
        } = job;
        let encoding = RefCell::new(WaitEncoding {
            room: self.hold_wait_encoding(0)?,
            refused: None,
        });
        let snapshot = HeldCallRef::of(&call, &lent, &encoding);
        let encoded = oneiron_organ_protocol::encoded_len(&snapshot)
            .map_err(|err| encoding.borrow_mut().error(err))?;
        let capacity = usize::try_from(encoded).map_err(|_| {
            HostError::Io(std::io::Error::new(
                std::io::ErrorKind::OutOfMemory,
                "held-call encoding exceeds addressable memory",
            ))
        })?;
        let admitted = encoding.borrow_mut().grow(encoded);
        admitted.map_err(|err| encoding.borrow_mut().error(err))?;
        let mut held = Vec::with_capacity(capacity);
        encoding
            .borrow_mut()
            .materialized(encoded, held.capacity() as u64);
        oneiron_organ_protocol::codec::write_into(&mut held, &snapshot)
            .map_err(|err| encoding.borrow_mut().error(err))?;
        match self.call_with(vault, call, lent, asks)? {
            Routed::Done { outcome, ran_on } => {
                let proposals = propose_organ_outputs(
                    vault, &artifact, &outcome, &run_ref, trigger, actor, submitter,
                )?;
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
                    submitter,
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
    /// connected, a tick), from a blocking thread. Under a mesh stop
    /// ([`crate::MeshCancel::scope`]) no held call starts once the stop has
    /// begun, and one its cancel cuts short stays held.
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
            let state = if shutdown::stopping() {
                Redrive::Deferred
            } else {
                self.redrive_one(vault, wait, asks)?
            };
            redriven.push(Redriven {
                artifact,
                run_ref,
                state,
            });
        }
        Ok(redriven)
    }

    fn decode_wait_call(
        &self,
        vault: &Vault,
        wait: &OrganWaitRef,
    ) -> Result<Option<DecodedWaitCall>, HostError> {
        let invalid =
            |err| HostError::ReplyInvalid(format!("the held call does not decode: {err}"));
        let Some(decoded) =
            vault.lend_organ_wait_call(wait, oneiron_organ_protocol::codec::decode_cost)?
        else {
            return Ok(None);
        };
        let decoded = decoded.map_err(invalid)?;
        let mut room = self.hold_wait_encoding(decoded)?;
        let Some(held) =
            vault.lend_organ_wait_call(wait, oneiron_organ_protocol::from_slice::<HeldCall>)?
        else {
            return Ok(None);
        };
        let held = held.map_err(invalid)?;
        let before = held.allocated_bytes();
        if let Some(room) = &mut room {
            room.materialized(decoded, before);
        }
        let replaced = (held.inputs.capacity() as u64)
            .saturating_mul(std::mem::size_of::<HeldInput>() as u64)
            .saturating_add(held.inputs.iter().fold(0u64, |bytes, input| {
                bytes.saturating_add(input.artifact.capacity() as u64)
            }))
            .saturating_add(
                (held.lent.capacity() as u64)
                    .saturating_mul(std::mem::size_of::<(String, ByteBuf)>() as u64),
            );
        let extra = (held.inputs.len() as u64)
            .saturating_mul(std::mem::size_of::<SightedInput>() as u64)
            .saturating_add(
                (held.lent.len() as u64).saturating_mul(std::mem::size_of::<LentInput>() as u64),
            );
        if let Some(room) = &mut room {
            room.grow_untimed(extra, &shutdown::stopping)
                .map_err(wait_floor_error)?;
        }
        let (call, lent) = held.into_call().map_err(|err| {
            HostError::ReplyInvalid(format!("the held call does not decode: {err}"))
        })?;
        if let Some(room) = &mut room {
            room.materialized(extra, 0);
            let after = before
                .saturating_sub(replaced)
                .saturating_add(
                    (call.inputs.capacity() as u64)
                        .saturating_mul(std::mem::size_of::<SightedInput>() as u64),
                )
                .saturating_add(
                    (lent.capacity() as u64)
                        .saturating_mul(std::mem::size_of::<LentInput>() as u64),
                );
            if after >= before {
                room.materialized(0, after - before);
            } else {
                room.shrink(before - after);
            }
        }
        Ok(Some(DecodedWaitCall {
            call,
            lent,
            _room: room,
        }))
    }

    fn redrive_one(
        &self,
        vault: &Vault,
        wait: OrganWaitRef,
        asks: &AskHandlers<'_>,
    ) -> Result<Redrive, HostError> {
        if !vault.organ_wait_is_current(&wait)? {
            return Ok(Redrive::Failed(
                "the held call is no longer current".to_owned(),
            ));
        }
        let artifact = wait.artifact_id;
        let now = vault.now_recorded_at();
        let failed = |detail: String| -> Result<Redrive, HostError> {
            vault.fail_organ_wait(&artifact, &wait.run_ref, &detail, now)?;
            Ok(Redrive::Failed(detail))
        };
        let held = match self.decode_wait_call(vault, &wait) {
            Ok(Some(held)) => held,
            Err(HostError::Interrupted) => return Ok(Redrive::Interrupted),
            Err(err) => return failed(err.to_string()),
            Ok(None) => return Ok(Redrive::Failed("the held call is no longer current".into())),
        };
        // Admission may have waited while a delete or release committed.
        if !vault.organ_wait_is_current(&wait)? {
            return Ok(Redrive::Failed("the held call is no longer current".into()));
        }
        let DecodedWaitCall { call, lent, _room } = held;
        match self.call_with(vault, call, lent, asks) {
            Ok(Routed::Done { outcome, .. }) => match propose_organ_outputs(
                vault,
                &artifact,
                &outcome,
                &wait.run_ref,
                wait.trigger.clone(),
                wait.held_by,
                wait.submitter,
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
            Err(HostError::Interrupted) => Ok(Redrive::Interrupted),
            Err(err) => failed(err.to_string()),
        }
    }
}

fn wait_floor_error(refused: crate::resource_memory::FloorRefusal) -> HostError {
    match refused {
        crate::resource_memory::FloorRefusal::Floor { needed, available } => {
            HostError::Io(std::io::Error::new(
                std::io::ErrorKind::OutOfMemory,
                format!("held-call decoding needs {needed} bytes, {available} available"),
            ))
        }
        crate::resource_memory::FloorRefusal::Deadline => HostError::Interrupted,
    }
}
