//! The organ host: install, call, unload, revoke.

use std::collections::{HashMap, HashSet};
use std::ops::Deref;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use oneiron::Vault;
use oneiron_organ_protocol::{
    ByteBuf, Call, CancelReason, Hash32, Input, MAX_FDS_PER_FRAME, MappedRegion, Outcome, Output,
    Payload, Proposal, SharedRegion, TypedBody,
};

use crate::budget::{Budget, Kept, Permit};
use crate::error::{HostError, Unavailable};
use crate::process::{CallFailure, OrganProcess};
use crate::receipt::{CallReceipt, ReceiptInput, ReceiptOutput, bound_notes, bound_text, digest};
use crate::regions::RegionCache;
use crate::slot::{OrganStatus, Slot};
use crate::spec::{HostConfig, OrganCall, OrganInput, OrganSpec};

const MAX_DETAIL_BYTES: usize = 512;
const MAX_NAME_BYTES: usize = 256;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What an organ proposed, checked by the host. Nothing here is in the vault
/// yet: the caller lands it through the write gate, or drops it.
#[derive(Debug)]
pub struct OrganOutcome {
    pub body: Option<TypedBody>,
    pub outputs: Vec<OrganOutput>,
    pub report: rmpv::Value,
    pub receipt: CallReceipt,
}

/// One file an organ made, hashed by the host.
#[derive(Debug)]
pub struct OrganOutput {
    pub name: String,
    pub media_type: String,
    pub content_hash: Hash32,
    bytes: OutputBytes,
    /// The budget memory these bytes hold until they drop.
    _kept: Kept,
}

#[derive(Debug)]
enum OutputBytes {
    Inline(Vec<u8>),
    Mapped(MappedRegion),
}

impl Deref for OrganOutput {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match &self.bytes {
            OutputBytes::Inline(bytes) => bytes,
            OutputBytes::Mapped(region) => region,
        }
    }
}

#[derive(Debug)]
enum Held {
    Inline(Vec<u8>),
    Region(Arc<SharedRegion>),
}

#[derive(Debug)]
struct Resolved {
    input: OrganInput,
    media_type: String,
    hash: Hash32,
    len: u64,
    held: Held,
}

/// The engine side of the organ protocol.
#[derive(Debug)]
pub struct OrganHost {
    config: HostConfig,
    budget: Budget,
    regions: RegionCache,
    slots: Mutex<HashMap<String, Arc<Slot>>>,
    /// Slots a reinstall replaced, kept in sight of revocations until no
    /// process of theirs runs.
    retired: Mutex<Vec<Arc<Slot>>>,
    revoked: Mutex<HashSet<String>>,
}

impl OrganHost {
    #[must_use]
    pub fn new(config: HostConfig) -> Self {
        Self {
            budget: Budget::new(config.budget),
            regions: RegionCache::new(config.region_cache_bytes),
            config,
            slots: Mutex::new(HashMap::new()),
            retired: Mutex::new(Vec::new()),
            revoked: Mutex::new(HashSet::new()),
        }
    }

    /// Installs (or reinstalls) an organ. A reinstall stops the old process
    /// and clears its crash history and any refusal.
    pub fn install(&self, spec: OrganSpec) {
        let name = spec.name.clone();
        let old = {
            let mut slots = lock(&self.slots);
            let old = slots.insert(name, Arc::new(Slot::new(spec)));
            // In the same breath as the swap, so a revocation always finds
            // the old slot: installed, or retired.
            if let Some(old) = &old {
                lock(&self.retired).push(Arc::clone(old));
            }
            old
        };
        if let Some(old) = old {
            for process in old.retire(Unavailable::Reinstalled) {
                process.stop();
            }
        }
        let retired: Vec<Arc<Slot>> = lock(&self.retired).clone();
        let finished: Vec<Arc<Slot>> = retired
            .into_iter()
            .filter(|slot| slot.live().is_empty())
            .collect();
        lock(&self.retired).retain(|slot| !finished.iter().any(|done| Arc::ptr_eq(done, slot)));
    }

    /// Every slot a revocation must search: the installed and the retired.
    fn all_slots(&self) -> Vec<Arc<Slot>> {
        let slots = lock(&self.slots);
        let mut all: Vec<Arc<Slot>> = slots.values().cloned().collect();
        all.extend(lock(&self.retired).iter().cloned());
        all
    }

    fn slot(&self, organ: &str) -> Result<Arc<Slot>, HostError> {
        lock(&self.slots)
            .get(organ)
            .cloned()
            .ok_or_else(|| HostError::NotInstalled(organ.to_owned()))
    }

    #[must_use]
    pub fn status(&self, organ: &str) -> Option<OrganStatus> {
        self.slot(organ).ok().map(|slot| slot.status())
    }

    /// Starts the organ now if it is cold. Returns spawn-to-`hello_ack` for
    /// the live process.
    ///
    /// # Errors
    /// The organ is not installed, unavailable, backing off, or fails to start.
    pub fn warm(&self, organ: &str) -> Result<Duration, HostError> {
        Ok(self.slot(organ)?.process(&self.config, None)?.spawn_time)
    }

    /// Stops the organ's process now, as an idle unload does.
    pub fn unload(&self, organ: &str) -> bool {
        let Ok(slot) = self.slot(organ) else {
            return false;
        };
        let Some(process) = slot.current() else {
            return false;
        };
        slot.stopped(&process);
        process.shutdown(Duration::from_secs(1));
        true
    }

    /// Stops every process idle longer than `idle_unload`.
    pub fn unload_idle(&self) -> usize {
        let slots: Vec<Arc<Slot>> = lock(&self.slots).values().cloned().collect();
        let mut unloaded = 0;
        for slot in slots {
            if let Some(process) = slot.take_if_idle(self.config.idle_unload) {
                process.shutdown(Duration::from_secs(1));
                unloaded += 1;
            }
        }
        unloaded
    }

    /// Withdraws an organ's install grant: its process is killed and every
    /// later call is refused until a reinstall.
    pub fn revoke(&self, organ: &str) {
        let Ok(slot) = self.slot(organ) else {
            return;
        };
        let cancel_by = Instant::now() + self.config.cancel_grace;
        for process in slot.revoke() {
            process.cancel_all(CancelReason::Revoked, cancel_by);
            process.stop();
        }
    }

    /// Withdraws a call grant. Calls under it are cancelled, and every
    /// process that ever received a handle under it is killed after the
    /// cancel grace, so the kernel drops what it mapped. Other calls on those
    /// processes fail as crashed and may be retried.
    pub fn revoke_grant(&self, grant: &str) {
        // Recorded before the holders are sought: a call marks its process
        // as a holder before it checks this set, so a call this scan misses
        // sees the revocation and is never sent.
        lock(&self.revoked).insert(grant.to_owned());
        let slots = self.all_slots();
        let holders: Vec<(Arc<Slot>, Arc<OrganProcess>)> = slots
            .iter()
            .flat_map(|slot| {
                slot.live()
                    .into_iter()
                    .filter(|process| process.holds_grant(grant))
                    .map(|process| (Arc::clone(slot), process))
            })
            .collect();
        let cancel_by = Instant::now() + self.config.cancel_grace;
        for (_, process) in &holders {
            process.cancel_all(CancelReason::Revoked, cancel_by);
        }
        if !holders.is_empty() {
            thread::sleep(cancel_by.saturating_duration_since(Instant::now()));
        }
        for (slot, process) in holders {
            slot.stopped(&process);
            process.stop();
        }
    }

    fn grant_revoked(&self, grant: &str) -> bool {
        lock(&self.revoked).contains(grant)
    }

    /// Drops every kept region; later calls copy their inputs again.
    pub fn clear_regions(&self) {
        self.regions.clear();
    }

    /// Runs one organ call and returns the checked proposal.
    ///
    /// The caller has already authorized its actor to read every input, as
    /// for any engine read; the host checks the organ's grant (verb, media
    /// type) and hands the organ those inputs and nothing else.
    ///
    /// # Errors
    /// See [`HostError`]: grants, budget, the organ's state, its reply.
    pub fn call(&self, vault: &Vault, call: OrganCall) -> Result<OrganOutcome, HostError> {
        let begun = Instant::now();
        let deadline = begun + call.deadline;
        self.unload_idle();
        if self.grant_revoked(&call.grant) {
            return Err(HostError::Revoked);
        }
        let slot = self.slot(&call.organ)?;
        let unknown = || HostError::UnknownVerb {
            organ: call.organ.clone(),
            verb: call.verb.clone(),
            schema: call.schema,
        };
        if !slot.spec.verbs.iter().any(|verb| verb == &call.verb) {
            return Err(unknown());
        }
        if call.inputs.len() > MAX_FDS_PER_FRAME {
            return Err(HostError::TooManyInputs);
        }
        let mut permit = self
            .budget
            .admit(call.class, 1, slot.spec.call_memory_bytes, deadline)?;
        let inputs = call
            .inputs
            .iter()
            .map(|input| self.resolve(vault, &slot.spec, *input))
            .collect::<Result<Vec<_>, _>>()?;
        let process = slot.process(&self.config, Some(deadline))?;
        let offered = process
            .hello
            .verbs
            .iter()
            .any(|verb| verb.name == call.verb && verb.schema == call.schema);
        if !offered {
            return Err(unknown());
        }
        let queued = begun.elapsed();
        let sent_at = Instant::now();
        let (reply, fds) = self.exchange(&slot, &process, &call, &inputs, deadline)?;
        // A grant withdrawn while the organ worked voids its answer too.
        if self.grant_revoked(&call.grant) {
            return Err(HostError::Revoked);
        }
        let proposal = match reply {
            Outcome::Proposal(proposal) => proposal,
            Outcome::Error(mut error) => {
                error.detail = bound_text(&error.detail, MAX_DETAIL_BYTES);
                return Err(HostError::Organ(error));
            }
        };
        let reply = Replied {
            proposal,
            fds,
            queued,
            sent_at,
            deadline,
            max_output_bytes: slot.spec.max_output_bytes.min(slot.spec.call_memory_bytes),
        };
        finish(&call, &process, &inputs, reply, &mut permit)
    }

    fn exchange(
        &self,
        slot: &Slot,
        process: &Arc<OrganProcess>,
        call: &OrganCall,
        inputs: &[Resolved],
        deadline: Instant,
    ) -> Result<(Outcome, Vec<OwnedFd>), HostError> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let (wire_inputs, fds) = wire_inputs(inputs);
        let wire = Call {
            id: 0,
            verb: call.verb.clone(),
            schema: call.schema,
            args: call.args.clone(),
            body: call.body.clone(),
            inputs: wire_inputs,
            deadline_ms: u32::try_from(remaining.as_millis()).unwrap_or(u32::MAX),
        };
        let revoked = || self.grant_revoked(&call.grant);
        let grace = self.config.cancel_grace;
        match process.call(wire, &fds, &call.grant, &revoked, deadline, grace) {
            Ok((reply, fds)) => Ok((reply.outcome, fds)),
            Err(CallFailure::Deadline { stopped }) => {
                // An organ that took the cancel lives on, still tracked;
                // only a killed one leaves its slot.
                if stopped {
                    slot.stopped(process);
                }
                Err(if revoked() {
                    HostError::Revoked
                } else {
                    HostError::DeadlineExceeded
                })
            }
            Err(CallFailure::Revoked) => Err(HostError::Revoked),
            Err(CallFailure::Busy) => Err(HostError::BudgetTimeout),
            Err(CallFailure::Refused(err)) => Err(err),
            Err(CallFailure::Crashed) => {
                slot.crashed(process);
                Err(if revoked() {
                    HostError::Revoked
                } else {
                    HostError::Crashed(call.organ.clone())
                })
            }
            Err(CallFailure::Frame(err)) => {
                slot.crashed(process);
                Err(err)
            }
        }
    }

    /// Lends one input from the vault: inline when small, else a sealed
    /// region, made once per content hash and kept for reuse.
    fn resolve(
        &self,
        vault: &Vault,
        spec: &OrganSpec,
        input: OrganInput,
    ) -> Result<Resolved, HostError> {
        let inline_max = self.config.inline_max_bytes;
        let lent =
            vault.lend_blob_artifact_version(&input.artifact, input.version, |record, bytes| {
                let media_type = record.export_media_type.clone();
                if !spec
                    .media_types
                    .iter()
                    .any(|granted| granted == &media_type)
                {
                    return Err(HostError::MediaTypeNotGranted(media_type));
                }
                let len = bytes.len() as u64;
                // A kept region was verified under this hash when it was made;
                // a row whose length no longer matches it is checked afresh,
                // and fails closed.
                let kept = self
                    .regions
                    .get(&record.content_hash)
                    .filter(|region| region.len() == len);
                let held = if bytes.len() <= inline_max {
                    Held::Inline(bytes.verified()?.to_vec())
                } else if let Some(region) = kept {
                    Held::Region(region)
                } else {
                    let region = SharedRegion::from_bytes(&bytes.verified()?)?;
                    Held::Region(self.regions.insert(record.content_hash, region))
                };
                Ok(Resolved {
                    input,
                    media_type,
                    hash: Hash32(record.content_hash),
                    len,
                    held,
                })
            })?;
        lent.unwrap_or_else(|| {
            Err(HostError::InputNotFound {
                artifact: input.artifact.to_hex(),
                version: input.version,
            })
        })
    }
}

fn wire_inputs(inputs: &[Resolved]) -> (Vec<Input>, Vec<BorrowedFd<'_>>) {
    let mut fds = Vec::new();
    let wire = inputs
        .iter()
        .map(|resolved| {
            let data = match &resolved.held {
                Held::Inline(bytes) => Payload::Inline(ByteBuf::from(bytes.clone())),
                Held::Region(region) => {
                    let slot = u16::try_from(fds.len()).unwrap_or(u16::MAX);
                    fds.push(region.fd());
                    Payload::Slot(slot)
                }
            };
            Input {
                media_type: resolved.media_type.clone(),
                len: resolved.len,
                content_hash: resolved.hash,
                data,
            }
        })
        .collect();
    (wire, fds)
}

/// A reply as it came back, with what `finish` needs to check it.
struct Replied {
    proposal: Proposal,
    fds: Vec<OwnedFd>,
    queued: Duration,
    sent_at: Instant,
    deadline: Instant,
    max_output_bytes: u64,
}

/// Checks a proposal, hashes its outputs and writes the receipt.
fn finish(
    call: &OrganCall,
    process: &OrganProcess,
    inputs: &[Resolved],
    reply: Replied,
    permit: &mut Permit,
) -> Result<OrganOutcome, HostError> {
    let Replied {
        proposal,
        fds,
        queued,
        sent_at,
        deadline,
        max_output_bytes,
    } = reply;
    if let (Some(base), Some(next)) = (&call.body, &proposal.body)
        && base.kind != next.kind
    {
        return Err(HostError::ReplyInvalid(format!(
            "a {} body came back as {}",
            base.kind, next.kind
        )));
    }
    let outputs = take_outputs(proposal.outputs, fds, max_output_bytes, deadline, permit)?;
    let receipt = CallReceipt {
        organ: process.hello.organ.clone(),
        protocol: process.hello.protocol,
        verb: call.verb.clone(),
        schema: call.schema,
        args_digest: digest(&call.args),
        inputs: inputs
            .iter()
            .map(|resolved| ReceiptInput {
                artifact: resolved.input.artifact.to_hex(),
                version: resolved.input.version,
                content_hash: resolved.hash,
                len: resolved.len,
            })
            .collect(),
        base_body: call.body.as_ref().map(digest),
        result_body: proposal.body.as_ref().map(digest),
        outputs: outputs
            .iter()
            .map(|output| ReceiptOutput {
                name: output.name.clone(),
                media_type: output.media_type.clone(),
                content_hash: output.content_hash,
                len: output.len() as u64,
            })
            .collect(),
        notes: bound_notes(proposal.notes),
        class: call.class,
        grant: call.grant.clone(),
        queue_us: u64::try_from(queued.as_micros()).unwrap_or(u64::MAX),
        run_us: u64::try_from(sent_at.elapsed().as_micros()).unwrap_or(u64::MAX),
    };
    Ok(OrganOutcome {
        body: proposal.body,
        outputs,
        report: proposal.report,
        receipt,
    })
}

/// Hashes in pieces, so a large output cannot run the call past its deadline.
fn hash_until(bytes: &[u8], deadline: Instant) -> Result<Hash32, HostError> {
    const PIECE: usize = 32 * 1024 * 1024;
    let mut hasher = blake3::Hasher::new();
    for piece in bytes.chunks(PIECE) {
        if Instant::now() >= deadline {
            return Err(HostError::DeadlineExceeded);
        }
        hasher.update(piece);
    }
    Ok(Hash32(*hasher.finalize().as_bytes()))
}

/// Maps and hashes the outputs. Region outputs must be sealed, and all
/// outputs together stay within `max_output_bytes`, checked before each
/// map. Their bytes keep that much of the call's booked memory until they
/// drop, so outputs a caller holds on to stay counted.
fn take_outputs(
    outputs: Vec<Output>,
    fds: Vec<OwnedFd>,
    max_output_bytes: u64,
    deadline: Instant,
    permit: &mut Permit,
) -> Result<Vec<OrganOutput>, HostError> {
    if outputs.len() > MAX_FDS_PER_FRAME {
        return Err(HostError::ReplyInvalid("more than 16 outputs".into()));
    }
    let mut slots: Vec<Option<OwnedFd>> = fds.into_iter().map(Some).collect();
    let mut left = max_output_bytes;
    outputs
        .into_iter()
        .map(|output| {
            let bytes = match output.data {
                Payload::Inline(bytes) => {
                    left = left.checked_sub(bytes.len() as u64).ok_or_else(|| {
                        HostError::ReplyInvalid("outputs past the output limit".into())
                    })?;
                    OutputBytes::Inline(bytes.into_vec())
                }
                Payload::Slot(slot) => {
                    let fd = slots
                        .get_mut(usize::from(slot))
                        .and_then(Option::take)
                        .ok_or_else(|| HostError::ReplyInvalid("output slot".into()))?;
                    let region = MappedRegion::map_sealed(fd, left)
                        .map_err(|err| HostError::ReplyInvalid(format!("output region: {err}")))?;
                    left -= region.len() as u64;
                    OutputBytes::Mapped(region)
                }
            };
            let content_hash = match &bytes {
                OutputBytes::Inline(inline) => hash_until(inline, deadline)?,
                OutputBytes::Mapped(region) => hash_until(region, deadline)?,
            };
            let len = match &bytes {
                OutputBytes::Inline(inline) => inline.len(),
                OutputBytes::Mapped(region) => region.len(),
            };
            Ok(OrganOutput {
                name: bound_text(&output.name, MAX_NAME_BYTES),
                media_type: bound_text(&output.media_type, MAX_NAME_BYTES),
                content_hash,
                bytes,
                _kept: permit.keep(len as u64),
            })
        })
        .collect()
}
