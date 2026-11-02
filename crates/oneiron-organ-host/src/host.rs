//! The organ host: install, call, unload, revoke.

use std::collections::HashMap;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use oneiron::Vault;
use oneiron::limit_ask::EngineLimit;
use oneiron_organ_protocol::{
    ByteBuf, Call, CancelReason, Hash32, INLINE_MAX_BYTES, Input, MAX_FDS_PER_FRAME, Outcome,
    Payload, SharedRegion,
};

use crate::asks::{AskContext, CallAsks};
use crate::budget::{Budget, CallRoom, Lease};
use crate::error::{HostError, Unavailable};
use crate::handlers::{AskHandlers, in_handler};
use crate::measure::install_row;
use crate::outcome::OrganOutcome;
use crate::process::{CallFailure, Grant, OrganProcess, Revocations, Wait};
use crate::regions::RegionCache;
use crate::resource_memory::{MachineFloor, SharedFloor};
use crate::shutdown::{self, MeshCancel};
use crate::slot::{OrganStatus, Slot};
use crate::spec::{HostConfig, LentInput, OrganCall, OrganInput, OrganSpec, SightedInput};

mod outputs;
mod sized;

use outputs::{Called, Replied, finish};
pub use sized::{CallMeasure, CallSize};
use sized::{OneCall, Run};

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A reply's outcome, its descriptors, the room its frame holds, and the
/// call's deadline as its waits for room moved it.
type Exchanged = (Outcome, Vec<OwnedFd>, Lease, Instant);

#[derive(Debug)]
enum Held {
    Inline(Vec<u8>),
    Region(Arc<SharedRegion>),
}

#[derive(Debug)]
struct Resolved {
    /// `None` for bytes the caller lent.
    input: Option<OrganInput>,
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
    /// Slots a reinstall replaced, kept in sight of revocations until they
    /// are retired (no call can start a process in them) and no process of
    /// theirs runs.
    retired: Mutex<Vec<Arc<Slot>>>,
    revoked: Revocations,
    /// The machine's memory floor organs' own buffers lease from
    /// (`memory.grow`, FIX 7654); none on a host built by [`Self::new`].
    floor: Option<SharedFloor>,
}

impl OrganHost {
    /// A host with no machine memory floor: it refuses every `memory.grow`
    /// ask, so an organ that reserves its buffers cannot run on it.
    #[must_use]
    pub fn new(config: HostConfig) -> Self {
        Self {
            budget: Budget::new(config.budget),
            regions: RegionCache::new(config.region_cache_bytes),
            config,
            slots: Mutex::new(HashMap::new()),
            retired: Mutex::new(Vec::new()),
            revoked: Revocations::default(),
            floor: None,
        }
    }

    /// A host whose organs' own buffers lease from `floor`, the machine's
    /// memory (`memory.grow`, FIX 7654): each call holds what it leased
    /// until it ends. Share one floor across the machine's work.
    #[must_use]
    pub fn with_floor(config: HostConfig, floor: Arc<dyn MachineFloor>) -> Self {
        Self {
            floor: Some(SharedFloor(floor)),
            ..Self::new(config)
        }
    }

    /// The machine floor this host's organs lease from, for a router that
    /// takes bytes back from other nodes beside it.
    pub(crate) fn floor(&self) -> Option<SharedFloor> {
        self.floor.clone()
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
        self.prune_retired();
    }

    /// Removes an organ, as the uninstall of the pack that carried it does:
    /// its process stops, a call starting in it is refused as revoked, and
    /// later calls find it not installed, so the mesh no longer offers it.
    /// `false` when no such organ was installed.
    pub fn uninstall(&self, organ: &str) -> bool {
        let old = {
            let mut slots = lock(&self.slots);
            let old = slots.remove(organ);
            // In the same breath as the removal, so a revocation always
            // finds the slot: installed, or retired.
            if let Some(old) = &old {
                lock(&self.retired).push(Arc::clone(old));
            }
            old
        };
        let Some(old) = old else {
            return false;
        };
        for process in old.retire(Unavailable::Revoked) {
            process.stop();
        }
        self.prune_retired();
        true
    }

    /// Drops the retired slots no process of which runs any more.
    fn prune_retired(&self) {
        let retired: Vec<Arc<Slot>> = lock(&self.retired).clone();
        let finished: Vec<Arc<Slot>> = retired.into_iter().filter(|slot| slot.finished()).collect();
        lock(&self.retired).retain(|slot| !finished.iter().any(|done| Arc::ptr_eq(done, slot)));
    }

    /// The spec an organ is installed under, so a host can tell whether a
    /// newer one replaces it.
    #[must_use]
    pub fn spec(&self, organ: &str) -> Option<OrganSpec> {
        self.slot(organ).ok().map(|slot| slot.spec.clone())
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

    /// Every installed organ and the verbs its grant names, by name,
    /// whether or not this host can start it now.
    #[must_use]
    pub fn installed(&self) -> Vec<(String, Vec<String>)> {
        let mut installed: Vec<(String, Vec<String>)> = lock(&self.slots)
            .iter()
            .map(|(name, slot)| (name.clone(), slot.spec.verbs.clone()))
            .collect();
        installed.sort();
        installed
    }

    /// The installed organs this host can start now, and the verbs each
    /// grant names, by name: what this machine offers the owner's other
    /// nodes (FIX 7888). It reads the start's own decision, a warm process
    /// or none that refuses one; nothing starts or is checked to say so.
    #[must_use]
    pub fn offered(&self) -> Vec<(String, Vec<String>)> {
        let slots: Vec<(String, Arc<Slot>)> = lock(&self.slots)
            .iter()
            .map(|(name, slot)| (name.clone(), Arc::clone(slot)))
            .collect();
        let mut offered: Vec<(String, Vec<String>)> = slots
            .into_iter()
            .filter(|(_, slot)| slot.startable())
            .map(|(name, slot)| (name, slot.spec.verbs.clone()))
            .collect();
        offered.sort();
        offered
    }

    /// Starts the organ now if it is cold. Returns spawn-to-`hello_ack` for
    /// the live process.
    ///
    /// # Errors
    /// The organ is not installed, unavailable, backing off, or fails to start.
    pub fn warm(&self, organ: &str) -> Result<Duration, HostError> {
        let room = self.budget.room(self.floor.clone());
        Ok(self
            .slot(organ)?
            .process(&self.config, &room, None)?
            .spawn_time)
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
        slot.prune();
        true
    }

    /// Stops every process idle longer than `idle_unload`.
    pub fn unload_idle(&self) -> usize {
        let slots: Vec<Arc<Slot>> = lock(&self.slots).values().cloned().collect();
        let mut unloaded = 0;
        for slot in slots {
            if let Some(process) = slot.take_if_idle(self.config.idle_unload) {
                process.shutdown(Duration::from_secs(1));
                slot.prune();
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
        slot.prune();
    }

    /// Withdraws a call grant. Calls under it are cancelled, and every
    /// process that ever received a handle under it is killed after the
    /// cancel grace, so the kernel drops what it mapped. Other calls on those
    /// processes fail as crashed and may be retried.
    pub fn revoke_grant(&self, grant: &str) {
        // Recorded before the holders are sought: a call marks its process
        // as a holder before it checks this set, so a call this scan misses
        // sees the revocation and is never sent. An answer's first byte holds
        // a read of this set, so recording waits for one in progress, and
        // no answer under the grant starts after it.
        self.revoked.record(grant);
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
            slot.prune();
        }
    }

    fn grant_revoked(&self, grant: &str) -> bool {
        self.revoked.contains(grant)
    }

    /// Drops every kept region; later calls copy their inputs again.
    pub fn clear_regions(&self) {
        self.regions.clear();
    }

    /// Runs one organ call and returns the checked proposal.
    ///
    /// The caller has already authorized its actor to read every input, as
    /// for any engine read, and judged the sight it reads each under
    /// ([`SightedInput`]); the host checks the organ's grant (verb, media
    /// type) and hands the organ those inputs, as that sight reads them, and
    /// nothing else. Every ask the organ makes is refused.
    ///
    /// # Errors
    /// See [`HostError`]: grants, budget, the organ's state, its reply.
    pub fn call(&self, vault: &Vault, call: OrganCall) -> Result<OrganOutcome, HostError> {
        self.call_with(vault, call, Vec::new(), &AskHandlers::none())
    }

    /// [`Self::call`], with bytes the caller lends after the vault inputs,
    /// and the handlers that answer the organ's asks (protocol 1.1). An ask
    /// is answered only when the install grant names its verb and `asks`
    /// holds a handler for it; handlers run on this thread, inside the
    /// call's deadline, and may not call an organ themselves. Every ask's
    /// receipt line is also kept in `asks` ([`AskHandlers::asked`]), so a
    /// call that fails still leaves a record of what its handlers did.
    ///
    /// # Errors
    /// As [`Self::call`], plus [`HostError::Reentrant`] from inside a
    /// handler. No count or size of the organ's asks refuses one: each is
    /// measured against its `[limits]` row, and the call's booking grows to
    /// hold every answer.
    pub fn call_with(
        &self,
        vault: &Vault,
        call: OrganCall,
        lent: Vec<LentInput>,
        asks: &AskHandlers<'_>,
    ) -> Result<OrganOutcome, HostError> {
        self.run(vault, call, unvouched(lent), asks, Run::Warm)
    }

    /// [`Self::call_with`], in a process started for this call alone: it
    /// never served another call, never serves a later one, and is stopped
    /// when this call ends, however it ends. The organ's warm process, if
    /// any, does not serve it. A second opinion runs this way, so nothing an
    /// earlier call left in a process can decide it.
    ///
    /// # Errors
    /// As [`Self::call_with`].
    pub fn call_fresh_with(
        &self,
        vault: &Vault,
        call: OrganCall,
        lent: Vec<LentInput>,
        asks: &AskHandlers<'_>,
    ) -> Result<OrganOutcome, HostError> {
        self.run(vault, call, unvouched(lent), asks, Run::Fresh)
    }

    /// A call another of the owner's nodes sent over the mesh. That node
    /// read every input from its own vault, under its own actor's
    /// authority, and sent the bytes: each comes with the artifact version
    /// it read (none for bytes its caller lent), and is hashed here again,
    /// so the receipt holds what this host saw. `call.inputs` is empty. It
    /// runs under the mesh's `cancel` (FIX 4756): cut short, it says
    /// [`HostError::Interrupted`].
    pub(crate) fn call_for_peer(
        &self,
        vault: &Vault,
        call: OrganCall,
        inputs: Vec<(Option<OrganInput>, LentInput)>,
        asks: &AskHandlers<'_>,
        cancel: &MeshCancel,
    ) -> Result<OrganOutcome, HostError> {
        cancel.scope(|| shutdown::settle(self.run(vault, call, inputs, asks, Run::Warm)))
    }

    fn run(
        &self,
        vault: &Vault,
        call: OrganCall,
        lent: Vec<(Option<OrganInput>, LentInput)>,
        asks: &AskHandlers<'_>,
        mut how: Run<'_>,
    ) -> Result<OrganOutcome, HostError> {
        if in_handler() {
            return Err(HostError::Reentrant);
        }
        let begun = Instant::now();
        // The wire says a deadline in u32 milliseconds (about 49 days); a
        // longer one, up to `Duration::MAX`, waits that long and never
        // overflows the clock.
        let longest = Duration::from_millis(u64::from(u32::MAX));
        let deadline = begun + call.deadline.min(longest);
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
        // The install grant's kinds, as the owner granted them (FIX 7985):
        // a typed body of another kind is never dispatched.
        if let (Some(body), Some(kinds)) = (&call.body, &slot.spec.kinds)
            && !kinds.iter().any(|kind| kind == &body.kind)
        {
            return Err(HostError::KindNotGranted(body.kind.clone()));
        }
        if call.inputs.len() + lent.len() > MAX_FDS_PER_FRAME {
            return Err(HostError::TooManyInputs);
        }
        let booking = how.booking(&slot.spec);
        // The call's room: its booking, grown as its answers and outputs
        // need (FIX 5284), and as the organ's own buffers lease the machine's
        // floor (FIX 7654).
        let permit = self.budget.admit(call.class, 1, booking, deadline)?;
        let room = CallRoom::new(permit, self.floor.clone());
        let mut inputs = call
            .inputs
            .iter()
            .map(|input| self.resolve(vault, &slot.spec, *input))
            .collect::<Result<Vec<_>, _>>()?;
        for (of, input) in lent {
            inputs.push(self.lend(&slot.spec, input, of)?);
        }
        let frames = self.budget.room(self.floor.clone());
        let process = if how.fresh() {
            let memory = how.process_memory(&slot.spec);
            slot.fresh_process(&self.config, &frames, Some(deadline), memory)?
        } else {
            slot.process(&self.config, &frames, Some(deadline))?
        };
        let _one_call = how.fresh().then(|| OneCall {
            slot: slot.as_ref(),
            process: Arc::clone(&process),
        });
        // The process's kernel limits follow what its buffers are granted.
        let limits: Arc<OrganProcess> = Arc::clone(&process);
        room.bind(limits);
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
        let inline_max = self.config.inline_max_bytes.min(INLINE_MAX_BYTES);
        let revoked = || self.grant_revoked(&call.grant);
        let context = AskContext {
            vault,
            room: &room,
            revoked: &revoked,
        };
        let mut asked = CallAsks::new(
            &slot.spec,
            asks,
            context,
            &call.verb,
            &call.grant,
            inline_max,
        );
        let exchanged = self.exchange(&slot, &process, &call, &inputs, &mut asked, deadline);
        how.measured(&process);
        // The deadline as the exchange's waits for room moved it: the
        // outputs count on from there (FIX 8020).
        let (reply, fds, frame, moved) = exchanged?;
        asked.frame_received(frame.bytes());
        measure_frames(vault, &slot.spec, asked.frames());
        // The lines also reach `asks` when `asked` drops, on every path.
        let asks = asked.receipts.clone();
        // A grant withdrawn while the organ worked voids its answer too.
        if revoked() {
            return Err(HostError::Revoked);
        }
        let proposal = match reply {
            Outcome::Proposal(proposal) => proposal,
            Outcome::Error(error) => {
                vault.measure_limit(EngineLimit::OrganDetailBytes, error.detail.len() as u64);
                return Err(HostError::Organ(error));
            }
        };
        let reply = Replied {
            proposal,
            fds,
            frame,
            queued,
            sent_at,
            deadline: moved,
            asks,
            budget: self.budget.memory_bytes(),
        };
        let called = Called {
            vault,
            call: &call,
            spec: &slot.spec,
            process: &process,
            inputs: &inputs,
            room: &room,
            revoked: &revoked,
        };
        finish(&called, reply)
    }

    fn exchange(
        &self,
        slot: &Slot,
        process: &Arc<OrganProcess>,
        call: &OrganCall,
        inputs: &[Resolved],
        asked: &mut CallAsks<'_>,
        deadline: Instant,
    ) -> Result<Exchanged, HostError> {
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
        let _interruptible = shutdown::interruptible(process, grace);
        let wait = Wait {
            grant: Grant {
                name: &call.grant,
                revocations: &self.revoked,
            },
            asks: asked,
            deadline,
            grace,
        };
        match process.call(wire, &fds, wait) {
            Ok((reply, fds, frame, moved)) => {
                shutdown::answered();
                Ok((reply.outcome, fds, frame, moved))
            }
            // The mesh's stop ended the call's wait: a live process is unharmed.
            Err(failure)
                if !matches!(failure, CallFailure::Revoked)
                    && shutdown::interrupted()
                    && process.is_alive() =>
            {
                Err(HostError::Interrupted)
            }
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
            Err(CallFailure::Refused(err) | CallFailure::Ended(err)) => Err(err),
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

    /// Lends one input from the vault, as its caller's sight reads it:
    /// inline when small, else a sealed region, made once per lent hash and
    /// kept for reuse. The lent hash names the bytes the organ reads, a
    /// masked copy's own included (FIX 6508), so the receipt says what it saw.
    fn resolve(
        &self,
        vault: &Vault,
        spec: &OrganSpec,
        sighted: SightedInput,
    ) -> Result<Resolved, HostError> {
        let SightedInput { input, sight } = sighted;
        let inline_max = self.config.inline_max_bytes;
        let lent = vault.lend_blob_artifact_version(
            &input.artifact,
            input.version,
            sight,
            |record, bytes| {
                let media_type = record.export_media_type.clone();
                if !spec
                    .media_types
                    .iter()
                    .any(|granted| granted == &media_type)
                {
                    return Err(HostError::MediaTypeNotGranted(media_type));
                }
                let len = bytes.len() as u64;
                let hash = *bytes.hash();
                // A kept region was verified under this hash when it was made;
                // a row whose length no longer matches it is checked afresh,
                // and fails closed.
                let kept = self.regions.get(&hash).filter(|region| region.len() == len);
                let held = if bytes.len() <= inline_max {
                    Held::Inline(bytes.verified()?.to_vec())
                } else if let Some(region) = kept {
                    Held::Region(region)
                } else {
                    let region = SharedRegion::from_bytes(&bytes.verified()?)?;
                    Held::Region(self.regions.insert(hash, region))
                };
                Ok(Resolved {
                    input: Some(input),
                    media_type,
                    hash: Hash32(hash),
                    len,
                    held,
                })
            },
        )?;
        lent.unwrap_or_else(|| {
            Err(HostError::InputNotFound {
                artifact: input.artifact.to_hex(),
                version: input.version,
            })
        })
    }

    /// Lends bytes the caller holds: hashed here, inline when small, else a
    /// sealed region kept by content hash like a vault input's. `of` is the
    /// vault version another node read them from, if any.
    fn lend(
        &self,
        spec: &OrganSpec,
        input: LentInput,
        of: Option<OrganInput>,
    ) -> Result<Resolved, HostError> {
        let LentInput { media_type, bytes } = input;
        if !spec
            .media_types
            .iter()
            .any(|granted| granted == &media_type)
        {
            return Err(HostError::MediaTypeNotGranted(media_type));
        }
        let hash = Hash32::of(&bytes);
        let len = bytes.len() as u64;
        let held = if bytes.len() <= self.config.inline_max_bytes {
            Held::Inline(bytes)
        } else if let Some(region) = self
            .regions
            .get(&hash.0)
            .filter(|region| region.len() == len)
        {
            Held::Region(region)
        } else {
            Held::Region(
                self.regions
                    .insert(hash.0, SharedRegion::from_bytes(&bytes)?),
            )
        };
        Ok(Resolved {
            input: of,
            media_type,
            hash,
            len,
            held,
        })
    }
}

/// Bytes a local caller lent: no vault version stands behind them.
fn unvouched(lent: Vec<LentInput>) -> Vec<(Option<OrganInput>, LentInput)> {
    lent.into_iter().map(|input| (None, input)).collect()
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

/// Measures the largest frames a call's process carried for it against
/// the install grant's own frame sizes: thresholds, never refusals, under
/// the wire's own `u32` length (Rule 5).
fn measure_frames(vault: &Vault, spec: &OrganSpec, (sent, received): (u64, u64)) {
    let rows = [
        (EngineLimit::OrganCallFrameBytes, spec.max_call_frame, sent),
        (
            EngineLimit::OrganReplyFrameBytes,
            spec.max_reply_frame,
            received,
        ),
    ];
    for (row, install, measured) in rows {
        install_row(vault, row, u64::from(install), measured);
    }
}
