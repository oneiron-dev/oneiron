//! Admission on the node (design pass 33, 7.2 and 7.3): `Reserve`,
//! `Release` and `Submit` on `oneiron/job/1`; the stop of a key and the
//! key's receipt, which `oneiron/job-status/1` serves (row R4 maps its
//! requests here); and the engine's own end of a key (a revoke, a disk
//! limit).
//!
//! The caller has already proven the peer for the protocol and checked that
//! it is one of the node's issuers (row R1's gate). Here every request that
//! names a key is answered only to the issuer the journal recorded for it,
//! and known keys are resolved before any refusal, so a refusal never hides
//! a key that already took effect. Under the admission lock, before any new
//! record, `Reserve` and `Submit` read the clock and the issuer's authority
//! again: a grant that ended after the gate is refused as the gate refuses
//! it, with nothing journaled.

use std::collections::BTreeSet;

use oneiron::EntityId;
use oneiron::job_workload::{
    DeviceClaim, DeviceLease, DevicePlacement, DevicePlacementError, DeviceState, HeldDevice,
    ResourceRequest,
};

use super::end::end_of;
use super::job_unit::{RenewRefusal, read_end_record};
use super::journal::{EndingCause, JobJournal, JournalEvent, JournalWriteError, NodeKey};
use super::node_parts::{GpuSlotRequest, NodeDevices};
use super::receipt::{ReceiptClock, chunk_receipt_of, receipt_of, sign_receipt};
use super::{BUSY_RETRY_AFTER_MS, NodeBook, NodeGate, NodeJobs};
use crate::gpu_execution_node::renewal_timing::RENEWAL_MARGIN_NS;
use crate::gpu_execution_node::wire::{
    JobAnswer, JobEnd, JobReceipt, JobRefusal, JobReserve, JobState, JobStatusAnswer,
    SignedJobSubmit, SlotSelector,
};

const MIB: u64 = 1024 * 1024;

const NANOS_PER_SEC: u64 = 1_000_000_000;

/// A renewal's refusals that no wait undoes (row W1): the run is gone or
/// can no longer take a renewal, the signed submit expired, or the run
/// reached its longest. Only these close a chunk key while the node's fold
/// lags the issuer's authority heads; every other refusal waits for it.
const RENEWAL_REFUSALS_FOR_GOOD: [&str; 4] = [
    "continues_unknown",
    "continues_ended",
    "submit_expired",
    "session_max_reached",
];

/// The most devices one key leases in this slice: the GPU slot table holds
/// one lease per key, and a receipt names one device. A bound of the
/// table's shape, not a policy.
pub(super) const DEVICES_PER_KEY_MAX: usize = 1;

/// When a key's request is placed, and so whose leases count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Placing {
    /// Design 7.3 reserve step 7: whether the request could be placed here
    /// at all. Leases of other keys are left out, as they end; a withheld
    /// or quarantined device still does not count.
    AtReserve,
    /// Design 7.5 step 4: the placement the launch commit leases, with
    /// every holder counted.
    AtLaunch,
}

/// The placement of `reserve`'s request on the node's devices (pass 34,
/// 2.1, `ResourceRequest::place_devices`), read fresh and narrowed by the
/// reserve's slot selector. A request with no device claim reads no
/// device: it is placed on threads and memory alone.
///
/// # Errors
///
/// The reason for the key's end: the devices cannot be read, no device of
/// the machine meets a claim (`no_device: claim <n>`), the devices that
/// meet it are taken (`device_unavailable: claim <n>`), the host memory
/// the placement leases has no value in MiB (`host_memory_overflow: claim
/// <n>`), or the placement takes more devices than a key may hold
/// (`devices_above_one`).
pub(super) fn placement(
    devices: &dyn NodeDevices,
    reserve: &JobReserve,
    placing: Placing,
) -> Result<DevicePlacement, String> {
    let request = &reserve.pin.request;
    let held = if claims_devices(request) {
        let mut held = selected(devices.devices()?, &reserve.slot);
        if placing == Placing::AtReserve {
            for device in &mut held {
                device.holders.clear();
                if matches!(device.facts.state, DeviceState::Leased { .. }) {
                    device.facts.state = DeviceState::Offered;
                }
            }
        }
        held
    } else {
        Vec::new()
    };
    let placed = request.place_devices(&held).map_err(|error| match error {
        DevicePlacementError::NoDevice { claim, .. } => format!("no_device: claim {claim}"),
        DevicePlacementError::DeviceBusy { claim } => {
            format!("device_unavailable: claim {claim}")
        }
        DevicePlacementError::HostMemoryOverflow { claim } => {
            format!("host_memory_overflow: claim {claim}")
        }
    })?;
    if placed.devices.len() > DEVICES_PER_KEY_MAX {
        return Err("devices_above_one".to_owned());
    }
    Ok(placed)
}

/// Whether the request claims a device at all: a claim with a count of 0
/// takes no lease.
fn claims_devices(request: &ResourceRequest) -> bool {
    request.devices.iter().any(|claim| claim.count > 0)
}

/// The devices the reserve's slot selector lets the key take: the one it
/// names by id, of the model it names; every device when it names neither.
/// It keeps every row of a chosen id, so placement still sees an id the
/// report repeats on rows of other models, and leases none of them.
fn selected(devices: Vec<HeldDevice>, slot: &SlotSelector) -> Vec<HeldDevice> {
    let chosen: BTreeSet<String> = devices
        .iter()
        .filter(|held| {
            slot.device_id
                .as_ref()
                .is_none_or(|id| *id == held.facts.id)
                && slot
                    .model
                    .as_ref()
                    .is_none_or(|model| *model == held.facts.model)
        })
        .map(|held| held.facts.id.clone())
        .collect();
    devices
        .into_iter()
        .filter(|held| chosen.contains(&held.facts.id))
        .collect()
}

/// The slot request that leases one placed device under `key`. The journal
/// books the key's disk at `Reserve`, so the slot claims none of it again.
#[must_use]
pub(super) fn device_slot_request(
    key: &str,
    lease: &DeviceLease,
    claim: &DeviceClaim,
) -> GpuSlotRequest {
    GpuSlotRequest {
        key: key.to_owned(),
        device_id: Some(lease.device_id.clone()),
        claim: claim.clone(),
        disk_bytes: 0,
    }
}

/// `mib` in bytes, as the machine's memory floor counts them.
#[must_use]
pub(super) fn mib_bytes(mib: u64) -> u64 {
    mib.saturating_mul(MIB)
}

fn busy() -> JobAnswer {
    JobAnswer::Busy {
        retry_after_ms: BUSY_RETRY_AFTER_MS,
    }
}

pub(super) fn status_busy() -> JobStatusAnswer {
    JobStatusAnswer::Busy {
        retry_after_ms: BUSY_RETRY_AFTER_MS,
    }
}

/// The journal, when the node admits work now.
fn admitting(book: &mut NodeBook) -> Result<&mut JobJournal, JobAnswer> {
    match &book.gate {
        NodeGate::Recovering => return Err(busy()),
        NodeGate::HistoryLost { .. } => return Err(JobAnswer::Refused(JobRefusal::HistoryLost)),
        NodeGate::Open => {}
    }
    match book.journal.as_mut() {
        Some(journal) if !journal.is_poisoned() => Ok(journal),
        _ => Err(busy()),
    }
}

/// The journal, when the node answers key questions now.
pub(super) fn answering(book: &mut NodeBook) -> Result<&mut JobJournal, JobStatusAnswer> {
    match &book.gate {
        NodeGate::Recovering => return Err(status_busy()),
        NodeGate::HistoryLost { .. } => return Err(JobStatusAnswer::HistoryLost),
        NodeGate::Open => {}
    }
    match book.journal.as_mut() {
        Some(journal) if !journal.is_poisoned() => Ok(journal),
        _ => Err(status_busy()),
    }
}

impl NodeJobs {
    /// The signed receipt of `key` now, as a `job/1` answer. A receipt that
    /// cannot be signed is no receipt: the issuer asks again.
    pub(super) fn receipt_answer(
        &self,
        key: &NodeKey,
        epoch: super::JournalEpoch,
        now: &ReceiptClock,
    ) -> JobAnswer {
        let parts = self.parts();
        // A renewed run's first key answers its own chunk's slice.
        let receipt = if key.renewals.is_empty() {
            Some(receipt_of(key, parts.machine, epoch, now))
        } else {
            chunk_receipt_of(
                key,
                0,
                self.last_tick_boot_ns(key),
                parts.machine,
                epoch,
                now,
            )
        };
        let Some(receipt) = receipt else {
            return busy();
        };
        self.signed_answer(key, receipt)
    }

    /// The receipt of chunk `chunk` of `first`'s renewed run (row W1), as a
    /// `job/1` answer.
    pub(super) fn chunk_answer(
        &self,
        first: &NodeKey,
        chunk: u32,
        epoch: super::JournalEpoch,
        now: &ReceiptClock,
    ) -> JobAnswer {
        let alive_at_boot_ns = self.last_tick_boot_ns(first);
        match chunk_receipt_of(
            first,
            chunk,
            alive_at_boot_ns,
            self.parts().machine,
            epoch,
            now,
        ) {
            Some(receipt) => self.signed_answer(first, receipt),
            None => busy(),
        }
    }

    /// `receipt` with the scope `holder`'s unit proved, signed.
    fn signed_answer(&self, holder: &NodeKey, mut receipt: JobReceipt) -> JobAnswer {
        let parts = self.parts();
        receipt.scope = parts.units.scope_facts(&holder.id);
        let key = receipt.key.clone();
        match sign_receipt(receipt, parts.signer.as_ref()) {
            Ok(signed) => JobAnswer::Receipt(signed),
            Err(error) => {
                tracing::warn!(key = %key, %error, "job receipt not signed; answering busy");
                busy()
            }
        }
    }

    /// The receipt of `key` for a status answer: its own, or, for a renewed
    /// chunk's key, its slice of the run (row W1). `None` when the journal
    /// holds neither.
    pub(super) fn any_receipt(
        &self,
        journal: &JobJournal,
        key: &str,
        now: &ReceiptClock,
    ) -> Option<(EntityId, JobAnswer)> {
        let epoch = journal.epoch();
        if let Some(known) = journal.table().get(key) {
            return Some((known.issuer, self.receipt_answer(known, epoch, now)));
        }
        let (first, chunk) = journal.table().chunk(key)?;
        Some((first.issuer, self.chunk_answer(first, chunk, epoch, now)))
    }

    /// Records `event` and answers the key's receipt. A record that did not
    /// land answers `Busy`: nothing was written, so the issuer may ask
    /// again.
    fn record_and_answer(
        &self,
        journal: &mut JobJournal,
        key: &str,
        issuer: EntityId,
        event: JournalEvent,
        now: &ReceiptClock,
    ) -> JobAnswer {
        let epoch = journal.epoch();
        match journal.record(key, issuer, &now.boot_id, now.wall_ms, event) {
            Ok(entry) => {
                let entry = entry.clone();
                self.receipt_answer(&entry, epoch, now)
            }
            Err(error) => {
                log_write_error(key, &error);
                busy()
            }
        }
    }

    /// `Reserve` (design 7.3): holds the key and its disk space, never a
    /// device, and never starts a process. Journaled before it is answered.
    #[must_use]
    pub fn reserve(&self, peer: EntityId, reserve: JobReserve) -> JobAnswer {
        if peer != reserve.issuer {
            return JobAnswer::Refused(JobRefusal::NotIssuer);
        }
        let mut book = self.lock();
        let now = self.now();
        let journal = match admitting(&mut book) {
            Ok(journal) => journal,
            Err(answer) => return answer,
        };
        if let Some(answer) = Self::chunk_key_refusal(journal, &reserve.key, peer) {
            return answer;
        }
        if let Some(known) = journal.table().get(&reserve.key) {
            if known.issuer != peer {
                return JobAnswer::Refused(JobRefusal::NotTheKeysIssuer);
            }
            let known = known.clone();
            return self.receipt_answer(&known, journal.epoch(), &now);
        }
        if let Err(not_live) = self.parts().admission.issuer_live(peer) {
            return JobAnswer::Refused(not_live.refusal);
        }
        let key = reserve.key.clone();
        let event =
            match self.reserve_refusal(&reserve, journal.table().booked_disk_mib(), now.wall_ms) {
                Some(reason) => JournalEvent::Ended {
                    end: JobEnd::Refused { reason },
                    end_boot_ns: None,
                },
                None => match reserve.pin.digest() {
                    Ok(pin_digest) => JournalEvent::Reserved {
                        reserve,
                        pin_digest,
                    },
                    Err(_) => JournalEvent::Ended {
                        end: JobEnd::Refused {
                            reason: "pin_unencodable".to_owned(),
                        },
                        end_boot_ns: None,
                    },
                },
            };
        self.record_and_answer(journal, &key, peer, event, &now)
    }

    /// Steps 4 to 7 of the reserve: the reason the key is refused for good,
    /// or `None`.
    fn reserve_refusal(
        &self,
        reserve: &JobReserve,
        booked_mib: u64,
        now_ms: u64,
    ) -> Option<String> {
        let admission = &self.parts().admission;
        if let Some(reason) = admission.controls().refusal() {
            return Some(reason);
        }
        let skew_ms = admission
            .job_settings()
            .submit_skew_secs
            .saturating_mul(1_000);
        if now_ms.saturating_add(skew_ms) < reserve.issued_at_ms || now_ms > reserve.not_after_ms {
            return Some("outside_window".to_owned());
        }
        if reserve.pin.request.maximum_secs == 0 {
            return Some("maximum_zero".to_owned());
        }
        if let Err(reason) = admission.admit_pin(&reserve.pin) {
            return Some(reason);
        }
        if let Err(reason) = admission.disk_room(booked_mib, reserve.pin.request.disk_mib) {
            return Some(reason);
        }
        placement(self.parts().devices.as_ref(), reserve, Placing::AtReserve).err()
    }

    /// `Release` (design 7.1): withdraws a `Held` key that has no accepted
    /// submit. A key the node never saw is closed the same way, so a reserve
    /// that arrives after its release starts nothing; an ended key answers
    /// its receipt; a key past `Held` is refused.
    #[must_use]
    pub fn release(&self, peer: EntityId, key: &str) -> JobAnswer {
        let mut book = self.lock();
        let now = self.now();
        let journal = match admitting(&mut book) {
            Ok(journal) => journal,
            Err(answer) => return answer,
        };
        if let Some(answer) = Self::chunk_key_refusal(journal, key, peer) {
            return answer;
        }
        let state = match journal.table().get(key) {
            Some(known) if known.issuer != peer => {
                return JobAnswer::Refused(JobRefusal::NotTheKeysIssuer);
            }
            Some(known) => Some(known.state),
            None => None,
        };
        match state {
            None | Some(JobState::Held) => {
                let event = withdrawn();
                self.record_and_answer(journal, key, peer, event, &now)
            }
            Some(JobState::Ended) => {
                let known = journal.table().get(key).cloned();
                known.map_or_else(busy, |known| {
                    self.receipt_answer(&known, journal.epoch(), &now)
                })
            }
            Some(state) => JobAnswer::Refused(JobRefusal::NotReleasable { state }),
        }
    }

    /// `Submit` (design 7.3): runs a key this node holds as `Held` for the
    /// same issuer and the same pin. Journaled before it is answered; the
    /// staging worker then runs outside the request.
    #[must_use]
    pub fn submit(&self, peer: EntityId, signed: SignedJobSubmit) -> JobAnswer {
        if peer != signed.submit.issuer {
            return JobAnswer::Refused(JobRefusal::NotIssuer);
        }
        if signed.verify(self.parts().signer.as_ref()).is_err() {
            return JobAnswer::Refused(JobRefusal::SubmitSignatureInvalid);
        }
        if let Some(first) = signed.submit.continues.clone() {
            return self.renew(peer, &first, signed);
        }
        let key = signed.submit.key.clone();
        let answer = {
            let mut book = self.lock();
            let now = self.now();
            let journal = match admitting(&mut book) {
                Ok(journal) => journal,
                Err(answer) => return answer,
            };
            if let Some(answer) = Self::chunk_key_refusal(journal, &key, peer) {
                return answer;
            }
            let known = journal.table().get(&key).cloned();
            // A key that already took effect is answered first: the
            // issuer, the pin and the slot must be the same.
            if let Some(known) = &known {
                if known.issuer != peer {
                    return JobAnswer::Refused(JobRefusal::NotTheKeysIssuer);
                }
                let digest = signed.submit.pin.digest().ok();
                let other_slot = known
                    .reserve
                    .as_ref()
                    .is_some_and(|reserve| reserve.slot != signed.submit.slot);
                if (known.pin_digest.is_some() && digest != known.pin_digest) || other_slot {
                    return JobAnswer::Refused(JobRefusal::KeyConflict);
                }
                if known.state != JobState::Held {
                    return self.receipt_answer(known, journal.epoch(), &now);
                }
            }
            // Before any new record (the key's close for a missing reserve,
            // its close past the window, its acceptance), the issuer's
            // authority, read again under the lock: a grant that ended after
            // the gate is refused as the gate refuses it, with nothing
            // journaled.
            if let Err(not_live) = self.parts().admission.issuer_live(peer) {
                return JobAnswer::Refused(not_live.refusal);
            }
            let Some(known) = known else {
                let event = JournalEvent::Ended {
                    end: JobEnd::Refused {
                        reason: "not_reserved".to_owned(),
                    },
                    end_boot_ns: None,
                };
                return self.record_and_answer(journal, &key, peer, event, &now);
            };
            // A reserve past its window is closed here, before any submit
            // could take it up, even when the tick has not closed it yet.
            if known
                .reserve
                .as_ref()
                .is_some_and(|reserve| now.wall_ms > reserve.not_after_ms)
            {
                return self.record_and_answer(journal, &key, peer, withdrawn(), &now);
            }
            let event = match self.submit_refusal(&signed, &known, now.wall_ms) {
                Some(reason) => JournalEvent::Ended {
                    end: JobEnd::Refused { reason },
                    end_boot_ns: None,
                },
                None => JournalEvent::Accepted { submit: signed },
            };
            self.record_and_answer(journal, &key, peer, event, &now)
        };
        if let JobAnswer::Receipt(receipt) = &answer
            && receipt.receipt.state == JobState::Accepted
        {
            self.start_staging(key);
        }
        answer
    }

    /// Step 3 of the submit: the reason the key is refused for good, or
    /// `None`.
    fn submit_refusal(
        &self,
        signed: &SignedJobSubmit,
        held: &NodeKey,
        now_ms: u64,
    ) -> Option<String> {
        let submit = &signed.submit;
        let Some(reserve) = held.reserve.as_ref() else {
            return Some("not_reserved".to_owned());
        };
        if now_ms > submit.not_after_ms {
            return Some("submit_expired".to_owned());
        }
        if submit.maximum_secs == 0 || submit.maximum_secs > reserve.pin.request.maximum_secs {
            return Some("maximum_above_pin".to_owned());
        }
        let admission = &self.parts().admission;
        if let Some(reason) = admission.controls().refusal() {
            return Some(reason);
        }
        if admission.template_digest(&reserve.pin.template).as_deref()
            != Some(reserve.pin.template_digest.as_str())
        {
            return Some("template_changed".to_owned());
        }
        None
    }

    /// A session's renewal (pass 34, 2.5; row W1): a signed submit whose
    /// key pays the next chunk of the run launched under `first`. It needs
    /// no reserve and passes every check a submit passes; then the run's
    /// `renewed` record moves its cutoff forward by the submit's maximum,
    /// from the end of the paid time so far, and only after that record is
    /// on disk is the scope asked to move its cutoff. The chunk's key never
    /// starts a process and never holds a lease. A renewal the run can no
    /// longer take (it ended, it is ending, or its cutoff is too near) is
    /// written down as the chunk key's `Refused` end: it continues nothing
    /// and bills nothing. A renewal sent again answers the chunk's receipt.
    /// Two conditions that will pass answer `Busy` and write nothing: the
    /// scope has not yet taken the last renewal of a run that can still
    /// take one, or the node's fold does not hold the issuer's authority
    /// heads yet.
    fn renew(&self, peer: EntityId, first: &str, signed: SignedJobSubmit) -> JobAnswer {
        let key = signed.submit.key.clone();
        let (answer, armed) = {
            let mut book = self.lock();
            let now = self.now();
            let journal = match admitting(&mut book) {
                Ok(journal) => journal,
                Err(answer) => return answer,
            };
            let epoch = journal.epoch();
            // A chunk or key that already took effect is answered first.
            if let Some((holder, chunk)) = journal.table().chunk(&key) {
                if holder.issuer != peer {
                    return JobAnswer::Refused(JobRefusal::NotTheKeysIssuer);
                }
                let same_terms = holder.key == first
                    && holder.pin_digest == signed.submit.pin.digest().ok()
                    && holder
                        .reserve
                        .as_ref()
                        .is_some_and(|reserve| reserve.slot == signed.submit.slot);
                if !same_terms {
                    return JobAnswer::Refused(JobRefusal::KeyConflict);
                }
                let holder = holder.clone();
                return self.chunk_answer(&holder, chunk, epoch, &now);
            }
            if let Some(known) = journal.table().get(&key) {
                if known.issuer != peer {
                    return JobAnswer::Refused(JobRefusal::NotTheKeysIssuer);
                }
                let known = known.clone();
                return self.receipt_answer(&known, epoch, &now);
            }
            if let Err(not_live) = self.parts().admission.issuer_live(peer) {
                return JobAnswer::Refused(not_live.refusal);
            }
            // The run's own end first: a workload that exited before this
            // tick read its end takes no renewal.
            let live = journal
                .table()
                .get(first)
                .filter(|holder| holder.issuer == peer && holder.renewable())
                .cloned();
            if let Some(live) = live
                && self.read_unit_end(&mut book, &live, &now).is_err()
            {
                return busy();
            }
            // Only the issuer's own run that can still take a renewal waits
            // for the scope: the tick asks again only for a live run, so an
            // ended or ending run falls through to its `Refused` end below,
            // and another issuer's key tells nothing by a `Busy`.
            let pending = book.journal.as_ref().and_then(|journal| {
                let holder = journal
                    .table()
                    .get(first)
                    .filter(|holder| holder.issuer == peer && holder.renewable())?;
                let cutoff = holder.launch.as_ref()?.cutoff_boot_ns;
                (!holder.renewals.is_empty() && book.armed_cutoffs.get(first) != Some(&cutoff))
                    .then_some(())
            });
            if pending.is_some() {
                // The scope has not taken the last renewal yet: until it
                // does, the run's armed cutoff is earlier than the journal's.
                return busy();
            }
            // The renewal's own time: the end read above may have waited on
            // the service manager, and the scope's deadline counts from the
            // moment the renewal is journaled.
            let now = self.now();
            let journal = match admitting(&mut book) {
                Ok(journal) => journal,
                Err(answer) => return answer,
            };
            let holder = journal
                .table()
                .get(first)
                .filter(|holder| holder.issuer == peer)
                .cloned();
            let folded = self
                .parts()
                .authority
                .folded(&signed.submit.authority_heads);
            match self.renewal(&signed, holder.as_ref(), &now) {
                // While the node's fold lags the issuer's authority heads, a
                // renewal waits and writes nothing, unless no wait could let
                // it pass: its run ended or came too near its stop, so the
                // wait ends there.
                Ok(_) if !folded => return busy(),
                Err(reason) if !folded && !RENEWAL_REFUSALS_FOR_GOOD.contains(&reason.as_str()) => {
                    return busy();
                }
                Err(reason) => {
                    let event = JournalEvent::Ended {
                        end: JobEnd::Refused { reason },
                        end_boot_ns: None,
                    };
                    (
                        self.record_and_answer(journal, &key, peer, event, &now),
                        None,
                    )
                }
                Ok((holder, from_boot_ns, cutoff_boot_ns)) => {
                    let event = JournalEvent::Renewed {
                        submit: signed,
                        from_boot_ns,
                        cutoff_boot_ns,
                    };
                    match journal.record(&holder.key, peer, &now.boot_id, now.wall_ms, event) {
                        Ok(entry) => {
                            let entry = entry.clone();
                            let chunk = u32::try_from(entry.renewals.len()).unwrap_or(u32::MAX);
                            let answer = self.chunk_answer(&entry, chunk, epoch, &now);
                            (answer, Some((entry.key, cutoff_boot_ns)))
                        }
                        Err(error) => {
                            log_write_error(&key, &error);
                            (busy(), None)
                        }
                    }
                }
            }
        };
        if let Some((first, cutoff_boot_ns)) = armed {
            self.arm_renewed_cutoff(&first, cutoff_boot_ns);
        }
        answer
    }

    /// Whether `signed` may renew `holder`'s run now, and if so the run, the
    /// end of its paid time and its cutoff after this chunk.
    ///
    /// # Errors
    ///
    /// The reason the chunk's key is refused for good.
    fn renewal(
        &self,
        signed: &SignedJobSubmit,
        holder: Option<&NodeKey>,
        now: &ReceiptClock,
    ) -> Result<(NodeKey, u64, u64), String> {
        let submit = &signed.submit;
        let Some(holder) = holder else {
            return Err("continues_unknown".to_owned());
        };
        let (Some(reserve), Some(launch)) = (holder.reserve.as_ref(), holder.launch.as_ref())
        else {
            return Err("continues_ended".to_owned());
        };
        let admission = &self.parts().admission;
        // The run's own pin and slot: a renewal pays for the run it names
        // and for nothing else.
        if submit.pin.digest().ok() != holder.pin_digest || submit.slot != reserve.slot {
            return Err("continues_other_pin".to_owned());
        }
        let Some(session_max_secs) = admission.template_session_max_secs(&reserve.pin.template)
        else {
            return Err("template_not_session".to_owned());
        };
        if now.wall_ms > submit.not_after_ms {
            return Err("submit_expired".to_owned());
        }
        if submit.maximum_secs == 0 || submit.maximum_secs > reserve.pin.request.maximum_secs {
            return Err("maximum_above_pin".to_owned());
        }
        if let Some(reason) = admission.controls().refusal() {
            return Err(reason);
        }
        if admission.template_digest(&reserve.pin.template).as_deref()
            != Some(reserve.pin.template_digest.as_str())
        {
            return Err("template_changed".to_owned());
        }
        // The run must still be running in this boot, with its cutoff far
        // enough off that the scope can move it before it stops the unit.
        let stop_grace_ns = admission.stop_grace_secs().saturating_mul(NANOS_PER_SEC);
        let too_late = launch.boot_id != now.boot_id
            || now
                .boot_ns
                .saturating_add(stop_grace_ns)
                .saturating_add(RENEWAL_MARGIN_NS)
                >= launch.cutoff_boot_ns;
        if !holder.renewable() || too_late {
            return Err("continues_ended".to_owned());
        }
        let from_boot_ns = launch.cutoff_boot_ns;
        let Some(cutoff_boot_ns) = submit
            .maximum_secs
            .checked_mul(NANOS_PER_SEC)
            .and_then(|chunk_ns| from_boot_ns.checked_add(chunk_ns))
        else {
            return Err("session_max_reached".to_owned());
        };
        let longest_ns = session_max_secs.saturating_mul(NANOS_PER_SEC);
        if cutoff_boot_ns.saturating_sub(launch.launch_boot_ns) > longest_ns {
            return Err("session_max_reached".to_owned());
        }
        Ok((holder.clone(), from_boot_ns, cutoff_boot_ns))
    }

    /// Asks the scope to move the run's cutoff to `cutoff_boot_ns`. One it
    /// does not take is asked again at each tick, and after a restart
    /// (`rearm_renewed_cutoffs`); if it never takes it, the run ends at its
    /// old cutoff and the renewed chunk bills nothing.
    pub(super) fn arm_renewed_cutoff(&self, first: &str, cutoff_boot_ns: u64) {
        let id = super::JobKeyId::for_key(first);
        match self.parts().units.renew(&id, cutoff_boot_ns) {
            // An older ask that finishes after a newer one keeps the newer
            // value: the scope moves a cutoff only forward.
            Ok(()) => {
                self.lock()
                    .armed_cutoffs
                    .entry(first.to_owned())
                    .and_modify(|held| *held = (*held).max(cutoff_boot_ns))
                    .or_insert(cutoff_boot_ns);
            }
            // A scope that cannot move a cutoff answers so at every tick:
            // the run ends at its old cutoff, and the line is no news.
            Err(error @ RenewRefusal::Unsupported) => {
                tracing::debug!(key = first, %error, "session cutoff not moved; the scope does not renew");
            }
            Err(error) => {
                tracing::warn!(key = first, %error, "session cutoff not moved; the next tick asks again");
            }
        }
    }

    /// A request on a path that takes no chunk (`Reserve`, `Release`, a
    /// submit without `continues`) that names a renewed chunk's key (row
    /// W1): refused as another issuer's key, or as a key conflict, with
    /// nothing journaled.
    fn chunk_key_refusal(journal: &JobJournal, key: &str, peer: EntityId) -> Option<JobAnswer> {
        let (holder, _) = journal.table().chunk(key)?;
        Some(JobAnswer::Refused(if holder.issuer == peer {
            JobRefusal::KeyConflict
        } else {
            JobRefusal::NotTheKeysIssuer
        }))
    }

    /// The stop of a key (design 7.2 rules 1 and 3). Before the launch
    /// commit it closes the key as `Withdrawn`, also a key the node never
    /// saw; after it the key moves to `Ending` and its unit is stopped. An
    /// ended key answers its receipt. A renewed run's key (row W1), its
    /// first key or a chunk's, stops the run it holds, unless its own slice
    /// is already over, which answers its receipt and changes nothing. The
    /// stop is decided and journaled before any receipt is signed.
    #[must_use]
    pub fn stop(&self, peer: EntityId, key: &str) -> JobStatusAnswer {
        let mut book = self.lock();
        let now = self.now();
        let journal = match answering(&mut book) {
            Ok(journal) => journal,
            Err(answer) => return answer,
        };
        let sliced = journal.table().chunk(key).or_else(|| {
            journal
                .table()
                .get(key)
                .filter(|known| !known.renewals.is_empty())
                .map(|known| (known, 0))
        });
        if let Some((holder, chunk)) = sliced {
            if holder.issuer != peer {
                return JobStatusAnswer::Refused(JobRefusal::NotTheKeysIssuer);
            }
            let holder = holder.clone();
            let epoch = journal.epoch();
            let slice_over = chunk_receipt_of(
                &holder,
                chunk,
                self.last_tick_boot_ns(&holder),
                self.parts().machine,
                epoch,
                &now,
            )
            .is_some_and(|slice| slice.state == JobState::Ended);
            if !slice_over {
                match holder.state {
                    JobState::Launching | JobState::Running => {
                        if let Err(error) =
                            self.begin_ending(journal, &holder, EndingCause::Stopped, &now)
                        {
                            log_write_error(key, &error);
                            return status_busy();
                        }
                    }
                    // A stop the service manager did not take: ask again.
                    JobState::Ending => self.stop_unit(&holder.key),
                    _ => {}
                }
            }
            let Some(holder) = journal.table().get(&holder.key).cloned() else {
                return status_busy();
            };
            return match self.chunk_answer(&holder, chunk, epoch, &now) {
                JobAnswer::Receipt(signed) => JobStatusAnswer::Known(signed),
                _ => status_busy(),
            };
        }
        let state = match journal.table().get(key) {
            Some(known) if known.issuer != peer => {
                return JobStatusAnswer::Refused(JobRefusal::NotTheKeysIssuer);
            }
            Some(known) => Some(known.state),
            None => None,
        };
        let answer = match state {
            None | Some(JobState::Held | JobState::Accepted | JobState::Staging) => {
                self.record_and_answer(journal, key, peer, withdrawn(), &now)
            }
            Some(JobState::Launching | JobState::Running) => {
                let Some(known) = journal.table().get(key).cloned() else {
                    return status_busy();
                };
                match self.begin_ending(journal, &known, EndingCause::Stopped, &now) {
                    Ok(()) => journal
                        .table()
                        .get(key)
                        .cloned()
                        .map_or_else(busy, |known| {
                            self.receipt_answer(&known, journal.epoch(), &now)
                        }),
                    Err(error) => {
                        log_write_error(key, &error);
                        busy()
                    }
                }
            }
            Some(JobState::Ending) => {
                self.stop_unit(key);
                let known = journal.table().get(key).cloned();
                known.map_or_else(busy, |known| {
                    self.receipt_answer(&known, journal.epoch(), &now)
                })
            }
            Some(JobState::Ended) => {
                let known = journal.table().get(key).cloned();
                known.map_or_else(busy, |known| {
                    self.receipt_answer(&known, journal.epoch(), &now)
                })
            }
        };
        match answer {
            JobAnswer::Receipt(signed) => JobStatusAnswer::Known(signed),
            _ => status_busy(),
        }
    }

    /// The key's newest receipt (`Find`, `Status`): `Known`, `Absent` with
    /// the journal's epoch, history lost, or `Busy` while not swept.
    #[must_use]
    pub fn find(&self, peer: EntityId, key: &str) -> JobStatusAnswer {
        let mut book = self.lock();
        let now = self.now();
        let journal = match answering(&mut book) {
            Ok(journal) => journal,
            Err(answer) => return answer,
        };
        let epoch = journal.epoch();
        match self.any_receipt(journal, key, &now) {
            None => JobStatusAnswer::Absent {
                epoch: epoch.to_hex(),
            },
            Some((issuer, _)) if issuer != peer => {
                JobStatusAnswer::Refused(JobRefusal::NotTheKeysIssuer)
            }
            Some((_, JobAnswer::Receipt(signed))) => JobStatusAnswer::Known(signed),
            Some(_) => status_busy(),
        }
    }

    /// The engine's own end of a key: a revoke it saw (EN-4: a revoke stops
    /// what it authorised) or a payload directory over its disk request. A
    /// launched key moves to `Ending` with `cause` and its unit is stopped;
    /// a key that has not launched is closed as `Withdrawn`.
    ///
    /// # Errors
    ///
    /// Why the change was not made (the gate is closed, or the record did
    /// not land).
    pub fn end_key(&self, key: &str, cause: EndingCause) -> Result<(), String> {
        let mut book = self.lock();
        let now = self.now();
        if book.gate != NodeGate::Open {
            return Err(format!("job_service.gate_closed: {:?}", book.gate));
        }
        let Some(journal) = book.journal.as_mut() else {
            return Err("job_service.history_lost".to_owned());
        };
        let Some(known) = journal.table().get(key).cloned() else {
            return Ok(());
        };
        match known.state {
            JobState::Held | JobState::Accepted | JobState::Staging => journal
                .record(key, known.issuer, &now.boot_id, now.wall_ms, withdrawn())
                .map(drop)
                .map_err(|error| error.to_string()),
            JobState::Launching | JobState::Running => self
                .begin_ending(journal, &known, cause, &now)
                .map_err(|error| error.to_string()),
            JobState::Ending => {
                self.stop_unit(key);
                Ok(())
            }
            JobState::Ended => Ok(()),
        }
    }

    /// Moves a launched key to `Ending { cause }`, and only once that record
    /// is on disk asks the service manager to stop its unit. A key whose
    /// unit already ended (its end record is complete) ends as that record
    /// says: a stop that came after the exit does not rename its end.
    ///
    /// # Errors
    ///
    /// The record did not land; the unit was not asked to stop.
    pub(super) fn begin_ending(
        &self,
        journal: &mut JobJournal,
        known: &NodeKey,
        cause: EndingCause,
        now: &ReceiptClock,
    ) -> Result<(), JournalWriteError> {
        let control_dir = known.id.control_dir(&self.paths().state_dir);
        if let Ok(Some(end_record)) = read_end_record(&control_dir, &known.key)
            && end_record.cgroup_empty
        {
            let event = JournalEvent::Ended {
                end: end_of(&end_record, known.ending_cause),
                end_boot_ns: Some(end_record.end_boot_ns),
            };
            journal.record(&known.key, known.issuer, &now.boot_id, now.wall_ms, event)?;
            return Ok(());
        }
        journal.record(
            &known.key,
            known.issuer,
            &now.boot_id,
            now.wall_ms,
            JournalEvent::Ending { cause },
        )?;
        self.stop_unit(&known.key);
        Ok(())
    }

    /// Asks the service manager to stop the key's unit. A stop that is not
    /// taken is asked again at the next tick, which sees the key `Ending`.
    pub(super) fn stop_unit(&self, key: &str) {
        let id = super::JobKeyId::for_key(key);
        if let Err(error) = self.parts().units.stop(&id) {
            tracing::warn!(key, %error, "job unit stop not taken; the next tick asks again");
        }
    }
}

/// A `Withdrawn` end, for a key that never launched.
pub(super) fn withdrawn() -> JournalEvent {
    JournalEvent::Ended {
        end: JobEnd::Withdrawn,
        end_boot_ns: None,
    }
}

pub(super) fn log_write_error(key: &str, error: &JournalWriteError) {
    tracing::error!(key, %error, "job journal record did not land; nothing was answered for it");
}
