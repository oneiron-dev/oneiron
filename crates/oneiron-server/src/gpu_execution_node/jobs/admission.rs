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

use oneiron::EntityId;

use super::end::end_of;
use super::job_unit::read_end_record;
use super::journal::{EndingCause, JobJournal, JournalEvent, JournalWriteError, NodeKey};
use super::node_parts::GpuSlotRequest;
use super::receipt::{ReceiptClock, receipt_of, sign_receipt};
use super::{BUSY_RETRY_AFTER_MS, NodeBook, NodeGate, NodeJobs};
use crate::gpu_execution_node::wire::{
    JobAnswer, JobEnd, JobRefusal, JobReserve, JobState, JobStatusAnswer, SignedJobSubmit,
    SlotSelector, WorkloadPin,
};

const MIB: u64 = 1024 * 1024;

/// The GPU slot request a key's pin and slot selector make. The journal
/// books the key's disk at `Reserve`, so the slot claims none of it again.
#[must_use]
pub(super) fn slot_request(key: &str, pin: &WorkloadPin, slot: &SlotSelector) -> GpuSlotRequest {
    GpuSlotRequest {
        key: key.to_owned(),
        device_id: slot.device_id.clone(),
        model: slot.model.clone(),
        min_memory_mib: pin.request.vram_mib,
        disk_bytes: 0,
    }
}

/// The memory a key's pin takes from the machine's floor, in bytes.
#[must_use]
pub(super) fn memory_bytes(pin: &WorkloadPin) -> u64 {
    pin.request.memory_mib.saturating_mul(MIB)
}

fn busy() -> JobAnswer {
    JobAnswer::Busy {
        retry_after_ms: BUSY_RETRY_AFTER_MS,
    }
}

fn status_busy() -> JobStatusAnswer {
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
fn answering(book: &mut NodeBook) -> Result<&mut JobJournal, JobStatusAnswer> {
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
        match sign_receipt(
            receipt_of(key, parts.machine, epoch, now),
            parts.signer.as_ref(),
        ) {
            Ok(signed) => JobAnswer::Receipt(signed),
            Err(error) => {
                tracing::warn!(key = %key.key, %error, "job receipt not signed; answering busy");
                busy()
            }
        }
    }

    fn status_receipt(
        &self,
        key: &NodeKey,
        epoch: super::JournalEpoch,
        now: &ReceiptClock,
    ) -> JobStatusAnswer {
        match self.receipt_answer(key, epoch, now) {
            JobAnswer::Receipt(signed) => JobStatusAnswer::Known(signed),
            _ => status_busy(),
        }
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
        let request = slot_request(&reserve.key, &reserve.pin, &reserve.slot);
        self.parts().devices.could_take(&request).err()
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
        let key = signed.submit.key.clone();
        let answer = {
            let mut book = self.lock();
            let now = self.now();
            let journal = match admitting(&mut book) {
                Ok(journal) => journal,
                Err(answer) => return answer,
            };
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

    /// The stop of a key (design 7.2 rules 1 and 3). Before the launch
    /// commit it closes the key as `Withdrawn`, also a key the node never
    /// saw; after it the key moves to `Ending` and its unit is stopped. An
    /// ended key answers its receipt.
    #[must_use]
    pub fn stop(&self, peer: EntityId, key: &str) -> JobStatusAnswer {
        let mut book = self.lock();
        let now = self.now();
        let journal = match answering(&mut book) {
            Ok(journal) => journal,
            Err(answer) => return answer,
        };
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
        match journal.table().get(key) {
            None => JobStatusAnswer::Absent {
                epoch: epoch.to_hex(),
            },
            Some(known) if known.issuer != peer => {
                JobStatusAnswer::Refused(JobRefusal::NotTheKeysIssuer)
            }
            Some(known) => {
                let known = known.clone();
                self.status_receipt(&known, epoch, &now)
            }
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
