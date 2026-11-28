//! The status side's answers that admission does not give (design pass 33,
//! 7.1 and 7.6 step 5; row R4): one page of the asker's keys (`Keys`), a
//! checkpoint notice (`Signal`), one returnable output (`Fetch`), the
//! issuer's custody acknowledgement (`Ack`), and the cleaning of an
//! acknowledged key's payload once its keep time has passed. `Find`,
//! `Status` and `Stop` are admission's [`NodeJobs::find`] and
//! [`NodeJobs::stop`].
//!
//! Every answer that names a key goes only to the issuer the journal
//! recorded for it, and `Keys` lists only the asker's keys. While the node
//! recovers each answers `Busy`; once its history is lost each answers
//! `HistoryLost`.
//!
//! The node keeps the only copy of an output until the issuer acknowledges
//! custody: nothing cleans an unacknowledged payload, by a timer or
//! otherwise. After the `Ack` the payload stays for `jobs.receipts.keep_days`
//! and is then removed; its own bytes count in the disk's free space until
//! then, and the key's booking ends at the `Ack`.

use std::io::Read as _;
use std::path::Path;

use oneiron::EntityId;
use sha2::{Digest as _, Sha256};

use super::NodeJobs;
use super::admission::{answering, log_write_error, status_busy};
use super::journal::{JournalEvent, KeyTable, NodeKey};
use super::receipt::chunk_receipt_of;
use crate::gpu_execution_node::wire::{
    JobAnswer, JobEnd, JobRefusal, JobState, JobStatusAnswer, KeyEntry, KeyPage, OutputDigest,
    OutputsState,
};

/// The most bytes the entries of one `Keys` page take in the codec, so the
/// page with its envelope stays under the transport's 1 MiB message bound.
pub const KEYS_PAGE_MAX_BYTES: usize = 786_432;

const MILLIS_PER_DAY: u64 = 86_400_000;

fn not_fetchable(why: impl Into<String>) -> JobStatusAnswer {
    JobStatusAnswer::Refused(JobRefusal::OutputNotFetchable { why: why.into() })
}

/// The key `key` of `peer` in `journal`'s table: `Absent` with the epoch, or
/// `NotTheKeysIssuer` for another issuer's key. Callers pass
/// [`super::KeyTable::holder`], so a renewed chunk's key (row W1) acts on
/// the run its first key holds: its notice, outputs, acknowledgement and
/// log.
pub(super) fn own_key(
    known: Option<&NodeKey>,
    peer: EntityId,
    epoch_hex: String,
) -> Result<NodeKey, JobStatusAnswer> {
    match known {
        None => Err(JobStatusAnswer::Absent { epoch: epoch_hex }),
        Some(known) if known.issuer != peer => {
            Err(JobStatusAnswer::Refused(JobRefusal::NotTheKeysIssuer))
        }
        Some(known) => Ok(known.clone()),
    }
}

impl NodeJobs {
    /// `Keys { after }`: the keys of `peer` the journal holds, live and
    /// ended, in key order after `after`, each ended one with its signed
    /// terminal receipt, in a page under [`KEYS_PAGE_MAX_BYTES`]. `next`
    /// names the page's last key while more follow; the issuer has every
    /// key only once it read a page with no `next`.
    #[must_use]
    pub fn keys_page(&self, peer: EntityId, after: Option<&str>) -> JobStatusAnswer {
        let now = self.now();
        let mut book = self.lock();
        let journal = match answering(&mut book) {
            Ok(journal) => journal,
            Err(answer) => return answer,
        };
        let epoch = journal.epoch();
        let mut entries = Vec::new();
        let mut used = 0usize;
        let mut next = None;
        let table = journal.table();
        // The keys of the journal and each renewed chunk's key (row W1), in
        // key order.
        let mut listed: Vec<&str> = table
            .iter()
            .filter(|known| known.issuer == peer)
            .map(|known| known.key.as_str())
            .chain(
                table
                    .chunk_keys()
                    .filter(|(_, first)| table.get(first).is_some_and(|first| first.issuer == peer))
                    .map(|(chunk, _)| chunk),
            )
            .filter(|key| after.is_none_or(|after| *key > after))
            .collect();
        listed.sort_unstable();
        for key in listed {
            let Some(entry) = self.key_entry(table, key, epoch, &now) else {
                // An unsigned receipt is no receipt: the issuer asks again.
                return status_busy();
            };
            let Ok(encoded) = oneiron_organ_protocol::to_vec(&entry) else {
                return status_busy();
            };
            if !entries.is_empty() && used.saturating_add(encoded.len()) > KEYS_PAGE_MAX_BYTES {
                next = entries.last().map(|entry: &KeyEntry| entry.key.clone());
                break;
            }
            used = used.saturating_add(encoded.len());
            entries.push(entry);
        }
        JobStatusAnswer::Keys(KeyPage { entries, next })
    }

    /// One key's entry in a `Keys` page: its state and, once it ended, its
    /// signed terminal receipt. A renewed run's keys (row W1) each list
    /// their own slice's state. `None` when a receipt could not be signed.
    fn key_entry(
        &self,
        table: &KeyTable,
        key: &str,
        epoch: super::JournalEpoch,
        now: &super::ReceiptClock,
    ) -> Option<KeyEntry> {
        let answer = match table.get(key) {
            Some(known) if known.renewals.is_empty() => {
                if known.state != JobState::Ended {
                    return Some(KeyEntry {
                        key: key.to_owned(),
                        state: known.state,
                        ended: None,
                    });
                }
                self.receipt_answer(known, epoch, now)
            }
            Some(first) => self.chunk_answer(first, 0, epoch, now),
            None => {
                let (first, chunk) = table.chunk(key)?;
                self.chunk_answer(first, chunk, epoch, now)
            }
        };
        let JobAnswer::Receipt(signed) = answer else {
            return None;
        };
        let state = signed.receipt.state;
        Some(KeyEntry {
            key: key.to_owned(),
            state,
            ended: (state == JobState::Ended).then_some(signed),
        })
    }

    /// `Signal { key, signal }`: a checkpoint notice. It reaches the
    /// workload only while the key runs and only when its template names an
    /// operating-system signal for it; otherwise it is a no-op. Either way
    /// the notice is answered `Acknowledged`: it never stops the unit,
    /// moves the cutoff or changes the key.
    #[must_use]
    pub fn signal(&self, peer: EntityId, key: &str, signal: &str) -> JobStatusAnswer {
        let known = {
            let mut book = self.lock();
            let journal = match answering(&mut book) {
                Ok(journal) => journal,
                Err(answer) => return answer,
            };
            let epoch = journal.epoch().to_hex();
            match own_key(journal.table().holder(key), peer, epoch) {
                Ok(known) => known,
                Err(answer) => return answer,
            }
        };
        let named = known.reserve.as_ref().and_then(|reserve| {
            self.parts()
                .admission
                .template_signal(&reserve.pin.template)
        });
        if let Some(os_signal) = named
            && known.state == JobState::Running
            && let Err(error) = self.parts().units.signal(&known.id, &os_signal)
        {
            tracing::warn!(key, notice = signal, %error, "checkpoint notice not delivered");
        }
        JobStatusAnswer::Acknowledged
    }

    /// `Fetch { key, name }`: the bytes of one output of an ended key that
    /// the node hashed as returnable, read again beneath the key's `out/`
    /// without following a link, at most the returnable bound, and only
    /// when they still match the digest the receipt carries. The issuer
    /// checks the digest again against its stored receipt.
    #[must_use]
    pub fn fetch(&self, peer: EntityId, key: &str, name: &str) -> JobStatusAnswer {
        // The holder's id names the payload: a renewed chunk's key reads its
        // run's (row W1).
        let (digest, holder_id) = {
            let mut book = self.lock();
            let journal = match answering(&mut book) {
                Ok(journal) => journal,
                Err(answer) => return answer,
            };
            let epoch = journal.epoch().to_hex();
            let known = match own_key(journal.table().holder(key), peer, epoch) {
                Ok(known) => known,
                Err(answer) => return answer,
            };
            if known.state != JobState::Ended {
                return not_fetchable(format!("key_not_ended: {:?}", known.state));
            }
            if known.cleaned {
                return not_fetchable("payload_cleaned");
            }
            let OutputsState::Hashed(outputs) = &known.outputs else {
                return not_fetchable(format!("outputs_not_hashed: {:?}", known.outputs));
            };
            match outputs.iter().find(|output| output.name == name) {
                Some(output) if output.returnable => (output.clone(), known.id.clone()),
                Some(_) => return not_fetchable(format!("not_returnable: {name}")),
                None => return not_fetchable(format!("not_an_output: {name}")),
            }
        };
        let bound = self.parts().admission.job_settings().returnable_bound();
        let payload_dir = holder_id.payload_dir(&self.paths().work_dir);
        match read_output(&payload_dir, &digest, bound) {
            Ok(bytes) => JobStatusAnswer::Output { bytes },
            Err(why) => not_fetchable(why),
        }
    }

    /// `Ack { key }`: the issuer holds every returnable output of the key it
    /// wants (or wants none). Journaled once; a repeat answers the same. A
    /// key that has not ended is refused; a launched key whose outputs are
    /// not hashed yet answers `Busy`, as the hashing will end.
    #[must_use]
    pub fn acknowledge(&self, peer: EntityId, key: &str) -> JobStatusAnswer {
        let now = self.now();
        let mut book = self.lock();
        let journal = match answering(&mut book) {
            Ok(journal) => journal,
            Err(answer) => return answer,
        };
        let epoch = journal.epoch().to_hex();
        let known = match own_key(journal.table().holder(key), peer, epoch) {
            Ok(known) => known,
            Err(answer) => return answer,
        };
        // A renewed run's payload is acknowledged through the key whose slice
        // holds the run's end, never through a slice the run went past or
        // never reached (row W1): those carry no outputs.
        if !known.renewals.is_empty() {
            let renewal = journal.table().chunk(key).map_or(0, |(_, renewal)| renewal);
            let slice = chunk_receipt_of(
                &known,
                renewal,
                self.last_tick_boot_ns(&known),
                self.parts().machine,
                journal.epoch(),
                &now,
            );
            let holds_end = slice.as_ref().is_some_and(|slice| {
                slice.state == JobState::Ended
                    && !matches!(slice.end, Some(JobEnd::Continued | JobEnd::Withdrawn))
            });
            if !holds_end {
                let state = slice.map_or(known.state, |slice| slice.state);
                return JobStatusAnswer::Refused(JobRefusal::NotAcknowledgeable { state });
            }
        }
        if known.acknowledged_at_ms.is_some() {
            return JobStatusAnswer::Acknowledged;
        }
        if known.state != JobState::Ended {
            return JobStatusAnswer::Refused(JobRefusal::NotAcknowledgeable { state: known.state });
        }
        if !known.acknowledgeable() {
            return status_busy();
        }
        // A renewed chunk's key acknowledges its run's payload, which its
        // first key holds (row W1).
        match journal.record(
            &known.key,
            known.issuer,
            &now.boot_id,
            now.wall_ms,
            JournalEvent::Acknowledged,
        ) {
            Ok(_) => JobStatusAnswer::Acknowledged,
            Err(error) => {
                log_write_error(key, &error);
                status_busy()
            }
        }
    }

    /// The tick's cleaning (design 7.6 step 5): removes the payload
    /// directory of each key the issuer acknowledged at least
    /// `jobs.receipts.keep_days` ago, then journals `cleaned`. A removal
    /// that fails is tried again at the next tick. An unacknowledged key is
    /// never cleaned here, and nothing is cleaned while a key holds the quiet
    /// lease. One hold of the admission lock runs from that check to the
    /// last removal and its record, so a quiet reserve cannot take the lease
    /// in between.
    pub(super) fn clean_acknowledged_payloads(&self) {
        let keep_ms = self
            .parts()
            .admission
            .job_settings()
            .receipt_keep_days
            .saturating_mul(MILLIS_PER_DAY);
        let now = self.now();
        let mut book = self.lock();
        let Some(journal) = book.journal.as_mut() else {
            return;
        };
        if super::quiet_lease::holder(journal.table()).is_some() {
            return;
        }
        let due: Vec<NodeKey> = journal
            .table()
            .iter()
            .filter(|known| !known.cleaned)
            .filter(|known| {
                known
                    .acknowledged_at_ms
                    .is_some_and(|at| now.wall_ms >= at.saturating_add(keep_ms))
            })
            .cloned()
            .collect();
        for known in due {
            let payload_dir = known.id.payload_dir(&self.paths().work_dir);
            match std::fs::remove_dir_all(&payload_dir) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    tracing::warn!(key = %known.key, %error, "acknowledged payload not cleaned; the next tick tries again");
                    continue;
                }
            }
            if let Err(error) = journal.record(
                &known.key,
                known.issuer,
                &now.boot_id,
                now.wall_ms,
                JournalEvent::Cleaned,
            ) {
                log_write_error(&known.key, &error);
            }
        }
    }
}

/// Reads `<payload_dir>/out/<name>` as [`super::outputs::hash_outputs`] opened
/// it: beneath `out/`, without following a link, a regular file, at most
/// `bound` bytes, and with the digest the receipt names.
fn read_output(payload_dir: &Path, digest: &OutputDigest, bound: u64) -> Result<Vec<u8>, String> {
    use rustix::fs::{FileType, Mode, OFlags};
    let name = digest.name.as_str();
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        return Err(format!("not_a_plain_name: {name}"));
    }
    let directory = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let base = rustix::fs::open(payload_dir, directory, Mode::empty())
        .map_err(|error| format!("payload_dir: {error}"))?;
    let out = rustix::fs::openat(&base, "out", directory, Mode::empty())
        .map_err(|error| format!("out: {error}"))?;
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let descriptor = rustix::fs::openat(&out, name, flags, Mode::empty())
        .map_err(|error| format!("{name}: {error}"))?;
    let regular = rustix::fs::fstat(&descriptor)
        .is_ok_and(|stat| FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile);
    if !regular {
        return Err(format!("{name}: not a regular file"));
    }
    let mut bytes = Vec::new();
    std::fs::File::from(descriptor)
        .take(bound.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("{name}: {error}"))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > bound {
        return Err(format!(
            "{name}: over the returnable bound of {bound} bytes"
        ));
    }
    let sha256 = oneiron_hex::encode(&Sha256::digest(&bytes));
    if sha256 != digest.sha256 {
        return Err(format!("{name}: changed since it was hashed"));
    }
    Ok(bytes)
}
