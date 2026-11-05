//! The connection half of a HOST order's prospective capture (FIX 13866):
//! stands the order, then streams its outbox in batches, each with its own
//! summary naming its exact ordinal range and its own acknowledgement, and
//! deletes a batch only after that acknowledgement. The order's term, its
//! release and the managed final drain end the loop; term end and release
//! destroy the standing with its outbox (FIX 13867). The final drain, run once
//! every writer of the process stopped, sends one last batch naming the
//! order's next ordinal and keeps the standing for a later start.

use std::io;
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::Duration;

use oneiron_crypto::HybridPublicKey;
use oneiron_vault_contract::host_legal::{CaptureExtent, CaptureRequest};

use super::collector::{Collector, SummaryCounts};
use crate::Vault;
use crate::deletion::legal_hold::prospective::{self, OrderKey, OutboxEntry};
use crate::error::{Error, Result};

impl super::HostLegalConnection {
    /// Ends on the order's release, its term, a socket error, or after the
    /// final batch of the managed final drain. Managed stop's trigger does
    /// not end it: the final drain runs once every writer stopped.
    pub(super) fn run_prospective(
        mut self,
        vault: &Vault,
        request: CaptureRequest,
        public: HybridPublicKey,
    ) -> Result<()> {
        let key: OrderKey = (request.order, request.generation);
        let request_digest = request.digest()?;
        let attempts = &vault.host_legal_captures.prospective;
        // Attached before it stands: a release either sees this attempt and
        // cancels it, or commits first so that standing is refused.
        let attached = Attached::new(attempts, key, &self.stream)?;
        let attempt = &attached.attempt;
        let check = || {
            if attempt.cancelled.load(Ordering::Acquire) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "legal prospective capture cancelled",
                )
                .into());
            }
            if vault.store.clock.now_recorded_at() >= request.ends_at {
                return Err(
                    io::Error::new(io::ErrorKind::TimedOut, "legal order term ended").into(),
                );
            }
            Ok(())
        };
        {
            let mut wtxn = vault.store.env.write_txn()?;
            check()?;
            prospective::stand_in_txn(&vault.store, &mut wtxn, &request, request_digest)?;
            wtxn.commit()?;
        }
        loop {
            // Sampled before the check: a stop or release after this point
            // either fails the check or moves the generation waited on.
            let seen = vault.store.host_legal_prospective.generation();
            // Sampled before the barrier: once set, every writer of this
            // process has stopped, so the read below is the last one.
            let finishing = attempts.finishing();
            if let Err(error) = check() {
                if vault.store.clock.now_recorded_at() >= request.ends_at {
                    // Term end destroys this generation's standing and outbox.
                    let mut wtxn = vault.store.env.write_txn()?;
                    prospective::end_in_txn(&vault.store, &mut wtxn, key, false)?;
                    wtxn.commit()?;
                }
                return Err(error);
            }
            // The LMDB writer as a barrier: a writer that sealed into this
            // outbox and bumped `seen` has committed or rolled back.
            let outbox = {
                let wtxn = vault.store.env.write_txn()?;
                let outbox = prospective::outbox_in_txn(&vault.store, &wtxn, key)?;
                drop(wtxn);
                outbox
            };
            let Some((next_ordinal, batch)) = outbox else {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "legal prospective order no longer stands",
                )
                .into());
            };
            if batch.is_empty() && !finishing {
                let remaining = request
                    .ends_at
                    .saturating_sub(vault.store.clock.now_recorded_at());
                vault
                    .store
                    .host_legal_prospective
                    .wait_past(seen, Duration::from_secs(remaining));
                continue;
            }
            let first = batch.first().map_or(next_ordinal, |(ordinal, _)| *ordinal);
            if batch
                .iter()
                .zip(first..)
                .any(|((ordinal, _), expected)| *ordinal != expected)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "legal prospective outbox ordinals",
                )
                .into());
            }
            let entries = batch.len() as u64;
            let end = first
                .checked_add(entries)
                .ok_or(Error::ArithmeticOverflow("legal prospective batch"))?;
            // Only the batch that reaches the next ordinal after every writer
            // stopped is final; an earlier slice of a long outbox is not.
            let last = finishing && end == next_ordinal;
            let mut collector = Collector::pinned(&mut self.stream, &public, &request)?;
            let mut counts = SummaryCounts {
                batch_first_ordinal: first,
                batch_entries: entries,
                final_next_ordinal: last.then_some(next_ordinal),
                ..SummaryCounts::default()
            };
            for (_, entry) in &batch {
                match entry {
                    OutboxEntry::SealedRow { sealed, .. } => {
                        collector.stored_component(
                            &sealed.frames,
                            &sealed.descriptor_digest,
                            sealed.plaintext_len,
                            check,
                        )?;
                        counts.messages += 1;
                    }
                    OutboxEntry::SealedEdge { sealed, .. } => collector.stored_component(
                        &sealed.frames,
                        &sealed.descriptor_digest,
                        sealed.plaintext_len,
                        check,
                    )?,
                    OutboxEntry::Missed { message } => counts.missed_messages.push(*message),
                }
            }
            collector.finish_counted(counts, CaptureExtent::ProspectiveMessages, check)?;
            let mut wtxn = vault.store.env.write_txn()?;
            if !prospective::acknowledge_in_txn(
                &vault.store,
                &mut wtxn,
                key,
                request.capture,
                first,
                entries,
            )? {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "legal prospective order no longer stands",
                )
                .into());
            }
            wtxn.commit()?;
            if last {
                // The standing stays for a later start of the same source.
                return Ok(());
            }
        }
    }
}

/// Release of `key` destroys its standing and outbox and records the released
/// generation, then cancels every live attempt of it, shuts its socket and
/// waits for it to end, so nothing more of it streams after `Released`. No
/// writer or registry lock is held while it waits.
pub(super) fn release(vault: &Vault, key: OrderKey) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    prospective::end_in_txn(&vault.store, &mut wtxn, key, true)?;
    wtxn.commit()?;
    vault.store.host_legal_prospective.bump();
    for attempt in vault.host_legal_captures.prospective.cancel(Some(key)) {
        attempt.wait_ended();
    }
    Ok(())
}

/// Each live prospective connection, so release can cancel and await it,
/// the final drain can await all and managed stop can cancel all. In memory
/// only.
#[derive(Default)]
pub(crate) struct ProspectiveAttempts {
    attempts: Mutex<Vec<Arc<ProspectiveAttempt>>>,
    /// Set by the final drain once every writer of this process stopped.
    finishing: AtomicBool,
}

pub(super) struct ProspectiveAttempt {
    key: OrderKey,
    cancelled: AtomicBool,
    /// A clone of the connection's socket, shut down on cancel.
    stream: UnixStream,
    ended: Mutex<bool>,
    ended_changed: Condvar,
}

impl ProspectiveAttempt {
    pub(super) fn wait_ended(&self) {
        let ended = self.ended.lock().unwrap_or_else(PoisonError::into_inner);
        drop(
            self.ended_changed
                .wait_while(ended, |ended| !*ended)
                .unwrap_or_else(PoisonError::into_inner),
        );
    }
}

impl ProspectiveAttempts {
    fn finishing(&self) -> bool {
        self.finishing.load(Ordering::Acquire)
    }

    /// Starts the final drain: every attempt drains its outbox to empty,
    /// sends its final batch and ends. Returns the attached attempts, for the
    /// caller that waits for them.
    pub(super) fn finish(&self) -> Vec<Arc<ProspectiveAttempt>> {
        self.finishing.store(true, Ordering::Release);
        self.attempts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Cancels every attempt of `key` (every attempt when `None`) and shuts
    /// its socket. Returns them, for a caller that must wait for them.
    pub(super) fn cancel(&self, key: Option<OrderKey>) -> Vec<Arc<ProspectiveAttempt>> {
        let matched: Vec<_> = self
            .attempts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|attempt| key.is_none_or(|key| attempt.key == key))
            .cloned()
            .collect();
        for attempt in &matched {
            attempt.cancelled.store(true, Ordering::Release);
            let _ = attempt.stream.shutdown(Shutdown::Both);
        }
        matched
    }
}

/// One attached attempt; detached and marked ended on every exit path.
struct Attached<'a> {
    attempts: &'a ProspectiveAttempts,
    attempt: Arc<ProspectiveAttempt>,
}

impl<'a> Attached<'a> {
    fn new(attempts: &'a ProspectiveAttempts, key: OrderKey, stream: &UnixStream) -> Result<Self> {
        let attempt = Arc::new(ProspectiveAttempt {
            key,
            cancelled: AtomicBool::new(false),
            stream: stream.try_clone()?,
            ended: Mutex::new(false),
            ended_changed: Condvar::new(),
        });
        attempts
            .attempts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Arc::clone(&attempt));
        Ok(Self { attempts, attempt })
    }
}

impl Drop for Attached<'_> {
    fn drop(&mut self) {
        self.attempts
            .attempts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|attempt| !Arc::ptr_eq(attempt, &self.attempt));
        *self
            .attempt
            .ended
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = true;
        self.attempt.ended_changed.notify_all();
    }
}
