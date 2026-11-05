//! The connection half of a HOST order's prospective capture (FIX 13866):
//! stands the order, then streams its outbox in batches, each with its own
//! summary naming its exact ordinal range and its own acknowledgement, and
//! deletes a batch only after that acknowledgement. The order's term, its
//! release and managed stop end the loop; term end and release destroy the
//! standing with its outbox (FIX 13867).

use std::io;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use oneiron_crypto::HybridPublicKey;
use oneiron_vault_contract::host_legal::{CaptureExtent, CaptureRequest};

use super::collector::{Collector, SummaryCounts};
use crate::Vault;
use crate::deletion::legal_hold::prospective::{self, OrderKey, OutboxEntry};
use crate::error::Result;

impl super::HostLegalConnection {
    pub(super) fn run_prospective(
        mut self,
        vault: &Vault,
        request: CaptureRequest,
        public: HybridPublicKey,
        cancelled: &AtomicBool,
    ) -> Result<()> {
        let key: OrderKey = (request.order, request.generation);
        let request_digest = request.digest()?;
        let check = || super::check(vault, &request, cancelled);
        {
            let mut wtxn = vault.store.env.write_txn()?;
            check()?;
            prospective::stand_in_txn(&vault.store, &mut wtxn, &request, request_digest)?;
            wtxn.commit()?;
        }
        loop {
            if let Err(error) = check() {
                if vault.store.clock.now_recorded_at() >= request.ends_at {
                    // Term end destroys this generation's standing and outbox.
                    let mut wtxn = vault.store.env.write_txn()?;
                    prospective::end_in_txn(&vault.store, &mut wtxn, key, false)?;
                    wtxn.commit()?;
                }
                return Err(error);
            }
            let seen = vault.store.host_legal_prospective.generation();
            // The LMDB writer as a barrier: a writer that sealed into this
            // outbox and bumped `seen` has committed or rolled back.
            let batch = {
                let wtxn = vault.store.env.write_txn()?;
                let batch = prospective::outbox_in_txn(&vault.store, &wtxn, key)?;
                drop(wtxn);
                batch
            };
            let Some(batch) = batch else {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "legal prospective order no longer stands",
                )
                .into());
            };
            let Some(&(first, _)) = batch.first() else {
                let remaining = request
                    .ends_at
                    .saturating_sub(vault.store.clock.now_recorded_at());
                vault
                    .store
                    .host_legal_prospective
                    .wait_past(seen, Duration::from_secs(remaining));
                continue;
            };
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
            let mut collector = Collector::pinned(&mut self.stream, &public, &request)?;
            let mut counts = SummaryCounts {
                batch_first_ordinal: first,
                batch_entries: entries,
                ..SummaryCounts::default()
            };
            for (_, entry) in &batch {
                match entry {
                    OutboxEntry::Sealed {
                        frames,
                        descriptor_digest,
                        plaintext_len,
                        ..
                    } => {
                        collector.stored_component(
                            frames,
                            descriptor_digest,
                            *plaintext_len,
                            check,
                        )?;
                        counts.messages += 1;
                    }
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
        }
    }
}

/// Release of `key` destroys its standing and outbox and records the released
/// generation, then wakes its worker to end.
pub(super) fn release(vault: &Vault, key: OrderKey) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    prospective::end_in_txn(&vault.store, &mut wtxn, key, true)?;
    wtxn.commit()?;
    vault.store.host_legal_prospective.bump();
    Ok(())
}
