//! The machine's outbox (FIX 3966): the queued updates it still owes its
//! home, window by window, each with the digest of its raw row and the
//! home's answer to its latest send. A Durable answer retires a row, so an
//! owed row that still carries one waits behind an earlier row of its window
//! that the home has not acknowledged; a Held answer keeps its row owed. The
//! answers are this process's: a restart forgets them until the rows are
//! sent again.

use std::collections::HashMap;

use super::SyncConnection;
use crate::EntityId;
use crate::sync::SyncClient;
use crate::verbs::{SyncOutbox, SyncOutboxReceipt, SyncOutboxRow, SyncOutboxWindow};

/// The home's answer to one queue send: the BLAKE3 digest of the raw row it
/// answered, and whether it was Durable.
#[derive(Debug, Clone, Copy)]
pub(super) struct HomeReceipt {
    digest: [u8; 32],
    durable: bool,
}

/// The answers by queue sequence.
pub(super) type HomeReceipts = HashMap<u64, HomeReceipt>;

impl SyncConnection {
    /// Keeps `client`'s answers for the rows still queued, for
    /// [`Self::outbox`].
    pub(super) fn note_home_receipts(&self, client: &SyncClient) {
        if let Ok(mut receipts) = self.home_receipts.lock() {
            *receipts = client
                .residence_acks
                .iter()
                .map(|(seq, ack)| {
                    (
                        *seq,
                        HomeReceipt {
                            digest: *ack.digest(),
                            durable: ack.is_durable(),
                        },
                    )
                })
                .collect();
        }
    }

    /// The updates `machine`, this connection's machine, still owes its home,
    /// in queue order and grouped by window. A row's receipt is the home's
    /// answer to the bytes it holds now, and `None` until one came.
    pub fn outbox(&self, machine: EntityId) -> crate::error::Result<SyncOutbox> {
        let receipts = self
            .home_receipts
            .lock()
            .map(|receipts| receipts.clone())
            .unwrap_or_default();
        let updates = self.queue.drain_updates()?;
        let owed = updates.len() as u64;
        let mut windows: Vec<SyncOutboxWindow> = Vec::new();
        for queued in updates {
            let digest = blake3::hash(&queued.encoded);
            let receipt = receipts
                .get(&queued.seq)
                .filter(|receipt| &receipt.digest == digest.as_bytes())
                .map(|receipt| {
                    if receipt.durable {
                        SyncOutboxReceipt::Durable
                    } else {
                        SyncOutboxReceipt::Held
                    }
                });
            let row = SyncOutboxRow {
                seq: queued.seq,
                digest: digest.to_hex().to_string(),
                bytes: queued.encoded.len() as u64,
                receipt,
            };
            match windows
                .iter_mut()
                .find(|window| window.window_key == queued.window_key)
            {
                Some(window) => window.rows.push(row),
                None => windows.push(SyncOutboxWindow {
                    window_key: queued.window_key,
                    rows: vec![row],
                }),
            }
        }
        Ok(SyncOutbox {
            machine,
            owed,
            windows,
        })
    }
}
