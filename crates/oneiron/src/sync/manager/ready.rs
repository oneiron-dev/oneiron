//! Ready windows (fix list row 19634): a window a policy wake persisted again
//! is ready for every live connection.
//!
//! The wake's persist routes only a commit it makes itself, and a redaction
//! an erase already wrote into the stored window makes none, so no peer would
//! hear of it before its next handshake. After each such persist the wake
//! raises the window's ready generation ([`WindowManager::mark_window_ready`]).
//! Each connection, on the client and on the served host, keeps a
//! [`ReadyProgress`]: the generation of each window it last asked its peer to
//! exchange, and the window its last pass ended at. Each pass asks for up to
//! [`READY_WINDOWS_PER_PASS`] windows whose generation it has not asked for,
//! from the one after where the last pass ended, round to the start, and
//! stamps a window only once its request is on the socket. A new connection,
//! and so a restart, starts with nothing asked and asks again for every ready
//! window. A request on the socket is not the peer's receipt: nothing here
//! retires a ready row, a full-resync marker or a queued write, and the
//! exchange the request starts decides what goes.

use std::collections::HashMap;

use heed::RoTxn;

use super::WindowManager;
use crate::Vault;
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::sync::types::WindowKey;
use crate::sync::window_rows::{WINDOW_SNAPSHOT, WINDOW_UPDATE};

/// The most ready windows one pass of one connection asks for. One pass of
/// the policy wakes persists at most as many windows, so each connection
/// keeps their pace. A scheduling choice: a window past it waits for the next
/// pass.
pub const READY_WINDOWS_PER_PASS: usize = 8;

/// Each stored window's ready generation, little-endian; an absent row is 0.
const READY_GENERATION: SideTable<String, [u8; 8], Raw> =
    SideTable::new(&side_table::WINDOW_READY_GENERATION);

impl WindowManager {
    /// Raises window `key`'s ready generation by one, in its own
    /// transaction, when this vault stores the window (a snapshot, or
    /// pending updates): every live connection asks its peer to exchange the
    /// window again. `false`, with nothing written, when it stores none: a
    /// ready row never stands for an empty window.
    ///
    /// # Errors
    ///
    /// Storage errors, and a generation at its last value.
    pub(crate) fn mark_window_ready(&self, key: &WindowKey) -> Result<bool> {
        let vault = self.vault();
        vault.with_write_txn_grouped(|wtxn| {
            if !window_stored_in(vault, wtxn, key)? {
                return Ok(false);
            }
            let generation = READY_GENERATION
                .get(&vault.store, wtxn, &key.0)?
                .map_or(0, u64::from_le_bytes)
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("window ready generation"))?;
            READY_GENERATION.put(&vault.store, wtxn, &key.0, &generation.to_le_bytes())?;
            Ok(true)
        })
    }

    /// Whether this vault stores window `key`: its snapshot, or pending
    /// updates a cold open recovers. A transport asks it before it names a
    /// ready window to its peer, so no ready row opens an empty window.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn window_stored(&self, key: &WindowKey) -> Result<bool> {
        let vault = self.vault();
        let txn = vault.store.env.read_txn()?;
        window_stored_in(vault, &txn, key)
    }
}

/// Whether this vault stores window `key`, read in `txn`: its snapshot, or a
/// pending update.
fn window_stored_in(vault: &Vault, txn: &RoTxn<'_>, key: &WindowKey) -> Result<bool> {
    let updates = format!("{}:", key.as_str());
    Ok(WINDOW_SNAPSHOT.contains(&vault.store, txn, &key.0)?
        || WINDOW_UPDATE
            .iter_raw_from(&vault.store, txn, updates.as_bytes())?
            .next()
            .transpose()?
            .is_some())
}

/// One connection's place in the ready windows: the generation of each
/// window it last asked its peer to exchange, and the window its last pass
/// ended at. It lives as long as its connection.
#[derive(Debug, Default)]
pub struct ReadyProgress {
    asked: HashMap<WindowKey, u64>,
    cursor: Option<WindowKey>,
}

impl ReadyProgress {
    /// Up to `budget` ready windows this connection has not asked for at
    /// their current generation and that `eligible` takes now, each with the
    /// generation read: from the one after where the last pass ended, round
    /// to the start. A window `eligible` passes over stays owed for a later
    /// pass. Nothing is stamped here.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn due(
        &mut self,
        manager: &WindowManager,
        budget: usize,
        mut eligible: impl FnMut(&WindowKey) -> bool,
    ) -> Result<Vec<(WindowKey, u64)>> {
        let mut owed = Vec::new();
        {
            let vault = manager.vault();
            let txn = vault.store.env.read_txn()?;
            for row in READY_GENERATION.iter_raw_from(&vault.store, &txn, &[])? {
                let (label, generation) = row?;
                // A row that reads as no window and generation names nothing
                // to ask for.
                let (Some(key), Ok(generation)) = (
                    String::from_utf8(label).ok().and_then(WindowKey::try_new),
                    <[u8; 8]>::try_from(generation.as_slice()),
                ) else {
                    continue;
                };
                let generation = u64::from_le_bytes(generation);
                if self.asked.get(&key).is_none_or(|asked| *asked < generation) {
                    owed.push((key, generation));
                }
            }
        }
        // From the one after where the last pass ended, round to the start.
        let start = self.cursor.as_ref().map_or(0, |cursor| {
            owed.partition_point(|(key, _)| key.as_str() <= cursor.as_str())
        });
        owed.rotate_left(start);
        let mut due = Vec::new();
        for (key, generation) in owed {
            if due.len() == budget {
                break;
            }
            self.cursor = Some(key.clone());
            if eligible(&key) {
                due.push((key, generation));
            }
        }
        Ok(due)
    }

    /// Records that window `key`'s request went out on the socket at
    /// `generation`, the generation [`Self::due`] read: a later one is owed
    /// again.
    pub fn stamp(&mut self, key: WindowKey, generation: u64) {
        self.asked.insert(key, generation);
    }

    /// Forgets what this connection asked of window `key`: an answer that
    /// could not be made now leaves the next pass owing the request again.
    pub fn retry(&mut self, key: &WindowKey) {
        self.asked.remove(key);
    }
}
