//! MCP task handles (ARCH-0028 `#mcp-tasks`, owner ruling ONEIRON-MCP-TASKS = AB; L1-03).
//!
//! An MCP task is a transport handle over a record the engine already keeps (a saved-workflow
//! run by its root attempt, a Dreamer night step by its wake's root attempt, a provider job by
//! its ticket). It is never a TASK entity and never a second scheduler: the record's own end gives
//! the task's end. One row per handle, bound to the actor whose request minted it, stored before
//! the handle is returned. The row is keyed by the BLAKE3 hash of the handle's id, so a store
//! read never yields a live handle.
//!
//! A handle answers only its own actor. An unknown id, another actor's handle and a handle past
//! its time to live all read as missing, so no answer tells that a hidden handle exists. An
//! expired handle's row is removed; the record it wrapped goes on. Three clocks stay apart: the
//! record's retention, the handle's time to live and any grant's lifetime.
//!
//! A task's end is final. The handle keeps the first end a read of its record saw, and answers
//! that end from then on, though the record may go on working (a night step's remainder runs a
//! policy interval later under the same root).

pub(crate) mod tables;

use crate::Vault;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

/// One handle row. Key: blake3 hash32 of the handle id.
const HANDLES: SideTable<[u8; 32], McpTaskRecord, Named> = SideTable::new(&side_table::MCP_TASK);

/// The id of one MCP task handle: 32 bytes from the OS random source, written as 64 lowercase hex
/// digits (the wire `taskId`). No other caller can guess it, and it still grants nothing: every
/// read through it checks its caller again.
#[derive(Clone, PartialEq, Eq)]
pub struct McpTaskId([u8; 32]);

impl McpTaskId {
    /// The id as its 64 lowercase hex digits.
    #[must_use]
    pub fn to_hex(&self) -> String {
        bytes_to_hex_lower(&self.0)
    }

    /// Parses a wire `taskId`: exactly 64 lowercase hex digits, else `None`.
    #[must_use]
    pub fn from_hex(text: &str) -> Option<Self> {
        let digits = text.as_bytes();
        if digits.len() != 64 {
            return None;
        }
        let mut bytes = [0u8; 32];
        for (slot, pair) in bytes.iter_mut().zip(digits.chunks_exact(2)) {
            *slot = (lower_hex_digit(pair[0])? << 4) | lower_hex_digit(pair[1])?;
        }
        Some(Self(bytes))
    }

    /// The row key: the id's BLAKE3 hash, never the id itself.
    fn row_key(&self) -> [u8; 32] {
        *blake3::hash(&self.0).as_bytes()
    }
}

/// The id is a live handle: it is never written to a log.
impl std::fmt::Debug for McpTaskId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("McpTaskId(..)")
    }
}

fn lower_hex_digit(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

/// The record a handle wraps, named by the record's own key. The handle keeps no copy of the
/// record's state: each read goes to the record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum McpTaskSubject {
    /// A saved-workflow run, by its root attempt.
    WorkflowRun { root_attempt_ref: EntityId },
    /// A Dreamer night step, by its wake's root attempt.
    NightStep { wake_root_ref: EntityId },
    /// A provider job, by its ticket.
    ProviderJob { job: String },
}

/// How the record behind a handle ended, as the handle answers it from then on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpTaskEnd {
    /// The record ended; a partial or deferred outcome ends here too, naming itself.
    Completed,
    /// The record ended in failure: the task ends completed, its result marked an error.
    CompletedWithError,
    /// The record's work stopped on a cancel.
    Cancelled,
}

/// The end a handle keeps: the first end a read of its record saw, and when.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpTaskEnded {
    pub end: McpTaskEnd,
    /// Host milliseconds when the end was kept.
    pub at_ms: u64,
}

/// One stored handle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpTaskRecord {
    /// The actor whose request minted the handle: the only actor it answers.
    pub actor_ref: EntityId,
    pub subject: McpTaskSubject,
    /// Host milliseconds when the handle was minted.
    pub created_at_ms: u64,
    /// The handle's retention, from `created_at_ms`. `None` keeps it until its row is removed.
    pub ttl_ms: Option<u64>,
    /// When the handle's actor first asked its work to stop, in host milliseconds.
    #[serde(default)]
    pub cancel_requested_at_ms: Option<u64>,
    /// The record's end as the handle first saw it. A task's end is final: a record that
    /// goes on working after it (a night step's remainder, due a policy interval later)
    /// leaves the handle at this end.
    #[serde(default)]
    pub ended: Option<McpTaskEnded>,
}

impl McpTaskRecord {
    /// The handle's last change, in host milliseconds: the latest of its mint, its cancel
    /// request and its end.
    #[must_use]
    pub fn last_updated_at_ms(&self) -> u64 {
        [
            Some(self.created_at_ms),
            self.cancel_requested_at_ms,
            self.ended.map(|ended| ended.at_ms),
        ]
        .into_iter()
        .flatten()
        .max()
        .unwrap_or(self.created_at_ms)
    }
}

impl McpTaskRecord {
    /// Whether the handle's time to live has run out at `now_ms`.
    fn expired_at(&self, now_ms: u64) -> bool {
        self.ttl_ms
            .is_some_and(|ttl| now_ms >= self.created_at_ms.saturating_add(ttl))
    }
}

/// What a handle's row holds for one reader at one instant.
enum HandleRead {
    /// No row, or another actor's row.
    Missing,
    /// A row past its time to live: it reads as missing and is removed.
    Expired,
    Live(McpTaskRecord),
}

fn read_handle(row: Option<McpTaskRecord>, actor: EntityId, now_ms: u64) -> HandleRead {
    match row {
        None => HandleRead::Missing,
        Some(row) if row.expired_at(now_ms) => HandleRead::Expired,
        Some(row) if row.actor_ref == actor => HandleRead::Live(row),
        Some(_) => HandleRead::Missing,
    }
}

impl Vault {
    /// Stores one MCP task handle over `subject` for `actor` and returns its id. Call it only
    /// after the record `subject` names has committed in its own writer, so a handle never names
    /// work that is not stored, and return the id only after this call: the handle is stored
    /// before its holder learns it. `ttl_ms` is the handle's retention from `now_ms`; `None`
    /// keeps it. A repeated call over one record mints a second handle and starts nothing.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn mint_mcp_task(
        &self,
        actor: EntityId,
        subject: McpTaskSubject,
        ttl_ms: Option<u64>,
        now_ms: u64,
    ) -> Result<McpTaskId> {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let id = McpTaskId(bytes);
        let row = McpTaskRecord {
            actor_ref: actor,
            subject,
            created_at_ms: now_ms,
            ttl_ms,
            cancel_requested_at_ms: None,
            ended: None,
        };
        let mut txn = self.store.env.write_txn()?;
        HANDLES.put(&self.store, &mut txn, &id.row_key(), &row)?;
        txn.commit()?;
        Ok(id)
    }

    /// The handle `id` as `actor` reads it at `now_ms`. `None` alike for an unknown id, another
    /// actor's handle and a handle past its time to live; an expired handle's row is removed then.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn mcp_task(
        &self,
        actor: EntityId,
        id: &McpTaskId,
        now_ms: u64,
    ) -> Result<Option<McpTaskRecord>> {
        let key = id.row_key();
        let read = {
            let txn = self.store.env.read_txn()?;
            read_handle(HANDLES.get(&self.store, &txn, &key)?, actor, now_ms)
        };
        match read {
            HandleRead::Missing => Ok(None),
            HandleRead::Live(row) => Ok(Some(row)),
            HandleRead::Expired => {
                let mut txn = self.store.env.write_txn()?;
                // Read again in the writer: only a row still past its time is removed.
                if let HandleRead::Expired =
                    read_handle(HANDLES.get(&self.store, &txn, &key)?, actor, now_ms)
                {
                    HANDLES.delete(&self.store, &mut txn, &key)?;
                    txn.commit()?;
                }
                Ok(None)
            }
        }
    }

    /// Records that `actor` asked the work behind handle `id` to stop, the first time only, and
    /// answers the handle as [`Self::mcp_task`] reads it after the write. The record the handle
    /// wraps does not change here: the caller runs that record's own cancel door, which asks the
    /// work to stop and never undoes committed work.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn request_mcp_task_cancel(
        &self,
        actor: EntityId,
        id: &McpTaskId,
        now_ms: u64,
    ) -> Result<Option<McpTaskRecord>> {
        let key = id.row_key();
        let mut txn = self.store.env.write_txn()?;
        match read_handle(HANDLES.get(&self.store, &txn, &key)?, actor, now_ms) {
            HandleRead::Missing => Ok(None),
            HandleRead::Expired => {
                HANDLES.delete(&self.store, &mut txn, &key)?;
                txn.commit()?;
                Ok(None)
            }
            HandleRead::Live(mut row) => {
                if row.cancel_requested_at_ms.is_none() {
                    row.cancel_requested_at_ms = Some(now_ms);
                    HANDLES.put(&self.store, &mut txn, &key, &row)?;
                    txn.commit()?;
                }
                Ok(Some(row))
            }
        }
    }

    /// Keeps `end` as the end of handle `id` for `actor`, the first time only, and answers
    /// the handle as [`Self::mcp_task`] reads it after the write. Call it once a read of the
    /// record, run as `actor`, saw the record end. A handle that already keeps an end keeps
    /// it: the answer then names the earlier end, so a task's end never changes.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn end_mcp_task(
        &self,
        actor: EntityId,
        id: &McpTaskId,
        end: McpTaskEnd,
        now_ms: u64,
    ) -> Result<Option<McpTaskRecord>> {
        let key = id.row_key();
        let mut txn = self.store.env.write_txn()?;
        match read_handle(HANDLES.get(&self.store, &txn, &key)?, actor, now_ms) {
            HandleRead::Missing => Ok(None),
            HandleRead::Expired => {
                HANDLES.delete(&self.store, &mut txn, &key)?;
                txn.commit()?;
                Ok(None)
            }
            HandleRead::Live(mut row) => {
                if row.ended.is_none() {
                    row.ended = Some(McpTaskEnded { end, at_ms: now_ms });
                    HANDLES.put(&self.store, &mut txn, &key, &row)?;
                    txn.commit()?;
                }
                Ok(Some(row))
            }
        }
    }
}
