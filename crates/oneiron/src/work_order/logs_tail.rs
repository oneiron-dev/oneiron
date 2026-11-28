//! `vault.jobs.logs.tail` (pass 34, 7.2 and 14.2; row Q3): an attempt's stdout or stderr from a
//! byte offset, read on the machine that runs it. Logs stay on the machine: the vault keeps no
//! byte of them. The engine's part is who may read and where: the owner reads any attempt, and
//! an agent whose Grant lists the verb reads an attempt it requested (the actor that started
//! the attempt's job, which for an order's attempt is the order's requester). Any other caller
//! is answered as if the attempt did not exist. The host door asks the machine, and with
//! `wait_ms` asks again each second until bytes arrive, the stream ends or the wait passes
//! (Q3-2-WAIT = C: the wait is in the door, at most [`LOGS_TAIL_WAIT_MAX_MS`]; a code-mode run
//! calls the door through its generic verb call and needs no timer).

use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::consent::AuthenticatedOwner;
use crate::memory::verb_grant_caller::VerbGrantCaller;
use crate::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_NOT_FOUND, Memory, MemoryError, MemoryResult,
};

use super::LOGS_TAIL_VERB;

/// The longest one `vault.jobs.logs.tail` call waits for bytes, in milliseconds. A longer
/// `wait_ms` waits this long.
pub const LOGS_TAIL_WAIT_MAX_MS: u64 = 60_000;

/// One of an attempt's two log streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LogsTailStream {
    Stdout,
    Stderr,
}

/// `vault.jobs.logs.tail`: bytes of one attempt's log from a byte offset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LogsTailRequest {
    /// The attempt's dispatch key, as an order's attempt receipt names it (`key`).
    pub attempt: String,
    pub stream: LogsTailStream,
    /// Where to read from: 0, or the `next_offset` of the answer before. Offsets count every
    /// byte the workload wrote to the stream, also bytes the machine's log cap dropped.
    #[serde(default)]
    pub offset: u64,
    /// The most bytes to answer; at most (and when absent) one transport piece, 1,044,480.
    #[serde(default)]
    pub max: Option<u32>,
    /// How long to wait, in milliseconds, while the stream has no bytes past `offset` and has
    /// not ended: the call answers when bytes arrive, when the stream ends, or when the wait
    /// passes (at most 60,000). Absent: the call answers at once.
    #[serde(default)]
    pub wait_ms: Option<u64>,
}

/// The bytes the machine's log cap removed between the asked offset and the first byte
/// answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LogsTailTruncation {
    pub dropped: u64,
}

/// The answer of `vault.jobs.logs.tail`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LogsTail {
    /// The stream's bytes from the asked offset (after the bytes `truncated` skipped), as text.
    /// A byte sequence that is not UTF-8 reads as U+FFFD. A character the read cut short at its
    /// end is left for the next read: `next_offset` stops before it while the stream runs.
    pub bytes: String,
    /// Where the next call reads from. Never past the stream's end.
    pub next_offset: u64,
    /// The attempt ended and nothing follows `next_offset`: the stream is whole.
    pub ended: bool,
    /// The log cap dropped bytes the call asked for: `bytes` begin after them.
    pub truncated: Option<LogsTailTruncation>,
}

impl LogsTail {
    /// The answer for the machine's read: `bytes` end at `next_offset`, and `ended` says the
    /// stream ended there. A UTF-8 sequence cut short at the end of `bytes` is held back for
    /// the next read, unless the stream ended there or nothing else was read.
    #[must_use]
    pub fn from_machine(bytes: &[u8], next_offset: u64, ended: bool, dropped: Option<u64>) -> Self {
        let cut = if ended { 0 } else { cut_short_tail(bytes) };
        let (kept, held_back) = if cut < bytes.len() {
            (&bytes[..bytes.len() - cut], cut)
        } else {
            (bytes, 0)
        };
        Self {
            bytes: String::from_utf8_lossy(kept).into_owned(),
            next_offset: next_offset.saturating_sub(u64::try_from(held_back).unwrap_or(0)),
            ended,
            truncated: dropped.map(|dropped| LogsTailTruncation { dropped }),
        }
    }
}

/// How many bytes at the end of `bytes` begin a UTF-8 sequence the read cut short: 0 when the
/// last sequence is whole or not UTF-8 at all.
fn cut_short_tail(bytes: &[u8]) -> usize {
    for back in 1..=bytes.len().min(3) {
        let byte = bytes[bytes.len() - back];
        if byte & 0b1100_0000 == 0b1000_0000 {
            continue;
        }
        let needs = match byte {
            0xF0..=0xF4 => 4,
            0xE0..=0xEF => 3,
            0xC2..=0xDF => 2,
            _ => return 0,
        };
        return if needs > back { back } else { 0 };
    }
    0
}

/// Where one attempt's log is read, for a caller `vault.jobs.logs.tail` admits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogsTailTarget {
    /// The attempt's dispatch key, the node's journal key.
    pub key: String,
    /// The machine that runs it.
    pub machine: EntityId,
}

fn no_such_attempt() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_NOT_FOUND,
        "no such attempt",
        &["An order's attempts carry their keys: read them with vault.jobs.orders.get."],
    )
}

/// `vault.jobs.logs.tail`'s read: the attempt `input` names, for `memory`'s caller, judged in
/// one snapshot. Asked again before each read of the machine, so a revoke ends a waiting
/// read at its next ask.
///
/// # Errors
///
/// `bad_request` for `max` 0; `forbidden` for a caller the verb does not admit; `not_found`
/// for an attempt the caller did not request or that does not exist (the two answer alike).
pub fn logs_tail_target_as(
    memory: &Memory<'_>,
    owner: Option<&AuthenticatedOwner>,
    input: &LogsTailRequest,
) -> MemoryResult<LogsTailTarget> {
    if input.max == Some(0) {
        return Err(MemoryError::new(
            MEMORY_CODE_BAD_REQUEST,
            "max must be at least 1",
            &[],
        ));
    }
    let vault = memory.vault();
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    let caller = memory.verb_grant_caller_admits_in_txn(&txn, owner, LOGS_TAIL_VERB)?;
    let Some(dispatch) = vault.job_dispatch_in_txn(&txn, &input.attempt)? else {
        return Err(no_such_attempt());
    };
    let requested = match caller {
        VerbGrantCaller::Owner => true,
        VerbGrantCaller::Agent { actor, .. } => vault
            .gpu_job_in_txn(&txn, &dispatch.job)?
            .is_some_and(|job| job.started_by == Some(actor)),
    };
    if !requested {
        return Err(no_such_attempt());
    }
    Ok(LogsTailTarget {
        key: dispatch.key,
        machine: dispatch.machine,
    })
}
