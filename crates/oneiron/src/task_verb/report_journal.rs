//! The per-attempt report journal (OF-220).
//!
//! A report key names one report of one try. The first report under a key
//! that moves its TASK is journaled with its receipt, in the transaction
//! that moves it: the try (attempt and count), the reporter, the TASK, the
//! key, and a digest of the whole request. A re-issued report finds its
//! entry before any fence, question or ask, and answers the first receipt,
//! marked a replay; a different request under the same key is refused.
//!
//! The journal keys on the try, so only a report that names one is
//! journaled: an external taker's accepted handle, or a host binding's
//! leased attempt. A person's report on the human lane, an acknowledgement
//! and a brief revision keep their own idempotency. An entry proves nothing:
//! it is read only after the reporter's own read has admitted the TASK, and
//! only for the reporter that wrote it.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::memory::{MemoryError, MemoryResult};
use crate::side_table::{self, Named, SideTable};

use super::brief::hex32;
use super::highway_types::{TaskCallReceipt, TaskReport, TaskVia};

/// Domain of a journaled request's digest.
const REQUEST_DIGEST_DOMAIN: &[u8] = b"oneiron.tasks.report.request.v1";
/// Domain of the key digest one try's entry is stored under.
const KEY_DIGEST_DOMAIN: &[u8] = b"oneiron.tasks.report.key.v1";

/// The try, its count, and a digest of who reported what key on which TASK.
type ReportKey = ([u8; 16], u64, [u8; 32]);

/// Try and key → the request first journaled under them, and its receipt.
const REPORTS: SideTable<ReportKey, ReportEntry, Named> =
    SideTable::new(&side_table::TASK_REPORT_JOURNAL);

/// What one journaled report was: the try it reported on, its reporter, its
/// TASK, its key, and a digest of the whole request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReportIdentity {
    attempt: AttemptId,
    attempt_count: u32,
    actor: EntityId,
    task_ref: EntityId,
    report_key: String,
    #[serde(with = "hex32")]
    request_digest: [u8; 32],
}

/// One journal row: the request, and the receipt it was first answered with.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportEntry {
    identity: ReportIdentity,
    receipt: TaskCallReceipt,
}

fn digest(domain: &[u8], value: &impl Serialize) -> MemoryResult<[u8; 32]> {
    let bytes = rmp_serde::to_vec_named(value)
        .map_err(|_| MemoryError::bad_request("the report does not encode"))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&bytes);
    Ok(*hasher.finalize().as_bytes())
}

/// The journal identity of `report` by `actor` under `qualified_key`: the try
/// its accepted handle names, else the attempt its host binding leased.
/// `None` for a report that names no try. The digest covers the whole
/// request: its handle, its body and every flag in it.
pub(super) fn identity(
    actor: EntityId,
    via: &TaskVia,
    report: &TaskReport,
    qualified_key: &str,
) -> MemoryResult<Option<ReportIdentity>> {
    let (attempt, attempt_count) = match (&report.attempt, via) {
        (Some(handle), _) => (handle.attempt_ref, handle.attempt_count),
        (None, TaskVia::Host(binding)) => (binding.parent(), binding.attempt_count()),
        (None, TaskVia::Wire) => return Ok(None),
    };
    Ok(Some(ReportIdentity {
        attempt,
        attempt_count,
        actor,
        task_ref: report.task_ref,
        report_key: qualified_key.to_owned(),
        request_digest: digest(REQUEST_DIGEST_DOMAIN, &(actor, qualified_key, report))?,
    }))
}

impl ReportIdentity {
    fn key(&self) -> MemoryResult<ReportKey> {
        Ok((
            *self.attempt.as_bytes(),
            u64::from(self.attempt_count),
            digest(
                KEY_DIGEST_DOMAIN,
                &(self.actor, self.task_ref, self.report_key.as_str()),
            )?,
        ))
    }
}

/// The receipt the first report under `identity`'s try and key was answered
/// with, marked a replay; `None` when none was journaled. The same key
/// naming a different request is refused.
pub(super) fn replay_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    identity: &ReportIdentity,
) -> MemoryResult<Option<TaskCallReceipt>> {
    let Some(entry) = REPORTS.get(&vault.store, txn, &identity.key()?)? else {
        return Ok(None);
    };
    if entry.identity != *identity {
        return Err(MemoryError::bad_request_with(
            "this report key already names a different request",
            &["Re-issue the same report, or use a new report key."],
        ));
    }
    let mut receipt = entry.receipt;
    receipt.idempotent_replay = true;
    Ok(Some(receipt))
}

/// Journals `receipt` as the answer to `identity`, in the transaction that
/// moved its TASK.
pub(super) fn put_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    identity: &ReportIdentity,
    receipt: &TaskCallReceipt,
) -> MemoryResult<()> {
    let entry = ReportEntry {
        identity: identity.clone(),
        receipt: receipt.clone(),
    };
    REPORTS.put(&vault.store, txn, &identity.key()?, &entry)?;
    Ok(())
}
