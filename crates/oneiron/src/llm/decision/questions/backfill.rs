//! Scheduled backfill (OF-516): the question's principal sets a time, and from
//! then the question pump answers, once, each covered unit with no answer at
//! the question's current version, as a scheduled refresh answers it, under
//! the same responsible-role runner, dial and hold.

use super::super::types::invalid;
use super::{
    records::*,
    store::{
        QUESTION_VERSION, VersionKey, decode_family, family_prefix, owned_head,
        secret_scan_before_put,
    },
};
use crate::side_table::{self, Named, SideKey, SideTable};
use crate::{EntityId, Error, Result, Vault};

/// Key of one question's scheduled backfill. Family: `backfill_at`, suffix: empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct BackfillAtKey(pub(super) EntityId);

impl SideKey for BackfillAtKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&family_prefix(self.0, b"backfill_at"));
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (id, suffix) = decode_family(bytes, b"backfill_at")?;
        suffix.is_empty().then_some(Self(id))
    }
}

pub(super) const QUESTION_BACKFILL_AT: SideTable<BackfillAtKey, ScheduledBackfill, Named> =
    SideTable::new(&side_table::TYPED_QUESTION);

/// Schedules `principal`'s standing question's backfill at `due_at`, over
/// `expected_version`. A later schedule replaces it and an edit retires it;
/// a paused question's backfill waits for its resume. An artifact question
/// asks its artifacts on its own pump and takes none.
pub fn schedule_backfill(
    vault: &Vault,
    principal: EntityId,
    question: EntityId,
    expected_version: u32,
    due_at: u64,
) -> Result<ScheduledBackfill> {
    vault.with_write_txn_grouped(|txn| {
        let head = owned_head(vault, txn, principal, question)?;
        if head.version != expected_version {
            return Err(Error::ConcurrentWrite("standing question changed"));
        }
        let record = QUESTION_VERSION
            .get(
                &vault.store,
                txn,
                &VersionKey {
                    id: question,
                    version: head.version,
                },
            )?
            .ok_or(Error::CorruptedIndex("question version"))?;
        if record.definition.adapter == ARTIFACT_ADAPTER {
            return Err(invalid("an artifact question takes no backfill"));
        }
        let backfill = ScheduledBackfill {
            question,
            version: head.version,
            due_at,
        };
        secret_scan_before_put(&backfill)?;
        QUESTION_BACKFILL_AT.put(&vault.store, txn, &BackfillAtKey(question), &backfill)?;
        // The host's question timer re-reads its next due instant.
        crate::batch::queue_proactivity_change(vault, txn);
        Ok(backfill)
    })
}
