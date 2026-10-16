//! OF-490: a vault export is a read of agent diaries. It reads the diaries
//! the exporting owner's grant covers, logs each read with the reason
//! `export`, and holds out the diaries of an agent that reviews each read
//! first, recording that pending review in the manifest; the export itself
//! is never blocked (export is never gated). L07-A's diary-read door, which
//! owns the per-agent review setting, takes over [`export_diary_admission`]'s
//! body when it lands.
use std::collections::BTreeMap;

use super::{ExportDiaryHold, ExportDiaryHoldReason, ExportDiaryRead};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// The reason every export's diary read states.
pub const EXPORT_DIARY_READ_REASON: &str = "export";

/// The author of the NOTE `body` when it is a diary.
pub(crate) fn diary_author(body: &[u8]) -> Option<EntityId> {
    crate::note::decode_note_body_using(body, crate::note::NoteKind::wire)
        .ok()
        .filter(|note| note.kind == crate::note::NoteKind::Diary)
        .map(|note| note.author_ref)
}

/// Whether this export reads `author`'s diary, or why it holds it out: THE
/// one call L07-A's OF-490 diary-read door replaces. The exporting owner's
/// grant covers every live agent of this vault. The per-agent review setting
/// is that door's (on for Eiri); until it lands no agent reviews first, and
/// an agent that does is held as `AgentReviewPending`.
pub(crate) fn export_diary_admission(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    author: &EntityId,
) -> Result<Option<ExportDiaryHoldReason>> {
    if !crate::vault::live_entity_row_in_txn(&vault.store, rtxn, author)?.is_live() {
        return Ok(Some(ExportDiaryHoldReason::NotCoveredByGrant));
    }
    Ok(None)
}

/// Each agent's diaries this export read and held, counted.
#[derive(Debug, Default)]
pub(crate) struct ExportDiaryLedger {
    read: BTreeMap<EntityId, u64>,
    held: BTreeMap<(EntityId, ExportDiaryHoldReason), u64>,
}

impl ExportDiaryLedger {
    /// Admits one diary by `author`: true when it is read.
    pub(crate) fn admit(
        &mut self,
        vault: &Vault,
        rtxn: &heed::RoTxn<'_>,
        author: EntityId,
    ) -> Result<bool> {
        match export_diary_admission(vault, rtxn, &author)? {
            None => {
                *self.read.entry(author).or_default() += 1;
                Ok(true)
            }
            Some(reason) => {
                *self.held.entry((author, reason)).or_default() += 1;
                Ok(false)
            }
        }
    }

    pub(crate) fn finish(self) -> (Vec<ExportDiaryRead>, Vec<ExportDiaryHold>) {
        let reads = self
            .read
            .into_iter()
            .map(|(agent, diaries)| ExportDiaryRead {
                agent: agent.to_hex(),
                diaries,
                reason: EXPORT_DIARY_READ_REASON.to_owned(),
            })
            .collect();
        let holds = self
            .held
            .into_iter()
            .map(|((agent, reason), diaries)| ExportDiaryHold {
                agent: agent.to_hex(),
                diaries,
                reason,
            })
            .collect();
        (reads, holds)
    }
}
