//! OF-490: a vault export is a read of agent diaries. It reads the diaries
//! the exporting owner's grant covers, logs each read with the reason
//! `export`, and holds out the diaries of an agent that reviews each read
//! first, recording that pending review in the manifest; the export itself
//! is never blocked (export is never gated). L07-A's diary-read door takes
//! over [`export_diary_admission`]'s body when it lands.
use std::collections::BTreeMap;

use super::{ExportDiaryHold, ExportDiaryHoldReason, ExportDiaryRead};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, RawValue, SideTable};

/// The reason every export's diary read states.
pub const EXPORT_DIARY_READ_REASON: &str = "export";

const DIARY_READ_REVIEW: SideTable<EntityId, DiaryReadReview, Raw> =
    SideTable::new(&side_table::DIARY_READ_REVIEW);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DiaryReadReview(bool);

impl RawValue for DiaryReadReview {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, side_table::CodecError> {
        Ok(vec![u8::from(self.0)])
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, side_table::CodecError> {
        match bytes {
            [0] => Ok(Self(false)),
            [1] => Ok(Self(true)),
            _ => Err(Error::CorruptedIndex("diary read review setting").into()),
        }
    }
}

impl Vault {
    /// Sets whether `agent` reviews each read of its diary first. On for
    /// Eiri, as her consent rule; absent means off.
    pub fn set_agent_diary_read_review(&self, agent: EntityId, on: bool) -> Result<()> {
        self.with_write_txn_grouped(|wtxn| {
            DIARY_READ_REVIEW.put(&self.store, wtxn, &agent, &DiaryReadReview(on))?;
            Ok(())
        })
    }

    /// Whether `agent` reviews each read of its diary first.
    pub fn agent_diary_read_review(&self, agent: EntityId) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        agent_reviews_diary_reads_in_txn(self, &rtxn, &agent)
    }
}

fn agent_reviews_diary_reads_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    agent: &EntityId,
) -> Result<bool> {
    Ok(DIARY_READ_REVIEW
        .get(&vault.store, rtxn, agent)?
        .is_some_and(|review| review.0))
}

/// The author of the NOTE `body` when it is a diary.
pub(crate) fn diary_author(body: &[u8]) -> Option<EntityId> {
    crate::note::decode_note_body_using(body, crate::note::NoteKind::wire)
        .ok()
        .filter(|note| note.kind == crate::note::NoteKind::Diary)
        .map(|note| note.author_ref)
}

/// Whether this export reads `author`'s diary, or why it holds it out. The
/// exporting owner's grant covers every live agent of this vault; an agent
/// that reviews each read first has not reviewed this one yet.
pub(crate) fn export_diary_admission(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    author: &EntityId,
) -> Result<Option<ExportDiaryHoldReason>> {
    if !crate::vault::live_entity_row_in_txn(&vault.store, rtxn, author)?.is_live() {
        return Ok(Some(ExportDiaryHoldReason::NotCoveredByGrant));
    }
    if agent_reviews_diary_reads_in_txn(vault, rtxn, author)? {
        return Ok(Some(ExportDiaryHoldReason::AgentReviewPending));
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
