//! OF-490: a vault export is a read of agent diaries, made through the diary
//! door's [`DiaryReadGate`] with the reason `export`. Each diary entry in the
//! snapshot is admitted inside the snapshot's read transaction: the reader's
//! `diary.read` Grant decides what is covered, and an agent that reviews each
//! read first (on for Eiri) holds its entries until it answers. After the
//! snapshot the gate logs the reads where each agent sees them, spends the
//! yes they used and opens pending reviews. Held entries stay out of the
//! archive and the manifest's `diary_holds` names them; the export itself is
//! never blocked (export is never gated).
use std::collections::{BTreeMap, BTreeSet};

use super::{ExportDiaryHold, ExportDiaryHoldReason, ExportDiaryRead};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::memory::{DiaryEntryAdmission, DiaryReadGate, DiaryReadHold};
use crate::write_envelope::WriteActor;

/// The reason every export's diary read states.
pub const EXPORT_DIARY_READ_REASON: &str = "export";

/// The author of the NOTE `body` when it is a diary.
pub(crate) fn diary_author(body: &[u8]) -> Option<EntityId> {
    crate::note::decode_note_body_using(body, crate::note::NoteKind::wire)
        .ok()
        .filter(|note| note.kind == crate::note::NoteKind::Diary)
        .map(|note| note.author_ref)
}

/// One export's diary reads: the gate, the entries it admitted, and the
/// entries it held, by agent.
pub(crate) struct ExportDiaryLedger {
    gate: DiaryReadGate,
    read: BTreeMap<EntityId, BTreeSet<EntityId>>,
    held: BTreeMap<(EntityId, ExportDiaryHoldReason), u64>,
}

impl ExportDiaryLedger {
    /// The ledger of `reader`'s export: the owner who exports, or for an
    /// export-first removal the owner who receives it.
    pub(crate) fn new(reader: WriteActor) -> Result<Self> {
        Ok(Self {
            gate: DiaryReadGate::new(reader, EXPORT_DIARY_READ_REASON)?,
            read: BTreeMap::new(),
            held: BTreeMap::new(),
        })
    }

    /// Admits `entry`, a diary entry by `agent`: true when it is read.
    pub(crate) fn admit(
        &mut self,
        vault: &Vault,
        rtxn: &heed::RoTxn<'_>,
        agent: EntityId,
        entry: EntityId,
    ) -> Result<bool> {
        match self.gate.admit(vault, rtxn, agent, entry)? {
            DiaryEntryAdmission::Read => {
                self.read.entry(agent).or_default().insert(entry);
                Ok(true)
            }
            DiaryEntryAdmission::Held(hold) => {
                let reason = match hold {
                    DiaryReadHold::PendingReview => ExportDiaryHoldReason::AgentReviewPending,
                    DiaryReadHold::Declined => ExportDiaryHoldReason::Declined,
                    DiaryReadHold::NotCovered => ExportDiaryHoldReason::NotCoveredByGrant,
                };
                *self.held.entry((agent, reason)).or_default() += 1;
                Ok(false)
            }
        }
    }

    /// Logs the reads through the gate, after the snapshot. Returns the reads
    /// for the receipt, the holds for the manifest, and the entries to leave
    /// out: when the read log cannot be written, no admitted entry leaves
    /// unlogged, and the export goes on without them.
    pub(crate) fn finish(
        mut self,
        vault: &Vault,
    ) -> (
        Vec<ExportDiaryRead>,
        Vec<ExportDiaryHold>,
        BTreeSet<EntityId>,
    ) {
        let mut unlogged = BTreeSet::new();
        let reads = match self.gate.finish(vault) {
            Ok(receipt) => {
                let reason = receipt.reason;
                receipt
                    .agents
                    .into_iter()
                    .filter(|agent| agent.entries > 0)
                    .map(|agent| ExportDiaryRead {
                        agent: agent.agent.to_hex(),
                        diaries: agent.entries,
                        reason: reason.clone(),
                    })
                    .collect()
            }
            Err(error) => {
                tracing::warn!(%error, "export diary read log unwritable; diaries held out");
                for (agent, entries) in std::mem::take(&mut self.read) {
                    *self
                        .held
                        .entry((agent, ExportDiaryHoldReason::ReadLogUnavailable))
                        .or_default() += entries.len() as u64;
                    unlogged.extend(entries);
                }
                Vec::new()
            }
        };
        let holds = self
            .held
            .into_iter()
            .map(|((agent, reason), diaries)| ExportDiaryHold {
                agent: agent.to_hex(),
                diaries,
                reason,
            })
            .collect();
        (reads, holds, unlogged)
    }
}
