//! Source revisions that bind a sheet answer split to its settlement transaction.

use super::{Split, UnitWithdrawal};
use crate::Vault;
use crate::blob_artifact::read_blob_artifact_head_in_txn;
use crate::edit_roundtrip::EditProposal;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::office_body::LivePin;
use crate::provenance::made_by::MadeBy;

pub(in crate::edit_settle) struct SheetKeep {
    sources: Vec<SourceRevision>,
    pub(in crate::edit_settle) split: Option<Split>,
}

struct SourceRevision {
    id: EntityId,
    head: Option<(u64, [u8; 32])>,
    live: Option<LivePin>,
}

impl SourceRevision {
    fn read(vault: &Vault, txn: &heed::RoTxn<'_>, id: EntityId) -> Result<Self> {
        Ok(Self {
            id,
            head: read_blob_artifact_head_in_txn(&vault.store, txn, &id)?
                .map(|head| (head.version, head.content_hash)),
            live: vault.office_body_pin_in_txn(txn, &id)?.map(|(pin, _)| pin),
        })
    }
}

impl SheetKeep {
    pub(in crate::edit_settle) fn is_current_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
    ) -> Result<bool> {
        for source in &self.sources {
            let current = SourceRevision::read(vault, txn, source.id)?;
            if source.head != current.head || source.live != current.live {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl Vault {
    pub(in crate::edit_settle) fn prepare_sheet_keep(
        &self,
        artifact: &EntityId,
        proposal: &EditProposal,
        made_by: Option<&MadeBy>,
        previous: Option<&UnitWithdrawal>,
    ) -> Result<Option<SheetKeep>> {
        let Some(bundle) = proposal.sheet_answers.as_deref() else {
            return Ok(None);
        };
        // Capture before splitting: recording revisions after it could certify a
        // newer file that the carried answer never read.
        let mut sources = Vec::<SourceRevision>::new();
        {
            let txn = self.store.env.read_txn()?;
            for id in std::iter::once(*artifact).chain(
                bundle
                    .answers
                    .iter()
                    .filter_map(|answer| answer.source.as_ref().map(|source| source.id)),
            ) {
                if !sources.iter().any(|source| source.id == id) {
                    sources.push(SourceRevision::read(self, &txn, id)?);
                }
            }
        }
        let mut split = self.split_sheet_answers(artifact, proposal, bundle, made_by, true)?;
        if let (Some(split), Some(previous)) = (&mut split, previous) {
            let mut answers = previous.answers.clone();
            answers.append(&mut split.withdrawal.answers);
            split.withdrawal.answers = answers;
        }
        let carried = match &split {
            Some(split) => split.carried.as_ref(),
            None => Some(proposal),
        };
        // Withdrawn files cannot invalidate the answers still being kept. An
        // all-withdrawn settlement appends no answer and needs no source retry.
        sources.retain(|source| {
            carried.is_some_and(|proposal| {
                source.id == *artifact
                    || proposal.sheet_answers.as_ref().is_some_and(|bundle| {
                        bundle.answers.iter().any(|answer| {
                            answer.value.is_some()
                                && answer
                                    .source
                                    .as_ref()
                                    .is_some_and(|pin| pin.id == source.id)
                        })
                    })
            })
        });
        Ok(Some(SheetKeep { sources, split }))
    }
}
