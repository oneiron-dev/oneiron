//! The withdrawal fences and epoch floors a window carries (OF-013, FIX
//! 2867), through canonical capture and rebuild (FIX 8820). A window
//! rebuilt from the artifact carries them again, so the forward pass stages
//! them before its entity pass, as a window open does, and a withdrawn body
//! the artifact still names is refused whichever carrier wins its key.
//!
//! Rows keep the window map's grammar (`sync::withdrawn_cutoffs`): an
//! artifact's newest withdrawn generation and its replacement under its
//! lowercase id, the shared nine-byte cutoff (FIX 931: the generation eight
//! bytes big-endian, then the tag of an epoch keyframe or a Shell); a
//! lineage's epoch floor under `epoch_floor/` and its session's id, then `/`
//! and its conversation's id for a conversation's lineage (FIX 5029), its
//! epoch and the turn it ended at, eight bytes big-endian each. A fence whose
//! artifact body the window no longer holds stays. A floor of a session or
//! conversation this vault removed goes, as every export drops it.

use loro::LoroDoc;
use serde::{Deserialize, Serialize};

#[cfg(feature = "sync")]
use super::ByteBudget;
use super::{CanonicalSnapshot, id, insert};
use crate::deletion::{WithdrawnCutoff, WithdrawnReplacement};
use crate::error::Result;

/// The window root map of cutoffs, as sync files it.
const WITHDRAWN_CUTOFFS: &str = "withdrawn_cutoffs";
/// The key prefix of a lineage's epoch floor in that map.
const EPOCH_FLOOR: &str = "epoch_floor/";

/// One row of a window's cutoff map.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum CanonicalCutoff {
    /// The newest withdrawn generation of an artifact, and whether a Shell,
    /// its header alone, stands in for it rather than an epoch keyframe (FIX
    /// 931).
    Withdrawn {
        artifact: [u8; 16],
        generation: u64,
        shell: bool,
    },
    /// A lineage's epoch floor: the removed epoch and the turn it ended at.
    /// `conversation` names a conversation's lineage within the session
    /// (FIX 5029); none names the session's own.
    EpochFloor {
        session: [u8; 16],
        #[serde(default, skip_serializing_if = "Option::is_none")]
        conversation: Option<[u8; 16]>,
        epoch: u64,
        turn_end: u64,
    },
}

impl CanonicalCutoff {
    /// The key the window map files this row under.
    pub(super) fn key(&self) -> Result<String> {
        Ok(match self {
            Self::Withdrawn { artifact, .. } => id(*artifact)?.to_hex(),
            Self::EpochFloor {
                session,
                conversation: None,
                ..
            } => format!("{EPOCH_FLOOR}{}", id(*session)?.to_hex()),
            Self::EpochFloor {
                session,
                conversation: Some(conversation),
                ..
            } => format!(
                "{EPOCH_FLOOR}{}/{}",
                id(*session)?.to_hex(),
                id(*conversation)?.to_hex()
            ),
        })
    }

    /// The bytes the window map holds for it.
    fn value(&self) -> Vec<u8> {
        match self {
            Self::Withdrawn {
                generation, shell, ..
            } => WithdrawnCutoff {
                generation: *generation,
                replacement: if *shell {
                    WithdrawnReplacement::Shell
                } else {
                    WithdrawnReplacement::EpochKeyframe
                },
            }
            .encode()
            .to_vec(),
            Self::EpochFloor {
                epoch, turn_end, ..
            } => [epoch.to_be_bytes(), turn_end.to_be_bytes()].concat(),
        }
    }
}

/// Carries every cutoff `doc` holds, sorted by key, read through the map's
/// own admission grammar. A row the grammar refuses is left out with a
/// warning, as the window's own staging leaves it out; a floor of a session
/// or conversation this vault removed is left out too.
#[cfg(feature = "sync")]
pub(super) fn capture(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    doc: &LoroDoc,
    snapshot: &mut CanonicalSnapshot,
    budget: &mut ByteBudget,
) -> Result<()> {
    use crate::sync::withdrawn_cutoffs::{CarriedCutoff, admit_withdrawn_cutoff_carrier};
    for (key, value) in super::binary_rows_within(doc, WITHDRAWN_CUTOFFS, budget)? {
        let row = match admit_withdrawn_cutoff_carrier(&key, &loro::LoroValue::from(value)) {
            // The tag rides the row as the live map held it (FIX 931).
            Ok(CarriedCutoff::Withdrawn(artifact, cutoff)) => CanonicalCutoff::Withdrawn {
                artifact: *artifact.as_bytes(),
                generation: cutoff.generation,
                shell: cutoff.replacement == WithdrawnReplacement::Shell,
            },
            Ok(CarriedCutoff::EpochFloor(scope, epoch, turn_end)) => {
                if crate::sync::withdrawn_cutoffs::epoch_floor_removed_in(vault, txn, &scope)? {
                    continue;
                }
                CanonicalCutoff::EpochFloor {
                    session: *scope.session.as_bytes(),
                    conversation: scope
                        .conversation
                        .map(|conversation| *conversation.as_bytes()),
                    epoch,
                    turn_end,
                }
            }
            Err(_) => {
                tracing::warn!(
                    window = %snapshot.window,
                    key = %key,
                    "withdrawn cutoff malformed; left out of the canonical snapshot"
                );
                continue;
            }
        };
        snapshot.withdrawn_cutoffs.push(row);
    }
    sort(&mut snapshot.withdrawn_cutoffs)
}

#[cfg(feature = "sync")]
fn sort(rows: &mut Vec<CanonicalCutoff>) -> Result<()> {
    let mut keyed = std::mem::take(rows)
        .into_iter()
        .map(|row| Ok((row.key()?, row)))
        .collect::<Result<Vec<_>>>()?;
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    rows.extend(keyed.into_iter().map(|(_, row)| row));
    Ok(())
}

/// Each row names a canonical id, and the rows sort by their map key, each
/// key once.
#[derive(Default)]
pub(super) struct WithdrawnCutoffsValidation {
    stage: CutoffValidationStage,
    next: usize,
    keys: Vec<String>,
}

#[derive(Default)]
enum CutoffValidationStage {
    #[default]
    Keys,
    Strict,
}

impl WithdrawnCutoffsValidation {
    pub(super) fn advance(
        &mut self,
        snapshot: &CanonicalSnapshot,
        max_rows: usize,
    ) -> Result<bool> {
        let page = max_rows.max(1);
        match self.stage {
            CutoffValidationStage::Keys => {
                let rows = &snapshot.withdrawn_cutoffs;
                let end = self.next.saturating_add(page).min(rows.len());
                for row in &rows[self.next..end] {
                    self.keys.push(row.key()?);
                }
                self.next = end;
                if self.next < rows.len() {
                    return Ok(false);
                }
                // Every native key error precedes the first ordering error.
                self.next = 0;
                self.stage = CutoffValidationStage::Strict;
                Ok(self.keys.is_empty())
            }
            CutoffValidationStage::Strict => {
                let end = self.next.saturating_add(page).min(self.keys.len());
                crate::recovery::validation::strict(
                    self.keys[self.next.saturating_sub(1)..end].iter(),
                )?;
                self.next = end;
                Ok(self.next == self.keys.len())
            }
        }
    }

    pub(super) fn position(&self) -> (&'static str, usize) {
        let stage = match self.stage {
            CutoffValidationStage::Keys => "keys",
            CutoffValidationStage::Strict => "strict",
        };
        (stage, self.next)
    }
}

/// Files one cutoff back in the rebuilt window's map, where the forward pass
/// stages it before its entity pass.
pub(super) fn rebuild_row(doc: &LoroDoc, row: &CanonicalCutoff) -> Result<()> {
    insert(doc, WITHDRAWN_CUTOFFS, &row.key()?, &row.value())
}

#[cfg(feature = "sync")]
impl CanonicalSnapshot {
    /// The cutoffs as this vault recovers them: a floor of a session or
    /// conversation this vault removed since the capture goes.
    pub(in crate::recovery) fn settle_cutoffs_here(
        &mut self,
        vault: &crate::Vault,
        txn: &heed::RoTxn<'_>,
    ) -> Result<()> {
        let mut kept = Vec::with_capacity(self.withdrawn_cutoffs.len());
        for row in std::mem::take(&mut self.withdrawn_cutoffs) {
            if let CanonicalCutoff::EpochFloor {
                session,
                conversation,
                ..
            } = &row
            {
                let mut removed = false;
                for owner in std::iter::once(session).chain(conversation) {
                    removed |= crate::ports::removed_in_txn(&vault.store, txn, &id(*owner)?)?;
                }
                if removed {
                    continue;
                }
            }
            kept.push(row);
        }
        self.withdrawn_cutoffs = kept;
        Ok(())
    }
}
