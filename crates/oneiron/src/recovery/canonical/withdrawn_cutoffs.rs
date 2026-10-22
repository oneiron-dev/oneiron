//! The withdrawal fences and session epoch floors a window carries (OF-013,
//! FIX 2867), through canonical capture and rebuild (FIX 8820). A window
//! rebuilt from the artifact carries them again, so the forward pass stages
//! them before its entity pass, as a window open does, and a withdrawn body
//! the artifact still names is refused whichever carrier wins its key.
//!
//! Rows keep the window map's grammar (`sync::withdrawn_cutoffs`): an
//! artifact's newest withdrawn generation under its lowercase id, eight bytes
//! big-endian; a session's epoch floor under `epoch_floor/` and its id, its
//! epoch and the turn it ended at, eight bytes big-endian each. A fence whose
//! artifact body the window no longer holds stays. A floor of a session this
//! vault removed goes, as every export drops it.

use loro::LoroDoc;
use serde::{Deserialize, Serialize};

#[cfg(feature = "sync")]
use super::ByteBudget;
use super::{CanonicalSnapshot, id, insert};
use crate::error::Result;

/// The window root map of cutoffs, as sync files it.
const WITHDRAWN_CUTOFFS: &str = "withdrawn_cutoffs";
/// The key prefix of a session's epoch floor in that map.
const EPOCH_FLOOR: &str = "epoch_floor/";

/// One row of a window's cutoff map.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum CanonicalCutoff {
    /// The newest withdrawn generation of an artifact.
    Withdrawn { artifact: [u8; 16], generation: u64 },
    /// A session's epoch floor: the removed epoch and the turn it ended at.
    EpochFloor {
        session: [u8; 16],
        epoch: u64,
        turn_end: u64,
    },
}

impl CanonicalCutoff {
    /// The key the window map files this row under.
    pub(super) fn key(&self) -> Result<String> {
        Ok(match self {
            Self::Withdrawn { artifact, .. } => id(*artifact)?.to_hex(),
            Self::EpochFloor { session, .. } => format!("{EPOCH_FLOOR}{}", id(*session)?.to_hex()),
        })
    }

    /// The bytes the window map holds for it.
    fn value(&self) -> Vec<u8> {
        match self {
            Self::Withdrawn { generation, .. } => generation.to_be_bytes().to_vec(),
            Self::EpochFloor {
                epoch, turn_end, ..
            } => [epoch.to_be_bytes(), turn_end.to_be_bytes()].concat(),
        }
    }
}

/// Carries every cutoff `doc` holds, sorted by key, read through the map's
/// own admission grammar. A row the grammar refuses is left out with a
/// warning, as the window's own staging leaves it out; a floor of a session
/// this vault removed is left out too.
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
            Ok(CarriedCutoff::Withdrawn(artifact, generation)) => CanonicalCutoff::Withdrawn {
                artifact: *artifact.as_bytes(),
                generation,
            },
            Ok(CarriedCutoff::EpochFloor(session, epoch, turn_end)) => {
                if crate::ports::removed_in_txn(&vault.store, txn, &session)? {
                    continue;
                }
                CanonicalCutoff::EpochFloor {
                    session: *session.as_bytes(),
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
pub(super) fn validate(snapshot: &CanonicalSnapshot) -> Result<()> {
    let keys = snapshot
        .withdrawn_cutoffs
        .iter()
        .map(CanonicalCutoff::key)
        .collect::<Result<Vec<_>>>()?;
    crate::recovery::validation::strict(keys.iter())
}

/// Files one cutoff back in the rebuilt window's map, where the forward pass
/// stages it before its entity pass.
pub(super) fn rebuild_row(doc: &LoroDoc, row: &CanonicalCutoff) -> Result<()> {
    insert(doc, WITHDRAWN_CUTOFFS, &row.key()?, &row.value())
}

#[cfg(feature = "sync")]
impl CanonicalSnapshot {
    /// The cutoffs as this vault recovers them: a floor of a session this
    /// vault removed since the capture goes.
    pub(in crate::recovery) fn settle_cutoffs_here(
        &mut self,
        vault: &crate::Vault,
        txn: &heed::RoTxn<'_>,
    ) -> Result<()> {
        let mut kept = Vec::with_capacity(self.withdrawn_cutoffs.len());
        for row in std::mem::take(&mut self.withdrawn_cutoffs) {
            if let CanonicalCutoff::EpochFloor { session, .. } = &row
                && crate::ports::removed_in_txn(&vault.store, txn, &id(*session)?)?
            {
                continue;
            }
            kept.push(row);
        }
        self.withdrawn_cutoffs = kept;
        Ok(())
    }
}
