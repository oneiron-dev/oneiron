//! The owner's learned decision bands, kept in the vault (ARCH-0076 promise-dura-10: a
//! learned band's mode and its version stay in effect after a restart). The band doors
//! write each row here first; a host loads every row into its [`DecisionBandPolicy`]
//! whenever it builds its bands.
//!
//! [`DecisionBandPolicy`]: super::DecisionBandPolicy

use super::{DecisionBand, DecisionQuestion, LearnedBand, LearnedBandKey, Reversibility};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Error, Result, Vault};

/// Every learned row. Key: id16(question) + u32be(question version) + u8(reversibility).
const BANDS: SideTable<(EntityId, [u8; 4], [u8; 1]), LearnedBand, Named> =
    SideTable::new(&side_table::DECISION_BAND);

/// The stored byte of a reversibility class.
fn reversibility_byte(reversibility: Reversibility) -> u8 {
    match reversibility {
        Reversibility::ReversibleRead => 0,
        Reversibility::OutboundEffect => 1,
    }
}

/// The reversibility class a stored byte names; none for another byte.
fn reversibility_from_byte(byte: u8) -> Option<Reversibility> {
    match byte {
        0 => Some(Reversibility::ReversibleRead),
        1 => Some(Reversibility::OutboundEffect),
        _ => None,
    }
}

fn row_key(
    question: &DecisionQuestion,
    reversibility: Reversibility,
) -> (EntityId, [u8; 4], [u8; 1]) {
    (
        question.id,
        question.version.to_be_bytes(),
        [reversibility_byte(reversibility)],
    )
}

impl Vault {
    /// Learns `band` at `version` in shadow mode for `question` under `reversibility`, as
    /// [`super::DecisionBandPolicy::learn_shadow`] does, over the row the vault holds:
    /// `version` must advance the stored row's. Answers the row now stored.
    pub fn learn_decision_band(
        &self,
        question: &DecisionQuestion,
        reversibility: Reversibility,
        band: DecisionBand,
        version: u32,
    ) -> Result<LearnedBand> {
        let key = row_key(question, reversibility);
        self.with_write_txn_grouped(|txn| {
            let held = BANDS.get(&self.store, &*txn, &key)?;
            let row = LearnedBand::learned_over(held.as_ref(), question, band, version)?;
            BANDS.put(&self.store, txn, &key, &row)?;
            Ok(row)
        })
    }

    /// Enforces the stored band of `question` under `reversibility`, as
    /// [`super::DecisionBandPolicy::enforce`] does: a band the vault holds no row for is
    /// refused. Answers the row now stored.
    pub fn enforce_decision_band(
        &self,
        question: &DecisionQuestion,
        reversibility: Reversibility,
    ) -> Result<LearnedBand> {
        let key = row_key(question, reversibility);
        self.with_write_txn_grouped(|txn| {
            let held = BANDS.get(&self.store, &*txn, &key)?;
            let row = LearnedBand::enforced_over(held.as_ref(), question)?;
            BANDS.put(&self.store, txn, &key, &row)?;
            Ok(row)
        })
    }

    /// Every learned band the vault holds, by its question id, question version and
    /// reversibility class.
    pub fn learned_decision_bands(&self) -> Result<Vec<(LearnedBandKey, LearnedBand)>> {
        let txn = self.store.env.read_txn()?;
        BANDS
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|((question, version, [reversibility]), row)| {
                let reversibility = reversibility_from_byte(reversibility)
                    .ok_or(Error::CorruptedIndex("decision band reversibility"))?;
                Ok(((question, u32::from_be_bytes(version), reversibility), row))
            })
            .collect()
    }
}
