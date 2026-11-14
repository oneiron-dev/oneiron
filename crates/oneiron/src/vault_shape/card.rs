//! `describe(vault)`'s card (ARCH-0070 doors): the arrangement at a glance
//! and what its actors can send, a free read. The editable seed is
//! `vault.shape.read`; this card is what the arrangement amounts to.
use super::reach::reach_projection;
use crate::error::Result;
use crate::{EntityId, Vault};
use std::collections::BTreeMap;

#[doc(hidden)]
pub use oneiron_verb_wire::vault_shape::card::ShapeCard;

impl Vault {
    /// The shape card over the rows `visible` admits. The reach joins every
    /// row first and leaves out the paths `visible` hides.
    ///
    /// # Errors
    ///
    /// A read failure, an undecodable setup row, or `visible`'s own.
    pub fn shape_card_visible(
        &self,
        visible: &mut dyn FnMut(&EntityId) -> Result<bool>,
    ) -> Result<ShapeCard> {
        let live = self.read_live_shape(visible)?;
        // Open applies count as the caller reads them (FIX 10199), and the
        // seed is named only when its carrier is the caller's to read (FIX
        // 9960).
        let (seed, applies) = self.visible_seed_and_applies(&live.withheld, visible)?;
        let mut counts = BTreeMap::new();
        for (row, _) in &live.rows {
            *counts.entry(row.target().kind().to_owned()).or_insert(0u32) += 1;
        }
        // Judged before the naming snapshot opens: `visible` opens its own
        // (FIX 21880).
        let reach = reach_projection(&live.reach).visible(visible)?;
        let txn = self.store.env.read_txn()?;
        let reach = reach.named(&mut |reference| self.reach_name_in(&txn, reference))?;
        Ok(ShapeCard {
            seed_id: seed.map(|stored| stored.id),
            counts,
            open_applies: u32::try_from(applies.len()).unwrap_or(u32::MAX),
            line: reach.line(),
            reach,
        })
    }
}
