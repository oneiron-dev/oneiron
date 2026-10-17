//! `describe(vault)`'s card (ARCH-0070 doors): the arrangement at a glance
//! and what its actors can send, a free read. The editable seed is
//! `vault.shape.read`; this card is what the arrangement amounts to.
use super::ShapeReach;
use super::reach::reach_projection;
use crate::error::Result;
use crate::{EntityId, Vault};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The vault's shape card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ShapeCard {
    /// The stored seed's revision; none until a seed is first stored.
    pub seed_id: Option<String>,
    /// The live setup rows the caller reads, counted by kind.
    pub counts: BTreeMap<String, u32>,
    /// Applies with an item still waiting for the owner's word, or torn.
    pub open_applies: u32,
    /// Every send path the caller reads.
    pub reach: ShapeReach,
    /// The reach in one line.
    pub line: String,
}

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
        let mut counts = BTreeMap::new();
        for (row, _) in &live.rows {
            *counts.entry(row.target().kind().to_owned()).or_insert(0u32) += 1;
        }
        let reach = reach_projection(&live.reach).visible(visible)?;
        Ok(ShapeCard {
            seed_id: self.shape_seed()?.map(|stored| stored.id),
            counts,
            open_applies: u32::try_from(self.open_shape_applies()?.len()).unwrap_or(u32::MAX),
            line: reach.line(),
            reach,
        })
    }
}
