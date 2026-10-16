//! Hook blocks on the board (ARCH-0080 §11, OI-1 = A). A block is a timed
//! pin: the rows it names render in their usual sections, MEMORIES or TASKS,
//! tagged with the hook, for the block's lifetime. One token cap per binding
//! bounds what its blocks pin. There is no HOOKS section.

use std::collections::{BTreeMap, BTreeSet};

use super::memories::MemoriesSection;
use super::memories_frame::memory_row_text;
use super::memories_projection::foreign_row;
use super::memory_pins::pinned_row;
use super::TasksSection;
use crate::claim::{PointRead, ScopedRead, ScopedReadReceipt};
use crate::{EntityId, Result, Vault};

/// One live block a board delivery may carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookPin {
    pub block: EntityId,
    pub binding: EntityId,
    /// `<pack>/<hook>`, the tag the board shows.
    pub hook: String,
    pub refs: Vec<EntityId>,
    pub token_cap: u32,
}

impl Vault {
    /// The blocks that reach a board delivery for `session` on `branch`: live,
    /// and active by now. A block names its recipient session, or none to
    /// reach any; a board that names no session passes `""`.
    pub fn board_hook_pins(&self, session: &str, branch: Option<&str>) -> Result<Vec<HookPin>> {
        let now = self.store.clock.now_recorded_at();
        Ok(self
            .hook_blocks_for(session, branch)?
            .into_iter()
            .filter(|(_, block)| block.activation <= now)
            .map(|(id, block)| HookPin {
                block: id,
                binding: block.binding,
                hook: block.hook,
                refs: block.refs,
                token_cap: block.token_cap,
            })
            .collect())
    }

    /// Spends one delivery of each block a board carried, once its response
    /// is final. A block that spends its last delivery expires.
    pub fn record_board_hook_deliveries(&self, blocks: &BTreeSet<EntityId>) -> Result<()> {
        for block in blocks {
            self.record_hook_block_delivery(*block)?;
        }
        Ok(())
    }
}

impl MemoriesSection {
    /// Pins each block's rows, tagged with its hook. Every row reads under
    /// `reader`'s ceiling and `disclosure`'s clamp, as an explicit pin does,
    /// and a withheld row is skipped. A TASK is left to TASKS. A row already
    /// on the board renders once: a hook's pin takes its place, and a row
    /// another hook pinned keeps that hook's tag. A binding's rows stop at its
    /// token cap. Returns each read's receipt.
    pub fn include_hook_pins(
        &mut self,
        reader: &ScopedRead<'_>,
        pins: &[HookPin],
        disclosure: Option<&crate::disclosure::DisclosureContext>,
    ) -> Result<Vec<ScopedReadReceipt>> {
        let mut receipts = Vec::new();
        let mut spent = BTreeMap::<EntityId, usize>::new();
        let mut pinned = false;
        for pin in pins {
            for id in &pin.refs {
                let (receipt, row) = pinned_row(reader, PointRead::id(*id), None, disclosure)?;
                receipts.push(receipt);
                let Some(mut row) = row else {
                    continue;
                };
                if row.entity_type == crate::registry::ENTITY_TYPE_TASK
                    || self
                        .rows
                        .iter()
                        .any(|old| old.id == row.id && old.hook.is_some())
                {
                    continue;
                }
                row.hook = Some(pin.hook.clone());
                let cost =
                    crate::count_context_pack_tokens(&memory_row_text(&row, foreign_row(&row)));
                let used = spent.entry(pin.binding).or_default();
                if used.saturating_add(cost) > pin.token_cap as usize {
                    continue;
                }
                *used += cost;
                self.rows.retain(|old| old.id != row.id);
                self.rows.push(row);
                pinned = true;
            }
        }
        if pinned {
            self.refinish();
        }
        Ok(receipts)
    }

    /// The blocks whose rows this section carries under their hook's tag.
    #[must_use]
    pub fn hook_blocks_delivered(&self, pins: &[HookPin]) -> BTreeSet<EntityId> {
        pins.iter()
            .filter(|pin| {
                self.rows.iter().any(|row| {
                    row.hook.as_deref() == Some(pin.hook.as_str())
                        && pin.refs.iter().any(|id| id.to_hex() == row.id)
                })
            })
            .map(|pin| pin.block)
            .collect()
    }
}

impl TasksSection {
    /// Tags each TASKS row a block names with the block's hook, in place.
    /// The rows are the ones the caller's TASKS already reads; a block adds
    /// none. The first block to name a row tags it. Returns the blocks that
    /// tagged a row.
    pub fn tag_hook_pins(&mut self, pins: &[HookPin]) -> BTreeSet<EntityId> {
        let mut delivered = BTreeSet::new();
        let mut tagged = BTreeSet::new();
        for pin in pins {
            for id in &pin.refs {
                let id = id.to_hex();
                let Some(row) = self.rows.iter_mut().find(|row| row.id == id) else {
                    continue;
                };
                if !tagged.insert(id) {
                    continue;
                }
                row.line.push_str(" hook=");
                row.line.push_str(&super::quoted_leaf(&pin.hook));
                delivered.insert(pin.block);
            }
        }
        delivered
    }
}
