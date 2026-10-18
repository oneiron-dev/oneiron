//! A target's machine-claim history as the home serves it (FIX 3820), for a
//! machine that holds a handoff packet without its ancestors. The rows are
//! the ones a selector export carries beside the target: its birth, each
//! transition event and every handoff of its chain, read from this vault's
//! stored truth under its pin. They page by count; the cursor binds the
//! target and the tip the pages walk, and a moved tip starts over.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// The most history rows one page carries. CALLS: "FIX 3820 machine history
/// page".
pub const MACHINE_HISTORY_PAGE_ROWS: usize = 128;

/// Where a target's history paging stands: the target, the tip it walks (the
/// id of this vault's pinned handoff) and how many rows came before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MachineHistoryCursor {
    target: EntityId,
    tip: EntityId,
    offset: u64,
}

impl MachineHistoryCursor {
    /// The cursor as the wire carries it: the target and tip in hex, then the
    /// offset as 16 hex digits.
    #[must_use]
    pub fn encode(&self) -> String {
        format!(
            "{}{}{:016x}",
            self.target.to_hex(),
            self.tip.to_hex(),
            self.offset
        )
    }

    /// A cursor [`Self::encode`] wrote; `None` for anything else.
    #[must_use]
    pub fn decode(cursor: &str) -> Option<Self> {
        let target = EntityId::from_hex(cursor.get(..32)?).ok()?;
        let tip = EntityId::from_hex(cursor.get(32..64)?).ok()?;
        let offset = u64::from_str_radix(cursor.get(64..)?, 16).ok()?;
        let decoded = Self {
            target,
            tip,
            offset,
        };
        (decoded.encode() == cursor).then_some(decoded)
    }
}

/// One page of a target's machine-claim history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachineHistoryPage {
    /// This vault's own copy of the history does not resolve whole under its
    /// pin: it serves none of it.
    Pending,
    /// Rows of the history, each its id and raw envelope (metadata header,
    /// then body): the birth, then the transition events, then the handoffs
    /// oldest first.
    Rows {
        rows: Vec<(EntityId, Vec<u8>)>,
        /// Where the next page starts; past the last row once none is left.
        cursor: MachineHistoryCursor,
        /// Whether rows are left after this page.
        more: bool,
    },
}

/// One page of `target`'s machine-claim history, from where `cursor` stopped.
/// The pages walk the whole history back to genesis: no depth bounds it, only
/// the page size. A cursor of another target or another tip starts over at
/// the birth, since the history it paged has moved.
///
/// # Errors
///
/// Storage errors.
pub fn machine_history_page(
    vault: &Vault,
    target: EntityId,
    cursor: Option<MachineHistoryCursor>,
) -> Result<MachineHistoryPage> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(ids) = crate::sync::selector::machine_history_controls(vault, &rtxn, target)? else {
        return Ok(MachineHistoryPage::Pending);
    };
    let Some(&tip) = ids.last() else {
        return Ok(MachineHistoryPage::Pending);
    };
    let start = cursor
        .filter(|cursor| cursor.target == target && cursor.tip == tip)
        .map_or(0, |cursor| {
            usize::try_from(cursor.offset).map_or(ids.len(), |offset| offset.min(ids.len()))
        });
    let mut rows = Vec::new();
    for id in ids.iter().skip(start).take(MACHINE_HISTORY_PAGE_ROWS) {
        let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, &rtxn, id)?
        else {
            return Ok(MachineHistoryPage::Pending);
        };
        rows.push((*id, raw));
    }
    let end = start + rows.len();
    Ok(MachineHistoryPage::Rows {
        rows,
        cursor: MachineHistoryCursor {
            target,
            tip,
            offset: u64::try_from(end).unwrap_or(u64::MAX),
        },
        more: end < ids.len(),
    })
}
