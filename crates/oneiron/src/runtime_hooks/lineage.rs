//! Causal lineage and the cycle check (ARCH-0080 §4 Lineage and loops). Every
//! row a hook lands keeps the chain of hooks and runs behind it. A cycle or a
//! deep chain raises an owner check; it never stops the run.

use serde::{Deserialize, Serialize};

use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Result, Vault};

use super::store::RunKey;

/// The chain behind each landed row, by row id (claim, proposal, task,
/// attempt or block).
const LINEAGE: SideTable<[u8; 16], HookLineage, Named> = SideTable::new(&side_table::HOOKS_LINEAGE);
/// Raised owner checks, by run key.
const CHECKS: SideTable<RunKey, HookCheck, Named> = SideTable::new(&side_table::HOOKS_CHECK);
/// A chain this deep raises a check.
pub(super) const MAX_LINEAGE_DEPTH: usize = 8;
/// The links a stored chain keeps, newest last.
const MAX_STORED_LINKS: usize = 32;
const MAX_CHECKS_LISTED: usize = 1_000;

/// One hop of a chain: a run of one binding on one fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LineageLink {
    #[serde(with = "crate::serialize::entity_ref")]
    #[schemars(with = "String")]
    pub binding: EntityId,
    pub run_key: String,
    #[serde(with = "crate::serialize::entity_ref")]
    #[schemars(with = "String")]
    pub entity: EntityId,
    pub position: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HookLineage {
    chain: Vec<LineageLink>,
}

/// Why a check was raised.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HookCheckReason {
    /// The same hook fired again inside its own causal chain.
    Cycle,
    /// The chain reached [`MAX_LINEAGE_DEPTH`].
    Depth,
}

impl HookCheckReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cycle => "cycle",
            Self::Depth => "depth",
        }
    }
}

/// An "is everything okay" check for the owner, with the chain shown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HookCheck {
    #[serde(with = "crate::serialize::entity_ref")]
    #[schemars(with = "String")]
    pub binding: EntityId,
    pub run_key: String,
    pub reason: HookCheckReason,
    pub chain: Vec<LineageLink>,
    pub raised_at: u64,
}

/// The chain behind `row`, empty when no hook landed it.
pub(super) fn chain_of(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    row: &EntityId,
) -> Result<Vec<LineageLink>> {
    Ok(LINEAGE
        .get(&vault.store, txn, row.as_bytes())?
        .map(|lineage| lineage.chain)
        .unwrap_or_default())
}

/// The chain behind this run on `entity` (`link`), and the check it raises,
/// if any: the chain behind the row, then [`extend`], with a watcher's next
/// occurrence read in `txn` ([`next_occurrence_in_txn`]; `due_at` only for a
/// tick).
pub(super) fn run_chain_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    entity: &EntityId,
    link: LineageLink,
    due_at: Option<u64>,
) -> Result<(Vec<LineageLink>, Option<HookCheckReason>)> {
    let parent = chain_of(vault, txn, entity)?;
    let next = next_occurrence_in_txn(vault, txn, &parent, &link.binding, due_at)?;
    Ok(extend(&parent, link, next))
}

/// Whether a run of `binding` on the tick of a TASK due at `due_at` is its
/// watcher's next occurrence (FIX 4749): the newest hop of `parent`, the
/// chain behind the TASK, is a run of the same binding, which Enqueued this
/// TASK, and that run committed before the TASK's due time. A successor
/// already due when it was Enqueued repeats at once, every runner pass, so
/// it is no next occurrence and raises the cycle check as any repeat does.
fn next_occurrence_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    parent: &[LineageLink],
    binding: &EntityId,
    due_at: Option<u64>,
) -> Result<bool> {
    let (Some(due_at), Some(newest)) = (due_at, parent.last()) else {
        return Ok(false);
    };
    if newest.binding != *binding {
        return Ok(false);
    }
    let Some(key) = run_key_of(&newest.run_key) else {
        return Ok(false);
    };
    Ok(super::store::MEMOS
        .get(&vault.store, txn, &key)?
        .is_some_and(|enqueued| enqueued.committed_at < due_at.saturating_mul(1_000)))
}

/// The run key a lineage hop spells as lowercase hex.
fn run_key_of(hex: &str) -> Option<RunKey> {
    if hex.len() != 64 {
        return None;
    }
    let mut key = [0_u8; 32];
    for (slot, pair) in key.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        *slot = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(key)
}

/// `parent` plus this run, and the check it raises, if any.
///
/// A watcher's next occurrence is no cycle (FIX 4749). When this run is one
/// ([`next_occurrence_in_txn`]), the run takes the newest hop's place, so a
/// recurring watcher keeps one depth however often it repeats, and the
/// cycle and depth checks read the chain behind that hop. Any other repeat
/// of a hook inside its own chain, through another hook, on a fact that is
/// no tick, or on a successor already due when it was Enqueued, is still a
/// cycle.
pub(super) fn extend(
    parent: &[LineageLink],
    link: LineageLink,
    next_occurrence: bool,
) -> (Vec<LineageLink>, Option<HookCheckReason>) {
    let parent = match parent.split_last() {
        Some((newest, behind)) if next_occurrence && newest.binding == link.binding => behind,
        _ => parent,
    };
    let reason = if parent.iter().any(|hop| hop.binding == link.binding) {
        Some(HookCheckReason::Cycle)
    } else if parent.len() >= MAX_LINEAGE_DEPTH {
        Some(HookCheckReason::Depth)
    } else {
        None
    };
    let skip = (parent.len() + 1).saturating_sub(MAX_STORED_LINKS);
    let chain = parent
        .iter()
        .cloned()
        .chain(std::iter::once(link))
        .skip(skip)
        .collect();
    (chain, reason)
}

pub(super) fn put_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    row: &[u8; 16],
    chain: &[LineageLink],
) -> Result<()> {
    LINEAGE.put(
        &vault.store,
        txn,
        row,
        &HookLineage {
            chain: chain.to_vec(),
        },
    )
}

pub(super) fn raise_check_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &RunKey,
    check: &HookCheck,
) -> Result<()> {
    CHECKS.put(&vault.store, txn, key, check)
}

impl Vault {
    /// The owner checks hooks raised: cycles and deep chains, oldest key
    /// first.
    pub fn hook_checks(&self) -> Result<Vec<HookCheck>> {
        let rtxn = self.store.env.read_txn()?;
        self.hook_checks_in_txn(&rtxn)
    }

    /// Reads the existing cycle and depth checks under the owner's live
    /// proof, in the same snapshot that reads the checks. Changes nothing.
    pub fn hook_checks_as_owner(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
    ) -> Result<Vec<HookCheck>> {
        let rtxn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &rtxn)?;
        self.hook_checks_in_txn(&rtxn)
    }

    fn hook_checks_in_txn(&self, txn: &heed::RoTxn<'_>) -> Result<Vec<HookCheck>> {
        CHECKS
            .iter_from(&self.store, txn, &[])?
            .take(MAX_CHECKS_LISTED)
            .map(|row| row.map(|(_, check)| check))
            .collect()
    }
}
