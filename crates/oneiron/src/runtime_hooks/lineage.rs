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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageLink {
    #[serde(with = "crate::serialize::entity_ref")]
    pub binding: EntityId,
    pub run_key: String,
    #[serde(with = "crate::serialize::entity_ref")]
    pub entity: EntityId,
    pub position: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HookLineage {
    chain: Vec<LineageLink>,
}

/// Why a check was raised.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookCheck {
    #[serde(with = "crate::serialize::entity_ref")]
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

/// `parent` plus this run, and the check it raises, if any.
pub(super) fn extend(
    parent: &[LineageLink],
    link: LineageLink,
) -> (Vec<LineageLink>, Option<HookCheckReason>) {
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
        CHECKS
            .iter_from(&self.store, &rtxn, &[])?
            .take(MAX_CHECKS_LISTED)
            .map(|row| row.map(|(_, check)| check))
            .collect()
    }
}
