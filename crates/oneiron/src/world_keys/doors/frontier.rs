//! The read-only plan of one machine's wraps of one key (FIX 5552): the rows
//! its records name, how its recipients split across records within the
//! codec's bounds, and whether the first record names the frontier, decided
//! before anything is sealed or signed.
//!
//! The writer (`append`) plans and then seals and signs exactly this plan;
//! an owner's diagnostics plan the same way from a fresh snapshot, per key
//! and across restarts, and write nothing. The plan never mints, wraps,
//! raises OF-520's question or touches the store: the writer raises the
//! question when a plan is too wide ([`WrapsWide`]). A plan on the frontier
//! counts only the parents its records name, so a world whose explicit
//! evidence outgrows one record is too wide only when the frontier does not
//! carry it (FIX 5680).

use std::collections::BTreeSet;

use super::super::WrapRecipient;
use crate::authority::{
    AuthorityEntryHash, AuthorityFold, AuthorityKey, KeyFrontier, MAX_PARENTS, WORLD_KEY_WRAPS_MAX,
    scope_head, standing_rows,
};
use crate::error::Result;
use crate::{EntityId, Vault};

/// Whether a record's width counts only the parents it names (FIX 5680;
/// CALLS "FIX 5680 frontier width", Engine 10-20 01:1x): a frontier
/// candidate that carries every row the records would name explicitly takes
/// them whatever that evidence's width, so the world asks no OF-520 question
/// and takes no bridge record. A candidate that does not carry them leaves
/// the plan on today's explicit rows and widths.
const FRONTIER_WIDTH_ON_SELECTED_PARENTS: bool = true;

/// Which parents an append's records may name.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Parents {
    /// The frontier candidate when it carries every row the records would
    /// name, else those rows.
    Frontier,
    /// The rows the records' evidence rests on alone: a view the store has
    /// moved past (repin's old-pin pre-wrap, CALLS "FIX 5464 partial
    /// evidence").
    Explicit,
}

/// The signer's previous row of the world, which the plan's first record
/// names beside its parents.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChainHead {
    /// A row this store holds, or none: what the writer chains to.
    Row(Option<AuthorityEntryHash>),
    /// A row an earlier append of the same door writes first: the first
    /// record names it as one more parent, and a read-only plan, which
    /// cannot read it, keeps the records off the frontier.
    Planned,
}

impl ChainHead {
    /// `signer`'s previous row of `world` on `fold`, before any append.
    pub(crate) fn of(fold: &AuthorityFold, signer: &AuthorityKey, world: EntityId) -> Self {
        Self::Row(scope_head(fold, signer, world))
    }

    /// Whether the first record names this head beside `parents` and `rows`:
    /// a row among them counts once, there.
    fn named_beside(
        self,
        parents: &BTreeSet<AuthorityEntryHash>,
        rows: &BTreeSet<AuthorityEntryHash>,
    ) -> bool {
        match self {
            Self::Row(chain) => {
                chain.is_some_and(|chain| !parents.contains(&chain) && !rows.contains(&chain))
            }
            Self::Planned => true,
        }
    }
}

/// What one plan is for: the snapshot, the signer, the key's world, its
/// recipients and the owner work request the records do.
pub(crate) struct WrapPlanInput<'a> {
    pub(crate) fold: &'a AuthorityFold,
    pub(crate) machine: EntityId,
    pub(crate) world: EntityId,
    pub(crate) recipients: &'a [WrapRecipient],
    pub(crate) chain: ChainHead,
    pub(crate) request: Option<AuthorityEntryHash>,
    pub(crate) parents: Parents,
}

/// One record of a plan: the parents it names and its recipients, by their
/// index in the input.
pub(crate) struct PlannedRecord {
    pub(crate) parents: BTreeSet<AuthorityEntryHash>,
    pub(crate) recipients: Vec<usize>,
}

/// The records one append signs, in order.
pub(crate) struct WrapPlan {
    pub(crate) records: Vec<PlannedRecord>,
    /// The first record names the frontier candidate and each later one the
    /// record before it (FIX 5464).
    pub(crate) on_frontier: bool,
}

/// A record on the explicit rows would name more rows than one record may:
/// `rows`. `base` when the world's edits and the standing rows alone are too
/// many, else a recipient's standing beside them. Never raised for a plan on
/// the frontier ([`FRONTIER_WIDTH_ON_SELECTED_PARENTS`]).
pub(crate) struct WrapsWide {
    pub(crate) rows: usize,
    pub(crate) base: bool,
}

impl Vault {
    /// The plan of `input`'s wraps in `txn`'s snapshot: the world's live
    /// edits, the rows each named machine's standing rests on, the pinned
    /// root's record and the request, counted before any split. A frontier
    /// candidate that carries those rows and every recipient's standing takes
    /// the records first, its parents alone counted (FIX 5680); otherwise
    /// recipients split across records so each stays within the codec's
    /// bounds, then the frontier choice. Reads only.
    pub(crate) fn plan_world_key_wraps_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        input: &WrapPlanInput<'_>,
    ) -> Result<std::result::Result<WrapPlan, WrapsWide>> {
        let fold = input.fold;
        let frontier = fold.worlds.get(&input.world);
        let mut base: BTreeSet<AuthorityEntryHash> = frontier
            .into_iter()
            .flat_map(|folded| folded.live.keys().copied())
            .collect();
        base.extend(standing_rows(fold, input.machine));
        if let Some(root) = self.pinned_root_recipient_in_txn(txn, fold)? {
            base.insert(root.entry);
        }
        base.extend(input.request);
        // Whether a live edit counts may rest on a later revision of its
        // machine, so name those too while they stay few (as the settings
        // door does).
        let authors: BTreeSet<_> = frontier
            .into_iter()
            .flat_map(|folded| folded.live.values())
            .flat_map(|author| standing_rows(fold, *author))
            .collect();
        if base.union(&authors).count() <= MAX_PARENTS / 2 {
            base.extend(authors);
        }
        if FRONTIER_WIDTH_ON_SELECTED_PARENTS {
            // A frontier that does not read here leaves the plan on today's
            // path: the explicit width rule below decides, as it did.
            match self.selected_frontier_plan_in_txn(txn, input, &base) {
                Ok(Some(plan)) => return Ok(Ok(plan)),
                Ok(None) => {}
                Err(error) => tracing::warn!(
                    kind = ?error.kind(),
                    "a world key's frontier did not read for its width; its records keep today's plan"
                ),
            }
        }
        // Each record names its signer's previous row of the world beside
        // these: the first names the scope head, which counts once when it is
        // already a live edit here, and each later one the record before it
        // (Astra #1422d F1).
        let named = |parents: &BTreeSet<AuthorityEntryHash>,
                     rows: &BTreeSet<AuthorityEntryHash>,
                     first: bool| {
            let chained = !first || input.chain.named_beside(parents, rows);
            parents.union(rows).count() + usize::from(chained)
        };
        let base_named = named(&base, &BTreeSet::new(), true);
        if base_named > MAX_PARENTS {
            return Ok(Err(WrapsWide {
                rows: base_named,
                base: true,
            }));
        }
        let mut records: Vec<PlannedRecord> = Vec::new();
        let mut parents = base.clone();
        let mut wraps = Vec::new();
        for (index, recipient) in input.recipients.iter().enumerate() {
            let rows = match recipient {
                WrapRecipient::Machine(id) => standing_rows(fold, *id),
                WrapRecipient::RecoveryRoot(_) => BTreeSet::new(),
            };
            let full = |parents: &BTreeSet<_>, wraps: &Vec<_>, first: bool| {
                named(parents, &rows, first) > MAX_PARENTS || wraps.len() == WORLD_KEY_WRAPS_MAX
            };
            if full(&parents, &wraps, records.is_empty()) && !wraps.is_empty() {
                records.push(PlannedRecord {
                    parents: std::mem::replace(&mut parents, base.clone()),
                    recipients: std::mem::take(&mut wraps),
                });
            }
            if full(&parents, &wraps, records.is_empty()) {
                return Ok(Err(WrapsWide {
                    rows: named(&parents, &rows, records.is_empty()),
                    base: false,
                }));
            }
            parents.extend(rows);
            wraps.push(index);
        }
        records.push(PlannedRecord {
            parents,
            recipients: wraps,
        });
        let on_frontier = match (input.parents, input.chain) {
            (Parents::Frontier, ChainHead::Row(chain)) => {
                self.frontier_records_in_txn(txn, fold, input.world, chain, &mut records)?
            }
            (Parents::Frontier, ChainHead::Planned) | (Parents::Explicit, _) => false,
        };
        Ok(Ok(WrapPlan {
            records,
            on_frontier,
        }))
    }

    /// The plan of `input`'s wraps on its frontier candidate (FIX 5680): when
    /// the candidate carries `base` and every recipient's standing, the rows
    /// today's records would name explicitly, the first record names the
    /// candidate, which holds its signer's previous row of the world beneath
    /// it, and each later one only the record before it. A record's width is
    /// then its selected parents' alone (the candidate is within one record's
    /// bound), and recipients split by [`WORLD_KEY_WRAPS_MAX`] only; no
    /// recipients still make one record. `None` for explicit parents, a
    /// planned chain, no candidate or one that does not carry those rows: the
    /// plan stays on today's path.
    fn selected_frontier_plan_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        input: &WrapPlanInput<'_>,
        base: &BTreeSet<AuthorityEntryHash>,
    ) -> Result<Option<WrapPlan>> {
        let (Parents::Frontier, ChainHead::Row(chain)) = (input.parents, input.chain) else {
            return Ok(None);
        };
        let mut named = base.clone();
        for recipient in input.recipients {
            if let WrapRecipient::Machine(id) = recipient {
                named.extend(standing_rows(input.fold, *id));
            }
        }
        let Some(mut frontier) =
            KeyFrontier::of_in_txn(&self.store, txn, input.fold, input.world, chain)?
        else {
            return Ok(None);
        };
        if !frontier.carries_in_txn(&self.store, txn, input.fold, &named)? {
            return Ok(None);
        }
        let indices: Vec<usize> = (0..input.recipients.len()).collect();
        let records = indices
            .chunks(WORLD_KEY_WRAPS_MAX)
            .map(<[usize]>::to_vec)
            .chain(input.recipients.is_empty().then(Vec::new))
            .enumerate()
            .map(|(index, recipients)| PlannedRecord {
                parents: if index == 0 {
                    frontier.parents().clone()
                } else {
                    BTreeSet::new()
                },
                recipients,
            })
            .collect();
        Ok(Some(WrapPlan {
            records,
            on_frontier: true,
        }))
    }

    /// Whether `records` go on frontier parents (FIX 5464, CALLS "FIX 5464
    /// side parents"), decided before any record is signed: when the frontier
    /// candidate carries every row the records name, the first record names
    /// the candidate, which holds its signer's previous row of the world
    /// (`chain`) beneath it, and each later one only the record before it.
    /// Otherwise the records keep the rows they name, and nothing changes.
    fn frontier_records_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        world: EntityId,
        chain: Option<AuthorityEntryHash>,
        records: &mut [PlannedRecord],
    ) -> Result<bool> {
        let Some(mut frontier) = KeyFrontier::of_in_txn(&self.store, txn, fold, world, chain)?
        else {
            return Ok(false);
        };
        let named: BTreeSet<_> = records
            .iter()
            .flat_map(|record| record.parents.iter().copied())
            .collect();
        if !frontier.carries_in_txn(&self.store, txn, fold, &named)? {
            return Ok(false);
        }
        for (index, record) in records.iter_mut().enumerate() {
            record.parents = if index == 0 {
                frontier.parents().clone()
            } else {
                BTreeSet::new()
            };
        }
        Ok(true)
    }
}
