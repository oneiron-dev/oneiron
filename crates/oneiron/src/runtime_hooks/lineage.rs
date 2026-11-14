//! Causal lineage and the cycle check (ARCH-0080 §4 Lineage and loops). Every
//! row a hook lands keeps the chain of hooks and runs behind it. A cycle or a
//! deep chain raises an owner check; it never stops the run. A permanent
//! erase takes an erased entity out of every chain and check (FIX 22184),
//! and a chain or check written after it names none (FIX 22191).

use std::borrow::Cow;
use std::collections::BTreeSet;

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
    // The entity the run fired on, a verb run's caller; the erased marker,
    // spelled `ERASED_CALL_IDENTITY`, once a permanent erase took it.
    #[serde(with = "link_entity")]
    #[schemars(with = "String")]
    pub entity: EntityId,
    pub position: String,
}

/// The entity an erase leaves in a link in place of the erased one: the
/// reserved all-zero id, which no row has and no id parse yields, spelled
/// [`ERASED_CALL_IDENTITY`](crate::receipt::ERASED_CALL_IDENTITY) on the
/// wire ([`link_entity`]).
fn erased_entity() -> EntityId {
    EntityId::from_bytes_unchecked([0; 16])
}

/// A link's entity as its hex ref, or
/// [`ERASED_CALL_IDENTITY`](crate::receipt::ERASED_CALL_IDENTITY) for
/// [`erased_entity`].
mod link_entity {
    use serde::{Deserialize, Deserializer, Serializer};

    use crate::EntityId;
    use crate::receipt::ERASED_CALL_IDENTITY;

    pub(super) fn serialize<S: Serializer>(
        entity: &EntityId,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        if *entity == super::erased_entity() {
            serializer.serialize_str(ERASED_CALL_IDENTITY)
        } else {
            serializer.serialize_str(&entity.to_hex())
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<EntityId, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text == ERASED_CALL_IDENTITY {
            return Ok(super::erased_entity());
        }
        EntityId::from_hex(&text).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HookLineage {
    chain: Vec<LineageLink>,
}

#[doc(hidden)]
pub use oneiron_verb_wire::runtime_hooks::lineage::HookCheckReason;

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

/// Keeps `chain` behind the landed `row`. A row a permanent erase fenced
/// before this write gets no chain back (review #6797): a proposal's intent
/// can settle after its proposal is erased, as its dependencies name the
/// source, not the row. A link on an entity such an erase fenced names the
/// erased marker ([`fenced_in_txn`]).
pub(super) fn put_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    row: &[u8; 16],
    chain: &[LineageLink],
) -> Result<()> {
    if let Ok(id) = EntityId::from_bytes(*row)
        && super::store::source_erased_in_txn(vault, txn, &id)?
    {
        return Ok(());
    }
    let chain = fenced_in_txn(vault, txn, chain)?.into_owned();
    LINEAGE.put(&vault.store, txn, row, &HookLineage { chain })
}

/// Raises `check` under `key`. A link on an entity a permanent erase fenced
/// before this write names the erased marker ([`fenced_in_txn`]): a fact
/// run's own link names its entity, which can be erased while it runs.
pub(super) fn raise_check_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &RunKey,
    check: &HookCheck,
) -> Result<()> {
    let Cow::Owned(chain) = fenced_in_txn(vault, txn, &check.chain)? else {
        return CHECKS.put(&vault.store, txn, key, check);
    };
    let check = HookCheck {
        binding: check.binding,
        run_key: check.run_key.clone(),
        reason: check.reason,
        chain,
        raised_at: check.raised_at,
    };
    CHECKS.put(&vault.store, txn, key, &check)
}

/// `chain` as a write lands it: each link on an entity a permanent erase
/// fenced in this write's snapshot names the erased marker, as that erase's
/// scrub leaves a stored chain ([`scrub_erased_in_txn`]). So a chain built
/// before an erase and written after it names no erased entity, and the
/// erase's id is never scrubbed from lineage again (FIX 22191).
fn fenced_in_txn<'c>(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    chain: &'c [LineageLink],
) -> Result<Cow<'c, [LineageLink]>> {
    let mut checked = BTreeSet::new();
    let mut erased = BTreeSet::new();
    for link in chain {
        if checked.insert(link.entity)
            && link.entity != erased_entity()
            && super::store::source_erased_in_txn(vault, txn, &link.entity)?
        {
            erased.insert(link.entity);
        }
    }
    if erased.is_empty() {
        return Ok(Cow::Borrowed(chain));
    }
    let mut chain = chain.to_vec();
    erase_entities(&mut chain, |entity| erased.contains(entity));
    Ok(Cow::Owned(chain))
}

/// Names the erased marker ([`erased_entity`]) in each link of `chain` on
/// `id`; whether any was on it ([`erase_entities`]).
pub(super) fn erase_entity(chain: &mut [LineageLink], id: &EntityId) -> bool {
    erase_entities(chain, |entity| entity == id)
}

/// Names the erased marker ([`erased_entity`]) in each link of `chain`
/// whose entity `erased` takes; whether any was. Each link keeps its
/// binding, run key and position, all the cycle, depth and next-occurrence
/// checks read, so a chain checks as it did before the erase.
pub(super) fn erase_entities(
    chain: &mut [LineageLink],
    erased: impl Fn(&EntityId) -> bool,
) -> bool {
    let mut named = false;
    for link in chain.iter_mut().filter(|link| erased(&link.entity)) {
        link.entity = erased_entity();
        named = true;
    }
    named
}

/// `chain` as a write lands it after `erased`'s permanent erase
/// ([`erase_entity`]); as it is when no erase fenced an id it names.
pub(super) fn without_erased<'c>(
    chain: &'c [LineageLink],
    erased: Option<&EntityId>,
) -> Cow<'c, [LineageLink]> {
    match erased {
        Some(id) if chain.iter().any(|link| link.entity == *id) => {
            let mut chain = chain.to_vec();
            erase_entity(&mut chain, id);
            Cow::Owned(chain)
        }
        _ => Cow::Borrowed(chain),
    }
}

/// Takes the erased `ids` out of hook lineage in the caller's erase write
/// (FIX 22184). The chain behind each goes: its runs fired on a row that is
/// gone, and a later run on it starts a chain of its own. Every other
/// chain, and every raised check, that names one as a link's entity names
/// the erased marker there instead ([`erase_entities`]); a link is never
/// dropped, as a shorter chain would miss a cycle through it and read
/// shallower. One walk of the lineage table and one of the checks, for all
/// of `ids` together.
pub(super) fn scrub_erased_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    ids: &BTreeSet<EntityId>,
) -> Result<()> {
    let mut chains = Vec::new();
    for row in LINEAGE.iter_from(&vault.store, txn, &[])? {
        let (key, mut lineage) = row?;
        if !ids.contains(&EntityId::from_bytes_unchecked(key))
            && erase_entities(&mut lineage.chain, |entity| ids.contains(entity))
        {
            chains.push((key, lineage));
        }
    }
    for id in ids {
        LINEAGE.delete(&vault.store, txn, id.as_bytes())?;
    }
    for (key, lineage) in &chains {
        LINEAGE.put(&vault.store, txn, key, lineage)?;
    }
    let mut checks = Vec::new();
    for row in CHECKS.iter_from(&vault.store, txn, &[])? {
        let (key, mut check) = row?;
        if erase_entities(&mut check.chain, |entity| ids.contains(entity)) {
            checks.push((key, check));
        }
    }
    for (key, check) in &checks {
        CHECKS.put(&vault.store, txn, key, check)?;
    }
    Ok(())
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
