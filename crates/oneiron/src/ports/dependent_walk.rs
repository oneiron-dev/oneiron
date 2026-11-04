//! A source's dependents are withdrawn in bounded batches, never refused for
//! how many records were derived from it (rule 5: ARCH-0044 C5, OF-520).
//!
//! The transaction that erases or changes a source walks the first batch of
//! its dependency rows. Past that batch it leaves a durable walk row for the
//! source, and every read honours the row at once: a dependent the walk has
//! not reached yet reads as withdrawn, for the worlds the source's words sat
//! in, as it will once its batch runs. Later write transactions finish the
//! walk one batch each ([`Vault::finish_dependent_walks`]): the delete facade
//! before it returns, every open, and the host's maintenance tick.

use super::SourceSpan;
use super::integrity::{self, DEP};
use crate::batch::EntityMetadataHeader;
use crate::error::{Error, Result};
use crate::settings::CarriedWorlds;
use crate::side_table::{self, CodecError, Named, Raw, RawValue, SideTable};
use crate::store::{ManifestDbs, Store};
use crate::{EntityId, Vault};
use heed::{RoTxn, RwTxn};
use mark::{Mark, WalkRow};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;

/// Dependents one write transaction withdraws: the count the walk refused
/// at before, so every walk that completed then still completes in the one
/// transaction that marks it.
pub const DEFAULT_DEPENDENT_WALK_BATCH: u64 = 100_000;
/// Dependents of one source past which its walk asks whether everything is
/// okay: far above what a fleet derives from one record.
pub const DEFAULT_DEPENDENT_WALK_CHECK_THRESHOLD: u64 = 1_000_000;

/// What is left of one source's walk. Key: the source.
const WALK: SideTable<EntityId, WalkRow, Raw> = SideTable::new(&side_table::PORTS_DEPENDENT_WALK);
/// The check one source's walk raised. Key: the source.
const CHECK: SideTable<EntityId, DependentWalkCheck, Named> =
    SideTable::new(&side_table::PORTS_DEPENDENT_WALK_CHECK);
/// Device-local walk policy. Key: ().
const POLICY: SideTable<(), DependentWalkPolicy, Raw> =
    SideTable::new(&side_table::PORTS_DEPENDENT_WALK_POLICY);
/// A row the walk of its source passes by: one admitted after the mark, or a
/// dependent withdrawn early because a put rewrote it. Key: the source and
/// the row. Value: the generation of the walk that settled it; a later mark
/// of the source covers the row again.
const SETTLED: SideTable<(EntityId, RowKey), u64, Raw> =
    SideTable::new(&side_table::PORTS_DEPENDENT_WALK_SETTLED);

/// The frontier and dependent of a dependency row: its key after the source.
const ROW: usize = 24;
type RowKey = [u8; ROW];

/// The two rows of a dependent walk. Neither refuses: the batch bounds one
/// transaction, and crossing the threshold raises a check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DependentWalkPolicy {
    /// Dependents one write transaction withdraws. At least one.
    pub batch: u64,
    /// Raise one typed check when a walk has withdrawn more than this.
    pub check_threshold: u64,
}

impl Default for DependentWalkPolicy {
    fn default() -> Self {
        Self {
            batch: DEFAULT_DEPENDENT_WALK_BATCH,
            check_threshold: DEFAULT_DEPENDENT_WALK_CHECK_THRESHOLD,
        }
    }
}

impl DependentWalkPolicy {
    fn validate(self) -> Result<()> {
        if self.batch == 0 {
            return Err(Error::InvalidConfig(
                "dependent walk batch must be positive".to_owned(),
            ));
        }
        Ok(())
    }
}

impl RawValue for DependentWalkPolicy {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok([self.batch.to_be_bytes(), self.check_threshold.to_be_bytes()].concat())
    }

    fn from_raw(raw: &[u8]) -> std::result::Result<Self, CodecError> {
        let corrupt = || Error::CorruptedIndex("dependent walk policy");
        let (batch, threshold) = raw
            .split_at_checked(8)
            .filter(|(_, threshold)| threshold.len() == 8)
            .ok_or_else(corrupt)?;
        let policy = Self {
            batch: u64::from_be_bytes(batch.try_into().map_err(|_| corrupt())?),
            check_threshold: u64::from_be_bytes(threshold.try_into().map_err(|_| corrupt())?),
        };
        policy.validate()?;
        Ok(policy)
    }
}

/// OF-520 question a source's walk raised once it withdrew more dependents
/// than the threshold. It is evidence for the host, never a refusal: the walk
/// went on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependentWalkCheck {
    /// The source whose dependents were walked.
    pub document: String,
    /// The door that walked them ([`DependentWalkProgress::door`]).
    pub door: String,
    /// The threshold in force at the crossing.
    pub threshold: u64,
    /// Dependents withdrawn when the walk crossed it.
    pub walked: u64,
}

impl DependentWalkCheck {
    /// Machine-readable check discriminator; presentation text belongs to hosts.
    pub const KIND: &'static str = "dependent_walk_size";
}

/// A walk still under way.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DependentWalkProgress {
    /// The source whose dependents are withdrawn.
    pub document: EntityId,
    /// The door that started the walk: `soft_erase`, `purge`,
    /// `changed_docs_source`, `tombstone` or `unmade_epoch`.
    pub door: &'static str,
    /// Dependents withdrawn so far.
    pub walked: u64,
}

/// Each door that walks a source's dependents. Every caller of
/// [`super::invalidate_source_in_txn`] names itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DependentWalkDoor {
    /// A SoftErase of the active store: a user delete, an erase a replica
    /// replays, a redirect shell a hard erase scrubs.
    SoftErase,
    /// The purge of a row (`batch::deindex_entity`).
    Purge,
    /// A docs source whose body changed.
    ChangedDocsSource,
    /// A standalone tombstone.
    Tombstone,
    /// An epoch summary rewritten into a body that is no epoch.
    UnmadeEpoch,
}

impl DependentWalkDoor {
    /// Every door, for the check that none refuses for a count.
    #[cfg(test)]
    pub(crate) const ALL: [Self; 5] = [
        Self::SoftErase,
        Self::Purge,
        Self::ChangedDocsSource,
        Self::Tombstone,
        Self::UnmadeEpoch,
    ];

    const fn tag(self) -> u8 {
        match self {
            Self::SoftErase => 1,
            Self::Purge => 2,
            Self::ChangedDocsSource => 3,
            Self::Tombstone => 4,
            Self::UnmadeEpoch => 5,
        }
    }

    const fn from_tag(tag: u8) -> Option<Self> {
        Some(match tag {
            1 => Self::SoftErase,
            2 => Self::Purge,
            3 => Self::ChangedDocsSource,
            4 => Self::Tombstone,
            5 => Self::UnmadeEpoch,
            _ => return None,
        })
    }

    /// The closed code a walk, its check and its log line name the door by.
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::SoftErase => "soft_erase",
            Self::Purge => "purge",
            Self::ChangedDocsSource => "changed_docs_source",
            Self::Tombstone => "tombstone",
            Self::UnmadeEpoch => "unmade_epoch",
        }
    }
}

fn row_key(frontier: u64, dependent: &EntityId) -> RowKey {
    let mut row = [0; ROW];
    row[..8].copy_from_slice(&frontier.to_be_bytes());
    row[8..].copy_from_slice(dependent.as_bytes());
    row
}

/// The row a dependency key under `prefix` names.
fn row_of(key: &[u8], prefix: &[u8]) -> Result<RowKey> {
    key.strip_prefix(prefix)
        .and_then(|row| row.try_into().ok())
        .ok_or(Error::CorruptedIndex("source dependency key"))
}

fn dependent_of(row: &RowKey) -> Result<EntityId> {
    EntityId::from_bytes(
        row[8..]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("dependent id"))?,
    )
}

/// The walk policy in force here: also the batch past which a withdrawal's
/// source chain takes the stale mark alone (FIX 1494).
pub(super) fn policy_in(store: &Store, txn: &RoTxn<'_>) -> Result<DependentWalkPolicy> {
    Ok(POLICY.get(store, txn, &())?.unwrap_or_default())
}

fn entity_type_in(dbs: &impl ManifestDbs, txn: &RoTxn<'_>, id: &EntityId) -> Result<Option<u8>> {
    Ok(dbs
        .entities()
        .get(txn, id.as_bytes())?
        .and_then(|raw| EntityMetadataHeader::parse(&raw))
        .map(|header| header.entity_type))
}

/// Withdraws `document`'s dependents for `door` in the caller's transaction:
/// the first batch here, and past it a walk row that this transaction leaves
/// and later ones finish. A walk already pending for `document` starts again
/// from its first row under the new mark, keeping what the pending one had
/// not reached as an earlier mark, so each row is withdrawn for the worlds
/// of the marks that covered it, as two walks would give it.
pub(super) fn begin_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    document: &EntityId,
    door: DependentWalkDoor,
) -> Result<()> {
    let prefix = [DEP, document.as_bytes()].concat();
    let highest = [prefix.as_slice(), &[0xFF; ROW]].concat();
    let last = store
        .vault_meta
        .rev_range(
            txn,
            &(
                Bound::Included(prefix.as_slice()),
                Bound::Included(highest.as_slice()),
            ),
        )?
        .next()
        .transpose()?
        .map(|(key, _)| row_of(&key, &prefix))
        .transpose()?;
    let Some(end) = last else {
        return Ok(());
    };
    // Where the words sat, read while the row, its stamp and its edges still
    // stand: an epoch summary it withdraws keeps them as its own. A source no
    // one can place withdraws it for an unknown world, and the walk goes on.
    let worlds = integrity::carried_now(store, txn, document)?;
    let mut walk = WalkRow {
        door,
        walked: 0,
        mark: Mark {
            generation: 0,
            after: None,
            end,
            worlds,
        },
        earlier: Vec::new(),
    };
    if let Some(pending) = WALK.get(store, txn, document)? {
        // A new generation: the rows the pending walk settled are covered
        // again, and its batches take their settled rows.
        walk.mark.generation = pending.mark.generation.wrapping_add(1);
        walk.mark.end = end.max(pending.mark.end);
        walk.walked = pending.walked;
        // What the pending walk had not reached it still withdraws, for its
        // own worlds. One left with only its sweep withdrew all it covered,
        // and lends the new mark none of its worlds.
        let cursor = pending.mark.after;
        let earlier = std::iter::once(pending.mark)
            .chain(pending.earlier)
            .map(|mut mark| {
                mark.after = mark.after.max(cursor);
                mark
            })
            .filter(|mark| !mark.covers_none())
            .collect();
        walk.earlier = mark::keep_apart(earlier, &walk.mark);
    }
    batch_in_txn(store, txn, document, walk)
}

/// Withdraws the next batch of `walk`, then keeps what is left of it, or
/// retires it once no row it covers is left.
fn batch_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    document: &EntityId,
    mut walk: WalkRow,
) -> Result<()> {
    let policy = policy_in(store, txn)?;
    let prefix = [DEP, document.as_bytes()].concat();
    let lower = walk.mark.after.map_or_else(
        || Bound::Included(prefix.clone()),
        |after| Bound::Excluded([prefix.as_slice(), &after].concat()),
    );
    let upper = Bound::Included([prefix.as_slice(), &walk.mark.end].concat());
    let range = (
        lower.as_ref().map(Vec::as_slice),
        upper.as_ref().map(Vec::as_slice),
    );
    let mut rows = Vec::new();
    for row in store.vault_meta.range(txn, &range)? {
        if rows.len() as u64 >= policy.batch {
            break;
        }
        rows.push(row_of(&row?.0, &prefix)?);
    }
    let mut dependents = BTreeMap::<EntityId, CarriedWorlds>::new();
    for row in &rows {
        // A batch takes each settled row it passes, so none outlives the walk.
        let key = (*document, *row);
        let settled = SETTLED.get(store, txn, &key)?;
        if settled.is_some() {
            SETTLED.delete(store, txn, &key)?;
        }
        if let Some(worlds) = walk.worlds_for(row, settled) {
            dependents
                .entry(dependent_of(row)?)
                .or_default()
                .absorb(&worlds);
        }
    }
    for (dependent, worlds) in &dependents {
        integrity::withdraw_dependent_in_txn(store, txn, document, dependent, worlds)?;
    }
    walk.walked = walk.walked.saturating_add(dependents.len() as u64);
    if walk.walked > policy.check_threshold && !CHECK.contains(store, txn, document)? {
        ask_in_txn(store, txn, document, &walk, policy)?;
    }
    match rows.last() {
        Some(last) if rows.len() as u64 == policy.batch && *last != walk.mark.end => {
            walk.mark.after = Some(*last);
            walk.earlier.retain(|mark| mark.end > *last);
            WALK.put(store, txn, document, &walk)
        }
        _ => retire_in_txn(store, txn, document, walk, policy.batch),
    }
}

/// Retires `walk` once no settled row of `document` is left. A row the
/// batches never passed (a regeneration moved its dependency) leaves its
/// settled row behind; those go `budget` a transaction too, so a later walk
/// of the source starts with none.
fn retire_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    document: &EntityId,
    mut walk: WalkRow,
    budget: u64,
) -> Result<()> {
    let left = SETTLED
        .iter_from(store, txn, document.as_bytes())?
        .take(usize::try_from(budget).unwrap_or(usize::MAX))
        .map(|row| row.map(|(key, _)| key))
        .collect::<Result<Vec<_>>>()?;
    for key in &left {
        SETTLED.delete(store, txn, key)?;
    }
    if SETTLED
        .iter_from(store, txn, document.as_bytes())?
        .next()
        .is_some()
    {
        // Covers no row now; only its sweep is left.
        walk.mark.after = Some(walk.mark.end);
        walk.earlier.clear();
        return WALK.put(store, txn, document, &walk);
    }
    WALK.delete(store, txn, document)?;
    Ok(())
}

/// Records the walk's one check and asks the host whether everything is
/// okay. The walk goes on either way.
fn ask_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    document: &EntityId,
    walk: &WalkRow,
    policy: DependentWalkPolicy,
) -> Result<()> {
    let check = DependentWalkCheck {
        document: document.to_hex(),
        door: walk.door.code().to_owned(),
        threshold: policy.check_threshold,
        walked: walk.walked,
    };
    CHECK.put(store, txn, document, &check)?;
    tracing::warn!(
        kind = DependentWalkCheck::KIND,
        door = walk.door.code(),
        threshold = policy.check_threshold,
        walked = walk.walked,
        "a source's dependent walk crossed its threshold and goes on; is everything okay?"
    );
    Ok(())
}

/// The worlds the pending walks withdraw `id` for before their batches reach
/// it; `Some` where one does. A walk withdraws each dependent its range still
/// covers, an EVENT that outlives its source excepted, and through each one
/// every epoch summary written from it, as the batch itself will. The rest
/// of each one's source chain is withdrawn when the batch reaches it (FIX
/// 1494), not before.
pub(super) fn pending_withdrawal_in(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<CarriedWorlds>> {
    if !any_pending_walk(dbs, txn)? {
        return Ok(None);
    }
    let mut withdrawn: Option<CarriedWorlds> = None;
    let mut seen = BTreeSet::new();
    // A worklist up the epoch summaries' sources, not recursion.
    let mut pending = vec![*id];
    while let Some(node) = pending.pop() {
        if !seen.insert(node) {
            continue;
        }
        let sources = super::regeneration::sources_of(dbs, txn, &node)?;
        if sources.is_empty() {
            continue;
        }
        let entity_type = entity_type_in(dbs, txn, &node)?;
        if let Some(worlds) = direct_withdrawal_in(dbs, txn, &node, &sources, entity_type)? {
            withdrawn
                .get_or_insert_with(CarriedWorlds::default)
                .absorb(&worlds);
        }
        if entity_type == Some(crate::registry::ENTITY_TYPE_SUMMARY)
            && integrity::epoch_summary_in(dbs, txn, &node)?
        {
            pending.extend(sources.iter().map(|source| source.document));
        }
    }
    Ok(withdrawn)
}

/// The worlds the pending walks withdraw `node` for through its own
/// dependency rows, from `sources`; `Some` where one does.
fn direct_withdrawal_in(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    node: &EntityId,
    sources: &[SourceSpan],
    entity_type: Option<u8>,
) -> Result<Option<CarriedWorlds>> {
    let mut withdrawn: Option<CarriedWorlds> = None;
    for SourceSpan { document, frontier } in sources {
        let row = row_key(*frontier, node);
        let Some(walk) = WALK.get(dbs, txn, document)? else {
            continue;
        };
        if !walk.mark.covers(&row) {
            continue;
        }
        let settled = SETTLED.get(dbs, txn, &(*document, row))?;
        if let Some(worlds) = walk.worlds_for(&row, settled)
            && !(entity_type == Some(crate::registry::ENTITY_TYPE_EVENT)
                && crate::calendar::origin::survives_source_deletion(dbs, txn, *node)?)
        {
            withdrawn
                .get_or_insert_with(CarriedWorlds::default)
                .absorb(&worlds);
        }
    }
    Ok(withdrawn)
}

/// Whether a pending walk withdraws `id` through its own dependency rows: it
/// still holds the body the mark covered, which the walk's batch marks again.
/// No regeneration of that body completes, as none would after a
/// single-transaction walk.
pub(super) fn withdrawn_directly_in(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    if !any_pending_walk(dbs, txn)? {
        return Ok(false);
    }
    let sources = super::regeneration::sources_of(dbs, txn, id)?;
    let entity_type = entity_type_in(dbs, txn, id)?;
    Ok(direct_withdrawal_in(dbs, txn, id, &sources, entity_type)?.is_some())
}

/// Whether any walk is pending: one seek, so a hot read asks once.
pub(crate) fn any_pending_walk(dbs: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<bool> {
    Ok(WALK.iter_raw_from(dbs, txn, &[])?.next().is_some())
}

/// A dependency row written while its source's walk is pending is the new
/// version's, never one the mark covered: the walk passes it by.
pub(super) fn settle_admitted_in_txn(
    dbs: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    source: SourceSpan,
    dependent: &EntityId,
) -> Result<()> {
    let row = row_key(source.frontier, dependent);
    if let Some(walk) = WALK.get(dbs, txn, &source.document)?
        && walk.mark.covers(&row)
    {
        SETTLED.put(dbs, txn, &(source.document, row), &walk.mark.generation)?;
    }
    Ok(())
}

/// A put is about to rewrite `id`, a dependent a pending walk has not
/// reached: it is withdrawn here first, from the body and revision the walk
/// would have read at the mark, and its rows are settled so the walk passes
/// them by. Its regeneration then meets the same fence as after a
/// single-transaction walk.
pub(crate) fn withdraw_before_rewrite_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let Some(worlds) = pending_withdrawal_in(store, txn, id)? else {
        return Ok(());
    };
    let mut direct = false;
    for SourceSpan { document, frontier } in super::regeneration::sources_of(store, txn, id)? {
        let row = row_key(frontier, id);
        let Some(walk) = WALK.get(store, txn, &document)? else {
            continue;
        };
        let settled = SETTLED.get(store, txn, &(document, row))?;
        if let Some(worlds) = walk.worlds_for(&row, settled) {
            integrity::withdraw_dependent_in_txn(store, txn, &document, id, &worlds)?;
            SETTLED.put(store, txn, &(document, row), &walk.mark.generation)?;
            direct = true;
        }
    }
    // An epoch summary withdrawn only through one it was written from: marked
    // once, as the batch that reaches that one marks it, with its source
    // chain, and never again for a put that repeats (its regeneration's own
    // revision would fence it).
    if !direct {
        integrity::withdraw_source_chain_in_txn(store, txn, vec![*id], &worlds)?;
    }
    Ok(())
}

impl Vault {
    /// What an erase or sweep left after its commit, resumed on open: the
    /// gate key retirements it staged and the dependent walks it marked.
    /// Reads honour a walk that fails here until a later pass finishes it.
    pub(crate) fn resume_erases_after_commit(&self) {
        self.finish_gate_decision_retirements_after_commit();
        if let Err(error) = self.finish_dependent_walks() {
            tracing::warn!(
                kind = ?error.kind(),
                "a dependent walk did not finish on open; the next pass resumes it"
            );
        }
    }

    /// Finishes every pending dependent walk, one batch per write
    /// transaction. A walk an erase, a purge or a changed source left resumes
    /// here; reads honour it until its last batch.
    ///
    /// # Errors
    ///
    /// The first walk that failed, once every other walk has finished. A
    /// failed walk keeps its row and resumes on the next call.
    pub fn finish_dependent_walks(&self) -> Result<()> {
        let mut failed = BTreeSet::new();
        let mut first_error = None;
        loop {
            let next = {
                let txn = self.store.env.read_txn()?;
                WALK.scan_keys(&self.store, &txn, &[])?
                    .into_iter()
                    .find(|document| !failed.contains(document))
            };
            let Some(document) = next else {
                return first_error.map_or(Ok(()), Err);
            };
            #[cfg(test)]
            if !self.store.test_hooks.run_dependent_walk_batch() {
                return Ok(());
            }
            let batch =
                self.with_write_txn_grouped(|txn| match WALK.get(&self.store, txn, &document)? {
                    Some(walk) => batch_in_txn(&self.store, txn, &document, walk),
                    None => Ok(()),
                });
            if let Err(error) = batch {
                failed.insert(document);
                first_error.get_or_insert(error);
            }
        }
    }

    /// The walks still under way, in source order.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub fn pending_dependent_walks(&self) -> Result<Vec<DependentWalkProgress>> {
        let txn = self.store.env.read_txn()?;
        Ok(WALK
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(document, walk)| DependentWalkProgress {
                document,
                door: walk.door.code(),
                walked: walk.walked,
            })
            .collect())
    }

    /// The checks walks raised, one per source, in source order.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub fn dependent_walk_checks(&self) -> Result<Vec<DependentWalkCheck>> {
        let txn = self.store.env.read_txn()?;
        Ok(CHECK
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(_, check)| check)
            .collect())
    }

    /// The local dependent walk policy.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub fn dependent_walk_policy(&self) -> Result<DependentWalkPolicy> {
        let txn = self.store.env.read_txn()?;
        policy_in(&self.store, &txn)
    }

    /// Sets the local dependent walk policy for the batches that follow.
    ///
    /// # Errors
    ///
    /// A zero batch, or storage failures.
    pub fn set_dependent_walk_policy(&self, policy: DependentWalkPolicy) -> Result<()> {
        policy.validate()?;
        self.with_write_txn_grouped(|txn| POLICY.put(&self.store, txn, &(), &policy))
    }
}

mod mark;
#[cfg(test)]
mod tests;
