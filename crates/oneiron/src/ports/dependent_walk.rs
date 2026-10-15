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
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
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
/// the row.
const SETTLED: SideTable<(EntityId, RowKey), (), Raw> =
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

/// What is left of one source's walk. It covers the dependency rows the
/// source held when it was marked, `(after, end]` in key order. A row written
/// later is a newer version's (a deleted source takes none), and the walk
/// leaves it alone.
#[derive(Clone, Debug, PartialEq, Eq)]
struct WalkRow {
    door: DependentWalkDoor,
    /// Dependents withdrawn so far.
    walked: u64,
    /// The last row walked; `None` before the first batch.
    after: Option<RowKey>,
    /// The last row the source held at the mark.
    end: RowKey,
    /// Where the source's words sat, read at the mark while its row, stamp
    /// and edges still stood: later batches cannot read them again.
    worlds: CarriedWorlds,
}

impl WalkRow {
    fn covers(&self, row: &RowKey) -> bool {
        self.after.is_none_or(|after| *row > after) && *row <= self.end
    }
}

impl RawValue for WalkRow {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let mut raw = Vec::with_capacity(2 + 8 + 2 * ROW);
        raw.push(self.door.tag());
        raw.extend_from_slice(&self.walked.to_be_bytes());
        raw.extend_from_slice(&self.end);
        raw.push(u8::from(self.after.is_some()));
        raw.extend_from_slice(&self.after.unwrap_or([0; ROW]));
        raw.extend_from_slice(&self.worlds.encode());
        Ok(raw)
    }

    fn from_raw(raw: &[u8]) -> std::result::Result<Self, CodecError> {
        let corrupt = || Error::CorruptedIndex("dependent walk");
        let (head, worlds) = raw.split_at_checked(2 + 8 + 2 * ROW).ok_or_else(corrupt)?;
        let door = DependentWalkDoor::from_tag(head[0]).ok_or_else(corrupt)?;
        let walked = u64::from_be_bytes(head[1..9].try_into().map_err(|_| corrupt())?);
        let end: RowKey = head[9..9 + ROW].try_into().map_err(|_| corrupt())?;
        let after: RowKey = head[10 + ROW..].try_into().map_err(|_| corrupt())?;
        let after = match head[9 + ROW] {
            0 => None,
            1 => Some(after),
            _ => return Err(corrupt().into()),
        };
        Ok(Self {
            door,
            walked,
            after,
            end,
            worlds: CarriedWorlds::decode(worlds)?,
        })
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

fn policy_in(store: &Store, txn: &RoTxn<'_>) -> Result<DependentWalkPolicy> {
    Ok(POLICY.get(store, txn, &())?.unwrap_or_default())
}

/// Withdraws `document`'s dependents for `door` in the caller's transaction:
/// the first batch here, and past it a walk row that this transaction leaves
/// and later ones finish. A walk already pending for `document` starts again
/// from its first row with the worlds of both, so a dependent it already
/// withdrew takes the new ones too, as a second walk would give it.
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
    let Some(mut end) = last else {
        return Ok(());
    };
    // Where the words sat, read while the row, its stamp and its edges still
    // stand: an epoch summary it withdraws keeps them as its own. A source no
    // one can place withdraws it for an unknown world, and the walk goes on.
    let mut worlds = integrity::carried_now(store, txn, document)?;
    let mut walked = 0;
    if let Some(pending) = WALK.get(store, txn, document)? {
        worlds.absorb(&pending.worlds);
        walked = pending.walked;
        end = end.max(pending.end);
        // The new mark covers every row the source holds now.
        SETTLED.delete_from(store, txn, document.as_bytes())?;
    }
    let walk = WalkRow {
        door,
        walked,
        after: None,
        end,
        worlds,
    };
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
    let lower = walk.after.map_or_else(
        || Bound::Included(prefix.clone()),
        |after| Bound::Excluded([prefix.as_slice(), &after].concat()),
    );
    let upper = Bound::Included([prefix.as_slice(), &walk.end].concat());
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
    let mut dependents = BTreeSet::new();
    for row in &rows {
        if !SETTLED.contains(store, txn, &(*document, *row))? {
            dependents.insert(dependent_of(row)?);
        }
    }
    for dependent in &dependents {
        integrity::withdraw_dependent_in_txn(store, txn, document, dependent, &walk.worlds)?;
    }
    walk.walked = walk.walked.saturating_add(dependents.len() as u64);
    if walk.walked > policy.check_threshold && !CHECK.contains(store, txn, document)? {
        ask_in_txn(store, txn, document, &walk, policy)?;
    }
    match rows.last() {
        Some(last) if rows.len() as u64 == policy.batch && *last != walk.end => {
            walk.after = Some(*last);
            WALK.put(store, txn, document, &walk)
        }
        _ => {
            WALK.delete(store, txn, document)?;
            SETTLED.delete_from(store, txn, document.as_bytes())?;
            Ok(())
        }
    }
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
/// every epoch summary written from it, as the batch itself will.
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
        let entity_type = dbs
            .entities()
            .get(txn, node.as_bytes())?
            .and_then(|raw| EntityMetadataHeader::parse(&raw))
            .map(|header| header.entity_type);
        for SourceSpan { document, frontier } in &sources {
            let row = row_key(*frontier, &node);
            if let Some(walk) = WALK.get(dbs, txn, document)?
                && walk.covers(&row)
                && !SETTLED.contains(dbs, txn, &(*document, row))?
                && !(entity_type == Some(crate::registry::ENTITY_TYPE_EVENT)
                    && crate::calendar::origin::survives_source_deletion(dbs, txn, node)?)
            {
                withdrawn
                    .get_or_insert_with(CarriedWorlds::default)
                    .absorb(&walk.worlds);
            }
        }
        if entity_type == Some(crate::registry::ENTITY_TYPE_SUMMARY)
            && integrity::epoch_summary_in(dbs, txn, &node)?
        {
            pending.extend(sources.iter().map(|source| source.document));
        }
    }
    Ok(withdrawn)
}

/// Whether any walk is pending: one seek, so a hot read asks once.
pub(crate) fn any_pending_walk(dbs: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<bool> {
    Ok(WALK.iter_raw_from(dbs, txn, &[])?.next().is_some())
}

/// Whether a pending walk withdraws `id` before its batch reaches it.
pub(crate) fn pending_withdrawn_in(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    Ok(pending_withdrawal_in(dbs, txn, id)?.is_some())
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
    if WALK
        .get(dbs, txn, &source.document)?
        .is_some_and(|walk| walk.covers(&row))
    {
        SETTLED.put(dbs, txn, &(source.document, row), &())?;
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
        if walk.covers(&row) && !SETTLED.contains(store, txn, &(document, row))? {
            integrity::withdraw_dependent_in_txn(store, txn, &document, id, &walk.worlds)?;
            SETTLED.put(store, txn, &(document, row), &())?;
            direct = true;
        }
    }
    // Withdrawn only through an epoch summary it was written from: marked
    // now, so the batch that reaches that summary finds it done.
    if !direct {
        integrity::withdraw_in_txn(store, txn, id, &worlds)?;
    }
    Ok(())
}

impl Vault {
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

#[cfg(test)]
mod tests;
