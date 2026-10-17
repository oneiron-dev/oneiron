//! Capture and admission of project revisions (section 2 of the PR 3
//! contract). Every door that stages a PROJECT row captures the signed chain
//! of the incoming row and of the row it replaces, so no later row erases an
//! earlier state; every companion that arrives on its own passes one
//! admission arm in `apply_put`.
use super::revision::{
    PROJECT_REVISION_BACKFILL, ProjectRevision, ProjectRevisionHash, REVISION_AWAITING_MINT,
    REVISIONS, RevisionOrigin, admissible_revision, project_revision_type, revision_entity_id,
    revisions_of_row,
};
use super::*;
use crate::store::Store;

/// Companion puts a PROJECT put brings (decision 8): the chain of the
/// incoming row and of the stored row it replaces, minus the revisions
/// already held, so every signed state either carried stays. The batch writes
/// them through the revision arm right after the PROJECT row. A put of any
/// other kind brings none.
pub(crate) fn capture_project_put(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: u8,
    data: &[u8],
) -> Result<Vec<(EntityId, Vec<u8>)>> {
    if !is_project_type(store, kind) || project_revision_type(store).is_none() {
        return Ok(Vec::new());
    }
    let incoming: ProjectRecord = decode(data)?;
    let mut chain = revisions_of_row(id, &incoming)?;
    if let Some(old) = read::stored(store, txn, id, kind)? {
        chain.extend(revisions_of_row(id, &old)?);
    }
    unheld(store, txn, id, chain)
}

fn unheld(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    project: EntityId,
    chain: Vec<(ProjectRevisionHash, ProjectRevision)>,
) -> Result<Vec<(EntityId, Vec<u8>)>> {
    let mut seen = BTreeSet::new();
    let mut puts = Vec::new();
    for (hash, revision) in chain {
        if !seen.insert(hash) || REVISIONS.contains(store, txn, &(project, hash))? {
            continue;
        }
        puts.push((revision_entity_id(hash)?, revision.canonical_bytes()?));
    }
    Ok(puts)
}

/// A companion put that passed admission, before its body is written.
pub(crate) struct RevisionPut {
    pub(crate) project: EntityId,
    hash: ProjectRevisionHash,
    /// A row of another kind sits at the derived id: evicted before the write.
    pub(crate) squatter: bool,
}

/// The revision arm of `apply_put`: pure checks, before any write. Only the
/// engine's capture and replicated transport write one; the public gate
/// already refused every other door. The body is canonical, its hash derives
/// `id`, and its slip names this vault. A row of another kind at `id` is a
/// squatter (an ordinary id never lands on a derived one except by intent);
/// a held companion keeps its id, and the id fixes its bytes.
pub(crate) fn check_revision_put(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    data: &[u8],
    replicated: bool,
    posture: crate::HostingPrivacyPosture,
) -> Result<RevisionPut> {
    if !replicated {
        return Err(RecordError::ProjectRevisionWrite.into());
    }
    let fold = crate::authority::authority_fold_readonly_for_store_in_txn(store, posture, txn)?;
    let (hash, revision) = admissible_revision(Some(&fold), id, data)?;
    let squatter = match crate::ports::EntityStoreRead::port_entity_raw(store, txn, &id)? {
        None => false,
        Some(raw) => {
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if super::revision::is_project_revision_type(store, header.entity_type) {
                if raw[ENTITY_METADATA_HEADER_LEN..] != *data {
                    return Err(RecordError::ProjectRevisionCollision { id }.into());
                }
                false
            } else {
                true
            }
        }
    };
    Ok(RevisionPut {
        project: revision.project(),
        hash,
        squatter,
    })
}

/// The projects a staged put touches, each folded once at the batch end: a
/// PROJECT row's own; an admitted companion's, indexed here to await
/// authentication; and those an authority-log entry may change.
pub(crate) fn projects_touched_by_put(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    (id, kind): (EntityId, u8),
    revision: Option<&RevisionPut>,
    entry: Option<&crate::authority::AuthorityLogEntry>,
) -> Result<BTreeSet<EntityId>> {
    let mut touched = BTreeSet::new();
    if let Some(put) = revision {
        let key = (put.project, put.hash);
        if REVISIONS.get(store, txn, &key)?.is_none() {
            REVISIONS.put(store, txn, &key, &(id, RevisionOrigin::AwaitingParent))?;
        }
        touched.insert(put.project);
    } else if is_project_type(store, kind) {
        touched.insert(id);
    }
    if let Some(entry) = entry {
        touched.extend(projects_touched_by_authority_entry(store, txn, entry)?);
    }
    Ok(touched)
}

/// The projects an authority-log entry may change: those with a revision
/// waiting for the slip it mints, and every parent project a frozen
/// descendant waits on.
fn projects_touched_by_authority_entry(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    entry: &crate::authority::AuthorityLogEntry,
) -> Result<BTreeSet<EntityId>> {
    // Any entry can change a slip's standing, and with it a parent project's
    // view: its refresh retries the frozen descendants waiting on it (Wonder
    // r6 F6). The index holds rows of frozen projects only.
    let mut touched: BTreeSet<EntityId> = super::history_policy::PROJECT_FROZEN_WAIT_PROJECT
        .scan_keys(store, txn, &[])?
        .into_iter()
        .map(|(parent, _)| parent)
        .collect();
    if let crate::authority::AuthorityOp::SlipMint(action) = &entry.op {
        touched.extend(
            REVISION_AWAITING_MINT
                .scan_keys(store, txn, &action.claims.slip_id)?
                .into_iter()
                .map(|(_, (project, _))| project),
        );
    }
    Ok(touched)
}

/// One companion to write: its id, canonical bytes and the times of the
/// PROJECT row it was captured from.
pub(crate) type CapturedRevision = (EntityId, Vec<u8>, TimeRange, u64);

/// The unheld chain of one stored PROJECT row, with that row's times.
fn stored_chain(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: u8,
) -> Result<Vec<CapturedRevision>> {
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw_wiped(store, txn, &id)? else {
        return Ok(Vec::new());
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != kind || raw.len() == ENTITY_METADATA_HEADER_LEN {
        return Ok(Vec::new());
    }
    let record: ProjectRecord = decode(&raw[ENTITY_METADATA_HEADER_LEN..])?;
    let occurred = TimeRange {
        start: header.occurred_start,
        end: header.occurred_end,
    };
    Ok(unheld(store, txn, id, revisions_of_row(id, &record)?)?
        .into_iter()
        .map(|(revision, bytes)| (revision, bytes, occurred, header.learned_at))
        .collect())
}

/// Capture before tear (R2-F4): the unheld chain of a PROJECT row a delete
/// or erase door is about to remove.
pub(crate) fn capture_before_tear(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Vec<CapturedRevision>> {
    match (project_type(store), project_revision_type(store)) {
        (Some(kind), Some(_)) => stored_chain(store, txn, id, kind),
        _ => Ok(Vec::new()),
    }
}

/// Companion puts for the stored chain of every PROJECT row: the one-time
/// capture at writable open, and the capture after a checkpoint restore
/// copied rows past the staging hook.
pub(crate) fn capture_stored_chains(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<CapturedRevision>> {
    let (Some(kind), Some(_)) = (project_type(store), project_revision_type(store)) else {
        return Ok(Vec::new());
    };
    let mut ids = Vec::new();
    for id in crate::ports::EntityStoreRead::port_entity_ids_by_type(store, txn, kind, None)? {
        ids.push(id?);
    }
    let mut puts = Vec::new();
    for id in ids {
        puts.extend(stored_chain(store, txn, id, kind)?);
    }
    Ok(puts)
}

impl Vault {
    /// Writes captured companions through the revision arm in `txn`; the
    /// batch end refreshes their projects.
    pub(crate) fn put_project_revisions_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        puts: Vec<CapturedRevision>,
    ) -> Result<()> {
        if puts.is_empty() {
            return Ok(());
        }
        let kind = project_revision_type(&self.store).ok_or_else(invalid)?;
        let mut batch = self.batch_in();
        for (id, bytes, occurred, learned_at) in &puts {
            batch = batch.put_engine_history(id, kind, *occurred, *learned_at, bytes);
        }
        batch.apply(txn)
    }

    /// Capture before tear at an erase door.
    pub(crate) fn capture_project_before_tear_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: EntityId,
    ) -> Result<()> {
        let puts = capture_before_tear(&self.store, txn, id)?;
        self.put_project_revisions_in_txn(txn, puts)
    }

    /// The one-time capture of every stored chain at writable open (R2-F4),
    /// and again after a restore copied rows past the staging hook.
    pub(crate) fn capture_project_revisions(&self, force: bool) -> Result<()> {
        if !force && !backfill_due(&self.store, &self.store.env.read_txn()?)? {
            return Ok(());
        }
        self.with_write_txn_grouped(|txn| {
            let puts = capture_stored_chains(&self.store, txn)?;
            self.put_project_revisions_in_txn(txn, puts)?;
            mark_backfilled(&self.store, txn)
        })
    }
}

/// The version of the open-time capture this vault ran.
const BACKFILL_VERSION: u64 = 1;

/// Whether the one-time capture at writable open still has to run.
fn backfill_due(store: &Store, txn: &heed::RoTxn<'_>) -> Result<bool> {
    Ok(PROJECT_REVISION_BACKFILL.get(store, txn, &())? != Some(BACKFILL_VERSION))
}

fn mark_backfilled(store: &Store, txn: &mut heed::RwTxn<'_>) -> Result<()> {
    PROJECT_REVISION_BACKFILL.put(store, txn, &(), &BACKFILL_VERSION)
}

/// Revisions are never deleted (decision 10): every delete, erase and
/// tombstone door refuses one, as it refuses an authority-log row.
pub(crate) fn refuse_revision_delete(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)? else {
        return Ok(());
    };
    match EntityMetadataHeader::parse(&raw) {
        Some(header) if super::revision::is_project_revision_type(store, header.entity_type) => {
            Err(crate::error::RegistryError::MaintenanceKindNotWritable(header.entity_type).into())
        }
        _ => Ok(()),
    }
}

/// After a restore: the revision index is derived, so it is rebuilt from the
/// companions the restore kept, and every project with history is refreshed.
pub(crate) fn rebuild_project_revision_indexes(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
) -> Result<()> {
    let Some(kind) = project_revision_type(store) else {
        return Ok(());
    };
    let mut rows = Vec::new();
    for id in crate::ports::EntityStoreRead::port_entity_ids_by_type(store, txn, kind, None)? {
        rows.push(id?);
    }
    let mut touched = BTreeSet::new();
    for id in rows {
        let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &id)? else {
            continue;
        };
        let Ok((hash, revision)) =
            super::revision::decode_revision(id, &raw[ENTITY_METADATA_HEADER_LEN..])
        else {
            continue;
        };
        let key = (revision.project(), hash);
        if !REVISIONS.contains(store, txn, &key)? {
            REVISIONS.put(store, txn, &key, &(id, RevisionOrigin::AwaitingParent))?;
        }
        touched.insert(revision.project());
    }
    super::refresh::refresh_project_frontiers(store, txn, store.privacy_posture, &touched)
}

/// The companions of a PROJECT row that travel with it: every held revision
/// but a forged one. Empty for any other id.
#[cfg(feature = "sync")]
pub(crate) fn exportable_revisions_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    project: EntityId,
) -> Result<Vec<EntityId>> {
    Ok(REVISIONS
        .scan_from(store, txn, project.as_bytes())?
        .into_iter()
        .filter(|(_, (_, origin))| *origin != RevisionOrigin::Forged)
        .map(|(_, (id, _))| id)
        .collect())
}

/// Whether `id` holds a revision this vault marked forged: such a row is
/// kept, so its id stays fixed, but never exported (sections 2 and 9).
#[cfg(feature = "sync")]
pub(crate) fn forged_revision_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<bool> {
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &id)? else {
        return Ok(false);
    };
    let is_revision = EntityMetadataHeader::parse(&raw)
        .is_some_and(|header| super::revision::is_project_revision_type(store, header.entity_type));
    if !is_revision {
        return Ok(false);
    }
    let Ok((hash, revision)) =
        super::revision::decode_revision(id, &raw[ENTITY_METADATA_HEADER_LEN..])
    else {
        return Ok(false);
    };
    Ok(REVISIONS
        .get(store, txn, &(revision.project(), hash))?
        .is_some_and(|(_, origin)| origin == RevisionOrigin::Forged))
}

/// The transported carriers, at revision ids this vault does not hold, that
/// its admission arm refuses (section 9): not canonical, not hash-derived,
/// bound to another vault, or forged once their chain and mint are held
/// here. Every carrier joins its project's held set before any is judged, so
/// a carrier's parent may be another carrier.
#[cfg(feature = "sync")]
pub(crate) fn inadmissible_revision_carriers(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    fold: &crate::authority::AuthorityFold,
    carriers: &[(EntityId, Vec<u8>)],
) -> Result<Vec<EntityId>> {
    let mut refused = Vec::new();
    let mut admitted = Vec::new();
    for (id, blob) in carriers {
        let body = EntityMetadataHeader::parse(blob)
            .is_some_and(|header| header.occurred_start <= header.occurred_end)
            .then(|| blob.get(ENTITY_METADATA_HEADER_LEN..))
            .flatten();
        match body.and_then(|body| admissible_revision(Some(fold), *id, body).ok()) {
            Some((hash, revision)) => admitted.push((*id, hash, revision)),
            None => refused.push(*id),
        }
    }
    let Some(kind) = project_type(store) else {
        return Ok(refused);
    };
    let mut held = std::collections::BTreeMap::new();
    for (_, hash, revision) in &admitted {
        let project = revision.project();
        let set = match held.entry(project) {
            std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(super::revision::held_in_txn(store, txn, project, kind)?)
            }
        };
        set.insert(*hash, revision.clone(), RevisionOrigin::AwaitingParent);
    }
    for (id, hash, revision) in &admitted {
        if held.get(&revision.project()).is_some_and(|set| {
            super::revision::authenticate(set, fold, *hash) == RevisionOrigin::Forged
        }) {
            refused.push(*id);
        }
    }
    Ok(refused)
}
