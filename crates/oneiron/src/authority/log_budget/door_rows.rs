//! The store doors' view of the stored log, kept across authority
//! generations (FIX [OWNER-RESERVE-PROJECTION-COST],
//! [AUTHORITY-DOOR-VIEW-MID-BATCH-REBUILD]). A view rebuilt from every stored
//! row on each generation decoded and hashed every row again, rebuilt the
//! consent structure with its signature checks, and rebuilt the counts and
//! the projection: one machine's chain, one row per put, cost about N^2 / 2
//! row decodes, and a batch or an import of k rows about k (N + k), since
//! each staged row moves the generation.
//!
//! A view now keeps what it read ([`DoorRows`]), and the next generation's
//! view extends it by the rows sequenced past it in the store order. Only
//! those rows are decoded and hashed, and pushed into the kept structure
//! builder, whose structure is the same for the same rows in any push order.
//! The counts are extended by the new rows, or recounted over the kept rows
//! when one of them is a row the builder reads, since a grant can change how
//! an earlier row counts. The projection's rows are extended, and its exact
//! peak is built only where a door needs it ([`DoorProjection`]). The view is
//! then the one a rebuild gives. A view extends another only when every
//! other input of a rebuild is unchanged: the same adopted image, the same
//! local roots, one genesis, a complete store order, and every row the other
//! view read still stored. Otherwise it is rebuilt.
//!
//! A view is the committed view only at the committed generation, as before.
//! A view of a write's staged rows is kept as the last staged view, and a
//! later view of the same write extends it while the write holds exactly the
//! rows it read past the committed ones (after a nested write rolled back, it
//! does not).

use super::super::log_structure::{LocalRoots, StructureBuilder, structure_reads};
use super::super::store_order::{complete_next_in_txn, ids_sequenced_in_txn};
use super::*;
use crate::EntityId;

/// A row a kept door view decoded, shared with its structure builder.
type KeptRow = Arc<FoldRow>;

/// What a door view read, so a later generation's view reads only the rows
/// stored past it.
#[derive(Debug, Clone)]
pub(super) struct DoorRows {
    /// The store-order sequence past every row the view read, where the
    /// index was complete: the rows sequenced below it are exactly those. A
    /// view without one is never extended.
    next_seq: Option<u64>,
    /// Every stored row the view read, by store id: its body, or None for a
    /// row the adopted image covers, which the view counts from the image.
    ids: im::OrdMap<EntityId, Option<KeptRow>>,
    /// The adopted image whose evidence the view read.
    image: Option<[u8; 32]>,
    /// The roots this install took as its own.
    local: LocalRoots,
    /// The consent structure's builder, settled over every row read.
    builder: StructureBuilder<KeptRow>,
    tally: Tally,
    /// Set for a view that read rows a write staged.
    staged: Option<StagedRows>,
}

/// The rows a write staged that a door view read.
#[derive(Debug, Clone)]
struct StagedRows {
    /// The committed store-order sequence past the committed rows.
    committed_next: u64,
    /// The ids the write held from there, in sequence order.
    ids: im::Vector<EntityId>,
}

/// Every input of a door view but the stored rows themselves.
struct Inputs {
    evidence: Option<Arc<AdoptedEvidence>>,
    image: Option<[u8; 32]>,
    local: LocalRoots,
    /// The store order's next sequence, where the index is complete.
    next_seq: Option<u64>,
}

impl Inputs {
    fn read(store: &Store, txn: &heed::RoTxn<'_>) -> crate::error::Result<Self> {
        let evidence = super::super::checkpoint_adopt::cached_adopted_evidence_in_txn(store, txn)?;
        Ok(Self {
            image: evidence.as_ref().map(|evidence| evidence.checkpoint().id()),
            evidence,
            local: LocalRoots::read_in_txn(store, txn)?,
            next_seq: complete_next_in_txn(store, txn)?,
        })
    }
}

/// Which state a read transaction sees, against the committed one.
#[derive(Clone, Copy)]
enum Snapshot {
    /// The committed generation.
    Committed,
    /// A write's staged rows past the committed generation, and the
    /// committed store order's next sequence where its index is complete.
    Staged { committed_next: Option<u64> },
    /// An older snapshot, or one the committed state could not be read for.
    Other,
}

impl Snapshot {
    /// `generation`'s snapshot. A second read txn on this thread fails with
    /// MDB_BAD_RSLOT, so the committed state is read on another thread, as
    /// `readonly_fold::cache_fold_if_committed` does.
    fn of(store: &Store, generation: u64) -> Self {
        let committed = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let committed = store.env.read_txn().ok()?;
                    Some((
                        authority_cache_generation(store, &committed).ok()?,
                        complete_next_in_txn(store, &committed).ok()?,
                    ))
                })
                .join()
                .ok()
                .flatten()
        });
        match committed {
            Some((committed, _)) if committed == generation => Self::Committed,
            Some((committed, committed_next)) if generation > committed => {
                Self::Staged { committed_next }
            }
            _ => Self::Other,
        }
    }
}

/// The door view of `txn`'s stored log: the committed view at its
/// generation, or one extended from the last staged or committed view, or a
/// rebuild.
pub(super) fn door_view(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> crate::error::Result<Arc<AuthorityDoorView>> {
    let generation = authority_cache_generation(store, txn)?;
    let committed = store
        .authority_door_view
        .lock()
        .ok()
        .and_then(|cache| cache.clone());
    if let Some((cached, view)) = &committed
        && *cached == generation
    {
        return Ok(Arc::clone(view));
    }
    let snapshot = Snapshot::of(store, generation);
    let staged = match snapshot {
        Snapshot::Staged { .. } => store
            .authority_door_view_staged
            .lock()
            .ok()
            .and_then(|cache| cache.clone()),
        Snapshot::Committed | Snapshot::Other => None,
    };
    let inputs = Inputs::read(store, txn)?;
    let mut extended = None;
    for base in staged.iter().chain(committed.iter().map(|(_, view)| view)) {
        extended = extended_view(store, txn, base, &inputs, snapshot)?;
        if extended.is_some() {
            break;
        }
    }
    let view = match extended {
        Some(view) => view,
        None => Arc::new(rebuilt(store, txn, &inputs, snapshot)?),
    };
    match snapshot {
        Snapshot::Committed => {
            if let Ok(mut cache) = store.authority_door_view.lock() {
                *cache = Some((generation, Arc::clone(&view)));
            }
        }
        Snapshot::Staged { .. } => {
            if let Ok(mut cache) = store.authority_door_view_staged.lock() {
                *cache = Some(Arc::clone(&view));
            }
        }
        Snapshot::Other => {}
    }
    Ok(view)
}

/// The door view of every row stored in `txn`, built afresh.
#[cfg(oneiron_test_support)]
pub(super) fn rebuilt_door_view(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> crate::error::Result<AuthorityDoorView> {
    rebuilt(store, txn, &Inputs::read(store, txn)?, Snapshot::Other)
}

/// One stored row as the fold takes it: opened with its overlay record when
/// it seals one, or, when that record does not open here, as structure
/// (census L5-22 1a-iii).
fn decode_row(store: &Store, txn: &heed::RoTxn<'_>, body: &[u8]) -> crate::error::Result<KeptRow> {
    #[cfg(oneiron_test_support)]
    DOOR_VIEW_ROWS_DECODED.with(|rows| rows.set(rows.get() + 1));
    Ok(Arc::new(decode_vault_authority_fold_row_in_txn(
        store, txn, body,
    )?))
}

/// The counts of `entries`, the stored rows read whole, and of the rows
/// `evidence`'s image covers, under `structure`.
fn tally_of<'e>(
    structure: &AuthorityStructure,
    entries: impl Iterator<Item = &'e FoldRow>,
    evidence: Option<&AdoptedEvidence>,
) -> Tally {
    let mut tally = Tally::default();
    for row in entries {
        tally.count(structure, row.signer_key(), is_slip_row(row), Some(row));
    }
    if let Some(evidence) = evidence {
        for (hash, summary) in evidence.rows() {
            let row = evidence.body(hash).cloned().map(FoldRow::Open);
            tally.count(structure, &summary.signer, summary.slip_op, row.as_ref());
        }
    }
    tally
}

fn view_of(
    rows: DoorRows,
    projection: DoorProjection,
    evidence: Option<Arc<AdoptedEvidence>>,
) -> AuthorityDoorView {
    AuthorityDoorView {
        structure: rows.builder.structure.clone(),
        rows: rows.tally.rows.clone(),
        counted: rows.tally.counted,
        issuer_handoffs: rows.tally.issuer_handoffs,
        strangers: rows.tally.strangers,
        projection,
        evidence,
        kept: rows,
    }
}

/// The door view of every row stored in `txn`. It is kept for a later
/// generation's view to extend when the store order vouches for the rows it
/// read: complete, and for a write's staged rows, read past the committed
/// ones.
fn rebuilt(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    inputs: &Inputs,
    snapshot: Snapshot,
) -> crate::error::Result<AuthorityDoorView> {
    #[cfg(test)]
    DOOR_VIEW_BUILDS.with(|builds| builds.set(builds.get() + 1));
    let evidence = inputs.evidence.as_deref();
    let mut ids = im::OrdMap::new();
    let mut entries = Vec::new();
    for (id, body) in authority_log_rows_in_txn(store, txn)? {
        // A covered row counts once, from the image.
        if evidence.is_some_and(|evidence| evidence.covers_id(&id)) {
            ids.insert(id, None);
            continue;
        }
        let entry = decode_row(store, txn, &body)?;
        ids.insert(id, Some(Arc::clone(&entry)));
        entries.push(entry);
    }
    // The structure reads the image's carried rows as the stored rows they
    // stand for: it admits what the covered history admitted, never what the
    // folded roster now holds.
    let mut builder = StructureBuilder::under(inputs.local.clone());
    for carried in evidence
        .iter()
        .flat_map(|evidence| evidence.bodies().values())
    {
        builder.push(Arc::new(FoldRow::Open(carried.clone())));
    }
    for entry in &entries {
        builder.push(Arc::clone(entry));
    }
    builder.settle();
    builder.grown.clear();
    let tally = tally_of(
        &builder.structure,
        entries.iter().map(|entry| &**entry),
        evidence,
    );
    let mut projection = DoorProjection::default();
    for row in &entries {
        projection.insert(row.hash()?, row.parent_hashes());
    }
    if let Some(evidence) = evidence {
        for (hash, row) in evidence.rows() {
            projection.insert(*hash, &row.parents);
        }
    }
    let (next_seq, staged) = match (snapshot, inputs.next_seq) {
        (Snapshot::Committed | Snapshot::Other, next_seq) => (next_seq, None),
        (
            Snapshot::Staged {
                committed_next: Some(committed_next),
            },
            Some(next),
        ) => match ids_sequenced_in_txn(store, txn, committed_next, next)? {
            Some(staged) => (
                Some(next),
                Some(StagedRows {
                    committed_next,
                    ids: staged.into_iter().collect(),
                }),
            ),
            None => (None, None),
        },
        (Snapshot::Staged { .. }, _) => (None, None),
    };
    let rows = DoorRows {
        next_seq,
        ids,
        image: inputs.image,
        local: inputs.local.clone(),
        builder,
        tally,
        staged,
    };
    Ok(view_of(rows, projection, inputs.evidence.clone()))
}

/// `base` extended by the rows sequenced past it in `txn`, or None where it
/// cannot be: another adopted image or local roots, not one genesis, an
/// incomplete store order, or a row `base` read that `txn` no longer holds.
fn extended_view(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    base: &Arc<AuthorityDoorView>,
    inputs: &Inputs,
    snapshot: Snapshot,
) -> crate::error::Result<Option<Arc<AuthorityDoorView>>> {
    let kept = &base.kept;
    let (Some(base_next), Some(next)) = (kept.next_seq, inputs.next_seq) else {
        return Ok(None);
    };
    if kept.image != inputs.image
        || kept.local != inputs.local
        || !kept.builder.structure.has_one_root()
        || base_next > next
    {
        return Ok(None);
    }
    // A staged view extends only in the same write, while it holds exactly
    // the staged rows the view read: a nested write that rolled back holds
    // others.
    if let Some(staged) = &kept.staged {
        let Snapshot::Staged {
            committed_next: Some(committed_next),
        } = snapshot
        else {
            return Ok(None);
        };
        if committed_next != staged.committed_next {
            return Ok(None);
        }
        let Some(held) = ids_sequenced_in_txn(store, txn, staged.committed_next, base_next)? else {
            return Ok(None);
        };
        if !held.iter().eq(staged.ids.iter()) {
            return Ok(None);
        }
    }
    let Some(tail) = ids_sequenced_in_txn(store, txn, base_next, next)? else {
        return Ok(None);
    };
    // Every stored row is sequenced once, and every row `base` read is
    // still stored, so with no tail row among them the stored rows are
    // exactly `base`'s and the tail's.
    if tail.iter().any(|id| kept.ids.contains_key(id)) {
        return Ok(None);
    }
    if tail.is_empty() {
        return Ok(Some(Arc::clone(base)));
    }
    let staged = match snapshot {
        Snapshot::Committed | Snapshot::Other => None,
        Snapshot::Staged {
            committed_next: Some(committed_next),
        } => {
            let mut ids = match &kept.staged {
                Some(staged) => staged.ids.clone(),
                None => im::Vector::new(),
            };
            // Past a committed base, the staged rows are the tail's rows
            // sequenced past the committed ones.
            let committed_in_tail = match &kept.staged {
                Some(_) => 0,
                None => match committed_next.checked_sub(base_next) {
                    Some(committed) => usize::try_from(committed).unwrap_or(usize::MAX),
                    None => return Ok(None),
                },
            };
            if committed_in_tail > tail.len() {
                return Ok(None);
            }
            ids.extend(tail[committed_in_tail..].iter().copied());
            Some(StagedRows {
                committed_next,
                ids,
            })
        }
        Snapshot::Staged {
            committed_next: None,
        } => return Ok(None),
    };
    #[cfg(test)]
    DOOR_VIEW_BUILDS.with(|builds| builds.set(builds.get() + 1));
    let mut rows = DoorRows {
        next_seq: Some(next),
        ids: kept.ids.clone(),
        image: kept.image,
        local: kept.local.clone(),
        builder: kept.builder.clone(),
        tally: kept.tally.clone(),
        staged,
    };
    let mut projection = base.projection.to_extend();
    let mut entries = Vec::new();
    for id in tail {
        if inputs
            .evidence
            .as_ref()
            .is_some_and(|evidence| evidence.covers_id(&id))
        {
            rows.ids.insert(id, None);
            continue;
        }
        let entry = decode_row(store, txn, &authority_log_body_in_txn(store, txn, &id)?)?;
        projection.insert(entry.hash()?, entry.parent_hashes());
        rows.ids.insert(id, Some(Arc::clone(&entry)));
        entries.push(entry);
    }
    let grants = entries.iter().any(|entry| structure_reads(entry));
    for entry in &entries {
        rows.builder.push(Arc::clone(entry));
    }
    rows.builder.settle();
    rows.builder.grown.clear();
    if grants {
        rows.tally = tally_of(
            &rows.builder.structure,
            rows.ids.values().flatten().map(|entry| &**entry),
            inputs.evidence.as_deref(),
        );
    } else {
        for row in &entries {
            rows.tally.count(
                &rows.builder.structure,
                row.signer_key(),
                is_slip_row(row),
                Some(row),
            );
        }
    }
    Ok(Some(Arc::new(view_of(
        rows,
        projection,
        inputs.evidence.clone(),
    ))))
}
