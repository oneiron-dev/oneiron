//! The sources a text a model derived from repo bytes stands on (FIX 7608
//! S3F, FIX 10405): a caption or transcript (ASSET_TEXT) is bound to each
//! ASSET it was written from by its own `DerivedFrom` edges, never by a
//! path, a hash string or equal words.
//!
//! A model-written text is not literal: a marked blob's spans cannot be
//! found in its words. So when any of its sources is marked, itself or
//! through a source it derives from, the whole text is indexed only as a
//! safe copy derived again from the sources' masked copies (CALL
//! DERIVED-TEXT-COPY). That copy is bound to a proof: the text's own
//! content, and every source's id and current identity (its record and,
//! for a marked source, its copy's stamp), unmarked sources included, so a
//! later mark, mask, edit or new source edge makes it stale. Discovery reads
//! the edges as they are now, so a text or an edge written after the mark
//! is found as well as an older one. Edges are followed with a visited set
//! and no depth or count cap.
//!
//! A marked blob's snapshot record is marked by its id, which the blob's
//! BLAKE3 derives, so it stays marked once erased. A record a mark covers
//! by its media bytes alone (an inline envelope) is bound to that blob when
//! a copy is derived from it ([`bind_envelope_sources_in_txn`]), and reads
//! marked by that binding once erased (FIX 10887).

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};

use super::{RepoIndexMarks, RepoIndexProjectionStamp};
use crate::Vault;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead};
use crate::registry::ENTITY_TYPE_ASSET_TEXT;
use crate::side_table::{self, Named, SideTable};
use crate::store::{ManifestDbs, Store};

/// The domain of one source's identity.
const REPO_DERIVED_SOURCE_CONTEXT: &str = "oneiron.repo-index-projection.derived-source.v1";
/// The domain of a derived text's proof.
const REPO_DERIVED_PROOF_CONTEXT: &str = "oneiron.repo-index-projection.derived-proof.v1";

/// Each source record a mark covered by its media bytes when a copy was
/// derived from it, with that blob's whole BLAKE3 (FIX 10887). Key: id16.
const ENVELOPE_SOURCE_BLOBS: SideTable<EntityId, [u8; 32], Named> =
    SideTable::new(&side_table::REPO_DERIVED_SOURCE_BLOB);

/// One source a derived text was written from, as it stands now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepoDerivedSource {
    pub(crate) id: EntityId,
    /// Its record's type, body and copy stamp, and those of every source it
    /// derives from; all zero for a source that is gone.
    pub(crate) identity: [u8; 32],
    /// Whether a mark covers it, itself or through a source it derives from.
    pub(crate) marked: bool,
}

/// What a derived text with a marked source is bound to now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepoDerivedIndexSources {
    pub(crate) entity: EntityId,
    /// The whole BLAKE3 of the text's own stored body.
    pub(crate) content: [u8; 32],
    /// Every source it names, sorted by id.
    pub(crate) sources: Vec<RepoDerivedSource>,
    /// Every record of its source chain a mark covers by its media bytes,
    /// not by its id, with that blob: the bindings
    /// [`bind_envelope_sources_in_txn`] keeps (FIX 10887).
    pub(crate) envelope_blobs: Vec<(EntityId, [u8; 32])>,
}

impl RepoDerivedIndexSources {
    /// One digest of the text's content and every source's identity: the
    /// proof a safe copy is derived under, and is current only while it is.
    pub(crate) fn proof(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(REPO_DERIVED_PROOF_CONTEXT);
        hasher.update(self.entity.as_bytes());
        hasher.update(&self.content);
        hasher.update(&(self.sources.len() as u64).to_be_bytes());
        for source in &self.sources {
            hasher.update(source.id.as_bytes());
            hasher.update(&source.identity);
            hasher.update(&[u8::from(source.marked)]);
        }
        *hasher.finalize().as_bytes()
    }
}

/// The sources of ASSET_TEXT `entity`, as `view` holds them in `txn`, when
/// any of them is marked; `None` for any other record, a text bound to no
/// source, or one whose sources are all unmarked, which indexes as it
/// always has.
///
/// # Errors
/// A store failure, or the projection of a marked source failing.
pub(crate) fn repo_derived_index_sources_in(
    vault: &Vault,
    view: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    marks: &RepoIndexMarks,
    entity: &EntityId,
) -> Result<Option<RepoDerivedIndexSources>> {
    if marks.is_empty() {
        return Ok(None);
    }
    let Some(row) = view.port_entity_record(txn, entity)? else {
        return Ok(None);
    };
    if row.entity_type != ENTITY_TYPE_ASSET_TEXT {
        return Ok(None);
    }
    let mut visited = BTreeSet::from([*entity]);
    let mut sources = Vec::new();
    let mut envelope_blobs = Vec::new();
    for peer in derived_from(view, txn, entity)? {
        let (marked, identity) = source_identity(
            vault,
            view,
            txn,
            marks,
            &peer,
            &mut visited,
            &mut envelope_blobs,
        )?
        .unwrap_or_default();
        sources.push(RepoDerivedSource {
            id: peer,
            identity,
            marked,
        });
    }
    if !sources.iter().any(|source| source.marked) {
        return Ok(None);
    }
    sources.sort_by_key(|source| source.id);
    Ok(Some(RepoDerivedIndexSources {
        entity: *entity,
        content: *blake3::hash(&row.body).as_bytes(),
        sources,
        envelope_blobs,
    }))
}

/// Keeps each binding `sources` found, in the writer that queues or lands
/// its copy (FIX 10887): a source a mark covers by its media bytes stays
/// bound to that blob, so it reads marked once erased, as a snapshot record
/// does by its id. One keyed read per binding, and a write only when new.
///
/// # Errors
/// A store failure.
pub(crate) fn bind_envelope_sources_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    sources: &RepoDerivedIndexSources,
) -> Result<()> {
    for (id, blob) in &sources.envelope_blobs {
        if ENVELOPE_SOURCE_BLOBS.get_lenient(store, wtxn, id)?.as_ref() != Some(blob) {
            ENVELOPE_SOURCE_BLOBS.put(store, wtxn, id, blob)?;
        }
    }
    Ok(())
}

/// Every record that derives from one of `roots`, through `DerivedFrom`
/// edges followed back from them as `view` holds them: the texts (and the
/// derived assets, and their texts) a mask change on `roots` reaches.
///
/// # Errors
/// A store failure.
pub(crate) fn repo_derived_dependents_in(
    view: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    roots: &BTreeSet<EntityId>,
) -> Result<BTreeSet<EntityId>> {
    let mut seen = roots.clone();
    let mut stack = roots.iter().copied().collect::<Vec<_>>();
    let mut dependents = BTreeSet::new();
    while let Some(id) = stack.pop() {
        for peer in view.port_edge_peers(txn, &id, EdgeDirection::In, EdgeKind::DerivedFrom)? {
            let peer = peer?;
            if seen.insert(peer) {
                dependents.insert(peer);
                stack.push(peer);
            }
        }
    }
    Ok(dependents)
}

/// Record `id`'s markedness and identity as a source, as `view` holds it
/// (itself and what it derives from); `None` for a record that is gone.
///
/// # Errors
/// A store failure, or the projection of a marked source failing.
pub(crate) fn repo_source_identity_in(
    vault: &Vault,
    view: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    marks: &RepoIndexMarks,
    id: &EntityId,
) -> Result<Option<(bool, [u8; 32])>> {
    source_identity(
        vault,
        view,
        txn,
        marks,
        id,
        &mut BTreeSet::new(),
        &mut Vec::new(),
    )
}

/// The records `entity` names by its own outgoing `DerivedFrom` edges.
fn derived_from(
    view: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    entity: &EntityId,
) -> Result<Vec<EntityId>> {
    view.port_edge_peers(txn, entity, EdgeDirection::Out, EdgeKind::DerivedFrom)?
        .collect()
}

/// Source `id`'s markedness and identity; `None` for a source that is gone
/// and no marked blob's snapshot record or bound envelope. Each record of
/// the chain a mark covers by its media bytes goes into `envelopes`.
fn source_identity(
    vault: &Vault,
    view: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    marks: &RepoIndexMarks,
    id: &EntityId,
    visited: &mut BTreeSet<EntityId>,
    envelopes: &mut Vec<(EntityId, [u8; 32])>,
) -> Result<Option<(bool, [u8; 32])>> {
    let Some(row) = view.port_entity_record(txn, id)? else {
        // A marked blob's snapshot record stays marked by its id alone, held
        // or erased, and a bound envelope by its binding (FIX 10887): a text
        // written from either never reads as unmarked.
        let source = match marks.source_of(id) {
            Some(source) => Some(source),
            None => erased_envelope_blob(view, txn, marks, id)?,
        };
        return Ok(source.map(|source| {
            let mut hasher = blake3::Hasher::new_derive_key(REPO_DERIVED_SOURCE_CONTEXT);
            hasher.update(id.as_bytes());
            hasher.update(&source);
            (true, *hasher.finalize().as_bytes())
        }));
    };
    let mut hasher = blake3::Hasher::new_derive_key(REPO_DERIVED_SOURCE_CONTEXT);
    hasher.update(id.as_bytes());
    hasher.update(&[row.entity_type]);
    hasher.update(blake3::hash(&row.body).as_bytes());
    let mut marked = false;
    if let Some(stamp) = repo_source_copy_stamp_in(vault, txn, marks, id, &row.body)? {
        marked = true;
        hasher.update(&stamp.fingerprint());
        if marks.source_of(id).is_none() {
            envelopes.push((*id, stamp.source_blake3));
        }
    } else if row.body.is_empty()
        && let Some(blob) = erased_envelope_blob(view, txn, marks, id)?
    {
        // An erased shell keeps no bytes to join by: its binding does.
        marked = true;
        hasher.update(&blob);
    }
    if visited.insert(*id) {
        for parent in derived_from(view, txn, id)? {
            let (parent_marked, identity) =
                source_identity(vault, view, txn, marks, &parent, visited, envelopes)?
                    .unwrap_or_default();
            marked |= parent_marked;
            hasher.update(parent.as_bytes());
            hasher.update(&identity);
        }
    }
    Ok(Some((marked, *hasher.finalize().as_bytes())))
}

/// The blob erased record `id` was bound to by its media bytes (FIX
/// 10887), while a mark still covers it.
fn erased_envelope_blob(
    view: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    marks: &RepoIndexMarks,
    id: &EntityId,
) -> Result<Option<[u8; 32]>> {
    Ok(ENVELOPE_SOURCE_BLOBS
        .get_lenient(view, txn, id)?
        .filter(|blob| marks.is_marked(blob)))
}

/// The stamp of the copy record `id`, holding `body`, is read as when a
/// mark covers it: a marked blob's snapshot ASSET, or an ASSET whose media
/// bytes are a marked blob's. `None` for any other record.
///
/// # Errors
/// A store failure, or the projection of a marked blob failing.
pub(crate) fn repo_source_copy_stamp_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    marks: &RepoIndexMarks,
    id: &EntityId,
    body: &[u8],
) -> Result<Option<RepoIndexProjectionStamp>> {
    if let Some(source) = marks.source_of(id) {
        return Ok(marks
            .source_input_in_txn(vault, txn, &source, body.to_vec())?
            .stamp()
            .cloned());
    }
    // FIX 9949: an ASSET's bytes are the blob it holds by reference.
    let Some(bytes) = crate::embed::repo_media_bytes(body, |blob| {
        Ok(vault
            .store
            .port_entity_record(txn, blob)?
            .map(|blob| blob.body))
    })?
    else {
        return Ok(None);
    };
    Ok(marks.input_in_txn(vault, txn, bytes)?.stamp().cloned())
}
