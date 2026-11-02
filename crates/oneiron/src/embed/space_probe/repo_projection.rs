//! The query a space move runs for a probe written from repo bytes (FIX
//! 7608 S3F, FIX 10408; CALL PROBE-QUERY-COPY).
//!
//! A probe one of whose query's sources a mark covers (itself, or through
//! what it derives from) may hold words a model or the owner wrote from the
//! stored bytes. Its stored row stays exactly as written: id, query, family,
//! sources, targets, author and cohort, and the owner's put, list and delete
//! are today's doors. A move's evaluation runs only its safe evaluation copy
//! instead: a query the vault's own probe author writes again from its
//! document's CURRENT masked copy, under the probe's original id, bound to
//! a proof of the probe's content and its sources. While that
//! copy is pending, or its proof is stale, the probe is left out of the
//! evaluation, never scored as a placeholder; the author's next pass
//! rebuilds it. A source that changes again makes it pending again, with no
//! expiry and no retry ceiling. No owner probe is refused.

use std::collections::{BTreeMap, BTreeSet};

use heed::{RoTxn, RwTxn};

use super::super::media::{MediaEmbedReport, text_document_of};
use super::super::repo_projection::{
    RepoDerivedOwner, RepoDerivedReady, copy_in, delete_in_txn, is_storage_error, pending_in,
    put_pending_in_txn, put_ready_in_txn,
};
use super::super::space::InputKind;
use super::super::{EgressDecision, EgressPredicate};
use super::{EMBEDDING_PROBE, SPACE_PROBE_QUERY_MAX_LEN, SpaceProbe, SpaceProbeAuthor};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::origin::secret_projection::index::{RepoIndexMarks, repo_source_identity_in};

/// The domain of a probe copy's proof.
const PROBE_COPY_PROOF_CONTEXT: &str = "oneiron.repo-index-projection.probe-proof.v1";

/// Probe `id`'s proof under `marks` when a source of its query is marked
/// ([`SpaceProbe::query_sources`]: its document, media query and the rows
/// they were read and derived from, FIX 9829): its id, its query's words
/// and each source's identity, with the sources' ids; `None` when none is
/// marked.
fn probe_proof_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    marks: &RepoIndexMarks,
    id: &[u8; 16],
    probe: &SpaceProbe,
) -> Result<Option<([u8; 32], Vec<[u8; 16]>)>> {
    if marks.is_empty() {
        return Ok(None);
    }
    let mut hasher = blake3::Hasher::new_derive_key(PROBE_COPY_PROOF_CONTEXT);
    hasher.update(id);
    hasher.update(blake3::hash(probe.query.as_bytes()).as_bytes());
    let mut marked = false;
    let mut sources = Vec::new();
    for source in probe.query_sources() {
        let (source_marked, identity) =
            repo_source_identity_in(vault, &vault.store, txn, marks, &source)?.unwrap_or_default();
        marked |= source_marked;
        hasher.update(source.as_bytes());
        hasher.update(&identity);
        sources.push(*source.as_bytes());
    }
    Ok(marked.then(|| (*hasher.finalize().as_bytes(), sources)))
}

/// [`probe_proof_in`] under the marks `txn` reads now, per blob.
fn current_probe_proof_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    id: &[u8; 16],
    probe: &SpaceProbe,
) -> Result<Option<([u8; 32], Vec<[u8; 16]>)>> {
    let marks = RepoIndexMarks::read_scoped_in_txn(vault, txn)?;
    probe_proof_in(vault, txn, &marks, id, probe)
}

/// In the writer that changed the marks: every stored probe one of whose
/// query's sources is one of `affected` and is now marked is made pending,
/// unless its ready copy still holds. The stored probe is untouched; a
/// target alone is no proof its query came from that record.
///
/// # Errors
/// A store failure.
pub(crate) fn refresh_repo_probe_queries_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    marks: &RepoIndexMarks,
    affected: &BTreeSet<EntityId>,
) -> Result<()> {
    for (id, probe) in EMBEDDING_PROBE.scan(&vault.store, wtxn)? {
        let reached = probe
            .query_sources()
            .iter()
            .any(|source| affected.contains(source));
        if !reached {
            continue;
        }
        match probe_proof_in(vault, wtxn, marks, &id, &probe) {
            Ok(Some((proof, _))) => {
                put_pending_in_txn(
                    &vault.store,
                    wtxn,
                    RepoDerivedOwner::Probe(id),
                    Some(&proof),
                )?;
            }
            Ok(None) => {}
            Err(error) if is_storage_error(&error) => return Err(error),
            Err(_) => put_pending_in_txn(&vault.store, wtxn, RepoDerivedOwner::Probe(id), None)?,
        }
    }
    Ok(())
}

/// After the owner puts probe `id`: its evaluation copy is queued when a
/// source of its query needs projection, and an older one dropped when none
/// does. It validates nothing and refuses nothing; marks that cannot
/// be read queue it, for the author's pass to settle.
///
/// # Errors
/// A store failure.
pub(super) fn queue_probe_query_copy_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    id: &[u8; 16],
    probe: &SpaceProbe,
) -> Result<()> {
    let owner = RepoDerivedOwner::Probe(*id);
    let proof = current_probe_proof_in(vault, wtxn, id, probe);
    match proof {
        Ok(Some((proof, _))) => put_pending_in_txn(&vault.store, wtxn, owner, Some(&proof)),
        Ok(None) => delete_in_txn(&vault.store, wtxn, owner),
        Err(error) if is_storage_error(&error) => Err(error),
        Err(_) => put_pending_in_txn(&vault.store, wtxn, owner, None),
    }
}

/// After the owner deletes probe `id`: its evaluation copy goes with it.
///
/// # Errors
/// A store failure.
pub(super) fn drop_probe_query_copy_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    id: &[u8; 16],
) -> Result<()> {
    delete_in_txn(&vault.store, wtxn, RepoDerivedOwner::Probe(*id))
}

/// After the author stores probe `id`, written from its document's projected
/// copy in this same writer: when a source of its query is marked, the query
/// it wrote is its evaluation copy, ready under the current proof.
///
/// # Errors
/// A store failure.
pub(super) fn record_authored_probe_copy_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    id: &[u8; 16],
    probe: &SpaceProbe,
) -> Result<()> {
    let owner = RepoDerivedOwner::Probe(*id);
    let proof = current_probe_proof_in(vault, wtxn, id, probe);
    match proof {
        Ok(Some((proof, sources))) => put_ready_in_txn(
            &vault.store,
            wtxn,
            owner,
            RepoDerivedReady {
                proof,
                sources,
                safe_text: probe.query.clone(),
                provenance: probe.author.clone(),
            },
        ),
        Ok(None) => delete_in_txn(&vault.store, wtxn, owner),
        Err(error) if is_storage_error(&error) => Err(error),
        Err(_) => put_pending_in_txn(&vault.store, wtxn, owner, None),
    }
}

/// The stored probes a move's evaluation runs, in id order (CALL
/// PROBE-QUERY-COPY): a probe with no copy row as stored; one whose ready
/// copy holds under its current proof as a transient clone carrying the
/// safe query under its ORIGINAL id; one whose query's sources are no longer
/// marked as stored; every other (pending, stale, or its marks
/// unreadable) left out. Marks are read only when some probe has a row, so
/// a mark failure never touches a probe without one.
///
/// # Errors
/// A store failure.
pub(crate) fn projected_space_probes_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
) -> Result<Vec<([u8; 16], SpaceProbe)>> {
    let stored = EMBEDDING_PROBE.scan(&vault.store, txn)?;
    let mut rows = BTreeMap::new();
    for (id, _) in &stored {
        if let Some(row) = copy_in(&vault.store, txn, RepoDerivedOwner::Probe(*id))? {
            rows.insert(*id, row);
        }
    }
    if rows.is_empty() {
        return Ok(stored);
    }
    let marks = match RepoIndexMarks::read_scoped_in_txn(vault, txn) {
        Ok(marks) => Some(marks),
        Err(error) if is_storage_error(&error) => return Err(error),
        Err(error) => {
            tracing::warn!(error = %error, "probes written from repo bytes stay out of this check");
            None
        }
    };
    let mut projected = Vec::with_capacity(stored.len());
    for (id, mut probe) in stored {
        let Some(row) = rows.get(&id) else {
            projected.push((id, probe));
            continue;
        };
        let Some(marks) = &marks else {
            continue;
        };
        match probe_proof_in(vault, txn, marks, &id, &probe) {
            Ok(None) => projected.push((id, probe)),
            Ok(Some((proof, _))) => {
                if let Some(ready) = row.ready_under(&proof) {
                    probe.query.clone_from(&ready.safe_text);
                    projected.push((id, probe));
                }
            }
            Err(error) if is_storage_error(&error) => return Err(error),
            Err(_) => {}
        }
    }
    Ok(projected)
}

impl Vault {
    /// Rebuilds up to `max_items` pending evaluation copies of `kind`'s
    /// probes through `author`: each from its document's CURRENT projected
    /// copy ([`SpaceProbe::document`], never its old query, and never its
    /// family, a grouping since FIX 9831), egress asked as the author's
    /// own pass asks it, landing only when the probe and its proof are
    /// unchanged in the writer. A probe whose sources are no longer marked
    /// runs as stored again. Returns how many landed.
    ///
    /// # Errors
    /// A store failure, or the author's.
    pub(super) fn rebuild_probe_query_copies(
        &self,
        kind: InputKind,
        author: &dyn SpaceProbeAuthor,
        max_items: usize,
        egress: Option<&dyn EgressPredicate>,
    ) -> Result<usize> {
        let mut work = Vec::new();
        {
            let rtxn = self.store.env.read_txn()?;
            let marks = RepoIndexMarks::read_scoped_in_txn(self, &rtxn)?;
            let mut pending: Vec<[u8; 16]> = pending_in(&self.store, &rtxn, usize::MAX)?
                .into_iter()
                .filter_map(|owner| match owner {
                    RepoDerivedOwner::Probe(id) => Some(id),
                    RepoDerivedOwner::Text(_) => None,
                })
                .collect();
            // A pass draws a different few each time, so a probe no seat can
            // rewrite yet never holds the others back.
            let draw = self.store.clock.now_recorded_at().to_be_bytes();
            pending.sort_by_cached_key(|id| {
                *blake3::keyed_hash(blake3::hash(&draw).as_bytes(), id).as_bytes()
            });
            for id in pending {
                if work.len() >= max_items {
                    break;
                }
                let Some(probe) = EMBEDDING_PROBE.get(&self.store, &rtxn, &id)? else {
                    continue;
                };
                if probe.kind != kind {
                    continue;
                }
                let proof = match probe_proof_in(self, &rtxn, &marks, &id, &probe) {
                    Ok(proof) => proof,
                    Err(error) if is_storage_error(&error) => return Err(error),
                    Err(_) => continue,
                };
                let mut read = MediaEmbedReport::default();
                let document = match probe.kind {
                    InputKind::Text => {
                        text_document_of(self, &self.store, &rtxn, probe.document(), &mut read)?
                    }
                    InputKind::Image | InputKind::Audio => {
                        super::super::repo_projection::asset_document_projected_in(
                            self,
                            &self.store,
                            &rtxn,
                            probe.document(),
                            &BTreeSet::from([kind]),
                            &mut read,
                        )?
                    }
                };
                work.push((id, probe, proof, document));
            }
        }
        let mut written = Vec::new();
        for (id, probe, proof, document) in work {
            let Some((proof, sources)) = proof else {
                written.push((id, probe, None));
                continue;
            };
            let Some(document) = document else {
                continue;
            };
            let input = document.input();
            if let Some(egress) = egress
                && (egress.decide_media(&input) != EgressDecision::Allow
                    || !self.media_rows_may_leave(None, &[document.id])?)
            {
                continue;
            }
            let Some(query) = author
                .write_probe(&input)?
                .map(|query| query.trim().to_owned())
                .filter(|query| !query.is_empty() && query.len() <= SPACE_PROBE_QUERY_MAX_LEN)
            else {
                continue;
            };
            let ready = RepoDerivedReady {
                proof,
                sources,
                safe_text: query,
                provenance: author.author_id().to_owned(),
            };
            written.push((id, probe, Some(ready)));
        }
        if written.is_empty() {
            return Ok(0);
        }
        let mut landed = 0;
        let mut wtxn = self.store.env.write_txn()?;
        let marks = RepoIndexMarks::read_scoped_in_txn(self, &wtxn)?;
        for (id, probe, ready) in written {
            if EMBEDDING_PROBE.get(&self.store, &wtxn, &id)?.as_ref() != Some(&probe) {
                continue;
            }
            let owner = RepoDerivedOwner::Probe(id);
            let now = match probe_proof_in(self, &wtxn, &marks, &id, &probe) {
                Ok(now) => now.map(|(proof, _)| proof),
                Err(error) if is_storage_error(&error) => return Err(error),
                Err(_) => continue,
            };
            match (ready, now) {
                (None, None) => delete_in_txn(&self.store, &mut wtxn, owner)?,
                (Some(ready), Some(now)) if ready.proof == now => {
                    put_ready_in_txn(&self.store, &mut wtxn, owner, ready)?;
                    landed += 1;
                }
                _ => {}
            }
        }
        wtxn.commit()?;
        Ok(landed)
    }
}
