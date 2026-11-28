//! Rebuilds the local dependency registrations of an own-vault CLAIM put.
//!
//! A CLAIM cites two kinds of source, and each takes its own rule on a replicated put:
//! - a verified MESSAGE locator holds the CLAIM on a sync-all device until the MESSAGE arrives
//!   (PR1-OPENED-COLD-SOURCE-MODE = A, 28 Nov);
//! - every other source (a typed citation, a deep-doc CLAIM's chunk and root ASSET) never holds
//!   it (PR2-TYPED-REF-ABSENCE = A and PR2-DEEP-DOC-ROOT-ORDER = A, 28 Nov). Such a source that B
//!   cannot resolve, on any device, gets a cold-citation row, and the CLAIM lands readable.
//!
//! Both rules register what B can resolve: a resident source at its header, an index-listed one
//! at its listing. Deletion evidence marks the CLAIM stale. A cold source that lands later is
//! judged at its arrival, as a resident source is (`register_arrived_source_in_txn`).

use crate::EntityId;
use crate::error::{Error, Result};
use crate::store::{ManifestDbs, Store};
use crate::write_envelope::claim_body::{ClaimBody, ClaimSubject};
use rmpv::Value;
use std::collections::BTreeSet;

const CITED_SOURCE_PENDING: &str = "a CLAIM's cited source has not arrived";

/// The derivation kind a deep-doc CLAIM's evidence names (`ingest/docs_deep/review.rs`).
const DEEP_DOC_CLAIM_KIND: &str = "ner_claim";

#[cfg(feature = "sync")]
pub(crate) fn claim_source_pending(error: &Error) -> bool {
    matches!(error, Error::InvalidClaimBody(CITED_SOURCE_PENDING))
}

/// Only promotion evidence with the verified locator field reaches this door.
pub(crate) fn locator_evidence(body: &ClaimBody) -> Option<&Value> {
    let value = map_entry(body.evidence.as_ref()?, "candidate_evidence")?;
    map_entry(value, "locators")?;
    Some(value)
}

fn map_entry<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    value
        .as_map()?
        .iter()
        .find_map(|(key, value)| (key.as_str() == Some(name)).then_some(value))
}

/// The MESSAGE ids a CLAIM's verified locators cite; empty without locator evidence.
fn locator_sources(body: &ClaimBody) -> Result<BTreeSet<EntityId>> {
    let Some(evidence) = locator_evidence(body) else {
        return Ok(BTreeSet::new());
    };
    let citations = super::decode_verified_citations(evidence)
        .map_err(|_| Error::InvalidClaimBody("invalid verified consolidation locators"))?;
    Ok(citations
        .into_iter()
        .flat_map(|(_, _, spans)| spans.into_iter().map(|span| span.message))
        .collect())
}

/// The chunk and root ASSET a deep-doc CLAIM derives from, as `write_deep_batch` binds them on
/// the writer (`ingest/docs_deep.rs`): the chunk is `candidate_evidence.derivation.source_ref`
/// of imported docs-export evidence whose derivation kind is `ner_claim`, and the root is the
/// CLAIM's entity subject. `None` for any other CLAIM.
fn deep_doc_sources(body: &ClaimBody) -> Option<[EntityId; 2]> {
    let candidate = map_entry(body.evidence.as_ref()?, "candidate_evidence")?;
    if map_entry(candidate, "source_id")?.as_str()? != crate::ingest::DOCS_EXPORT_SOURCE_ID {
        return None;
    }
    let derivation = map_entry(candidate, "derivation")?;
    if map_entry(derivation, "derived_kind")?.as_str()? != DEEP_DOC_CLAIM_KIND {
        return None;
    }
    let chunk = EntityId::from_hex(map_entry(derivation, "source_ref")?.as_str()?).ok()?;
    let ClaimSubject::Entity(root) = &body.subject else {
        return None;
    };
    Some([chunk, *root])
}

/// The typed citations' entities and a deep-doc CLAIM's chunk and root: the sources that never
/// hold the CLAIM. A typed citation whose entity id does not parse names no source, as on the
/// writer. Evidence whose typed slots do not decode names none either: the CLAIM lands as it
/// does today, since the writer refused such a body at its own put.
fn typed_and_deep_sources(body: &ClaimBody) -> BTreeSet<EntityId> {
    let typed = body.evidence_refs().unwrap_or_default();
    let mut sources: BTreeSet<EntityId> = typed
        .iter()
        .filter_map(|reference| EntityId::from_hex(&reference.entity).ok())
        .collect();
    sources.extend(deep_doc_sources(body).into_iter().flatten());
    sources
}

/// Every source a CLAIM cites: its verified locators' MESSAGEs, its typed citations' entities, and
/// a deep-doc CLAIM's chunk and root.
pub(crate) fn cited_sources(body: &ClaimBody) -> Result<BTreeSet<EntityId>> {
    let mut sources = locator_sources(body)?;
    sources.extend(typed_and_deep_sources(body));
    Ok(sources)
}

/// Whether a CLAIM cites any source the replay hook judges: the federation origin filter tags
/// these CLAIMs, so a peer copy of one keeps today's rule.
#[cfg(feature = "sync")]
pub(crate) fn cites_sources(body: &ClaimBody) -> bool {
    locator_evidence(body).is_some() || !typed_and_deep_sources(body).is_empty()
}

/// What a replicated put found for one cited source.
pub(crate) enum SourceStanding {
    /// Local or carrier deletion evidence: the CLAIM is marked stale.
    Deleted,
    /// Resident at its header, or index-listed at its listing: the dependency is recorded.
    Registered,
    /// Absent, unlisted and unmarked: the source's rule decides.
    Unresolved,
}

/// The row's own-vault replay context, not carried by other replicated puts.
#[derive(Debug)]
pub(crate) struct ClaimSourceReplay {
    pub(crate) claim: EntityId,
    /// The cited sources whose carrier tombstone the window's tombstone pass replays
    /// (`sync/ingest/claim_source_tombstones.rs`). A carrier tombstone the pass skips proves no
    /// deletion, so it never marks the CLAIM stale (#10654 review r1).
    #[cfg(feature = "sync")]
    pub(crate) carrier_deleted: BTreeSet<EntityId>,
}

impl ClaimSourceReplay {
    pub(crate) fn register_in_txn(
        &self,
        store: &Store,
        txn: &mut heed::RwTxn<'_>,
        body: &ClaimBody,
    ) -> Result<()> {
        let locators = locator_sources(body)?;
        // A typed self-citation is skipped, never waited on: the writer's dependency writer
        // refuses a resident self-source, so the writer recorded no such edge.
        let mut unheld = typed_and_deep_sources(body);
        unheld.retain(|source| *source != self.claim && !locators.contains(source));
        if locators.is_empty() && unheld.is_empty() {
            return Ok(());
        }
        #[cfg(feature = "sync")]
        let opened = crate::sync::residence::device_residence_opened_in_txn(store, txn)?;
        let mut withdrawn = false;
        let mut pending = false;
        for source in locators {
            if source == self.claim {
                return Err(Error::InvalidClaimBody(
                    "a CLAIM cannot cite itself as a MESSAGE",
                ));
            }
            match self.resolve_source_in_txn(store, txn, &source)? {
                SourceStanding::Deleted => withdrawn = true,
                SourceStanding::Registered => {}
                SourceStanding::Unresolved => {
                    // On an opened device an absent, unlisted source lands the CLAIM with no
                    // registration row: a cold source has no frontier, and a hard erase of it
                    // never reaches an opened device (PR1-OPENED-COLD-SOURCE-MODE = A, 28 Nov).
                    // Its cold-citation row lets the read gate judge the source on local
                    // evidence: a soft-drop marker hides the CLAIM, at arrival or later, and a
                    // restore shows it again with no replay (#10654 review r1).
                    #[cfg(feature = "sync")]
                    if opened {
                        crate::sync::residence::put_cold_citation_in_txn(
                            store,
                            txn,
                            &self.claim,
                            &source,
                        )?;
                        continue;
                    }
                    pending = true;
                }
            }
        }
        for source in unheld {
            match self.resolve_source_in_txn(store, txn, &source)? {
                SourceStanding::Deleted => withdrawn = true,
                SourceStanding::Registered => {}
                SourceStanding::Unresolved => {
                    // Never held, on any device (PR2-TYPED-REF-ABSENCE = A): the CLAIM lands
                    // readable with a cold-citation row, and the read gate hides it only on local
                    // evidence, a deletion mark or a soft-drop marker. The writer keeps a typed
                    // citation whether or not it registered it, so B's absence cannot tell a
                    // dependency to wait for from one never recorded. A deep-doc root ASSET is
                    // visited after the CLAIM in the same pass (`waits_for_sibling_row`), so a
                    // hold would keep every same-window deep-doc CLAIM out
                    // (PR2-DEEP-DOC-ROOT-ORDER = A).
                    #[cfg(feature = "sync")]
                    crate::sync::residence::put_cold_citation_in_txn(
                        store,
                        txn,
                        &self.claim,
                        &source,
                    )?;
                }
            }
        }
        if withdrawn {
            self.mark_withdrawn_in_txn(store, txn)?;
        } else if pending {
            return Err(Error::InvalidClaimBody(CITED_SOURCE_PENDING));
        }
        Ok(())
    }

    /// Judges one cited source on this device ([`resolve_dependent_source_in_txn`]), taking a
    /// carrier tombstone the window's tombstone pass replays as deletion evidence.
    fn resolve_source_in_txn(
        &self,
        store: &Store,
        txn: &mut heed::RwTxn<'_>,
        source: &EntityId,
    ) -> Result<SourceStanding> {
        #[cfg(feature = "sync")]
        let crdt_deleted = self.carrier_deleted.contains(source);
        #[cfg(not(feature = "sync"))]
        let crdt_deleted = false;
        resolve_dependent_source_in_txn(store, txn, &self.claim, source, crdt_deleted)
    }

    fn mark_withdrawn_in_txn(&self, store: &Store, txn: &mut heed::RwTxn<'_>) -> Result<()> {
        if !crate::ports::stale_in_txn(store, txn, &self.claim)? {
            let at = crate::ports::recorded_at_in_txn(store, txn)?;
            crate::ports::stage_stale_mark_in_txn(store, txn, &self.claim, at)?;
        }
        Ok(())
    }
}

/// Judges one source `dependent` names on this device: deletion evidence first (`carrier_deleted`
/// says the window's tombstone pass replays the source's carrier tombstone), then a resident row
/// (keyed by its header's learned-at, as on the writer, never a locator's optional CRDT
/// frontier), then an index listing. Records the dependency of a resolved source.
pub(crate) fn resolve_dependent_source_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    dependent: &EntityId,
    source: &EntityId,
    carrier_deleted: bool,
) -> Result<SourceStanding> {
    if carrier_deleted || crate::ports::source_deleted_or_withdrawn_in_txn(store, txn, source)? {
        return Ok(SourceStanding::Deleted);
    }
    if store.entities().get(txn, source.as_bytes())?.is_some() {
        crate::ports::record_derived_edge_in_txn(store, txn, dependent, source)?;
        return Ok(SourceStanding::Registered);
    }
    #[cfg(feature = "sync")]
    if crate::ports::record_index_listed_dependency_in_txn(store, txn, source, dependent)? {
        return Ok(SourceStanding::Registered);
    }
    Ok(SourceStanding::Unresolved)
}

/// Marks the resident `dependent` stale at its own revision, as a dependency walk marks it, unless
/// it is marked already: only a newer version of it may complete a regeneration over the mark
/// (`ports/regeneration.rs`).
#[cfg(feature = "sync")]
pub(crate) fn mark_dependent_stale_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    dependent: &EntityId,
) -> Result<()> {
    if crate::ports::stale_in_txn(store, txn, dependent)? {
        return Ok(());
    }
    let revision = store
        .entities()
        .get(txn, dependent.as_bytes())?
        .map(|raw| {
            crate::batch::EntityMetadataHeader::parse(&raw)
                .map(|header| header.learned_at)
                .ok_or(Error::CorruptedIndex("stale dependent header"))
        })
        .transpose()?
        .unwrap_or(0);
    crate::ports::stage_stale_mark_in_txn(store, txn, dependent, revision)
}

/// Judges `source`, which just landed on this device, for every dependent that landed without it
/// (a CLAIM, a scope SUMMARY, a PSYCH_PROFILE), as the put judges a resident source: deletion
/// evidence marks the dependent stale, else the dependency is recorded at the source's header.
/// Each dependent is judged once: its by-source cold row is taken here. The cold-citation row
/// itself stays, the record that the dependent landed without the source, and the read gate judges
/// a resident source by it as it does by the dependency. A source that is not resident after its
/// put (a staged or pending row) is left for its real landing.
#[cfg(feature = "sync")]
pub(crate) fn register_arrived_source_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    source: &EntityId,
) -> Result<()> {
    let citers = crate::sync::residence::cold_citers_of_source_in_txn(store, txn, source)?;
    if citers.is_empty() || store.entities().get(txn, source.as_bytes())?.is_none() {
        return Ok(());
    }
    for dependent in citers {
        crate::sync::residence::delete_cold_citation_by_source_in_txn(
            store, txn, source, &dependent,
        )?;
        if store.entities().get(txn, dependent.as_bytes())?.is_none() {
            continue;
        }
        if let SourceStanding::Deleted =
            resolve_dependent_source_in_txn(store, txn, &dependent, source, false)?
        {
            mark_dependent_stale_in_txn(store, txn, &dependent)?;
        }
    }
    Ok(())
}
