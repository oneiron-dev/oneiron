//! Rebuilds the local dependency registrations of an own-vault CLAIM put.

use crate::EntityId;
use crate::error::{Error, Result};
use crate::store::{ManifestDbs, Store};
use crate::write_envelope::claim_body::ClaimBody;
use rmpv::Value;

const CITED_SOURCE_PENDING: &str = "a CLAIM's cited source has not arrived";

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

/// The row's own-vault replay context, not carried by other replicated puts.
#[derive(Debug)]
pub(crate) struct ClaimSourceReplay {
    pub(crate) claim: EntityId,
    #[cfg(feature = "sync")]
    pub(crate) tombstones: Option<loro::LoroMap>,
}

impl ClaimSourceReplay {
    pub(crate) fn register_in_txn(
        &self,
        store: &Store,
        txn: &mut heed::RwTxn<'_>,
        body: &ClaimBody,
    ) -> Result<()> {
        let Some(evidence) = locator_evidence(body) else {
            return Ok(());
        };
        let citations = super::decode_verified_citations(evidence)
            .map_err(|_| Error::InvalidClaimBody("invalid verified consolidation locators"))?;
        let sources: std::collections::BTreeSet<_> = citations
            .into_iter()
            .flat_map(|(_, _, spans)| spans.into_iter().map(|span| span.message))
            .collect();
        if sources.is_empty() {
            return Ok(());
        }
        #[cfg(feature = "sync")]
        let tombstones = self
            .tombstones
            .as_ref()
            .map(oneiron_store::loro_tombstones::TombstoneIndex::build);
        #[cfg(feature = "sync")]
        let opened = crate::sync::residence::device_residence_opened_in_txn(store, txn)?;
        let mut withdrawn = false;
        let mut pending = false;
        for source in sources {
            if source == self.claim {
                return Err(Error::InvalidClaimBody(
                    "a CLAIM cannot cite itself as a MESSAGE",
                ));
            }
            #[cfg(feature = "sync")]
            let crdt_deleted = tombstones
                .as_ref()
                .is_some_and(|index| index.contains(&source));
            #[cfg(not(feature = "sync"))]
            let crdt_deleted = false;
            if crdt_deleted
                || crate::ports::source_deleted_or_withdrawn_in_txn(store, txn, &source)?
            {
                withdrawn = true;
                continue;
            }
            // As on the writer, a resident dependency is keyed by the MESSAGE
            // header's learned-at, not the locator's optional CRDT frontier.
            if store.entities().get(txn, source.as_bytes())?.is_some() {
                crate::ports::record_derived_edge_in_txn(store, txn, &self.claim, &source)?;
                continue;
            }
            #[cfg(feature = "sync")]
            if crate::ports::record_index_listed_dependency_in_txn(
                store,
                txn,
                &source,
                &self.claim,
            )? {
                continue;
            }
            // On an opened device an absent, unlisted, unmarked source lands the CLAIM readable
            // with no registration row: a cold source has no frontier, and a hard erase of it
            // never reaches an opened device (PR1-OPENED-COLD-SOURCE-MODE = A, 28 Nov).
            #[cfg(feature = "sync")]
            if opened
                && !crate::sync::residence::soft_drop_marker_exists_in_txn(
                    store,
                    txn,
                    &source.to_hex(),
                )?
            {
                continue;
            }
            pending = true;
        }
        if withdrawn {
            if !crate::ports::stale_in_txn(store, txn, &self.claim)? {
                let at = crate::ports::recorded_at_in_txn(store, txn)?;
                crate::ports::stage_stale_mark_in_txn(store, txn, &self.claim, at)?;
            }
        } else if pending {
            return Err(Error::InvalidClaimBody(CITED_SOURCE_PENDING));
        }
        Ok(())
    }
}
