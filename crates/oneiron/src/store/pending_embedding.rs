//! Pending-embedding marker rows gating vector writes: encode/decode,
//! mark/clear, and token checks.

use heed::{RoTxn, RwTxn};
use sha2::{Digest, Sha256};

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN};
use crate::side_table::{self, HexId, Raw, SideTable};

use super::*;

/// Kept only for `Store::pending_embedding_marker_key` below: production
/// reads/writes go through the typed [`MARKERS`] table, but
/// `origin::smart_http::landing_tests` and `batch::tests::support` still spell
/// the raw `sync_state` key directly to seed fixtures.
#[cfg(test)]
const PENDING_EMBEDDING_MARKER_PREFIX: &str = "pe:";

const PENDING_EMBEDDING_MARKER_VERSION: u8 = 2;

/// The version of a marker sealed for the vault's derivation owner.
const SEALED_PENDING_EMBEDDING_MARKER_VERSION: u8 = 3;

const PENDING_EMBEDDING_MARKER_TOKEN_LEN: usize = 1 + 32;

pub(super) const ENTITY_BODY_OFFSET: usize = 25;

/// Typed door for the `pe:` marker family. The value stays `Vec<u8>`: every
/// reader compares the stored bytes against a freshly computed token rather
/// than decoding fields, and a marker of the "wrong" length (a stale test
/// fixture, or truly ancient data) must read back as present-but-not-current,
/// never as a corrupt row.
const MARKERS: SideTable<HexId, Vec<u8>, Raw> =
    SideTable::new(&side_table::PENDING_EMBEDDING_MARKER);

impl Store {
    #[cfg(test)]
    pub(crate) fn pending_embedding_marker_key(id: &EntityId) -> String {
        format!("{PENDING_EMBEDDING_MARKER_PREFIX}{}", id.to_hex())
    }

    pub(crate) fn pending_embedding_marker_token(
        epoch: u64,
        claim_body: &[u8],
    ) -> [u8; PENDING_EMBEDDING_MARKER_TOKEN_LEN] {
        let mut hasher = Sha256::new();
        hasher.update(epoch.to_le_bytes());
        hasher.update(claim_body);
        let digest = hasher.finalize();
        let mut token = [0_u8; PENDING_EMBEDDING_MARKER_TOKEN_LEN];
        token[0] = PENDING_EMBEDDING_MARKER_VERSION;
        token[1..].copy_from_slice(&digest);
        token
    }

    fn scoped_embedding_token(
        epoch: u64,
        body: &[u8],
        owner: Option<crate::federation::derivation::DerivationOwner>,
    ) -> [u8; PENDING_EMBEDDING_MARKER_TOKEN_LEN] {
        let Some(owner) = owner else {
            return Self::pending_embedding_marker_token(epoch, body);
        };
        let digest = crate::federation::derivation::sealed_digest(
            owner,
            crate::federation::derivation::DerivationKind::Embedding,
            &epoch.to_be_bytes(),
            body,
        );
        let mut token = [0; PENDING_EMBEDDING_MARKER_TOKEN_LEN];
        token[0] = SEALED_PENDING_EMBEDDING_MARKER_VERSION;
        token[1..].copy_from_slice(&digest);
        token
    }
    fn pending_marker_is_current(
        marker: &[u8],
        epoch: u64,
        claim_body: &[u8],
        owner: Option<crate::federation::derivation::DerivationOwner>,
    ) -> bool {
        // A v1 body-only marker cannot prove which embedding-model epoch
        // produced its vector, even when the vault has no derivation owner.
        marker == Self::scoped_embedding_token(epoch, claim_body, owner)
    }

    pub(crate) fn mark_pending_embedding(
        &self,
        wtxn: &mut RwTxn<'_>,
        id: &EntityId,
        claim_body: &[u8],
    ) -> Result<Vec<u8>> {
        let epoch = crate::hnsw::read_embedding_model_epoch(self, &*wtxn)?;
        let owner = crate::federation::derivation::owner_in_txn(self, wtxn)?;
        let token = Self::scoped_embedding_token(epoch, claim_body, owner);
        MARKERS.put(self, wtxn, &HexId(*id), &token.to_vec())?;
        Ok(token.to_vec())
    }

    /// Reseal already queued work during the first account binding. Historical
    /// or stale tokens stay stale; only work current before the binding moves.
    ///
    /// A TURN's marker commits to its messages' text, which the store cannot
    /// read, so it is sealed over the marker itself: a fill leased before the
    /// binding no longer equals it, and the worker leases the turn again and
    /// marks it at its text under the owner.
    pub(crate) fn seal_pending_embeddings_for_owner(
        &self,
        wtxn: &mut RwTxn<'_>,
        owner: crate::federation::derivation::DerivationOwner,
    ) -> Result<()> {
        let epoch = crate::hnsw::read_embedding_model_epoch(self, wtxn)?;
        let pending = MARKERS.scan(self, &*wtxn)?;
        for (HexId(id), marker) in pending {
            let Some(record) = self.entities.get(&*wtxn, id.as_bytes())? else {
                continue;
            };
            let token = if is_turn_record(&record) {
                if !self.marker_is_current_for_record(&marker, &record, epoch, None) {
                    continue;
                }
                Self::scoped_embedding_token(epoch, &marker, Some(owner))
            } else {
                let Some(body) = self.embeddable_body_from_record(&record) else {
                    continue;
                };
                if !Self::pending_marker_is_current(&marker, epoch, body, None) {
                    continue;
                }
                Self::scoped_embedding_token(epoch, body, Some(owner))
            };
            MARKERS.put(self, wtxn, &HexId(id), &token.to_vec())?;
        }
        Ok(())
    }

    pub(crate) fn clear_pending_embedding(
        &self,
        wtxn: &mut RwTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        MARKERS.delete(self, wtxn, &HexId(*id))
    }

    pub(crate) fn clear_pending_embedding_if_token_matches(
        &self,
        wtxn: &mut RwTxn<'_>,
        id: &EntityId,
        token: &[u8],
    ) -> Result<bool> {
        if !self.pending_embedding_matches_in_txn(wtxn, id, token)? {
            return Ok(false);
        }
        self.clear_pending_embedding(wtxn, id)
    }

    pub(crate) fn pending_embedding_token(
        &self,
        rtxn: &RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<Vec<u8>>> {
        let Some(marker) = MARKERS.get(self, rtxn, &HexId(*id))? else {
            return Ok(None);
        };
        let Some(record) = self.entities.get(rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        let epoch = crate::hnsw::read_embedding_model_epoch(self, rtxn)?;
        let owner = crate::federation::derivation::owner_in_txn(self, rtxn)?;
        Ok(self
            .marker_is_current_for_record(&marker, &record, epoch, owner)
            .then(|| marker.to_vec()))
    }

    #[cfg(feature = "sync")]
    pub(crate) fn pending_embedding_token_in_txn(
        &self,
        wtxn: &RwTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<Vec<u8>>> {
        let Some(marker) = MARKERS.get(self, wtxn, &HexId(*id))? else {
            return Ok(None);
        };
        let Some(record) = self.entities.get(wtxn, id.as_bytes())? else {
            return Ok(None);
        };
        let epoch = crate::hnsw::read_embedding_model_epoch(self, wtxn)?;
        let owner = crate::federation::derivation::owner_in_txn(self, wtxn)?;
        Ok(self
            .marker_is_current_for_record(&marker, &record, epoch, owner)
            .then(|| marker.to_vec()))
    }

    pub(crate) fn has_current_pending_embedding_in_txn(
        &self,
        wtxn: &RwTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        let Some(marker) = MARKERS.get(self, wtxn, &HexId(*id))? else {
            return Ok(false);
        };
        let Some(record) = self.entities.get(wtxn, id.as_bytes())? else {
            return Ok(false);
        };
        let epoch = crate::hnsw::read_embedding_model_epoch(self, wtxn)?;
        let owner = crate::federation::derivation::owner_in_txn(self, wtxn)?;
        Ok(self.marker_is_current_for_record(&marker, &record, epoch, owner))
    }

    pub(crate) fn pending_embedding_matches_in_txn(
        &self,
        wtxn: &RwTxn<'_>,
        id: &EntityId,
        token: &[u8],
    ) -> Result<bool> {
        let Some(marker) = MARKERS.get(self, wtxn, &HexId(*id))? else {
            return Ok(false);
        };
        if *marker != *token {
            return Ok(false);
        }
        let Some(record) = self.entities.get(wtxn, id.as_bytes())? else {
            return Ok(false);
        };
        let epoch = crate::hnsw::read_embedding_model_epoch(self, wtxn)?;
        let owner = crate::federation::derivation::owner_in_txn(self, wtxn)?;
        Ok(self.marker_is_current_for_record(&marker, &record, epoch, owner))
    }

    /// Whether a record's marker is the one its current text would mark.
    ///
    /// A TURN's marker commits to its messages' text, which this store-level
    /// check cannot read: the turn doors re-mark the turn whenever that text
    /// moves (`embed::mark_turn_in_txn`) and the worker re-marks it from the
    /// text it leases, so the marker they last wrote is the current one and a
    /// fill for older text no longer equals it. An embedding-space swap marks
    /// every turn again, and the first owner binding seals each turn's marker
    /// anew ([`Self::seal_pending_embeddings_for_owner`]). Only a marker of
    /// the vault's owner state counts, so none written before the binding is
    /// current after it.
    fn marker_is_current_for_record(
        &self,
        marker: &[u8],
        record: &[u8],
        epoch: u64,
        owner: Option<crate::federation::derivation::DerivationOwner>,
    ) -> bool {
        if is_turn_record(record) {
            let version = match owner {
                Some(_) => SEALED_PENDING_EMBEDDING_MARKER_VERSION,
                None => PENDING_EMBEDDING_MARKER_VERSION,
            };
            return marker.len() == PENDING_EMBEDDING_MARKER_TOKEN_LEN && marker[0] == version;
        }
        self.embeddable_body_from_record(record)
            .is_some_and(|body| Self::pending_marker_is_current(marker, epoch, body, owner))
    }

    /// The embeddable body of a base record, or `None` when the row carries no
    /// vector-bearing body.
    ///
    /// Every marker reader above funnels through here, and the token is computed
    /// over exactly the bytes this returns, so the accepted type set IS the set
    /// of rows whose marker can be matched, cleared, or turned into embed work.
    /// RT-05 (ONE-1687) adds SUMMARY: while this refused it, the epoch-summary
    /// keyframe's mint-time marker was durably unreadable and leaked.
    fn embeddable_body_from_record<'a>(&self, record: &'a [u8]) -> Option<&'a [u8]> {
        if record.len() <= ENTITY_BODY_OFFSET {
            return None;
        }
        if record[0] != ENTITY_TYPE_CLAIM && record[0] != ENTITY_TYPE_SUMMARY {
            return None;
        }
        let body = &record[ENTITY_BODY_OFFSET..];
        (!body.is_empty()).then_some(body)
    }
}

/// A TURN record that is not an erased shell: its marker commits to its
/// messages' text, not to its own body.
fn is_turn_record(record: &[u8]) -> bool {
    record.len() > ENTITY_BODY_OFFSET && record[0] == ENTITY_TYPE_TURN
}
