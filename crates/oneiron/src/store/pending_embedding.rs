//! Pending-embedding marker rows gating vector writes: encode/decode,
//! mark/clear, and token checks.

use std::str;

use heed::{RoTxn, RwTxn};
use sha2::{Digest, Sha256};

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_SUMMARY};

use super::*;

const PENDING_EMBEDDING_MARKER_PREFIX: &str = "pe:";

const PENDING_EMBEDDING_MARKER_VERSION: u8 = 2;

const PENDING_EMBEDDING_MARKER_TOKEN_LEN: usize = 1 + 32;

pub(super) const ENTITY_BODY_OFFSET: usize = 25;

impl Store {
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

    fn legacy_pending_embedding_marker_token(
        claim_body: &[u8],
    ) -> [u8; PENDING_EMBEDDING_MARKER_TOKEN_LEN] {
        let digest = Sha256::digest(claim_body);
        let mut token = [0_u8; PENDING_EMBEDDING_MARKER_TOKEN_LEN];
        token[0] = 1;
        token[1..].copy_from_slice(&digest);
        token
    }

    fn pending_marker_is_current(marker: &[u8], epoch: u64, claim_body: &[u8]) -> bool {
        marker == Self::pending_embedding_marker_token(epoch, claim_body)
            || (marker.len() == PENDING_EMBEDDING_MARKER_TOKEN_LEN
                && marker[0] == 1
                && marker == Self::legacy_pending_embedding_marker_token(claim_body))
    }

    pub(crate) fn mark_pending_embedding(
        &self,
        wtxn: &mut RwTxn<'_>,
        id: &EntityId,
        claim_body: &[u8],
    ) -> Result<Vec<u8>> {
        let key = Self::pending_embedding_marker_key(id);
        let epoch = crate::hnsw::read_embedding_model_epoch(self, &*wtxn)?;
        let token = Self::pending_embedding_marker_token(epoch, claim_body);
        self.sync_state.put(wtxn, key.as_str(), token.as_slice())?;
        Ok(token.to_vec())
    }

    pub(crate) fn clear_pending_embedding(
        &self,
        wtxn: &mut RwTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        let key = Self::pending_embedding_marker_key(id);
        self.sync_state.delete(wtxn, key.as_str())
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
        let key = Self::pending_embedding_marker_key(id);
        let Some(marker) = self.sync_state.get(rtxn, key.as_str())? else {
            return Ok(None);
        };
        let Some(record) = self.entities.get(rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        let epoch = crate::hnsw::read_embedding_model_epoch(self, rtxn)?;
        Ok(self
            .embeddable_body_from_record(&record)
            .filter(|body| Self::pending_marker_is_current(&marker, epoch, body))
            .map(|_| marker.to_vec()))
    }

    #[cfg(feature = "sync")]
    pub(crate) fn pending_embedding_token_in_txn(
        &self,
        wtxn: &RwTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<Vec<u8>>> {
        let key = Self::pending_embedding_marker_key(id);
        let Some(marker) = self.sync_state.get(wtxn, key.as_str())? else {
            return Ok(None);
        };
        let Some(record) = self.entities.get(wtxn, id.as_bytes())? else {
            return Ok(None);
        };
        let epoch = crate::hnsw::read_embedding_model_epoch(self, wtxn)?;
        Ok(self
            .embeddable_body_from_record(&record)
            .filter(|body| Self::pending_marker_is_current(&marker, epoch, body))
            .map(|_| marker.to_vec()))
    }

    pub(crate) fn has_current_pending_embedding_in_txn(
        &self,
        wtxn: &RwTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        let key = Self::pending_embedding_marker_key(id);
        let Some(marker) = self.sync_state.get(wtxn, key.as_str())? else {
            return Ok(false);
        };
        let Some(record) = self.entities.get(wtxn, id.as_bytes())? else {
            return Ok(false);
        };
        let epoch = crate::hnsw::read_embedding_model_epoch(self, wtxn)?;
        Ok(self
            .embeddable_body_from_record(&record)
            .is_some_and(|body| Self::pending_marker_is_current(&marker, epoch, body)))
    }

    pub(crate) fn pending_embedding_matches_in_txn(
        &self,
        wtxn: &RwTxn<'_>,
        id: &EntityId,
        token: &[u8],
    ) -> Result<bool> {
        let key = Self::pending_embedding_marker_key(id);
        let Some(marker) = self.sync_state.get(wtxn, key.as_str())? else {
            return Ok(false);
        };
        if *marker != *token {
            return Ok(false);
        }
        let Some(record) = self.entities.get(wtxn, id.as_bytes())? else {
            return Ok(false);
        };
        let epoch = crate::hnsw::read_embedding_model_epoch(self, wtxn)?;
        Ok(self
            .embeddable_body_from_record(&record)
            .is_some_and(|body| Self::pending_marker_is_current(&marker, epoch, body)))
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
