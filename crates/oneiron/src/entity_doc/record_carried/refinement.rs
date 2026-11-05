//! Exact first-Candidate bytes retained by the source revision ledger.
//!
//! A transported revision is data, not a local admission or native authority.

use heed::RoTxn;

use super::CarriedRecordDocument;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_doc::invalid;
use crate::error::Result;
use crate::vault::entity_revision::{
    ReadMode, RevisionRef, read_entity_revision_in_txn, revision_for_body_hash_in_txn,
};
use crate::{EntityId, Vault};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RefinementOriginSource {
    revision: RevisionRef,
    raw: Vec<u8>,
}

impl RefinementOriginSource {
    pub(super) fn capture_in_txn(
        vault: &Vault,
        txn: &RoTxn<'_>,
        entity: &EntityId,
        origin: Option<&[u8; 32]>,
    ) -> Result<Option<Self>> {
        let Some(origin) = origin else {
            return Ok(None);
        };
        let Some(revision) = revision_for_body_hash_in_txn(vault, txn, entity, origin)? else {
            return Ok(None);
        };
        // The pinned reader keeps its actual Generic/common namespace,
        // source withdrawal and erasure checks. It never substitutes live.
        let Some(raw) =
            read_entity_revision_in_txn(vault, txn, entity, ReadMode::Pinned(revision))?
        else {
            return Ok(None);
        };
        Self::from_bytes(revision, raw, origin).map(Some)
    }

    /// Reassembly checks the permanent hash and Candidate shape only. A
    /// recipient must still admit these bytes and their actual source.
    pub(crate) fn from_carried(
        record: &CarriedRecordDocument,
        revision: RevisionRef,
        raw: Vec<u8>,
    ) -> Result<Self> {
        let origin = record
            .refinement_origin()
            .ok_or_else(|| invalid("refinement source without origin"))?;
        Self::from_bytes(revision, raw, origin)
    }

    fn from_bytes(revision: RevisionRef, raw: Vec<u8>, origin: &[u8; 32]) -> Result<Self> {
        if EntityMetadataHeader::parse(&raw)
            .is_none_or(|header| header.entity_type != crate::registry::ENTITY_TYPE_SKILL)
        {
            return Err(invalid("refinement source kind"));
        }
        let body = &raw[ENTITY_METADATA_HEADER_LEN..];
        if blake3::hash(body).as_bytes() != origin {
            return Err(invalid("refinement source bytes"));
        }
        let record = crate::skill::decode_skill_record(body)?;
        if record.lifecycle_status != crate::skill::SkillLifecycle::Candidate
            || !crate::store::skill_refinement_origin::declares_skill_refinement(&record)
        {
            return Err(invalid("refinement source is not a first Candidate"));
        }
        Ok(Self { revision, raw })
    }

    pub(crate) fn revision(&self) -> RevisionRef {
        self.revision
    }

    pub(crate) fn raw(&self) -> &[u8] {
        &self.raw
    }
}
