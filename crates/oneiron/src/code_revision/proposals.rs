//! Durable stranded revisions against the new head; reconciliation is explicit.

use super::codec::{encode_value, entity_value, hash_from_value};
use super::types::{CodeRevisionFrontierRecord, CodeRevisionIntegrityRecord};
use super::{
    CodeRevision,
    codec::{decode_code_revision, encode_code_revision},
};
use crate::error::{ArtifactError, Error, Result};
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::store::Store;
use crate::{Vault, entity_id::EntityId};
use heed::{RoTxn, RwTxn};
use rmpv::Value;

/// Stranded/diverged revision proposal awaiting reconciliation with the head. Key: revision id.
const PROPOSALS: SideTable<EntityId, CodeRevisionProposal, Raw> =
    SideTable::new(&side_table::CODE_REVISION_PROPOSAL);

/// The row is its own pinned hand-rolled MessagePack layout: the side table stores exactly the
/// bytes [`encode_proposal`] spells, and any decode failure surfaces through the SAME
/// `invalid()` error this codec has always returned (a crate [`Error`] round-trips through
/// [`side_table::CodecError::Value`] unchanged).
impl RawValue for CodeRevisionProposal {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode_proposal(self)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(decode(bytes)?)
    }
}

/// A frontier conflict does not finalize or rebase the submitted revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeRevisionWriteOutcome {
    Finalized,
    Proposed(Box<CodeRevisionProposal>),
}

/// Complete stranded revision plus the verified head it must reconcile with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeRevisionProposal {
    pub revision: CodeRevision,
    pub head_revision_id: EntityId,
    pub head_fold: [u8; 32],
    pub proposed_fold: [u8; 32],
    pub artifact_body: Vec<u8>,
}

impl Vault {
    pub fn code_revision_proposal(
        &self,
        revision_id: &EntityId,
    ) -> Result<Option<CodeRevisionProposal>> {
        let txn = self.store.env.read_txn()?;
        load(&self.store, &txn, revision_id)
    }

    pub fn code_revision_proposals(
        &self,
        session_id: &EntityId,
    ) -> Result<Vec<CodeRevisionProposal>> {
        let txn = self.store.env.read_txn()?;
        let mut proposals = Vec::new();
        for (key, proposal) in PROPOSALS.scan(&self.store, &txn)? {
            if key != proposal.revision.revision_id {
                return Err(invalid());
            }
            verify(&self.store, &txn, &proposal)?;
            if proposal.revision.session_id == *session_id {
                proposals.push(proposal);
            }
        }
        proposals.sort_by_key(|p| (p.revision.finalized_at, p.revision.revision_id));
        Ok(proposals)
    }
}

fn invalid() -> Error {
    Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
        "invalid stranded revision proposal",
    ))
}

pub(super) fn load(
    store: &Store,
    txn: &RoTxn<'_>,
    revision_id: &EntityId,
) -> Result<Option<CodeRevisionProposal>> {
    let Some(proposal) = PROPOSALS.get(store, txn, revision_id)? else {
        return Ok(None);
    };
    if proposal.revision.revision_id != *revision_id {
        return Err(invalid());
    }
    verify(store, txn, &proposal)?;
    Ok(Some(proposal))
}

pub(super) fn retain(
    store: &Store,
    txn: &mut RwTxn<'_>,
    revision: &CodeRevision,
    head: &CodeRevisionFrontierRecord,
    integrity: &CodeRevisionIntegrityRecord,
    artifact_body: &[u8],
) -> Result<CodeRevisionProposal> {
    let proposal = CodeRevisionProposal {
        revision: revision.clone(),
        head_revision_id: head.revision_id,
        head_fold: head.revision_fold,
        proposed_fold: integrity.revision_fold,
        artifact_body: artifact_body.to_vec(),
    };
    PROPOSALS.put(store, txn, &proposal.revision.revision_id, &proposal)?;
    Ok(proposal)
}

fn encode_proposal(proposal: &CodeRevisionProposal) -> Result<Vec<u8>> {
    let fields = Value::Map(vec![
        (
            Value::from("revision"),
            Value::Binary(encode_code_revision(&proposal.revision)?),
        ),
        (
            Value::from("head_revision_id"),
            Value::Binary(proposal.head_revision_id.as_bytes().to_vec()),
        ),
        (
            Value::from("head_fold"),
            Value::Binary(proposal.head_fold.to_vec()),
        ),
        (
            Value::from("proposed_fold"),
            Value::Binary(proposal.proposed_fold.to_vec()),
        ),
        (
            Value::from("artifact_body"),
            Value::Binary(proposal.artifact_body.clone()),
        ),
    ]);
    encode_value(&fields, "stranded revision encode")
}

fn decode(raw: &[u8]) -> Result<CodeRevisionProposal> {
    let mut cursor = raw;
    let Value::Map(fields) = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid())? else {
        return Err(invalid());
    };
    let names = [
        "revision",
        "head_revision_id",
        "head_fold",
        "proposed_fold",
        "artifact_body",
    ];
    if !cursor.is_empty()
        || fields.len() != names.len()
        || names.iter().any(|name| {
            fields
                .iter()
                .filter(|(k, _)| k.as_str() == Some(name))
                .count()
                != 1
        })
    {
        return Err(invalid());
    }
    let field = |name: &str| {
        fields
            .iter()
            .find(|(k, _)| k.as_str() == Some(name))
            .map(|(_, v)| v)
            .ok_or_else(invalid)
    };
    let Value::Binary(revision) = field("revision")? else {
        return Err(invalid());
    };
    let Value::Binary(body) = field("artifact_body")? else {
        return Err(invalid());
    };
    Ok(CodeRevisionProposal {
        revision: decode_code_revision(revision)?,
        head_revision_id: entity_value(field("head_revision_id")?, "head_revision_id")?,
        head_fold: hash_from_value(field("head_fold")?, "head_fold")?,
        proposed_fold: hash_from_value(field("proposed_fold")?, "proposed_fold")?,
        artifact_body: body.clone(),
    })
}

fn verify(store: &Store, txn: &RoTxn<'_>, proposal: &CodeRevisionProposal) -> Result<()> {
    let integrity = super::integrity::build_code_revision_integrity_record(
        store,
        txn,
        &proposal.revision,
        &proposal.artifact_body,
    )?;
    let head = super::storage::get_code_revision_in_txn(store, txn, &proposal.head_revision_id)?
        .ok_or_else(invalid)?;
    let mut visiting = std::collections::HashSet::new();
    let head_integrity = super::integrity::verify_or_build_code_revision_integrity_record_in_txn(
        store,
        txn,
        &head,
        &mut visiting,
    )?;
    if integrity.revision_fold != proposal.proposed_fold
        || head_integrity.revision_fold != proposal.head_fold
        || head.session_id != proposal.revision.session_id
    {
        return Err(invalid());
    }
    Ok(())
}
