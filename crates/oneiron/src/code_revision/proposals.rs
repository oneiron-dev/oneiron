//! Durable stranded revisions against the new head; reconciliation is explicit.

use super::codec::{encode_value, entity_value, hash_from_value};
use super::types::{CodeRevisionFrontierRecord, CodeRevisionIntegrityRecord};
use super::{
    CodeRevision,
    codec::{decode_code_revision, encode_code_revision},
};
use crate::error::{ArtifactError, Error, Result};
use crate::store::Store;
use crate::{Vault, entity_id::EntityId};
use heed::{RoTxn, RwTxn};
use rmpv::Value;

const PREFIX: &[u8] = b"code_revision:proposal:v1:";

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
        for row in self.store.vault_meta.prefix_iter(&txn, PREFIX)? {
            let (key, raw) = row?;
            let proposal = decode(&raw)?;
            if key != proposal_key(&proposal.revision.revision_id) {
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
fn proposal_key(id: &EntityId) -> Vec<u8> {
    [PREFIX, id.as_bytes()].concat()
}

pub(super) fn load(
    store: &Store,
    txn: &RoTxn<'_>,
    revision_id: &EntityId,
) -> Result<Option<CodeRevisionProposal>> {
    let Some(raw) = store.vault_meta.get(txn, &proposal_key(revision_id))? else {
        return Ok(None);
    };
    let proposal = decode(&raw)?;
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
    let fields = Value::Map(vec![
        (
            Value::from("revision"),
            Value::Binary(encode_code_revision(revision)?),
        ),
        (
            Value::from("head_revision_id"),
            Value::Binary(head.revision_id.as_bytes().to_vec()),
        ),
        (
            Value::from("head_fold"),
            Value::Binary(head.revision_fold.to_vec()),
        ),
        (
            Value::from("proposed_fold"),
            Value::Binary(integrity.revision_fold.to_vec()),
        ),
        (
            Value::from("artifact_body"),
            Value::Binary(artifact_body.to_vec()),
        ),
    ]);
    store.vault_meta.put(
        txn,
        &proposal_key(&revision.revision_id),
        &encode_value(&fields, "stranded revision encode")?,
    )?;
    Ok(proposal)
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
