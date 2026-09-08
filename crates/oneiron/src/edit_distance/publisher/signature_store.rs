//! Stored signature rows: codec and vault_meta keys.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::signature::is_content_hash;
use super::{CountKey, IssueCategory, IssueSignature, PublisherResult, put_meta};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

const SIGNATURE_KEY_PREFIX: &[u8] = b"edit_distance/issue_signature/v1\0";

const SEND_STATE_KEY_PREFIX: &[u8] = b"edit_distance/issue_signature_send/v1\0";

/// On-disk shape of a stored signature.
///
/// Separate from [`IssueSignature`] on purpose: deriving `Deserialize` on the
/// public type would hand every caller a second constructor that skips every
/// check `new` makes. Readback re-validates the closed vocabularies and the
/// hash shape through [`IssueSignature`]'s own invariants below.
#[derive(Serialize, Deserialize)]
struct SignatureRow {
    schema_version: u8,
    category: String,
    artifact: String,
    version: u32,
    model_id: String,
    counts: BTreeMap<String, u32>,
    content_hash: String,
}

const SIGNATURE_SCHEMA_VERSION: u8 = 1;

fn corrupt() -> Error {
    Error::CorruptedIndex("issue signature record")
}

pub(super) fn signature_key(id: EntityId) -> Vec<u8> {
    let mut key = SIGNATURE_KEY_PREFIX.to_vec();
    key.extend_from_slice(id.as_bytes());
    key
}

pub(super) fn send_state_key(id: EntityId) -> Vec<u8> {
    let mut key = SEND_STATE_KEY_PREFIX.to_vec();
    key.extend_from_slice(id.as_bytes());
    key
}

fn encode_signature(sig: &IssueSignature) -> Result<Vec<u8>> {
    let row = SignatureRow {
        schema_version: SIGNATURE_SCHEMA_VERSION,
        category: sig.category.as_str().to_owned(),
        artifact: sig.artifact.to_hex(),
        version: sig.version,
        model_id: sig.model_id.as_str().to_owned(),
        counts: sig
            .counts
            .iter()
            .map(|(key, value)| (key.as_str().to_owned(), *value))
            .collect(),
        content_hash: sig.content_hash.clone(),
    };
    crate::llm::canonical_json_bytes(&row)
        .map_err(|_| Error::InvariantViolation("issue signature encode"))
}

fn decode_signature(bytes: &[u8]) -> Result<IssueSignature> {
    let row: SignatureRow = serde_json::from_slice(bytes).map_err(|_| corrupt())?;
    if row.schema_version != SIGNATURE_SCHEMA_VERSION || !is_content_hash(&row.content_hash) {
        return Err(corrupt());
    }
    let mut counts = BTreeMap::new();
    for (key, value) in row.counts {
        let key = CountKey::parse(&key).ok_or_else(corrupt)?;
        if counts.insert(key, value).is_some() {
            return Err(corrupt());
        }
    }
    Ok(IssueSignature {
        category: IssueCategory::parse(&row.category).ok_or_else(corrupt)?,
        artifact: EntityId::from_hex(&row.artifact).map_err(|_| corrupt())?,
        version: row.version,
        model_id: row.model_id.parse().map_err(|_| corrupt())?,
        counts,
        content_hash: row.content_hash,
    })
}

/// Stores a signature and returns the id it landed under.
///
/// # Errors
///
/// Storage errors.
pub fn emit_issue_signature(vault: &Vault, sig: IssueSignature) -> PublisherResult<EntityId> {
    let id = EntityId::now();
    let value = encode_signature(&sig)?;
    put_meta(vault, &signature_key(id), &value)?;
    Ok(id)
}

/// Reads back the signature stored under `id`.
///
/// # Errors
///
/// Storage errors, and [`Error::CorruptedIndex`] on a row this engine did not
/// write.
pub fn issue_signature(vault: &Vault, id: EntityId) -> PublisherResult<Option<IssueSignature>> {
    let rtxn = vault.store.env.read_txn().map_err(Error::from)?;
    let Some(raw) = vault.store.vault_meta.get(&rtxn, &signature_key(id))? else {
        return Ok(None);
    };
    Ok(Some(decode_signature(&raw)?))
}
