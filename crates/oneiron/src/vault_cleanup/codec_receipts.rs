//! vault_meta row codecs and the digest receipt projector.

use super::{
    CLEANUP_PHASE, CleanupCandidate, CleanupDecision, CleanupDigest, CleanupKind, CleanupPosture,
    CleanupProposal, DIGEST_PREFIX, DIGEST_ROW_LABEL, DIGEST_SCHEMA_VERSION,
    FIELD_CLEANUP_ARCHIVED_COUNT, FIELD_CLEANUP_ARCHIVED_IDS, FIELD_CLEANUP_DECISION,
    FIELD_CLEANUP_PHASE, FIELD_CLEANUP_POSTURE, FIELD_CLEANUP_PROPOSAL,
    FIELD_CLEANUP_SKIPPED_COUNT, FIELD_CLEANUP_SKIPPED_IDS, FIELD_CLEANUP_TOMBSTONE_REASON,
    KEY_ARCHIVED, KEY_AT, KEY_ATTEMPT, KEY_CANDIDATES, KEY_CREATED_AT, KEY_DECISION, KEY_ENTITY,
    KEY_KIND, KEY_POSTURE, KEY_PROPOSAL, KEY_SCHEMA_VERSION, KEY_SKIPPED, PROPOSAL_PREFIX,
    PROPOSAL_ROW_LABEL, PROPOSAL_SCHEMA_VERSION, VAULT_CLEANUP_ACTOR, VAULT_CLEANUP_RECEIPT_PREFIX,
};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::deletion::DeleteReason;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::receipt::{
    MAX_RECEIPT_QUERY_SCAN, ReceiptKind, ReceiptQuery, ReceiptRecord, hex_lower,
    retain_newest_receipt,
};
use rmpv::Value;
use std::collections::BTreeMap;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Row codecs
// ---------------------------------------------------------------------------

pub(super) fn fresh_row_id() -> Result<EntityId> {
    EntityId::from_bytes(Uuid::now_v7().into_bytes())
}

pub(super) fn proposal_key(id: &EntityId) -> Vec<u8> {
    prefixed_key(PROPOSAL_PREFIX, id)
}

pub(super) fn digest_key(id: &EntityId) -> Vec<u8> {
    prefixed_key(DIGEST_PREFIX, id)
}

pub(super) fn prefixed_key(prefix: &[u8], id: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + ENTITY_ID_LEN);
    key.extend_from_slice(prefix);
    key.extend_from_slice(id.as_bytes());
    key
}

fn id_from_key(key: &[u8], prefix: &[u8], label: &'static str) -> Result<EntityId> {
    let tail = key
        .get(prefix.len()..)
        .ok_or(Error::CorruptedIndex(label))?
        .try_into()
        .map_err(|_| Error::CorruptedIndex(label))?;
    EntityId::from_bytes(tail).map_err(|_| Error::CorruptedIndex(label))
}

pub(super) fn encode_row(row: &Value, label: &'static str) -> Result<Vec<u8>> {
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, row).map_err(|_| Error::CorruptedIndex(label))?;
    Ok(encoded)
}

pub(super) fn decode_row(raw: &[u8], label: &'static str) -> Result<Vec<(Value, Value)>> {
    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(raw))
        .map_err(|_| Error::CorruptedIndex(label))?;
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err(Error::CorruptedIndex(label)),
    }
}

pub(super) fn field<'a>(entries: &'a [(Value, Value)], name: &str) -> Option<&'a Value> {
    entries
        .iter()
        .find(|(key, _)| key.as_str() == Some(name))
        .map(|(_, value)| value)
}

pub(super) fn id_list(
    entries: &[(Value, Value)],
    name: &str,
    label: &'static str,
) -> Result<Vec<EntityId>> {
    let Some(Value::Array(items)) = field(entries, name) else {
        return Err(Error::CorruptedIndex(label));
    };
    items
        .iter()
        .map(|item| {
            item.as_str()
                .and_then(|hex| EntityId::from_hex(hex).ok())
                .ok_or(Error::CorruptedIndex(label))
        })
        .collect()
}

pub(super) fn id_value_list(ids: &[EntityId]) -> Value {
    Value::Array(ids.iter().map(|id| Value::from(id.to_hex())).collect())
}

pub(super) fn put_proposal_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    proposal: &CleanupProposal,
) -> Result<()> {
    let row = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(PROPOSAL_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_ATTEMPT),
            Value::from(hex_lower(proposal.attempt.as_bytes())),
        ),
        (
            Value::from(KEY_CREATED_AT),
            Value::from(proposal.created_at),
        ),
        (
            Value::from(KEY_CANDIDATES),
            Value::Array(
                proposal
                    .candidates
                    .iter()
                    .map(|candidate| {
                        Value::Map(vec![
                            (
                                Value::from(KEY_ENTITY),
                                Value::from(candidate.entity.to_hex()),
                            ),
                            (Value::from(KEY_KIND), Value::from(candidate.kind.as_str())),
                        ])
                    })
                    .collect(),
            ),
        ),
    ]);
    let encoded = encode_row(&row, PROPOSAL_ROW_LABEL)?;
    vault
        .store
        .vault_meta
        .put(wtxn, &proposal_key(&proposal.id), &encoded)?;
    Ok(())
}

pub(super) fn decode_proposal(key: &[u8], raw: &[u8]) -> Result<CleanupProposal> {
    let id = id_from_key(key, PROPOSAL_PREFIX, PROPOSAL_ROW_LABEL)?;
    let entries = decode_row(raw, PROPOSAL_ROW_LABEL)?;
    if field(&entries, KEY_SCHEMA_VERSION).and_then(Value::as_u64) != Some(PROPOSAL_SCHEMA_VERSION)
    {
        return Err(Error::CorruptedIndex(PROPOSAL_ROW_LABEL));
    }
    let attempt = field(&entries, KEY_ATTEMPT)
        .and_then(Value::as_str)
        .and_then(hex_to_bytes_16)
        .ok_or(Error::CorruptedIndex(PROPOSAL_ROW_LABEL))?;
    let created_at = field(&entries, KEY_CREATED_AT)
        .and_then(Value::as_u64)
        .ok_or(Error::CorruptedIndex(PROPOSAL_ROW_LABEL))?;
    let Some(Value::Array(items)) = field(&entries, KEY_CANDIDATES) else {
        return Err(Error::CorruptedIndex(PROPOSAL_ROW_LABEL));
    };
    let mut candidates = Vec::with_capacity(items.len());
    for item in items {
        let Value::Map(fields) = item else {
            return Err(Error::CorruptedIndex(PROPOSAL_ROW_LABEL));
        };
        let entity = field(fields, KEY_ENTITY)
            .and_then(Value::as_str)
            .and_then(|hex| EntityId::from_hex(hex).ok())
            .ok_or(Error::CorruptedIndex(PROPOSAL_ROW_LABEL))?;
        let kind = field(fields, KEY_KIND)
            .and_then(Value::as_str)
            .and_then(CleanupKind::parse)
            .ok_or(Error::CorruptedIndex(PROPOSAL_ROW_LABEL))?;
        candidates.push(CleanupCandidate { entity, kind });
    }
    Ok(CleanupProposal {
        id,
        attempt: AttemptId::from_bytes(&attempt)?,
        created_at,
        candidates,
    })
}

pub(super) fn put_digest_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    digest: &CleanupDigest,
) -> Result<()> {
    let row = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DIGEST_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_ATTEMPT),
            digest.attempt.map_or(Value::Nil, |attempt| {
                Value::from(hex_lower(attempt.as_bytes()))
            }),
        ),
        (
            Value::from(KEY_PROPOSAL),
            digest
                .proposal
                .map_or(Value::Nil, |id| Value::from(id.to_hex())),
        ),
        (
            Value::from(KEY_DECISION),
            Value::from(digest.decision.as_str()),
        ),
        (
            Value::from(KEY_POSTURE),
            Value::from(digest.posture.as_str()),
        ),
        (Value::from(KEY_AT), Value::from(digest.at)),
        (Value::from(KEY_ARCHIVED), id_value_list(&digest.archived)),
        (Value::from(KEY_SKIPPED), id_value_list(&digest.skipped)),
    ]);
    let encoded = encode_row(&row, DIGEST_ROW_LABEL)?;
    vault
        .store
        .vault_meta
        .put(wtxn, &digest_key(&digest.id), &encoded)?;
    Ok(())
}

fn decode_digest(key: &[u8], raw: &[u8]) -> Result<CleanupDigest> {
    let id = id_from_key(key, DIGEST_PREFIX, DIGEST_ROW_LABEL)?;
    let entries = decode_row(raw, DIGEST_ROW_LABEL)?;
    if field(&entries, KEY_SCHEMA_VERSION).and_then(Value::as_u64) != Some(DIGEST_SCHEMA_VERSION) {
        return Err(Error::CorruptedIndex(DIGEST_ROW_LABEL));
    }
    let attempt = match field(&entries, KEY_ATTEMPT) {
        Some(Value::Nil) | None => None,
        Some(value) => Some(AttemptId::from_bytes(
            &value
                .as_str()
                .and_then(hex_to_bytes_16)
                .ok_or(Error::CorruptedIndex(DIGEST_ROW_LABEL))?,
        )?),
    };
    let proposal = match field(&entries, KEY_PROPOSAL) {
        Some(Value::Nil) | None => None,
        Some(value) => Some(
            value
                .as_str()
                .and_then(|hex| EntityId::from_hex(hex).ok())
                .ok_or(Error::CorruptedIndex(DIGEST_ROW_LABEL))?,
        ),
    };
    Ok(CleanupDigest {
        id,
        attempt,
        proposal,
        decision: field(&entries, KEY_DECISION)
            .and_then(Value::as_str)
            .and_then(CleanupDecision::parse)
            .ok_or(Error::CorruptedIndex(DIGEST_ROW_LABEL))?,
        posture: field(&entries, KEY_POSTURE)
            .and_then(Value::as_str)
            .and_then(CleanupPosture::parse)
            .ok_or(Error::CorruptedIndex(DIGEST_ROW_LABEL))?,
        at: field(&entries, KEY_AT)
            .and_then(Value::as_u64)
            .ok_or(Error::CorruptedIndex(DIGEST_ROW_LABEL))?,
        archived: id_list(&entries, KEY_ARCHIVED, DIGEST_ROW_LABEL)?,
        skipped: id_list(&entries, KEY_SKIPPED, DIGEST_ROW_LABEL)?,
    })
}

fn hex_to_bytes_16(hex: &str) -> Option<[u8; 16]> {
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0_u8; 16];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(hex.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Every cleanup decision this vault has recorded, in decision order.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an unreadable row.
pub fn cleanup_digests(vault: &Vault) -> Result<Vec<CleanupDigest>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut out = Vec::new();
    for row in vault.store.vault_meta.prefix_iter(&rtxn, DIGEST_PREFIX)? {
        let (key, raw) = row?;
        out.push(decode_digest(&key, &raw)?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Receipts (a projector in the `Gate` family)
// ---------------------------------------------------------------------------

/// Whether a receipt is a vault-cleanup run digest.
#[must_use]
pub fn is_vault_cleanup_receipt(record: &ReceiptRecord) -> bool {
    record.receipt_kind == ReceiptKind::Gate
        && record.receipt_id.starts_with(VAULT_CLEANUP_RECEIPT_PREFIX)
}

/// The exclusive upper bound of the digest keyspace.
fn digest_key_range_end() -> Vec<u8> {
    let mut end = DIGEST_PREFIX.to_vec();
    if let Some(last) = end.last_mut() {
        *last = last.saturating_add(1);
    }
    end
}

/// Projects the cleanup digest ledger as `Gate` receipts.
///
/// The cron's decision to archive IS a gate decision — the engine ruled on
/// rows it may remove from view — so it mints no receipt kind of its own,
/// following `consent_graduation::ramp_receipts`,
/// `edit_distance::escalation` and `skill_optimize`'s verdict projector down
/// to the discriminating id prefix. Opens its own read txn, as they do.
///
/// ONE receipt per DECISION, never one per entity: the ratified contracts row
/// pins `receipt: false` for the `archived_by_cleanup` tombstone, and this is
/// the job-level record that replaces it. The archived ids ride the digest's
/// fields, so the per-entity fact is still auditable without a per-entity
/// receipt.
///
/// Bounded like its siblings: digest keys are UUIDv7-ordered, so walking them
/// newest-first under [`MAX_RECEIPT_QUERY_SCAN`] spends the work bound on the
/// decisions a reader asked for.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an unreadable row.
pub(crate) fn cleanup_receipts(vault: &Vault, query: &ReceiptQuery) -> Result<Vec<ReceiptRecord>> {
    let rtxn = vault.store.env.read_txn()?;
    let end = digest_key_range_end();
    let bounds = (
        std::ops::Bound::Included(DIGEST_PREFIX),
        std::ops::Bound::Excluded(&end[..]),
    );
    let mut out = Vec::new();
    // One row PAST the cap is reached and never decoded: it is what separates
    // a ledger holding exactly the cap from one the cap truncated.
    for (scanned, row) in vault
        .store
        .vault_meta
        .rev_range(&rtxn, &bounds)?
        .take(MAX_RECEIPT_QUERY_SCAN + 1)
        .enumerate()
    {
        if scanned == MAX_RECEIPT_QUERY_SCAN {
            tracing::warn!(
                scan_cap = MAX_RECEIPT_QUERY_SCAN,
                "vault cleanup digest scan hit the receipt-family work cap; older runs were not \
                 projected"
            );
            break;
        }
        let (key, raw) = row?;
        let record = cleanup_digest_receipt(&decode_digest(&key, &raw)?);
        if !query.matches(&record) {
            continue;
        }
        if query.job_ref.is_some() {
            out.push(record);
        } else {
            retain_newest_receipt(&mut out, record, query.limit);
        }
    }
    Ok(out)
}

fn cleanup_digest_receipt(digest: &CleanupDigest) -> ReceiptRecord {
    let mut fields = BTreeMap::from([
        (FIELD_CLEANUP_PHASE.to_owned(), CLEANUP_PHASE.to_owned()),
        (
            FIELD_CLEANUP_DECISION.to_owned(),
            digest.decision.as_str().to_owned(),
        ),
        (
            FIELD_CLEANUP_POSTURE.to_owned(),
            digest.posture.as_str().to_owned(),
        ),
        (
            FIELD_CLEANUP_ARCHIVED_COUNT.to_owned(),
            digest.archived.len().to_string(),
        ),
        (
            FIELD_CLEANUP_SKIPPED_COUNT.to_owned(),
            digest.skipped.len().to_string(),
        ),
        (
            FIELD_CLEANUP_ARCHIVED_IDS.to_owned(),
            join_ids(&digest.archived),
        ),
        (
            FIELD_CLEANUP_SKIPPED_IDS.to_owned(),
            join_ids(&digest.skipped),
        ),
        (
            FIELD_CLEANUP_TOMBSTONE_REASON.to_owned(),
            DeleteReason::ArchivedByCleanup.as_str().to_owned(),
        ),
    ]);
    if let Some(proposal) = digest.proposal {
        fields.insert(FIELD_CLEANUP_PROPOSAL.to_owned(), proposal.to_hex());
    }
    ReceiptRecord {
        receipt_id: format!("{VAULT_CLEANUP_RECEIPT_PREFIX}{}", digest.id.to_hex()),
        receipt_kind: ReceiptKind::Gate,
        occurred_at: digest.at,
        actor: Some(VAULT_CLEANUP_ACTOR.to_owned()),
        on_behalf_of: None,
        outcome: digest.decision.as_str().to_owned(),
        job_ref: digest.attempt.map(|attempt| hex_lower(attempt.as_bytes())),
        trigger_ref: digest
            .proposal
            .map(|proposal| format!("vault_cleanup_proposal:{}", proposal.to_hex())),
        policy_trace: vec![format!("vault_cleanup.{}", digest.decision.as_str())],
        fields,
    }
}

fn join_ids(ids: &[EntityId]) -> String {
    ids.iter()
        .map(EntityId::to_hex)
        .collect::<Vec<_>>()
        .join(",")
}
