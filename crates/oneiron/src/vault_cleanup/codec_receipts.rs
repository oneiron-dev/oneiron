//! Core half of `vault_cleanup::codec_receipts`: its store-layer items live in `oneiron_store::vault_cleanup::codec_receipts` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::vault_cleanup::codec_receipts::*;

use super::{
    CLEANUP_PHASE, CleanupCandidate, CleanupDecision, CleanupDigest, CleanupKind, CleanupPosture,
    CleanupProposal, DIGEST_ROW_LABEL, DIGEST_SCHEMA_VERSION, FIELD_CLEANUP_ARCHIVED_COUNT,
    FIELD_CLEANUP_ARCHIVED_IDS, FIELD_CLEANUP_DECISION, FIELD_CLEANUP_PHASE, FIELD_CLEANUP_POSTURE,
    FIELD_CLEANUP_PROPOSAL, FIELD_CLEANUP_REJECTED_COUNT, FIELD_CLEANUP_REJECTED_IDS,
    FIELD_CLEANUP_SKIPPED_COUNT, FIELD_CLEANUP_SKIPPED_IDS, FIELD_CLEANUP_TOMBSTONE_REASON,
    KEY_ARCHIVED, KEY_AT, KEY_ATTEMPT, KEY_CANDIDATES, KEY_CREATED_AT, KEY_DECISION, KEY_ENTITY,
    KEY_KIND, KEY_POSTURE, KEY_PROPOSAL, KEY_REJECTED, KEY_SCHEMA_VERSION, KEY_SKIPPED,
    PROPOSAL_ROW_LABEL, PROPOSAL_SCHEMA_VERSION, VAULT_CLEANUP_ACTOR, VAULT_CLEANUP_RECEIPT_PREFIX,
};
use crate::Vault;
use crate::deletion::DeleteReason;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::store::attempt_id::AttemptId;
use crate::store::receipt_row::{
    ReceiptKind, ReceiptQuery, ReceiptRecord, hex_lower, retain_newest_receipt,
};
use rmpv::Value;
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Row codecs
// ---------------------------------------------------------------------------

/// Open cleanup archive proposal awaiting owner accept/reject. Key: id16.
pub(super) const PROPOSAL: SideTable<EntityId, Vec<u8>, Raw> =
    SideTable::new(&side_table::VAULT_CLEANUP_PROPOSAL);

/// One recorded vault-cleanup decision. Key: id16.
pub(super) const DIGEST: SideTable<EntityId, Vec<u8>, Raw> =
    SideTable::new(&side_table::VAULT_CLEANUP_DIGEST);

pub(super) fn fresh_row_id(vault: &Vault) -> Result<EntityId> {
    vault.store.clock.entity_id()
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
                    .map(|candidate| candidate_value(candidate.as_ref()))
                    .collect(),
            ),
        ),
    ]);
    let encoded = encode_row(&row, PROPOSAL_ROW_LABEL)?;
    PROPOSAL.put(&vault.store, wtxn, &proposal.id, &encoded)?;
    // An open proposal is pending digest work too.
    crate::batch::queue_proactivity_change(vault, wtxn);
    Ok(())
}

pub(super) fn put_digest_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    digest: &CleanupDigest,
) -> Result<()> {
    let mut row = vec![
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
    ];
    // Only a mixed decision rejects: every other digest keeps its row shape.
    if !digest.rejected.is_empty() {
        row.push((Value::from(KEY_REJECTED), id_value_list(&digest.rejected)));
    }
    let encoded = encode_row(&Value::Map(row), DIGEST_ROW_LABEL)?;
    DIGEST.put(&vault.store, wtxn, &digest.id, &encoded)?;
    // The decision is pending digest work: the deadline re-reads after commit.
    crate::batch::queue_proactivity_change(vault, wtxn);
    Ok(())
}

/// Every cleanup decision this vault has recorded, in decision order.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an unreadable row.
pub fn cleanup_digests(vault: &Vault) -> Result<Vec<CleanupDigest>> {
    let rtxn = vault.store.env.read_txn()?;
    cleanup_digests_in_txn(vault, &rtxn)
}

/// [`cleanup_digests`] inside the caller's transaction: the proactivity
/// digest reads the decisions it reports in the snapshot it commits on.
pub(crate) fn cleanup_digests_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
) -> Result<Vec<CleanupDigest>> {
    DIGEST
        .scan(&vault.store, rtxn)?
        .into_iter()
        .map(|(id, raw)| decode_digest(id, &raw))
        .collect()
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
/// Digest keys are UUIDv7-ordered, so the walk reads them newest-first, the
/// whole ledger with no count cutting it short (FIX 3582); past its threshold
/// row it raises one check and reads on (rule 5).
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an unreadable row.
pub(crate) fn cleanup_receipts(vault: &Vault, query: &ReceiptQuery) -> Result<Vec<ReceiptRecord>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut count = crate::store::scan_count::ScanCount::start(
        &vault.store,
        &rtxn,
        crate::store::EngineScan::ReceiptSourceRows,
        b"vault_cleanup",
    )?;
    let mut out = Vec::new();
    for row in DIGEST.iter_rev_from(&vault.store, &rtxn, &[])? {
        count.row();
        let (id, raw) = row?;
        let record = cleanup_digest_receipt(&decode_digest(id, &raw)?);
        if !query.matches(&record) {
            continue;
        }
        if query.job_ref.is_some() {
            out.push(record);
        } else {
            retain_newest_receipt(&mut out, record, query.limit);
        }
    }
    count.finish(vault);
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
    if !digest.rejected.is_empty() {
        fields.insert(
            FIELD_CLEANUP_REJECTED_COUNT.to_owned(),
            digest.rejected.len().to_string(),
        );
        fields.insert(
            FIELD_CLEANUP_REJECTED_IDS.to_owned(),
            join_ids(&digest.rejected),
        );
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
