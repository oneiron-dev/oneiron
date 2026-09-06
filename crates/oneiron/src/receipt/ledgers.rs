use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::field_set::append_pack_manifest_fields;
#[cfg(test)]
use super::kernel::ATTEMPT_PACK_SCAN_CAPPED;
use super::kernel::{
    FIELD_AUDIT_REGISTER, FIELD_CARE_REGISTER, FIELD_ENGINE_REGISTER, FIELD_INTENT_REF,
    FIELD_RECEIPT_SCHEMA, FIELD_TASK_REF, FIELD_TRANSPORT_DISPATCHED, MAX_RECEIPT_QUERY_SCAN,
    ReceiptKind, ReceiptRecord, hex_lower,
};
use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptRecord};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::outbound::OutboundIntent;
use crate::store::{SEND_RECEIPT_RECORD_VERSION, Store};

/// `vault_meta` keyspace of the attempt PACK RECEIPT ledger. The suffix is the
/// receipt id itself, so a cited `receipt_ref` point-reads its row.
const ATTEMPT_PACK_RECEIPT_KEY_PREFIX: &[u8] = b"attempt_receipt:v1:";
/// `receipt_id` namespace of the same ledger.
const ATTEMPT_PACK_RECEIPT_ID_PREFIX: &str = "attempt:";

const OUTBOUND_RECEIPT_SCHEMA: &str = "outbound_receipt.v1";
const OUTBOUND_ENGINE_REGISTER: &str = "neutral";
const OUTBOUND_CARE_REGISTER: &str = "eirispec_care_register";
const OUTBOUND_AUDIT_REGISTER: &str = "dashboard_atom_kit_audit";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct DurableSendReceipt {
    version: u8,
    task_ref: String,
    outcome: SendReceiptOutcome,
    transport_dispatched: bool,
    receipt: ReceiptRecord,
}

// ONE-1690 closes the known interim double-authority window: ledger rows are
// the resend authority; send receipts are required-outcome audit narrative.

/// Delivery state carried by the additive connector-send receipt ledger.
/// Failed transport audit rows remain visible but are not idempotency tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SendReceiptOutcome {
    Delivered,
    Failed,
}

/// The stable `receipt_id` of one attempt's terminal PACK RECEIPT.
///
/// Attribution evidence cites this string, and the ledger is keyed by it, so
/// a cited `receipt_ref` resolves with a point-read rather than a scan.
#[must_use]
pub fn attempt_pack_receipt_id(attempt_id: &AttemptId) -> String {
    format!(
        "{ATTEMPT_PACK_RECEIPT_ID_PREFIX}{}",
        hex_lower(attempt_id.as_bytes())
    )
}

fn attempt_pack_receipt_key(receipt_id: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(ATTEMPT_PACK_RECEIPT_KEY_PREFIX.len() + receipt_id.len());
    key.extend_from_slice(ATTEMPT_PACK_RECEIPT_KEY_PREFIX);
    key.extend_from_slice(receipt_id.as_bytes());
    key
}

/// Stamps the terminal pack receipt for an attempt that ran underneath a
/// skill pack, inside the terminal transition's OWN write transaction.
///
/// This is the production call path for [`append_pack_manifest_fields`]:
/// [`AttemptQueue::complete`] and [`AttemptQueue::fail`] are the two doors
/// every execute leaves through, so stamping there cannot be forgotten by a
/// caller and cannot drift per lane. An attempt whose pack loaded nothing
/// mints no row — the manifest IS the reason this receipt exists.
///
/// Atomic with the state seal: a terminal attempt with a manifest and no
/// receipt (or the reverse) is not a reachable state. The row is written
/// once, at the transition, and never rewritten — which is what makes
/// "a closed attempt's manifest is the evidence its receipt already
/// projected" true rather than aspirational.
///
/// [`AttemptQueue::complete`]: crate::attempt_queue::AttemptQueue::complete
/// [`AttemptQueue::fail`]: crate::attempt_queue::AttemptQueue::fail
pub(crate) fn stamp_attempt_pack_receipt_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    record: &AttemptRecord,
    actor: &str,
) -> Result<()> {
    if record.manifest().is_empty() {
        return Ok(());
    }
    let mut receipt = ReceiptRecord {
        receipt_id: attempt_pack_receipt_id(&record.id),
        receipt_kind: ReceiptKind::Outbound,
        occurred_at: record.updated_at,
        actor: Some(actor.to_owned()),
        on_behalf_of: None,
        outcome: record.state.as_str().to_owned(),
        job_ref: record.run_id.clone(),
        trigger_ref: record.task_ref.clone(),
        policy_trace: Vec::new(),
        fields: BTreeMap::new(),
    };
    append_pack_manifest_fields(&mut receipt, record.manifest())?;
    let encoded = rmp_serde::to_vec_named(&receipt)
        .map_err(|_| Error::InvariantViolation("attempt pack receipt encode failed"))?;
    store.vault_meta.put(
        wtxn,
        &attempt_pack_receipt_key(&receipt.receipt_id),
        &encoded,
    )?;
    Ok(())
}

/// Point-reads the attempt pack receipt named by `receipt_id`.
///
/// `Ok(None)` means "no such receipt on the ledger" — the answer attribution
/// needs to reject a fabricated `receipt_ref`, and the reason this is a
/// point-read: it runs once per recorded outcome.
pub fn attempt_pack_receipt(vault: &Vault, receipt_id: &str) -> Result<Option<ReceiptRecord>> {
    if !receipt_id.starts_with(ATTEMPT_PACK_RECEIPT_ID_PREFIX) {
        return Ok(None);
    }
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault
        .store
        .vault_meta
        .get(&rtxn, &attempt_pack_receipt_key(receipt_id))?
    else {
        return Ok(None);
    };
    decode_attempt_pack_receipt(&raw).map(Some)
}

/// Overwrites one row of the pack receipt ledger.
///
/// Test-only by construction: production stamps exactly once, at the terminal
/// transition, and never rewrites. Tests use it to synthesize rows the current
/// stamper cannot produce (a receipt predating the manifest field-set).
#[cfg(test)]
pub(crate) fn overwrite_attempt_pack_receipt_for_test(
    vault: &Vault,
    receipt: &ReceiptRecord,
) -> Result<()> {
    vault.with_write_txn(|wtxn| put_attempt_pack_receipt_for_test(&vault.store, wtxn, receipt))
}

/// The transaction-scoped half of [`overwrite_attempt_pack_receipt_for_test`],
/// so a test that synthesizes a large ledger pays one write transaction rather
/// than one per row.
#[cfg(test)]
pub(crate) fn put_attempt_pack_receipt_for_test(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    receipt: &ReceiptRecord,
) -> Result<()> {
    let encoded = rmp_serde::to_vec_named(receipt)
        .map_err(|_| Error::InvariantViolation("attempt pack receipt encode failed"))?;
    store.vault_meta.put(
        wtxn,
        &attempt_pack_receipt_key(&receipt.receipt_id),
        &encoded,
    )?;
    Ok(())
}

/// Names the first key past the attempt pack receipt family.
///
/// The reverse walk needs an explicit half-open range because `OverlayDb`
/// exposes no reverse prefix iterator. The prefix is an ASCII literal, so its
/// final byte is nowhere near `0xFF` and bumping it is the exclusive bound.
fn attempt_pack_receipt_key_range_end() -> Vec<u8> {
    let mut end = ATTEMPT_PACK_RECEIPT_KEY_PREFIX.to_vec();
    if let Some(last) = end.last_mut() {
        *last = last.saturating_add(1);
    }
    end
}

/// Collects the attempt pack receipt ledger under the family DoS guard.
///
/// Walks the key range NEWEST-FIRST — the key embeds the UUIDv7 attempt id, so
/// key order IS mint order — and caps the walk at [`MAX_RECEIPT_QUERY_SCAN`].
/// Direction is the whole point of the cap: these rows persist for the life of
/// the vault (unlike the attempt events they project from, which drain), so an
/// oldest-first cap would permanently hide every RECENT receipt behind an
/// attacker-grown backlog, and the family query is newest-first by contract.
/// Callers sort and truncate downstream, so below the cap this returns the
/// same set the unbounded walk did.
///
/// Above the cap the answer is a bounded PREFIX, not the family — which
/// [`note_attempt_pack_scan_capped`] says out loud rather than truncating in
/// silence.
pub(super) fn attempt_pack_receipts(vault: &Vault) -> Result<Vec<ReceiptRecord>> {
    let rtxn = vault.store.env.read_txn()?;
    let end = attempt_pack_receipt_key_range_end();
    let bounds = (
        std::ops::Bound::Included(ATTEMPT_PACK_RECEIPT_KEY_PREFIX),
        std::ops::Bound::Excluded(&end[..]),
    );
    let mut receipts = Vec::new();
    // One row PAST the cap is read and never decoded: it is what separates a
    // ledger holding exactly the cap from one the cap truncated.
    for row in vault
        .store
        .vault_meta
        .rev_range(&rtxn, &bounds)?
        .take(MAX_RECEIPT_QUERY_SCAN + 1)
    {
        let (_, raw) = row?;
        if receipts.len() == MAX_RECEIPT_QUERY_SCAN {
            note_attempt_pack_scan_capped();
            break;
        }
        receipts.push(decode_attempt_pack_receipt(&raw)?);
    }
    Ok(receipts)
}

/// Surfaces an attempt pack receipt scan that stopped at the work cap.
///
/// The discarded remainder is unbounded by construction, so it is never
/// counted — the signal is that the cap FIRED, which is the fact an operator
/// (or a test) needs to know the query answered from a prefix.
fn note_attempt_pack_scan_capped() {
    tracing::warn!(
        scan_cap = MAX_RECEIPT_QUERY_SCAN,
        "attempt pack receipt scan hit the receipt-family work cap; older rows were not projected"
    );
    #[cfg(test)]
    ATTEMPT_PACK_SCAN_CAPPED.with(|fired| fired.set(fired.get() + 1));
}

fn decode_attempt_pack_receipt(raw: &[u8]) -> Result<ReceiptRecord> {
    rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex("attempt pack receipt row"))
}

/// Appends one outbound attempt's audit receipt and updates its TASK summary.
/// Delivered summaries are sticky and atomically install the actor-scoped client
/// idempotency index. Failed receipts never authorize idempotency and remain in
/// the history after a later attempt updates the summary.
pub(crate) fn persist_send_receipt(
    vault: &Vault,
    task_ref: EntityId,
    receipt: ReceiptRecord,
    outcome: SendReceiptOutcome,
    transport_dispatched: bool,
    delivered_idempotency: Option<(EntityId, &str)>,
) -> Result<bool> {
    vault.with_write_txn(|wtxn| {
        persist_send_receipt_in_txn(
            &vault.store,
            wtxn,
            task_ref,
            receipt,
            outcome,
            transport_dispatched,
            delivered_idempotency,
        )
    })
}

/// Transaction-composable persistence. Each dispatch attempt must have its own
/// `receipt_id`; a repeated identity cannot replace different audit evidence.
/// The caller owns commit/abort and must abort on error. Returns false only
/// when the TASK already has a delivered receipt.
pub(crate) fn persist_send_receipt_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    task_ref: EntityId,
    mut receipt: ReceiptRecord,
    outcome: SendReceiptOutcome,
    transport_dispatched: bool,
    delivered_idempotency: Option<(EntityId, &str)>,
) -> Result<bool> {
    let existing = store.get_send_receipt_by_task_in_txn(wtxn, &task_ref)?;
    if let Some(raw) = existing.as_deref() {
        let existing = decode_durable_send_receipt(task_ref.as_bytes(), raw)?;
        if existing.outcome == SendReceiptOutcome::Delivered {
            return Ok(false);
        }
    }
    receipt
        .fields
        .insert(FIELD_TASK_REF.to_owned(), task_ref.to_hex());
    receipt.fields.insert(
        FIELD_TRANSPORT_DISPATCHED.to_owned(),
        transport_dispatched.to_string(),
    );
    let durable = DurableSendReceipt {
        version: SEND_RECEIPT_RECORD_VERSION,
        task_ref: task_ref.to_hex(),
        outcome,
        transport_dispatched,
        receipt,
    };
    let encoded = rmp_serde::to_vec_named(&durable)
        .map_err(|_| Error::InvariantViolation("send receipt encode failed"))?;
    store.append_send_receipt_in_txn(wtxn, &task_ref, &durable.receipt.receipt_id, &encoded)?;
    if existing.is_some() {
        store.set_send_receipt_in_txn(wtxn, &task_ref, &encoded)?;
    } else {
        store.put_send_receipt_in_txn(wtxn, &task_ref, &encoded)?;
    }
    if outcome == SendReceiptOutcome::Delivered
        && let Some((actor_ref, idempotency_key)) = delivered_idempotency
    {
        store.put_delivered_send_idempotency_in_txn(wtxn, &actor_ref, idempotency_key, &task_ref)?;
    }
    Ok(true)
}

/// Point-reads a delivered receipt for executor and schedule idempotency.
/// Failed audit rows intentionally project as absent from this seam.
pub(crate) fn delivered_send_receipt_for_task(
    vault: &Vault,
    task_ref: EntityId,
) -> Result<Option<ReceiptRecord>> {
    let Some(raw) = vault.store.get_send_receipt_by_task(&task_ref)? else {
        return Ok(None);
    };
    let durable = decode_durable_send_receipt(task_ref.as_bytes(), &raw)?;
    Ok((durable.outcome == SendReceiptOutcome::Delivered).then_some(durable.receipt))
}

pub(super) fn decode_durable_send_receipt(
    task_id: &[u8; 16],
    raw: &[u8],
) -> Result<DurableSendReceipt> {
    let durable: DurableSendReceipt =
        rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex("send receipt ledger"))?;
    let expected_receipt_outcome = match durable.outcome {
        SendReceiptOutcome::Delivered => "delivered_to_channel",
        SendReceiptOutcome::Failed => "failed",
    };
    if durable.version != SEND_RECEIPT_RECORD_VERSION
        || durable.task_ref != crate::entity_id::bytes_to_hex_lower(task_id)
        || durable.receipt.receipt_kind != ReceiptKind::Outbound
        || durable.receipt.outcome != expected_receipt_outcome
        || durable.receipt.fields.get(FIELD_TASK_REF) != Some(&durable.task_ref)
        || durable
            .receipt
            .fields
            .get(FIELD_TRANSPORT_DISPATCHED)
            .and_then(|value| value.parse::<bool>().ok())
            != Some(durable.transport_dispatched)
    {
        return Err(Error::CorruptedIndex("send receipt ledger"));
    }
    Ok(durable)
}

pub(super) fn durable_send_receipts(vault: &Vault) -> Result<Vec<ReceiptRecord>> {
    vault
        .store
        .send_receipt_rows()?
        .into_iter()
        .map(|(task_id, raw)| {
            decode_durable_send_receipt(&task_id, &raw).map(|durable| durable.receipt)
        })
        .collect()
}

/// Builds an outbound receipt row from the OF-327 intent spine.
///
/// The helper keeps `job_ref` propagation explicit for brief-rooted runs while
/// preserving legacy compatibility: callers that pass an older intent without a
/// attempt ref still emit a receipt with `job_ref: None`.
#[must_use]
pub fn outbound_intent_receipt(
    receipt_id: impl Into<String>,
    intent_ref: impl Into<String>,
    intent: &OutboundIntent,
    occurred_at: u64,
    outcome: impl Into<String>,
) -> ReceiptRecord {
    let receipt_id = receipt_id.into();
    let mut fields = BTreeMap::new();
    fields.insert(FIELD_INTENT_REF.to_owned(), intent_ref.into());
    fields.insert("verb".to_owned(), intent.verb.clone());
    fields.insert("channel".to_owned(), intent.channel.clone());
    fields.insert("target".to_owned(), intent.target.clone());
    fields.insert("intent_source".to_owned(), intent.intent_source.clone());
    fields.insert(
        FIELD_RECEIPT_SCHEMA.to_owned(),
        OUTBOUND_RECEIPT_SCHEMA.to_owned(),
    );
    fields.insert(
        FIELD_ENGINE_REGISTER.to_owned(),
        OUTBOUND_ENGINE_REGISTER.to_owned(),
    );
    fields.insert(
        FIELD_CARE_REGISTER.to_owned(),
        OUTBOUND_CARE_REGISTER.to_owned(),
    );
    fields.insert(
        FIELD_AUDIT_REGISTER.to_owned(),
        OUTBOUND_AUDIT_REGISTER.to_owned(),
    );
    if let Some(content_ref) = intent.content_ref.as_ref() {
        fields.insert("content_ref".to_owned(), content_ref.clone());
    }
    if let Some(idempotency_key) = intent.idempotency_key.as_ref() {
        fields.insert("idempotency_key".to_owned(), idempotency_key.clone());
    }
    if let Some(dedupe_key) = intent.dedupe_key.as_ref() {
        fields.insert("dedupe_key".to_owned(), dedupe_key.clone());
    }

    ReceiptRecord {
        receipt_id,
        receipt_kind: ReceiptKind::Outbound,
        occurred_at,
        actor: Some(intent.actor.clone()),
        on_behalf_of: intent.on_behalf_of.clone(),
        outcome: outcome.into(),
        job_ref: intent.job_ref.clone(),
        trigger_ref: Some(intent.trigger_ref.clone()),
        policy_trace: Vec::new(),
        fields,
    }
}
