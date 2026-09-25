use std::collections::BTreeMap;
use std::ops::Bound;

use serde::{Deserialize, Serialize};

use super::field_set::append_pack_manifest_fields;
#[cfg(test)]
use super::kernel::ATTEMPT_PACK_SCAN_CAPPED;
use super::kernel::{
    FIELD_AUDIT_REGISTER, FIELD_CARE_REGISTER, FIELD_ENGINE_REGISTER, FIELD_INTENT_REF,
    FIELD_RECEIPT_SCHEMA, FIELD_TASK_REF, FIELD_TRANSPORT_DISPATCHED, MAX_RECEIPT_QUERY_SCAN,
    ReceiptKind, ReceiptRecord, ReceiptScan, hex_lower,
};
use super::send_receipt_txn::persist_send_receipt_in_txn;
use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptRecord};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::outbound::OutboundIntent;
use crate::side_table::{self, Named, SideTable};
use crate::store::{SEND_RECEIPT_RECORD_VERSION, Store};

/// `vault_meta` keyspace of the attempt PACK RECEIPT ledger. The suffix is the
/// receipt id itself, so a cited `receipt_ref` point-reads its row. Key: string
/// (the receipt id).
const PACK_RECEIPT: SideTable<String, ReceiptRecord, Named> =
    SideTable::new(&side_table::ATTEMPT_PACK_RECEIPT);
/// `receipt_id` namespace of the same ledger.
const ATTEMPT_PACK_RECEIPT_ID_PREFIX: &str = "attempt:";

const OUTBOUND_RECEIPT_SCHEMA: &str = "outbound_receipt.v1";
const OUTBOUND_ENGINE_REGISTER: &str = "neutral";
const OUTBOUND_CARE_REGISTER: &str = "eirispec_care_register";
const OUTBOUND_AUDIT_REGISTER: &str = "dashboard_atom_kit_audit";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct DurableSendReceipt {
    pub(super) version: u8,
    pub(super) task_ref: String,
    pub(super) outcome: SendReceiptOutcome,
    pub(super) transport_dispatched: bool,
    pub(super) receipt: ReceiptRecord,
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
    PACK_RECEIPT.put(store, wtxn, &receipt.receipt_id, &receipt)?;
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
    PACK_RECEIPT.get(&vault.store, &rtxn, &receipt_id.to_owned())
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
    PACK_RECEIPT.put(store, wtxn, &receipt.receipt_id, receipt)?;
    Ok(())
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
/// Compatibility view for callers that do not consume completeness metadata.
pub(super) fn attempt_pack_receipts(vault: &Vault) -> Result<Vec<ReceiptRecord>> {
    Ok(scan_attempt_pack_receipts(vault)?.records)
}

/// Scans the same bounded prefix and reports a source continuation in production.
/// The overflow probe is never projected and does not increase the projection cap.
pub(super) fn scan_attempt_pack_receipts(vault: &Vault) -> Result<ReceiptScan> {
    let rtxn = vault.store.env.read_txn()?;
    let mut scan = ReceiptScan::from_complete_records(Vec::new());
    let mut before = None;
    // One row PAST the cap is read and never projected: it is what separates a
    // ledger holding exactly the cap from one the cap truncated.
    for row in PACK_RECEIPT
        .iter_rev_from(&vault.store, &rtxn, &[])?
        .take(MAX_RECEIPT_QUERY_SCAN + 1)
    {
        let (key, record) = row?;
        if scan.records.len() == MAX_RECEIPT_QUERY_SCAN {
            scan.mark_incomplete().attempt_pack_before = before;
            note_attempt_pack_scan_capped();
            break;
        }
        scan.records.push(record);
        before = Some(PACK_RECEIPT.key_bytes(&key));
    }
    Ok(scan)
}

/// Forward, continuation-bearing scan for production receipt consumers. One extra
/// key proves completeness; unlike the UI lens this can reach older receipts.
pub(crate) fn attempt_pack_receipt_page(
    vault: &Vault,
    after: Option<&str>,
    limit: usize,
) -> Result<(Vec<ReceiptRecord>, bool)> {
    if !(1..=1024).contains(&limit) {
        return Err(Error::InvalidConfig(
            "receipt page limit must be in 1..=1024".to_owned(),
        ));
    }
    if after.is_some_and(|id| !id.starts_with(ATTEMPT_PACK_RECEIPT_ID_PREFIX)) {
        return Err(Error::CorruptedIndex("receipt sweep cursor"));
    }
    let start = after.map(str::to_owned);
    let txn = vault.store.env.read_txn()?;
    let mut records = Vec::new();
    for row in PACK_RECEIPT
        .iter_range(
            &vault.store,
            &txn,
            start.as_ref().map_or(Bound::Unbounded, Bound::Excluded),
            Bound::Unbounded,
        )?
        .take(limit + 1)
    {
        let (_, record) = row?;
        if records.len() == limit {
            return Ok((records, false));
        }
        records.push(record);
    }
    Ok((records, true))
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

/// This projector reads its entire existing audit source; it has no source cap.
pub(super) fn scan_durable_send_receipts(vault: &Vault) -> Result<ReceiptScan> {
    durable_send_receipts(vault).map(ReceiptScan::from_complete_records)
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

/// Read actual terminal evidence on the caller's consistent archive snapshot.
/// This accessor provides data, never a way to install a foreign receipt.
pub(crate) fn attempt_pack_receipt_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    receipt_id: &str,
) -> Result<Option<ReceiptRecord>> {
    let Some(suffix) = receipt_id.strip_prefix(ATTEMPT_PACK_RECEIPT_ID_PREFIX) else {
        return Ok(None);
    };
    let Ok(id) = EntityId::from_hex(suffix) else {
        return Ok(None);
    };
    if id.to_hex() != suffix {
        return Ok(None);
    }
    let Some(receipt) = PACK_RECEIPT.get(store, txn, &receipt_id.to_owned())? else {
        return Ok(None);
    };
    if receipt.receipt_id != receipt_id {
        return Err(Error::CorruptedIndex("attempt receipt key/body identity"));
    }
    Ok(Some(receipt))
}
