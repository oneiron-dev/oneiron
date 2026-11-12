//! A chain's receipt tail (FIX 1429, FIX 5429): the newest receipts of the
//! caller's whole family, and in a room the room's own Hook receipts beside
//! them, each with its source rows. Each hook reads the tail only as its
//! own input shows it ([`super::projection`], FIX 10084).

use serde_json::Value;

use crate::memory::MemoryReceipt;
use crate::receipt::ReceiptKind;
use crate::runtime_hooks::filter;
use crate::{EntityId, Vault};

use super::super::VerbCall;
use super::super::storage::VerbHookStorage;

/// Receipts the input's tail carries.
const RECEIPT_TAIL: usize = 8;
/// The tail's kinds: the full receipt family (FIX 1429).
const RECEIPT_TAIL_KINDS: [ReceiptKind; 15] = [
    ReceiptKind::Outbound,
    ReceiptKind::Gate,
    ReceiptKind::IdentityLifecycle,
    ReceiptKind::ScopedRead,
    ReceiptKind::Share,
    ReceiptKind::ArtifactSettle,
    ReceiptKind::ProposalOutcome,
    ReceiptKind::CommitmentLifecycle,
    ReceiptKind::Extraction,
    ReceiptKind::ServedForm,
    ReceiptKind::Hook,
    ReceiptKind::ReferenceRefusal,
    ReceiptKind::TaskLifecycle,
    ReceiptKind::RunHoldOverride,
    ReceiptKind::Inquiry,
];

/// The tail `call`'s chain on `storage` reads, as JSON, and the source rows
/// of each room Hook receipt in it, by its ref: a hook reads one only while
/// its own view shows them all (FIX 5429). A chain in a room also reads the
/// room's own Hook receipts, which base's family does not hold. A tail that
/// does not read is empty.
pub(super) fn receipt_tail(
    vault: &Vault,
    storage: VerbHookStorage<'_>,
    call: &VerbCall,
) -> (Value, Vec<(String, Vec<EntityId>)>) {
    let kinds = RECEIPT_TAIL_KINDS.map(|kind| kind.as_str().to_owned());
    let base = vault
        .memory(call.actor, filter::edge_class(call.class))
        .receipts_of_kinds(RECEIPT_TAIL, &kinds)
        .ok();
    let (records, sources): (Vec<_>, Vec<_>) = match storage {
        VerbHookStorage::Session(hooks) => hooks
            .room_hook_receipts(vault, call.reader.as_ref(), RECEIPT_TAIL)
            .unwrap_or_default()
            .into_iter()
            .unzip(),
        VerbHookStorage::Canonical => (Vec::new(), Vec::new()),
    };
    let room = crate::memory::Memory::room_tail_receipts(records);
    let room_sources = room
        .iter()
        .map(|receipt| receipt.receipt_ref.clone())
        .zip(sources)
        .collect();
    let tail = base
        .map(|base| merged_tail(base, room))
        .and_then(|receipts| serde_json::to_value(receipts).ok())
        .unwrap_or_else(|| Value::Array(Vec::new()));
    (tail, room_sources)
}

/// A room chain's receipt tail: base's family tail and the room's own Hook
/// receipts, one per receipt (the room's wins), newest first, cut at
/// [`RECEIPT_TAIL`] (FIX 5429). With no room receipt, base's tail as it is.
fn merged_tail(base: Vec<MemoryReceipt>, room: Vec<MemoryReceipt>) -> Vec<MemoryReceipt> {
    if room.is_empty() {
        return base;
    }
    let mut tail = room;
    for receipt in base {
        if !tail
            .iter()
            .any(|kept| kept.kind == receipt.kind && kept.receipt_ref == receipt.receipt_ref)
        {
            tail.push(receipt);
        }
    }
    tail.sort_by(|left, right| {
        right
            .created_at
            .cmp(&left.created_at)
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| left.receipt_ref.cmp(&right.receipt_ref))
    });
    tail.truncate(RECEIPT_TAIL);
    tail
}
