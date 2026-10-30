//! The repair of stored usage events that no longer decode (FIX 6476). Every
//! seat read counts such a row as an unpriced call of unknown seat, model and
//! time, so one of them holds every offer check of the vault at unclassified
//! while it is stored. The vault's owner, or an agent his Grant names the
//! verb for, lists the metering scope's rows that do not decode and removes
//! one he reviewed, by the hash of its bytes; every other such row is still
//! counted as before, and nothing is removed on its own. A removal deletes
//! that one row, marks its billing owner's derived rollup stale and keeps its
//! receipt, all in one write. No raw key, prefix or replacement bytes reach
//! it: the scope is the vault the trusted host bound this server's meter to,
//! every billing owner's rows in it, the vault owner's and each room-paid
//! payer account's alike (FIX 7035).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use oneiron::authority::ActSurface;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::usage_repair::{
    UndecodableUsageList, UndecodableUsageReason, UndecodableUsageRow, UsageRepairReason,
    UsageRepairReceipt, UsageRepairReceiptList, UsageRepairRemoveRequest, UsageRepairVerb,
};
use oneiron::memory::{
    MEMORY_CODE_INTERNAL, MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult,
};
use oneiron::store::GateDecisionId;

use super::codec::{UsageError, decode_entry};
use super::keys::{
    USAGE_EVENT_ROOT, decoded_key_part, usage_event_parts, usage_repair_receipt_key, validate_key,
    vault_key_part, vault_rollup_key_of_parts,
};
use super::ledger::UsageLedger;
use super::rollup::mark_rollup_stale_in_txn;

/// A reviewed row whose bytes hash to something else now.
const USAGE_EVENT_CHANGED: &str = "usage_event_changed";
/// A reviewed row that decodes now: it is counted as a call, and no repair
/// removes it.
const USAGE_EVENT_DECODABLE: &str = "usage_event_decodable";
/// A server whose meter is bound to no scope.
const USAGE_METERING_UNBOUND: &str = "usage_metering_unbound";

/// The metering scope a repair reads: the vault the trusted host bound this
/// server's meter to, never a caller's, with every billing owner's rows in
/// it (FIX 7035).
#[derive(Clone, Debug)]
pub(crate) struct UsageScope {
    vault_id: String,
}

impl UsageScope {
    /// The scope `server`'s meter is bound to; `None` while it meters none.
    pub(crate) fn of(server: &crate::server::SyncServer) -> Option<Self> {
        server.vault_usage().map(|usage| Self {
            vault_id: usage.vault_id().to_owned(),
        })
    }
}

/// Why a reviewed row was not removed, as the remove's refusal names it in
/// its typed reason codes: `usage_event_changed` or `usage_event_decodable`
/// (FIX 7038, 11007). `None` for every other refusal.
pub(crate) fn removal_conflict_reason(error: &MemoryError) -> Option<&'static str> {
    if error.code != MEMORY_CODE_INVALID_STATE {
        return None;
    }
    [USAGE_EVENT_CHANGED, USAGE_EVENT_DECODABLE]
        .into_iter()
        .find(|reason| error.reason_codes.iter().any(|code| code == reason))
}

impl UsageLedger {
    /// Every stored event of `scope` that does not decode by the decoder
    /// every seat read uses, in key order, whichever billing owner it lands
    /// on, read in the writer that admits the caller
    /// ([`Memory::with_usage_repair_txn`]). Each row ref names its owner's
    /// part of the key and the rest after the vault's. No row changes; a
    /// storage failure fails the list and never reads as a row.
    pub(crate) fn list_undecodable_events(
        &self,
        memory: &Memory<'_>,
        owner: Option<&AuthenticatedOwner>,
        scope: Option<&UsageScope>,
    ) -> MemoryResult<UndecodableUsageList> {
        memory.with_usage_repair_txn(owner, UsageRepairVerb::List, |txn, _| {
            let scope = bound(scope)?;
            let vault = vault_key_part(&scope.vault_id);
            let mut events = Vec::new();
            self.vault.sync_state_visit_prefix_in_write_txn(
                txn,
                USAGE_EVENT_ROOT,
                |key, raw| -> MemoryResult<()> {
                    let Some((billed, _, id)) =
                        usage_event_parts(key).filter(|(_, part, _)| *part == vault)
                    else {
                        return Ok(());
                    };
                    if decode_entry(raw).is_ok() {
                        return Ok(());
                    }
                    events.push(UndecodableUsageRow {
                        row_ref: URL_SAFE_NO_PAD.encode(format!("{billed}:{id}")),
                        byte_length: raw.len() as u64,
                        hash: hash(raw),
                        decode_reason: UndecodableUsageReason::StoredEventDecodeFailed,
                    });
                    Ok(())
                },
            )?;
            Ok(UndecodableUsageList { events })
        })
    }

    /// Removes the one stored event of `scope` that `request` names, in the
    /// writer that admits the caller, while its bytes still hash to the
    /// reviewed hash and still do not decode: deletes that row alone, marks
    /// its billing owner's rollup stale so the next read rebuilds it without
    /// the row, and keeps the receipt it answers, naming that owner, all in
    /// that write. A row that is gone is not found; one that changed or
    /// decodes now is a conflict, and nothing changes.
    pub(crate) fn remove_undecodable_event(
        &self,
        memory: &Memory<'_>,
        owner: Option<&AuthenticatedOwner>,
        scope: Option<&UsageScope>,
        surface: ActSurface,
        request: &UsageRepairRemoveRequest,
    ) -> MemoryResult<UsageRepairReceipt> {
        memory.with_usage_repair_txn(owner, UsageRepairVerb::Remove, |txn, caller| {
            let scope = bound(scope)?;
            let (billed, id) = suffix(request)?;
            let vault = vault_key_part(&scope.vault_id);
            let key = format!("{USAGE_EVENT_ROOT}{billed}:{vault}:{id}");
            validate_key(&key).map_err(|_| {
                MemoryError::bad_request("rowRef names a key no stored usage event can have")
            })?;
            if !is_hash(&request.expected_hash) {
                return Err(MemoryError::bad_request(
                    "expectedHash must be 64 lowercase hex digits: the BLAKE3 hash the list gave",
                ));
            }
            let Some(raw) = self.vault.sync_state_get_in_write_txn(txn, &key)? else {
                return Err(MemoryError::not_found(format!(
                    "no stored usage event {} in this vault's metering scope",
                    request.row_ref
                )));
            };
            if hash(&raw) != request.expected_hash {
                return Err(conflict(
                    USAGE_EVENT_CHANGED,
                    "the row's bytes changed since it was listed; nothing was removed",
                ));
            }
            if decode_entry(&raw).is_ok() {
                return Err(conflict(
                    USAGE_EVENT_DECODABLE,
                    "the row decodes now and is counted as a call; nothing was removed",
                ));
            }
            if !self.vault.sync_state_delete_in_write_txn(txn, &key)? {
                return Err(
                    oneiron::Error::InvariantViolation("usage event read but not deleted").into(),
                );
            }
            mark_rollup_stale_in_txn(
                &self.vault,
                txn,
                &vault_rollup_key_of_parts(&billed, &vault),
            )
            .map_err(failed)?;
            let receipt = UsageRepairReceipt {
                receipt_id: GateDecisionId::now().to_hex(),
                owner: decoded_key_part(&billed).unwrap_or(billed),
                vault_id: scope.vault_id.clone(),
                row_ref: request.row_ref.clone(),
                hash: request.expected_hash.clone(),
                byte_length: raw.len() as u64,
                reason: UsageRepairReason::UndecodableEventRemoved,
                actor_ref: caller.actor().to_hex(),
                actor_class: caller.class().gate_actor_class().to_owned(),
                authority: caller.authority().clone(),
                surface: surface.into(),
                recorded_at: caller.at(),
            };
            let encoded = rmp_serde::to_vec_named(&receipt)
                .map_err(|error| failed(UsageError::Encode(error)))?;
            self.vault.sync_state_put_in_write_txn(
                txn,
                &usage_repair_receipt_key(&receipt.receipt_id),
                &encoded,
            )?;
            Ok(receipt)
        })
    }
}

impl UsageLedger {
    /// Every receipt a removal kept for `scope` (FIX 7036), in key order, as
    /// its write kept it, whichever billing owner it names, read in the
    /// writer that admits the caller for the receipts' own verb
    /// ([`Memory::with_usage_repair_txn`]). None is capped or dropped. A kept
    /// row that does not decode is counted, never read as a receipt; a
    /// storage failure fails the list.
    pub(crate) fn list_repair_receipts(
        &self,
        memory: &Memory<'_>,
        owner: Option<&AuthenticatedOwner>,
        scope: Option<&UsageScope>,
    ) -> MemoryResult<UsageRepairReceiptList> {
        memory.with_usage_repair_txn(owner, UsageRepairVerb::Receipts, |txn, _| {
            let scope = bound(scope)?;
            let mut receipts = Vec::new();
            let mut undecodable = 0_u64;
            self.vault.sync_state_visit_prefix_in_write_txn(
                txn,
                &usage_repair_receipt_key(""),
                |_, raw| -> MemoryResult<()> {
                    match rmp_serde::from_slice::<UsageRepairReceipt>(raw) {
                        Ok(receipt) if receipt.vault_id == scope.vault_id => receipts.push(receipt),
                        Ok(_) => {}
                        Err(_) => undecodable = undecodable.saturating_add(1),
                    }
                    Ok(())
                },
            )?;
            Ok(UsageRepairReceiptList {
                receipts,
                undecodable,
            })
        })
    }
}

/// The scope a repair reads, or its refusal on a server that meters none.
fn bound(scope: Option<&UsageScope>) -> MemoryResult<&UsageScope> {
    scope.ok_or_else(|| {
        MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            format!(
                "{USAGE_METERING_UNBOUND}: this server meters no usage, so it holds no usage event to repair"
            ),
            &["Call the server whose meter records this vault's usage."],
        )
    })
}

/// The billing owner's key part and the rest of the key after the vault's
/// that `request`'s row ref names, as the list encoded them.
fn suffix(request: &UsageRepairRemoveRequest) -> MemoryResult<(String, String)> {
    URL_SAFE_NO_PAD
        .decode(&request.row_ref)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|suffix| {
            let (owner, id) = suffix.split_once(':')?;
            (!owner.is_empty() && !id.is_empty()).then(|| (owner.to_owned(), id.to_owned()))
        })
        .ok_or_else(|| MemoryError::bad_request("rowRef must be a row ref the list gave"))
}

/// BLAKE3 of `raw`, 64 lowercase hex digits.
fn hash(raw: &[u8]) -> String {
    blake3::hash(raw).to_hex().to_string()
}

fn is_hash(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// A reviewed row that is no longer what its review read: `reason` is its
/// typed reason code (FIX 11007), which every surface carries beside the
/// message.
fn conflict(reason: &str, why: &str) -> MemoryError {
    let mut error = MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        format!("{reason}: {why}"),
        &["List the undecodable usage events again, and remove what that list shows."],
    );
    error.reason_codes.push(reason.to_owned());
    error
}

/// A usage store failure in the repair's write, which then commits nothing.
fn failed(error: UsageError) -> MemoryError {
    match error {
        UsageError::Storage(error) => error.into(),
        other => MemoryError::new(
            MEMORY_CODE_INTERNAL,
            format!("usage repair: {other}"),
            &["Report this usage repair failure."],
        ),
    }
}
