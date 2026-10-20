//! The repair of stored usage events that no longer decode (FIX 6476). Every
//! seat read counts such a row as an unpriced call of unknown seat, model and
//! time, so one of them holds every offer check of the vault at unclassified
//! while it is stored. The vault's owner, or an agent his Grant names the
//! verb for, lists the metering scope's rows that do not decode and removes
//! one he reviewed, by the hash of its bytes; every other such row is still
//! counted as before, and nothing is removed on its own. A removal deletes
//! that one row, marks the derived rollup stale and keeps its receipt, all
//! in one write. No raw key, prefix or replacement bytes reach it: the scope
//! is the one the trusted host bound to this server's meter.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use oneiron::authority::ActSurface;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::usage_repair::{
    UndecodableUsageList, UndecodableUsageReason, UndecodableUsageRow, UsageRepairReason,
    UsageRepairReceipt, UsageRepairRemoveRequest, UsageRepairVerb,
};
use oneiron::memory::{
    MEMORY_CODE_INTERNAL, MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult,
};
use oneiron::store::GateDecisionId;

use super::codec::{UsageError, decode_entry};
use super::keys::{usage_event_prefix, usage_repair_receipt_key, validate_key, vault_rollup_key};
use super::ledger::UsageLedger;
use super::rollup::mark_rollup_stale_in_txn;

/// A reviewed row whose bytes hash to something else now.
const USAGE_EVENT_CHANGED: &str = "usage_event_changed";
/// A reviewed row that decodes now: it is counted as a call, and no repair
/// removes it.
const USAGE_EVENT_DECODABLE: &str = "usage_event_decodable";
/// A server whose meter is bound to no scope.
const USAGE_METERING_UNBOUND: &str = "usage_metering_unbound";

/// The metering scope a repair reads: the billing owner and vault the
/// trusted host bound this server's meter to, never a caller's.
#[derive(Clone, Debug)]
pub(crate) struct UsageScope {
    owner: String,
    vault_id: String,
}

impl UsageScope {
    /// The scope `server`'s meter is bound to; `None` while it meters none.
    pub(crate) fn of(server: &crate::server::SyncServer) -> Option<Self> {
        server.vault_usage().map(|usage| Self {
            owner: usage.owner().to_owned(),
            vault_id: usage.vault_id().to_owned(),
        })
    }
}

impl UsageLedger {
    /// Every stored event of `scope` that does not decode by the decoder
    /// every seat read uses, in key order, read in the writer that admits
    /// the caller ([`Memory::with_usage_repair_txn`]). No row changes; a
    /// storage failure fails the list and never reads as a row.
    pub(crate) fn list_undecodable_events(
        &self,
        memory: &Memory<'_>,
        owner: Option<&AuthenticatedOwner>,
        scope: Option<&UsageScope>,
    ) -> MemoryResult<UndecodableUsageList> {
        memory.with_usage_repair_txn(owner, UsageRepairVerb::List, |txn, _| {
            let scope = bound(scope)?;
            let prefix = usage_event_prefix(&scope.owner, &scope.vault_id);
            let mut events = Vec::new();
            self.vault.sync_state_visit_prefix_in_write_txn(
                txn,
                &prefix,
                |key, raw| -> MemoryResult<()> {
                    if decode_entry(raw).is_ok() {
                        return Ok(());
                    }
                    let suffix = key.strip_prefix(prefix.as_str()).ok_or_else(|| {
                        MemoryError::from(oneiron::Error::CorruptedIndex("usage event key"))
                    })?;
                    events.push(UndecodableUsageRow {
                        row_ref: URL_SAFE_NO_PAD.encode(suffix),
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
    /// the scope's rollup stale so the next read rebuilds it without the
    /// row, and keeps the receipt it answers, all in that write. A row that
    /// is gone is not found; one that changed or decodes now is a conflict,
    /// and nothing changes.
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
            let key = usage_event_prefix(&scope.owner, &scope.vault_id) + &suffix(request)?;
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
                    "no stored usage event {} in this server's metering scope",
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
                &vault_rollup_key(&scope.owner, &scope.vault_id),
            )
            .map_err(failed)?;
            let receipt = UsageRepairReceipt {
                receipt_id: GateDecisionId::now().to_hex(),
                owner: scope.owner.clone(),
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

/// The key suffix `request`'s row ref names, as the list encoded it.
fn suffix(request: &UsageRepairRemoveRequest) -> MemoryResult<String> {
    URL_SAFE_NO_PAD
        .decode(&request.row_ref)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .filter(|suffix| !suffix.is_empty())
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

/// A reviewed row that is no longer what its review read.
fn conflict(reason: &str, why: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        format!("{reason}: {why}"),
        &["List the undecodable usage events again, and remove what that list shows."],
    )
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
