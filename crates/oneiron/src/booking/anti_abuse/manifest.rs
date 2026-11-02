//! Activated booking anti-abuse rule rows as POLICY_MANIFEST rows (FIX 9628).
//! Entry: `BOOKING_ANTI_ABUSE_RULES_KEY`.
//! Defines its own items.
//!
//! The rows ride the vault's policy manifests under one field and reach every
//! node through the manifest's own write and sync path: the owner-trusted
//! default manifest is the one this lane writes, and every trusted manifest's
//! rows join the resolved policy. Rate counters, the slot-list cache, rule
//! proposals and restorable submissions stay node-local `vault_meta` rows.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

use super::rules::{BookingAntiAbuseRuleRow, booking_rule_row_id, validate_rule_row};
use super::storage::{engine_failure, refused};
use crate::booking::BookingError;
use crate::consent::AuthenticatedOwner;
use crate::{Error, Vault};

/// The POLICY_MANIFEST field holding a manifest's booking anti-abuse rule
/// rows: an array of rows, at most one per row id.
pub const BOOKING_ANTI_ABUSE_RULES_KEY: &str = "booking_anti_abuse_rules";

/// The gate receipt reason one activated rule row's manifest write records.
const RULE_WRITE_REASON_CODE: &str = "gate.allow.owner_booking_anti_abuse_rule";

/// Decodes one manifest body's rule rows, for the manifest decoder: empty
/// when the body has no rule field, and `None` when the field repeats or
/// does not hold valid rows ([`decode_manifest_rule_rows`]).
pub(crate) fn decode_manifest_rule_field(
    entries: &[(rmpv::Value, rmpv::Value)],
) -> Option<Vec<BookingAntiAbuseRuleRow>> {
    let mut fields = entries
        .iter()
        .filter(|(key, _)| key.as_str() == Some(BOOKING_ANTI_ABUSE_RULES_KEY));
    let Some((_, value)) = fields.next() else {
        return Some(Vec::new());
    };
    if fields.next().is_some() {
        return None;
    }
    decode_manifest_rule_rows(value)
}

/// Decodes one rule field's value: `None` when it is not an array of valid
/// rows, a row id is not its canonical scope and rule identity, or two rows
/// share an id.
fn decode_manifest_rule_rows(value: &rmpv::Value) -> Option<Vec<BookingAntiAbuseRuleRow>> {
    let rmpv::Value::Array(entries) = value else {
        return None;
    };
    let mut rows: Vec<BookingAntiAbuseRuleRow> = Vec::with_capacity(entries.len());
    for entry in entries {
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, entry).ok()?;
        let row: BookingAntiAbuseRuleRow = rmp_serde::from_slice(&bytes).ok()?;
        validate_rule_row(&row).ok()?;
        if row.row_id != booking_rule_row_id(&row.scope, &row.rule)
            || rows.iter().any(|kept| kept.row_id == row.row_id)
        {
            return None;
        }
        rows.push(row);
    }
    Some(rows)
}

fn encode_manifest_rule_rows(rows: &[BookingAntiAbuseRuleRow]) -> Result<rmpv::Value, Error> {
    let bytes = rmp_serde::to_vec_named(rows)
        .map_err(|_| Error::InvalidConfig("booking anti-abuse rule rows encoding".to_owned()))?;
    rmpv::decode::read_value(&mut std::io::Cursor::new(bytes))
        .map_err(|_| Error::InvalidConfig("booking anti-abuse rule rows encoding".to_owned()))
}

/// The rule rows in force: every trusted manifest's rows, one per row id at
/// its highest version. Two trusted manifests holding one row at the same
/// version resolve to the one the fold read first.
pub(super) fn effective_rule_rows_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
) -> Result<Vec<BookingAntiAbuseRuleRow>, BookingError> {
    let resolution = crate::gate::resolve_policy_manifest(&vault.store, rtxn)
        .map_err(|error| engine_failure("policy manifest resolve", error))?;
    let mut by_id: BTreeMap<&str, &BookingAntiAbuseRuleRow> = BTreeMap::new();
    for row in &resolution.booking_anti_abuse_rows {
        match by_id.entry(row.row_id.as_str()) {
            Entry::Vacant(slot) => {
                slot.insert(row);
            }
            Entry::Occupied(mut slot) => {
                if row.version > slot.get().version {
                    slot.insert(row);
                }
            }
        }
    }
    Ok(by_id.into_values().cloned().collect())
}

/// [`effective_rule_rows_in_txn`] in a fresh read transaction.
pub(super) fn effective_rule_rows(
    vault: &Vault,
) -> Result<Vec<BookingAntiAbuseRuleRow>, BookingError> {
    let rtxn = vault
        .store
        .env
        .read_txn()
        .map_err(|error| engine_failure("read transaction", error))?;
    effective_rule_rows_in_txn(vault, &rtxn)
}

/// Stores one activated row in the owner-trusted default manifest, replacing
/// the row with its id, through the owner's manifest writer, and returns the
/// gate receipt that write recorded.
pub(super) fn put_manifest_rule_row_in_txn(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    wtxn: &mut heed::RwTxn<'_>,
    row: &BookingAntiAbuseRuleRow,
) -> Result<String, BookingError> {
    crate::gate::policy_manifest_doors::rewrite_default_manifest_field_as_owner_in_txn(
        vault,
        owner,
        wtxn,
        BOOKING_ANTI_ABUSE_RULES_KEY,
        |current| {
            let mut rows = match current {
                Some(value) => decode_manifest_rule_rows(value).ok_or_else(|| {
                    Error::InvalidConfig("stored booking anti-abuse rule rows are malformed".into())
                })?,
                None => Vec::new(),
            };
            rows.retain(|kept| kept.row_id != row.row_id);
            rows.push(row.clone());
            rows.sort_by(|left, right| left.row_id.cmp(&right.row_id));
            encode_manifest_rule_rows(&rows)
        },
        RULE_WRITE_REASON_CODE,
    )
    .map_err(|error| {
        refused(format!(
            "booking anti-abuse rule manifest write refused: {error}"
        ))
    })
}
