//! The nested values of a ledger row (approval, budget marker, capability
//! provenance, recorded outcome) and the typed field readers every key's
//! decoder shares.

use rmpv::Value;

use super::super::types::{
    AdmittedApproval, BudgetChargeMarker, BudgetClass, IntentEscalationReason, IntentLedgerError,
    IntentLedgerResult, RecordedOutboundOutcome,
};
use super::{BUDGET_ACCOUNTING_KEYS, CAPABILITY_PROVENANCE_KEYS, RECORDED_OUTCOME_KEYS};
use crate::connector_key::ScopedCapabilityProvenance;
use crate::entity_id::EntityId;

pub(super) fn decode_admitted_approval(
    value: &Value,
) -> IntentLedgerResult<Option<AdmittedApproval>> {
    if matches!(value, Value::Nil) {
        return Ok(None);
    }
    let Value::Map(entries) = value else {
        return Err(IntentLedgerError::InvalidRecord(
            "admitted approval must be a map",
        ));
    };
    if entries.len() != 2
        || entries[0].0.as_str() != Some("intent_id")
        || entries[1].0.as_str() != Some("effect_digest")
    {
        return Err(IntentLedgerError::InvalidRecord(
            "admitted approval keys are not canonical",
        ));
    }
    let intent_id = expect_binary_array::<32>(&entries[0].1)?;
    let digest = expect_binary_array::<32>(&entries[1].1)?;
    Ok(Some(AdmittedApproval::from_gate(
        intent_id,
        crate::consent::EffectDigest::from_bytes(digest),
    )))
}

pub(super) fn decode_budget_accounting(value: &Value) -> IntentLedgerResult<BudgetChargeMarker> {
    let Value::Map(entries) = value else {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent budget_accounting must be a map",
        ));
    };
    validate_nested_keys(entries, &BUDGET_ACCOUNTING_KEYS)?;
    let key_ref = match nested_value(entries, BUDGET_ACCOUNTING_KEYS[0])? {
        Value::Nil => None,
        value => Some(
            EntityId::from_bytes(expect_binary_array::<16>(value)?).map_err(|_| {
                IntentLedgerError::InvalidRecord("outbound intent budget key_ref is invalid")
            })?,
        ),
    };
    let budget_class = nested_value(entries, BUDGET_ACCOUNTING_KEYS[1])?
        .as_str()
        .and_then(BudgetClass::parse)
        .ok_or(IntentLedgerError::InvalidRecord(
            "outbound intent budget_class is invalid",
        ))?;
    let Value::Array(row_values) = nested_value(entries, BUDGET_ACCOUNTING_KEYS[2])? else {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent matched_rows must be an array",
        ));
    };
    let mut matched_rows = Vec::with_capacity(row_values.len());
    for value in row_values {
        let row = expect_u64(value)?;
        matched_rows.push(u16::try_from(row).map_err(|_| {
            IntentLedgerError::InvalidRecord("outbound intent matched row is invalid")
        })?);
    }
    Ok(BudgetChargeMarker {
        key_ref,
        budget_class,
        matched_rows,
        sends_debit: expect_u64(nested_value(entries, BUDGET_ACCOUNTING_KEYS[3])?)?,
        accounted_at_ms: expect_u64(nested_value(entries, BUDGET_ACCOUNTING_KEYS[4])?)?,
    })
}

/// Decodes the typed scoped capability provenance fail-closed: unknown or
/// duplicate nested keys, a malformed grant id, an unsafe/non-canonical server,
/// or a connector that is not EXACTLY the identity that (server, grant) mints
/// are all rejected, so no durable row can carry a forged capability (ONE-1885).
pub(super) fn decode_capability_provenance(
    value: &Value,
) -> IntentLedgerResult<Option<ScopedCapabilityProvenance>> {
    if matches!(value, Value::Nil) {
        return Ok(None);
    }
    let Value::Map(entries) = value else {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent capability_provenance must be a map",
        ));
    };
    validate_nested_keys(entries, &CAPABILITY_PROVENANCE_KEYS)?;
    let grant_id = EntityId::from_bytes(expect_binary_array::<16>(nested_value(
        entries,
        CAPABILITY_PROVENANCE_KEYS[0],
    )?)?)
    .map_err(|_| {
        IntentLedgerError::InvalidRecord("outbound intent capability grant_id is invalid")
    })?;
    let server = expect_string(nested_value(entries, CAPABILITY_PROVENANCE_KEYS[1])?)?;
    let connector = expect_string(nested_value(entries, CAPABILITY_PROVENANCE_KEYS[2])?)?;
    ScopedCapabilityProvenance::from_persisted_parts(&grant_id, &server, &connector)
        .map(Some)
        .ok_or(IntentLedgerError::InvalidRecord(
            "outbound intent capability_provenance is inconsistent",
        ))
}

pub(super) fn decode_recorded_outcome(
    value: &Value,
) -> IntentLedgerResult<Option<RecordedOutboundOutcome>> {
    if matches!(value, Value::Nil) {
        return Ok(None);
    }
    let Value::Map(entries) = value else {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent recorded_outcome must be a map",
        ));
    };
    validate_nested_keys(entries, &RECORDED_OUTCOME_KEYS)?;
    let kind = nested_value(entries, RECORDED_OUTCOME_KEYS[0])?
        .as_str()
        .ok_or(IntentLedgerError::InvalidRecord(
            "outbound intent outcome kind is invalid",
        ))?;
    let reason = nested_value(entries, RECORDED_OUTCOME_KEYS[1])?;
    match (kind, reason) {
        ("definite_non_delivery", Value::Nil) => {
            Ok(Some(RecordedOutboundOutcome::DefiniteNonDelivery))
        }
        ("acked", Value::Nil) => Ok(Some(RecordedOutboundOutcome::Acked)),
        ("deferred", Value::Nil) => Ok(Some(RecordedOutboundOutcome::Deferred)),
        ("abandoned", value) => {
            let reason = value
                .as_str()
                .and_then(IntentEscalationReason::parse)
                .ok_or(IntentLedgerError::InvalidRecord(
                    "outbound intent abandonment reason is invalid",
                ))?;
            Ok(Some(RecordedOutboundOutcome::Abandoned(reason)))
        }
        _ => Err(IntentLedgerError::InvalidRecord(
            "outbound intent recorded_outcome is inconsistent",
        )),
    }
}

fn validate_nested_keys(entries: &[(Value, Value)], keys: &[&str]) -> IntentLedgerResult<()> {
    let mut seen = vec![false; keys.len()];
    for (key, _) in entries {
        let key = key.as_str().ok_or(IntentLedgerError::InvalidRecord(
            "outbound intent nested keys must be strings",
        ))?;
        let index = keys.iter().position(|candidate| *candidate == key).ok_or(
            IntentLedgerError::InvalidRecord("outbound intent nested key is not pinned"),
        )?;
        if seen[index] {
            return Err(IntentLedgerError::InvalidRecord(
                "duplicate outbound intent nested key",
            ));
        }
        seen[index] = true;
    }
    if seen.into_iter().all(|value| value) {
        Ok(())
    } else {
        Err(IntentLedgerError::InvalidRecord(
            "outbound intent nested field is missing",
        ))
    }
}

fn nested_value<'a>(entries: &'a [(Value, Value)], key: &str) -> IntentLedgerResult<&'a Value> {
    entries
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
        .ok_or(IntentLedgerError::InvalidRecord(
            "outbound intent nested field is missing",
        ))
}

pub(super) fn expect_u64(value: &Value) -> IntentLedgerResult<u64> {
    value.as_u64().ok_or(IntentLedgerError::InvalidRecord(
        "outbound intent integer field is invalid",
    ))
}

pub(super) fn expect_string(value: &Value) -> IntentLedgerResult<String> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or(IntentLedgerError::InvalidRecord(
            "outbound intent string field is invalid",
        ))
}

pub(super) fn expect_binary(value: &Value) -> IntentLedgerResult<Vec<u8>> {
    let Value::Binary(bytes) = value else {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent binary field is invalid",
        ));
    };
    Ok(bytes.clone())
}

pub(super) fn expect_binary_array<const N: usize>(value: &Value) -> IntentLedgerResult<[u8; N]> {
    expect_binary(value)?
        .try_into()
        .map_err(|_| IntentLedgerError::InvalidRecord("outbound intent binary length is invalid"))
}

pub(super) fn required<T>(value: Option<T>, reason: &'static str) -> IntentLedgerResult<T> {
    value.ok_or(IntentLedgerError::InvalidRecord(reason))
}
