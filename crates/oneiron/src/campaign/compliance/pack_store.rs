//! Seed loading, pack validation/coverage, and vault persistence plus msgpack encode/decode.

use crate::Vault;
use crate::error::{Error, Result};
use crate::store::Store;

use super::rules::{
    B2bExemption, CAMPAIGN_COMPLIANCE_META_KEY, CAMPAIGN_COMPLIANCE_SEED_JSON, CompliancePack,
    ComplianceRuleKind, ComplianceRuleRow, JURISDICTION_NONE,
};

// ---------------------------------------------------------------------------
// Pack loading and validation
// ---------------------------------------------------------------------------

/// Parses and validates the embedded bootstrap seed.
///
/// # Errors
///
/// [`Error::InvariantViolation`] when the shipped JSON is unparseable, and the
/// [`Error::InvalidConfig`] shape errors of [`validate_compliance_pack`]
/// otherwise. Both are build-time defects, not runtime conditions.
pub fn embedded_seed_pack() -> Result<CompliancePack> {
    let pack: CompliancePack =
        serde_json::from_str(CAMPAIGN_COMPLIANCE_SEED_JSON).map_err(|_| {
            Error::InvariantViolation("campaign compliance seed pack is not valid JSON")
        })?;
    validate_compliance_pack(&pack)?;
    Ok(pack)
}

/// Rejects a pack that cannot be applied deterministically.
///
/// Runs before EVERY activation, seed or amendment, so a pack that would
/// evaluate ambiguously never becomes active in the first place.
///
/// # Errors
///
/// [`Error::InvalidConfig`] naming the first defect found.
pub fn validate_compliance_pack(pack: &CompliancePack) -> Result<()> {
    if pack.pack_id.trim().is_empty() || pack.warning.trim().is_empty() || pack.rows.is_empty() {
        return Err(invalid_pack(
            "pack id, warning, and rows must all be present",
        ));
    }
    if pack.strict_pole_jurisdiction.trim().is_empty()
        || pack.strict_pole_jurisdiction == JURISDICTION_NONE
    {
        return Err(invalid_pack("strict pole must name a seeded jurisdiction"));
    }
    let mut keys: Vec<(&str, &str, ComplianceRuleKind)> = Vec::with_capacity(pack.rows.len());
    for row in &pack.rows {
        validate_compliance_row(row)?;
        keys.push(row.key());
    }
    keys.sort_unstable();
    if keys.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(invalid_pack(
            "duplicate (jurisdiction, channel, rule_kind) row key",
        ));
    }
    validate_pack_coverage(pack)
}

fn validate_compliance_row(row: &ComplianceRuleRow) -> Result<()> {
    let blank = row.jurisdiction.trim().is_empty()
        || row.channel.trim().is_empty()
        || row.requirement.trim().is_empty()
        || row.penalty_note.trim().is_empty()
        || row.source.citation.trim().is_empty()
        || row.source.url.trim().is_empty();
    if blank {
        return Err(invalid_pack("rule row has a blank required field"));
    }
    if row.verified_at == 0 || row.version == 0 {
        return Err(invalid_pack("rule row needs a verified_at and a version"));
    }
    Ok(())
}

/// Every disposition the evaluator relies on must be seeded.
fn validate_pack_coverage(pack: &CompliancePack) -> Result<()> {
    if !pack
        .rows
        .iter()
        .any(|row| row.jurisdiction == JURISDICTION_NONE)
    {
        return Err(invalid_pack(
            "pack needs an explicit unknown-jurisdiction disposition row",
        ));
    }
    if !pack
        .rows
        .iter()
        .any(|row| row.jurisdiction == pack.strict_pole_jurisdiction)
    {
        return Err(invalid_pack("strict pole has no rows"));
    }
    let unbound = pack.rows.iter().find(|row| {
        row.b2b_exemption == B2bExemption::Conditional
            && row.rule_kind == ComplianceRuleKind::ConsentClass
            && row.jurisdiction != JURISDICTION_NONE
            && pack.exemption_evidence(&row.jurisdiction).is_none()
    });
    if unbound.is_some() {
        return Err(invalid_pack(
            "conditional consent-class row has no declared exemption evidence",
        ));
    }
    Ok(())
}

pub(super) fn invalid_pack(message: &str) -> Error {
    Error::InvalidConfig(format!("campaign compliance pack: {message}"))
}

/// The ACTIVE pack, or the embedded seed when the vault holds none.
///
/// # Errors
///
/// Storage errors, and [`Error::CorruptedIndex`] when the stored row cannot be
/// decoded.
pub fn load_active_compliance_pack(vault: &Vault) -> Result<CompliancePack> {
    let rtxn = vault.store.env.read_txn()?;
    active_compliance_pack_in_txn(&vault.store, &rtxn)
}

pub(super) fn active_compliance_pack_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<CompliancePack> {
    match store.vault_meta.get(txn, CAMPAIGN_COMPLIANCE_META_KEY)? {
        Some(raw) => decode_pack(&raw, "campaign compliance active pack"),
        None => embedded_seed_pack(),
    }
}

/// The ONLY writer of the active pack, and deliberately private: the public
/// path is the versioned amendment transaction, which cannot be bypassed.
pub(super) fn store_active_compliance_pack(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    pack: &CompliancePack,
) -> Result<()> {
    validate_compliance_pack(pack)?;
    let encoded = encode_pack(pack)?;
    store
        .vault_meta
        .put(wtxn, CAMPAIGN_COMPLIANCE_META_KEY, &encoded)?;
    Ok(())
}

pub(super) fn encode_pack(pack: &CompliancePack) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(pack)
        .map_err(|_| Error::InvariantViolation("campaign compliance pack encode failed"))
}

pub(super) fn decode_pack(raw: &[u8], label: &'static str) -> Result<CompliancePack> {
    rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex(label))
}
