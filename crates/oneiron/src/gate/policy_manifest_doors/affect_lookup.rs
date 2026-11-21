//! The coping lookup's tunables in the owner-trusted default manifest
//! (canon `manifest:affect_lookup`: "the nearest-state metric ... and the
//! outcome count below which the ledger answers from generic regulation
//! priors ... These are tunable starting values, not engine constants").
//! An absent row reads as the starting values.
use oneiron_contracts::fingerprint::ContentHash;
use serde::{Deserialize, Serialize};

use super::{body_in_txn, decode_fields, invalid, rewrite_default_manifest_field_as_owner_in_txn};
use crate::consent::AuthenticatedOwner;
use crate::{Error, Result, Vault};

pub(crate) const AFFECT_LOOKUP_KEY: &str = "affect_lookup";

/// The starting value of `cold_start_min_outcomes`; canon names no number.
const AFFECT_LOOKUP_COLD_START_MIN_OUTCOMES: u64 = 3;

/// How the coping lookup finds "this state".
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum NearestStateMetric {
    /// Euclidean distance over the canonical (valence, arousal, dominance)
    /// floats.
    #[default]
    PadDistance,
}

/// Manifest `affect_lookup`: the coping-ledger metric and cold-start gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AffectLookupPolicy {
    pub nearest_state_metric: NearestStateMetric,
    /// Below this many observed outcomes the lookup answers generic
    /// regulation priors at low confidence; 0 never does.
    pub cold_start_min_outcomes: u64,
}

impl Default for AffectLookupPolicy {
    fn default() -> Self {
        Self {
            nearest_state_metric: NearestStateMetric::PadDistance,
            cold_start_min_outcomes: AFFECT_LOOKUP_COLD_START_MIN_OUTCOMES,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AffectLookupConfigureRequest {
    pub expected_body_hash: String,
    pub policy: AffectLookupPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AffectLookupView {
    pub manifest_ref: String,
    pub body_hash: String,
    /// The stored row, or the starting values when the manifest has none.
    pub policy: AffectLookupPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AffectLookupReceipt {
    pub configuration: AffectLookupView,
    pub receipt_ref: String,
}

pub(crate) fn decode_affect_lookup(
    fields: &[(rmpv::Value, rmpv::Value)],
) -> Result<Option<AffectLookupPolicy>> {
    let mut rows = fields
        .iter()
        .filter(|(key, _)| key.as_str() == Some(AFFECT_LOOKUP_KEY));
    let Some((_, value)) = rows.next() else {
        return Ok(None);
    };
    if rows.next().is_some() {
        return Err(invalid("duplicate affect_lookup"));
    }
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).map_err(|_| invalid("affect lookup encoding"))?;
    rmp_serde::from_slice(&bytes)
        .map(Some)
        .map_err(|_| invalid("invalid affect lookup"))
}

/// The tunables a coping lookup reads, in the lookup's own snapshot. A vault
/// with no default manifest, or a manifest with no row, reads the starting
/// values; a default manifest the owner does not trust is refused, as the
/// retrieval priors refuse it.
pub(crate) fn affect_lookup_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<AffectLookupPolicy> {
    let id = crate::gate::default_policy_manifest_id()?;
    let Some(body) = body_in_txn(vault, txn, id)? else {
        return Ok(AffectLookupPolicy::default());
    };
    if !crate::gate::manifest_authenticity::manifest_is_trusted(&vault.store, txn, &id, &body)? {
        return Err(invalid(
            "the affect lookup requires an owner-trusted manifest",
        ));
    }
    Ok(decode_affect_lookup(&decode_fields(&body)?)?.unwrap_or_default())
}

fn view(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<AffectLookupView> {
    let id = crate::gate::default_policy_manifest_id()?;
    let body = body_in_txn(vault, txn, id)?.ok_or(Error::EntityNotFound)?;
    if !crate::gate::manifest_authenticity::manifest_is_trusted(&vault.store, txn, &id, &body)? {
        return Err(invalid(
            "the affect lookup requires an owner-trusted manifest",
        ));
    }
    Ok(AffectLookupView {
        manifest_ref: id.to_hex(),
        body_hash: ContentHash::of(&body).to_hex(),
        policy: decode_affect_lookup(&decode_fields(&body)?)?.unwrap_or_default(),
    })
}

/// Read the effective tunables and the default manifest's edit precondition.
pub fn affect_lookup_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
) -> Result<AffectLookupView> {
    let txn = vault.store.env.read_txn()?;
    owner.revalidate_in_txn(vault, &txn)?;
    view(vault, &txn)
}

/// Replace only this row through the native owner writer and receipt ledger.
pub fn configure_affect_lookup_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: AffectLookupConfigureRequest,
) -> Result<AffectLookupReceipt> {
    let receipt = vault.with_write_txn_grouped(|txn| {
        owner.revalidate_in_txn(vault, txn)?;
        if view(vault, txn)?.body_hash != input.expected_body_hash {
            return Err(invalid(
                "expected_body_hash must match the current policy manifest",
            ));
        }
        let replacement = rmp_serde::to_vec_named(&input.policy)
            .map_err(|_| invalid("affect lookup encoding"))?;
        let value = rmpv::decode::read_value(&mut std::io::Cursor::new(replacement))
            .map_err(|_| invalid("affect lookup encoding"))?;
        let receipt_ref = rewrite_default_manifest_field_as_owner_in_txn(
            vault,
            owner,
            txn,
            AFFECT_LOOKUP_KEY,
            |_| Ok(value),
            "gate.allow.owner_affect_lookup",
        )?;
        Ok(AffectLookupReceipt {
            configuration: view(vault, txn)?,
            receipt_ref,
        })
    })?;
    vault.apply_pending_rebinds_after_commit();
    Ok(receipt)
}
