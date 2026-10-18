//! The owner's content-policy configuration, kept in the existing default manifest.
use serde::{Deserialize, Serialize};

use super::{body_in_txn, decode_fields, encode_fields, hex, invalid, record};
use crate::consent::AuthenticatedOwner;
use crate::gate::{self, resolve_policy_manifest};
use crate::policy_model::{PolicyOutputContract, PolicyPatternRule};
use crate::{EdgeActorClass, Error, Result, Vault, WriteActor};

const FIELDS: &[&str] = &[
    "owner_policy_enabled",
    "owner_policy_document",
    "owner_policy_output_contract",
    "owner_policy_patterns",
];

#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OwnerPolicyConfiguration {
    #[serde(default)]
    pub owner_policy_enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_policy_document: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_policy_output_contract: Option<PolicyOutputContract>,
    #[serde(default)]
    pub owner_policy_patterns: Vec<PolicyPatternRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OwnerPolicyConfigureRequest {
    pub expected_body_hash: String,
    pub configuration: OwnerPolicyConfiguration,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OwnerPolicyConfigurationView {
    pub manifest_ref: String,
    pub body_hash: String,
    pub read_frontier_hash: String,
    /// The folded plane state, including other trusted contributions.
    pub enabled: bool,
    pub configuration: OwnerPolicyConfiguration,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OwnerPolicyConfigurationReceipt {
    pub configuration: OwnerPolicyConfigurationView,
    pub receipt_ref: String,
}

fn view(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<OwnerPolicyConfigurationView> {
    let id = gate::default_policy_manifest_id()?;
    let body = body_in_txn(vault, txn, id)?.ok_or(Error::EntityNotFound)?;
    let fields = decode_fields(&body)?.into_iter().filter(|(key, _)| {
        key.as_str().is_some_and(|key| FIELDS.contains(&key))
    }).collect();
    let configuration = rmp_serde::from_slice(&encode_fields(fields)?)
        .map_err(|_| invalid("owner policy configuration does not decode"))?;
    let policy = resolve_policy_manifest(&vault.store, txn)?;
    Ok(OwnerPolicyConfigurationView {
        manifest_ref: id.to_hex(),
        body_hash: blake3::hash(&body).to_hex().to_string(),
        read_frontier_hash: hex(&policy.read_frontier_hash()?),
        enabled: policy.owner_policy_enabled(),
        configuration,
    })
}

/// Read the owner's configured plane, not a second settings store.
pub fn owner_policy_configuration(
    vault: &Vault,
    owner: &AuthenticatedOwner,
) -> Result<OwnerPolicyConfigurationView> {
    let txn = vault.store.env.read_txn()?;
    owner.revalidate_in_txn(vault, &txn)?;
    view(vault, &txn)
}

/// Replace only content-policy settings through the existing authenticated writer.
pub fn configure_owner_policy(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: OwnerPolicyConfigureRequest,
) -> Result<OwnerPolicyConfigurationReceipt> {
    vault.with_write_txn_grouped(|txn| {
        let actor = owner.revalidate_in_txn(vault, txn)?;
        let id = gate::default_policy_manifest_id()?;
        let body = body_in_txn(vault, txn, id)?.ok_or(Error::EntityNotFound)?;
        if blake3::hash(&body).to_hex().as_str() != input.expected_body_hash {
            return Err(invalid("expected_body_hash must match the current policy manifest"));
        }
        if !gate::manifest_authenticity::manifest_is_trusted(&vault.store, txn, &id, &body)? {
            return Err(invalid("the default policy manifest is not owner trusted"));
        }
        let config = &input.configuration;
        if config.owner_policy_document.is_some() != config.owner_policy_output_contract.is_some() {
            return Err(invalid("a policy document and output contract must be supplied together"));
        }
        let mut fields = decode_fields(&body)?;
        fields.retain(|(key, _)| !key.as_str().is_some_and(|key| FIELDS.contains(&key)));
        let replacement = rmp_serde::to_vec_named(config)
            .map_err(|_| invalid("owner policy configuration does not encode"))?;
        fields.extend(decode_fields(&replacement)?);
        let data = encode_fields(fields)?;
        let decoded = gate::decode::decode_policy_manifest(&data)
            .ok_or_else(|| invalid("invalid owner policy configuration"))?;
        if decoded.unsupported_schema || decoded.engine_version_floor
            || decoded.owner_policy_patterns_dropped || decoded.owner_policy_rows_dropped {
            return Err(invalid("invalid owner policy configuration"));
        }
        crate::policy_model::doors::validate_owner_patterns(
            &config.owner_policy_patterns,
            &decoded.owner_policy_rows.iter().map(|row| row.row_ref.clone()).collect::<Vec<_>>(),
        )?;
        vault.write_owner_policy_manifest_in_txn(owner, txn, id, data, crate::unix_seconds_now())?;
        let body = body_in_txn(vault, txn, id)?.ok_or(Error::EntityNotFound)?;
        let receipt_ref = record(vault, txn, WriteActor::new(actor, EdgeActorClass::Human),
            id, &body, ("allow", vec!["gate.allow.owner_content_policy_configuration".to_owned()]))?;
        Ok(OwnerPolicyConfigurationReceipt { configuration: view(vault, txn)?, receipt_ref })
    })
}
