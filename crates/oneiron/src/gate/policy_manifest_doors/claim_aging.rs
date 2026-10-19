//! Owner-configured class aging in the existing trusted default policy manifest.
use serde::{Deserialize, Serialize};

use super::{body_in_txn, decode_fields, encode_fields, invalid, record};
use crate::claim::ClaimAgingProfiles;
use crate::consent::AuthenticatedOwner;
use crate::{EdgeActorClass, Error, Result, Vault, WriteActor};

pub(crate) const CLAIM_AGING_PROFILES_KEY: &str = "claim_aging_profiles";

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimAgingProfilesConfigureRequest {
    pub expected_body_hash: String,
    pub profiles: ClaimAgingProfiles,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClaimAgingProfilesView {
    pub manifest_ref: String,
    pub body_hash: String,
    pub profiles: ClaimAgingProfiles,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClaimAgingProfilesReceipt {
    pub configuration: ClaimAgingProfilesView,
    pub receipt_ref: String,
}

pub(crate) fn decode_claim_aging_profiles(
    fields: &[(rmpv::Value, rmpv::Value)],
) -> Result<Option<ClaimAgingProfiles>> {
    let mut rows = fields
        .iter()
        .filter(|(key, _)| key.as_str() == Some(CLAIM_AGING_PROFILES_KEY));
    let Some((_, value)) = rows.next() else {
        return Ok(None);
    };
    if rows.next().is_some() {
        return Err(invalid("duplicate claim_aging_profiles"));
    }
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value)
        .map_err(|_| invalid("claim aging profiles encoding"))?;
    let profiles: ClaimAgingProfiles =
        rmp_serde::from_slice(&bytes).map_err(|_| invalid("invalid claim aging profiles"))?;
    profiles.validate()?;
    Ok(Some(profiles))
}

fn view(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<ClaimAgingProfilesView> {
    let id = crate::gate::default_policy_manifest_id()?;
    let body = body_in_txn(vault, txn, id)?.ok_or(Error::EntityNotFound)?;
    if !crate::gate::manifest_authenticity::manifest_is_trusted(&vault.store, txn, &id, &body)? {
        return Err(invalid(
            "claim aging profiles require an owner-trusted manifest",
        ));
    }
    Ok(ClaimAgingProfilesView {
        manifest_ref: id.to_hex(),
        body_hash: blake3::hash(&body).to_hex().to_string(),
        profiles: decode_claim_aging_profiles(&decode_fields(&body)?)?.unwrap_or_default(),
    })
}

/// Freeze the effective profiles once for every pass, trace and score in a run.
pub(crate) fn claim_aging_profiles_for_run(vault: &Vault) -> Result<ClaimAgingProfiles> {
    let txn = vault.store.env.read_txn()?;
    Ok(view(vault, &txn)?.profiles)
}

pub fn claim_aging_profiles_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
) -> Result<ClaimAgingProfilesView> {
    let txn = vault.store.env.read_txn()?;
    owner.revalidate_in_txn(vault, &txn)?;
    view(vault, &txn)
}

/// Validation, owner revalidation, compare-and-set, write and receipt share one writer.
pub fn configure_claim_aging_profiles_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: ClaimAgingProfilesConfigureRequest,
) -> Result<ClaimAgingProfilesReceipt> {
    vault.with_write_txn_grouped(|txn| {
        let actor = owner.revalidate_in_txn(vault, txn)?;
        input.profiles.validate()?;
        let current = view(vault, txn)?;
        if current.body_hash != input.expected_body_hash {
            return Err(invalid(
                "expected_body_hash must match the current policy manifest",
            ));
        }
        let id = crate::gate::default_policy_manifest_id()?;
        let body = body_in_txn(vault, txn, id)?.ok_or(Error::EntityNotFound)?;
        let mut fields = decode_fields(&body)?;
        fields.retain(|(key, _)| key.as_str() != Some(CLAIM_AGING_PROFILES_KEY));
        let replacement = rmp_serde::to_vec_named(&input.profiles)
            .map_err(|_| invalid("claim aging profiles encoding"))?;
        let value = rmpv::decode::read_value(&mut std::io::Cursor::new(replacement))
            .map_err(|_| invalid("claim aging profiles encoding"))?;
        fields.push((rmpv::Value::from(CLAIM_AGING_PROFILES_KEY), value));
        vault.write_owner_policy_manifest_in_txn(
            owner,
            txn,
            id,
            encode_fields(fields)?,
            crate::unix_seconds_now(),
        )?;
        let body = body_in_txn(vault, txn, id)?.ok_or(Error::EntityNotFound)?;
        let receipt_ref = record(
            vault,
            txn,
            WriteActor::new(actor, EdgeActorClass::Human),
            id,
            &body,
            (
                "allow",
                vec!["gate.allow.owner_claim_aging_profiles".to_owned()],
            ),
        )?;
        Ok(ClaimAgingProfilesReceipt {
            configuration: view(vault, txn)?,
            receipt_ref,
        })
    })
}
