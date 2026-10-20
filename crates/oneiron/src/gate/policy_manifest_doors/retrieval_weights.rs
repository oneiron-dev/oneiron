//! Owner-configured retrieval priors in the existing trusted default manifest.
use serde::{Deserialize, Serialize};

use super::{body_in_txn, decode_fields, encode_fields, invalid, record};
use crate::consent::AuthenticatedOwner;
use crate::{EdgeActorClass, Error, Result, Vault, WriteActor};

pub(crate) const RETRIEVAL_WEIGHTS_KEY: &str = "retrieval_weights";

/// Independent, default-off read-side priors. None changes claim truth or authority.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetrievalWeights {
    /// Emotion congruence, in 0..=0.4.
    pub affect: f32,
    /// Arousal half-life stretch, in 0..=4.
    pub arousal: f32,
    /// Nonnegative community beta; the existing community safety caps still apply.
    pub community: f32,
    /// Stored semantic-edge VAD salience for PPR, in 0..=0.4.
    pub vad: f32,
}

impl RetrievalWeights {
    fn from_config(config: &crate::config::VaultConfig) -> Self {
        Self {
            affect: config.affect_retrieval.emotion_weight,
            arousal: config.affect_retrieval.arousal_stretch,
            community: config.ppr_community.beta,
            vad: config.ppr_vad_alpha,
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        crate::pipeline::AffectRetrievalPolicy {
            emotion_weight: self.affect,
            arousal_stretch: self.arousal,
            ..Default::default()
        }
        .validate()?;
        crate::config::validate_ppr_vad_alpha(self.vad)?;
        crate::config::validate_ppr_community(&crate::config::PprCommunityConfig {
            beta: self.community,
            ..Default::default()
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetrievalWeightsConfigureRequest {
    pub expected_body_hash: String,
    pub weights: RetrievalWeights,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalWeightsView {
    pub manifest_ref: String,
    pub body_hash: String,
    pub weights: RetrievalWeights,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalWeightsReceipt {
    pub configuration: RetrievalWeightsView,
    pub receipt_ref: String,
}

pub(crate) fn decode_retrieval_weights(
    fields: &[(rmpv::Value, rmpv::Value)],
) -> Result<Option<RetrievalWeights>> {
    let mut rows = fields
        .iter()
        .filter(|(key, _)| key.as_str() == Some(RETRIEVAL_WEIGHTS_KEY));
    let Some((_, value)) = rows.next() else {
        return Ok(None);
    };
    if rows.next().is_some() {
        return Err(invalid("duplicate retrieval_weights"));
    }
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value)
        .map_err(|_| invalid("retrieval weights encoding"))?;
    let weights: RetrievalWeights =
        rmp_serde::from_slice(&bytes).map_err(|_| invalid("invalid retrieval weights"))?;
    weights.validate()?;
    Ok(Some(weights))
}

/// One serving run reads its priors once, from the owner's trusted manifest.
/// An absent row leaves the host's existing runtime configuration unchanged.
pub(crate) fn retrieval_weights_for_run(vault: &Vault) -> Result<Option<RetrievalWeights>> {
    let txn = vault.store.env.read_txn()?;
    let id = crate::gate::default_policy_manifest_id()?;
    let Some(body) = body_in_txn(vault, &txn, id)? else {
        return Ok(None);
    };
    if !crate::gate::manifest_authenticity::manifest_is_trusted(&vault.store, &txn, &id, &body)? {
        return Err(invalid(
            "retrieval weights require an owner-trusted manifest",
        ));
    }
    decode_retrieval_weights(&decode_fields(&body)?)
}

fn view(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<RetrievalWeightsView> {
    let id = crate::gate::default_policy_manifest_id()?;
    let body = body_in_txn(vault, txn, id)?.ok_or(Error::EntityNotFound)?;
    if !crate::gate::manifest_authenticity::manifest_is_trusted(&vault.store, txn, &id, &body)? {
        return Err(invalid(
            "retrieval weights require an owner-trusted manifest",
        ));
    }
    let weights = decode_retrieval_weights(&decode_fields(&body)?)?
        .unwrap_or_else(|| RetrievalWeights::from_config(&vault.config));
    Ok(RetrievalWeightsView {
        manifest_ref: id.to_hex(),
        body_hash: blake3::hash(&body).to_hex().to_string(),
        weights,
    })
}

pub fn retrieval_weights_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
) -> Result<RetrievalWeightsView> {
    let txn = vault.store.env.read_txn()?;
    owner.revalidate_in_txn(vault, &txn)?;
    view(vault, &txn)
}

/// Only this manifest field is replaced, through the existing owner writer and receipt ledger.
pub fn configure_retrieval_weights_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: RetrievalWeightsConfigureRequest,
) -> Result<RetrievalWeightsReceipt> {
    input.weights.validate()?;
    let receipt = vault.with_write_txn_grouped(|txn| {
        let actor = owner.revalidate_in_txn(vault, txn)?;
        let current = view(vault, txn)?;
        if current.body_hash != input.expected_body_hash {
            return Err(invalid(
                "expected_body_hash must match the current policy manifest",
            ));
        }
        let id = crate::gate::default_policy_manifest_id()?;
        let body = body_in_txn(vault, txn, id)?.ok_or(Error::EntityNotFound)?;
        let mut fields = decode_fields(&body)?;
        fields.retain(|(key, _)| key.as_str() != Some(RETRIEVAL_WEIGHTS_KEY));
        let replacement = rmp_serde::to_vec_named(&input.weights)
            .map_err(|_| invalid("retrieval weights encoding"))?;
        let value = rmpv::decode::read_value(&mut std::io::Cursor::new(replacement))
            .map_err(|_| invalid("retrieval weights encoding"))?;
        fields.push((rmpv::Value::from(RETRIEVAL_WEIGHTS_KEY), value));
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
                vec!["gate.allow.owner_retrieval_weights".to_owned()],
            ),
        )?;
        Ok(RetrievalWeightsReceipt {
            configuration: view(vault, txn)?,
            receipt_ref,
        })
    })?;
    // A floor this commit moved is judged again at once (FIX 5505).
    vault.apply_pending_rebinds_after_commit();
    Ok(receipt)
}
