//! Builds a remote rung with a nonblocking host egress predicate.
use super::admitted::AdmittedRequests;
use super::endpoint::HttpEmbedder;
use super::local::evidence::RunProfile;
use crate::config::{EmbedderConfig, remote_embedder::EgressPolicy};
use oneiron::embed::{EgressDecision, EgressPredicate, PendingEmbeddingInput, RemoteRung};
use oneiron::llm::run_admission::RunReceiptSink;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

/// What a remote rung's answers are held to: the vault's space as the vault
/// admitted it from its own provider.
#[derive(Clone, Debug, Default)]
pub(crate) struct RungHold {
    /// The transform the vault admitted, if its provider named one.
    pub(crate) transform: Option<String>,
    /// The vault judges evidence by its model's measured floors, which hold
    /// only for the profile they were measured under ([`RunProfile`]).
    pub(crate) measured: bool,
}

impl RungHold {
    /// Whether an answer a rung returned for `model_id` stays in the vault's
    /// space: what it names of the model it loaded, its transform and its
    /// profile is what the vault admitted. A server that names none, any
    /// other OpenAI server, is held to the configured model's promise alone.
    pub(crate) fn holds(
        &self,
        model_id: &str,
        named_model: Option<&str>,
        named_transform: Option<&str>,
        named_profile: Option<&serde_json::Value>,
    ) -> bool {
        let measured_profile = |profile: &serde_json::Value| {
            serde_json::from_value::<RunProfile>(profile.clone())
                .is_ok_and(|profile| profile.is_measured())
        };
        named_model.is_none_or(|named| named == model_id)
            && named_transform.is_none_or(|named| Some(named) == self.transform.as_deref())
            && (!self.measured || named_profile.is_none_or(measured_profile))
    }
}

struct ConfiguredEgress {
    allow: HashSet<oneiron::EntityId>,
    deny: HashSet<oneiron::EntityId>,
    allow_all: bool,
}
impl ConfiguredEgress {
    fn new(policy: &EgressPolicy) -> oneiron::Result<Self> {
        Ok(Self {
            allow: policy
                .allow
                .iter()
                .map(|id| oneiron::EntityId::from_hex(id))
                .collect::<oneiron::Result<_>>()?,
            deny: policy
                .deny
                .iter()
                .map(|id| oneiron::EntityId::from_hex(id))
                .collect::<oneiron::Result<_>>()?,
            allow_all: policy.allow_all,
        })
    }
}
impl EgressPredicate for ConfiguredEgress {
    fn decide(&self, input: &PendingEmbeddingInput) -> EgressDecision {
        if self.deny.contains(&input.entity_id) {
            EgressDecision::Deny
        } else if self.allow_all || self.allow.contains(&input.entity_id) {
            EgressDecision::Allow
        } else {
            EgressDecision::NoVerdict
        }
    }
}

/// The per-row egress list `primary`'s remote rung configures, if it
/// configures one: the one host verdict on which rows may leave for a model
/// off this device, which the GPU pool's batches are judged by too
/// (FIX 9486). With `None`, the world release alone judges a pod's rows.
pub(crate) fn configured_egress(
    primary: &EmbedderConfig,
) -> oneiron::Result<Option<Arc<dyn EgressPredicate>>> {
    let Some(policy) = primary
        .remote
        .as_ref()
        .and_then(|remote| remote.egress.as_ref())
    else {
        return Ok(None);
    };
    Ok(Some(Arc::new(ConfiguredEgress::new(policy)?)))
}

/// The remote rung `primary` configures, if any. Its answers are held to the
/// vault's model and to `hold`, the space the vault admits from the primary
/// provider ([`HttpEmbedder::hold_as_rung`]). Each embedding request it sends
/// is admitted and settled as a paid call, its rows written to `receipts`.
pub(crate) fn build_remote_rung(
    primary: &EmbedderConfig,
    hold: Arc<Mutex<RungHold>>,
    receipts: Arc<dyn RunReceiptSink>,
) -> oneiron::Result<Option<RemoteRung>> {
    build_remote_rung_with_broker(primary, hold, receipts, None)
}

/// [`build_remote_rung`], with the vault's credential-broker context a
/// `key_secret` rung sends through, request by request.
pub(crate) fn build_remote_rung_with_broker(
    primary: &EmbedderConfig,
    hold: Arc<Mutex<RungHold>>,
    receipts: Arc<dyn RunReceiptSink>,
    broker: Option<&crate::models::BrokerContext>,
) -> oneiron::Result<Option<RemoteRung>> {
    crate::config::remote_embedder::validate_remote(primary)?;
    let Some(config) = &primary.remote else {
        return Ok(None);
    };
    let policy = config.egress.as_ref().ok_or_else(|| {
        oneiron::Error::InvalidConfig("remote rung missing egress predicate".into())
    })?;
    let embedder = HttpEmbedder::with_broker(&config.endpoint_config(primary), broker)?;
    embedder.hold_as_rung(hold);
    embedder.pay_through(Arc::new(AdmittedRequests::unmetered(
        config,
        oneiron::embed::Embedder::locality(&*embedder),
        receipts,
    )?));
    let mut rung = RemoteRung::new(embedder, Arc::new(ConfiguredEgress::new(policy)?));
    rung.lease_duration_ms = config.lease_ms;
    Ok(Some(rung))
}
