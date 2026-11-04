//! Builds a remote rung with a nonblocking host egress predicate.
use super::admitted::AdmittedRequests;
use super::endpoint::HttpEmbedder;
use super::local::evidence::RunProfile;
use crate::config::EmbedderConfig;
use crate::config::remote_embedder::{EgressPolicy, RemoteEvidenceRule};
use oneiron::embed::{
    EgressDecision, EgressPredicate, EmbedderLocality, PendingEmbeddingInput, RemoteRung,
};
use oneiron::llm::run_admission::{RunReceiptSink, offer_id, offer_place};
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
        named_model.is_none_or(|named| named == model_id)
            && named_transform.is_none_or(|named| Some(named) == self.transform.as_deref())
            && (!self.measured || named_profile.is_none_or(names_measured_profile))
    }
}

/// Whether `profile`, as an answer names it, is a measured run profile ([`RunProfile`]).
fn names_measured_profile(profile: &serde_json::Value) -> bool {
    serde_json::from_value::<RunProfile>(profile.clone()).is_ok_and(|profile| profile.is_measured())
}

/// The owner's egress rule as a remote rung reads it: which rows may leave, and what the
/// rung's answers must show (FIX 9488).
#[derive(Debug)]
pub(crate) struct ConfiguredEgress {
    allow: HashSet<oneiron::EntityId>,
    deny: HashSet<oneiron::EntityId>,
    allow_all: bool,
    remote_evidence: Option<RemoteEvidenceRule>,
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
            remote_evidence: policy.remote_evidence,
        })
    }

    /// Whether an answer that names `profile` meets the owner's evidence rule (FIX 9488):
    /// [`RemoteEvidenceRule::MeasuredProfile`] asks, where the model's measured floors hold,
    /// for a named profile that is the measured one. No rule asks nothing.
    pub(crate) fn admits_profile(
        &self,
        profile: Option<&serde_json::Value>,
        measured_floors: bool,
    ) -> bool {
        match self.remote_evidence {
            None => true,
            Some(RemoteEvidenceRule::MeasuredProfile) => {
                !measured_floors || profile.is_some_and(names_measured_profile)
            }
        }
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
    // One rule judges which rows the rung is sent and what its answers show (FIX 9488).
    let egress = Arc::new(ConfiguredEgress::new(policy)?);
    let embedder = HttpEmbedder::with_broker(&config.endpoint_config(primary), broker)?;
    embedder.hold_as_rung(hold, Arc::clone(&egress));
    embedder.pay_through(Arc::new(AdmittedRequests::unmetered(
        config,
        oneiron::embed::Embedder::locality(&*embedder),
        receipts,
    )?));
    let mut rung = RemoteRung::new(embedder, egress);
    rung.lease_duration_ms = config.lease_ms;
    // The rung's full `model@place` route id (FIX 11768 seam for L05),
    // minted through the one producer from its space id and its
    // endpoint's origin — the same resolution the ladder's doors judge. A
    // rung whose id cannot be minted carries none, and no ordered world
    // admits it.
    if let (Ok(model), Ok(url)) = (
        oneiron::ModelId::new(oneiron::embed::Embedder::model_id(&*rung.embedder)),
        reqwest::Url::parse(&config.endpoint),
    ) {
        let locality = match oneiron::embed::Embedder::locality(&*rung.embedder) {
            EmbedderLocality::OnDevice => oneiron::ModelLocality::OnDevice,
            EmbedderLocality::OwnerServer => oneiron::ModelLocality::OwnServer,
            EmbedderLocality::ThirdParty => oneiron::ModelLocality::ThirdParty,
        };
        let place = offer_place(locality, &url.origin().ascii_serialization());
        rung.offer_id = Some(offer_id(&model, &place));
    }
    Ok(Some(rung))
}
