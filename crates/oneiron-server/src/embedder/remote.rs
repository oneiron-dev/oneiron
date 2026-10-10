//! Builds a remote rung with a nonblocking host egress predicate.
use super::endpoint::HttpEmbedder;
use crate::config::{EmbedderConfig, remote_embedder::EgressPolicy};
use oneiron::embed::{EgressDecision, EgressPredicate, PendingEmbeddingInput, RemoteRung};
use std::{collections::HashSet, sync::Arc};

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

/// The remote rung `primary` configures, if any. Its answers are held to the
/// vault's model and to `transform`, the one the vault admitted from the
/// primary provider ([`HttpEmbedder::hold_as_rung`]).
pub(crate) fn build_remote_rung(
    primary: &EmbedderConfig,
    transform: Option<String>,
) -> oneiron::Result<Option<RemoteRung>> {
    crate::config::remote_embedder::validate_remote(primary)?;
    let Some(config) = &primary.remote else {
        return Ok(None);
    };
    let policy = config.egress.as_ref().ok_or_else(|| {
        oneiron::Error::InvalidConfig("remote rung missing egress predicate".into())
    })?;
    let embedder = HttpEmbedder::from_config(&config.endpoint_config(primary))?;
    embedder.hold_as_rung(transform);
    let mut rung = RemoteRung::new(embedder, Arc::new(ConfiguredEgress::new(policy)?));
    rung.lease_duration_ms = config.lease_ms;
    Ok(Some(rung))
}
