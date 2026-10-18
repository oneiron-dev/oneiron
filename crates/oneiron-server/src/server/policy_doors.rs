//! Host bindings for the public content-policy doors. No request installs these.
use std::sync::Arc;

use oneiron::policy_model::{
    AttestedRelayDomain, AuthenticatedConnectionIdentity, EdgeServiceRegistry, PolicyModelConfig,
    VaultSideVerdictSource,
};

use super::SyncServer;

#[derive(Default)]
pub(crate) struct PolicyDoors {
    pub(crate) owner: PolicyModelConfig,
    pub(crate) relay: Option<HostedPolicyRelay>,
}

/// A hosted relay's identity and policy, bound before its routes are served.
/// There is deliberately no constructor from a service label or an HTTP body.
pub struct HostedPolicyRelay {
    pub(crate) domain: AttestedRelayDomain,
    pub(crate) registry: EdgeServiceRegistry,
    pub(crate) config: PolicyModelConfig,
    pub(crate) verdicts: Arc<dyn VaultSideVerdictSource + Send + Sync>,
    pub(crate) unavailable_notice: String,
}

impl HostedPolicyRelay {
    /// Bind an identity already proved by connector-edge authentication.
    /// A hosted door always fails closed and offers the host's local-model path.
    pub fn new(
        identity: &AuthenticatedConnectionIdentity,
        registry: EdgeServiceRegistry,
        config: PolicyModelConfig,
        verdicts: Arc<dyn VaultSideVerdictSource + Send + Sync>,
        unavailable_notice: String,
    ) -> oneiron::Result<Self> {
        let domain = AttestedRelayDomain::from_connection_identity(identity);
        oneiron::policy_model::doors::validate_hosted_relay_notice(&config, &unavailable_notice)?;
        if registry
            .hosted_legal_policy(domain.service_identity())
            .is_none()
        {
            return Err(oneiron::Error::InvalidConfig(
                "no hosted policy is bound to the attested relay".to_owned(),
            ));
        }
        Ok(Self {
            domain,
            registry,
            config,
            verdicts,
            unavailable_notice,
        })
    }
}

impl SyncServer {
    /// The owner's notice wording, classifier dial and model binding are host configuration.
    #[must_use]
    pub fn with_owner_policy_config(mut self, config: PolicyModelConfig) -> Self {
        self.policy_doors.owner = config;
        self
    }

    /// Attach only an already-attested hosted relay; absent bindings refuse the door.
    #[must_use]
    pub fn with_hosted_policy_relay(mut self, relay: HostedPolicyRelay) -> Self {
        self.policy_doors.relay = Some(relay);
        self
    }
}
