//! Sealed identity and witness chain: trust domains, connection class, edge-auth mint, attested domain, hosted attestation.

use serde::Serialize;

use crate::error::{Error, Result};

use super::registry::EdgeServiceRegistry;
use crate::error::RelayError;

/// Trust domain of a relay-boundary pass.
///
/// The hosted relay / connector edge MUST derive this from the connection's
/// infrastructure trust domain, NEVER from a vault-attested "already
/// classified" receipt.
///
/// Intentionally `Serialize` but NOT `Deserialize`: this must never be decoded
/// from the wire. A future protocol carrying `"trust_domain":"cloud_vault"`
/// parsed from vault-supplied bytes would be exactly the vault-attested-receipt
/// bypass in a different coat — the trust domain is established by our
/// infrastructure, so it is emitted (receipts/logs) but never accepted inbound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayTrustDomain {
    /// Cloud vault: content was classified vault-side on our infra; the relay
    /// independently attests the domain, recomputes the verification hash, and
    /// compares the stored content and read-frontier hashes (plus the
    /// safeguard selector) — and, where a hosted legal policy is bound to the
    /// attested identity, requires the receipt to attest that policy's version
    /// and hash. A fully verified `Allow` trusts the vault-side pass, a
    /// verified non-`Allow` is returned as it stands, and anything untrusted
    /// falls back to a hosted pass and audits the breach.
    CloudVault,
    /// Local/self-host vault whose outbound transits an Oneiron-hosted
    /// connector. Our infra relays the content, so the hosted legal plane runs
    /// at the boundary.
    LocalViaHostedConnector,
    /// Local/self-host vault using its own connector: nothing transits us, so
    /// nothing of ours evaluates it.
    LocalViaByoConnector,
}

impl RelayTrustDomain {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CloudVault => "cloud_vault",
            Self::LocalViaHostedConnector => "local_via_hosted_connector",
            Self::LocalViaByoConnector => "local_via_byo_connector",
        }
    }
}

/// Connection class of a connector-edge-authenticated peer, established by the
/// edge auth layer once bearer verification settles. The class decides which
/// [`RelayTrustDomain`] the connection's content may be attested under. There
/// is deliberately NO BYO class: a BYO connector never transits our
/// infrastructure, so it never authenticates to our edge and can never hold an
/// identity here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectionClass {
    /// First-party cloud-vault peer: content was classified vault-side on our
    /// infra.
    CloudVaultPeer,
    /// Local/self-host vault whose outbound transits an Oneiron-hosted
    /// connector: our infra relays the content and runs the hosted pass.
    LocalVaultViaHostedConnector,
}

impl ConnectionClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CloudVaultPeer => "cloud_vault_peer",
            Self::LocalVaultViaHostedConnector => "local_vault_via_hosted_connector",
        }
    }
}

/// Grammar prefix every connector-edge service identity must carry.
pub(super) const EDGE_SERVICE_IDENTITY_PREFIX: &str = "connector-edge:";

/// Connection identity as established by connector-edge auth. Sealed:
/// constructible only through the edge-auth path, which validates the
/// service-identity grammar and the identity/class consistency against the
/// caller-supplied registry — and which is `pub(crate)` until the real edge
/// wiring lands, so no downstream crate can fabricate an identity from public
/// labels. Never parsed from vault bytes and never carries token material: the
/// bearer is verified at the edge BEFORE this constructor is called.
#[derive(Debug)]
pub struct AuthenticatedConnectionIdentity {
    service_identity: String,
    connection_class: ConnectionClass,
}

impl AuthenticatedConnectionIdentity {
    /// The ONLY constructor — owned by connector-edge auth. Validates the
    /// `connector-edge:<name>` grammar (non-empty name) and that `class`
    /// matches the service identity's class in `registry`.
    ///
    /// `pub(crate)` on purpose: the pair `(service_identity, class)` is
    /// caller-supplied, so a PUBLIC constructor would let any downstream crate
    /// mint the strongest registered identity from public labels — a name is
    /// not a capability boundary. Until the connector-edge wiring lands, the
    /// mint is reachable only from first-party crate code, and that ticket
    /// widens visibility only behind real verification.
    ///
    /// Reserved crate API: no first-party caller exists yet, so it is
    /// exercised only by tests today.
    // Still reserved, re-checked: the only callers are this crate's tests and
    // the compile-fail pins, so a non-test build sees it unused. The `allow`
    // goes when the connector-edge wiring calls it for real.
    #[allow(dead_code)]
    pub(crate) fn from_edge_auth(
        service_identity: &str,
        class: ConnectionClass,
        registry: &EdgeServiceRegistry,
    ) -> Result<Self> {
        let name = service_identity
            .strip_prefix(EDGE_SERVICE_IDENTITY_PREFIX)
            .ok_or_else(|| {
                Error::Relay(RelayError::RelayAttestationInvalidServiceIdentity {
                    service_identity: service_identity.to_owned(),
                    reason: "service identity must match `connector-edge:<name>`",
                })
            })?;
        if name.is_empty() {
            return Err(Error::Relay(
                RelayError::RelayAttestationInvalidServiceIdentity {
                    service_identity: service_identity.to_owned(),
                    reason: "connector-edge service name must be non-empty",
                },
            ));
        }
        let registered_class = registry.registered_class(name).ok_or_else(|| {
            Error::Relay(RelayError::RelayAttestationInvalidServiceIdentity {
                service_identity: service_identity.to_owned(),
                reason: "unregistered connector-edge service",
            })
        })?;
        if registered_class != class {
            return Err(Error::Relay(RelayError::RelayAttestationClassMismatch {
                service_identity: service_identity.to_owned(),
                claimed: class.as_str(),
                registered: registered_class.as_str(),
            }));
        }
        Ok(Self {
            service_identity: service_identity.to_owned(),
            connection_class: class,
        })
    }

    /// The verified connector-edge service identity (`connector-edge:<name>`).
    #[must_use]
    pub fn service_identity(&self) -> &str {
        &self.service_identity
    }

    /// The connection class validated against the service table at
    /// construction.
    #[must_use]
    pub const fn connection_class(&self) -> ConnectionClass {
        self.connection_class
    }
}

/// Sealed witness: a [`RelayTrustDomain`] carrying evidence of its origin AND
/// the attested service identity that origin belongs to. The fields are
/// private and the only general mint is
/// [`AttestedRelayDomain::from_connection_identity`], so a relay caller cannot
/// pick a trust domain off a menu — it must present an
/// [`AuthenticatedConnectionIdentity`] that connector-edge auth validated, and
/// that identity cannot be fabricated outside the crate.
///
/// The identity rides ALONG with the domain rather than being passed beside
/// it, because it is what selects the hosted legal policy at the relay seam
/// (see [`EdgeServiceRegistry::hosted_legal_policy`]). A relay entry point that
/// took a policy as its own argument would let the caller choose the
/// jurisdiction it is judged under; here the caller cannot name one at all.
///
/// Serialize-only, like its inner: emitted into receipts/logs, never accepted
/// inbound.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct AttestedRelayDomain {
    domain: RelayTrustDomain,
    service_identity: String,
}

impl AttestedRelayDomain {
    /// Mints the witness from a validated connection identity, routing the
    /// identity's registered connection class through the single
    /// `HostedDomain` mapping chain — the ONLY `ConnectionClass` to trust
    /// domain mapping in the crate, so this general mint and the hosted-edge
    /// attester can never diverge. The identity's own service name is captured
    /// here and never re-supplied later. Infallible by design: the identity was
    /// already validated at construction and the mapping is exhaustive over
    /// the hosted classes, so there is no failure mode to reserve.
    #[must_use]
    pub fn from_connection_identity(id: &AuthenticatedConnectionIdentity) -> Self {
        Self::from_hosted_domain(
            HostedDomain::from_connection_class(id.connection_class()),
            id.service_identity().to_owned(),
        )
    }

    /// The attested trust domain, for receipts/logs and the relay seams.
    #[must_use]
    pub const fn domain(&self) -> RelayTrustDomain {
        self.domain
    }

    /// The attested `connector-edge:<name>` identity this pass runs under. The
    /// relay resolves the hosted legal policy from THIS, never from a caller
    /// argument.
    #[must_use]
    pub fn service_identity(&self) -> &str {
        &self.service_identity
    }

    /// Mints through the hosted-edge two-variant domain. Private: the only
    /// caller is [`Self::from_connection_identity`] (which
    /// [`HostedEdgeAttestation::attest`] delegates to), keeping one mapping.
    pub(crate) fn from_hosted_domain(hosted: HostedDomain, service_identity: String) -> Self {
        let domain = match hosted {
            HostedDomain::CloudVault => RelayTrustDomain::CloudVault,
            HostedDomain::LocalViaHostedConnector => RelayTrustDomain::LocalViaHostedConnector,
        };
        Self {
            domain,
            service_identity,
        }
    }

    /// Honest test-only mint for the crate's own unit tests. `cfg(test)` +
    /// `pub(crate)` on purpose: integration crates and downstreams get NO
    /// mint — a production-reachable universal mint would make the seal
    /// cosmetic.
    #[cfg(test)]
    pub(crate) fn for_testing(domain: RelayTrustDomain, service_identity: &str) -> Self {
        Self {
            domain,
            service_identity: service_identity.to_owned(),
        }
    }
}

/// Hosted-edge domain: two variants ONLY. There is no `LocalViaByoConnector`
/// variant to name — a hosted-edge process relaying content that concludes
/// "not relayed by us" is a contradiction, and this type makes it
/// unrepresentable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum HostedDomain {
    CloudVault,
    LocalViaHostedConnector,
}

impl HostedDomain {
    /// The ONLY `ConnectionClass` to hosted-domain mapping: every mint path
    /// routes through here, so the general mint and the hosted-edge attester
    /// cannot drift apart. Exhaustive with no wildcard — a new
    /// `ConnectionClass` variant breaks this match at compile time.
    fn from_connection_class(class: ConnectionClass) -> Self {
        match class {
            ConnectionClass::CloudVaultPeer => Self::CloudVault,
            ConnectionClass::LocalVaultViaHostedConnector => Self::LocalViaHostedConnector,
        }
    }
}

/// Hosted-edge attester. The connector edge constructs this after its bearer
/// verification settles; attestation itself is pure over the already-validated
/// identity.
#[derive(Debug)]
pub struct HostedEdgeAttestation {
    _private: (),
}

impl HostedEdgeAttestation {
    #[must_use]
    pub const fn new() -> Self {
        Self { _private: () }
    }

    /// Attests the relay trust domain for a validated connection identity by
    /// delegating to [`AttestedRelayDomain::from_connection_identity`], the
    /// single mapping chain through `HostedDomain` — BYO is unreachable
    /// because no `HostedDomain` arm maps to it, and the two mint paths cannot
    /// diverge. Infallible by design: attestation is pure over the
    /// already-validated identity.
    #[must_use]
    pub fn attest(&self, id: &AuthenticatedConnectionIdentity) -> AttestedRelayDomain {
        AttestedRelayDomain::from_connection_identity(id)
    }
}

impl Default for HostedEdgeAttestation {
    fn default() -> Self {
        Self::new()
    }
}
