//! Moved from `crates/oneiron/src/policy_model/relay/trust.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Serialize;

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
pub const EDGE_SERVICE_IDENTITY_PREFIX: &str = "connector-edge:";

/// Hosted-edge domain: two variants ONLY. There is no `LocalViaByoConnector`
/// variant to name — a hosted-edge process relaying content that concludes
/// "not relayed by us" is a contradiction, and this type makes it
/// unrepresentable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HostedDomain {
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
