//! The hosted relay boundary: where OUR infrastructure touches someone else's
//! content, and the only place the hosted legal plane is ever evaluated.
//!
//! The rule that shapes this file is that a sovereign machine owns its box. A
//! vault's own claim that it "already classified this" is not evidence to us,
//! and a vault that never routes through us is never evaluated by us at all.
//! What we do get to enforce is the legal policy of the hosted service doing
//! the relaying — bound to that service's attested identity, versioned, and
//! attributed to the service rather than to the vault owner. The binding is
//! structural: the attested identity travels inside the witness and SELECTS
//! the policy from the edge-service registry, so no relay entry point takes a
//! policy (or a jurisdiction) as a caller argument.
//!
//! The halt contract this file publishes has three clauses. A `Block` or
//! `RouteToHelp` halts the relay. A `Warn` does not — the original bytes still
//! go out, with the notice alongside. And a DEGRADED pass halts wherever a
//! hosted legal policy was in play: the hosted plane is fail-closed, so an
//! outage in the tier that covers it must stop the relay rather than be
//! answered with an unexamined allow. An owner-plane-only degrade never halts;
//! the owner's plane is sovereign and has nothing underneath it.

use std::collections::{BTreeMap, HashMap};

use serde::Serialize;

use crate::Vault;
use crate::error::{Error, Result};
use crate::gate;
use crate::llm::{BudgetLease, LlmBackend};
use crate::store::{
    GATE_SYSTEM_NOTICE_BODY_MAX_LEN, GATE_SYSTEM_NOTICE_DOCS_URL_MAX_LEN,
    GATE_SYSTEM_NOTICE_VERSION_MAX_LEN,
};

use super::binding::{
    PolicyContentBinding, content_binding, relay_skip_content_binding, relay_verify_content_binding,
};
use super::notice::{HOSTED_NOTICE_TEMPLATE_MAX_FIXED_LEN, policy_notice};
use super::planes::{HostedLegalPolicy, hosted_rubric_rows};
use super::prompt::{parse_policy_model_response, render_classify_prompt};
use super::receipt::policy_model_reason_codes;
use super::request::{PolicyClassifyRequest, PolicyModelConfig};
use super::tripwire::hosted_tripwire_hit;
use super::verdict::{
    PolicyClassifyDecision, PolicyClassifyVerdict, PolicyConfidence, PolicyVerdictCategory,
};

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
const EDGE_SERVICE_IDENTITY_PREFIX: &str = "connector-edge:";

/// How long a jurisdiction name may be. Derived, not chosen: it is exactly the
/// room the gate-notice ledger's body bound leaves once the longest hosted
/// notice template has been paid for, so a registered jurisdiction can never
/// produce a notice the ledger refuses.
pub(super) const HOSTED_LEGAL_JURISDICTION_MAX_LEN: usize =
    GATE_SYSTEM_NOTICE_BODY_MAX_LEN - HOSTED_NOTICE_TEMPLATE_MAX_FIXED_LEN;

/// How long a policy hash may be. The hash never reaches the ledger; it is the
/// evidence a vault-side receipt must reproduce to be trusted, so it only has
/// to be present and bounded.
const HOSTED_LEGAL_POLICY_HASH_MAX_LEN: usize = 128;

/// Rejects a hosted legal policy whose attribution fields cannot survive the
/// gate-notice ledger. Every bound here mirrors one the ledger already
/// enforces, so registration and receipt-append agree by construction.
fn validate_hosted_legal_policy(service: &str, policy: &HostedLegalPolicy) -> Result<()> {
    bounded_attribution(
        service,
        "jurisdiction",
        &policy.jurisdiction,
        HOSTED_LEGAL_JURISDICTION_MAX_LEN,
    )?;
    bounded_attribution(
        service,
        "version",
        &policy.version,
        GATE_SYSTEM_NOTICE_VERSION_MAX_LEN,
    )?;
    bounded_attribution(
        service,
        "docs_url",
        &policy.docs_url,
        GATE_SYSTEM_NOTICE_DOCS_URL_MAX_LEN,
    )?;
    bounded_attribution(
        service,
        "policy_hash",
        &policy.policy_hash,
        HOSTED_LEGAL_POLICY_HASH_MAX_LEN,
    )
}

fn bounded_attribution(
    service: &str,
    field: &'static str,
    value: &str,
    max_len: usize,
) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::RelayHostedLegalPolicyInvalid {
            service: service.to_owned(),
            field,
            reason: "must not be blank",
        });
    }
    if value.len() > max_len {
        return Err(Error::RelayHostedLegalPolicyInvalid {
            service: service.to_owned(),
            field,
            reason: "is longer than the gate-notice ledger accepts",
        });
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EdgeService {
    class: ConnectionClass,
    legal_policy: Option<HostedLegalPolicy>,
}

/// Connector-edge service registry: the registration DATA that
/// `AuthenticatedConnectionIdentity::from_edge_auth` validates against (that
/// constructor is crate-private, so it carries no doc link), and the place a
/// hosted service's legal policy is bound to its identity.
///
/// The engine ships the validation MECHANISM only — no service identities and
/// no legal policies are engine constants, so adding a hosted connector edge
/// or amending a jurisdiction's rules never forces an engine release. The
/// deployment's connector-edge wiring supplies its own registrations, and the
/// crate's tests register fixture names.
///
/// Validation stays fail-closed on BOTH axes: an unregistered service identity
/// is rejected, and a registered service may never claim a stronger class than
/// its registration — a hosted connector edge can never present itself as a
/// cloud-vault peer (which would skip the hosted pass entirely).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EdgeServiceRegistry {
    services: BTreeMap<String, EdgeService>,
}

impl EdgeServiceRegistry {
    /// An empty registry: every service identity is unregistered, so every
    /// edge-auth validation fails closed until the deployment registers its
    /// edge services.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers `service` — the bare `<name>` suffix of the
    /// `connector-edge:<name>` grammar — as permitted to claim `class`.
    /// Idempotent for an identical re-registration; a CONFLICTING
    /// re-registration (same name, different class) is rejected, so a
    /// manifest can never silently re-stand an edge to another class.
    pub fn register(&mut self, service: &str, class: ConnectionClass) -> Result<()> {
        if service.is_empty() {
            return Err(Error::RelayAttestationInvalidServiceIdentity {
                service_identity: service.to_owned(),
                reason: "registered connector-edge service name must be non-empty",
            });
        }
        match self.services.get(service) {
            Some(registered) if registered.class == class => Ok(()),
            Some(registered) => Err(Error::RelayAttestationEdgeServiceConflict {
                service: service.to_owned(),
                registered: registered.class.as_str(),
                claimed: class.as_str(),
            }),
            None => {
                self.services.insert(
                    service.to_owned(),
                    EdgeService {
                        class,
                        legal_policy: None,
                    },
                );
                Ok(())
            }
        }
    }

    /// Binds a hosted legal policy to an already-registered service. The
    /// service must exist first: a policy with no identity behind it is
    /// exactly the free-floating jurisdiction claim this registry exists to
    /// prevent.
    ///
    /// The policy's attribution fields are validated HERE, against the same
    /// bounds the gate-notice ledger enforces. Deferring them would let a policy
    /// with, say, a blank `docs_url` register cleanly and then fail every
    /// hosted `Warn`/`Block` at receipt-append time — an enforcement outage
    /// disguised as a storage error, discovered only once it mattered.
    pub fn register_hosted_legal_policy(
        &mut self,
        service: &str,
        policy: HostedLegalPolicy,
    ) -> Result<()> {
        validate_hosted_legal_policy(service, &policy)?;
        let entry = self.services.get_mut(service).ok_or_else(|| {
            Error::RelayAttestationInvalidServiceIdentity {
                service_identity: service.to_owned(),
                reason: "hosted legal policy requires a registered connector-edge service",
            }
        })?;
        entry.legal_policy = Some(policy);
        Ok(())
    }

    /// The legal policy bound to a `connector-edge:<name>` identity, if the
    /// deployment registered one. The relay edge looks this up with the
    /// identity it just validated and hands it to the pass.
    #[must_use]
    pub fn hosted_legal_policy(&self, service_identity: &str) -> Option<&HostedLegalPolicy> {
        let name = service_identity.strip_prefix(EDGE_SERVICE_IDENTITY_PREFIX)?;
        self.services.get(name)?.legal_policy.as_ref()
    }

    fn registered_class(&self, service: &str) -> Option<ConnectionClass> {
        self.services.get(service).map(|entry| entry.class)
    }
}

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
    #[allow(dead_code)]
    pub(crate) fn from_edge_auth(
        service_identity: &str,
        class: ConnectionClass,
        registry: &EdgeServiceRegistry,
    ) -> Result<Self> {
        let name = service_identity
            .strip_prefix(EDGE_SERVICE_IDENTITY_PREFIX)
            .ok_or_else(|| Error::RelayAttestationInvalidServiceIdentity {
                service_identity: service_identity.to_owned(),
                reason: "service identity must match `connector-edge:<name>`",
            })?;
        if name.is_empty() {
            return Err(Error::RelayAttestationInvalidServiceIdentity {
                service_identity: service_identity.to_owned(),
                reason: "connector-edge service name must be non-empty",
            });
        }
        let registered_class = registry.registered_class(name).ok_or_else(|| {
            Error::RelayAttestationInvalidServiceIdentity {
                service_identity: service_identity.to_owned(),
                reason: "unregistered connector-edge service",
            }
        })?;
        if registered_class != class {
            return Err(Error::RelayAttestationClassMismatch {
                service_identity: service_identity.to_owned(),
                claimed: class.as_str(),
                registered: registered_class.as_str(),
            });
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
    pub(super) fn from_hosted_domain(hosted: HostedDomain, service_identity: String) -> Self {
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
pub(super) enum HostedDomain {
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

/// Why a hosted relay pass degraded off the safeguard-model tier. A degraded
/// pass fell back to the deterministic result (never below it); the marker
/// keeps a degraded `Allow` distinguishable from a model-confirmed `Allow` in
/// receipts and logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayFloorDegrade {
    /// The safeguard model was unavailable (transport/backend error).
    SafeguardModelUnavailable,
    /// The safeguard model responded but the response was unusable —
    /// unparseable, or a verdict bound to a row the hosted rubric never
    /// carried.
    SafeguardModelResponseUnusable,
}

impl RelayFloorDegrade {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SafeguardModelUnavailable => "safeguard_model_unavailable",
            Self::SafeguardModelResponseUnusable => "safeguard_model_response_unusable",
        }
    }
}

/// Outcome of a relay-boundary pass. Advisory only — this classifies, it does
/// not itself halt the relay; the caller must honor
/// [`RelayFloorPass::must_halt_relay`].
///
/// `FloorClassified` is the only variant that ran a pass, and its verdict is
/// HOSTED-LEGAL ONLY — the owner plane is never assembled at the relay, so the
/// verdict category can never be [`PolicyVerdictCategory::OwnerPolicy`] unless
/// it came from a verified vault-side receipt.
///
/// Intentionally `Serialize` but NOT `Deserialize` (same reason as
/// [`RelayTrustDomain`]): a relay outcome is emitted for receipts/logs, never
/// reconstructed from untrusted bytes.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RelayFloorPass {
    /// Cloud vault: already classified vault-side and verified here; trusted.
    TrustedVaultSide,
    /// BYO connector: nothing transits our infra; nothing ran.
    NotRelayedByUs,
    /// OUR infra ran the hosted legal pass. `degraded` is set when the pass
    /// fell back to the deterministic result because the safeguard-model tier
    /// failed. `hosted_policy_in_play` records whether a hosted legal policy
    /// was bound to the attested identity at all — a degrade means something
    /// different on each side of that line, so the fact travels with the pass
    /// rather than being re-derived by the caller.
    FloorClassified {
        verdict: PolicyClassifyVerdict,
        #[serde(skip_serializing_if = "Option::is_none")]
        degraded: Option<RelayFloorDegrade>,
        hosted_policy_in_play: bool,
    },
}

impl RelayFloorPass {
    /// The verdict, present only when OUR infra ran a relay pass.
    #[must_use]
    pub fn floor_verdict(&self) -> Option<&PolicyClassifyVerdict> {
        match self {
            Self::FloorClassified { verdict, .. } => Some(verdict),
            Self::TrustedVaultSide | Self::NotRelayedByUs => None,
        }
    }

    /// Whether OUR infra ran a classify pass at the relay boundary. False for
    /// a trusted cloud vault and for BYO (never transits us).
    #[must_use]
    pub fn ran_relay_classify(&self) -> bool {
        matches!(self, Self::FloorClassified { .. })
    }

    /// The degradation marker, if the safeguard-model tier failed and the pass
    /// fell back to the deterministic result.
    #[must_use]
    pub fn degraded(&self) -> Option<RelayFloorDegrade> {
        match self {
            Self::FloorClassified { degraded, .. } => *degraded,
            Self::TrustedVaultSide | Self::NotRelayedByUs => None,
        }
    }

    /// Whether the caller edge must NOT relay this content. `Block` and
    /// `RouteToHelp` halt; `Warn` does not — a warned relay still delivers the
    /// original content, with its notice alongside. A trusted cloud pass and
    /// an untouched BYO path never halt.
    ///
    /// A DEGRADED pass halts too, but only where a hosted legal policy was in
    /// play. The hosted plane is fail-closed and its
    /// [`HostedLegalCategory::JurisdictionRule`] arm has no deterministic
    /// tripwire behind it, so a safeguard-model outage leaves that category
    /// with zero coverage — relaying anyway would answer an outage with an
    /// unexamined allow. The owner plane is sovereign and gets the opposite
    /// treatment: an owner-plane-only degrade never halts, because nothing
    /// sits beneath the owner's own rows to fall back to.
    ///
    /// [`HostedLegalCategory::JurisdictionRule`]: super::verdict::HostedLegalCategory::JurisdictionRule
    #[must_use]
    pub fn must_halt_relay(&self) -> bool {
        match self {
            Self::FloorClassified {
                verdict,
                degraded,
                hosted_policy_in_play,
            } => {
                matches!(
                    verdict.decision,
                    PolicyClassifyDecision::Block | PolicyClassifyDecision::RouteToHelp
                ) || (degraded.is_some() && *hosted_policy_in_play)
            }
            Self::TrustedVaultSide | Self::NotRelayedByUs => false,
        }
    }
}

/// Narrow read-only port for vault-side receipts owned by our relay VM.
pub trait VaultSideVerdictSource {
    /// The key is the locally recomputed, identity-free verification hash.
    fn latest_floor_verdict(
        &self,
        verify_content_hash: &[u8; 32],
    ) -> Result<Option<PolicyClassifyVerdict>>;
}

/// Process-local vault-side verdict adapter keyed by the verification hash.
///
/// This is deliberately an adapter only: durable relay-store ownership belongs
/// to the connector edge that supplies this source.
#[derive(Debug, Default)]
pub struct InMemoryVaultSideVerdicts {
    verdicts: HashMap<[u8; 32], PolicyClassifyVerdict>,
}

impl InMemoryVaultSideVerdicts {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Associates a vault-side verdict with its identity-free verification key.
    pub fn insert(
        &mut self,
        verify_content_hash: [u8; 32],
        verdict: PolicyClassifyVerdict,
    ) -> Option<PolicyClassifyVerdict> {
        self.verdicts.insert(verify_content_hash, verdict)
    }
}

impl VaultSideVerdictSource for InMemoryVaultSideVerdicts {
    fn latest_floor_verdict(
        &self,
        verify_content_hash: &[u8; 32],
    ) -> Result<Option<PolicyClassifyVerdict>> {
        Ok(self.verdicts.get(verify_content_hash).cloned())
    }
}

/// CloudVault verification either supplies its trusted pass or requires the
/// caller to run the hosted pass and audit the breach.
enum CloudVaultPassOrFallback {
    Pass(RelayFloorPass),
    HostedFallback { receipt_breach: &'static str },
}

/// Runs the relay pass and structurally falls back to the hosted pass when a
/// CloudVault receipt is absent or untrusted.
pub fn relay_floor_pass_or_hosted_fallback(
    vault: &Vault,
    request: PolicyClassifyRequest,
    domain: &AttestedRelayDomain,
    registry: &EdgeServiceRegistry,
    config: &PolicyModelConfig,
    verdicts: &dyn VaultSideVerdictSource,
) -> Result<RelayFloorPass> {
    vault.relay_boundary_floor_pass_with_config(request, domain, registry, config, verdicts)
}

impl Vault {
    /// Relay-boundary pass over the hosted legal plane, deterministic tier
    /// only.
    ///
    /// Runs where OUR infrastructure touches a vault's outbound content, once
    /// per trust domain. `domain` is a sealed [`AttestedRelayDomain`] witness:
    /// the caller (the hosted relay / connector edge) mints it from an
    /// [`AuthenticatedConnectionIdentity`] its edge auth validated, NEVER from
    /// a vault-attested "already classified" receipt — the domain is evidence
    /// now, not a label the caller picks.
    ///
    /// The relaying service's legal policy is RESOLVED HERE, from `registry`
    /// keyed by the witness's own attested identity (see
    /// [`EdgeServiceRegistry::hosted_legal_policy`]) — there is deliberately no
    /// policy parameter, because a caller that could hand one in could choose
    /// the jurisdiction it is judged under. With no policy bound to that
    /// identity there is nothing to enforce and every pass is clean.
    ///
    /// * [`RelayTrustDomain::CloudVault`] — verifies the vault-side receipt
    ///   against locally recomputed hashes and, with a hosted policy in play,
    ///   against that policy's own attestation; a fully verified `Allow` is
    ///   trusted, a verified non-`Allow` is returned as it stands, and anything
    ///   untrusted falls back to the hosted pass with an audit receipt.
    /// * [`RelayTrustDomain::LocalViaHostedConnector`] — runs the hosted legal
    ///   plane on 100% of relayed content. The owner plane is never assembled
    ///   or evaluated here.
    /// * [`RelayTrustDomain::LocalViaByoConnector`] — nothing transits us; no
    ///   pass runs ([`RelayFloorPass::NotRelayedByUs`]).
    ///
    /// This never touches the input side and never runs the owner plane; it
    /// can only ADD coverage on the hosted-relay path, never weaken an
    /// existing deny path.
    ///
    /// Advisory: this classifies but does not itself halt the relay — the
    /// caller must honor [`RelayFloorPass::must_halt_relay`]. Every relay
    /// decision that blocks or skips is recorded as an audit receipt (a clean,
    /// non-degraded `Allow` is not), so a relay block or a mis-labeled skip is
    /// never silent. A returned `Err` means infrastructure misuse only —
    /// unresolvable/malformed local policy state or a failed receipt write.
    pub fn relay_boundary_floor_pass(
        &self,
        request: PolicyClassifyRequest,
        domain: &AttestedRelayDomain,
        registry: &EdgeServiceRegistry,
        verdicts: &dyn VaultSideVerdictSource,
    ) -> Result<RelayFloorPass> {
        self.relay_boundary_floor_pass_with_config(
            request,
            domain,
            registry,
            &PolicyModelConfig::default(),
            verdicts,
        )
    }

    pub fn relay_boundary_floor_pass_with_config(
        &self,
        request: PolicyClassifyRequest,
        domain: &AttestedRelayDomain,
        registry: &EdgeServiceRegistry,
        config: &PolicyModelConfig,
        verdicts: &dyn VaultSideVerdictSource,
    ) -> Result<RelayFloorPass> {
        let hosted = registry.hosted_legal_policy(domain.service_identity());
        let mut receipt_breach = None;
        let pass = match domain.domain() {
            RelayTrustDomain::CloudVault => {
                match self
                    .cloud_vault_pass_or_hosted_fallback(&request, hosted, config, verdicts)?
                {
                    CloudVaultPassOrFallback::Pass(pass) => pass,
                    CloudVaultPassOrFallback::HostedFallback {
                        receipt_breach: reason,
                    } => {
                        receipt_breach = Some(reason);
                        self.hosted_relay_pass(&request, hosted, config)?
                    }
                }
            }
            RelayTrustDomain::LocalViaByoConnector => RelayFloorPass::NotRelayedByUs,
            RelayTrustDomain::LocalViaHostedConnector => {
                self.hosted_relay_pass(&request, hosted, config)?
            }
        };
        self.record_relay_floor_receipt(RelayReceipt {
            request: &request,
            domain,
            pass: &pass,
            receipt_breach,
            hosted,
            config,
        })?;
        Ok(pass)
    }

    /// Relay-boundary pass with the safeguard model available for a flagged
    /// span.
    ///
    /// **Caller contract:** invoke this ONLY for a span the connector edge has
    /// already flagged for model review. The deterministic tier is not
    /// extended to emit flags, so the flag heuristic is the edge's
    /// responsibility; this method does not re-derive it. The deterministic
    /// tier still runs here as the backstop, and the HOSTED-ONLY safeguard
    /// model adjudicates the flagged span only when it did not already resolve
    /// it. The owner plane is never assembled, so a relay verdict can never be
    /// [`PolicyVerdictCategory::OwnerPolicy`]; a model verdict bound to a row
    /// the hosted rubric never carried is unusable and degrades rather than
    /// taking effect.
    ///
    /// Failure is symmetric and never below the deterministic result: if the
    /// safeguard model is unavailable OR its response is unusable, the pass
    /// falls back and marks itself `degraded`. A returned `Err` therefore
    /// means infrastructure misuse only, never a model outcome.
    ///
    /// `pub(crate)` by design: this takes an arbitrary safeguard backend, and
    /// on our relay infrastructure the classifier binding must be OURS —
    /// swapping in a weak model there would weaken enforcement of our own
    /// legal duty. Model freedom is a local/self-host/BYO property, so only
    /// first-party code that pins our classifier may drive the model tier; the
    /// public relay API is the deterministic pass.
    ///
    /// Reserved crate API: no first-party caller exists yet, so it is
    /// exercised only by tests today.
    #[allow(dead_code)]
    pub(crate) async fn relay_boundary_floor_pass_with_backend(
        &self,
        request: PolicyClassifyRequest,
        domain: &AttestedRelayDomain,
        registry: &EdgeServiceRegistry,
        config: &PolicyModelConfig,
        safeguard: RelaySafeguardTier<'_>,
        verdicts: &dyn VaultSideVerdictSource,
    ) -> Result<RelayFloorPass> {
        let hosted = registry.hosted_legal_policy(domain.service_identity());
        let mut receipt_breach = None;
        let pass = match domain.domain() {
            RelayTrustDomain::CloudVault => {
                match self
                    .cloud_vault_pass_or_hosted_fallback(&request, hosted, config, verdicts)?
                {
                    CloudVaultPassOrFallback::Pass(pass) => pass,
                    CloudVaultPassOrFallback::HostedFallback {
                        receipt_breach: reason,
                    } => {
                        receipt_breach = Some(reason);
                        self.hosted_relay_pass_with_backend(&request, hosted, config, safeguard)
                            .await?
                    }
                }
            }
            RelayTrustDomain::LocalViaByoConnector => RelayFloorPass::NotRelayedByUs,
            RelayTrustDomain::LocalViaHostedConnector => {
                self.hosted_relay_pass_with_backend(&request, hosted, config, safeguard)
                    .await?
            }
        };
        self.record_relay_floor_receipt(RelayReceipt {
            request: &request,
            domain,
            pass: &pass,
            receipt_breach,
            hosted,
            config,
        })?;
        Ok(pass)
    }

    fn hosted_relay_pass(
        &self,
        request: &PolicyClassifyRequest,
        hosted: Option<&HostedLegalPolicy>,
        config: &PolicyModelConfig,
    ) -> Result<RelayFloorPass> {
        // Deterministic tier only: needs the binding, not the model prompt.
        let binding = self.relay_policy_binding(request, config)?;
        Ok(RelayFloorPass::FloorClassified {
            verdict: hosted_tripwire_verdict(request, hosted, binding, config),
            degraded: None,
            hosted_policy_in_play: hosted.is_some(),
        })
    }

    async fn hosted_relay_pass_with_backend(
        &self,
        request: &PolicyClassifyRequest,
        hosted: Option<&HostedLegalPolicy>,
        config: &PolicyModelConfig,
        safeguard: RelaySafeguardTier<'_>,
    ) -> Result<RelayFloorPass> {
        let binding = self.relay_policy_binding(request, config)?;
        let Some(policy) = hosted else {
            // No hosted policy in play: there is nothing for the model to
            // classify against, so it is never called.
            return Ok(RelayFloorPass::FloorClassified {
                verdict: PolicyClassifyVerdict::clean_allow(binding, config),
                degraded: None,
                hosted_policy_in_play: false,
            });
        };
        if let Some(row) = hosted_tripwire_hit(&request.content, policy) {
            // The deterministic tier caught it; the model tier is not consulted.
            return Ok(RelayFloorPass::FloorClassified {
                verdict: hosted_row_verdict(row, policy, binding, config),
                degraded: None,
                hosted_policy_in_play: true,
            });
        }
        let prompt = render_classify_prompt(request, hosted_rubric_rows(policy));
        let pass = match safeguard
            .backend
            .generate(prompt.llm_request(config), safeguard.lease)
            .await
        {
            Ok(response) => match parse_policy_model_response(
                &response,
                &prompt.rubric_rows,
                Some(policy),
                binding,
                config,
            ) {
                Ok(verdict) => RelayFloorPass::FloorClassified {
                    verdict,
                    degraded: None,
                    hosted_policy_in_play: true,
                },
                Err(_off_plane_or_unparseable) => RelayFloorPass::FloorClassified {
                    verdict: PolicyClassifyVerdict::clean_allow(binding, config),
                    degraded: Some(RelayFloorDegrade::SafeguardModelResponseUnusable),
                    hosted_policy_in_play: true,
                },
            },
            Err(_unavailable) => RelayFloorPass::FloorClassified {
                verdict: PolicyClassifyVerdict::clean_allow(binding, config),
                degraded: Some(RelayFloorDegrade::SafeguardModelUnavailable),
                hosted_policy_in_play: true,
            },
        };
        Ok(pass)
    }

    /// Verifies a CloudVault receipt produced by our vault-side runner. The
    /// receipt lookup and every comparison are over locally derived values.
    ///
    /// Content and read-frontier hashes plus the safeguard selector establish
    /// that the receipt describes THIS content under THIS policy state. They do
    /// not, on their own, establish that the hosted legal plane ever ran: a
    /// vault-side pass evaluates the OWNER plane, and a clean owner-plane
    /// `Allow` verified this far would otherwise skip the relay entirely — the
    /// hosted service's own legal duty silently discharged by the vault's
    /// verdict about a different question. So with a hosted policy in play the
    /// receipt must additionally carry hosted evidence naming that policy's
    /// version and hash. A receipt without it is not an ERROR, it is simply not
    /// evidence of a hosted pass: it falls through to the hosted pass like any
    /// other untrusted receipt, and the breach is audited.
    ///
    /// The check sits BEFORE the decision branch on purpose. A stored non-Allow
    /// verdict is returned verbatim, and `Warn` does not halt — so trusting an
    /// unattested `Warn` would relay the content with the hosted plane never
    /// consulted, which is the same hole in a milder coat.
    pub(super) fn cloud_vault_verified_trust(
        &self,
        request: &PolicyClassifyRequest,
        hosted: Option<&HostedLegalPolicy>,
        config: &PolicyModelConfig,
        verdicts: &dyn VaultSideVerdictSource,
    ) -> Result<RelayFloorPass> {
        let binding = self.relay_verify_binding(request, config)?;
        let Some(receipt) = verdicts.latest_floor_verdict(&binding.content_hash)? else {
            return Err(Error::RelayVaultReceiptUntrusted { reason: "missing" });
        };
        if receipt.binding.content_hash != binding.content_hash
            || receipt.binding.read_frontier_hash != binding.read_frontier_hash
        {
            return Err(Error::RelayVaultReceiptUntrusted {
                reason: "binding_mismatch",
            });
        }
        if receipt.safeguard_binding != config.safeguard_binding.selector() {
            return Err(Error::RelayVaultReceiptUntrusted {
                reason: "safeguard_binding_mismatch",
            });
        }
        if let Some(policy) = hosted
            && !receipt.attests_hosted_plane(policy)
        {
            return Err(Error::RelayVaultReceiptUntrusted {
                reason: "hosted_plane_unattested",
            });
        }
        if receipt.decision != PolicyClassifyDecision::Allow {
            return Ok(RelayFloorPass::FloorClassified {
                verdict: receipt,
                degraded: None,
                hosted_policy_in_play: hosted.is_some(),
            });
        }
        Ok(RelayFloorPass::TrustedVaultSide)
    }

    /// Shares CloudVault verification and breach capture between relay entry
    /// points.
    fn cloud_vault_pass_or_hosted_fallback(
        &self,
        request: &PolicyClassifyRequest,
        hosted: Option<&HostedLegalPolicy>,
        config: &PolicyModelConfig,
        verdicts: &dyn VaultSideVerdictSource,
    ) -> Result<CloudVaultPassOrFallback> {
        match self.cloud_vault_verified_trust(request, hosted, config, verdicts) {
            Ok(pass) => Ok(CloudVaultPassOrFallback::Pass(pass)),
            Err(Error::RelayVaultReceiptUntrusted { reason }) => {
                Ok(CloudVaultPassOrFallback::HostedFallback {
                    receipt_breach: reason,
                })
            }
            Err(error) => Err(error),
        }
    }

    pub(super) fn relay_verify_binding(
        &self,
        request: &PolicyClassifyRequest,
        config: &PolicyModelConfig,
    ) -> Result<PolicyContentBinding> {
        let rtxn = self.store.env.read_txn()?;
        let policy = gate::resolve_policy_manifest(&self.store, &rtxn)?;
        if policy.diagnostics().loaded_manifest_forces_fail_closed() {
            return Err(malformed_relay_policy_error());
        }
        let _ = config; // Kept in the seam alongside the sibling relay binding.
        relay_verify_content_binding(request, &policy)
    }

    /// Binding plus fail-closed check for a relay pass. The vault's own policy
    /// state never decides a hosted verdict, but it does bind the receipt, so
    /// an unreadable manifest still fails the pass closed.
    fn relay_policy_binding(
        &self,
        request: &PolicyClassifyRequest,
        config: &PolicyModelConfig,
    ) -> Result<PolicyContentBinding> {
        let rtxn = self.store.env.read_txn()?;
        let policy = gate::resolve_policy_manifest(&self.store, &rtxn)?;
        if policy.diagnostics().loaded_manifest_forces_fail_closed() {
            return Err(malformed_relay_policy_error());
        }
        content_binding(request, &policy, config)
    }

    /// Writes the relay-boundary audit receipt. Called from both relay paths:
    /// a hosted pass that warns/blocks/routes or that degraded, and a
    /// trust-domain SKIP (trusted cloud, untouched BYO), are all recorded so a
    /// relay decision or a mis-labeled skip is never silent. A clean,
    /// non-degraded `Allow` carries no enforcement signal and is not receipted.
    fn record_relay_floor_receipt(&self, receipt: RelayReceipt<'_>) -> Result<()> {
        let domain = receipt.domain.domain();
        // The gate decision ledger requires every reason code to be namespaced
        // under `gate.`, so relay codes ride there too.
        let mut reason_codes = vec![
            format!("gate.relay.trust_domain.{}", domain.as_str()),
            if receipt.pass.ran_relay_classify() {
                "gate.relay.classify.ran".to_owned()
            } else {
                "gate.relay.classify.skipped".to_owned()
            },
        ];
        if let Some(degrade) = receipt.pass.degraded() {
            reason_codes.push(format!("gate.relay.degraded.{}", degrade.as_str()));
        }
        if let Some(reason) = receipt.receipt_breach {
            reason_codes.push(format!("gate.relay.vault_receipt_untrusted.{reason}"));
        }
        let mut notices = Vec::new();
        let (outcome, receipt_verdict) = match receipt.pass {
            RelayFloorPass::FloorClassified {
                verdict, degraded, ..
            } => {
                if verdict.decision == PolicyClassifyDecision::Allow
                    && degraded.is_none()
                    && receipt.receipt_breach.is_none()
                {
                    return Ok(());
                }
                reason_codes.extend(policy_model_reason_codes(verdict));
                notices.extend(policy_notice(
                    verdict.decision,
                    &verdict.category,
                    receipt.hosted,
                    receipt.config,
                ));
                (
                    format!("relay_floor_{}", verdict.decision.ledger_str()),
                    verdict.clone(),
                )
            }
            RelayFloorPass::TrustedVaultSide => (
                "relay_trusted_vault_side".to_owned(),
                relay_skip_verdict(receipt.request, receipt.config),
            ),
            RelayFloorPass::NotRelayedByUs => (
                "relay_not_relayed".to_owned(),
                relay_skip_verdict(receipt.request, receipt.config),
            ),
        };
        self.append_policy_model_gate_receipt(
            receipt.request,
            &receipt_verdict,
            &outcome,
            reason_codes,
            notices,
        )?;
        Ok(())
    }
}

struct RelayReceipt<'a> {
    request: &'a PolicyClassifyRequest,
    domain: &'a AttestedRelayDomain,
    pass: &'a RelayFloorPass,
    receipt_breach: Option<&'static str>,
    hosted: Option<&'a HostedLegalPolicy>,
    config: &'a PolicyModelConfig,
}

/// The safeguard model tier a relay pass may consult, with the lease it spends
/// from. Paired because the two are meaningless apart: a backend with no lease
/// has no budget to run under.
#[derive(Clone, Copy)]
pub(crate) struct RelaySafeguardTier<'a> {
    pub(crate) backend: &'a dyn LlmBackend,
    pub(crate) lease: &'a BudgetLease,
}

/// The deterministic hosted verdict: the tripwire hit, or clean.
fn hosted_tripwire_verdict(
    request: &PolicyClassifyRequest,
    hosted: Option<&HostedLegalPolicy>,
    binding: PolicyContentBinding,
    config: &PolicyModelConfig,
) -> PolicyClassifyVerdict {
    let Some(policy) = hosted else {
        return PolicyClassifyVerdict::clean_allow(binding, config);
    };
    match hosted_tripwire_hit(&request.content, policy) {
        Some(row) => hosted_row_verdict(row, policy, binding, config),
        None => PolicyClassifyVerdict::clean_allow(binding, config),
    }
}

fn hosted_row_verdict(
    row: &super::planes::HostedLegalRow,
    policy: &HostedLegalPolicy,
    binding: PolicyContentBinding,
    config: &PolicyModelConfig,
) -> PolicyClassifyVerdict {
    PolicyClassifyVerdict::new(
        row.action.decision(),
        PolicyVerdictCategory::HostedLegal {
            category: row.category,
            jurisdiction: policy.jurisdiction.clone(),
            policy_version: policy.version.clone(),
            row_ref: row.row_ref.clone(),
        },
        PolicyConfidence::CERTAIN,
        binding,
        config,
    )
}

/// Synthetic receipt verdict for a trust-domain SKIP. A skip never classifies
/// against policy state, so the receipt binds to a content-only hash with a
/// zero policy frontier — an honest "did not run" marker.
fn relay_skip_verdict(
    request: &PolicyClassifyRequest,
    config: &PolicyModelConfig,
) -> PolicyClassifyVerdict {
    PolicyClassifyVerdict::clean_allow(relay_skip_content_binding(request), config)
}

fn malformed_relay_policy_error() -> Error {
    Error::InvalidConfig("policy manifest is malformed for relay-boundary floor pass".to_owned())
}
