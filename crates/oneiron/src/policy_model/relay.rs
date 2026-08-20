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
//! # What the engine brings, and what it does not
//!
//! The engine brings NO policy. Not a pattern, not a category list, not a line
//! of prompt. The hosted service registers its own policy document, its own
//! rows and its own pattern rules; the engine stores them, hashes them, sends
//! the document to the classifier the host configured, reads the answer under
//! the contract the document declared, and receipts what happened.
//!
//! # The halt contract
//!
//! A `Block` or `RouteToHelp` halts the relay. A `Warn` does not — the original
//! bytes still go out, with the notice alongside. And a DEGRADED pass halts
//! wherever a hosted legal policy was in play: the hosted plane is fail-closed,
//! so a policy going unanswered must stop the relay rather than be answered
//! with an unexamined allow. A pass goes unanswered four ways — the safeguard
//! model failed, its answer was unreadable, the pass required a model call and
//! had no tier to make it with, or the policy in force declared no output
//! contract to read an answer under. An owner-plane-only degrade never halts;
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
use super::classify::{OwnerPlanePass, pass_audit, wants_model};
use super::concurrent::join2;
use super::notice::{
    HOSTED_NOTICE_TEMPLATE_MAX_FIXED_LEN, policy_model_rationale_notice, policy_notice,
};
use super::pattern::{
    CompiledPatternRule, CompiledPatternRules, POLICY_PATTERN_RULES_MAX, PatternEvaluation,
    PolicyPatternRole, compile_pattern_rules,
};
use super::planes::{HostedLegalPolicy, POLICY_DOCUMENT_MAX_LEN, PolicyPlane, hosted_rubric_rows};
use super::prompt::{AnswerPlane, render_classify_prompt, resolve_policy_model_response};
use super::receipt::policy_model_reason_codes;
use super::request::{PolicyClassifyRequest, PolicyModelConfig};
use super::verdict::{
    HostedLegalCategory, PolicyClassifyDecision, PolicyClassifyVerdict, PolicyConfidence,
    PolicyPassAudit, PolicyVerdictCategory,
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

/// The only scheme a hosted policy's `docs_url` may carry. That field ends up
/// in a notice as the link to the rule a reader was judged under: a
/// `javascript:` or `data:` URL there is not a document at all, and a plain
/// `http:` one lets the text that justifies a block be rewritten in transit.
/// Compared case-insensitively, because URL schemes are.
const HOSTED_LEGAL_DOCS_URL_SCHEME: &str = "https://";

/// Rejects a hosted legal policy that cannot be enforced or cannot be
/// attributed: attribution fields the gate-notice ledger would refuse, a
/// `docs_url` that is not a document a reader can trust, a missing or
/// unbounded policy document, an undeclared output contract, rows that carry
/// no readable rule, two rows claiming the same category, or pattern rules the
/// engine cannot compile.
///
/// Every bound here mirrors one the ledger already enforces, so registration
/// and receipt-append agree by construction — and everything else is refused at
/// REGISTRATION rather than at enforcement time, because a policy that fails
/// only when it fires is an enforcement outage disguised as a runtime error.
fn validate_hosted_legal_policy(
    service: &str,
    policy: &HostedLegalPolicy,
) -> Result<CompiledPatternRules> {
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
    https_attribution(service, "docs_url", &policy.docs_url)?;
    bounded_attribution(
        service,
        "policy_document",
        &policy.policy_document,
        POLICY_DOCUMENT_MAX_LEN,
    )?;
    if policy.output_contract.is_none() {
        return Err(Error::RelayHostedLegalPolicyInvalid {
            service: service.to_owned(),
            field: "output_contract",
            reason: "must be declared so the engine can read the model's answer",
        });
    }
    validate_hosted_rows(service, policy)?;
    compile_pattern_rules(&policy.pattern_rules, &|category| {
        policy.publishes_category(category)
    })
    .map_err(|defect| Error::RelayHostedLegalPolicyInvalid {
        service: service.to_owned(),
        field: defect.field,
        reason: defect.reason,
    })
}

/// A row the model can be shown and a reader can be pointed at.
///
/// The rows ARE the rubric: a blank `text` is sent to the model as the rule it
/// should judge against, and a blank `row_ref` names nothing a reader could go
/// and read. Two rows of the same category are worse than either, because
/// [`HostedLegalPolicy::row_for_category`] takes the FIRST — so a later row
/// with a stricter action is silently shadowed and never fires. Every one of
/// these is refused at registration, mirroring the id/pattern checks
/// `compile_pattern_rules` already applies to this policy's rules.
fn validate_hosted_rows(service: &str, policy: &HostedLegalPolicy) -> Result<()> {
    let invalid = |field: &'static str, reason: &'static str| {
        Err(Error::RelayHostedLegalPolicyInvalid {
            service: service.to_owned(),
            field,
            reason,
        })
    };
    let mut seen: Vec<HostedLegalCategory> = Vec::with_capacity(policy.rows.len());
    for row in &policy.rows {
        if row.row_ref.trim().is_empty() {
            return invalid("row_ref", "must not be blank");
        }
        if row.text.trim().is_empty() {
            return invalid(
                "row_text",
                "must not be blank: the row text IS the rule the model is shown",
            );
        }
        if seen.contains(&row.category) {
            return invalid(
                "row_category",
                "must be unique: a second row of one category never fires",
            );
        }
        seen.push(row.category);
    }
    Ok(())
}

fn https_attribution(service: &str, field: &'static str, value: &str) -> Result<()> {
    let Some(rest) = strip_scheme_ignore_ascii_case(value, HOSTED_LEGAL_DOCS_URL_SCHEME) else {
        return Err(Error::RelayHostedLegalPolicyInvalid {
            service: service.to_owned(),
            field,
            reason: "must be an https:// URL",
        });
    };
    // A bare `https://` passes a prefix check and points at nothing. The
    // scheme is not the document.
    if rest.trim().is_empty() {
        return Err(Error::RelayHostedLegalPolicyInvalid {
            service: service.to_owned(),
            field,
            reason: "must name a host after the https:// scheme",
        });
    }
    Ok(())
}

fn strip_scheme_ignore_ascii_case<'a>(value: &'a str, scheme: &str) -> Option<&'a str> {
    let prefix = value.get(..scheme.len())?;
    prefix
        .eq_ignore_ascii_case(scheme)
        .then(|| &value[scheme.len()..])
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

#[derive(Debug, Clone)]
struct EdgeService {
    class: ConnectionClass,
    legal_policy: Option<HostedLegalPolicy>,
    /// Compiled once, at registration. The relay path never compiles a regex.
    patterns: CompiledPatternRules,
}

/// Compares the DATA a service was registered with. The compiled patterns are
/// derived from `legal_policy`, so comparing them would only ask the same
/// question twice — and a compiled regex has no equality to ask it with.
impl PartialEq for EdgeService {
    fn eq(&self, other: &Self) -> bool {
        self.class == other.class && self.legal_policy == other.legal_policy
    }
}

impl Eq for EdgeService {}

/// Connector-edge service registry: the registration DATA that
/// `AuthenticatedConnectionIdentity::from_edge_auth` validates against (that
/// constructor is crate-private, so it carries no doc link), and the place a
/// hosted service's legal policy is bound to its identity.
///
/// The engine ships the validation MECHANISM only — no service identities, no
/// legal policies and no patterns are engine constants, so adding a hosted
/// connector edge or amending a jurisdiction's rules never forces an engine
/// release. The deployment's connector-edge wiring supplies its own
/// registrations, and the crate's tests register fixture names.
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
                        patterns: CompiledPatternRules::default(),
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
    /// Everything the policy will need at enforcement time is settled HERE —
    /// attribution bounds, the `https://` requirement, a non-blank bounded
    /// policy document, a declared output contract, rows that carry a readable
    /// rule under a category no other row claims, and pattern rules that
    /// compile and name categories this policy publishes.
    ///
    /// The stored `policy_hash` is DERIVED here (see
    /// [`HostedLegalPolicy::derive_policy_hash`]) and replaces whatever the
    /// caller set, so the attestation a receipt carries always names the exact
    /// text that was in force. Amend one byte of the document and no earlier
    /// receipt can attest the amended policy.
    pub fn register_hosted_legal_policy(
        &mut self,
        service: &str,
        policy: HostedLegalPolicy,
    ) -> Result<()> {
        let patterns = validate_hosted_legal_policy(service, &policy)?;
        let entry = self.services.get_mut(service).ok_or_else(|| {
            Error::RelayAttestationInvalidServiceIdentity {
                service_identity: service.to_owned(),
                reason: "hosted legal policy requires a registered connector-edge service",
            }
        })?;
        let mut policy = policy;
        policy.policy_hash = policy.derive_policy_hash();
        entry.legal_policy = Some(policy);
        entry.patterns = patterns;
        Ok(())
    }

    /// Binds a policy WITHOUT the registration guard, so the crate's own tests
    /// can reach the relay branches that exist only for a registry that was
    /// bypassed. `cfg(test)` + `pub(crate)` on purpose: a production-reachable
    /// unchecked bind would make the guard cosmetic.
    #[cfg(test)]
    pub(crate) fn bind_unvalidated_for_testing(
        &mut self,
        service: &str,
        class: ConnectionClass,
        policy: HostedLegalPolicy,
    ) {
        self.services.insert(
            service.to_owned(),
            EdgeService {
                class,
                legal_policy: Some(policy),
                patterns: CompiledPatternRules::default(),
            },
        );
    }

    /// The legal policy bound to a `connector-edge:<name>` identity, if the
    /// deployment registered one. The relay edge looks this up with the
    /// identity it just validated and hands it to the pass.
    #[must_use]
    pub fn hosted_legal_policy(&self, service_identity: &str) -> Option<&HostedLegalPolicy> {
        self.entry(service_identity)?.legal_policy.as_ref()
    }

    /// The most pattern rules one plane may hold. Exposed so a host can size
    /// its own admin surface against the engine's bound rather than guessing.
    #[must_use]
    pub const fn max_pattern_rules() -> usize {
        POLICY_PATTERN_RULES_MAX
    }

    fn compiled_patterns(&self, service_identity: &str) -> Option<&CompiledPatternRules> {
        Some(&self.entry(service_identity)?.patterns)
    }

    fn entry(&self, service_identity: &str) -> Option<&EdgeService> {
        let name = service_identity.strip_prefix(EDGE_SERVICE_IDENTITY_PREFIX)?;
        self.services.get(name)
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

/// Why a hosted relay pass did not get a safeguard-model answer for the policy
/// it ran under. A degraded pass fell back to whatever the substrate owner's
/// own `Decide` rules could conclude (never below it); the marker keeps a
/// degraded `Allow` distinguishable from a model-confirmed `Allow` in receipts
/// and logs.
///
/// `non_exhaustive` on purpose: the variants name coverage gaps, and naming a
/// gap that was previously unnamed is the normal way this list grows. A
/// downstream exhaustive match would turn that into a breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RelayBoundaryDegrade {
    /// The safeguard model was unavailable (transport/backend error).
    SafeguardModelUnavailable,
    /// The safeguard model responded but the answer was unusable —
    /// unreadable under the declared output contract, or naming a category the
    /// policy never published.
    SafeguardModelResponseUnusable,
    /// The pass required a model verdict and had no way to get one: no
    /// safeguard tier was supplied. Distinct from the two outage codes on
    /// purpose — no model failed here, the pass never had one.
    ///
    /// This is one form of the rule the engine has always held: a hosted
    /// policy's rows are prose only a model can read, so a pass without a
    /// model has answered nothing, whatever the patterns concluded.
    SafeguardModelTierAbsent,
    /// The pass had a model to ask but no declared output contract, so no
    /// answer it could get would be readable. Registration refuses a policy
    /// with no contract, so this names a policy that reached the relay without
    /// passing through the registry — the OTHER form of the same rule, and a
    /// different fault to chase than a missing tier.
    OutputContractUndeclared,
}

impl RelayBoundaryDegrade {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SafeguardModelUnavailable => "safeguard_model_unavailable",
            Self::SafeguardModelResponseUnusable => "safeguard_model_response_unusable",
            Self::SafeguardModelTierAbsent => "safeguard_model_tier_absent",
            Self::OutputContractUndeclared => "output_contract_undeclared",
        }
    }
}

/// How a pass reached its verdict. Every arm is a distinct receipt reason, so
/// a substrate owner reading the ledger can tell a pattern-decided block from
/// a model-decided one, and an allow the model examined from an allow the
/// patterns waved through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RelayResolution {
    /// A `Decide` pattern rule was the verdict; the model was never called.
    PatternDecided,
    /// The safeguard model answered and its answer governed.
    ModelDecided,
    /// `PatternGated` and nothing escalated: allowed with zero model calls.
    PatternGatedAllow,
    /// Only `Log` rules matched: recorded, never gated, zero model calls.
    LogOnly,
    /// Nothing to classify against — no hosted policy is bound to this
    /// identity.
    NoPolicyInPlay,
    /// A verified vault-side receipt carried the verdict, and the relay is
    /// returning it as it stands.
    ///
    /// It deliberately claims nothing about HOW the vault reached it. The
    /// receipt attests what was judged, not which machinery judged it: a
    /// vault-side pass may have been decided by one of the owner's `Decide`
    /// patterns with no model call at all, and with no hosted policy bound to
    /// the attested identity there is not even a hosted attestation to narrow
    /// it. Recording this as `ModelDecided` would put a claim in the ledger
    /// that no evidence supports.
    VaultSideDecided,
    /// The pass required a model verdict and did not get one, so it reached no
    /// resolution at all. The degrade marker beside it says why. Recorded as
    /// its own code rather than folded into `ModelDecided`, which would put a
    /// claim in the ledger that no model ever answered.
    Unresolved,
}

impl RelayResolution {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PatternDecided => "pattern_decided",
            Self::ModelDecided => "model_decided",
            Self::PatternGatedAllow => "pattern_gated_allow",
            Self::LogOnly => "log_only",
            Self::NoPolicyInPlay => "no_policy_in_play",
            Self::VaultSideDecided => "vault_side_decided",
            Self::Unresolved => "unresolved",
        }
    }
}

/// Outcome of a relay-boundary pass. Advisory only — this classifies, it does
/// not itself halt the relay; the caller must honor
/// [`RelayBoundaryPass::must_halt_relay`].
///
/// `Classified` is the only variant that ran a pass, and its verdict is
/// HOSTED-LEGAL ONLY — the owner plane is never assembled at the relay, so the
/// verdict category can never be [`PolicyVerdictCategory::OwnerPolicy`] unless
/// it came from a verified vault-side receipt.
///
/// Intentionally `Serialize` but NOT `Deserialize` (same reason as
/// [`RelayTrustDomain`]): a relay outcome is emitted for receipts/logs, never
/// reconstructed from untrusted bytes.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RelayBoundaryPass {
    /// Cloud vault: already classified vault-side and verified here; trusted.
    TrustedVaultSide,
    /// BYO connector: nothing transits our infra; nothing ran.
    NotRelayedByUs,
    /// OUR infra ran the hosted legal pass.
    ///
    /// Boxed because the two skip arms carry nothing: a pass that did not run
    /// should not pay for the verdict of one that did, and this outcome rides
    /// inside every relay call.
    Classified(Box<RelayClassifiedPass>),
}

/// What a relay pass that actually ran concluded.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RelayClassifiedPass {
    pub verdict: PolicyClassifyVerdict,
    /// Set when the pass could not get the model verdict it needed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub degraded: Option<RelayBoundaryDegrade>,
    /// Whether a hosted legal policy was bound to the attested identity at
    /// all. A degrade means something different on each side of that line, so
    /// the fact travels with the pass rather than being re-derived.
    pub hosted_policy_in_play: bool,
    pub resolution: RelayResolution,
}

impl RelayBoundaryPass {
    fn classified(
        verdict: PolicyClassifyVerdict,
        degraded: Option<RelayBoundaryDegrade>,
        hosted_policy_in_play: bool,
        resolution: RelayResolution,
    ) -> Self {
        Self::Classified(Box::new(RelayClassifiedPass {
            verdict,
            degraded,
            hosted_policy_in_play,
            resolution,
        }))
    }

    /// The verdict, present only when OUR infra ran a relay pass.
    #[must_use]
    pub fn boundary_verdict(&self) -> Option<&PolicyClassifyVerdict> {
        match self {
            Self::Classified(pass) => Some(&pass.verdict),
            Self::TrustedVaultSide | Self::NotRelayedByUs => None,
        }
    }

    /// Whether OUR infra ran a classify pass at the relay boundary. False for
    /// a trusted cloud vault and for BYO (never transits us).
    #[must_use]
    pub fn ran_relay_classify(&self) -> bool {
        matches!(self, Self::Classified(_))
    }

    /// The degradation marker, if the pass could not get the model verdict it
    /// needed.
    #[must_use]
    pub fn degraded(&self) -> Option<RelayBoundaryDegrade> {
        match self {
            Self::Classified(pass) => pass.degraded,
            Self::TrustedVaultSide | Self::NotRelayedByUs => None,
        }
    }

    /// How the pass reached its verdict, where it ran one.
    #[must_use]
    pub fn resolution(&self) -> Option<RelayResolution> {
        match self {
            Self::Classified(pass) => Some(pass.resolution),
            Self::TrustedVaultSide | Self::NotRelayedByUs => None,
        }
    }

    /// Whether the caller edge must NOT relay this content. `Block` and
    /// `RouteToHelp` halt; `Warn` does not — a warned relay still delivers the
    /// original content, with its notice alongside. A trusted cloud pass and
    /// an untouched BYO path never halt.
    ///
    /// A DEGRADED pass halts too, but only where a hosted legal policy was in
    /// play. The hosted plane is fail-closed and its rows are prose only the
    /// safeguard model can read, so a pass that never got a model verdict has
    /// zero coverage of them — whether the model was down, answered
    /// unreadably, was never supplied, or had no declared contract to answer
    /// under. Relaying anyway would answer a gap
    /// with an unexamined allow. The owner plane is sovereign and gets the
    /// opposite treatment: an owner-plane-only degrade never halts, because
    /// nothing sits beneath the owner's own policy to fall back to.
    #[must_use]
    pub fn must_halt_relay(&self) -> bool {
        match self {
            Self::Classified(pass) => {
                matches!(
                    pass.verdict.decision,
                    PolicyClassifyDecision::Block | PolicyClassifyDecision::RouteToHelp
                ) || (pass.degraded.is_some() && pass.hosted_policy_in_play)
            }
            Self::TrustedVaultSide | Self::NotRelayedByUs => false,
        }
    }
}

/// Both planes' answers about the same content, from one pass.
///
/// The two are kept apart on purpose. The relay's halt decision is the hosted
/// plane's business and the owner's verdict never feeds it; the owner's
/// enforcement is the vault's business and the hosted verdict never feeds
/// that. What they share is the content and the round trip.
#[derive(Debug, Clone, PartialEq)]
pub struct DualPlanePass {
    /// The vault owner's own verdict. A clean `Allow` when the owner's plane
    /// is off, has no document, or its model did not answer — that plane is
    /// sovereign and fails open.
    pub owner: PolicyClassifyVerdict,
    /// The hosted relay boundary's pass, which is what decides whether the
    /// relay may proceed.
    pub relay: RelayBoundaryPass,
    /// The owner plane wanted a model verdict and did not get one. Never halts
    /// anything; the caller is simply owed the fact.
    pub owner_model_skipped: bool,
}

/// Narrow read-only port for vault-side receipts owned by our relay VM.
pub trait VaultSideVerdictSource {
    /// The latest verdict recorded for this content at the relay boundary. The
    /// key is the locally recomputed, identity-free verification hash.
    fn latest_boundary_verdict(
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
    fn latest_boundary_verdict(
        &self,
        verify_content_hash: &[u8; 32],
    ) -> Result<Option<PolicyClassifyVerdict>> {
        Ok(self.verdicts.get(verify_content_hash).cloned())
    }
}

/// CloudVault verification either supplies its trusted pass or requires the
/// caller to run the hosted pass and audit the breach.
enum CloudVaultPassOrFallback {
    Pass(RelayBoundaryPass),
    HostedFallback { receipt_breach: &'static str },
}

/// The safeguard model tier a pass may consult, with the lease it spends from.
/// Paired because the two are meaningless apart: a backend with no lease has no
/// budget to run under.
///
/// Public because the classifier is the SUBSTRATE OWNER's choice now. An
/// earlier design kept this crate-private on the theory that our relay
/// infrastructure had to pin its own classifier; the ruling this file
/// implements moves every moderation input — patterns, policy document, model
/// binding, generation parameters, classifier mode — to the substrate owner,
/// so there is nothing left for the engine to pin on their behalf.
#[derive(Clone, Copy)]
pub struct RelaySafeguardTier<'a> {
    pub backend: &'a dyn LlmBackend,
    pub lease: &'a BudgetLease,
}

impl std::fmt::Debug for RelaySafeguardTier<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelaySafeguardTier")
            .field("lease", &self.lease.id())
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// The relay-boundary pass over the hosted legal plane.
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
    ///   plane. The owner plane is never assembled or evaluated here.
    /// * [`RelayTrustDomain::LocalViaByoConnector`] — nothing transits us; no
    ///   pass runs ([`RelayBoundaryPass::NotRelayedByUs`]).
    ///
    /// `safeguard` is optional so a deployment with no classifier can still
    /// call this — but a pass that NEEDED a model verdict and had none is
    /// degraded, and a degraded pass with a hosted policy in play halts the
    /// relay. Deterministic coverage during an outage is exactly and only the
    /// substrate owner's `Decide` pattern rules.
    ///
    /// Advisory: this classifies but does not itself halt the relay — the
    /// caller must honor [`RelayBoundaryPass::must_halt_relay`]. Every pass
    /// that carries a signal is receipted; the one pass that is not is a clean
    /// allow the model actually examined with nothing to say. A returned `Err`
    /// means infrastructure misuse only — unresolvable/malformed local policy
    /// state or a failed receipt write — never a model outcome.
    pub async fn relay_boundary_pass(
        &self,
        request: PolicyClassifyRequest,
        domain: &AttestedRelayDomain,
        registry: &EdgeServiceRegistry,
        config: &PolicyModelConfig,
        safeguard: Option<RelaySafeguardTier<'_>>,
        verdicts: &dyn VaultSideVerdictSource,
    ) -> Result<RelayBoundaryPass> {
        let hosted = registry.hosted_legal_policy(domain.service_identity());
        let patterns = registry.compiled_patterns(domain.service_identity());
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
                        self.hosted_relay_pass(&request, hosted, patterns, config, safeguard)
                            .await?
                    }
                }
            }
            RelayTrustDomain::LocalViaByoConnector => RelayBoundaryPass::NotRelayedByUs,
            RelayTrustDomain::LocalViaHostedConnector => {
                self.hosted_relay_pass(&request, hosted, patterns, config, safeguard)
                    .await?
            }
        };
        self.record_relay_receipt(RelayReceipt {
            request: &request,
            domain,
            pass: &pass,
            receipt_breach,
            hosted,
            config,
        })?;
        Ok(pass)
    }

    /// Both planes, one round trip.
    ///
    /// For content that BOTH leaves a vault under its owner's policy AND
    /// transits our relay under a hosted legal policy, the two model calls are
    /// independent — different documents, different rows, different machinery —
    /// so they are ISSUED CONCURRENTLY rather than one after the other. The
    /// latency of asking two planes is the latency of asking one.
    ///
    /// Each verdict is routed to its own plane: the hosted pass decides whether
    /// the relay may proceed, and the owner's verdict is the vault's to enforce.
    /// Neither is allowed to stand in for the other.
    pub async fn classify_both_planes(
        &self,
        request: PolicyClassifyRequest,
        domain: &AttestedRelayDomain,
        registry: &EdgeServiceRegistry,
        config: &PolicyModelConfig,
        safeguard: Option<RelaySafeguardTier<'_>>,
        verdicts: &dyn VaultSideVerdictSource,
    ) -> Result<DualPlanePass> {
        let owner_safeguard = safeguard.map(|tier| (tier.backend, tier.lease));
        let (owner, relay) = join2(
            self.owner_plane_pass(&request, config, owner_safeguard),
            self.relay_boundary_pass(
                request.clone(),
                domain,
                registry,
                config,
                safeguard,
                verdicts,
            ),
        )
        .await;
        let OwnerPlanePass {
            verdict,
            model_skipped,
        } = owner?;
        Ok(DualPlanePass {
            owner: verdict,
            relay: relay?,
            owner_model_skipped: model_skipped,
        })
    }

    async fn hosted_relay_pass(
        &self,
        request: &PolicyClassifyRequest,
        hosted: Option<&HostedLegalPolicy>,
        patterns: Option<&CompiledPatternRules>,
        config: &PolicyModelConfig,
        safeguard: Option<RelaySafeguardTier<'_>>,
    ) -> Result<RelayBoundaryPass> {
        let binding = self.relay_policy_binding(request, config)?;
        let Some(policy) = hosted else {
            // No hosted policy in play: there is nothing to classify against,
            // so the model is never called and nothing can degrade.
            return Ok(RelayBoundaryPass::classified(
                PolicyClassifyVerdict::clean_allow(binding, config),
                None,
                false,
                RelayResolution::NoPolicyInPlay,
            ));
        };
        let empty = CompiledPatternRules::default();
        let patterns = patterns.unwrap_or(&empty);
        let evaluation = patterns
            .evaluate_where(&request.content, &|rule: &CompiledPatternRule| {
                policy.row_for_category(rule.category()).is_some()
            });
        let audit = pass_audit(&evaluation);

        if evaluation.acting_role() == Some(PolicyPatternRole::Decide) {
            // A hard rule the substrate owner wrote. It is the verdict, the
            // model is not consulted, and this is the coverage that survives an
            // outage.
            let row = evaluation
                .acting
                .and_then(|rule| policy.row_for_category(rule.category()));
            if let Some(row) = row {
                return Ok(RelayBoundaryPass::classified(
                    hosted_row_verdict(row, policy, binding, config).with_audit(audit),
                    None,
                    true,
                    RelayResolution::PatternDecided,
                ));
            }
        }
        if !wants_model(config.relay_classifier_mode, evaluation.acting_role()) {
            return Ok(RelayBoundaryPass::classified(
                PolicyClassifyVerdict::clean_allow(binding, config).with_audit(audit),
                None,
                true,
                log_only_or_gated(&evaluation),
            ));
        }
        let Some(safeguard) = safeguard else {
            return Ok(degraded_hosted_pass(
                binding,
                config,
                audit,
                RelayBoundaryDegrade::SafeguardModelTierAbsent,
            ));
        };
        let Some(contract) = policy.output_contract else {
            // Registration refuses this, so reaching it means the registry was
            // bypassed. Fail closed rather than guess the answer shape — and
            // say WHICH gap it was: there is a model here, what is missing is
            // the shape of the answer.
            return Ok(degraded_hosted_pass(
                binding,
                config,
                audit,
                RelayBoundaryDegrade::OutputContractUndeclared,
            ));
        };
        let prompt = render_classify_prompt(
            request,
            &policy.policy_document,
            hosted_rubric_rows(policy),
            contract,
        );
        let response = match safeguard
            .backend
            .generate(prompt.llm_request(config), safeguard.lease)
            .await
        {
            Ok(response) => response,
            Err(_unavailable) => {
                return Ok(degraded_hosted_pass(
                    binding,
                    config,
                    audit,
                    RelayBoundaryDegrade::SafeguardModelUnavailable,
                ));
            }
        };
        let Ok(resolved) =
            resolve_policy_model_response(&response, &prompt, &AnswerPlane::Hosted(policy))
        else {
            return Ok(degraded_hosted_pass(
                binding,
                config,
                audit,
                RelayBoundaryDegrade::SafeguardModelResponseUnusable,
            ));
        };
        let mut audit = audit;
        audit.model_rule_ids = resolved.answer.rule_ids;
        audit.model_confidence = resolved.answer.confidence;
        audit.model_rationale = resolved.answer.rationale;
        Ok(RelayBoundaryPass::classified(
            PolicyClassifyVerdict::new(
                resolved.decision,
                resolved.category,
                PolicyConfidence::MEDIUM,
                binding,
                config,
            )
            .with_audit(audit),
            None,
            true,
            RelayResolution::ModelDecided,
        ))
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
    /// version and hash — and since the hash now covers the policy DOCUMENT,
    /// that evidence names the exact text that was in force.
    ///
    /// A receipt without it is not an ERROR, it is simply not evidence of a
    /// hosted pass: it falls through to the hosted pass like any other
    /// untrusted receipt, and the breach is audited.
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
    ) -> Result<RelayBoundaryPass> {
        let binding = self.relay_verify_binding(request, config)?;
        let Some(receipt) = verdicts.latest_boundary_verdict(&binding.content_hash)? else {
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
            // Returned as it stands, and recorded as exactly that. The relay
            // verified WHAT was judged; it has no evidence of HOW, and with no
            // hosted policy bound the attestation check that would narrow it
            // never even ran.
            return Ok(RelayBoundaryPass::classified(
                receipt,
                None,
                hosted.is_some(),
                RelayResolution::VaultSideDecided,
            ));
        }
        Ok(RelayBoundaryPass::TrustedVaultSide)
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

    /// Writes the relay-boundary audit receipt.
    ///
    /// The rule is that a pass carrying ANY signal is recorded: a warn, block
    /// or route; a degrade; an untrusted vault receipt; a trust-domain skip;
    /// any substrate-owner pattern that matched — including one the model went
    /// on to overrule, which is precisely the data that tells the owner their
    /// pattern is too wide; and any resolution other than a clean one nobody
    /// needs told about.
    ///
    /// Exactly TWO pass shapes write nothing, and both are silent because there
    /// was nothing to say: the model looked at the content and found it clean
    /// ([`RelayResolution::ModelDecided`]), and no hosted policy was bound to
    /// the attested identity at all
    /// ([`RelayResolution::NoPolicyInPlay`]) — in the second case no question
    /// was ever asked, so there is no answer to record. Either way a degrade, a
    /// breach or a matched pattern puts the row back.
    fn record_relay_receipt(&self, receipt: RelayReceipt<'_>) -> Result<()> {
        let domain = receipt.domain.domain();
        // The gate decision ledger requires every reason code to be namespaced
        // under `gate.`, so relay codes ride there too.
        let mut reason_codes = vec![
            format!("gate.relay.trust_domain.{}", domain.as_str()),
            format!(
                "gate.relay.classifier_mode.{}",
                receipt.config.relay_classifier_mode.as_str()
            ),
            if receipt.pass.ran_relay_classify() {
                "gate.relay.classify.ran".to_owned()
            } else {
                "gate.relay.classify.skipped".to_owned()
            },
        ];
        if let Some(degrade) = receipt.pass.degraded() {
            reason_codes.push(format!("gate.relay.degraded.{}", degrade.as_str()));
        }
        if let Some(resolution) = receipt.pass.resolution() {
            reason_codes.push(format!("gate.relay.resolution.{}", resolution.as_str()));
        }
        if let Some(reason) = receipt.receipt_breach {
            reason_codes.push(format!("gate.relay.vault_receipt_untrusted.{reason}"));
        }
        let mut notices = Vec::new();
        let (outcome, receipt_verdict) = match receipt.pass {
            RelayBoundaryPass::Classified(classified) => {
                let verdict = &classified.verdict;
                let signalless = verdict.decision == PolicyClassifyDecision::Allow
                    && classified.degraded.is_none()
                    && receipt.receipt_breach.is_none()
                    && matches!(
                        classified.resolution,
                        RelayResolution::ModelDecided | RelayResolution::NoPolicyInPlay
                    )
                    && verdict.audit.is_none();
                if signalless {
                    return Ok(());
                }
                reason_codes.extend(policy_model_reason_codes(verdict));
                notices.extend(policy_notice(
                    verdict.decision,
                    &verdict.category,
                    receipt.hosted,
                    receipt.config,
                ));
                // The relay boundary evaluates the hosted plane and nothing
                // else, so a rationale its verdict does not attribute — a
                // clean allow the model examined after a pattern fired — is
                // still a hosted-plane row.
                notices.extend(policy_model_rationale_notice(
                    verdict,
                    PolicyPlane::HostedLegal,
                    receipt.hosted.map(|hosted| hosted.version.as_str()),
                ));
                (
                    format!("relay_boundary_{}", verdict.decision.ledger_str()),
                    verdict.clone(),
                )
            }
            RelayBoundaryPass::TrustedVaultSide => (
                "relay_trusted_vault_side".to_owned(),
                relay_skip_verdict(receipt.request, receipt.config),
            ),
            RelayBoundaryPass::NotRelayedByUs => (
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

/// A pass that needed a model verdict and did not get one. The verdict falls
/// back to a clean allow — never below whatever a `Decide` rule already
/// concluded, because a `Decide` hit returns before this is reachable — and the
/// degrade marker is what makes the relay halt.
fn degraded_hosted_pass(
    binding: PolicyContentBinding,
    config: &PolicyModelConfig,
    audit: PolicyPassAudit,
    degrade: RelayBoundaryDegrade,
) -> RelayBoundaryPass {
    RelayBoundaryPass::classified(
        PolicyClassifyVerdict::clean_allow(binding, config).with_audit(audit),
        Some(degrade),
        true,
        RelayResolution::Unresolved,
    )
}

/// Which zero-model allow this is: only `Log` rules matched, or the gate simply
/// found nothing to escalate.
fn log_only_or_gated(evaluation: &PatternEvaluation<'_>) -> RelayResolution {
    if evaluation.acting_role() == Some(PolicyPatternRole::Log) {
        RelayResolution::LogOnly
    } else {
        RelayResolution::PatternGatedAllow
    }
}

struct RelayReceipt<'a> {
    request: &'a PolicyClassifyRequest,
    domain: &'a AttestedRelayDomain,
    pass: &'a RelayBoundaryPass,
    receipt_breach: Option<&'static str>,
    hosted: Option<&'a HostedLegalPolicy>,
    config: &'a PolicyModelConfig,
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
    Error::InvalidConfig("policy manifest is malformed for relay-boundary pass".to_owned())
}
