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
//!
//! That is the DEFAULT, and it stays the engine's own position. Whether an
//! outage in the host's own model tier should stop the host's own relay is the
//! host's exposure to weigh, so [`HostedOutagePolicy`] lets it choose
//! availability instead — for MODEL-AVAILABILITY degrades only, and never for
//! a verdict that could not be attested. See that type for the full split.

use std::collections::{BTreeMap, HashMap};

use serde::Serialize;

use crate::Vault;
use crate::error::{Error, Result};
use crate::gate;
use crate::llm::{BudgetLease, LlmBackend};
use crate::store::{
    GATE_SYSTEM_NOTICE_BODY_MAX_LEN, GATE_SYSTEM_NOTICE_DOCS_URL_MAX_LEN,
    GATE_SYSTEM_NOTICE_VERSION_MAX_LEN, GateSystemNoticeRecord,
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
use super::planes::{
    HostedLegalPolicy, POLICY_DOCUMENT_MAX_LEN, POLICY_HOSTED_CATEGORY_MAX_LEN, PolicyPlane,
    hosted_rubric_rows,
};
use super::prompt::{AnswerPlane, render_classify_prompt, resolve_policy_model_response};
use super::receipt::policy_model_reason_codes;
use super::request::{HostedOutagePolicy, PolicyClassifyRequest, PolicyModelConfig};
use super::verdict::{
    PolicyClassifyDecision, PolicyClassifyVerdict, PolicyConfidence, PolicyPassAudit,
    PolicyVerdictCategory,
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
/// and read. Two rows sharing a `row_ref` are worse than either, because
/// `row_ref` is what tells one legal concern from another in a notice and a
/// receipt — with it duplicated, a reader pointed at the rule they were judged
/// under finds two.
///
/// The CATEGORY is checked for shape and nothing else. It is the host's own
/// word, not a vocabulary the engine publishes, and several rows may share one
/// — two distinct concerns of the same class are two rows, and
/// [`HostedLegalPolicy::row_for_category`] resolves a shared label to the
/// strictest of them. What the shape check exists for is that the label rides
/// into a gate reason code as written: the bound and charset are the ones
/// `compile_pattern_rules` already holds this policy's rule ids to.
///
/// Every one of these is refused at REGISTRATION, so a policy that cannot be
/// enforced never reaches the relay to fail there.
fn validate_hosted_rows(service: &str, policy: &HostedLegalPolicy) -> Result<()> {
    let invalid = |field: &'static str, reason: &'static str| {
        Err(Error::RelayHostedLegalPolicyInvalid {
            service: service.to_owned(),
            field,
            reason,
        })
    };
    let mut seen: Vec<&str> = Vec::with_capacity(policy.rows.len());
    for row in &policy.rows {
        if row.row_ref.trim().is_empty() {
            return invalid("row_ref", "must not be blank");
        }
        if seen.contains(&row.row_ref.as_str()) {
            return invalid(
                "row_ref",
                "must be unique: it is what tells two rows of one category apart",
            );
        }
        if row.text.trim().is_empty() {
            return invalid(
                "row_text",
                "must not be blank: the row text IS the rule the model is shown",
            );
        }
        if row.category.trim().is_empty() {
            return invalid("row_category", "must not be blank");
        }
        if row.category.len() > POLICY_HOSTED_CATEGORY_MAX_LEN {
            return invalid(
                "row_category",
                "is longer than a receiptable category label",
            );
        }
        if !row
            .category
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        {
            return invalid(
                "row_category",
                "must be ascii alphanumeric with `_`, `-` or `.`",
            );
        }
        seen.push(row.row_ref.as_str());
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

/// Why a hosted relay pass could not put a usable safeguard-model answer
/// against the policy it ran under. A degraded pass fell back to whatever the
/// substrate owner's own `Decide` rules could conclude (never below it); the
/// marker keeps a degraded `Allow` distinguishable from a model-confirmed
/// `Allow` in receipts and logs.
///
/// Most variants name a missing ANSWER. The last names an answer that arrived
/// but could not be pinned to the policy state it was decided against, which
/// leaves the same hole: no verdict the pass can stand behind.
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
    /// The vault's policy state moved out from under the pass twice running,
    /// so no answer could be bound to the policy in force. Not a model fault:
    /// the model may well have answered both times. What is missing is a
    /// verdict this pass can attest, and the hosted plane does not relay
    /// content on a verdict it cannot attest.
    PolicyBindingMovedMidPass,
}

impl RelayBoundaryDegrade {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SafeguardModelUnavailable => "safeguard_model_unavailable",
            Self::SafeguardModelResponseUnusable => "safeguard_model_response_unusable",
            Self::SafeguardModelTierAbsent => "safeguard_model_tier_absent",
            Self::OutputContractUndeclared => "output_contract_undeclared",
            Self::PolicyBindingMovedMidPass => "policy_binding_moved_mid_pass",
        }
    }

    /// Whether this degrade is a MODEL-AVAILABILITY failure: the pass wanted
    /// an answer from a safeguard model and the model side could not supply
    /// one. That is the only class
    /// [`HostedOutagePolicy::ProceedReceipted`] applies to.
    ///
    /// The other two are excluded for reasons that are not about uptime.
    /// [`Self::OutputContractUndeclared`] means a policy reached the relay
    /// without passing registration, which no amount of model availability
    /// would fix. [`Self::PolicyBindingMovedMidPass`] means an answer arrived
    /// and could not be pinned to the policy state it was decided against —
    /// an unattestable verdict, which the hosted plane refuses to relay on
    /// whatever the host's outage posture is.
    #[must_use]
    pub const fn is_model_availability(self) -> bool {
        match self {
            Self::SafeguardModelUnavailable
            | Self::SafeguardModelResponseUnusable
            | Self::SafeguardModelTierAbsent => true,
            Self::OutputContractUndeclared | Self::PolicyBindingMovedMidPass => false,
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
    /// Whether [`Self::degraded`] stops the relay.
    ///
    /// Resolved where the degrade was RAISED, from the host's
    /// [`HostedOutagePolicy`] and the kind of degrade, because that is the one
    /// place holding both. Always `false` when nothing degraded — a pass with
    /// no degrade halts on its verdict alone.
    pub degrade_halts: bool,
    /// Whether a hosted legal policy was bound to the attested identity at
    /// all. A degrade means something different on each side of that line, so
    /// the fact travels with the pass rather than being re-derived.
    pub hosted_policy_in_play: bool,
    pub resolution: RelayResolution,
}

impl RelayBoundaryPass {
    /// A pass that reached a verdict. Every degrade in the crate is minted by
    /// [`degraded_hosted_pass`], which resolves the halt against the host's
    /// outage policy; this constructor is the non-degraded path, so it stays
    /// fail-closed by construction — any degrade arriving here halts.
    pub(super) fn classified(
        verdict: PolicyClassifyVerdict,
        degraded: Option<RelayBoundaryDegrade>,
        hosted_policy_in_play: bool,
        resolution: RelayResolution,
    ) -> Self {
        Self::Classified(Box::new(RelayClassifiedPass {
            verdict,
            degrade_halts: degraded.is_some(),
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

    /// Whether a hosted legal policy was bound to the attested identity for
    /// this pass. A degrade raised AFTER the pass has to carry the same answer
    /// the pass had, or a fallback with no hosted policy comes back claiming a
    /// plane it never had — and [`Self::must_halt_relay`] reads exactly this
    /// flag, so it would halt on it too.
    #[must_use]
    pub fn hosted_policy_in_play(&self) -> bool {
        match self {
            Self::Classified(pass) => pass.hosted_policy_in_play,
            Self::TrustedVaultSide | Self::NotRelayedByUs => false,
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
    ///
    /// That remains the DEFAULT and is what an unconfigured host gets. A host
    /// that chose [`HostedOutagePolicy::ProceedReceipted`] trades it for
    /// availability on model-availability degrades only, and the pass records
    /// that choice in [`RelayClassifiedPass::degrade_halts`] at the point the
    /// degrade was raised. A `Block` or `RouteToHelp` verdict halts either
    /// way: that is an answer, not an outage.
    #[must_use]
    pub fn must_halt_relay(&self) -> bool {
        match self {
            Self::Classified(pass) => {
                matches!(
                    pass.verdict.decision,
                    PolicyClassifyDecision::Block | PolicyClassifyDecision::RouteToHelp
                ) || (pass.degrade_halts && pass.hosted_policy_in_play)
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
        // The receipt write takes the LAST word on the policy binding, so a
        // move it catches replaces the pass the caller gets. Otherwise the
        // ledger would record a halt-worthy degrade against a pass whose
        // `must_halt_relay` is false, and the relay would proceed on an allow
        // its own receipt disowns.
        let recorded = self.record_relay_receipt(RelayReceipt {
            request: &request,
            domain,
            pass: &pass,
            receipt_breach,
            hosted,
            config,
        })?;
        Ok(recorded.unwrap_or(pass))
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
    ///
    /// BOTH planes are receipted, HERE, because this is the door that made
    /// both decisions. The relay pass writes its own row on the way through;
    /// the owner pass gets one under owner-plane keys, so a vault owner
    /// reading their own ledger finds their plane's verdict about their own
    /// content beside the hosted service's. A model that failed leaves a row
    /// too, saying the plane fell open.
    ///
    /// The owner verdict is handed back raw for the vault to enforce, and
    /// [`Vault::enforce_policy_model_verdict`] is where it goes. That door
    /// deliberately writes nothing: the decision is already in the ledger, and
    /// a second row for it under a second outcome would double every count
    /// read off those rows.
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
        let owner = owner?;
        let relay = relay?;
        self.record_owner_plane_receipt(&request, &owner, config)?;
        let OwnerPlanePass {
            verdict,
            model_skipped,
        } = owner;
        Ok(DualPlanePass {
            owner: verdict,
            relay,
            owner_model_skipped: model_skipped,
        })
    }

    /// Writes the OWNER plane's row for a dual-plane pass.
    ///
    /// The relay side receipts itself; this is the other half of the same
    /// pass, written under owner-plane keys with the same conventions as the
    /// relay row — `gate.`-namespaced codes, model-supplied strings tokenized
    /// by [`policy_model_reason_codes`]. Enforcing the verdict afterwards adds
    /// no second row; see [`Vault::enforce_policy_model_verdict`].
    ///
    /// Same silence rule too: a clean allow that learned nothing and got the
    /// model it wanted has nothing to record. A pass whose model did NOT
    /// answer is the opposite — the sovereign plane fell open, and that is
    /// precisely the fact the owner is owed.
    fn record_owner_plane_receipt(
        &self,
        request: &PolicyClassifyRequest,
        pass: &OwnerPlanePass,
        config: &PolicyModelConfig,
    ) -> Result<()> {
        let verdict = &pass.verdict;
        if verdict.decision == PolicyClassifyDecision::Allow
            && verdict.audit.is_none()
            && !pass.model_skipped
        {
            return Ok(());
        }
        let mut reason_codes = vec![
            "gate.relay.owner_plane.classify.ran".to_owned(),
            format!(
                "gate.relay.owner_plane.classifier_mode.{}",
                config.owner_classifier_mode.as_str()
            ),
        ];
        if pass.model_skipped {
            reason_codes.push("gate.relay.owner_plane.model_skipped".to_owned());
            reason_codes.push("gate.relay.owner_plane.fail_open".to_owned());
        }
        reason_codes.extend(policy_model_reason_codes(verdict));
        let mut notices: Vec<_> = policy_notice(verdict.decision, &verdict.category, None, config)
            .into_iter()
            .collect();
        // Appended last, as everywhere: an audit row must never become the
        // single body a caller surfaces.
        notices.extend(policy_model_rationale_notice(
            verdict,
            PolicyPlane::OwnerPolicy,
            None,
        ));
        self.append_policy_model_gate_receipt(
            request,
            verdict,
            &format!("owner_plane_{}", verdict.decision.ledger_str()),
            reason_codes,
            notices,
        )?;
        Ok(())
    }

    /// The hosted pass, plus the re-check its await window requires.
    ///
    /// # The manifest can move while the model is answering
    ///
    /// A pass binds its verdict to the vault's policy state, then AWAITS a
    /// network round trip. Policy state that moves during that await leaves
    /// the pass holding a verdict bound to a frontier that is no longer in
    /// force — and the relay would receipt it under that dead binding, so a
    /// later CloudVault verification recomputing the hash locally would find a
    /// receipt attesting policy state nobody could reproduce.
    ///
    /// This is the hole the owner plane closed at its own enforcement door: the
    /// verdict is checked against what is in force before it is acted on, and
    /// a stale one is derived again, ONCE.
    ///
    /// Where the two planes part is what happens when the second derivation is
    /// stale too. The owner plane is sovereign and fails OPEN. The hosted plane
    /// is fail-CLOSED — its rows are prose only a model can read, and relaying
    /// on a verdict it cannot pin to a policy is the unexamined allow the whole
    /// plane exists to refuse. So it DEGRADES, which is what makes
    /// [`RelayBoundaryPass::must_halt_relay`] stop the relay.
    ///
    /// With no hosted policy bound to the attested identity there is nothing to
    /// pin and no model call to pin it across, so the re-check is skipped
    /// whole.
    async fn hosted_relay_pass(
        &self,
        request: &PolicyClassifyRequest,
        hosted: Option<&HostedLegalPolicy>,
        patterns: Option<&CompiledPatternRules>,
        config: &PolicyModelConfig,
        safeguard: Option<RelaySafeguardTier<'_>>,
    ) -> Result<RelayBoundaryPass> {
        let pass = self
            .hosted_relay_pass_once(request, hosted, patterns, config, safeguard)
            .await?;
        if hosted.is_none() || !self.relay_binding_moved(request, config, &pass)? {
            return Ok(pass);
        }
        let pass = self
            .hosted_relay_pass_once(request, hosted, patterns, config, safeguard)
            .await?;
        if !self.relay_binding_moved(request, config, &pass)? {
            return Ok(pass);
        }
        // Reached only when `hosted.is_some()` — the guard above returns
        // early otherwise — so a hosted policy is bound by construction.
        Ok(degraded_hosted_pass(
            self.relay_policy_binding(request, config)?,
            config,
            pass_audit_of(&pass),
            RelayBoundaryDegrade::PolicyBindingMovedMidPass,
            true,
        ))
    }

    /// Whether the policy state a pass bound its verdict to is still the state
    /// in force. A pass that produced no verdict bound nothing, so nothing of
    /// it can have gone stale.
    fn relay_binding_moved(
        &self,
        request: &PolicyClassifyRequest,
        config: &PolicyModelConfig,
        pass: &RelayBoundaryPass,
    ) -> Result<bool> {
        let Some(verdict) = pass.boundary_verdict() else {
            return Ok(false);
        };
        Ok(verdict.binding != self.relay_policy_binding(request, config)?)
    }

    async fn hosted_relay_pass_once(
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
                PolicyClassifyVerdict::clean_allow(binding, config, PolicyPlane::HostedLegal),
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
        if !wants_model(config.hosted_classifier_mode, evaluation.acting_role()) {
            return Ok(RelayBoundaryPass::classified(
                PolicyClassifyVerdict::clean_allow(binding, config, PolicyPlane::HostedLegal)
                    .with_audit(audit),
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
                true,
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
                true,
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
                    true,
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
                true,
            ));
        };
        let mut audit = audit;
        audit.model_rule_ids = resolved.answer.rule_ids;
        audit.model_rule_ids_dropped = resolved.dropped_rule_ids;
        audit.model_confidence = resolved.answer.confidence;
        audit.model_rationale = resolved.answer.rationale;
        Ok(RelayBoundaryPass::classified(
            PolicyClassifyVerdict::new(
                resolved.decision,
                resolved.category,
                PolicyConfidence::MEDIUM,
                binding,
                config,
                PolicyPlane::HostedLegal,
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
        // The dial gets the same treatment as the selector beside it, and for
        // the same reason: the receipt is only evidence while the
        // configuration that produced it is the configuration in force. It is
        // the OWNER dial, because the pass this receipt records is a
        // vault-side one — the hosted dial governs the pass the relay would
        // run instead, not the pass it is deciding whether to trust. A receipt
        // recording no dial at all predates the field and is not trusted.
        if receipt.classifier_mode != Some(config.owner_classifier_mode) {
            return Err(Error::RelayVaultReceiptUntrusted {
                reason: "classifier_mode_mismatch",
            });
        }
        // The dial gets the same treatment as the selector beside it, and for
        // the same reason: the receipt is only evidence while the
        // configuration that produced it is the configuration in force. It is
        // the OWNER dial, because the pass this receipt records is a
        // vault-side one — the hosted dial governs the pass the relay would
        // run instead, not the pass it is deciding whether to trust. A receipt
        // recording no dial at all predates the field and is not trusted.

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
    /// Test-only door onto [`Self::record_relay_receipt`], which is private
    /// and takes a borrowed struct the test module cannot name a lifetime for
    /// otherwise. No production caller.
    #[cfg(test)]
    pub(super) fn record_relay_receipt_for_test(
        &self,
        request: &PolicyClassifyRequest,
        domain: &AttestedRelayDomain,
        pass: &RelayBoundaryPass,
        hosted: Option<&HostedLegalPolicy>,
        config: &PolicyModelConfig,
    ) -> Result<Option<RelayBoundaryPass>> {
        self.record_relay_receipt(RelayReceipt {
            request,
            domain,
            pass,
            receipt_breach: None,
            hosted,
            config,
        })
    }

    fn record_relay_receipt(&self, receipt: RelayReceipt<'_>) -> Result<Option<RelayBoundaryPass>> {
        let domain = receipt.domain.domain();
        // The gate decision ledger requires every reason code to be namespaced
        // under `gate.`, so relay codes ride there too. This row records the
        // HOSTED plane, so the dial it stamps is the hosted one; the owner
        // plane's row stamps its own under `gate.relay.owner_plane.`.
        let mut reason_codes = vec![
            format!("gate.relay.trust_domain.{}", domain.as_str()),
            format!(
                "gate.relay.classifier_mode.{}",
                receipt.config.hosted_classifier_mode.as_str()
            ),
            if receipt.pass.ran_relay_classify() {
                "gate.relay.classify.ran".to_owned()
            } else {
                "gate.relay.classify.skipped".to_owned()
            },
        ];
        if let Some(degrade) = receipt.pass.degraded() {
            reason_codes.push(format!("gate.relay.degraded.{}", degrade.as_str()));
            // WHICH degrade it was does not tell a reader what the relay then
            // did, because that depends on the host's outage policy and on
            // whether this degrade was an availability one. Say it outright.
            reason_codes.push(
                if receipt.pass.must_halt_relay() {
                    "gate.relay.degrade_halted"
                } else {
                    "gate.relay.degrade_proceeded"
                }
                .to_owned(),
            );
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
                    // A clean allow leaves no row — but it still has a pinned
                    // binding, and the relay is about to act on it. Skipping
                    // the re-check here would leave the commonest hosted
                    // result, an unaudited model allow, as the one path that
                    // can relay against policy state it can no longer pin.
                    // So the check still runs; it just writes nothing unless
                    // the binding moved, in which case the move IS the signal
                    // and earns its row.
                    return self.append_relay_receipt_binding_checked(
                        &receipt,
                        verdict,
                        &format!("relay_boundary_{}", verdict.decision.ledger_str()),
                        reason_codes,
                        Vec::new(),
                        RelayReceiptRow::OnlyIfBindingMoved,
                    );
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
        self.append_relay_receipt_binding_checked(
            &receipt,
            &receipt_verdict,
            &outcome,
            reason_codes,
            notices,
            RelayReceiptRow::Always,
        )
    }

    /// Writes the relay row, re-checking the policy binding INSIDE the write
    /// transaction and recording a degrade instead if it moved.
    ///
    /// The pass re-checks its binding and then returns; this row is written in
    /// a separate transaction afterwards. That gap is the same window the
    /// mid-pass re-check closes one seam earlier, and it has the same
    /// consequence: a manifest that moves in it leaves the ledger asserting a
    /// verdict against policy state nobody can reproduce, which is exactly
    /// what a later CloudVault verification would fail on.
    ///
    /// So the last word is taken where the row is written. If the binding
    /// moved, the row records `PolicyBindingMovedMidPass` against the FRESH
    /// binding rather than the verdict's dead one — the pass's own audit rides
    /// along, because what the substrate owner's patterns matched is still
    /// true and should not be thrown away with the verdict it replaces.
    ///
    /// A pass with no boundary verdict pinned nothing, so there is nothing of
    /// it to go stale and the check is skipped.
    ///
    /// Returns the degraded pass when the binding moved, so the CALLER's pass
    /// becomes the one the ledger describes. Writing a halt-worthy degrade row
    /// and then handing back the undegraded pass would make the ledger and the
    /// behaviour disagree: `must_halt_relay` would be false on a pass whose
    /// receipt says the relay stopped. A record nobody honours is worse than
    /// no record, because it reads as authoritative.
    pub(super) fn append_relay_receipt_binding_checked(
        &self,
        receipt: &RelayReceipt<'_>,
        verdict: &PolicyClassifyVerdict,
        outcome: &str,
        reason_codes: Vec<String>,
        notices: Vec<GateSystemNoticeRecord>,
        row: RelayReceiptRow,
    ) -> Result<Option<RelayBoundaryPass>> {
        // Only a pass OUR hosted path minted pinned a `content_binding`, and
        // only that binding is comparable to a freshly derived one. A verified
        // vault-side verdict is returned as it stands and carries the
        // identity-free VERIFY binding instead — a different family, so
        // comparing it here would read every such receipt as moved. It was
        // never pinned to the manifest by this pass, so there is nothing of it
        // to go stale.
        //
        // And no hosted policy means no re-check at all, in PARITY with
        // `hosted_relay_pass`: that seam skips its own comparison whenever
        // `hosted.is_none()`, because with nothing bound to the attested
        // identity there is nothing to pin and no model call to pin it
        // across. Running the comparison here and not there would let the
        // same event produce a degrade one seam later than it possibly could
        // — and a `NoPolicyInPlay` fallback, reachable through a receipt
        // breach, would come back HALTING on a hosted plane that was never in
        // play.
        let pinned = match receipt.pass.resolution() {
            Some(RelayResolution::VaultSideDecided) | None => None,
            _ if receipt.hosted.is_none() => None,
            Some(_) => receipt.pass.boundary_verdict().map(|v| v.binding),
        };
        let mut wtxn = self.store.env.write_txn()?;
        let moved = match pinned {
            Some(pinned) => {
                let policy = gate::resolve_policy_manifest(&self.store, &wtxn)?;
                if policy.diagnostics().loaded_manifest_forces_fail_closed() {
                    return Err(malformed_relay_policy_error());
                }
                let fresh = content_binding(receipt.request, &policy, receipt.config)?;
                (fresh != pinned).then_some(fresh)
            }
            None => None,
        };
        match moved {
            None => {
                if row == RelayReceiptRow::OnlyIfBindingMoved {
                    return Ok(None);
                }
                self.append_policy_model_gate_receipt_in_txn(
                    &mut wtxn,
                    receipt.request,
                    verdict,
                    outcome,
                    reason_codes,
                    notices,
                )?;
            }
            Some(fresh) => {
                // Minted through the one constructor that raises a degrade,
                // and told what the ORIGINAL pass knew: whether a hosted
                // policy was bound at all. Hardcoding that true would make a
                // fallback with no hosted policy in play come back claiming a
                // plane it never had — and `must_halt_relay` reads exactly
                // that flag, so it would halt on it too.
                let moved_pass = degraded_hosted_pass(
                    fresh,
                    receipt.config,
                    pass_audit_of(receipt.pass),
                    RelayBoundaryDegrade::PolicyBindingMovedMidPass,
                    receipt.pass.hosted_policy_in_play(),
                );
                let degraded = moved_pass
                    .boundary_verdict()
                    .ok_or(Error::CorruptedIndex("degraded relay pass without verdict"))?
                    .clone();
                let mut codes = vec![
                    format!(
                        "gate.relay.trust_domain.{}",
                        receipt.domain.domain().as_str()
                    ),
                    format!(
                        "gate.relay.classifier_mode.{}",
                        receipt.config.relay_classifier_mode.as_str()
                    ),
                    if receipt.pass.ran_relay_classify() {
                        "gate.relay.classify.ran".to_owned()
                    } else {
                        "gate.relay.classify.skipped".to_owned()
                    },
                    format!(
                        "gate.relay.degraded.{}",
                        RelayBoundaryDegrade::PolicyBindingMovedMidPass.as_str()
                    ),
                    format!(
                        "gate.relay.resolution.{}",
                        RelayResolution::Unresolved.as_str()
                    ),
                ];
                // The verdict is replaced; the EVIDENCE for why this pass ran
                // the way it did is not. An untrusted vault receipt is the
                // reason the hosted fallback happened at all, and rebuilding
                // the codes from scratch dropped it.
                if let Some(reason) = receipt.receipt_breach {
                    codes.push(format!("gate.relay.vault_receipt_untrusted.{reason}"));
                }
                codes.extend(policy_model_reason_codes(&degraded));
                // Same rule, the other carrier. `pass_audit_of` copies the
                // model's rule ids and confidence into the replacement, but
                // the RATIONALE has no reason code — its only durable form is
                // the audit notice, and passing an empty notice list threw it
                // away. What the model said about the substrate owner's rules
                // is what the owner reads back to improve them; replacing the
                // verdict is no reason to lose it.
                let notices: Vec<GateSystemNoticeRecord> = policy_model_rationale_notice(
                    &degraded,
                    PolicyPlane::HostedLegal,
                    receipt.hosted.map(|hosted| hosted.version.as_str()),
                )
                .into_iter()
                .collect();
                self.append_policy_model_gate_receipt_in_txn(
                    &mut wtxn,
                    receipt.request,
                    &degraded,
                    "relay_boundary_allow",
                    codes,
                    notices,
                )?;
                wtxn.commit()?;
                return Ok(Some(moved_pass));
            }
        }
        wtxn.commit()?;
        Ok(None)
    }
}

/// What a pass learned on its way to a verdict, so a degrade raised AFTER the
/// pass ran does not throw the substrate owner's matched pattern ids away with
/// the verdict it replaces.
fn pass_audit_of(pass: &RelayBoundaryPass) -> PolicyPassAudit {
    pass.boundary_verdict()
        .and_then(|verdict| verdict.audit.as_deref().cloned())
        .unwrap_or_default()
}

/// Whether the binding-checked receipt write leaves a row when the binding did
/// NOT move. A signalless clean allow writes none — that is the ledger's
/// existing contract — but it still has a pinned binding the relay is about to
/// act on, so it takes the check and writes only if the check finds something.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RelayReceiptRow {
    /// Write the row whatever the check finds.
    Always,
    /// Write only the degrade row, and only if the binding moved.
    OnlyIfBindingMoved,
}

/// A pass that needed a model verdict and did not get one. The verdict falls
/// back to a clean allow — never below whatever a `Decide` rule already
/// concluded, because a `Decide` hit returns before this is reachable — and the
/// degrade marker is what makes the relay halt.
///
/// This is the ONLY place in the crate that raises a degrade, which is why it
/// is also where the halt is resolved: it holds both the degrade and the
/// host's [`HostedOutagePolicy`]. Under the default `Halt` every degrade
/// stops the relay, exactly as before. Under `ProceedReceipted` a
/// model-availability degrade does not — and nothing else changes about the
/// pass: the marker, the `Unresolved` resolution and the receipt row are all
/// still written, so the allow stays visibly one no model confirmed.
fn degraded_hosted_pass(
    binding: PolicyContentBinding,
    config: &PolicyModelConfig,
    audit: PolicyPassAudit,
    degrade: RelayBoundaryDegrade,
    hosted_policy_in_play: bool,
) -> RelayBoundaryPass {
    let degrade_halts = match config.hosted_outage_policy {
        HostedOutagePolicy::Halt => true,
        HostedOutagePolicy::ProceedReceipted => !degrade.is_model_availability(),
    };
    RelayBoundaryPass::Classified(Box::new(RelayClassifiedPass {
        verdict: PolicyClassifyVerdict::clean_allow(binding, config, PolicyPlane::HostedLegal)
            .with_audit(audit),
        degraded: Some(degrade),
        degrade_halts,
        hosted_policy_in_play,
        resolution: RelayResolution::Unresolved,
    }))
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

pub(super) struct RelayReceipt<'a> {
    pub(super) request: &'a PolicyClassifyRequest,
    pub(super) domain: &'a AttestedRelayDomain,
    pub(super) pass: &'a RelayBoundaryPass,
    pub(super) receipt_breach: Option<&'static str>,
    pub(super) hosted: Option<&'a HostedLegalPolicy>,
    pub(super) config: &'a PolicyModelConfig,
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
            category: row.category.clone(),
            jurisdiction: policy.jurisdiction.clone(),
            policy_version: policy.version.clone(),
            row_ref: row.row_ref.clone(),
        },
        PolicyConfidence::CERTAIN,
        binding,
        config,
        PolicyPlane::HostedLegal,
    )
}

/// Synthetic receipt verdict for a trust-domain SKIP. A skip never classifies
/// against policy state, so the receipt binds to a content-only hash with a
/// zero policy frontier — an honest "did not run" marker.
fn relay_skip_verdict(
    request: &PolicyClassifyRequest,
    config: &PolicyModelConfig,
) -> PolicyClassifyVerdict {
    PolicyClassifyVerdict::clean_allow(
        relay_skip_content_binding(request),
        config,
        PolicyPlane::HostedLegal,
    )
}

fn malformed_relay_policy_error() -> Error {
    Error::InvalidConfig("policy manifest is malformed for relay-boundary pass".to_owned())
}
