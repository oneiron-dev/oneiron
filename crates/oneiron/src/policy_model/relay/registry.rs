//! Registration data and fail-closed validation: hosted-legal bounds and row checks plus the EdgeServiceRegistry bind paths.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::{Error, Result};
use crate::store::{
    GATE_SYSTEM_NOTICE_BODY_MAX_LEN, GATE_SYSTEM_NOTICE_DOCS_URL_MAX_LEN,
    GATE_SYSTEM_NOTICE_ROW_REF_MAX_LEN, GATE_SYSTEM_NOTICE_VERSION_MAX_LEN,
};

use super::super::notice::HOSTED_NOTICE_TEMPLATE_MAX_FIXED_LEN;
use super::super::pattern::{
    CompiledPatternRules, POLICY_PATTERN_RULES_MAX, compile_pattern_rules,
};
use super::super::planes::{
    HostedLegalPolicy, POLICY_DOCUMENT_MAX_LEN, POLICY_HOSTED_CATEGORY_MAX_LEN,
    POLICY_HOSTED_ROWS_MAX,
};
use super::trust::{ConnectionClass, EDGE_SERVICE_IDENTITY_PREFIX};
use crate::error::RelayError;

/// How long a jurisdiction name may be. Derived, not chosen: it is exactly the
/// room the gate-notice ledger's body bound leaves once the longest hosted
/// notice template has been paid for, so a registered jurisdiction can never
/// produce a notice the ledger refuses.
pub(in crate::policy_model) const HOSTED_LEGAL_JURISDICTION_MAX_LEN: usize =
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
        return Err(Error::Relay(RelayError::RelayHostedLegalPolicyInvalid {
            service: service.to_owned(),
            field: "output_contract",
            reason: "must be declared so the engine can read the model's answer",
        }));
    }
    validate_hosted_rows(service, policy)?;
    compile_pattern_rules(&policy.pattern_rules, &|category| {
        policy.publishes_category(category)
    })
    .map_err(|defect| {
        Error::Relay(RelayError::RelayHostedLegalPolicyInvalid {
            service: service.to_owned(),
            field: defect.field,
            reason: defect.reason,
        })
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
        Err(Error::Relay(RelayError::RelayHostedLegalPolicyInvalid {
            service: service.to_owned(),
            field,
            reason,
        }))
    };
    if policy.rows.len() > POLICY_HOSTED_ROWS_MAX {
        return invalid(
            "rows",
            "carries more rows than one hosted legal policy may hold",
        );
    }
    // A set, not a linear scan: the check ran once per row against every row
    // kept so far, so a wide policy cost the square of its own width at
    // registration.
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for row in &policy.rows {
        if row.row_ref.trim().is_empty() {
            return invalid("row_ref", "must not be blank");
        }
        // Bounded on the terms the NOTICE layer can actually carry. A ref
        // longer than `GATE_SYSTEM_NOTICE_ROW_REF_MAX_LEN` is not refused
        // there — `safe_notice_row_ref` drops it and lets the verdict stand —
        // so accepting one here buys a host notices that cannot say WHICH of
        // its rows acted. Registration is the moment that is visible and
        // fixable; the notice is not. F109's category bound with the same
        // reasoning, on the field beside it.
        if row.row_ref.trim().len() > GATE_SYSTEM_NOTICE_ROW_REF_MAX_LEN {
            return invalid(
                "row_ref",
                "is longer than a notice can carry, so no notice could name this row",
            );
        }
        if seen.contains(row.row_ref.as_str()) {
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
        seen.insert(row.row_ref.as_str());
    }
    // A `row_ref` may not spell another row's CATEGORY, in either form.
    //
    // Citations resolve through one map keyed by spelling, and a hosted row is
    // citable under its ref, its bare category and its plane-qualified
    // category. If one row's ref equals another row's category alias, the two
    // meanings collide in that map and the ref wins — so a citation of the
    // CONCERN silently canonicalizes to an unrelated row, which is a
    // misattribution in the audit rather than a lost one.
    //
    // The doc on `hosted_category_label` says the prefix is what keeps a
    // hosted label and a ref from ever colliding. That holds against OWNER
    // refs; it does not stop a host from writing the prefixed spelling as its
    // own hosted `row_ref`, which is the case being closed here. Registration
    // is where it is visible and fixable.
    for row in &policy.rows {
        let ref_spelling = row.row_ref.trim();
        // ANOTHER row's category, never its own. A row whose ref and category
        // are the same word is not ambiguous at all — both spellings name that
        // one row, which is exactly what the map should record. Refusing it
        // was a regression in the first version of this check: it rejected the
        // most natural way to write a single-concern row, where the host has
        // no reason to invent a second name for it.
        let collides = policy
            .rows
            .iter()
            .filter(|other| !std::ptr::eq(*other, row))
            .any(|other| {
                other.category == ref_spelling
                    || super::planes::hosted_category_label(&other.category) == ref_spelling
            });
        if collides {
            return invalid(
                "row_ref",
                "must not spell another row's category: one map resolves both, and the ref would win",
            );
        }
    }
    Ok(())
}

fn https_attribution(service: &str, field: &'static str, value: &str) -> Result<()> {
    let Some(rest) = strip_scheme_ignore_ascii_case(value, HOSTED_LEGAL_DOCS_URL_SCHEME) else {
        return Err(Error::Relay(RelayError::RelayHostedLegalPolicyInvalid {
            service: service.to_owned(),
            field,
            reason: "must be an https:// URL",
        }));
    };
    // A bare `https://` passes a prefix check and points at nothing. The
    // scheme is not the document.
    if rest.trim().is_empty() {
        return Err(Error::Relay(RelayError::RelayHostedLegalPolicyInvalid {
            service: service.to_owned(),
            field,
            reason: "must name a host after the https:// scheme",
        }));
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
        return Err(Error::Relay(RelayError::RelayHostedLegalPolicyInvalid {
            service: service.to_owned(),
            field,
            reason: "must not be blank",
        }));
    }
    if value.len() > max_len {
        return Err(Error::Relay(RelayError::RelayHostedLegalPolicyInvalid {
            service: service.to_owned(),
            field,
            reason: "is longer than the gate-notice ledger accepts",
        }));
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub(super) struct EdgeService {
    class: ConnectionClass,
    legal_policy: Option<HostedLegalPolicy>,
    /// Compiled once, at registration. The relay path never compiles a regex.
    pub(super) patterns: CompiledPatternRules,
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
            return Err(Error::Relay(
                RelayError::RelayAttestationInvalidServiceIdentity {
                    service_identity: service.to_owned(),
                    reason: "registered connector-edge service name must be non-empty",
                },
            ));
        }
        match self.services.get(service) {
            Some(registered) if registered.class == class => Ok(()),
            Some(registered) => Err(Error::Relay(
                RelayError::RelayAttestationEdgeServiceConflict {
                    service: service.to_owned(),
                    registered: registered.class.as_str(),
                    claimed: class.as_str(),
                },
            )),
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
            Error::Relay(RelayError::RelayAttestationInvalidServiceIdentity {
                service_identity: service.to_owned(),
                reason: "hosted legal policy requires a registered connector-edge service",
            })
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
    pub(in crate::policy_model) fn bind_unvalidated_for_testing(
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

    pub(super) fn entry(&self, service_identity: &str) -> Option<&EdgeService> {
        let name = service_identity.strip_prefix(EDGE_SERVICE_IDENTITY_PREFIX)?;
        self.services.get(name)
    }

    pub(super) fn registered_class(&self, service: &str) -> Option<ConnectionClass> {
        self.services.get(service).map(|entry| entry.class)
    }
}
