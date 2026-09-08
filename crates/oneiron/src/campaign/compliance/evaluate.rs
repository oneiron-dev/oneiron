//! Pure dispatch evaluator: jurisdiction selection, row matching, verdict.

use crate::entity_id::EntityId;

use super::rules::{
    B2bExemption, CHANNEL_WILDCARD, ComplianceExemptionEvidence, CompliancePack,
    ComplianceRuleKind, ComplianceRuleRow, JURISDICTION_NONE, UnknownJurisdictionDefault,
};

// ---------------------------------------------------------------------------
// Hydrated dispatch facts
// ---------------------------------------------------------------------------

/// A list-provenance record that RESOLVED and matched its claimed class.
///
/// Constructed only by `hydrate_dispatch_compliance_facts`. There is no
/// public constructor by design: the type's existence IS the evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HydratedListProvenance {
    /// The provenance record that was resolved.
    pub record_ref: EntityId,
    /// The class the evidence claimed and the record confirmed.
    pub claimed_class: String,
}

/// A publication-context record that RESOLVED, carrying its three facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HydratedJpPublicationFacts {
    /// The publication record that was resolved.
    pub record_ref: EntityId,
    /// The address was published by the recipient.
    pub published_by_recipient: bool,
    /// It was published in the course of business.
    pub in_course_of_business: bool,
    /// No statement refusing marketing was attached to it.
    pub no_marketing_statement_attached: bool,
}

impl HydratedJpPublicationFacts {
    /// All three Art. 3(1)(iv) facts hold.
    const fn exemption_holds(&self) -> bool {
        self.published_by_recipient
            && self.in_course_of_business
            && self.no_marketing_statement_attached
    }
}

/// Everything the evaluator is allowed to see, all of it already resolved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchComplianceFacts {
    /// The PERSON this dispatch addresses.
    pub counterparty: EntityId,
    /// The observed jurisdiction token, absent when none was recorded.
    pub jurisdiction: Option<String>,
    /// Confidence of that observation, in thousandths.
    pub jurisdiction_confidence_millis: Option<u16>,
    /// Normalized dispatch channel.
    pub channel: String,
    /// The recipient's legal form, absent when unknown.
    pub legal_form: Option<String>,
    /// Resolved list provenance, absent when unresolved or class-mismatched.
    pub list_provenance: Option<HydratedListProvenance>,
    /// Resolved publication context, absent when unresolved.
    pub jp_publication: Option<HydratedJpPublicationFacts>,
    /// The message carries an unconcealed sender identity.
    pub sender_identity_present: bool,
    /// The message carries a postal address.
    pub physical_address_present: bool,
    /// The message carries a working opt-out mechanism.
    pub optout_mechanism_present: bool,
    /// The message is identifiable as commercial.
    pub commercial_marking_present: bool,
    /// The engine clock this evaluation runs against.
    pub now_utc: u64,
}

/// Why a dispatch was blocked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComplianceBlockReason {
    /// A conditional exemption needs the recipient's legal form.
    UnknownLegalForm,
    /// A source-hygiene row needs resolved, class-matched list provenance.
    UnknownListProvenance,
    /// A conditional exemption needs a resolved publication-context record.
    MissingPublicationContext,
    /// A mandatory message element is absent.
    MissingRequiredMessageElement,
    /// The governing row is older than the pack's verification-age dial.
    StaleRule,
    /// The row is violated on its own terms, or the pack cannot apply it.
    RuleViolation,
}

impl ComplianceBlockReason {
    /// The receipt reason the gate records alongside the deny.
    ///
    /// `store.rs` owns a CLOSED receipt-reason vocabulary and admits only the
    /// `counterparty_` / `connector_key_` / `effector_budget_` / `charter_`
    /// families. These walls are counterparty-scoped legal facts — what may
    /// lawfully be sent to THIS recipient — so they ride the `counterparty_`
    /// family rather than minting a fifth one in a file this lane does not own.
    #[must_use]
    pub const fn receipt_reason(self) -> &'static str {
        match self {
            Self::UnknownLegalForm => "counterparty_compliance_unknown_legal_form",
            Self::UnknownListProvenance => "counterparty_compliance_unknown_list_provenance",
            Self::MissingPublicationContext => {
                "counterparty_compliance_missing_publication_context"
            }
            Self::MissingRequiredMessageElement => {
                "counterparty_compliance_missing_message_element"
            }
            Self::StaleRule => "counterparty_compliance_stale_rule",
            Self::RuleViolation => "counterparty_compliance_rule_violation",
        }
    }
}

/// The evaluator's answer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ComplianceVerdict {
    /// No matching row is violated. The dispatch proceeds to the next gate.
    Allow,
    /// A matching row blocks the dispatch.
    Block {
        /// Which wall was hit.
        reason: ComplianceBlockReason,
        /// The governing jurisdiction, when a row named one.
        jurisdiction: Option<String>,
        /// The governing row kind, when a row named one.
        rule_kind: Option<ComplianceRuleKind>,
    },
}

fn block(reason: ComplianceBlockReason, row: &ComplianceRuleRow) -> ComplianceVerdict {
    ComplianceVerdict::Block {
        reason,
        jurisdiction: Some(row.jurisdiction.clone()),
        rule_kind: Some(row.rule_kind),
    }
}

// ---------------------------------------------------------------------------
// Row selection and evaluation
// ---------------------------------------------------------------------------

/// Applies `pack` to `facts`. Pure: same inputs, same verdict, no storage.
///
/// Selection is exact jurisdiction first, then the configured strict pole. A
/// hierarchical token composes with its ancestors (`EU/DE` selects the German
/// rows AND the EU floor), every matching row is evaluated, and the strictest
/// outcome wins — a permissive row can never erase a stricter one because no
/// row can produce an allow, only the absence of a block.
#[must_use]
pub fn evaluate_dispatch_compliance(
    pack: &CompliancePack,
    facts: &DispatchComplianceFacts,
) -> ComplianceVerdict {
    let jurisdiction = effective_jurisdiction(pack, facts);
    let rows = matching_rows(pack, &jurisdiction, &facts.channel);
    if let Some(stale) = rows.iter().find(|row| pack.is_stale(row, facts.now_utc)) {
        return block(ComplianceBlockReason::StaleRule, stale);
    }
    if let Some(uncovered) = consent_class_coverage_gap(&rows) {
        return uncovered;
    }
    rows.iter()
        .find_map(|row| evaluate_row(pack, row, facts))
        .unwrap_or(ComplianceVerdict::Allow)
}

/// The jurisdiction the rows are selected for.
///
/// An absent token, a token below the pack's confidence floor, and a token the
/// pack does not seed all take the same road: the unknown disposition, which
/// routes to the strict pole rather than denying.
fn effective_jurisdiction(pack: &CompliancePack, facts: &DispatchComplianceFacts) -> String {
    trusted_jurisdiction(pack, facts).unwrap_or_else(|| match pack.unknown_jurisdiction_default {
        UnknownJurisdictionDefault::StrictPole => pack.strict_pole_jurisdiction.clone(),
    })
}

fn trusted_jurisdiction(pack: &CompliancePack, facts: &DispatchComplianceFacts) -> Option<String> {
    let observed = normalize_jurisdiction(facts.jurisdiction.as_deref()?);
    if observed.is_empty() || observed.eq_ignore_ascii_case(JURISDICTION_NONE) {
        return None;
    }
    if facts
        .jurisdiction_confidence_millis
        .is_some_and(|millis| millis < pack.jurisdiction_confidence_floor_millis)
    {
        return None;
    }
    pack.rows
        .iter()
        .any(|row| row.jurisdiction == observed)
        .then_some(observed)
}

/// Rows governing `(jurisdiction chain, channel)`, in a deterministic order.
///
/// The unknown-jurisdiction row is excluded on purpose: it states a
/// disposition, not a requirement, and [`effective_jurisdiction`] has already
/// applied it.
fn matching_rows<'a>(
    pack: &'a CompliancePack,
    jurisdiction: &str,
    channel: &str,
) -> Vec<&'a ComplianceRuleRow> {
    let chain = jurisdiction_chain(jurisdiction);
    let channel = normalize_token(channel);
    let mut rows: Vec<&ComplianceRuleRow> = pack
        .rows
        .iter()
        .filter(|row| row.jurisdiction != JURISDICTION_NONE)
        .filter(|row| chain.contains(&row.jurisdiction))
        .filter(|row| row.channel == CHANNEL_WILDCARD || row.channel == channel)
        .collect();
    rows.sort_unstable_by(|left, right| left.key().cmp(&right.key()));
    rows
}

/// `EU/DE` ⇒ `["EU", "EU/DE"]`; `UK` ⇒ `["UK"]`.
fn jurisdiction_chain(jurisdiction: &str) -> Vec<String> {
    let mut chain = Vec::new();
    let mut token = String::new();
    for segment in jurisdiction.split('/') {
        if !token.is_empty() {
            token.push('/');
        }
        token.push_str(segment);
        chain.push(token.clone());
    }
    chain
}

/// A jurisdiction that seeds no consent-class row for this channel cannot be
/// evaluated, so it fails closed rather than allowing on an empty axis.
///
/// The no-rows-at-all case fails closed for the same reason and reports no
/// governing row, because there is none: a pack that governs nothing here
/// cannot vouch for the send.
fn consent_class_coverage_gap(rows: &[&ComplianceRuleRow]) -> Option<ComplianceVerdict> {
    if rows
        .iter()
        .any(|row| row.rule_kind == ComplianceRuleKind::ConsentClass)
    {
        return None;
    }
    Some(rows.first().map_or(
        ComplianceVerdict::Block {
            reason: ComplianceBlockReason::RuleViolation,
            jurisdiction: None,
            rule_kind: None,
        },
        |anchor| block(ComplianceBlockReason::RuleViolation, anchor),
    ))
}

fn evaluate_row(
    pack: &CompliancePack,
    row: &ComplianceRuleRow,
    facts: &DispatchComplianceFacts,
) -> Option<ComplianceVerdict> {
    if !row.rule_kind.is_dispatch_enforced() {
        return None;
    }
    let element_present = match row.rule_kind {
        ComplianceRuleKind::SenderId => facts.sender_identity_present,
        ComplianceRuleKind::PhysicalAddress => facts.physical_address_present,
        ComplianceRuleKind::OptoutMechanism => facts.optout_mechanism_present,
        ComplianceRuleKind::ContentMarking => facts.commercial_marking_present,
        ComplianceRuleKind::SourceHygiene => return evaluate_source_hygiene(pack, row, facts),
        ComplianceRuleKind::ConsentClass => return evaluate_consent_class(pack, row, facts),
        ComplianceRuleKind::OptoutDeadline | ComplianceRuleKind::Records => return None,
    };
    (!element_present).then(|| block(ComplianceBlockReason::MissingRequiredMessageElement, row))
}

fn evaluate_consent_class(
    pack: &CompliancePack,
    row: &ComplianceRuleRow,
    facts: &DispatchComplianceFacts,
) -> Option<ComplianceVerdict> {
    if row.b2b_exemption != B2bExemption::Conditional {
        return None;
    }
    let Some(evidence) = pack.exemption_evidence(&row.jurisdiction) else {
        // A stored pack that skipped validation cannot apply its own
        // conditional row. Fail closed rather than guess which branch was meant.
        return Some(block(ComplianceBlockReason::RuleViolation, row));
    };
    match evidence {
        ComplianceExemptionEvidence::LegalForm => facts
            .legal_form
            .is_none()
            .then(|| block(ComplianceBlockReason::UnknownLegalForm, row)),
        ComplianceExemptionEvidence::PublicationContext => (!facts
            .jp_publication
            .is_some_and(|publication| publication.exemption_holds()))
        .then(|| block(ComplianceBlockReason::MissingPublicationContext, row)),
    }
}

fn evaluate_source_hygiene(
    pack: &CompliancePack,
    row: &ComplianceRuleRow,
    facts: &DispatchComplianceFacts,
) -> Option<ComplianceVerdict> {
    let Some(provenance) = facts.list_provenance.as_ref() else {
        return Some(block(ComplianceBlockReason::UnknownListProvenance, row));
    };
    pack.prohibited_list_provenance_classes
        .contains(&provenance.claimed_class)
        .then(|| block(ComplianceBlockReason::RuleViolation, row))
}

pub(super) fn normalize_token(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('-', "_")
}

/// Jurisdiction tokens are case-folded to upper for the country segments while
/// keeping the `/` hierarchy, so `eu/de` and `EU/DE` name the same rows.
pub(super) fn normalize_jurisdiction(value: &str) -> String {
    value.trim().to_ascii_uppercase()
}
