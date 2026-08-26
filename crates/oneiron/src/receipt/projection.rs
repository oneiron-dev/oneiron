use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::kernel::{
    FIELD_BRIEF_REF, FIELD_BUDGET, FIELD_BUDGET_DEBIT, FIELD_BUNDLE_REF,
    FIELD_CHANNEL_IDENTITY_REF, FIELD_COUNTERPARTY_REF, FIELD_FIRST_TOUCH, FIELD_GRANT_REF,
    FIELD_IDENTITY_REF, FIELD_INTENT_REF, FIELD_JOB_REF, FIELD_OPT_OUT, FIELD_PARENT_REF,
    FIELD_PROMO_CONSENT, FIELD_RECEIVING_IDENTITY_REF, FIELD_RUN_REF, ReceiptKind, ReceiptQuery,
    ReceiptRecord, receipt_newest_first_order,
};
use crate::Vault;
use crate::counterparty_contact::CounterpartyContactRecord;
use crate::entity_id::EntityId;
use crate::error::Result;

/// Brief-rooted receipt projection for the B2 RS4 project view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BriefReceiptProjection {
    pub brief_ref: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runs: Vec<ReceiptProjectionRun>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub direct_receipts: Vec<ReceiptRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub consent_grants: Vec<ReceiptRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bundles: Vec<ReceiptRecord>,
    pub budget_debit_total: u64,
}

/// One run under a brief-rooted receipt projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptProjectionRun {
    pub run_ref: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub intents: Vec<ReceiptProjectionIntent>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub direct_receipts: Vec<ReceiptRecord>,
    pub budget_debit_total: u64,
}

/// One outbound intent under a projected run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptProjectionIntent {
    pub intent_ref: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<ReceiptRecord>,
    pub budget_debit_total: u64,
}

/// Per-counterparty receipt projection for "who have you contacted on my behalf".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterpartyReceiptProjection {
    pub counterparty_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_touch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opt_out: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promo_consent: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<ReceiptRecord>,
    pub budget_debit_total: u64,
}

/// Per-grant receipt projection for "this grant produced N sends".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantReceiptProjection {
    pub grant_ref: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<ReceiptRecord>,
    pub budget_debit_total: u64,
}

/// Computes the brief/project receipt projection over supplied receipt rows.
///
/// This is a pure projection: it does not write grouping state. Direct
/// `job_ref`/`brief_ref` matches win, and older rows can still join the brief
/// through `trigger_ref` plus `run_ref`/`intent_ref`/`parent_ref` chain fields.
#[must_use]
pub fn project_receipts_by_brief(
    brief_ref: impl Into<String>,
    receipts: impl IntoIterator<Item = ReceiptRecord>,
) -> BriefReceiptProjection {
    let brief_ref = brief_ref.into();
    let receipts = receipts.into_iter().collect::<Vec<_>>();
    let index = ReceiptProjectionIndex::new(&receipts);
    let mut builder = BriefProjectionBuilder::new(brief_ref.clone());

    for receipt in receipts {
        if index.receipt_matches_brief(&receipt, &brief_ref) {
            builder.push(receipt, &index);
        }
    }

    builder.finish()
}

/// Computes one projection per counterparty over supplied receipt rows.
#[must_use]
pub fn project_receipts_by_counterparty(
    receipts: impl IntoIterator<Item = ReceiptRecord>,
) -> Vec<CounterpartyReceiptProjection> {
    project_receipts_by_counterparty_with_contacts(receipts, &BTreeMap::new())
}

pub(super) fn project_receipts_by_counterparty_with_contacts(
    receipts: impl IntoIterator<Item = ReceiptRecord>,
    contact_records: &BTreeMap<String, CounterpartyContactProjection>,
) -> Vec<CounterpartyReceiptProjection> {
    let mut projections = BTreeMap::<String, CounterpartyProjectionBuilder>::new();
    let mut receipts = receipts.into_iter().collect::<Vec<_>>();
    sort_receipts_newest_first(&mut receipts);

    for receipt in receipts {
        let Some(counterparty_ref) = receipt_counterparty_ref(&receipt) else {
            continue;
        };
        projections
            .entry(counterparty_ref.clone())
            .or_insert_with(|| CounterpartyProjectionBuilder::new(counterparty_ref))
            .push(receipt);
    }

    for (counterparty_ref, contact) in contact_records {
        if let Some(builder) = projections.get_mut(counterparty_ref) {
            builder.apply_contact(contact);
        }
    }

    projections
        .into_values()
        .map(CounterpartyProjectionBuilder::finish)
        .collect()
}

/// Computes the grant receipt projection over supplied receipt rows.
#[must_use]
pub fn project_receipts_by_grant(
    grant_ref: impl Into<String>,
    receipts: impl IntoIterator<Item = ReceiptRecord>,
) -> GrantReceiptProjection {
    project_receipts_by_grant_limited(grant_ref, receipts, usize::MAX)
}

pub(super) fn project_receipts_by_grant_limited(
    grant_ref: impl Into<String>,
    receipts: impl IntoIterator<Item = ReceiptRecord>,
    limit: usize,
) -> GrantReceiptProjection {
    let grant_ref = grant_ref.into();
    let mut projection = GrantReceiptProjection {
        grant_ref: grant_ref.clone(),
        receipts: Vec::new(),
        budget_debit_total: 0,
    };

    for receipt in receipts {
        if receipt_matches_grant(&receipt, &grant_ref) {
            projection.budget_debit_total = projection
                .budget_debit_total
                .saturating_add(receipt_budget_debit(&receipt));
            projection.receipts.push(receipt);
        }
    }
    projection.receipts.truncate(limit);

    projection
}

#[derive(Debug, Default)]
struct ReceiptProjectionIndex {
    run_to_brief: BTreeMap<String, String>,
    run_to_parent_run: BTreeMap<String, String>,
    intent_to_run: BTreeMap<String, String>,
    intent_to_brief: BTreeMap<String, String>,
}

impl ReceiptProjectionIndex {
    fn new(receipts: &[ReceiptRecord]) -> Self {
        let mut index = Self::default();
        for receipt in receipts {
            let brief_ref = direct_brief_ref(receipt);
            let run_ref = direct_run_ref(receipt);
            let intent_ref = direct_intent_ref(receipt);

            if let (Some(run_ref), Some(brief_ref)) = (run_ref.as_deref(), brief_ref.as_deref()) {
                index
                    .run_to_brief
                    .entry(run_ref.to_owned())
                    .or_insert_with(|| brief_ref.to_owned());
            }
            if let (Some(intent_ref), Some(brief_ref)) =
                (intent_ref.as_deref(), brief_ref.as_deref())
            {
                index
                    .intent_to_brief
                    .entry(intent_ref.to_owned())
                    .or_insert_with(|| brief_ref.to_owned());
            }
            if let (Some(intent_ref), Some(run_ref)) = (intent_ref.as_deref(), run_ref.as_deref()) {
                index
                    .intent_to_run
                    .entry(intent_ref.to_owned())
                    .or_insert_with(|| run_ref.to_owned());
            }

            if let Some(parent_ref) = field_ref(receipt, FIELD_PARENT_REF) {
                if parent_ref.starts_with("brief:") {
                    if let Some(run_ref) = run_ref.as_deref() {
                        index
                            .run_to_brief
                            .entry(run_ref.to_owned())
                            .or_insert_with(|| parent_ref.to_owned());
                    }
                    if let Some(intent_ref) = intent_ref.as_deref() {
                        index
                            .intent_to_brief
                            .entry(intent_ref.to_owned())
                            .or_insert_with(|| parent_ref.to_owned());
                    }
                } else if parent_ref.starts_with("run:") {
                    if let Some(run_ref) = run_ref.as_deref() {
                        index
                            .run_to_parent_run
                            .entry(run_ref.to_owned())
                            .or_insert_with(|| parent_ref.to_owned());
                    }
                    if let Some(intent_ref) = intent_ref.as_deref() {
                        index
                            .intent_to_run
                            .entry(intent_ref.to_owned())
                            .or_insert_with(|| parent_ref.to_owned());
                    }
                }
            }
        }

        loop {
            let mut changed = false;
            for run_ref in index.run_to_parent_run.keys().cloned() {
                let Some(parent_run_ref) = index.run_to_parent_run.get(&run_ref) else {
                    continue;
                };
                if let Some(brief_ref) = index.run_to_brief.get(parent_run_ref).cloned()
                    && !index.run_to_brief.contains_key(&run_ref)
                {
                    index.run_to_brief.insert(run_ref, brief_ref);
                    changed = true;
                }
            }
            for intent_ref in index.intent_to_run.keys().cloned() {
                let Some(run_ref) = index.intent_to_run.get(&intent_ref) else {
                    continue;
                };
                if let Some(brief_ref) = index.run_to_brief.get(run_ref).cloned()
                    && !index.intent_to_brief.contains_key(&intent_ref)
                {
                    index.intent_to_brief.insert(intent_ref, brief_ref);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }

        index
    }

    fn receipt_matches_brief(&self, receipt: &ReceiptRecord, brief_ref: &str) -> bool {
        if direct_brief_ref(receipt).is_some_and(|value| refs_match(&value, brief_ref)) {
            return true;
        }
        if let Some(run_ref) = direct_run_ref(receipt)
            && self
                .run_to_brief
                .get(&run_ref)
                .is_some_and(|value| refs_match(value, brief_ref))
        {
            return true;
        }
        if let Some(intent_ref) = direct_intent_ref(receipt) {
            if self
                .intent_to_brief
                .get(&intent_ref)
                .is_some_and(|value| refs_match(value, brief_ref))
            {
                return true;
            }
            if let Some(run_ref) = self.intent_to_run.get(&intent_ref)
                && self
                    .run_to_brief
                    .get(run_ref)
                    .is_some_and(|value| refs_match(value, brief_ref))
            {
                return true;
            }
        }
        false
    }

    fn receipt_run_ref(&self, receipt: &ReceiptRecord) -> Option<String> {
        direct_run_ref(receipt).or_else(|| {
            direct_intent_ref(receipt)
                .and_then(|intent_ref| self.intent_to_run.get(&intent_ref).cloned())
        })
    }
}

#[derive(Debug)]
struct BriefProjectionBuilder {
    brief_ref: String,
    runs: BTreeMap<String, ReceiptProjectionRunBuilder>,
    direct_receipts: Vec<ReceiptRecord>,
    consent_grants: Vec<ReceiptRecord>,
    bundles: Vec<ReceiptRecord>,
    budget_debit_total: u64,
}

impl BriefProjectionBuilder {
    fn new(brief_ref: String) -> Self {
        Self {
            brief_ref,
            runs: BTreeMap::new(),
            direct_receipts: Vec::new(),
            consent_grants: Vec::new(),
            bundles: Vec::new(),
            budget_debit_total: 0,
        }
    }

    fn push(&mut self, receipt: ReceiptRecord, index: &ReceiptProjectionIndex) {
        let budget = receipt_budget_debit(&receipt);
        self.budget_debit_total = self.budget_debit_total.saturating_add(budget);

        if receipt_is_consent_grant(&receipt) {
            self.consent_grants.push(receipt.clone());
        }
        if receipt_is_bundle_event(&receipt) {
            self.bundles.push(receipt.clone());
        }

        let intent_ref = direct_intent_ref(&receipt);
        if let Some(run_ref) = index.receipt_run_ref(&receipt) {
            self.runs
                .entry(run_ref.clone())
                .or_insert_with(|| ReceiptProjectionRunBuilder::new(run_ref))
                .push(receipt, intent_ref, budget);
        } else {
            self.direct_receipts.push(receipt);
        }
    }

    fn finish(self) -> BriefReceiptProjection {
        BriefReceiptProjection {
            brief_ref: self.brief_ref,
            runs: self
                .runs
                .into_values()
                .map(ReceiptProjectionRunBuilder::finish)
                .collect(),
            direct_receipts: self.direct_receipts,
            consent_grants: self.consent_grants,
            bundles: self.bundles,
            budget_debit_total: self.budget_debit_total,
        }
    }
}

#[derive(Debug)]
struct ReceiptProjectionRunBuilder {
    run_ref: String,
    intents: BTreeMap<String, ReceiptProjectionIntentBuilder>,
    direct_receipts: Vec<ReceiptRecord>,
    budget_debit_total: u64,
}

impl ReceiptProjectionRunBuilder {
    fn new(run_ref: String) -> Self {
        Self {
            run_ref,
            intents: BTreeMap::new(),
            direct_receipts: Vec::new(),
            budget_debit_total: 0,
        }
    }

    fn push(&mut self, receipt: ReceiptRecord, intent_ref: Option<String>, budget: u64) {
        self.budget_debit_total = self.budget_debit_total.saturating_add(budget);
        if let Some(intent_ref) = intent_ref {
            self.intents
                .entry(intent_ref.clone())
                .or_insert_with(|| ReceiptProjectionIntentBuilder::new(intent_ref))
                .push(receipt, budget);
        } else {
            self.direct_receipts.push(receipt);
        }
    }

    fn finish(self) -> ReceiptProjectionRun {
        ReceiptProjectionRun {
            run_ref: self.run_ref,
            intents: self
                .intents
                .into_values()
                .map(ReceiptProjectionIntentBuilder::finish)
                .collect(),
            direct_receipts: self.direct_receipts,
            budget_debit_total: self.budget_debit_total,
        }
    }
}

#[derive(Debug)]
struct ReceiptProjectionIntentBuilder {
    intent_ref: String,
    receipts: Vec<ReceiptRecord>,
    budget_debit_total: u64,
}

impl ReceiptProjectionIntentBuilder {
    fn new(intent_ref: String) -> Self {
        Self {
            intent_ref,
            receipts: Vec::new(),
            budget_debit_total: 0,
        }
    }

    fn push(&mut self, receipt: ReceiptRecord, budget: u64) {
        self.budget_debit_total = self.budget_debit_total.saturating_add(budget);
        self.receipts.push(receipt);
    }

    fn finish(self) -> ReceiptProjectionIntent {
        ReceiptProjectionIntent {
            intent_ref: self.intent_ref,
            receipts: self.receipts,
            budget_debit_total: self.budget_debit_total,
        }
    }
}

#[derive(Debug)]
struct CounterpartyProjectionBuilder {
    counterparty_ref: String,
    first_touch: Option<String>,
    opt_out: Option<bool>,
    promo_consent: Option<bool>,
    receipts: Vec<ReceiptRecord>,
    budget_debit_total: u64,
}

impl CounterpartyProjectionBuilder {
    fn new(counterparty_ref: String) -> Self {
        Self {
            counterparty_ref,
            first_touch: None,
            opt_out: None,
            promo_consent: None,
            receipts: Vec::new(),
            budget_debit_total: 0,
        }
    }

    fn push(&mut self, receipt: ReceiptRecord) {
        if self.first_touch.is_none()
            && let Some(first_touch) = field_ref(&receipt, FIELD_FIRST_TOUCH)
        {
            self.first_touch = Some(first_touch.to_owned());
        }
        if let Some(opt_out) = bool_field(&receipt, FIELD_OPT_OUT) {
            self.opt_out.get_or_insert(opt_out);
        }
        if let Some(promo_consent) = bool_field(&receipt, FIELD_PROMO_CONSENT) {
            self.promo_consent.get_or_insert(promo_consent);
        }
        self.budget_debit_total = self
            .budget_debit_total
            .saturating_add(receipt_budget_debit(&receipt));
        self.receipts.push(receipt);
    }

    fn apply_contact(&mut self, contact: &CounterpartyContactProjection) {
        self.first_touch = contact.first_touch.clone();
        self.opt_out = Some(contact.opt_out);
        self.promo_consent = Some(contact.promo_consent);
    }

    fn finish(self) -> CounterpartyReceiptProjection {
        CounterpartyReceiptProjection {
            counterparty_ref: self.counterparty_ref,
            first_touch: self.first_touch,
            opt_out: self.opt_out,
            promo_consent: self.promo_consent,
            receipts: self.receipts,
            budget_debit_total: self.budget_debit_total,
        }
    }
}

fn direct_brief_ref(receipt: &ReceiptRecord) -> Option<String> {
    receipt
        .job_ref
        .as_deref()
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| field_ref(receipt, FIELD_JOB_REF).map(str::to_owned))
        .or_else(|| field_ref(receipt, FIELD_BRIEF_REF).map(str::to_owned))
        .or_else(|| trigger_ref_with_prefix(receipt, "brief:"))
}

fn direct_run_ref(receipt: &ReceiptRecord) -> Option<String> {
    field_ref(receipt, FIELD_RUN_REF)
        .map(str::to_owned)
        .or_else(|| trigger_ref_with_prefix(receipt, "run:"))
}

fn direct_intent_ref(receipt: &ReceiptRecord) -> Option<String> {
    field_ref(receipt, FIELD_INTENT_REF)
        .map(str::to_owned)
        .or_else(|| trigger_ref_with_prefix(receipt, "intent:"))
}

fn receipt_counterparty_ref(receipt: &ReceiptRecord) -> Option<String> {
    field_ref(receipt, FIELD_COUNTERPARTY_REF)
        .or_else(|| field_ref(receipt, "target"))
        .map(str::to_owned)
}

fn receipt_identity_ref(receipt: &ReceiptRecord) -> Option<EntityId> {
    [
        FIELD_CHANNEL_IDENTITY_REF,
        FIELD_RECEIVING_IDENTITY_REF,
        FIELD_IDENTITY_REF,
    ]
    .iter()
    .find_map(|key| field_ref(receipt, key).and_then(entity_ref_from_str))
}

fn receipt_matches_grant(receipt: &ReceiptRecord, grant_ref: &str) -> bool {
    field_ref(receipt, FIELD_GRANT_REF).is_some_and(|value| refs_match(value, grant_ref))
        || receipt
            .trigger_ref
            .as_deref()
            .filter(|value| value.starts_with("access_grant:") || value.starts_with("grant:"))
            .is_some_and(|value| refs_match(value, grant_ref))
}

fn receipt_is_consent_grant(receipt: &ReceiptRecord) -> bool {
    receipt.receipt_kind == ReceiptKind::ScopedRead
}

fn receipt_is_bundle_event(receipt: &ReceiptRecord) -> bool {
    field_ref(receipt, FIELD_BUNDLE_REF).is_some()
        || receipt
            .trigger_ref
            .as_deref()
            .is_some_and(|value| value.starts_with("bundle:"))
        || field_ref(receipt, "event").is_some_and(|value| value == "bundle")
}

fn receipt_budget_debit(receipt: &ReceiptRecord) -> u64 {
    field_ref(receipt, FIELD_BUDGET_DEBIT)
        .or_else(|| field_ref(receipt, FIELD_BUDGET))
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0)
}

fn bool_field(receipt: &ReceiptRecord, key: &str) -> Option<bool> {
    match field_ref(receipt, key)? {
        "true" | "1" | "yes" => Some(true),
        "false" | "0" | "no" => Some(false),
        _ => None,
    }
}

fn field_ref<'a>(receipt: &'a ReceiptRecord, key: &str) -> Option<&'a str> {
    receipt
        .fields
        .get(key)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
}

fn trigger_ref_with_prefix(receipt: &ReceiptRecord, prefix: &str) -> Option<String> {
    receipt
        .trigger_ref
        .as_deref()
        .filter(|value| value.starts_with(prefix))
        .map(str::to_owned)
}

fn refs_match(candidate: &str, target: &str) -> bool {
    candidate == target || strip_ref_prefix(candidate) == strip_ref_prefix(target)
}

fn strip_ref_prefix(value: &str) -> &str {
    value
        .split_once(':')
        .map_or(value, |(_prefix, suffix)| suffix)
}

fn entity_ref_from_str(value: &str) -> Option<EntityId> {
    EntityId::from_hex(strip_ref_prefix(value)).ok()
}

fn sort_receipts_newest_first(records: &mut [ReceiptRecord]) {
    records.sort_by(receipt_newest_first_order);
}

pub(super) fn finalize_receipt_query_records(
    mut records: Vec<ReceiptRecord>,
    query: &ReceiptQuery,
    lineage_records: Option<&[ReceiptRecord]>,
) -> Vec<ReceiptRecord> {
    sort_receipts_newest_first(&mut records);
    if let Some(job_ref) = query.job_ref.as_deref() {
        let index = ReceiptProjectionIndex::new(lineage_records.unwrap_or(&records));
        records.retain(|receipt| index.receipt_matches_brief(receipt, job_ref));
    }
    records.truncate(query.limit);
    records
}

#[derive(Debug, Clone)]
pub(super) struct CounterpartyContactProjection {
    first_touch: Option<String>,
    first_touch_created_at: u64,
    opt_out: bool,
    promo_consent: bool,
}

impl CounterpartyContactProjection {
    fn new(contact: &CounterpartyContactRecord) -> Self {
        Self {
            first_touch: Some(contact.first_touch.as_str().to_owned()),
            first_touch_created_at: contact.created_at,
            opt_out: contact.is_opted_out(),
            promo_consent: contact.promo_consent,
        }
    }

    fn merge(&mut self, contact: &CounterpartyContactRecord) {
        if contact.created_at < self.first_touch_created_at {
            self.first_touch = Some(contact.first_touch.as_str().to_owned());
            self.first_touch_created_at = contact.created_at;
        }
        self.opt_out |= contact.is_opted_out();
        self.promo_consent &= contact.promo_consent;
    }
}

pub(super) fn counterparty_contact_records_for_receipts(
    vault: &Vault,
    receipts: &[ReceiptRecord],
) -> Result<BTreeMap<String, CounterpartyContactProjection>> {
    let mut wanted_by_identity = BTreeMap::<EntityId, BTreeMap<String, BTreeSet<String>>>::new();
    for receipt in receipts {
        let (Some(counterparty_ref), Some(identity_ref)) = (
            receipt_counterparty_ref(receipt),
            receipt_identity_ref(receipt),
        ) else {
            continue;
        };
        wanted_by_identity
            .entry(identity_ref)
            .or_default()
            .entry(counterparty_ref.trim().to_owned())
            .or_default()
            .insert(counterparty_ref);
    }

    let mut contacts = BTreeMap::<String, CounterpartyContactProjection>::new();
    for (identity_ref, wanted_counterparties) in wanted_by_identity {
        for (_contact_id, contact) in vault.counterparty_contacts_for_identity(&identity_ref)? {
            let Some(counterparty_refs) = wanted_counterparties.get(&contact.counterparty) else {
                continue;
            };
            for counterparty_ref in counterparty_refs {
                contacts
                    .entry(counterparty_ref.clone())
                    .and_modify(|projection| projection.merge(&contact))
                    .or_insert_with(|| CounterpartyContactProjection::new(&contact));
            }
        }
    }
    Ok(contacts)
}
