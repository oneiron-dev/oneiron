//! Per-counterparty receipt projections and the contact-facts join behind them.

use super::*;

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

/// Each counterparty's totals count every receipt; its listed receipts are
/// its newest `limit`. A message to several counts for every recipient it
/// lists (fix list row 17645): each one's projection lists the message and
/// counts its one debit, as a send to that recipient alone would.
pub(in crate::receipt) fn project_receipts_by_counterparty_with_contacts(
    receipts: impl IntoIterator<Item = ReceiptRecord>,
    contact_records: &BTreeMap<String, CounterpartyContactProjection>,
    limit: usize,
) -> Vec<CounterpartyReceiptProjection> {
    let mut projections = BTreeMap::<String, CounterpartyProjectionBuilder>::new();
    let mut receipts = receipts.into_iter().collect::<Vec<_>>();
    sort_receipts_newest_first(&mut receipts);

    for receipt in receipts {
        for counterparty_ref in receipt_other_recipients(&receipt) {
            projections
                .entry(counterparty_ref.clone())
                .or_insert_with(|| CounterpartyProjectionBuilder::new(counterparty_ref))
                .count(receipt.clone(), limit);
        }
        let Some(counterparty_ref) = receipt_counterparty_ref(&receipt) else {
            continue;
        };
        projections
            .entry(counterparty_ref.clone())
            .or_insert_with(|| CounterpartyProjectionBuilder::new(counterparty_ref))
            .push(receipt, limit);
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

    fn push(&mut self, receipt: ReceiptRecord, limit: usize) {
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
        self.count(receipt, limit);
    }

    /// Counts `receipt`'s debit and lists it, within `limit`. Alone, for a
    /// message to several that names this counterparty beside its own (fix
    /// list row 17645): the contact facts that receipt carries are its own
    /// counterparty's, never this one's.
    fn count(&mut self, receipt: ReceiptRecord, limit: usize) {
        self.budget_debit_total = self
            .budget_debit_total
            .saturating_add(receipt_budget_debit(&receipt));
        if self.receipts.len() < limit {
            self.receipts.push(receipt);
        }
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

#[derive(Debug, Clone)]
pub(in crate::receipt) struct CounterpartyContactProjection {
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

pub(in crate::receipt) fn counterparty_contact_records_for_receipts(
    vault: &Vault,
    receipts: &[ReceiptRecord],
) -> Result<BTreeMap<String, CounterpartyContactProjection>> {
    let mut wanted_by_identity = BTreeMap::<EntityId, BTreeMap<String, BTreeSet<String>>>::new();
    for receipt in receipts {
        let Some(identity_ref) = receipt_identity_ref(receipt) else {
            continue;
        };
        // Fix list row 17645: each recipient a message to several lists
        // joins its own contact facts, as its counterparty does.
        for counterparty_ref in receipt_counterparty_ref(receipt)
            .into_iter()
            .chain(receipt_other_recipients(receipt))
        {
            wanted_by_identity
                .entry(identity_ref)
                .or_default()
                .entry(counterparty_ref.trim().to_owned())
                .or_default()
                .insert(counterparty_ref);
        }
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
