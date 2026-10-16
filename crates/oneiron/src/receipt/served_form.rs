//! Served-form receipts (OF-329): which form of an ASSET a read served, and
//! to which holder.
//!
//! A read that serves an image's bytes or its text in place of its body
//! records one receipt before it answers, as its own RECEIPT_RECORD. The
//! record names the asset, the form and the ASSET_TEXT served; never a body,
//! never bytes. Who read it comes from the read's own lane, never from the
//! door that reports what it served.

use std::collections::BTreeMap;

use super::kernel::FIELD_ASSET_REF;
use super::{ReceiptKind, ReceiptRecord};
use crate::claim::ScopedReadActorKey;
use crate::entity_id::EntityId;

const OUTCOME_SERVED: &str = "served";
const FIELD_FORM: &str = "form";
const FIELD_ASSET_TEXT_REF: &str = "asset_text_ref";
const FIELD_ACTOR_CLASS: &str = "actor_class";
const FORM_IMAGE: &str = "image";
const FORM_TEXT: &str = "text";
/// Every field a served-form receipt may hold.
const SERVED_FIELDS: [&str; 4] = [
    FIELD_ASSET_REF,
    FIELD_FORM,
    FIELD_ASSET_TEXT_REF,
    FIELD_ACTOR_CLASS,
];

/// What one read served of one ASSET: its image bytes, or its text form in
/// place of its body. These are the only facts a door hands the served-form
/// write ([`crate::claim::ScopedRead::commit_served_forms`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServedForm {
    asset: EntityId,
    /// The ASSET_TEXT served as the text form; `None` is the image form.
    asset_text: Option<EntityId>,
}

impl ServedForm {
    /// `asset`'s image bytes.
    #[must_use]
    pub const fn image(asset: EntityId) -> Self {
        Self {
            asset,
            asset_text: None,
        }
    }

    /// `asset`'s text form: `asset_text`, served in place of its body.
    #[must_use]
    pub const fn text(asset: EntityId, asset_text: EntityId) -> Self {
        Self {
            asset,
            asset_text: Some(asset_text),
        }
    }
}

/// The receipt id of the served-form record stored at `id`.
fn receipt_id(id: &EntityId) -> String {
    format!("served_form:{}", id.to_hex())
}

/// The receipt the record at `id` carries: `served`, served to `holder` at
/// `at`. The holder's class rides along only when its lane knows one.
pub(super) fn served_form_receipt(
    id: &EntityId,
    served: &ServedForm,
    holder: &ScopedReadActorKey,
    at: u64,
) -> ReceiptRecord {
    let mut fields = BTreeMap::new();
    fields.insert(FIELD_ASSET_REF.to_owned(), served.asset.to_hex());
    match served.asset_text {
        Some(asset_text) => {
            fields.insert(FIELD_FORM.to_owned(), FORM_TEXT.to_owned());
            fields.insert(FIELD_ASSET_TEXT_REF.to_owned(), asset_text.to_hex());
        }
        None => {
            fields.insert(FIELD_FORM.to_owned(), FORM_IMAGE.to_owned());
        }
    }
    if let Some(class) = holder.actor_class() {
        fields.insert(FIELD_ACTOR_CLASS.to_owned(), class.to_owned());
    }
    ReceiptRecord {
        receipt_id: receipt_id(id),
        receipt_kind: ReceiptKind::ServedForm,
        occurred_at: at,
        actor: Some(holder.actor_ref().to_owned()),
        on_behalf_of: None,
        outcome: OUTCOME_SERVED.to_owned(),
        job_ref: None,
        trigger_ref: None,
        policy_trace: Vec::new(),
        fields,
    }
}

/// Whether `receipt` is the served-form record `id` carries: its own id, a
/// holder, the outcome `served`, and exactly the served facts, so a peer's
/// carrier cannot smuggle a body or bytes into the audit family.
pub(super) fn binds(id: &EntityId, receipt: &ReceiptRecord) -> bool {
    let field = |name: &str| receipt.fields.get(name).map(String::as_str);
    let entity_ref = |value: Option<&str>| {
        value.is_some_and(|hex| EntityId::from_hex(hex).is_ok_and(|parsed| parsed.to_hex() == hex))
    };
    let text = field(FIELD_ASSET_TEXT_REF);
    receipt.receipt_kind == ReceiptKind::ServedForm
        && receipt.receipt_id == receipt_id(id)
        && receipt.outcome == OUTCOME_SERVED
        && receipt
            .actor
            .as_deref()
            .is_some_and(|actor| !actor.trim().is_empty())
        && receipt.on_behalf_of.is_none()
        && receipt.job_ref.is_none()
        && receipt.trigger_ref.is_none()
        && receipt.policy_trace.is_empty()
        && entity_ref(field(FIELD_ASSET_REF))
        && match field(FIELD_FORM) {
            Some(FORM_IMAGE) => text.is_none(),
            Some(FORM_TEXT) => entity_ref(text),
            _ => false,
        }
        && field(FIELD_ACTOR_CLASS).is_none_or(|class| !class.trim().is_empty())
        && receipt
            .fields
            .keys()
            .all(|key| SERVED_FIELDS.contains(&key.as_str()))
}
