//! Served-form receipts (OF-329): which rung of the lazy-image ladder a read
//! served an ASSET at, to which holder, and every later pull of its pixels.
//!
//! A read that serves an image's bytes, its thumbnail, its text or its handle
//! alone in place of its body records one receipt before it answers, as its
//! own RECEIPT_RECORD. So does each explicit fetch of the full pixels through
//! the image's view handle (view, crop, zoom, or a small vision model's
//! `ask_image`), so the Coach reads which rung each image got and whether the
//! agent then pulled the pixels. The record names the asset, the rung and the
//! ASSET_TEXT served; never a body, never bytes, never a question. Who read
//! it comes from the read's own lane, never from the door that reports what
//! it served.

use std::collections::BTreeMap;

use super::kernel::FIELD_ASSET_REF;
use super::{ReceiptKind, ReceiptRecord};
use crate::claim::ScopedReadActorKey;
use crate::entity_id::EntityId;

const OUTCOME_SERVED: &str = "served";
const OUTCOME_PULLED: &str = "pulled";
const FIELD_FORM: &str = "form";
const FIELD_ASSET_TEXT_REF: &str = "asset_text_ref";
const FIELD_ACTOR_CLASS: &str = "actor_class";
const FIELD_PULL: &str = "pull";
const FIELD_PICK: &str = "pick";
const FORM_IMAGE: &str = "image";
const FORM_THUMBNAIL: &str = "thumbnail";
const FORM_TEXT: &str = "text";
const FORM_ASK: &str = "ask";
const PICK_FULL: &str = "full";
const PICK_DECLINED: &str = "declined";
/// Every field a served-form receipt may hold.
const SERVED_FIELDS: [&str; 6] = [
    FIELD_ASSET_REF,
    FIELD_FORM,
    FIELD_ASSET_TEXT_REF,
    FIELD_ACTOR_CLASS,
    FIELD_PULL,
    FIELD_PICK,
];

/// The rung of the lazy-image ladder one read served an image at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ServedRung {
    /// The full image's bytes.
    Full,
    /// A thumbnail beside the image's description and its view handle.
    Thumbnail,
    /// The image's description and its view handle; no pixels.
    Description,
    /// Nothing fit: the handle alone, and the vault asked whether everything
    /// is okay.
    Ask,
}

/// An explicit fetch of an image's full pixels through its view handle,
/// after the read that served it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PixelPull {
    /// The whole image.
    View,
    /// A region at the image's own resolution.
    Crop,
    /// A region scaled to a requested size.
    Zoom,
    /// The pixels read by a small vision model answering a question about
    /// them, in place of the asking agent.
    AskImage,
}

impl PixelPull {
    /// The pull's name, as its receipt and its verbs say it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::View => "view",
            Self::Crop => "crop",
            Self::Zoom => "zoom",
            Self::AskImage => "ask_image",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        [Self::View, Self::Crop, Self::Zoom, Self::AskImage]
            .into_iter()
            .find(|pull| pull.as_str() == value)
    }
}

/// What one read served of one ASSET, or one pull of its pixels. These are
/// the only facts a door hands the served-form write
/// ([`crate::claim::ScopedRead::commit_served_forms`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServedForm {
    asset: EntityId,
    rung: ServedRung,
    /// The ASSET_TEXT served beside a thumbnail or as the description.
    asset_text: Option<EntityId>,
    /// The explicit fetch this records; `None` is a read's serving.
    pull: Option<PixelPull>,
    /// What the host's per-image pick answered, when one ran: `true` asked
    /// for the full image (or was unsure), `false` declined it.
    pick: Option<bool>,
}

impl ServedForm {
    const fn served(asset: EntityId, rung: ServedRung, asset_text: Option<EntityId>) -> Self {
        Self {
            asset,
            rung,
            asset_text,
            pull: None,
            pick: None,
        }
    }

    /// `asset`'s image bytes.
    #[must_use]
    pub const fn image(asset: EntityId) -> Self {
        Self::served(asset, ServedRung::Full, None)
    }

    /// `asset`'s thumbnail, beside `asset_text` when it has one.
    #[must_use]
    pub const fn thumbnail(asset: EntityId, asset_text: Option<EntityId>) -> Self {
        Self::served(asset, ServedRung::Thumbnail, asset_text)
    }

    /// `asset`'s text form: `asset_text`, served in place of its body.
    #[must_use]
    pub const fn text(asset: EntityId, asset_text: EntityId) -> Self {
        Self::served(asset, ServedRung::Description, Some(asset_text))
    }

    /// `asset`'s handle alone: no form fit, and the read asked.
    #[must_use]
    pub const fn ask(asset: EntityId) -> Self {
        Self::served(asset, ServedRung::Ask, None)
    }

    /// One `pull` of `asset`'s full pixels through its handle.
    #[must_use]
    pub const fn pulled(asset: EntityId, pull: PixelPull) -> Self {
        Self {
            asset,
            rung: ServedRung::Full,
            asset_text: None,
            pull: Some(pull),
            pick: None,
        }
    }

    /// This serving, after the host's pick answered `full`.
    #[must_use]
    pub const fn picked(mut self, full: bool) -> Self {
        if self.pull.is_none() {
            self.pick = Some(full);
        }
        self
    }

    /// The rung served.
    #[must_use]
    pub const fn rung(&self) -> ServedRung {
        self.rung
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
    let form = match served.rung {
        ServedRung::Full => FORM_IMAGE,
        ServedRung::Thumbnail => FORM_THUMBNAIL,
        ServedRung::Description => FORM_TEXT,
        ServedRung::Ask => FORM_ASK,
    };
    fields.insert(FIELD_FORM.to_owned(), form.to_owned());
    if let Some(asset_text) = served.asset_text {
        fields.insert(FIELD_ASSET_TEXT_REF.to_owned(), asset_text.to_hex());
    }
    if let Some(pull) = served.pull {
        fields.insert(FIELD_PULL.to_owned(), pull.as_str().to_owned());
    }
    if let Some(full) = served.pick {
        let pick = if full { PICK_FULL } else { PICK_DECLINED };
        fields.insert(FIELD_PICK.to_owned(), pick.to_owned());
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
        outcome: if served.pull.is_some() {
            OUTCOME_PULLED
        } else {
            OUTCOME_SERVED
        }
        .to_owned(),
        job_ref: None,
        trigger_ref: None,
        policy_trace: Vec::new(),
        fields,
    }
}

/// Whether `receipt` is the served-form record `id` carries: its own id, a
/// holder, the outcome `served` (or `pulled` for a pull), and exactly the
/// served facts, so a peer's carrier cannot smuggle a body or bytes into the
/// audit family.
pub(super) fn binds(id: &EntityId, receipt: &ReceiptRecord) -> bool {
    let field = |name: &str| receipt.fields.get(name).map(String::as_str);
    let entity_ref = |value: Option<&str>| {
        value.is_some_and(|hex| EntityId::from_hex(hex).is_ok_and(|parsed| parsed.to_hex() == hex))
    };
    let text = field(FIELD_ASSET_TEXT_REF);
    let pull = field(FIELD_PULL);
    let pick = field(FIELD_PICK);
    receipt.receipt_kind == ReceiptKind::ServedForm
        && receipt.receipt_id == receipt_id(id)
        && match pull {
            None => receipt.outcome == OUTCOME_SERVED,
            Some(pull) => {
                receipt.outcome == OUTCOME_PULLED
                    && PixelPull::parse(pull).is_some()
                    && field(FIELD_FORM) == Some(FORM_IMAGE)
                    && pick.is_none()
            }
        }
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
            Some(FORM_IMAGE | FORM_ASK) => text.is_none(),
            Some(FORM_THUMBNAIL) => text.is_none_or(|_| entity_ref(text)),
            Some(FORM_TEXT) => entity_ref(text),
            _ => false,
        }
        && pick.is_none_or(|pick| pick == PICK_FULL || pick == PICK_DECLINED)
        && field(FIELD_ACTOR_CLASS).is_none_or(|class| !class.trim().is_empty())
        && receipt
            .fields
            .keys()
            .all(|key| SERVED_FIELDS.contains(&key.as_str()))
}
