//! Moved from `crates/oneiron/src/genui/shape_plan.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::vault_shape::apply::ShapeItemState;
use crate::vault_shape::plan::ShapeChange;
use crate::vault_shape::plan::ShapeItemClass;
use crate::vault_shape::shared_setup::ShapeLearningOutcome;
use oneiron_base::error::Result;
use oneiron_lens_wire::lens::atom::CollectionAtom;
use oneiron_lens_wire::lens::atom::LedgerCell;
use oneiron_lens_wire::lens::atom::LedgerRowAtom;
use oneiron_lens_wire::lens::atom::LensAtom;
use oneiron_lens_wire::lens::atom::LensNode;
use oneiron_lens_wire::lens::atom::LensStatus;
use oneiron_lens_wire::lens::atom::LensText;
use oneiron_lens_wire::lens::atom::LensTextSpan;
use oneiron_lens_wire::lens::atom::TextBlockAtom;
use oneiron_lens_wire::lens::wire_ids::LensAtomId;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

/// Lens text stays under the kit's own bound.
pub const MAX_CARD_TEXT_BYTES: usize = 16 * 1024 - 1;

/// One row of the plan card's diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ShapePlanCardItem {
    pub seq: u32,
    /// The change in words: "create world clients".
    pub line: String,
    pub change: ShapeChange,
    pub class: ShapeItemClass,
    /// The named door it lands through, if the vault has one.
    pub door: Option<String>,
    /// Where it stands in the apply; none before an apply opens.
    pub state: Option<ShapeItemState>,
}

pub fn conversation_learning_text(outcome: &ShapeLearningOutcome) -> String {
    let on_off = |on| if on { "on" } else { "off" };
    let mut text = format!(
        "Conversation learning in this apply: requested {}; written {}; ignored {}.",
        on_off(outcome.requested),
        outcome.written,
        outcome.ignored,
    );
    match &outcome.resulting {
        Some(setting) => text.push_str(&format!(
            " Setting after the apply: {} (revision {}; act {}).",
            on_off(setting.on),
            setting.revision,
            setting.act.as_deref().unwrap_or("none"),
        )),
        None => text.push_str(" Setting after the apply: unknown."),
    }
    if let Some(reason) = &outcome.reason {
        text.push_str(&format!(" Reason: {reason}"));
    }
    text
}

pub const fn change_word(change: ShapeChange) -> &'static str {
    match change {
        ShapeChange::Create => "create",
        ShapeChange::Update => "update",
        ShapeChange::Retire => "retire",
    }
}

/// How an item lands before an apply, or where it stands in one, as a
/// status and its words. One policy, so a ruling on the words moves one
/// place.
pub fn standing(item: &ShapePlanCardItem) -> (LensStatus, String) {
    match &item.state {
        None if item.class == ShapeItemClass::Authority => {
            (LensStatus::Proposed, "goes to its ceremony".to_owned())
        }
        None if item.door.is_none() => (LensStatus::Missing, "no door yet".to_owned()),
        None if item.class == ShapeItemClass::Widening => {
            (LensStatus::Proposed, "needs your word".to_owned())
        }
        None => (LensStatus::Auto, "lands with a receipt".to_owned()),
        Some(ShapeItemState::Pending) => (LensStatus::Running, "not reached yet".to_owned()),
        Some(ShapeItemState::Landed { .. }) => (LensStatus::Complete, "landed".to_owned()),
        Some(ShapeItemState::Proposed) => (LensStatus::Proposed, "waits for your word".to_owned()),
        Some(ShapeItemState::Filed { .. }) => (
            LensStatus::Proposed,
            "waits for your word in the widen inbox".to_owned(),
        ),
        Some(ShapeItemState::FileRefused { reason }) => (
            LensStatus::Proposed,
            format!("waits for your word; filing refused: {reason}"),
        ),
        Some(ShapeItemState::Held {
            approval_digest, ..
        }) => (
            LensStatus::Proposed,
            format!("the release waits for your approve-once press on {approval_digest}"),
        ),
        Some(ShapeItemState::HeldProvision {
            approval_digest, ..
        }) => (
            LensStatus::Proposed,
            format!("the provision waits for your approve-once press on {approval_digest}"),
        ),
        Some(ShapeItemState::Ceremony) => (LensStatus::Proposed, "goes to its ceremony".to_owned()),
        Some(ShapeItemState::NoDoor) => (LensStatus::Missing, "no door yet".to_owned()),
        Some(ShapeItemState::Refused { reason }) => {
            (LensStatus::Rejected, format!("refused: {reason}"))
        }
    }
}

pub fn sheet(id: &str, title: &str, rows: Vec<LedgerRowAtom>, fallback: &str) -> Result<LensNode> {
    Ok(LensNode::with_fallback_text(
        LensAtomId::new(id)?,
        LensAtom::Sheet(CollectionAtom {
            title: lens_text(title)?,
            rows,
        }),
        lens_text(fallback)?,
    ))
}

pub fn text_block(id: &str, text: &str) -> Result<LensNode> {
    Ok(LensNode::with_fallback_text(
        LensAtomId::new(id)?,
        LensAtom::TextBlock(TextBlockAtom {
            spans: vec![LensTextSpan::Literal(lens_text(text)?)],
        }),
        lens_text(text)?,
    ))
}

pub fn cell(label: &str, value: &str) -> Result<LedgerCell> {
    Ok(LedgerCell {
        label: lens_text(label)?,
        value: lens_text(value)?,
    })
}

/// Bounded, never blank: a node's fallback text is required.
pub fn lens_text(value: impl AsRef<str>) -> Result<LensText> {
    let value = value.as_ref().trim();
    if value.is_empty() {
        return LensText::new("none");
    }
    let mut cut = value.len().min(MAX_CARD_TEXT_BYTES);
    while !value.is_char_boundary(cut) {
        cut -= 1;
    }
    LensText::new(&value[..cut])
}
