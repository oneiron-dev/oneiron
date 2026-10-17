//! The vault shape's plan card (ARCH-0070 `shape:plan-apply`, the plan card
//! door): a plan as the owner meets it at the moment of change. It opens at
//! the resting depth, "4 changes, 1 needs your word", with the plan's reach
//! line, and unfolds to the whole diff, one row per item, each showing how
//! it lands and, once an apply has opened, where it stands. The payload is
//! render-neutral. [`ShapePlanCard::generated_ui`] composes it on the gen-UI
//! envelope from the existing atom kit, and every node carries fallback
//! text. No renderer, primitive or catalog entry is added (ARCH-0048,
//! RD-18); how the card unfolds is the app's.

use crate::error::Result;
use crate::lens::{
    CollectionAtom, GeneratedLens, GeneratedUiCard, LedgerCell, LedgerRowAtom, LensAtom,
    LensAtomId, LensNode, LensRenderId, LensStatus, LensText, LensTextSpan, StatusDotAtom,
    TextBlockAtom,
};
use crate::vault_shape::{
    ShapeApplyReceipt, ShapeApplyRun, ShapeChange, ShapeItemClass, ShapeItemState, ShapePlan,
    ShapePlanSummary,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Lens text stays under the kit's own bound.
const MAX_CARD_TEXT_BYTES: usize = 16 * 1024 - 1;

/// The plan card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ShapePlanCard {
    /// The plan's pinned frontier.
    pub frontier: String,
    /// The stored seed revision planned, when it is the stored one.
    pub seed_id: Option<String>,
    /// The resting depth: "4 changes, 1 needs your word".
    pub resting: String,
    pub summary: ShapePlanSummary,
    /// What the plan's actors can send before it and after it, in a line.
    pub reach_line: String,
    /// The whole diff, in landing order.
    pub items: Vec<ShapePlanCardItem>,
    /// Live structure the seed does not name; apply never touches it.
    pub undeclared: u32,
    /// The apply's run tree, whose root is its inbox group, once an apply
    /// of this plan has opened.
    pub run: Option<ShapeApplyRun>,
}

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

impl ShapePlanCard {
    /// The card for `plan`, with each item's standing from `apply`, the
    /// journal of an apply of this plan, when one has opened.
    #[must_use]
    pub fn of(plan: &ShapePlan, apply: Option<&ShapeApplyReceipt>) -> Self {
        let apply = apply.filter(|apply| apply.frontier == plan.frontier);
        let items = plan
            .items
            .iter()
            .map(|item| ShapePlanCardItem {
                seq: item.seq,
                line: format!(
                    "{} {} {}",
                    change_word(item.change),
                    item.target.kind(),
                    item.target.name()
                ),
                change: item.change,
                class: item.class,
                door: item.door.clone(),
                state: apply.and_then(|apply| {
                    apply
                        .items
                        .iter()
                        .find(|entry| entry.item.seq == item.seq)
                        .map(|entry| entry.state.clone())
                }),
            })
            .collect();
        Self {
            frontier: plan.frontier.clone(),
            seed_id: plan.seed_id.clone(),
            resting: plan.summary.resting_line(),
            summary: plan.summary,
            reach_line: plan.reach.line.clone(),
            items,
            undeclared: u32::try_from(plan.undeclared.len()).unwrap_or(u32::MAX),
            run: apply.map(|apply| apply.run.clone()),
        }
    }

    /// The whole card as text, for a surface with no cards at all.
    #[must_use]
    pub fn text(&self) -> String {
        let mut out = format!("{}.\n{}\n", self.resting, self.reach_line);
        for item in &self.items {
            let (_, stands) = standing(item);
            out.push_str(&format!("- {}: {stands}\n", item.line));
        }
        if self.undeclared > 0 {
            out.push_str(&format!(
                "{} live row(s) the seed does not name stay as they are.\n",
                self.undeclared
            ));
        }
        out
    }

    /// The card on the gen-UI envelope: the resting depth as its title, the
    /// reach line, then the whole diff.
    ///
    /// # Errors
    ///
    /// A card the envelope's validation refuses.
    pub fn generated_ui(&self) -> Result<GeneratedUiCard> {
        let mut root = sheet("shape-plan", &self.resting, Vec::new(), &self.text())?;
        root.children
            .push(text_block("shape-plan-reach", &self.reach_line)?);
        let mut rows = Vec::with_capacity(self.items.len());
        let mut fallback = String::from("Every change:");
        for item in &self.items {
            let (status, stands) = standing(item);
            rows.push(LedgerRowAtom {
                cells: vec![cell("Change", &item.line)?, cell("Lands", &stands)?],
                status: Some(StatusDotAtom {
                    status,
                    label: Some(lens_text(&stands)?),
                }),
                seal: None,
            });
            fallback.push_str(&format!(" {}: {stands};", item.line));
        }
        if !rows.is_empty() {
            root.children
                .push(sheet("shape-plan-items", "Every change", rows, &fallback)?);
        }
        let frontier = self.frontier.get(..16).unwrap_or(&self.frontier);
        GeneratedUiCard::new(
            LensRenderId::new(format!("vault-shape.plan.{frontier}"))?,
            GeneratedLens::new(root)?,
        )
    }
}

const fn change_word(change: ShapeChange) -> &'static str {
    match change {
        ShapeChange::Create => "create",
        ShapeChange::Update => "update",
        ShapeChange::Retire => "retire",
    }
}

/// How an item lands before an apply, or where it stands in one, as a
/// status and its words. One policy, so a ruling on the words moves one
/// place.
fn standing(item: &ShapePlanCardItem) -> (LensStatus, String) {
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
        Some(ShapeItemState::Ceremony) => (LensStatus::Proposed, "goes to its ceremony".to_owned()),
        Some(ShapeItemState::NoDoor) => (LensStatus::Missing, "no door yet".to_owned()),
        Some(ShapeItemState::Refused { reason }) => {
            (LensStatus::Rejected, format!("refused: {reason}"))
        }
    }
}

fn sheet(id: &str, title: &str, rows: Vec<LedgerRowAtom>, fallback: &str) -> Result<LensNode> {
    Ok(LensNode::with_fallback_text(
        LensAtomId::new(id)?,
        LensAtom::Sheet(CollectionAtom {
            title: lens_text(title)?,
            rows,
        }),
        lens_text(fallback)?,
    ))
}

fn text_block(id: &str, text: &str) -> Result<LensNode> {
    Ok(LensNode::with_fallback_text(
        LensAtomId::new(id)?,
        LensAtom::TextBlock(TextBlockAtom {
            spans: vec![LensTextSpan::Literal(lens_text(text)?)],
        }),
        lens_text(text)?,
    ))
}

fn cell(label: &str, value: &str) -> Result<LedgerCell> {
    Ok(LedgerCell {
        label: lens_text(label)?,
        value: lens_text(value)?,
    })
}

/// Bounded, never blank: a node's fallback text is required.
fn lens_text(value: impl AsRef<str>) -> Result<LensText> {
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
