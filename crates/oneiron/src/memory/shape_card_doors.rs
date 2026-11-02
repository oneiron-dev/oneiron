//! The vault shape's plan card and item receipts as typed reads (ARCH-0070
//! `shape:plan-apply`, FIX 3024): `vault.shape.plan.card` answers the whole
//! plan and its card beside the card on the gen-UI envelope, and
//! `vault.shape.items.receipt` reads the journal entry a landed item's
//! `vault_shape:<frontier>#<seq>` reference names, each over the rows the
//! caller's read admits. The owner's group doors share the inbox's owner
//! check (`agent_inbox_lens`); their request shape is here.
use super::{Memory, MemoryError, MemoryResult};
use crate::claim::ClaimReadStatus;
use crate::genui::ShapePlanCard;
use crate::inbox::InboxBulkVerb;
use crate::vault_shape::{ShapeApplyItem, ShapePlan, ShapePlanRequest, shape_item_ref_parts};
use serde::{Deserialize, Serialize};

/// `vault.shape.plan.card`'s answer: the plan, its card, and the card on the
/// gen-UI envelope. The envelope's node text is bounded for display; `plan`
/// and `card` carry every word whole.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ShapePlanCardView {
    /// The plan `vault.shape.plan` answers for the same request.
    pub plan: ShapePlan,
    /// Its resting depth, reach line and whole diff, each item where it
    /// stands once an apply of this plan has opened.
    pub card: ShapePlanCard,
    /// [`ShapePlanCard::generated_ui`], as the envelope serializes it.
    pub generated_ui: serde_json::Value,
}

/// `vault.shape.items.receipt`'s request.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShapeItemReceiptRequest {
    /// A landed item's `vault_shape:<frontier>#<seq>` reference, as its run
    /// row's result carries it.
    pub reference: String,
}

/// One shape item as its receipt reference names it: the journal entry,
/// with the run rows it stands on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ShapeItemReceipt {
    pub reference: String,
    /// The plan's frontier: the apply's journal key.
    pub frontier: String,
    pub seq: u32,
    /// The run id every row of the apply carries.
    pub run_id: String,
    /// The item's run-tree row, hex.
    pub attempt_id: Option<String>,
    /// The item and where it stands.
    pub item: ShapeApplyItem,
}

/// `vault.shape.groups.resolve`'s request: the owner's answer to one
/// apply's inbox group.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShapeGroupResolveRequest {
    /// The apply's run-tree root, hex, as `vault.shape.groups` lists it.
    pub group_key: String,
    pub verb: InboxBulkVerb,
}

impl Memory<'_> {
    /// `vault.shape.plan.card`: the plan `vault.shape.plan` answers, its
    /// card ([`Memory::shape_plan_card`]) and the card on the gen-UI
    /// envelope. Writes nothing.
    pub fn shape_plan_card_view(
        &self,
        input: &ShapePlanRequest,
    ) -> MemoryResult<ShapePlanCardView> {
        let plan = self.shape_plan(input)?;
        // The open apply reads as `vault.shape.read` lists it (FIX 9960).
        let read = self.read_lane(ClaimReadStatus::Surfaceable)?;
        let apply = self
            .vault
            .shape_apply_visible(&plan.frontier, &mut |id| read.is_entity_readable(id))?;
        let card = ShapePlanCard::of(&plan, apply.as_ref());
        let generated_ui = serde_json::to_value(card.generated_ui()?)
            .map_err(|_| MemoryError::bad_request("the plan card does not encode"))?;
        Ok(ShapePlanCardView {
            plan,
            card,
            generated_ui,
        })
    }

    /// `vault.shape.items.receipt`: the journal entry `input.reference`
    /// names, as the caller's read admits its apply. `None` for a reference
    /// that names no shape item, or an apply or item that is gone or that
    /// the caller cannot read.
    pub fn shape_item_receipt(
        &self,
        input: &ShapeItemReceiptRequest,
    ) -> MemoryResult<Option<ShapeItemReceipt>> {
        let Some((frontier, seq)) = shape_item_ref_parts(&input.reference) else {
            return Ok(None);
        };
        let read = self.read_lane(ClaimReadStatus::Surfaceable)?;
        let Some(mut journal) = self
            .vault
            .shape_apply_visible(frontier, &mut |id| read.is_entity_readable(id))?
        else {
            return Ok(None);
        };
        let Some(at) = journal.items.iter().position(|entry| entry.item.seq == seq) else {
            return Ok(None);
        };
        Ok(Some(ShapeItemReceipt {
            reference: input.reference.clone(),
            frontier: journal.frontier,
            seq,
            run_id: journal.run.run_id,
            attempt_id: journal.run.items.get(at).cloned(),
            item: journal.items.swap_remove(at),
        }))
    }
}
