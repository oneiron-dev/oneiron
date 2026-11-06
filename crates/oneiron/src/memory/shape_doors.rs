//! The vault shape on code mode and MCP (ARCH-0070): the free reads
//! `describe(vault)`, `vault.shape.read` and `vault.shape.plan`, over the setup rows the
//! caller's read admits, and the gated effect `vault.shape.apply`. A caller
//! who cannot read a world plans as though it were not there. The plan card
//! presents a plan on the gen-UI envelope.
use super::{Memory, MemoryError, MemoryResult};
use crate::EntityId;
use crate::claim::ClaimReadStatus;
use crate::genui::ShapePlanCard;
use crate::vault_shape::{
    ShapeApplier, ShapeApplyReceipt, ShapeApplyRequest, ShapePlan, ShapePlanRequest, ShapeRead,
};

impl Memory<'_> {
    /// `vault.shape.read`: the stored seed and the live arrangement.
    pub fn shape_read(&self) -> MemoryResult<ShapeRead> {
        let read = self.read_lane(ClaimReadStatus::Surfaceable)?;
        let mut shape = self
            .vault
            .shape_read_visible(&mut |id| read.is_entity_readable(id))?;
        self.withhold_learning_outcome(&mut shape.applies)?;
        Ok(shape)
    }

    /// `receipts` as this handle's actor reads them (FIX 10752): the
    /// conversation-learning outcome an apply carries reaches only a reader
    /// of the vault's learning setting, as
    /// [`crate::Vault::conversation_learning_view`] admits one. Every other
    /// caller reads the apply without it.
    fn withhold_learning_outcome(&self, receipts: &mut [ShapeApplyReceipt]) -> MemoryResult<()> {
        if self.vault.conversation_learning_reader(self.actor)? {
            return Ok(());
        }
        for receipt in receipts {
            receipt.conversation_learning = None;
        }
        Ok(())
    }

    /// `describe(vault)`: the vault's shape card, over the rows the caller
    /// reads. It names nothing else.
    pub fn describe_vault(
        &self,
        input: &DescribeRequest,
    ) -> MemoryResult<crate::task_verb::TaskDescription> {
        if input.self_target
            || input.task_ref.is_some()
            || input.key.is_some()
            || input.fold.is_some()
        {
            return Err(super::MemoryError::bad_request(
                "describe(vault) names the vault alone",
            ));
        }
        let read = self.read_lane(ClaimReadStatus::Surfaceable)?;
        let card = self
            .vault
            .shape_card_visible(&mut |id| read.is_entity_readable(id))?;
        Ok(crate::task_verb::TaskDescription::VaultCard { card })
    }

    /// `vault.shape.plan`: the difference between a seed, a preset pick's
    /// seed or the stored one, and the vault. Writes nothing.
    pub fn shape_plan(&self, input: &ShapePlanRequest) -> MemoryResult<ShapePlan> {
        let read = self.read_lane(ClaimReadStatus::Surfaceable)?;
        let seed = input.seed_for(self.actor)?;
        Ok(self
            .vault
            .plan_shape_visible(seed.as_ref(), &mut |id| read.is_entity_readable(id))?)
    }

    /// The plan card over the same plan `vault.shape.plan` answers: its
    /// resting depth, its reach line and the whole diff, with where each
    /// item stands once an apply of this plan has opened. Writes nothing;
    /// [`ShapePlanCard::generated_ui`] puts it on the envelope.
    pub fn shape_plan_card(&self, input: &ShapePlanRequest) -> MemoryResult<ShapePlanCard> {
        let plan = self.shape_plan(input)?;
        // The open apply reads as `vault.shape.read` lists it (FIX 9960).
        let read = self.read_lane(ClaimReadStatus::Surfaceable)?;
        let apply = self
            .vault
            .shape_apply_visible(&plan.frontier, &mut |id| read.is_entity_readable(id))?;
        Ok(ShapePlanCard::of(&plan, apply.as_ref()))
    }

    /// `vault.shape.apply`: lands a plan. On an embedded handle the vault's
    /// owner lands it through the owner's doors, from where his request
    /// reached this install (`with_owner_surface`, this install's own
    /// unless a host bound another); any other caller's apply stores the
    /// seed and leaves each item waiting for the owner's word.
    pub fn shape_apply(&self, input: &ShapeApplyRequest) -> MemoryResult<ShapeApplyReceipt> {
        let now = crate::unix_seconds_now();
        if let Ok(owner) = self.embedded_owner("vault.shape.apply") {
            return Ok(self.vault.apply_shape(
                ShapeApplier::Owner {
                    owner: &owner,
                    slips: None,
                    surface: self.owner_surface(),
                },
                input,
                now,
                &mut |_| Ok(true),
            )?);
        }
        self.shape_apply_as_principal(input)
    }

    /// `vault.shape.apply` as this handle's principal, never the owner: the
    /// seed is stored and every item waits for the owner's word. A new grant
    /// is also filed to the owner's widen inbox under the credential this
    /// handle reads with, when it has one.
    pub fn shape_apply_as_principal(
        &self,
        input: &ShapeApplyRequest,
    ) -> MemoryResult<ShapeApplyReceipt> {
        self.shape_apply_as_principal_listing(input).0
    }

    /// [`Self::shape_apply_as_principal`], beside the rows its receipt
    /// stands on ([`crate::Vault::apply_shape_listing`]), a resumed apply's
    /// included; a refusal answers beside the rows read before it. The same
    /// credential, locality, actor and read.
    pub fn shape_apply_as_principal_listing(
        &self,
        input: &ShapeApplyRequest,
    ) -> (MemoryResult<ShapeApplyReceipt>, Option<Vec<EntityId>>) {
        let now = crate::unix_seconds_now();
        // The read lane is the caller's authority; it lists no row.
        let read = match self.read_lane(ClaimReadStatus::Surfaceable) {
            Ok(read) => read,
            Err(refusal) => return (Err(refusal), Some(Vec::new())),
        };
        let applier = ShapeApplier::Actor {
            actor: self.actor,
            credential: self.read_proof.as_ref(),
        };
        let visible = &mut |id: &EntityId| read.is_entity_readable(id);
        let (receipt, rows) = self.vault.apply_shape_listing(applier, input, now, visible);
        // A resumed apply's receipt carries the learning outcome its creator's
        // apply stored (FIX 10752).
        let receipt = receipt.map_err(MemoryError::from).and_then(|mut receipt| {
            self.withhold_learning_outcome(std::slice::from_mut(&mut receipt))?;
            Ok(receipt)
        });
        (receipt, rows)
    }
}

use serde::{Deserialize, Serialize};

/// `describe`'s one input: the task to describe, a board card's key, the
/// vault for its shape card, or none for the whole TASKS section.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DescribeRequest {
    #[serde(default)]
    pub task_ref: Option<String>,
    #[serde(default, rename = "self")]
    pub self_target: bool,
    /// `describe(vault)`: the vault's shape card (ARCH-0070), what its
    /// arrangement amounts to and what its actors can send. Names nothing
    /// else.
    #[serde(default)]
    pub vault: bool,
    #[serde(default)]
    pub session_id: Option<String>,
    /// A board card's key: describe expands that card, under the board's
    /// scope and frame-epoch checks.
    #[serde(default)]
    pub key: Option<String>,
    /// The board frame the card key was read from; a stale one is refused.
    #[serde(default)]
    pub frame_epoch: Option<u64>,
    /// A fold of the run's own log (`f1`): its span, its stub and the ids it
    /// holds. Only the run that folded it answers this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fold: Option<String>,
    /// A task highway handle (OF-220): describe answers its status, the
    /// highway's own `TaskCallReceipt`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<crate::task_verb::TaskHandle>,
    /// The digest of the last status observed for `handle`: describe then
    /// polls, and an unchanged answer is `unchanged`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::task_verb::hex32::option"
    )]
    #[schemars(with = "Option<String>")]
    pub after: Option<[u8; 32]>,
}

/// The refusal of an `after` that names no handle to poll.
pub(crate) const AFTER_NEEDS_HANDLE: &str =
    "describe(after) polls a handle: name the handle it observed";

impl DescribeRequest {
    /// The one describe selector check (FIX 3256), which every door runs
    /// before any lookup and again on the args a pre hook left: naming none
    /// of `self`, `vault`, `task_ref`, `key`, `fold` and `handle` describes
    /// the TASKS section, and naming more than one is refused, never answered
    /// first-wins. `after` polls a handle, so it needs one; `session_id` and
    /// `frame_epoch` are context for the target, not targets of their own.
    pub fn validate(&self) -> MemoryResult<()> {
        let targets = self.targets();
        if targets.len() > 1 {
            return Err(MemoryError::bad_request(format!(
                "describe names one target, not {}",
                targets.join(" and ")
            )));
        }
        if self.after.is_some() && self.handle.is_none() {
            return Err(MemoryError::bad_request(AFTER_NEEDS_HANDLE));
        }
        Ok(())
    }

    /// The targets this request names, in the row's field order.
    fn targets(&self) -> Vec<&'static str> {
        [
            ("self", self.self_target),
            ("vault", self.vault),
            ("task_ref", self.task_ref.is_some()),
            ("key", self.key.is_some()),
            ("fold", self.fold.is_some()),
            ("handle", self.handle.is_some()),
        ]
        .into_iter()
        .filter_map(|(target, named)| named.then_some(target))
        .collect()
    }
}
