//! Plan: a pure read at a pinned frontier that renders the difference
//! between a seed and the vault, one item per declared name that differs.
//! Plan writes nothing; apply re-reads the same frontier and refuses a plan
//! whose frontier has moved, so what the owner approved is what they saw.
use super::live::LiveShape;
use super::seed::{hex, seed_digest};
use super::{ShapeCeiling, ShapeMemberRole, ShapeRead, ShapeRow, ShapeSeed, ShapeTarget, invalid};
use crate::error::Result;
use crate::{EntityId, Vault};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// What an item does to the named structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ShapeChange {
    /// The structure is missing and is created.
    Create,
    /// The structure exists and takes the declared values.
    Update,
    /// The structure leaves, by an explicit retire line.
    Retire,
}

/// How an item lands (ARCH-0070 `shape:plan-apply`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ShapeItemClass {
    /// A narrowing, or an ordinary setup write that widens nothing (a new
    /// world, a roster row at a proposed ceiling): lands with a receipt.
    Receipted,
    /// Any new grant, raised ceiling, retire line, new power or kind on the
    /// wire: lands Proposed and waits for the owner's stamp. A widening never
    /// rides autonomy, whatever the rung.
    Widening,
    /// A key binding, an ownership transfer or a co-sign change: goes to the
    /// AUTHORITY_LOG ceremony unchanged. A member row moving a role to or
    /// from Owner compiles to one.
    Authority,
}

/// One difference between the seed and the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ShapePlanItem {
    /// The item's place in landing order, from 0.
    pub seq: u32,
    pub target: ShapeTarget,
    pub change: ShapeChange,
    pub class: ShapeItemClass,
    /// The live row, when the structure exists.
    pub before: Option<ShapeRow>,
    /// The declared row; none for a retire.
    pub after: Option<ShapeRow>,
    /// The named door apply lands this item through; none while the vault
    /// has no door for it, and then apply reports the item and lands nothing.
    pub door: Option<String>,
}

/// The plan card's resting depth: "4 changes, 1 needs your word".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ShapePlanSummary {
    pub changes: u32,
    /// Widenings: each waits for the owner's word.
    pub needs_word: u32,
    /// Authority operations: each goes to its ceremony.
    pub ceremonies: u32,
    /// Items the vault has no door for yet.
    pub no_door: u32,
}

/// `vault.shape.plan`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ShapePlan {
    /// The stored revision planned, when the seed is the stored one.
    pub seed_id: Option<String>,
    /// The seed this plan renders; apply carries it back.
    pub seed: ShapeSeed,
    /// The pinned frontier, hex: the seed, the policy frontier and every
    /// live setup row this plan read.
    pub frontier: String,
    pub items: Vec<ShapePlanItem>,
    /// Live structure the seed does not name. Apply never sees it; it is
    /// drift, to adopt into the seed or leave be. Nothing reconciles it.
    pub undeclared: Vec<ShapeRow>,
    pub summary: ShapePlanSummary,
}

/// How a change to `target` lands. One policy, so a ruling moves one line.
fn classify(
    change: ShapeChange,
    before: Option<&ShapeRow>,
    after: Option<&ShapeRow>,
) -> ShapeItemClass {
    use ShapeItemClass::{Authority, Receipted, Widening};
    if change == ShapeChange::Retire {
        return Widening;
    }
    match (before, after) {
        (Some(ShapeRow::Member { role: was, .. }), Some(ShapeRow::Member { role: now, .. })) => {
            if *was == ShapeMemberRole::Owner || *now == ShapeMemberRole::Owner {
                Authority
            } else if now.reach() > was.reach() {
                Widening
            } else {
                Receipted
            }
        }
        (_, Some(ShapeRow::World { .. })) => Receipted,
        (None, Some(ShapeRow::Actor { ceiling, .. })) => match ceiling {
            ShapeCeiling::Auto => Widening,
            ShapeCeiling::Proposed => Receipted,
        },
        (
            Some(ShapeRow::Actor {
                ceiling: was,
                enabled: was_on,
                ..
            }),
            Some(ShapeRow::Actor {
                ceiling: now,
                enabled: now_on,
                ..
            }),
        ) => {
            let raised = *was == ShapeCeiling::Proposed && *now == ShapeCeiling::Auto;
            if raised || (!was_on && *now_on) {
                Widening
            } else {
                Receipted
            }
        }
        (_, Some(ShapeRow::Sync { on_wire: false, .. })) => Receipted,
        _ => Widening,
    }
}

/// The named door an item lands through, where the vault has one. A grant
/// row mints only from the bound it carries.
fn door(
    change: ShapeChange,
    target: &ShapeTarget,
    after: Option<&ShapeRow>,
) -> Option<&'static str> {
    match (change, target) {
        (ShapeChange::Create, ShapeTarget::Shared) => Some("initialize_shared_vault"),
        (ShapeChange::Create, ShapeTarget::Member { .. }) => Some("add_shared_member"),
        (ShapeChange::Update, ShapeTarget::Member { .. }) => Some("change_shared_member_role"),
        (ShapeChange::Retire, ShapeTarget::Member { .. }) => Some("remove_shared_member"),
        (ShapeChange::Create, ShapeTarget::World { .. }) => Some("create_world"),
        (ShapeChange::Create, ShapeTarget::Actor { .. }) => Some("define_agent"),
        (ShapeChange::Update | ShapeChange::Retire, ShapeTarget::Actor { .. }) => {
            Some("update_agent_definition_as")
        }
        (ShapeChange::Create | ShapeChange::Update, ShapeTarget::Pack { .. }) => Some("put_pack"),
        (ShapeChange::Retire, ShapeTarget::Pack { .. }) => Some("remove_pack"),
        (ShapeChange::Create, ShapeTarget::Grant { .. })
            if matches!(after, Some(ShapeRow::Grant { bound: Some(_), .. })) =>
        {
            Some("create_standing_grant")
        }
        (ShapeChange::Retire, ShapeTarget::Grant { .. }) => Some("revoke_consent_grant"),
        _ => None,
    }
}

fn frontier(seed: &ShapeSeed, live: &LiveShape) -> Result<String> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron.vault_shape.frontier.v1\0");
    hasher.update(&seed_digest(seed)?);
    hasher.update(&live.policy_frontier);
    for (row, entity) in &live.rows {
        let bytes = rmp_serde::to_vec_named(row).map_err(|_| invalid("row encoding failed"))?;
        hasher.update(&(bytes.len() as u64).to_be_bytes());
        hasher.update(&bytes);
        hasher.update(entity.map(|id| id.to_hex()).unwrap_or_default().as_bytes());
    }
    Ok(hex(hasher.finalize().as_bytes()))
}

impl Vault {
    /// The stored seed and the live arrangement, every row included.
    ///
    /// # Errors
    ///
    /// A read failure or an undecodable setup row.
    pub fn shape_read(&self) -> Result<ShapeRead> {
        self.shape_read_visible(&mut |_| Ok(true))
    }

    /// [`Self::shape_read`], keeping an entity-backed live row only when
    /// `visible` admits its entity.
    ///
    /// # Errors
    ///
    /// As [`Self::shape_read`], or `visible`'s own.
    pub fn shape_read_visible(
        &self,
        visible: &mut dyn FnMut(&EntityId) -> Result<bool>,
    ) -> Result<ShapeRead> {
        let seed = self.shape_seed()?;
        let live = self.read_live_shape(visible)?;
        Ok(ShapeRead {
            seed,
            live: ShapeSeed {
                rows: live.rows.into_iter().map(|(row, _)| row).collect(),
            },
            applies: self.open_shape_applies()?,
        })
    }

    /// Plans `seed`, or the stored seed when none is given, against the
    /// vault as it stands. Writes nothing.
    ///
    /// # Errors
    ///
    /// An invalid seed, a read failure or an undecodable setup row.
    pub fn plan_shape(&self, seed: Option<&ShapeSeed>) -> Result<ShapePlan> {
        self.plan_shape_visible(seed, &mut |_| Ok(true))
    }

    /// [`Self::plan_shape`] over the live rows `visible` admits.
    ///
    /// # Errors
    ///
    /// As [`Self::plan_shape`], or `visible`'s own.
    pub fn plan_shape_visible(
        &self,
        seed: Option<&ShapeSeed>,
        visible: &mut dyn FnMut(&EntityId) -> Result<bool>,
    ) -> Result<ShapePlan> {
        let stored = self.shape_seed()?;
        let (seed, seed_id) = match (seed, stored) {
            (Some(seed), stored) => {
                let id = stored
                    .filter(|stored| stored.seed == *seed)
                    .map(|stored| stored.id);
                (seed.clone(), id)
            }
            (None, Some(stored)) => (stored.seed, Some(stored.id)),
            (None, None) => (ShapeSeed::default(), None),
        };
        seed.validate()?;
        let live = self.read_live_shape(visible)?;
        let frontier = frontier(&seed, &live)?;
        let by_target: BTreeMap<ShapeTarget, &ShapeRow> = live
            .rows
            .iter()
            .map(|(row, _)| (row.target(), row))
            .collect();

        let mut pending = Vec::new();
        for (index, row) in seed.rows.iter().enumerate() {
            let target = row.target();
            let before = by_target.get(&target).copied();
            let (change, after) = match (row, before) {
                (ShapeRow::Retire { .. }, None) => continue,
                (ShapeRow::Retire { .. }, Some(_)) => (ShapeChange::Retire, None),
                // No sync declaration is stored yet, so every one is open.
                (ShapeRow::Sync { .. }, _) => (ShapeChange::Create, Some(row)),
                (_, None) => (ShapeChange::Create, Some(row)),
                (_, Some(live)) if row.satisfied_by(live) => continue,
                (_, Some(_)) => (ShapeChange::Update, Some(row)),
            };
            pending.push((target, index, change, before, after));
        }
        // Retire lines land last; the rest go structure first, then seed order.
        pending.sort_by_key(|(target, index, change, ..)| {
            (*change == ShapeChange::Retire, target.rank(), *index)
        });

        let mut summary = ShapePlanSummary::default();
        let mut items = Vec::with_capacity(pending.len());
        for (seq, (target, _, change, before, after)) in pending.into_iter().enumerate() {
            let class = classify(change, before, after);
            let door = door(change, &target, after).map(str::to_owned);
            summary.changes += 1;
            match class {
                ShapeItemClass::Widening => summary.needs_word += 1,
                ShapeItemClass::Authority => summary.ceremonies += 1,
                ShapeItemClass::Receipted => {}
            }
            if door.is_none() {
                summary.no_door += 1;
            }
            items.push(ShapePlanItem {
                seq: u32::try_from(seq).map_err(|_| invalid("plan too long"))?,
                target,
                change,
                class,
                before: before.cloned(),
                after: after.cloned(),
                door,
            });
        }
        let named: BTreeSet<ShapeTarget> = seed.rows.iter().map(ShapeRow::target).collect();
        let undeclared = live
            .rows
            .iter()
            .filter(|(row, _)| !named.contains(&row.target()))
            .map(|(row, _)| row.clone())
            .collect();
        Ok(ShapePlan {
            seed_id,
            seed,
            frontier,
            items,
            undeclared,
            summary,
        })
    }
}
