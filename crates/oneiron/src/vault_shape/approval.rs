//! A waiting approval stands on the reach its preview showed (FIX 10200).
//!
//! Once an apply journal exists, a later approval no longer re-plans the
//! whole frontier: that frontier moves with the journal's own landings, and
//! comparing against it would spoil torn-apply recovery. So each item pins
//! what its preview's reach actually stood on (the policy read-frontier,
//! the roster actors, the standing grants, the sending identities and their
//! send permission, each connector key's outward tools under its slate) as
//! one digest, re-pinned after each of the journal's own landings. An
//! owner's approval of a waiting widening lands only while that digest is
//! still the vault's; once another change moved it, the item asks for a
//! fresh preview instead, and every completed item keeps its receipt. A
//! journal written before the pin existed keeps today's reading.
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::apply::{ShapeApplyItem, ShapeItemState, open};
use super::live::LiveShape;
use super::plan::ShapePlanItem;
use super::seed::hex;
use super::{ShapeRow, ShapeTarget};
use crate::error::Result;
use crate::{EntityId, Vault};

/// Why a stale approval does not land.
const STALE_PREVIEW: &str = "what this item reaches changed since its preview; plan again to see \
                             the reach it would land with";

/// The dependencies a waiting item's preview stood on, as one digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ShapeApprovalDependencies {
    /// BLAKE3, hex, over the policy read-frontier and the reach rows.
    pub digest: String,
}

/// The dependencies `live` stands on.
pub(super) fn approval_dependencies(live: &LiveShape) -> ShapeApprovalDependencies {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron.vault_shape.approval.v1\0");
    hasher.update(&live.policy_frontier);
    live.reach.hash_into(&mut hasher);
    ShapeApprovalDependencies {
        digest: hex(hasher.finalize().as_bytes()),
    }
}

/// Whether a landing of `target` can move what the pin covers.
pub(super) const fn moves_reach(target: &ShapeTarget) -> bool {
    matches!(
        target,
        ShapeTarget::Shared
            | ShapeTarget::Member { .. }
            | ShapeTarget::Pack { .. }
            | ShapeTarget::Actor { .. }
            | ShapeTarget::Channel { .. }
            | ShapeTarget::Grant { .. }
            | ShapeTarget::Manifest { .. }
    )
}

/// Whether `item` already is what it declares in `live`: its own torn
/// landing, or the same change made elsewhere.
fn already_landed(item: &ShapePlanItem, live: Option<&(ShapeRow, Option<EntityId>)>) -> bool {
    match (&item.after, live) {
        (Some(after), Some((row, _))) => after.satisfied_by(row),
        (None, Some((row, _))) => row.retired(),
        (None, None) => true,
        (Some(_), None) => false,
    }
}

impl Vault {
    /// The dependencies the vault stands on now, every row read whole.
    ///
    /// # Errors
    ///
    /// A read failure or an undecodable setup row.
    pub(super) fn shape_approval_now(&self) -> Result<ShapeApprovalDependencies> {
        Ok(approval_dependencies(
            &self.read_live_shape(&mut |_| Ok(true))?,
        ))
    }
}

/// Where an approved waiting `entry` rests when its pin is no longer `now`:
/// landed when it already is so, else asking for a fresh preview; `None`
/// while the pin holds, or for a journal that never pinned one.
pub(super) fn check_waiting_shape_approval(
    entry: &ShapeApplyItem,
    now: &ShapeApprovalDependencies,
    live: Option<&(ShapeRow, Option<EntityId>)>,
    at: u64,
) -> Option<ShapeItemState> {
    if entry.approval.as_ref().is_none_or(|pinned| pinned == now) {
        return None;
    }
    Some(if already_landed(&entry.item, live) {
        ShapeItemState::Landed {
            at,
            receipt: "already so".to_owned(),
        }
    } else {
        ShapeItemState::Refused {
            reason: STALE_PREVIEW.to_owned(),
        }
    })
}

/// Re-pins the open items after `from` once the journal's own landing moved
/// the vault from `before` to `after`. An item pinned elsewhere was already
/// stale and stays so; `own` (an item found already so) re-pins them all.
pub(super) fn repin_waiting(
    items: &mut [ShapeApplyItem],
    from: usize,
    before: &ShapeApprovalDependencies,
    after: &ShapeApprovalDependencies,
    own: bool,
) {
    for entry in items.iter_mut().skip(from + 1) {
        if open(&entry.state)
            && entry
                .approval
                .as_ref()
                .is_some_and(|pinned| own || pinned == before)
        {
            entry.approval = Some(after.clone());
        }
    }
}
