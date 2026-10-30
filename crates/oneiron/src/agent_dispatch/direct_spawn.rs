//! OF-541: a direct spawn's ask, carried whole onto its child.
//!
//! A spawn the host does not plan (no planner bound, or no acquired agent
//! lease) runs its named target as before: the ask's budget narrows the
//! carve and, with the lease, its need places the type. Nothing else in the
//! ask applies. ARCH-0079 has every spawn carry the same fields and its
//! receipt record what was asked, what was resolved, and why. So the child's
//! frozen dispatch input keeps the whole ask, and the spawn's result names
//! each asked field it did not apply, with the reason. Nothing here honors a
//! field, refuses a spawn or reads the vault.

use serde::{Deserialize, Serialize};

use crate::code_run::SelfSpawnAsk;
use crate::entity_id::EntityId;

/// A field of a spawn's ask that a direct spawn may leave unapplied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpawnAskField {
    Need,
    Care,
    Notes,
    Model,
    Width,
    Pattern,
}

/// Why a direct spawn left an asked field unapplied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpawnUnappliedReason {
    /// The host binds no planner, so nothing read the field.
    PlannerUnbound,
    /// The spawning agent holds no acquired lease, so the host neither
    /// planned the spawn nor placed it on its need.
    AgentLeaseUnbound,
}

/// One asked field a direct spawn did not apply, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpawnUnapplied {
    pub field: SpawnAskField,
    pub reason: SpawnUnappliedReason,
}

/// A direct spawn's receipt, frozen on its child's dispatch input: the
/// whole ask as the spawner gave it, and the asked fields this spawn did not
/// apply. Never authority, and never part of the spawn's intent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectSpawnReceipt {
    pub ask: SelfSpawnAsk,
    pub unapplied: Vec<SpawnUnapplied>,
    /// The spawner that asked, as the host authenticated it, never as the
    /// call names it (FIX 9181): its erase takes this receipt's ask out of
    /// every row that carries it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asker_ref: Option<EntityId>,
}

/// The receipt of a direct spawn of `ask`. Its need always applies: a
/// leased agent's host places the spawn on it with every rung, and dispatch
/// places any other on it at the rule rung (FIX 2107). Each care, notes,
/// model, width or pattern it sets goes unapplied, since nothing plans the
/// spawn. Target, prompt, need and budget apply and are never listed.
/// `asker` is the spawner the host authenticated.
#[must_use]
pub fn direct_spawn_receipt(
    ask: &SelfSpawnAsk,
    planner_bound: bool,
    asker: EntityId,
) -> DirectSpawnReceipt {
    let mut unapplied = Vec::new();
    let reason = if planner_bound {
        SpawnUnappliedReason::AgentLeaseUnbound
    } else {
        SpawnUnappliedReason::PlannerUnbound
    };
    let asked = [
        (SpawnAskField::Care, ask.care.is_some()),
        (SpawnAskField::Notes, ask.notes.is_some()),
        (SpawnAskField::Model, ask.model.is_some()),
        (SpawnAskField::Width, ask.width.is_some()),
        (SpawnAskField::Pattern, ask.pattern.is_some()),
    ];
    unapplied.extend(
        asked
            .into_iter()
            .filter(|(_, set)| *set)
            .map(|(field, _)| SpawnUnapplied { field, reason }),
    );
    DirectSpawnReceipt {
        ask: ask.clone(),
        unapplied,
        asker_ref: Some(asker),
    }
}
