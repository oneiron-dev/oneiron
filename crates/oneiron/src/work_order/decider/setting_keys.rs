//! The slot deciders' Setting keys (pass 34, 1.2 and 6.3; row P1): per slot (the item: `rank`,
//! `place` or `after`), the Grant the owner named to decide it, how long the loop waits for its
//! answer, and how often an hour it may be asked. Each is the owner's, read in one place
//! ([`slot_policy_in_txn`]), at the vault or at one line's project.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::setting::{ItemDomain, Kind, ScopeKind, SettingScope, SettingValue};
use crate::{EntityId, Vault};

use super::super::record::SlotName;
use super::slot_item;

/// A slot's default deadline for its decider's answer, in milliseconds (1.2).
pub const SLOT_DEADLINE_MS_DEFAULT: u64 = 5_000;
/// The longest deadline a decider's ask may take: the decision ladder's own clock limit.
pub const SLOT_DEADLINE_MS_MAX: u64 = 60_000;
/// A slot's default ceiling of decider asks an hour (1.2).
pub const SLOT_MAX_ASKS_PER_HOUR_DEFAULT: u32 = 120;

/// The Grant the owner named to decide a slot: its id, as the setting stores it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct DeciderGrant(pub EntityId);

impl SettingValue for DeciderGrant {
    const CLOSED: bool = true;
}

/// Whether `item` names a slot the loop asks a decider for.
fn admits_slot(item: &str) -> bool {
    [SlotName::Rank, SlotName::Place, SlotName::After]
        .into_iter()
        .any(|slot| slot_item(slot) == item)
}

const SLOTS: ItemDomain = ItemDomain {
    name: "slots",
    admits: admits_slot,
};

fn no_decider() -> Option<DeciderGrant> {
    None
}

fn slot_deadline_ms() -> u64 {
    SLOT_DEADLINE_MS_DEFAULT
}

fn slot_max_asks_per_hour() -> u32 {
    SLOT_MAX_ASKS_PER_HOUR_DEFAULT
}

crate::setting::setting_keys! {
    /// The Grant that decides the slot (item: rank, place or after) among the options the
    /// engine lists, in place of the slot's rule. Null is none: the rule decides. The Grant must
    /// stand for its agent and ai.verdict; its answers are model reads charged to that agent.
    /// An answer outside the options, or none in time, keeps the rule's pick.
    pub(crate) SLOT_DECIDER: Option<DeciderGrant> = "policy.slots.decider" {
        kind: Kind::new(no_decider).strictest(no_decider),
        scopes: &[ScopeKind::Vault, ScopeKind::Project],
        item: Some(SLOTS),
    };
    /// How long the loop waits for the slot's decider (item: rank, place or after), in
    /// milliseconds, before the rule's pick stands. Default 5000; at most 60000.
    pub(crate) SLOT_DEADLINE_MS: u64 = "policy.slots.deadline_ms" {
        kind: Kind::new(slot_deadline_ms).lower(),
        scopes: &[ScopeKind::Vault, ScopeKind::Project],
        item: Some(SLOTS),
    };
    /// How many times an hour the loop may ask the slot's decider (item: rank, place or after);
    /// past it the rule decides until the next hour. Default 120. Fewer is tighter.
    pub(crate) SLOT_MAX_ASKS_PER_HOUR: u32 = "policy.slots.max_asks_per_hour" {
        kind: Kind::new(slot_max_asks_per_hour).lower(),
        scopes: &[ScopeKind::Vault, ScopeKind::Project],
        item: Some(SLOTS),
    };
}

/// What the owner set for one slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SlotPolicy {
    /// The Grant named to decide the slot; `None`: the rule decides.
    pub(crate) decider: Option<EntityId>,
    /// At most [`SLOT_DEADLINE_MS_MAX`].
    pub(crate) deadline_ms: u64,
    pub(crate) max_asks_per_hour: u32,
}

/// The slot `slot`'s policy in `txn`: at `project`'s scope when given (a line order's line),
/// else at the vault's.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn slot_policy_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    slot: SlotName,
    project: Option<EntityId>,
) -> Result<SlotPolicy> {
    let known: Vec<SettingScope> = project.map(SettingScope::Project).into_iter().collect();
    let item = Some(slot_item(slot));
    let decider = SLOT_DECIDER.read_in_txn(vault, txn, &known, item)?.value;
    let deadline_ms = SLOT_DEADLINE_MS
        .read_in_txn(vault, txn, &known, item)?
        .value;
    let max_asks_per_hour = SLOT_MAX_ASKS_PER_HOUR
        .read_in_txn(vault, txn, &known, item)?
        .value;
    Ok(SlotPolicy {
        decider: decider.map(|grant| grant.0),
        deadline_ms: deadline_ms.min(SLOT_DEADLINE_MS_MAX),
        max_asks_per_hour,
    })
}
