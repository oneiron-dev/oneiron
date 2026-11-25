//! The slot deciders' Setting keys (pass 34, 1.2 and 6.3; row P1): per slot (the item: `rank`,
//! `place` or `after`), the Grant the owner named to decide it, how long the loop waits for its
//! answer, and how often an hour it may be asked; for PLACE alone, how long an order its
//! decider holds waits before it is placed again, and how long the home leaves an agent run
//! placed on another machine (row P4). Each is the owner's, read in one place
//! ([`slot_policy_in_txn`], [`place_wait_reask_ms_in_txn`], [`place_grace_secs_in_txn`]), at the
//! vault or at one project's.

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
/// How long an order waits, by default, after its PLACE decider picked wait, before the loop
/// places it again and asks again, in milliseconds (Engine F3, 25 Nov 20:4x).
pub const PLACE_WAIT_REASK_MS_DEFAULT: u64 = 60_000;
/// The longest such wait: one hour, the span of a slot's ask ceiling.
pub const PLACE_WAIT_REASK_MS_MAX: u64 = 3_600_000;
/// How long, by default, the vault's home leaves an agent run placed on another machine before
/// it takes the run itself, in milliseconds (row P4): the two minutes the cloud placement grace
/// held before it became this setting.
pub const PLACE_GRACE_MS_DEFAULT: u64 = 120_000;
/// The longest such grace: one hour.
pub const PLACE_GRACE_MS_MAX: u64 = 3_600_000;

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

/// Whether `item` names the PLACE slot.
fn admits_place(item: &str) -> bool {
    item == slot_item(SlotName::Place)
}

const PLACE_SLOT: ItemDomain = ItemDomain {
    name: "place slot",
    admits: admits_place,
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

fn place_wait_reask_ms() -> u64 {
    PLACE_WAIT_REASK_MS_DEFAULT
}

fn place_grace_ms() -> u64 {
    PLACE_GRACE_MS_DEFAULT
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
    /// How long an order waits after the PLACE slot's decider picked wait (item: place), in
    /// milliseconds, before the loop places it again and asks its decider again. Default 60000;
    /// at most 3600000. Longer is tighter: fewer asks.
    pub(crate) SLOT_WAIT_REASK_MS: u64 = "policy.slots.wait_reask_ms" {
        kind: Kind::new(place_wait_reask_ms).higher(),
        scopes: &[ScopeKind::Vault, ScopeKind::Project],
        item: Some(PLACE_SLOT),
    };
    /// How long the vault's home leaves an agent run placed on another machine (item: place)
    /// before it takes the run itself, in milliseconds; other machines wait the handover grace.
    /// Default 120000; at most 3600000. Longer is tighter: the placement holds longer.
    pub(crate) SLOT_PLACE_GRACE_MS: u64 = "policy.slots.place_grace_ms" {
        kind: Kind::new(place_grace_ms).higher(),
        scopes: &[ScopeKind::Vault, ScopeKind::Project],
        item: Some(PLACE_SLOT),
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

/// How long an order whose PLACE decider picked wait waits before it is placed again, in `txn`:
/// at `project`'s scope when given (a line order's line), else at the vault's. At most
/// [`PLACE_WAIT_REASK_MS_MAX`].
///
/// # Errors
///
/// Storage errors.
pub(crate) fn place_wait_reask_ms_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: Option<EntityId>,
) -> Result<u64> {
    let known: Vec<SettingScope> = project.map(SettingScope::Project).into_iter().collect();
    let reask_ms = SLOT_WAIT_REASK_MS
        .read_in_txn(vault, txn, &known, Some(slot_item(SlotName::Place)))?
        .value;
    Ok(reask_ms.min(PLACE_WAIT_REASK_MS_MAX))
}

/// How long the vault's home leaves an agent run placed on another machine, in `txn`, in whole
/// seconds (the lease's unit), rounded up: at `project`'s scope when given (the run's), else at
/// the vault's. At most [`PLACE_GRACE_MS_MAX`].
///
/// # Errors
///
/// Storage errors.
pub(crate) fn place_grace_secs_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: Option<EntityId>,
) -> Result<u64> {
    let known: Vec<SettingScope> = project.map(SettingScope::Project).into_iter().collect();
    let grace_ms = SLOT_PLACE_GRACE_MS
        .read_in_txn(vault, txn, &known, Some(slot_item(SlotName::Place)))?
        .value;
    Ok(grace_ms.min(PLACE_GRACE_MS_MAX).div_ceil(1_000))
}
