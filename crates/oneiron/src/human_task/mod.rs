//! Human-assigned TASK follow-up and the identity-bound human response signal
//! (ONE-1708).
//!
//! ARCH-0067 §6: humans are first-class TASK assignees. A human-assigned TASK
//! gets **no job realization** — Dreamer follow-up (track / remind / digest /
//! escalate) instead — and durable workflows wait on humans exactly as on
//! agents, through the existing C9 trap.
//!
//! Two pieces of durable state live here, and neither is authoritative:
//!
//! * the **follow-up cursor**, derived scheduler state keyed by `task_ref`.
//!   The authoritative, synced facts stay on the TASK entity
//!   (`assignee` / `status` / `started_at`); this cursor only remembers WHERE
//!   the nudging got to, and is rebuildable from live human-assigned TASK rows
//!   after a migration or home-node change.
//! * the **wait binding**, the device-local row that lets an inbound human
//!   response find the trap parked on it. Claim-ACT mechanics: it never syncs.
//!
//! Nothing here extends OF-327. Reminders, digests and escalations are
//! ordinary connector `send` intents scheduled through the existing outbound
//! chokepoint, sharing ONE-1699's `(task_ref, stage)` idempotency namespace so
//! one task can never double-notify across follow-up families.

mod followup;
mod model;
mod storage;
mod wait;

pub use self::followup::{
    HumanTaskFollowupDriver, human_followup_record, human_followup_records,
    resolve_native_human_route,
};
pub(crate) use self::followup::{register_human_followup_in_txn, run_human_followups_on_wake};
pub use self::model::{
    HUMAN_FOLLOWUP_STAGE_DIGEST, HUMAN_FOLLOWUP_STAGE_ESCALATION, HUMAN_FOLLOWUP_STAGE_REMINDER,
    HUMAN_TASK_FOLLOWUP_SCHEMA_VERSION, HumanFollowupDispatch, HumanFollowupStage,
    HumanResponseSignal, HumanTaskError, HumanTaskFollowupRecord, HumanTaskResult,
    HumanTaskWaitBinding, NativeHumanRoute,
};
pub use self::wait::{
    bind_human_wait, human_wait_binding, release_human_wait, signal_human_response,
};

#[cfg(test)]
mod followup_tests;
#[cfg(test)]
mod signal_tests;

// The flat human_task.rs module used to provide these names to the sibling test
// module through `use super::*`: its own private crate/std import header, and
// every human_task-internal item the tests name bare. After the directory split
// the seam re-imports both so the test children resolve exactly as before.
#[cfg(test)]
use self::{
    model::{ESCALATION_AFTER_SECONDS, HUMAN_FOLLOWUP_VERB, REMINDER_AFTER_SECONDS},
    storage::{followup_key, put_followup_record_in_txn, wait_signal_marker},
    wait::stored_human_wait_binding,
};
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::channel_identity::ChannelIdentityState;
#[cfg(test)]
use crate::edge::EdgeActorClass;
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::llm::DreamerTrapKind;
#[cfg(test)]
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TASK};
#[cfg(test)]
use crate::task_verb::task_follow_up_dedupe_key;
#[cfg(test)]
use rmpv::Value;
