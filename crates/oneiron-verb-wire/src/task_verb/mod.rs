//! Moved from `crates/oneiron/src/task_verb/mod.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub(crate) use crate::task_verb::brief::hex32;

pub use crate::authority::task_ask_handle::TaskAskHandle;
pub use crate::disclosure::task_ask_default::TaskAskDefault;
pub use crate::failure_ladder::task_terminal::TaskTerminalDisposition;
pub use crate::task_verb::ask_soft_confirm_types::TaskAskConfirmation;
pub use crate::task_verb::ask_soft_confirm_types::TaskAskConfirmationDecision;
pub use crate::task_verb::ask_types::AskAuthorityScope;
pub use crate::task_verb::ask_types::TaskAskBranch;
pub use crate::task_verb::ask_types::TaskAskDisagree;
pub use crate::task_verb::ask_types::TaskAskElectorate;
pub use crate::task_verb::ask_types::TaskAskGuest;
pub use crate::task_verb::ask_types::TaskAskNeed;
pub use crate::task_verb::ask_types::TaskAskOption;
pub use crate::task_verb::ask_types::TaskAskProvisional;
pub use crate::task_verb::ask_types::TaskAskSurface;
pub use crate::task_verb::brief::BriefConstraints;
pub use crate::task_verb::brief::BriefIntent;
pub use crate::task_verb::brief::Care;
pub use crate::task_verb::brief::Criterion;
pub use crate::task_verb::brief::EscalationTrigger;
pub use crate::task_verb::brief::SpawnPins;
pub use crate::task_verb::brief::TypeRef;
pub use crate::task_verb::comm_widen::revoke::CommWidenRevokeReceipt;
pub use crate::task_verb::fanout_launch::FanoutCheckChoice;
pub use crate::task_verb::highway_types::TaskAccept;
pub use crate::task_verb::highway_types::TaskRedo;
pub use crate::task_verb::verb_kind::TaskTtl;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskWaitRequest {
    pub handle: TaskAskHandle,
    pub step_key: String,
}
pub mod ask_forward;
pub mod ask_soft_confirm_types;
pub mod ask_types;
pub mod brief;
pub mod comm_widen;
pub mod fanout_batch;
pub mod fanout_launch;
pub mod highway_types;
pub mod revoke_lands;
pub mod run_control;
pub mod run_doors;
pub mod verb_kind;
