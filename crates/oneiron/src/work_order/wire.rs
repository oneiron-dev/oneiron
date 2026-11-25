//! The work order verbs' inputs and answers (pass 34, 1.1 and 14.2). An order's id in the
//! answer is the handle every later call takes; there is no handle object.
use serde::{Deserialize, Serialize};

use crate::EntityId;

use super::blocker::BlockedOn;
use super::group::GroupRequest;
use super::record::{
    AfterCondition, EndKind, OrderCharge, OrderClass, OrderLimits, OrderWishes, ResultBinding,
    SlotDecision, WaitRule, WorkOrder,
};

/// The wait rule an order takes when the request names none: it waits.
const fn wait_open() -> WaitRule {
    WaitRule::Open
}

/// `vault.jobs.order`: run one pinned, approved workload, charged to an offer. No machine has
/// to be named: the PLACE rule picks among the machines the approval and the limits allow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkOrderRequest {
    /// The workload digest (64 lower hex) of a pinned workload.
    pub workload: String,
    pub charge: OrderCharge,
    #[serde(default)]
    pub limits: OrderLimits,
    #[serde(default)]
    pub wishes: OrderWishes,
    #[serde(default)]
    pub class: OrderClass,
    /// `open` (the default) waits; `no` answers a refusal at once; `until` waits to a time.
    #[serde(default = "wait_open")]
    pub wait: WaitRule,
    /// Failures to retry once (a nonzero exit, a limit): a deterministic failure is not
    /// retried otherwise.
    #[serde(default)]
    pub retry_on: Vec<EndKind>,
    /// Where a successful attempt's returnable outputs land; none fetches nothing.
    #[serde(default)]
    pub result: Option<ResultBinding>,
    /// The same key with the same input answers the order it made, `replayed: true`.
    #[serde(default)]
    pub intent_key: Option<String>,
    /// Run only after this order of the caller's reaches `Done`; its giving up or cancel gives
    /// this one up.
    #[serde(default)]
    pub after: Option<AfterCondition>,
    /// This order's place in an array: the group's cap holds how many members run at once.
    #[serde(default)]
    pub group: Option<GroupRequest>,
}

/// `vault.jobs.orders.get`, `vault.jobs.orders.cancel`: one order by its id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkOrderRef {
    pub order: EntityId,
}

/// `vault.jobs.orders.list`: the orders the caller may read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkOrderListRequest {
    /// Only orders that are not at an end.
    #[serde(default)]
    pub open_only: bool,
}

/// One order as the caller sees it: its state (with why it waits), its attempts with their
/// decisions and ends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WorkOrderView {
    pub order: WorkOrder,
    /// The request repeated an earlier one under the same intent key.
    #[serde(default)]
    pub replayed: bool,
    /// The newest signed receipt of the last attempt, once a node sent one (14.2: "the last
    /// one carries its signed receipt"). `None` with no attempt, before the node's first
    /// receipt, and for an offer's job, whose provider signs none.
    #[serde(default)]
    pub receipt: Option<AttemptReceipt>,
}

/// A node's signed receipt of one attempt, as the issuer holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AttemptReceipt {
    /// The attempt it is of (1-based).
    pub attempt: u16,
    /// The attempt's dispatch key.
    pub key: String,
    /// The node.
    pub machine: EntityId,
    /// The signed receipt in the job protocol's codec, base64 (standard alphabet, padded).
    pub signed: String,
    /// The issuer's wall clock when it arrived.
    pub observed_at_ms: u64,
}

/// What `vault.jobs.orders.wait` waits for.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum WaitUntil {
    /// The first attempt whose workload the machine started, or a terminal state with no
    /// start; the view's state tells which.
    Started,
    /// The terminal state.
    #[default]
    Terminal,
}

/// `vault.jobs.orders.wait`: wait on one order until `until`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkOrderWaitRequest {
    pub order: EntityId,
    #[serde(default)]
    pub until: WaitUntil,
}

/// The answer of `vault.jobs.orders.wait`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WorkOrderWaitAnswer {
    pub view: WorkOrderView,
    /// Whether the order has reached `until`. A code-mode run parks until it has, so it always
    /// reads true there. A caller that cannot park (MCP, HTTP) is answered at once and reads
    /// false while the order has not, and asks again.
    pub reached: bool,
}

/// The orders a caller may read, newest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WorkOrderList {
    pub orders: Vec<WorkOrder>,
}

/// `vault.machines.place`: where an order for this workload would go now, starting nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MachinesPlaceRequest {
    /// The workload digest (64 lower hex).
    pub workload: String,
    #[serde(default)]
    pub limits: OrderLimits,
    #[serde(default)]
    pub wishes: OrderWishes,
}

/// The candidates, each machine's reasons, and the PLACE rule's pick.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MachinesPlaceView {
    /// The machines that fit now, in the rule's order.
    pub candidates: Vec<EntityId>,
    /// Why each other allowed machine does not fit now.
    pub blocked: Vec<BlockedOn>,
    /// The rule's decision, when a machine fits.
    #[serde(default)]
    pub decision: Option<SlotDecision>,
}
