//! The stored work order (pass 34, section 1.1; Engine ruling EM-18 = A): one `WORK_ORDER` row
//! per order, above the built job. An open order holds no device and no money; an attempt is a
//! job the built start makes, under a job id the order and the attempt number fix.
use oneiron_contracts::fingerprint::{Fingerprint, purposes};
use serde::{Deserialize, Serialize};

use crate::gpu_line::{ClaimKey, UnitPurpose};
use crate::job_workload::{ResourceRequest, WorkloadStarter};
use crate::side_table::{self, Named, SideTable};
use crate::{EdgeActorClass, EntityId};

use super::blocker::{BlockedOn, Blocker};
use super::decider::{DeciderMiss, DeciderReceipt};

pub(super) const WORK_ORDERS: SideTable<EntityId, WorkOrder, Named> =
    SideTable::new(&side_table::WORK_ORDER);

/// One work order: somebody wants a pinned workload run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WorkOrder {
    pub id: EntityId,
    /// Whose authority the order runs under; carried out only while it lives (I8).
    pub ordered_by: OrderedBy,
    /// The `JOB_WORKLOAD` digest, 64 lower hex.
    pub workload: String,
    /// The workload pin's own request, copied: the digest fixes it.
    pub request: ResourceRequest,
    pub charge: OrderCharge,
    #[serde(default)]
    pub limits: OrderLimits,
    #[serde(default)]
    pub wishes: OrderWishes,
    #[serde(default)]
    pub class: OrderClass,
    pub wait: WaitRule,
    /// End causes of a failed attempt the requester asked to be retried (4.7: a deterministic
    /// failure is not retried unless the order lists it).
    #[serde(default)]
    pub retry_on: Vec<EndKind>,
    pub state: OrderState,
    /// Set when a cancel reached a running order: the attempt is being stopped, and the order
    /// is `Cancelled` once its end is in.
    #[serde(default)]
    pub cancel: Option<CancelAsk>,
    /// A retry's backoff: no attempt before this time (the blocker `RetryNotBefore`).
    #[serde(default)]
    pub retry_not_before_ms: Option<u64>,
    /// Every attempt, in order; attempt `n` is `attempts[n - 1]`.
    #[serde(default)]
    pub attempts: Vec<OrderAttempt>,
    /// Where the attempt's returnable outputs land, passed into each quote it makes (Engine
    /// ruling R4-RESULT-BINDING = A); none fetches nothing.
    #[serde(default)]
    pub result: Option<ResultBinding>,
    /// The caller's idempotency key: the same key with the same input answers this order.
    #[serde(default)]
    pub intent_key: Option<String>,
    /// The order this one waits on (row Q5): looked at only once that order is at an end.
    #[serde(default)]
    pub after: Option<AfterCondition>,
    /// The array this order is a member of (row Q5): the group's row caps its running
    /// members.
    #[serde(default)]
    pub group: Option<GroupMember>,
    pub ordered_at_ms: u64,
    pub updated_at_ms: u64,
    /// Every write compares and bumps it.
    pub revision: u64,
}

/// The artifact a successful attempt's returnable outputs land in as its next version,
/// pending Keep, through the starter's lane, and the task it belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResultBinding {
    pub artifact: EntityId,
    pub task: EntityId,
    /// The `application/json` artifact that takes the attempt's handoff manifest (row
    /// RSI-ARTIFACT-HANDOFF); `None` lands none. Left out of the encoding when `None`, so a
    /// binding without it encodes as before.
    #[serde(default)]
    pub manifest: Option<EntityId>,
}

/// Who ordered, as the loop checks it again at each attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OrderedBy {
    /// The vault owner: his recorded act, carried out without his presence while he is the
    /// owner. `None` after his erase.
    Owner { owner: Option<EntityId> },
    /// An agent under the live Grant that named `vault.jobs.order`; `actor` is `None` after
    /// its erase, which ends the order.
    Agent {
        actor: Option<EntityId>,
        class: EdgeActorClass,
        grant: EntityId,
    },
}

impl OrderedBy {
    /// The starter the workload check judges.
    #[must_use]
    pub fn starter(&self) -> Option<WorkloadStarter> {
        match self {
            Self::Owner { owner } => owner.map(WorkloadStarter::Owner),
            Self::Agent { grant, .. } => Some(WorkloadStarter::Grant(*grant)),
        }
    }

    /// The actor who ordered, while not erased.
    #[must_use]
    pub fn actor(&self) -> Option<EntityId> {
        match self {
            Self::Owner { owner } => *owner,
            Self::Agent { actor, .. } => *actor,
        }
    }
}

/// What an attempt's seconds are held on and charged to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OrderCharge {
    /// A `[gpu_jobs]` offer by name, with the requester's allowance: the built quote and start.
    Offer { name: String },
    /// A unit of a line's arm: the claim's logical key is (arm, rung, the order id in hex,
    /// attempt n) (pass 32, 5.2; EM-18). Its attempts are made through the line's reserve
    /// (`vault.arms.units.reserve` with a wait, row H3), which holds nothing until then: the
    /// reserve's terms the order carries are the line's project, the offer and the purpose.
    Line {
        arm: EntityId,
        rung: u8,
        /// The lane project the line is set on (the arm's line).
        line: EntityId,
        /// The line's offer the unit runs on.
        offer: String,
        purpose: UnitPurpose,
    },
}

/// Where the order may run: hard limits the loop never relaxes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OrderLimits {
    /// The machines allowed; empty means every machine the workload's approval names.
    #[serde(default)]
    pub machines: Vec<EntityId>,
    /// The scope kinds allowed (`host`, `container`); empty means any.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// The device ids allowed; empty means any.
    #[serde(default)]
    pub device_ids: Vec<String>,
    /// The named running caps the order counts against (row Q5): while a cap's setting
    /// `jobs.caps.<name>` is set, no more orders that name it have a live attempt at once.
    #[serde(default)]
    pub caps: Vec<String>,
}

/// An order that runs only after another (pass 34, 1.1): `on` is the end it waits for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AfterCondition {
    pub order: EntityId,
    #[serde(default)]
    pub on: AfterOn,
}

/// The end of the order an [`AfterCondition`] names that releases the waiting order. Any
/// other end gives the waiting order up.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AfterOn {
    /// The order is `Done`: its last attempt succeeded.
    #[default]
    Success,
}

/// An order's place in an array (pass 34, 1.1): the group's `WORK_ORDER_GROUP` row holds its
/// cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GroupMember {
    pub group: EntityId,
    pub index: u32,
}

/// Where the order would rather run: soft wishes the PLACE rule reads.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OrderWishes {
    /// Warm keys the work reads (4.1).
    #[serde(default)]
    pub warm: Vec<String>,
    #[serde(default)]
    pub machine: Option<EntityId>,
}

/// Who goes first among runnable orders (4.5).
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum OrderClass {
    Interactive,
    #[default]
    Normal,
    Background,
}

/// What the order does when it cannot run now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WaitRule {
    /// Answer a refusal at once: today's start.
    No,
    /// Wait until this time, then give up.
    Until { ms: u64 },
    /// Wait until it runs or is cancelled.
    Open,
}

/// Where an order stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OrderState {
    /// Waiting: why, when the loop last looked, and the earliest time a blocker clears by
    /// itself, when one is known. Nothing is held.
    Open {
        blocked: Vec<BlockedOn>,
        looked_at_ms: u64,
        earliest_ms: Option<u64>,
    },
    /// Attempt `attempt` (1-based) is live.
    Running {
        attempt: u16,
    },
    /// The last attempt ended in success.
    Done,
    GivenUp {
        why: GiveUpWhy,
    },
    Cancelled {
        why: CancelWhy,
    },
}

impl OrderState {
    /// Whether the order is at an end and never changes again.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Done | Self::GivenUp { .. } | Self::Cancelled { .. }
        )
    }
}

/// Why an order gave up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GiveUpWhy {
    /// The AFTER rule gave up on the last attempt's end.
    Ended { end: EndKind },
    /// Every allowed machine blocks it in a way no wait clears.
    NeverFits { blocked: Vec<BlockedOn> },
    /// `wait = No` and it could not run at once, or its `Until` time passed.
    WaitEnded { blocked: Vec<BlockedOn> },
    /// The owner wrote the last attempt off: nothing starts again unless somebody orders again.
    WrittenOff,
    /// The order this one waited on ended without the end it waited for (row Q5).
    Upstream { order: EntityId },
}

/// A cancel that reached a running order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CancelAsk {
    pub at_ms: u64,
    /// Who asked; `None` after their erase.
    pub by: Option<EntityId>,
}

/// Why an order was cancelled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CancelWhy {
    /// The owner or the requester cancelled it.
    Asked { by: Option<EntityId> },
    /// The authority it ran under ended before an attempt was made (I8).
    AuthorityEnded,
}

/// One keyed run of the order on one machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OrderAttempt {
    /// 1-based.
    pub n: u16,
    /// The job the built start made: [`attempt_job_id`] of the order and `n`.
    pub job: EntityId,
    pub machine: Option<EntityId>,
    /// The RANK decision that put the order first among the runnable ones.
    pub ranked: SlotDecision,
    /// The PLACE decision that chose the machine.
    pub placed: SlotDecision,
    pub made_at_ms: u64,
    /// When the loop first saw the machine's word that the attempt's workload ran (a node's
    /// receipt; for an offer's job, its provider's clock). An attempt is made before its
    /// create, so a made attempt may still end `NeverStarted`; `orders.wait` with
    /// `until: "started"` waits for this (14.2). A row written before the field reads `None`.
    #[serde(default)]
    pub started_at_ms: Option<u64>,
    /// The attempt's end and the AFTER decision on it, once the job's end is in.
    #[serde(default)]
    pub end: Option<AttemptEnd>,
}

/// How an attempt ended, and what the AFTER rule decided.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AttemptEnd {
    pub kind: EndKind,
    pub at_ms: u64,
    pub after: SlotDecision,
}

/// The end cause of an attempt, as the AFTER slot reads it (4.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EndKind {
    /// The process exited by itself with this code; 0 is success.
    Exited {
        code: i32,
    },
    /// Never started, zero seconds: a refusal, a busy device, a node restart before launch.
    NeverStarted,
    /// The start window passed with nothing accepted.
    Expired,
    /// Started, seconds unknown: the machine was lost or reset.
    Lost,
    MemoryLimit,
    DiskLimit,
    /// Stopped at its maximum.
    TimeLimit,
    /// The contract, the commit or the template changed: it cannot launch as pinned.
    LaunchRefusedChanged,
    /// The authority that started it was revoked.
    Revoked,
    /// The requester's or the owner's cancel.
    Stopped,
    /// The owner wrote the attempt off.
    WrittenOff,
    /// Closed at a task boundary (row P3).
    Closed,
}

impl EndKind {
    /// Whether the attempt succeeded.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Exited { code: 0 })
    }
}

/// A slot's decision, stored on the row it decides (1.2): "why here?" and "why this one
/// first?" are a read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SlotDecision {
    pub slot: SlotName,
    /// The lawful options the engine listed, in the rule's order.
    pub options: Vec<String>,
    pub pick: String,
    pub by: DecidedBy,
    /// At most 500 bytes.
    pub why: String,
}

/// The slots row Q1 builds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SlotName {
    Rank,
    Place,
    After,
}

/// Who decided: the slot's named rule, or (row P1) the decider the owner named.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DecidedBy {
    Rule {
        name: String,
    },
    /// The decider the owner named for the slot (row P1): its answer was one of the options
    /// and came inside the slot's deadline. The receipt is its read's.
    Grant {
        grant: EntityId,
        receipt: DeciderReceipt,
    },
    /// The slot's rule, kept because the decider the owner named did not decide (row P1, I9):
    /// why, and its read's receipt when it was asked.
    RuleKept {
        name: String,
        decider: EntityId,
        miss: DeciderMiss,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        receipt: Option<DeciderReceipt>,
    },
}

/// The most bytes a decision's reason holds.
pub const SLOT_WHY_MAX: usize = 500;

impl SlotDecision {
    /// The rule `rule`'s pick among `options`, with its reason cut to [`SLOT_WHY_MAX`] bytes.
    #[must_use]
    pub fn by_rule(
        slot: SlotName,
        rule: &str,
        options: Vec<String>,
        pick: String,
        why: &str,
    ) -> Self {
        let mut why = why.to_owned();
        if why.len() > SLOT_WHY_MAX {
            let mut cut = SLOT_WHY_MAX;
            while !why.is_char_boundary(cut) {
                cut -= 1;
            }
            why.truncate(cut);
        }
        Self {
            slot,
            options,
            pick,
            by: DecidedBy::Rule {
                name: rule.to_owned(),
            },
            why,
        }
    }
}

/// The job id of attempt `n` of order `order`: the id16 of the fingerprint
/// `purposes::work_order::ATTEMPT_JOB_ID` over the order id and `n` (1.1). A second pass of the
/// loop after a crash makes the same id, so the built start finds its own job and never makes
/// another.
///
/// # Errors
///
/// [`crate::Error::InvariantViolation`] in the one-in-2^128 case the digest is a reserved id.
pub fn attempt_job_id(order: &EntityId, n: u16) -> crate::Result<EntityId> {
    let digest = Fingerprint::of_parts(
        purposes::work_order::ATTEMPT_JOB_ID,
        &[&order.as_bytes()[..], &n.to_be_bytes()[..]],
    );
    EntityId::from_bytes(digest.prefix::<16>())
        .map_err(|_| crate::Error::InvariantViolation("a work order attempt id is reserved"))
}

impl WorkOrder {
    /// Whether the order's `Until` time has passed at `now_ms`: no attempt is made after it,
    /// whether or not the order fits then.
    #[must_use]
    pub fn wait_ran_out(&self, now_ms: u64) -> bool {
        matches!(self.wait, WaitRule::Until { ms } if now_ms >= ms)
    }

    /// What holds the order back from a new attempt at `now_ms` until a time passes: its
    /// retry's backoff ([`Self::retry_not_before_ms`]), or the wait its PLACE decider picked,
    /// which its open state keeps until the wait's `until_ms` (Engine F3, 25 Nov 20:4x).
    #[must_use]
    pub fn timed_hold(&self, now_ms: u64) -> Option<BlockedOn> {
        if let Some(ms) = self.retry_not_before_ms.filter(|ms| *ms > now_ms) {
            return Some(BlockedOn {
                machine: None,
                blocker: Blocker::RetryNotBefore { ms },
            });
        }
        let OrderState::Open { blocked, .. } = &self.state else {
            return None;
        };
        blocked
            .iter()
            .find(|on| {
                matches!(on.blocker, Blocker::DeciderWait { until_ms, .. } if until_ms > now_ms)
            })
            .cloned()
    }

    /// The attempt numbered `n`.
    #[must_use]
    pub fn attempt(&self, n: u16) -> Option<&OrderAttempt> {
        self.attempts.get(usize::from(n).checked_sub(1)?)
    }

    /// The last attempt.
    #[must_use]
    pub fn last_attempt(&self) -> Option<&OrderAttempt> {
        self.attempts.last()
    }

    /// Whether the order has an attempt that was made and has no end: it runs, or may still
    /// run on a machine that has not answered (I3). A running cap counts these.
    #[must_use]
    pub fn holds_live_attempt(&self) -> bool {
        self.last_attempt().is_some_and(|last| last.end.is_none())
    }

    /// The number the next attempt takes.
    #[must_use]
    pub fn next_attempt_number(&self) -> u16 {
        u16::try_from(self.attempts.len())
            .unwrap_or(u16::MAX)
            .saturating_add(1)
    }

    /// For a line unit, the claim key of attempt `n`: the unit key is the order id in hex
    /// (EM-18). `None` for an offer charge.
    #[must_use]
    pub fn claim_key(&self, n: u16) -> Option<ClaimKey> {
        match &self.charge {
            OrderCharge::Line { arm, rung, .. } => {
                Some(ClaimKey::of(*arm, *rung, &self.id.to_hex(), n))
            }
            OrderCharge::Offer { .. } => None,
        }
    }

    /// The key the running group of this order counts under for the RANK rule's second step:
    /// a line unit's arm, or an offer order's requester.
    #[must_use]
    pub fn family_key(&self) -> String {
        match (&self.charge, &self.ordered_by) {
            (OrderCharge::Line { arm, .. }, _) => format!("arm:{}", arm.to_hex()),
            (OrderCharge::Offer { .. }, OrderedBy::Agent { grant, .. }) => {
                format!("grant:{}", grant.to_hex())
            }
            (OrderCharge::Offer { .. }, OrderedBy::Owner { .. }) => "owner".to_owned(),
        }
    }
}
