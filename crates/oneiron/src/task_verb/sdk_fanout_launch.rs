//! The fan-out launch doors (OF-393): `vault.fanout.launch` reads one held or
//! launched fan-out, `vault.fanout.resume` is the owner's ruling on a held
//! launch, `vault.fanout.resume_as` a live lead or board holder's ruling on
//! one bound to its project, and `vault.fanout.ack` the owner's answer to the
//! width check of a fan-out that already went out. A ruling names the plan
//! digest its approver saw, as lower hex. The rulings are host doors: a
//! server passes the owner proof its request carried (`*_as`), or the holder
//! its slip names; an embedded handle its own embedded owner, or its actor.
use serde::{Deserialize, Serialize};

use super::{ConsultFanOutChoice, FanoutCheckChoice, FanoutLaunchReceipt};
use crate::agent_dispatch::FanoutStatement;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::memory::{Memory, MemoryError, MemoryResult};

/// `vault.fanout.launch`'s input: the launch to read.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FanoutLaunchRequest {
    pub launch_ref: EntityId,
}

/// The owner's ruling on a held launch. A denial keeps the hold, visible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FanoutLaunchRuling {
    ApproveOnce,
    ApproveAndRemember,
    Deny,
}

/// `vault.fanout.resume`'s input: the held launch, the digest the owner
/// saw, the ruling, and the standing cap an approve-and-remember keeps.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FanoutResumeRequest {
    pub launch_ref: EntityId,
    pub plan_digest: String,
    pub ruling: FanoutLaunchRuling,
    #[serde(default)]
    pub remembered_cap: Option<u64>,
}

/// `vault.fanout.ack`'s input: the launch whose width check is answered,
/// the digest the owner saw, the answer, and the standing cap an
/// ack-and-remember keeps.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FanoutAckRequest {
    pub launch_ref: EntityId,
    pub plan_digest: String,
    pub answer: FanoutCheckChoice,
    #[serde(default)]
    pub remembered_cap: Option<u64>,
}

/// The durable hold of a launch that waits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FanoutLaunchHold {
    pub surface_ref: String,
    pub denied: bool,
}

/// What the launch doors answer: the launch as it stands, with the
/// statement frozen before anything launched.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FanoutLaunchView {
    pub launch_ref: EntityId,
    pub plan_digest: String,
    pub statement: FanoutStatement,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<FanoutLaunchHold>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_row_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub choice_receipt_ref: Option<String>,
    pub task_refs: Vec<EntityId>,
}

impl From<FanoutLaunchReceipt> for FanoutLaunchView {
    fn from(receipt: FanoutLaunchReceipt) -> Self {
        Self {
            launch_ref: receipt.launch_ref,
            plan_digest: bytes_to_hex_lower(&receipt.plan_digest),
            statement: receipt.statement,
            held: receipt.paused.map(|pause| FanoutLaunchHold {
                surface_ref: pause.surface_ref,
                denied: pause.denied,
            }),
            check_row_ref: receipt.check_row_ref,
            choice_receipt_ref: receipt.choice_receipt_ref,
            task_refs: receipt.task_refs,
        }
    }
}

/// `vault.fanout.launch`: one launch, for its own actor, the vault's owner or
/// a live lead or board holder of its project; anything else reads as none.
pub fn read_fanout_launch(
    memory: &Memory<'_>,
    input: FanoutLaunchRequest,
) -> MemoryResult<Option<FanoutLaunchView>> {
    Ok(memory
        .task_fanout_launch(input.launch_ref)?
        .map(FanoutLaunchView::from))
}

/// `vault.fanout.resume` as the vault's embedded owner.
pub fn resume_fanout_launch_embedded(
    memory: &Memory<'_>,
    input: FanoutResumeRequest,
) -> MemoryResult<FanoutLaunchView> {
    resume_fanout_launch_as(
        memory,
        &memory.embedded_owner("vault.fanout.resume")?,
        input,
    )
}

/// `vault.fanout.resume` under the owner's proof; the engine door
/// revalidates it in its own transaction.
pub fn resume_fanout_launch_as(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: FanoutResumeRequest,
) -> MemoryResult<FanoutLaunchView> {
    Ok(memory
        .resume_task_fanout(
            input.launch_ref,
            plan_digest(&input.plan_digest)?,
            launch_choice(input.ruling),
            owner,
            input.remembered_cap,
        )?
        .into())
}

/// `vault.fanout.resume_as` as the handle's own actor.
pub fn resume_fanout_launch_holder(
    memory: &Memory<'_>,
    input: FanoutResumeRequest,
) -> MemoryResult<FanoutLaunchView> {
    resume_fanout_launch_as_holder(
        memory,
        &crate::WriteActor::new(memory.actor(), memory.actor_class()),
        input,
    )
}

/// `vault.fanout.resume_as` as `holder`, a live holder of the launch's bound
/// lead or board role: approve once or deny. Only the owner remembers, so an
/// approve-and-remember or a cap is refused.
pub fn resume_fanout_launch_as_holder(
    memory: &Memory<'_>,
    holder: &crate::WriteActor,
    input: FanoutResumeRequest,
) -> MemoryResult<FanoutLaunchView> {
    Ok(memory
        .resume_task_fanout_as(
            input.launch_ref,
            plan_digest(&input.plan_digest)?,
            launch_choice(input.ruling),
            holder,
            input.remembered_cap,
        )?
        .into())
}

/// The engine's choice for a ruling.
const fn launch_choice(ruling: FanoutLaunchRuling) -> ConsultFanOutChoice {
    match ruling {
        FanoutLaunchRuling::ApproveOnce => ConsultFanOutChoice::ApproveOnce,
        FanoutLaunchRuling::ApproveAndRemember => ConsultFanOutChoice::ApproveAndRemember,
        FanoutLaunchRuling::Deny => ConsultFanOutChoice::Deny,
    }
}

/// `vault.fanout.ack` as the vault's embedded owner.
pub fn ack_fanout_check_embedded(
    memory: &Memory<'_>,
    input: FanoutAckRequest,
) -> MemoryResult<FanoutLaunchView> {
    ack_fanout_check_as(memory, &memory.embedded_owner("vault.fanout.ack")?, input)
}

/// `vault.fanout.ack` under the owner's proof; the engine door revalidates
/// it in its own transaction.
pub fn ack_fanout_check_as(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: FanoutAckRequest,
) -> MemoryResult<FanoutLaunchView> {
    Ok(memory
        .ack_task_fanout_check(
            input.launch_ref,
            plan_digest(&input.plan_digest)?,
            input.answer,
            owner,
            input.remembered_cap,
        )?
        .into())
}

/// Exactly 32 lowercase hex bytes.
fn plan_digest(hex: &str) -> MemoryResult<[u8; 32]> {
    let malformed = || MemoryError::bad_request("plan_digest must be 64 lowercase hex digits");
    if hex.len() != 64 {
        return Err(malformed());
    }
    let mut out = [0_u8; 32];
    for (slot, pair) in out.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        let high = nibble(pair[0]).ok_or_else(malformed)?;
        let low = nibble(pair[1]).ok_or_else(malformed)?;
        *slot = (high << 4) | low;
    }
    Ok(out)
}

const fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}
