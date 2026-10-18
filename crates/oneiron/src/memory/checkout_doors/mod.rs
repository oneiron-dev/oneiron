//! Credential-bound CHECKOUT lease and result doors (ARCH-0068 RC1/RC2).
//! The lease ACT, TASK FACT and lifecycle receipt commit together. Presence is lossy,
//! through the host's EphemeralStore port; it is never authority or persisted custody.
mod operations;
mod types;
pub use types::*;

use super::{MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};
use crate::EntityId;
use crate::checkout::lease::*;

pub(crate) fn refusal(error: CheckoutError) -> MemoryError {
    match error {
        CheckoutError::Store(error) => error.into(),
        CheckoutError::Invalid(reason) => MemoryError::bad_request(reason),
        other => MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            format!("checkout refused: {other:?}"),
            &[],
        ),
    }
}

fn checkout_id(text: &str) -> MemoryResult<CheckoutId> {
    if text.len() != 32
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(MemoryError::bad_request(
            "checkout must be 32 lower-hex characters",
        ));
    }
    let id = EntityId::from_hex(text)?;
    CheckoutId::from_bytes(*id.as_bytes()).map_err(refusal)
}

fn fence(memory: &Memory<'_>, checkout: &str, epoch: u64) -> MemoryResult<CheckoutLeaseFence> {
    if epoch == 0 {
        return Err(MemoryError::bad_request("checkout epoch must be positive"));
    }
    Ok(CheckoutLeaseFence {
        checkout_id: checkout_id(checkout)?,
        epoch,
        holder_ref: memory.actor().to_hex(),
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn class(value: CheckoutClass) -> CheckoutTaskClass {
    match value {
        CheckoutClass::Edit => CheckoutTaskClass::Edit,
        CheckoutClass::Build => CheckoutTaskClass::Build,
        CheckoutClass::Verify => CheckoutTaskClass::Verify,
        CheckoutClass::Effect => CheckoutTaskClass::Effect,
    }
}

fn action(value: CheckoutAction) -> CheckoutSettlementDisposition {
    match value {
        CheckoutAction::Select => CheckoutSettlementDisposition::Select,
        CheckoutAction::Apply => CheckoutSettlementDisposition::Apply,
        CheckoutAction::Release => CheckoutSettlementDisposition::Release,
        CheckoutAction::Discard => CheckoutSettlementDisposition::Discard,
    }
}

fn pulse<L: CheckoutLiveness>(act: &CheckoutLeaseAct, live: &mut L, now: u64) -> MemoryResult<()> {
    live.publish(CheckoutLivenessPulse {
        checkout_id: act.checkout_id,
        epoch: act.epoch,
        holder_ref: act.holder_ref.clone(),
        observed_at: now,
    })
    .map_err(refusal)
}

fn view(
    act: CheckoutLeaseAct,
    now: u64,
    receipt: Option<String>,
) -> MemoryResult<CheckoutLeaseView> {
    Ok(CheckoutLeaseView {
        checkout: act.checkout_id.to_string(),
        task: act.task_ref,
        repo_ref: act.repo_ref.canonical(),
        holder: EntityId::from_hex(&act.holder_ref)?,
        epoch: act.epoch,
        task_class: match act.task_class {
            CheckoutTaskClass::Edit => CheckoutClass::Edit,
            CheckoutTaskClass::Build => CheckoutClass::Build,
            CheckoutTaskClass::Verify => CheckoutClass::Verify,
            CheckoutTaskClass::Effect => CheckoutClass::Effect,
        },
        state: match act.state {
            CheckoutLeaseState::Active => CheckoutState::Active,
            CheckoutLeaseState::Settling => CheckoutState::Settling,
            CheckoutLeaseState::Settled => CheckoutState::Settled,
            CheckoutLeaseState::Retained => CheckoutState::Retained,
        },
        claimed_at: act.claimed_at,
        expires_at: act.lease_expires_at,
        expired: act.lease_expires_at.is_some_and(|expiry| now >= expiry),
        ticket: format!("{}.{}", act.checkout_id, act.epoch),
        receipt,
    })
}

impl From<CheckoutError> for MemoryError {
    fn from(error: CheckoutError) -> Self {
        refusal(error)
    }
}
