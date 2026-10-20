//! The Dreamer's night step on the owner's say (FIX 6903): a Timer
//! `host.wake` asks for what a Timer wake asks for, beneath one root it
//! returns, every job it queues carrying one typed request id as its run.
//! There is no second scheduler: the resident deadline watch runs the work,
//! and the root's settlement read reports it.

use crate::dreamer_runner::{DreamerRunnerStore, EnqueueDreamerAttemptOutcome};
use crate::error::Result;
use crate::runtime_hooks::InvocationId;

/// One night step's request id: the 16 bytes of the logical invocation that
/// asked for it, so a replay of that invocation names the same request. Its
/// wire form is exactly 32 lowercase hex digits, and every job the request
/// queued carries that form as its run id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, schemars::JsonSchema)]
pub struct NightStepRequestId(#[schemars(with = "String")] [u8; 16]);

impl NightStepRequestId {
    /// The request `invocation` makes: its own bytes.
    #[must_use]
    pub const fn from_invocation(invocation: InvocationId) -> Self {
        Self(invocation.0)
    }

    /// 32 lowercase hex digits.
    #[must_use]
    pub fn to_hex(self) -> String {
        crate::entity_id::bytes_to_hex_lower(&self.0)
    }

    /// Parses [`Self::to_hex`]: exactly 32 lowercase hex digits, `None` for
    /// anything else.
    #[must_use]
    pub fn parse_hex(text: &str) -> Option<Self> {
        if text.len() != 32 {
            return None;
        }
        let mut bytes = [0_u8; 16];
        for (byte, pair) in bytes.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
            *byte = (lower_hex_nibble(pair[0])? << 4) | lower_hex_nibble(pair[1])?;
        }
        Some(Self(bytes))
    }
}

const fn lower_hex_nibble(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

impl serde::Serialize for NightStepRequestId {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> serde::Deserialize<'de> for NightStepRequestId {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let text = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::parse_hex(&text).ok_or_else(|| {
            serde::de::Error::custom("a night-step request id is 32 lowercase hex digits")
        })
    }
}

/// A Timer `host.wake` in its caller's write: the night step. Its
/// `dreamer.timer.plan` is found or queued FIRST, parentless, as the one root
/// it returns; the plan's own spending is planned under it as a Timer wake
/// plans it. Then every maintenance lane a Timer wake asks for is asked, in
/// the Timer order, beneath that plan. Every job carries `request_id` as its
/// run. A plan that already stands (a replay of the invocation) plans nothing
/// again, and the lanes are still asked beneath it, as a Timer wake asks them
/// each time; a lane row another request still holds pending stays where it
/// stands. The outcome is the plan's.
pub(crate) fn request_night_step_in_txn(
    store: &DreamerRunnerStore<'_>,
    txn: &mut heed::RwTxn<'_>,
    dedupe_key: Option<String>,
    request_id: NightStepRequestId,
    now: u64,
) -> Result<EnqueueDreamerAttemptOutcome> {
    let run_id = request_id.to_hex();
    let plan = super::nightly::enqueue_timer_plan_in_txn(
        store,
        txn,
        None,
        dedupe_key.clone(),
        Some(run_id.clone()),
        now,
    )?;
    let root = match &plan {
        EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status) => status.attempt.id,
    };
    super::scheduling::request_timer_maintenance_in_txn(
        store,
        txn,
        Some(root),
        dedupe_key.as_deref(),
        Some(run_id.as_str()),
        now,
    )?;
    Ok(plan)
}
