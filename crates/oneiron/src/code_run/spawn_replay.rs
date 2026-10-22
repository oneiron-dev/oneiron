//! The one comparison of a recorded bridge row's request with the request
//! its call makes again (FIX 7447), for every replay of a row: the replay
//! cursor, which never issues a call, and a resumed program's entry, which
//! issues live what no row answers.

use rmpv::Value;

use super::coordination_codec::SPAWN_INTENT_KEYS;
use super::types::SelfEffect;
use crate::Result;
use crate::batch::secret_scan::admitted_from;

/// How a recorded row's request meets the request its call makes now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReplayRequestMatch {
    /// The very request the row recorded: the row answers it. A request the
    /// side-row wall masked still matches the secrets it holds (OF-067).
    Hit,
    /// The same spawn asked for another project or other objectives (FIX
    /// 7447): a replay miss, never the row's answer. A live caller issues
    /// the call live through its ordinary gates; a replay-only one reports
    /// the mismatch.
    SpawnMiss,
    /// Any other request: the drift each caller answers as it did.
    Drift,
}

impl ReplayRequestMatch {
    /// Whether the row answers the call.
    pub(super) const fn is_hit(self) -> bool {
        matches!(self, Self::Hit)
    }
}

/// `stored`, the request a row of `effect` recorded, against `offered`, the
/// request its call makes now under the row's own bridge stamp. Pure: it
/// reads and writes nothing.
///
/// # Errors
///
/// A request the side-row wall cannot compare: unreadable.
pub(super) fn replay_request_match(
    effect: SelfEffect,
    stored: &Value,
    offered: &Value,
) -> Result<ReplayRequestMatch> {
    if stored == offered || admitted_from(stored, offered)? {
        return Ok(ReplayRequestMatch::Hit);
    }
    if effect == SelfEffect::AgentsSpawn {
        return spawn_match(stored, offered);
    }
    Ok(ReplayRequestMatch::Drift)
}

/// A spawn's request that is not its row's: a miss when the two differ only
/// in the project or the objectives asked for. Pack B (FIX 9180) recognizes
/// a row whose ask an erase took here, before the miss, as an arm of its own.
fn spawn_match(stored: &Value, offered: &Value) -> Result<ReplayRequestMatch> {
    let (Some(stored), Some(offered)) = (without_intent(stored), without_intent(offered)) else {
        return Ok(ReplayRequestMatch::Drift);
    };
    Ok(if stored == offered || admitted_from(&stored, &offered)? {
        ReplayRequestMatch::SpawnMiss
    } else {
        ReplayRequestMatch::Drift
    })
}

/// A spawn request without its project and objectives; `None` for a request
/// that is not a map.
fn without_intent(request: &Value) -> Option<Value> {
    let Value::Map(fields) = request else {
        return None;
    };
    Some(Value::Map(
        fields
            .iter()
            .filter(|(key, _)| {
                !key.as_str()
                    .is_some_and(|name| SPAWN_INTENT_KEYS.contains(&name))
            })
            .cloned()
            .collect(),
    ))
}
