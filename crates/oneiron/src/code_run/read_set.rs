//! Read-set witnesses a resident attempt's replay record can prove (FIX 7020).

use super::payload::decode_self_dispatch_outcome;
use super::replay::CodeRunReplayRecord;
use super::types::{SelfDispatchOutcome, SelfDurableWaitReason, SelfEffect};
use super::wait_rows::wait_rows;
use crate::EntityId;

/// The rows a resident attempt's tool answers and own replay/capsule reads
/// were served from, with its MemorySearch hit ids joined to the existing
/// verb-answer witness. `current_wait` is still parked and has no delivered
/// reply yet; every earlier durable wait must list its reply's source rows.
/// `None` when any answer, search or resumed wait lacks its row witness.
#[must_use]
pub fn resident_tool_answer_rows(
    record: &CodeRunReplayRecord,
    current_wait: Option<EntityId>,
) -> Option<Vec<EntityId>> {
    let mut rows = record.agent_verb_rows()?;
    // The run id names the replay record and capsules read back under it.
    rows.push(record.run_id);
    for call in &record.bridge_calls {
        match decode_self_dispatch_outcome(&call.outcome).ok()? {
            SelfDispatchOutcome::DurableWait(wait) => {
                let current_peer_wait = Some(wait.wait_id) == current_wait
                    && wait.reason == SelfDurableWaitReason::PeerResult;
                if !current_peer_wait && wait_rows(&call.outcome).is_none() {
                    return None;
                }
            }
            SelfDispatchOutcome::MemorySearch(search)
                if call.effect == SelfEffect::MemorySearch =>
            {
                rows.extend(search.results.into_iter().map(|hit| hit.id));
            }
            _ => {}
        }
    }
    rows.sort_unstable();
    rows.dedup();
    Some(rows)
}
