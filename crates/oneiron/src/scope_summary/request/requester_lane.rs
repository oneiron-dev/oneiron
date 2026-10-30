//! FIX 2194 (OF-506): a queued summary keeps the read lane its requester
//! declared it under. A declaration admitted under a narrowed credential
//! carries that lane frozen ([`crate::claim::FrozenReadLane`]); each landing
//! rebuilds the requester's actor-level reply lane and narrows it by the
//! frozen one, so a header's reply is checked inside the narrowing the
//! declaration was admitted in, and inside nothing once its credential is no
//! longer live. A lane that read as its requester's own adds nothing to the
//! declaration, which stays the one every other door declares. A narrowed
//! lane must read every source its summary plans, judged in the plan's own
//! snapshot (FIX 11829): a requester summarizes only what it reads.

use rmpv::Value;

use super::super::codec::invalid;
use super::super::derivation;
use super::{
    ScopeSummaryPlan, ScopeSummaryQueued, ScopeSummaryRequest, ScopeSummaryTarget,
    enqueue_with_lineage_in_txn, plan_in_txn,
};
use crate::Vault;
use crate::claim::{ClaimReadStatus, FrozenReadLane, ScopedRead};
use crate::conversation_dag::{ScopePath, ScopeSelector};
use crate::error::Result;

/// The declaration key a narrowed requester's frozen lane rides under.
const REQUESTER_LANE_KEY: &str = "requester_lane";
/// The purpose a NOTE set's summary takes unless its caller names another
/// (FIX 5757): never a session recap.
const NOTE_SET_PURPOSE: &str = "note_summary";

/// The purpose a declaration of `target` takes when its caller names none.
pub(super) fn default_purpose(target: &ScopeSummaryTarget) -> &'static str {
    match target {
        ScopeSummaryTarget::Scope {
            scope:
                ScopeSelector {
                    path: ScopePath::SubSession(_),
                    ..
                },
            ..
        } => "sub_agent_merge_artifact",
        ScopeSummaryTarget::Sources { scope: None, .. } => NOTE_SET_PURPOSE,
        ScopeSummaryTarget::Arc { .. } => super::super::arc::ARC_PURPOSE,
        _ => "session_recap",
    }
}

impl Vault {
    /// [`Self::request_scope_summary`], or [`Self::request_scope_summary_for`]
    /// with `purpose`, declared under `lane`, the requester's own live read
    /// lane at its door: a narrowed lane rides the declaration frozen, every
    /// landing's reply lane is narrowed by it, and it must read every source
    /// the plan names.
    ///
    /// # Errors
    /// As the request it stands for, [`FrozenReadLane::freeze`]'s refusal of
    /// a lane whose bound has no frozen form, and a narrowed lane's refusal
    /// of a planned source it does not read.
    pub fn request_scope_summary_in_lane(
        &self,
        request: &ScopeSummaryRequest,
        purpose: Option<&str>,
        lane: &ScopedRead<'_>,
    ) -> Result<ScopeSummaryQueued> {
        let frozen = lane.freeze()?;
        if frozen.is_principal() {
            return match purpose {
                Some(purpose) => self.request_scope_summary_for(request, purpose),
                None => self.request_scope_summary(request),
            };
        }
        let frozen = lane_value(&frozen)?;
        // The lane's grant clock settles before the write opens, so its
        // sources are judged in the plan's own snapshot.
        lane.persist_grant_clock()?;
        let queued = self.with_write_txn_grouped(|txn| {
            let purpose = purpose.unwrap_or_else(|| default_purpose(&request.target));
            let previous = derivation::current_in_txn(self, txn, request, purpose)?;
            let Value::Map(mut fields) = derivation::declaration(request, purpose, previous) else {
                return Err(invalid("summary request must be a map"));
            };
            fields.push((Value::from(REQUESTER_LANE_KEY), frozen));
            let input = Value::Map(fields);
            let plan = plan_in_txn(self, txn, &input)?;
            require_sources_in_lane(lane, txn, &plan)?;
            let now = self.store.clock.now_recorded_at();
            let queued = enqueue_with_lineage_in_txn(self, txn, input, None, None, now)?;
            crate::skill_attribution::note_summary_request_in_txn(&self.store, txn, queued.attempt);
            Ok(queued)
        })?;
        self.store.notify_attempt_observers();
        Ok(queued)
    }
}

/// Refuses a plan naming a source `lane` does not read, judged in `txn`, the
/// plan's own snapshot (FIX 11829).
///
/// # Errors
/// A planned source the lane does not read, and a store, fold or clock
/// failure judging one.
fn require_sources_in_lane(
    lane: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    plan: &ScopeSummaryPlan,
) -> Result<()> {
    let policy = lane.live_policy_manifest_in(txn)?;
    for source in &plan.sources {
        if !lane.is_ref_readable_with_policy_in(txn, &policy, source)? {
            return Err(invalid("summary source outside the requester's read lane"));
        }
    }
    Ok(())
}

/// `lane`, the requester's actor-level reply lane for `plan`, narrowed by
/// the lane its declaration froze; unchanged for a declaration that froze
/// none.
///
/// # Errors
/// A declaration whose frozen lane does not decode, or a store, fold or
/// clock failure judging its credential.
pub(super) fn narrowed_reply_lane<'m>(
    vault: &'m Vault,
    plan: &ScopeSummaryPlan,
    lane: Option<ScopedRead<'m>>,
) -> Result<Option<ScopedRead<'m>>> {
    let Some(lane) = lane else {
        return Ok(None);
    };
    let frozen = declared_lane(&derivation::decode(&plan.input)?)?;
    if frozen.is_principal() {
        return Ok(Some(lane));
    }
    let key = frozen.narrow(vault, lane.actor_key().clone())?;
    Ok(Some(
        vault
            .scoped_read(key)
            .with_claim_status(ClaimReadStatus::Recorded),
    ))
}

/// `frozen` as a declaration value: its named MessagePack form.
fn lane_value(frozen: &FrozenReadLane) -> Result<Value> {
    let bytes = rmp_serde::to_vec_named(frozen)
        .map_err(|_| invalid("summary requester lane did not encode"))?;
    rmpv::decode::read_value(&mut bytes.as_slice())
        .map_err(|_| invalid("summary requester lane did not encode"))
}

/// The lane a declaration froze; its requester's own when it froze none.
fn declared_lane(input: &Value) -> Result<FrozenReadLane> {
    let Value::Map(fields) = input else {
        return Err(invalid("summary request must be a map"));
    };
    let Some((_, value)) = fields
        .iter()
        .find(|(key, _)| key.as_str() == Some(REQUESTER_LANE_KEY))
    else {
        return Ok(FrozenReadLane::principal());
    };
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value)
        .map_err(|_| invalid("summary requester lane invalid"))?;
    rmp_serde::from_slice(&bytes).map_err(|_| invalid("summary requester lane invalid"))
}
