//! Repeated untouched approvals compile into reviewable affirmative evidence.

use rmpv::Value;
use std::collections::BTreeMap;

use super::emission::{cluster_handle, emit_preference_value};
use super::feedback::principal_decisions;
use super::model::{Bucket, ClusterKey, MinedOutcome, MinerRun};
use super::target::CompilationTarget;
use crate::Vault;
use crate::claim::preference_evidence_in_force;
use crate::error::{Error, Result};

pub(super) fn mine_untouched_approvals(
    vault: &Vault,
    run: &MinerRun,
    now: u64,
    k: u32,
) -> Result<Vec<MinedOutcome>> {
    let mut buckets: BTreeMap<ClusterKey, Bucket> = BTreeMap::new();
    let mut reviewed = BTreeMap::new();
    for row in principal_decisions(vault)? {
        if row.outcome != "approved" || !preference_evidence_in_force(row.at, now) {
            continue;
        }
        let Some(claim) = row.claim else {
            continue;
        };
        let Some(body) = vault.get_claim(&claim)? else {
            continue;
        };
        if !crate::claim::claim_surfaceable(&body) {
            continue;
        }
        reviewed.insert(row.fingerprint.clone(), (row.predicate, row.reviewed_value));
        let key = ClusterKey {
            principal: Some(row.principal),
            target: CompilationTarget::Fallback,
            scope: row.scope,
            actor: row.actor,
            from: String::new(),
            to: row.fingerprint,
        };
        // A gate receipt has no pack manifest. Do not fabricate a skill win.
        buckets
            .entry(key)
            .or_default()
            .observe(&row.receipt, None, row.at);
    }
    let mut outcomes = Vec::new();
    for (key, bucket) in buckets {
        let cluster = bucket.into_cluster(key);
        if cluster.count < k {
            outcomes.push(MinedOutcome::BelowThreshold);
            continue;
        }
        let mut domain = blake3::Hasher::new();
        domain.update(b"oneiron.preference.untouched.v1");
        domain.update(&cluster_handle(&cluster));
        let handle = *domain.finalize().as_bytes();
        let (predicate, original) = reviewed.get(&cluster.to).ok_or(Error::InvariantViolation(
            "approval bucket lost reviewed content",
        ))?;
        let value = Value::Map(vec![
            (Value::from("text"), Value::from(cluster.to.as_str())),
            (Value::from("outcome"), Value::from("untouched")),
            (
                Value::from("reviewed_predicate"),
                Value::from(predicate.as_str()),
            ),
            (
                Value::from("reviewed_value"),
                original.clone().unwrap_or(Value::Nil),
            ),
            (
                Value::from("receipts"),
                super::emission::receipt_citations(&cluster),
            ),
        ]);
        if let Some(id) = emit_preference_value(
            vault,
            run,
            &cluster,
            &handle,
            now,
            "preference.affirmed",
            value,
        )? {
            outcomes.push(MinedOutcome::UntouchedApprovalWin(id));
        }
    }
    Ok(outcomes)
}
