//! The permitted body delta of a demotion materialization.

use rmpv::Value;

use super::binding_error;
use crate::EntityId;
use crate::batch::BatchOp;
use crate::claim::{ClaimBody, ClaimLifecycleStatus};
use crate::error::Result;
use crate::store::Store;

/// Rebuild the permitted body delta instead of trusting caller-supplied axes.
pub(super) fn demotion_body(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    prior: &ClaimBody,
    next: &ClaimBody,
    tail: &[BatchOp],
) -> Result<ClaimBody> {
    use crate::claim::{
        CLAIM_SCOPE_DEMOTION_RUNG_KEY, ClaimDemotionRung, ClaimSubject, claim_demotion_rung,
    };
    use crate::edge::{EdgeKind, validate_edge_weight};
    use crate::vault::{edge_kind_prefix, parse_edge_record};

    if prior.lifecycle != ClaimLifecycleStatus::Active {
        return Err(binding_error());
    }
    let before = claim_demotion_rung(prior)?;
    let after = claim_demotion_rung(next)?;
    let mut expected = prior.clone();
    let rung = match (before, after, tail) {
        (
            None | Some(ClaimDemotionRung::Decayed),
            Some(ClaimDemotionRung::Decayed),
            [
                BatchOp::SetEdgeWeight {
                    src,
                    kind: EdgeKind::ClaimOf,
                    tgt,
                    weight,
                },
            ],
        ) if src == id && prior.subject == ClaimSubject::Entity(*tgt) => {
            validate_edge_weight(*weight)?;
            let mut current = None;
            for entry in store
                .edges_out
                .prefix_iter(txn, &edge_kind_prefix(id, EdgeKind::ClaimOf))?
            {
                let (key, value) = entry?;
                let edge = parse_edge_record(&key, &value)?;
                if edge.target == *tgt && current.replace(edge.weight).is_some() {
                    return Err(binding_error());
                }
            }
            if *weight > current.ok_or(binding_error())? {
                return Err(binding_error());
            }
            "decayed"
        }
        (
            Some(ClaimDemotionRung::Decayed | ClaimDemotionRung::Weakened),
            Some(ClaimDemotionRung::Weakened),
            [],
        ) if next.confidence.is_finite()
            && (0.0..=1.0).contains(&next.confidence)
            && next.confidence <= prior.confidence =>
        {
            expected.confidence = next.confidence;
            "weakened"
        }
        (Some(ClaimDemotionRung::Weakened), Some(ClaimDemotionRung::Stale), []) => {
            expected.stale = true;
            "stale"
        }
        _ => return Err(binding_error()),
    };
    let mut scope = match expected.scope.take() {
        None => Vec::new(),
        Some(Value::Map(entries)) => entries,
        Some(_) => return Err(binding_error()),
    };
    scope.retain(|(key, _)| key.as_str() != Some(CLAIM_SCOPE_DEMOTION_RUNG_KEY));
    scope.push((
        Value::from(CLAIM_SCOPE_DEMOTION_RUNG_KEY),
        Value::from(rung),
    ));
    expected.scope = Some(Value::Map(scope));
    Ok(expected)
}
