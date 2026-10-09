//! The permitted body delta of a demotion materialization.

use rmpv::Value;

use super::binding_error;
use crate::EntityId;
use crate::batch::BatchOp;
use crate::claim::{ClaimBody, ClaimLifecycleStatus, ClaimSuccession};
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
    use crate::claim::{ClaimDemotionRung, ClaimSubject, claim_demotion_rung};
    use crate::edge::{EdgeKind, validate_edge_weight};

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
            for entry in crate::ports::EdgeStoreRead::port_edges(
                store,
                txn,
                id,
                crate::ports::EdgeDirection::Out,
                Some(EdgeKind::ClaimOf),
                None,
            )? {
                let edge = entry?;
                if edge.target == *tgt && current.replace(edge.weight).is_some() {
                    return Err(binding_error());
                }
            }
            if *weight > current.ok_or(binding_error())? {
                return Err(binding_error());
            }
            "decayed"
        }
        (Some(ClaimDemotionRung::Weakened), Some(ClaimDemotionRung::Stale), []) => {
            expected.stale = true;
            "stale"
        }
        _ => return Err(binding_error()),
    };
    stamp_rung(&mut expected, rung)?;
    Ok(expected)
}

/// The only body a successor may carry: its active predecessor's, with the
/// one delta its succession permits. A weakening lowers confidence and stamps
/// `weakened`; a fork moves the facet stamp. Neither rewrites the predecessor
/// (ARCH-0003 change policy; ARCH-0055 r9, "fork, never restamp").
pub(super) fn successor_body(prior: &ClaimBody, succession: ClaimSuccession) -> Result<ClaimBody> {
    use crate::claim::{ClaimDemotionRung, claim_demotion_rung};

    if prior.lifecycle != ClaimLifecycleStatus::Active {
        return Err(binding_error());
    }
    let mut next = prior.clone();
    match succession {
        ClaimSuccession::Weakening { confidence } => {
            if !matches!(
                claim_demotion_rung(prior)?,
                Some(ClaimDemotionRung::Decayed | ClaimDemotionRung::Weakened)
            ) || !confidence.is_finite()
                || !(0.0..=1.0).contains(&confidence)
                || confidence > prior.confidence
            {
                return Err(binding_error());
            }
            next.confidence = confidence;
            stamp_rung(&mut next, "weakened")?;
        }
        ClaimSuccession::Fork { facet } => {
            if facet == prior.scope_facet {
                return Err(binding_error());
            }
            next.scope_facet = facet;
        }
    }
    Ok(next)
}

fn stamp_rung(body: &mut ClaimBody, rung: &'static str) -> Result<()> {
    use crate::claim::CLAIM_SCOPE_DEMOTION_RUNG_KEY;

    let mut scope = match body.scope.take() {
        None => Vec::new(),
        Some(Value::Map(entries)) => entries,
        Some(_) => return Err(binding_error()),
    };
    scope.retain(|(key, _)| key.as_str() != Some(CLAIM_SCOPE_DEMOTION_RUNG_KEY));
    scope.push((
        Value::from(CLAIM_SCOPE_DEMOTION_RUNG_KEY),
        Value::from(rung),
    ));
    body.scope = Some(Value::Map(scope));
    Ok(())
}
