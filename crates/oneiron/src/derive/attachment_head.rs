//! Native's attachment-head rule over the extraction attempt's bound read.

use crate::EntityId;
use crate::claim::ClaimSource;
use crate::dreamer_consolidation::PromotionCandidate;
use crate::dreamer_consolidation::extraction_pack::BoundBranchRead;
use crate::error::{Error, Result};

/// Whether one verified candidate can attach to its matched head.
pub(super) enum AttachmentHead {
    Attach(EntityId),
    AlreadySaid,
    Refused,
    NoHead,
}

/// Applies native's equal-match rule and guards, without an unlisted-head read.
/// Every head must be held by `bound` and admit its exact prior write.
pub(super) fn attachment_head(
    bound: &BoundBranchRead,
    candidate: &PromotionCandidate,
    matches: &[(EntityId, bool)],
    meet: ClaimSource,
) -> Result<AttachmentHead> {
    use AttachmentHead::{AlreadySaid, Attach, NoHead, Refused};
    let mut attachment = None;
    if let [(id, true)] = matches {
        attachment = Some(*id);
    } else if matches.len() > 1 && meet != ClaimSource::Imported {
        let mut all_equal = true;
        for (id, equal) in matches {
            if !equal {
                all_equal = false;
                break;
            }
            let Some(head) = bound.prior(*id) else {
                return Ok(Refused);
            };
            match bound.observation_prior_provisional(head) {
                Ok(false) => {}
                Ok(true) => {
                    all_equal = false;
                    break;
                }
                Err(_) => return Ok(Refused),
            }
        }
        if all_equal {
            let (id, _) = matches[0];
            let Some(head) = bound.prior(id) else {
                return Ok(Refused);
            };
            let probe =
                match crate::dreamer_consolidation::candidate_probe_body(&candidate.candidate) {
                    Ok(probe) => probe,
                    Err(Error::Claim(_) | Error::InvalidClaimBody(_)) => return Ok(Refused),
                    Err(error) => return Err(error),
                };
            let named = BoundBranchRead::observation_named_facet(probe.scope.as_ref())
                .ok()
                .flatten();
            let same_scope = named == Some(probe.scope_facet)
                && probe.scope_facet == head.body.scope_facet
                && probe.scope_project == head.body.scope_project
                && crate::dreamer_promotion::scope_with_taint(probe.scope, meet)
                    == crate::dreamer_promotion::scope_with_taint(head.body.scope.clone(), meet);
            if same_scope {
                attachment = Some(id);
            }
        }
    }
    let Some(id) = attachment else {
        return Ok(NoHead);
    };
    let Some(head) = bound.prior(id) else {
        return Ok(Refused);
    };
    match bound.observation_prior_provisional(head) {
        Ok(true) if id != candidate.claim_id => return Ok(AlreadySaid),
        Ok(_) => {}
        Err(_) => return Ok(Refused),
    }
    if candidate.evidence_turn_refs.contains(&id) || bound.require_prior_write(id).is_err() {
        return Ok(Refused);
    }
    Ok(Attach(id))
}
