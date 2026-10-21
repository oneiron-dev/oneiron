//! Campaign membership joins for resident-authored graph judgment workflows.

use crate::campaign::claims::{
    CampaignMemberState, PREDICATE_CAMPAIGN_MEMBER, decode_campaign_member_value,
};
use crate::claim::{ClaimSubject, ScopedReadActorKey, claim_surfaceable};
use crate::llm::decision::questions::GraphQuestionInput;
use crate::{EntityId, Error, Result, Vault};

/// One lead times one message variant. The membership claim anchors the answer;
/// the lead, campaign, variant and selected recent signals are required sources.
/// Signal selection and lookback remain the resident skill's context recipe.
#[derive(Debug, Clone)]
pub struct CampaignJudgmentRow {
    pub membership: EntityId,
    pub variant: EntityId,
    pub signals: Vec<EntityId>,
}

/// Resolve explicit membership rows under the asker's access. No cohort is
/// copied into the campaign, no fit formula is installed, and no send is made.
/// A row's stage outcome can bind through the membership claim's ClaimOf edge
/// to its lead, using the existing linked-unit outcome binding.
///
/// None marks a missing, hidden, inactive or non-enrolled membership. Positions
/// are retained so one omitted row cannot shift a later variant onto a lead.
/// Every returned source is checked again when `run_graph_question` executes.
pub fn campaign_judgment_inputs(
    vault: &Vault,
    principal: EntityId,
    campaign: EntityId,
    rows: &[CampaignJudgmentRow],
) -> Result<Vec<Option<GraphQuestionInput>>> {
    if rows.len() > 4096 {
        return Err(Error::InvalidConfig(
            "too many campaign judgment rows".into(),
        ));
    }
    let key = ScopedReadActorKey::new(principal.to_hex())
        .ok_or(Error::InvariantViolation(
            "canonical campaign judgment principal",
        ))?
        .exempt_while_owner(principal);
    // FIX 7461: this locally built reader also reads under the principal's
    // own live owner authority once its admission and Grants refuse a row.
    let scoped = crate::llm::decision::questions::question_lane(vault, key);
    let ids = rows.iter().map(|row| row.membership).collect::<Vec<_>>();
    let memberships = scoped.get_entities_parts_with_receipt(&ids, None)?.value;
    rows.iter()
        .zip(memberships)
        .map(|(row, parts)| {
            let Some((kind, _, body)) = parts else {
                return Ok(None);
            };
            if kind != crate::registry::ENTITY_TYPE_CLAIM {
                return Ok(None);
            }
            let body = crate::claim::decode_claim_body(&body, true)?;
            if body.predicate != PREDICATE_CAMPAIGN_MEMBER || !claim_surfaceable(&body) {
                return Ok(None);
            }
            let value = decode_campaign_member_value(&body.value)?;
            if value.campaign != campaign || value.state != CampaignMemberState::Enrolled {
                return Ok(None);
            }
            let ClaimSubject::Entity(lead) = body.subject else {
                return Ok(None);
            };
            let mut evidence = Vec::new();
            for id in [lead, campaign, row.variant]
                .into_iter()
                .chain(row.signals.iter().copied())
            {
                if id != row.membership && !evidence.contains(&id) {
                    evidence.push(id);
                }
            }
            Ok(Some(GraphQuestionInput {
                unit: row.membership,
                evidence,
            }))
        })
        .collect()
}
