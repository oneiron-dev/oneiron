//! The successor body for a live `campaign.member` head.

use rmpv::Value;

use super::codec::encode_campaign_member_value;
use super::types::CampaignMemberValue;
use crate::claim::ClaimBody;
use crate::entity_id::EntityId;

/// The body that replaces `old`: a clone whose membership value and transition
/// evidence alone change.
///
/// World, relationship, opaque scope, facet and project audience, approval,
/// source, confidence, valid time and session tag are all the predecessor's.
/// A suppression, a sender binding or a reply pause changes what the membership
/// says; it never changes who may read it, and it never approves a proposed
/// head as a side effect.
pub(in crate::campaign) fn member_replacement_body(
    old: &ClaimBody,
    value: &CampaignMemberValue,
    evidence_ref: EntityId,
) -> ClaimBody {
    let mut body = old.clone();
    body.value = encode_campaign_member_value(value);
    body.evidence = Some(Value::Array(vec![Value::from(evidence_ref.to_hex())]));
    body
}
