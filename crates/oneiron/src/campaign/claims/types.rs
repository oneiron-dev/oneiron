//! Cohort claim values are defined below the pack.

pub use crate::write_envelope::cohort_claims::{
    BounceKind, CAMPAIGN_PACK_CLAIM_PREDICATES, CampaignMemberChannel, CampaignMemberDerivation,
    CampaignMemberState, CampaignMemberValue, ClaimClassDescriptorRow, CommBounceValue,
    CommDoNotContactValue, CommJurisdictionValue, CrmFitValue, CrmFitVerdict, CrmStageValue,
    DO_NOT_CONTACT_SCOPE_ALL, EvidenceBasis, PREDICATE_CAMPAIGN_MEMBER, PREDICATE_COMM_BOUNCE,
    PREDICATE_COMM_DO_NOT_CONTACT, PREDICATE_COMM_JURISDICTION, PREDICATE_CRM_FIT,
    PREDICATE_CRM_STAGE, StageEvidenceClass, StageKey, claim_class_descriptors,
    is_campaign_pack_claim_predicate,
};
