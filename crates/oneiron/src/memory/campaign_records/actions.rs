//! Typed campaign enrollment, earned evidence and immediate unsubscribe.

use crate::write_envelope::cohort_claims::ladder::{PromotionMode, StageLadderDefinition};
use crate::write_envelope::cohort_claims::{EvidenceBasis, StageEvidenceClass, StageKey};
use serde::{Deserialize, Serialize};

#[doc(hidden)]
use oneiron_verb_wire::memory::campaign_records::actions::automatic;
#[doc(hidden)]
pub use oneiron_verb_wire::memory::campaign_records::actions::{
    CampaignActionProvenance, CampaignEnrollRequest, CampaignEnrollmentReceipt,
    CampaignEnrollmentState, CampaignMemberChannelSpec, CampaignStageEvidence,
    CampaignStageEvidenceOutcome, CampaignStageEvidenceReceipt, CampaignStageEvidenceRequest,
    CampaignUnsubscribeReceipt, CampaignUnsubscribeRequest,
};
