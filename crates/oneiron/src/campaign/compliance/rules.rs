//! Pure dispatch compliance rules defined beside the gate.

pub use crate::gate::dispatch_compliance::rules::CAMPAIGN_COMPLIANCE_PACK_ID;
pub use crate::gate::dispatch_compliance::rules::CAMPAIGN_COMPLIANCE_SEED_JSON;
pub use crate::gate::dispatch_compliance::rules::PREDICATE_CRM_COMPLIANCE_EVIDENCE;
pub use crate::gate::dispatch_compliance::rules::PREDICATE_CRM_COMPLIANCE_LIST_PROVENANCE;
pub use crate::gate::dispatch_compliance::rules::PREDICATE_CRM_COMPLIANCE_JP_PUBLICATION;
pub use crate::gate::dispatch_compliance::rules::PREDICATE_CRM_COMPLIANCE_MESSAGE_ELEMENTS;
pub use crate::gate::dispatch_compliance::rules::PREDICATE_CRM_COMPLIANCE_CONSENT;
pub(super) use crate::gate::dispatch_compliance::rules::JURISDICTION_NONE;
pub(super) use crate::gate::dispatch_compliance::rules::CHANNEL_WILDCARD;
pub(super) use crate::gate::dispatch_compliance::rules::PROPOSAL_HASH_DOMAIN;
pub(super) use crate::gate::dispatch_compliance::rules::CONFIDENCE_MILLIS_SCALE;
pub use crate::gate::dispatch_compliance::rules::ComplianceRuleKind;
pub use crate::gate::dispatch_compliance::rules::B2bExemption;
pub use crate::gate::dispatch_compliance::rules::ComplianceSource;
pub use crate::gate::dispatch_compliance::rules::ComplianceRuleRow;
pub use crate::gate::dispatch_compliance::rules::UnknownJurisdictionDefault;
pub use crate::gate::dispatch_compliance::rules::ComplianceExemptionEvidence;
pub use crate::gate::dispatch_compliance::rules::ConditionalExemptionEvidence;
pub use crate::gate::dispatch_compliance::rules::CompliancePack;
