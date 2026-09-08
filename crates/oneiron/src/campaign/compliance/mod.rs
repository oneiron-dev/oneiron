//! CA-06's compliance pack: versioned, vault-resident legal rule rows and the
//! dispatch gate that enforces them.
//!
//! Three properties decide this module's shape.
//!
//! * **Law is data.** The seeded rule rows live in `compliance/seed_v1.json`,
//!   not in jurisdiction-specific `if` statements. Rust parses, validates,
//!   selects, and applies rows; it never spells a country's rule. Adding
//!   Ireland, retuning the verification-age dial, or taking a counsel-reviewed
//!   correction is a data revision, not a code change. The two machine checks a
//!   conditional exemption can demand (`ComplianceExemptionEvidence`) are
//!   mechanical primitives; which jurisdiction demands which is a pack row.
//! * **Evidence is hydrated, never presence-checked.** The evaluator accepts
//!   only `HydratedListProvenance` / `HydratedJpPublicationFacts`, both of
//!   which exist only after the referenced record was resolved from the vault,
//!   bound to this counterparty, and class-validated. A dangling reference is
//!   not weaker evidence, it is no evidence, and the strict path applies.
//! * **This is enforcement, not a new approval surface.** A blocking verdict
//!   maps to a hard gate deny in `gate.rs`. Nothing here asks a human to
//!   approve a compliant send, and an unknown jurisdiction is NOT an automatic
//!   deny — it routes to the pack's strictest seeded pole, where satisfying
//!   facts still allow.
//!
//! Storage mirrors the `gate` module's `PolicyPack`/`PolicyRule` carrier shape
//! and the `connector_key` module's propose-versus-stamp amendment posture.
//! Neither is reused: connector-charter storage stays connector-local, and this
//! module shares no storage or code with BK-06's `booking::anti_abuse`, which
//! imitates the row/amendment SHAPE only. Convergence onto one rule-row
//! substrate is a later integrator's concern.

mod amend;
mod codec;
mod evaluate;
mod hydrate;
mod pack_store;
mod rules;

pub use self::amend::{
    ComplianceAmendmentClass, ComplianceAmendmentOutcome, classify_compliance_amendment,
    compliance_amendment_notices, compliance_proposal_hash, ingest_published_compliance_update,
    propose_compliance_amendment, stamp_compliance_amendment,
};
pub use self::evaluate::{
    ComplianceBlockReason, ComplianceVerdict, DispatchComplianceFacts, HydratedJpPublicationFacts,
    HydratedListProvenance, evaluate_dispatch_compliance,
};
pub use self::pack_store::{
    embedded_seed_pack, load_active_compliance_pack, validate_compliance_pack,
};
pub use self::rules::{
    B2bExemption, CAMPAIGN_COMPLIANCE_META_KEY, CAMPAIGN_COMPLIANCE_PACK_ID,
    CAMPAIGN_COMPLIANCE_SEED_JSON, ComplianceExemptionEvidence, CompliancePack, ComplianceRuleKind,
    ComplianceRuleRow, ComplianceSource, ConditionalExemptionEvidence,
    PREDICATE_CRM_COMPLIANCE_EVIDENCE, PREDICATE_CRM_COMPLIANCE_JP_PUBLICATION,
    PREDICATE_CRM_COMPLIANCE_LIST_PROVENANCE, PREDICATE_CRM_COMPLIANCE_MESSAGE_ELEMENTS,
    UnknownJurisdictionDefault,
};

pub(crate) use self::hydrate::campaign_compliance_gate;

#[cfg(test)]
mod tests;

// The flat compliance.rs module used to provide these names to the sibling test
// module through `use super::*`: its own private crate/std import header, and
// every compliance-internal item the tests name bare. After the directory split
// the seam re-imports both so `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use self::{hydrate::*, rules::*};
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::claim::{ClaimBody, ClaimLifecycleStatus, ClaimSubject};
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::registry::ENTITY_TYPE_PERSON;
