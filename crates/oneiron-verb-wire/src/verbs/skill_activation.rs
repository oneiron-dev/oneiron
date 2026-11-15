//! Wire types of the owner's held-out admission door for a hub skill (FIX
//! [SKILL-HUB-PROMOTION-VERBS]): `vault.skills.activation.admit`. `oneiron`
//! re-exports each item.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

use crate::skill_hub::admission::HubAdmissionReceipt;

/// `vault.skills.activation.admit`: the held-out ruling on a hub Candidate's
/// activation ask, the ask the owner's prepare route showed. The ask is
/// rebuilt from these fields and must carry the same digest.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillActivationAdmitRequest {
    /// The hub Candidate.
    pub entity: EntityId,
    /// The publisher admitted for the skill's hub.
    pub publisher: String,
    /// An active local skill whose attributed outcomes are the baseline.
    pub evidence_skill: EntityId,
    /// The ask's effect digest, as hex, that the prepare route showed.
    pub effect_digest: String,
}

/// The ruling. A Candidate that declares a capability waits for the owner's
/// answer on the approve route before any replay; every other one is scored
/// at once and lands Active only on a held-out win.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum SkillActivationAdmitReceipt {
    /// The ask widens the skill's permissions and the owner has not answered it.
    PendingConsent {
        entity: EntityId,
        effect_digest: String,
    },
    /// The held-out win: the skill is Active.
    Admitted {
        entity: EntityId,
        admission: HubAdmissionReceipt,
    },
    /// No held-out win: the skill stays a Candidate and this ask stays refused.
    Refused {
        entity: EntityId,
        admission: HubAdmissionReceipt,
    },
}
