//! Moved from `crates/oneiron/src/skill/helper.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::skill::call::frozen::amend::CallableAmendOutcome;
pub use crate::skill::call::frozen::amend::CallableAmendReceipt;
pub use crate::skill::call::frozen::amend::CallableAmendRequest;
use oneiron_authority::claim_history_handoff::ScopedRead;
use oneiron_base::error::ArtifactError;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_base::registry::ENTITY_TYPE_SKILL;
use oneiron_contracts::claim::ClaimApprovalStatus;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::temporal::TimeRange;
use oneiron_store::write_envelope::WriteActor;
use oneiron_store::write_envelope::skill_record::lifecycle::SkillLifecycle;
use oneiron_store::write_envelope::skill_record::record::SkillRecord;
use oneiron_store::write_envelope::skill_record::role::SkillCallContract;
use oneiron_store::write_envelope::skill_record::role::SkillRole;
use oneiron_store::write_envelope::skill_record::skill_loadable;
use oneiron_store::write_envelope::skill_source::HubFile;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value as JsonValue;

/// One loadable callable helper as an agent sees it.
#[derive(Debug, Clone, PartialEq)]
pub struct CallableCard {
    pub skill: EntityId,
    pub skill_id: String,
    pub version: String,
    pub desc: String,
    pub call: SkillCallContract,
}

/// A callable card as the SDK returns it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CallableCardView {
    /// The skill entity id, hex.
    pub skill: String,
    pub skill_id: String,
    pub version: String,
    pub desc: String,
    /// The entry file the call runs.
    pub reference: String,
    pub arguments: JsonValue,
    pub returns: JsonValue,
}

impl From<CallableCard> for CallableCardView {
    fn from(card: CallableCard) -> Self {
        Self {
            skill: card.skill.to_hex(),
            skill_id: card.skill_id,
            version: card.version,
            desc: card.desc,
            reference: card.call.reference,
            arguments: card.call.arguments,
            returns: card.call.returns,
        }
    }
}

/// One source file of a saved skill: `SKILL.md`, or a script it calls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillSourceFile {
    pub path: String,
    /// UTF-8 file text.
    pub content: String,
}

/// `self.skills.save`: an agent saves a skill it wrote, `SKILL.md` and
/// scripts together. A callable helper declares `role: callable` and its
/// `call` contract in the frontmatter. A new skill lands Candidate +
/// Proposed; nothing here activates it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillSaveRequest {
    /// The skill entity to revise, hex; absent mints a new skill.
    #[serde(default)]
    pub id: Option<String>,
    pub files: Vec<SkillSourceFile>,
    /// The version the caller last read, for an update.
    #[serde(default)]
    pub expected_version: Option<String>,
}

/// `self.skills.fork`: an agent forks a skill under its own identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillForkRequest {
    /// The parent skill entity, hex.
    pub parent: String,
    /// The fork's entity id, hex; absent mints one.
    #[serde(default)]
    pub id: Option<String>,
    /// The fork's own skill identity.
    pub skill_id: String,
}
