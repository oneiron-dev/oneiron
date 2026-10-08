//! What the activation gate decides about a skill: the posture its bytes'
//! scan verdicts give an entry into `Active`, and the approval that entry
//! lands with. A board plugin section, a marketplace ask and a shared-skill
//! merge read the same posture; what else they read is the skill's content
//! or authority the row classes compare.
use super::{Decision, held_by_either};
use crate::claim::ClaimApprovalStatus;
use crate::registry::ENTITY_TYPE_SKILL;
use crate::skill::SkillContentHash;
use crate::skill_scan::ActivationPosture;
use crate::{EntityId, Result, Vault};
use std::collections::BTreeSet;

/// How the activation gate takes each skill either vault holds into `Active`
/// with the bytes a record of it carries.
/// `skill_scan::scan_gate_for_activation` folds the active verdicts that the
/// `claim_of` edges of those bytes' content anchor reach, under the live
/// dial, into a posture; on an entry into `Active`,
/// `skill_scan::escalate_activation_approval_in_txn` lands an `auto` record
/// `proposed` when that posture asks for the owner's tap. A restore puts a
/// skill into `Active` without passing the gate, so a restored skill may not
/// load where the live one does not when the live gate would hold its entry
/// for a tap. Bytes only a live record carries leave with it.
pub(super) struct SkillActivations;

/// What the gate makes of one skill's bytes in one vault.
pub(super) struct Activation {
    /// Whether the vault's record of the skill carries these bytes.
    carries: bool,
    /// Whether the record loads as canon (`skill::skill_loadable`).
    loads: bool,
    /// The approval the record's entry into `Active` with these bytes lands
    /// with, where the vault holds it.
    lands: Option<ClaimApprovalStatus>,
    posture: ActivationPosture,
}

impl Decision for SkillActivations {
    type Subject = (EntityId, [u8; 32]);
    type Answer = Activation;

    fn subjects(vaults: [&Vault; 2]) -> Result<BTreeSet<Self::Subject>> {
        let mut subjects = BTreeSet::new();
        for skill in held_by_either(vaults, ENTITY_TYPE_SKILL)? {
            for vault in vaults {
                // A record that does not decode carries no bytes the gate
                // reads.
                if let Ok(Some(record)) = vault.get_skill_record(&skill)
                    && let Some(bytes) = record.content_hash
                {
                    subjects.insert((skill, *bytes.as_bytes()));
                }
            }
        }
        Ok(subjects)
    }

    fn answers(
        vault: &Vault,
        subjects: &BTreeSet<Self::Subject>,
    ) -> Result<Vec<Option<Self::Answer>>> {
        let answer = |(skill, bytes): &Self::Subject| -> Result<Activation> {
            let bytes = SkillContentHash::from_bytes(*bytes);
            let record = vault.get_skill_record(skill)?;
            let posture = crate::skill_scan::scan_gate_for_activation(vault, bytes)?;
            let carries = record
                .as_ref()
                .is_some_and(|record| record.content_hash == Some(bytes));
            let loads = record.as_ref().is_some_and(crate::skill::skill_loadable);
            Ok(Activation {
                carries,
                loads,
                lands: record.map(|record| posture.approval_for(record.approval_status)),
                posture,
            })
        };
        Ok(subjects
            .iter()
            .map(|subject| answer(subject).ok())
            .collect())
    }

    fn loosens(live: &Activation, restored: &Activation) -> bool {
        restored.carries
            && (asks_less(live.posture, restored.posture)
                || (restored.loads
                    && !live.loads
                    && live.lands == Some(ClaimApprovalStatus::Proposed)))
    }
}

/// Whether `restored` asks less of an activation than `live`: no tap where
/// live asks for one, or one for a lesser risk.
fn asks_less(live: ActivationPosture, restored: ActivationPosture) -> bool {
    match (live, restored) {
        (
            ActivationPosture::ProposedRequired { risk: live },
            ActivationPosture::ProposedRequired { risk: restored },
        ) => restored < live,
        (ActivationPosture::ProposedRequired { .. }, ActivationPosture::AutoEligible) => true,
        (ActivationPosture::AutoEligible, _) => false,
    }
}
