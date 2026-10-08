//! What the activation gate decides about a skill: the posture its bytes'
//! scan verdicts give an entry into `Active`, and the approval that entry
//! lands with. A board plugin section, a marketplace ask and a shared-skill
//! merge read the same posture; what else they read is the skill's content
//! or authority the row classes compare. Beside it, the script code an
//! installed pack's name runs.
use super::{Decision, held_by_either};
use crate::claim::ClaimApprovalStatus;
use crate::registry::ENTITY_TYPE_SKILL;
use crate::skill::SkillContentHash;
use crate::skill_hub::pack_catalog::{PackAdapter, PackRuntimeRecipe};
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

/// Whether `restored` lets an activation in without the owner's tap where
/// `live` asks for one. The risk a tap is asked for is what the ask shows:
/// every risk past the dial asks the same tap (`approval_for`).
fn asks_less(live: ActivationPosture, restored: ActivationPosture) -> bool {
    matches!(
        (live, restored),
        (
            ActivationPosture::ProposedRequired { .. },
            ActivationPosture::AutoEligible
        )
    )
}

/// Which script code each installed pack name runs: the source and the
/// qualified runtime `Vault::installed_script_pack`, the preflight of every
/// script run and wake subscription, selects for the name from its `Active`
/// install receipt. An install under the name replaces that receipt, so a
/// restore takes the name back to code a later install replaced, with the
/// runtime it was qualified on then, without qualifying it again. A restored
/// name may not run a source or a runtime the live one does not; it may run
/// none where the live one runs one. Each script source a receipt in either
/// vault selects is asked about under that receipt's name, where both vaults
/// hold the source live: one only one vault holds returns or leaves with the
/// restore (RD-20).
pub(super) struct InstalledScriptPacks;

impl Decision for InstalledScriptPacks {
    type Subject = (String, EntityId);
    /// The runtime the name runs the source on; `None` where it runs no
    /// script, or another source.
    type Answer = Option<PackRuntimeRecipe>;

    fn subjects(vaults: [&Vault; 2]) -> Result<BTreeSet<Self::Subject>> {
        let mut selected = BTreeSet::new();
        for vault in vaults {
            for receipt in vault.installed_packs()? {
                if matches!(receipt.adapter, Some(PackAdapter::Script(_))) {
                    let source = EntityId::from_hex(&receipt.source_id)?;
                    selected.insert((receipt.pack_name, source));
                }
            }
        }
        let [live, restored] = vaults;
        let mut subjects = BTreeSet::new();
        for (name, source) in selected {
            if live.get_pack_source(&source)?.is_some()
                && restored.get_pack_source(&source)?.is_some()
            {
                subjects.insert((name, source));
            }
        }
        Ok(subjects)
    }

    fn answers(
        vault: &Vault,
        subjects: &BTreeSet<Self::Subject>,
    ) -> Result<Vec<Option<Self::Answer>>> {
        let answer = |(name, source): &Self::Subject| -> Result<Option<PackRuntimeRecipe>> {
            let (_, _, receipt) = vault.installed_script_pack(name)?;
            let selected = EntityId::from_hex(&receipt.source_id)? == *source;
            Ok(receipt.runtime.filter(|_| selected))
        };
        Ok(subjects
            .iter()
            .map(|subject| answer(subject).ok())
            .collect())
    }

    fn loosens(live: &Option<PackRuntimeRecipe>, restored: &Option<PackRuntimeRecipe>) -> bool {
        restored
            .as_ref()
            .is_some_and(|runtime| live.as_ref() != Some(runtime))
    }

    fn refusal() -> Option<Option<PackRuntimeRecipe>> {
        Some(None)
    }
}
