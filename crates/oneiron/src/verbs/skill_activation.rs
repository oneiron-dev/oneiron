//! The owner's held-out admission door for a hub skill (FIX
//! [SKILL-HUB-PROMOTION-VERBS]). The owner's prepare route shows the ask, and
//! the approve route records the owner's answer on a permission widening;
//! this door runs the host's held-out scorer on the ask the owner was shown.
use crate::consent::AuthenticatedOwner;
use crate::memory::{MemoryError, MemoryResult};
use crate::skill_hub::HubAdmissionDisposition;
use crate::skill_optimize::HeldOutReplayNotes;
use crate::{TimeRange, Vault};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::skill_activation::{
    SkillActivationAdmitReceipt, SkillActivationAdmitRequest,
};

/// Rebuilds the activation ask of `input.entity` from its first hub source,
/// the admitted publisher and the evidence baseline, as the prepare route
/// builds it, and admits it with `scorer` when its digest is the one shown.
/// The engine reads the owner's answer and the refusal history itself: no
/// caller's consent or score enters here.
pub fn skill_activation_admit_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SkillActivationAdmitRequest,
    scorer: &dyn HeldOutReplayNotes,
) -> MemoryResult<SkillActivationAdmitReceipt> {
    owner.revalidate(vault)?;
    let source = vault
        .skill_hub_sources(&input.entity)?
        .into_iter()
        .next()
        .ok_or_else(|| MemoryError::bad_request("the skill has no hub source"))?;
    let publisher = vault.admit_skill_publisher(owner, &input.publisher, source.hub_id)?;
    let ask = vault.prepare_marketplace_activation(
        input.entity,
        &source,
        &publisher,
        input.evidence_skill,
    )?;
    let digest = ask.effect_digest().to_hex();
    if digest != input.effect_digest {
        return Err(MemoryError::bad_request(
            "the activation ask moved; prepare it again",
        ));
    }
    let at = vault.now_recorded_at();
    let disposition =
        vault.admit_marketplace_skill(&ask, scorer, TimeRange { start: at, end: at }, at)?;
    let entity = input.entity;
    Ok(match disposition {
        HubAdmissionDisposition::PendingConsent => SkillActivationAdmitReceipt::PendingConsent {
            entity,
            effect_digest: digest,
        },
        HubAdmissionDisposition::Ruled(receipt) if receipt.accepted => {
            SkillActivationAdmitReceipt::Admitted {
                entity,
                admission: *receipt,
            }
        }
        HubAdmissionDisposition::Ruled(receipt) => SkillActivationAdmitReceipt::Refused {
            entity,
            admission: *receipt,
        },
    })
}
