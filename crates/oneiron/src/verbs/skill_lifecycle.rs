//! The owner's lifecycle door for a stored skill (FIX
//! [SKILL-HUB-PROMOTION-VERBS]): `vault.skills.lifecycle.set` moves one skill
//! through the ordinary skill update law, in the owner-checked write the
//! archive verb uses. The hub import-origin gate at the batch chokepoint
//! still refuses an Active flip of imported ancestry without its admission
//! proof, so a fork never launders an import.
use crate::consent::AuthenticatedOwner;
use crate::memory::{MemoryError, MemoryResult};
use crate::skill::SkillLifecycle;
use crate::{Error, TimeRange, Vault};

use super::HubSkillRequest;
use super::skills::{SkillLibraryLifecycle, SkillLibraryView, skill_library_get_as_owner};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::skill_lifecycle::SkillLifecycleSetRequest;

/// Moves `input.entity` to `input.lifecycle` in one write that revalidates
/// the owner, runs `validate_skill_update` (the lifecycle machine, the fork
/// law, the frozen Superseded revision) and lands the body through the batch
/// chokepoint every SKILL body converges on. Three moves keep their own
/// doors and are refused here: archiving (`vault.skills.archive`, which also
/// cancels running invocations), an archived skill's return
/// (`vault.skills.restore`, which rechecks its source evidence and repeats a
/// hub skill's admission), and supersession (an admitted successor and its
/// succession edge).
pub fn skill_lifecycle_set_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SkillLifecycleSetRequest,
) -> MemoryResult<SkillLibraryView> {
    let lifecycle = match input.lifecycle {
        SkillLibraryLifecycle::Candidate => SkillLifecycle::Candidate,
        SkillLibraryLifecycle::Active => SkillLifecycle::Active,
        SkillLibraryLifecycle::Stale => SkillLifecycle::Stale,
        SkillLibraryLifecycle::Archived => {
            return Err(MemoryError::bad_request(
                "archiving a skill is vault.skills.archive's act",
            ));
        }
        SkillLibraryLifecycle::Superseded => {
            return Err(MemoryError::bad_request(
                "supersession is the supersede door's act; a bare flip would orphan a frozen revision",
            ));
        }
    };
    let at = vault.now_recorded_at();
    vault.with_write_txn_grouped(|txn| {
        owner.revalidate_in_txn(vault, txn)?;
        if !crate::vault::live_entity_row_in_txn(&vault.store, txn, &input.entity)?.is_live() {
            return Err(Error::EntityNotFound);
        }
        let prior = vault.read_skill_record_in_txn(txn, &input.entity)?;
        if prior.lifecycle_status == SkillLifecycle::Quarantined {
            return Err(Error::InvalidClaimBody(
                "an archived skill returns through vault.skills.restore",
            ));
        }
        let mut updated = prior.clone();
        updated.lifecycle_status = lifecycle;
        crate::skill::validate_skill_update(&prior, &updated)?;
        vault.apply_skill_record_body(
            txn,
            &input.entity,
            TimeRange { start: at, end: at },
            at,
            crate::skill::encode_skill_record(&updated)?,
            false,
        )
    })?;
    skill_library_get_as_owner(
        vault,
        owner,
        &HubSkillRequest {
            entity: input.entity,
        },
    )
}
