//! Skill forks through the one fork law (`fork_skill_record_in_txn`): the
//! owner's, and a caller's own within its live write Grant (FIX 8167).
use crate::authority::VerifiedSlip;
use crate::consent::AuthenticatedOwner;
use crate::error::ClaimError;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::{EntityId, Error, TimeRange, Vault, WriteActor};

use super::sdk::HubSkillRequest;
use super::sdk_skills::{
    SkillLibraryForkRequest, SkillLibraryView, skill_library_get_as_owner, skill_library_view,
};

/// The verbs one of which a caller's slip carries for its write Grant to
/// admit a fork it makes as itself (FIX 8167).
const FORK_WRITE_VERBS: [&str; 2] = ["write", "core:write"];

pub fn skill_library_fork_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SkillLibraryForkRequest,
) -> MemoryResult<SkillLibraryView> {
    let entity = input.entity.unwrap_or_else(EntityId::now);
    let at = vault.now_recorded_at();
    vault.with_write_txn_grouped(|txn| {
        owner.revalidate_in_txn(vault, txn)?;
        vault.fork_skill_record_in_txn(
            txn,
            &input.parent,
            &entity,
            &input.skill_id,
            TimeRange { start: at, end: at },
            at,
        )
    })?;
    skill_library_get_as_owner(vault, owner, &HubSkillRequest { entity })
}

/// [`skill_library_fork_as_owner`] for the caller `memory` serves, on its own
/// verified `slip` (FIX 8167): a person, or an agent within its write Grant,
/// forks a skill it reads. The source must be readable under the caller's
/// own key, and in the fork's own write transaction the slip must still be
/// live, name the caller, carry a write verb over every record and channel,
/// and the caller's write binding must verify. The fork is the owner's fork
/// exactly: the source's governance tier, role and call, as a candidate. No
/// permission widens here; approving one stays the owner's.
pub fn skill_library_fork_by_caller(
    memory: &Memory<'_>,
    slip: &VerifiedSlip,
    input: &SkillLibraryForkRequest,
) -> MemoryResult<SkillLibraryView> {
    if memory.get_entity(&input.parent.to_hex())?.value.is_none() {
        return Err(MemoryError::not_found(
            "the skill to fork is absent or withheld",
        ));
    }
    let vault = memory.vault();
    let writer = WriteActor::new(memory.actor(), memory.actor_class());
    let entity = input.entity.unwrap_or_else(EntityId::now);
    let at = vault.now_recorded_at();
    vault.with_write_txn_grouped(|txn| {
        let claims = slip.claims();
        let granted = claims.invitation_ref.is_none()
            && FORK_WRITE_VERBS.iter().any(|verb| slip.allows_verb(verb));
        if claims.holder_ref != writer.entity_ref().to_hex()
            || !claims.records.is_empty()
            || !claims.channels.is_empty()
            || !granted
            || !vault.capability_slip_is_live_in_txn(txn, slip)?
        {
            return Err(Error::Claim(ClaimError::ActorLacksClaimAuthority {
                reason: "the caller's own live write Grant does not carry this fork",
            }));
        }
        vault.verify_write_actor_in_txn(txn, &writer)?;
        vault.fork_skill_record_in_txn(
            txn,
            &input.parent,
            &entity,
            &input.skill_id,
            TimeRange { start: at, end: at },
            at,
        )
    })?;
    skill_library_view(vault, &HubSkillRequest { entity })
}
