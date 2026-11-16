//! The owner's ingress door for a shared-skill merge offer (FIX
//! [SKILL-HUB-PROMOTION-VERBS]). The offer stages an untrusted Candidate; the
//! owner's merge route rules on it with the useful-upstream question, then
//! the held-out replay.
use base64::Engine as _;

use crate::consent::AuthenticatedOwner;
use crate::memory::{MemoryError, MemoryResult};
use crate::{TimeRange, Vault};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::skill_merge::{SkillMergeOfferRequest, SkillMergeOffered};

/// Stages `input`'s package bytes as a Candidate revision of `input.base`
/// (`Vault::submit_shared_skill_delta`). The bytes are re-derived from their
/// files, so no envelope claim of the sender's is kept; the submitter and the
/// sender's fork are stored as source assertions only.
pub fn skill_merge_offer_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SkillMergeOfferRequest,
) -> MemoryResult<SkillMergeOffered> {
    owner.revalidate(vault)?;
    let submitted = base64::engine::general_purpose::STANDARD
        .decode(&input.package_base64)
        .map_err(|_| MemoryError::bad_request("package_base64 is not standard base64"))?;
    let at = vault.now_recorded_at();
    let candidate = vault.submit_shared_skill_delta(
        &input.base,
        &submitted,
        input.lane,
        &input.submitted_by,
        &input.submitted_fork,
        TimeRange { start: at, end: at },
        at,
    )?;
    let delta = vault
        .shared_skill_delta(&candidate)?
        .ok_or_else(|| MemoryError::not_found("the staged offer was closed before it was read"))?;
    Ok(SkillMergeOffered { candidate, delta })
}
