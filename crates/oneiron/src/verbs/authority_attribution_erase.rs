//! The owner's erase of one subject's authority attribution on this vault.
//! The engine writer owns the erase and custody's retirement finisher; this
//! door exposes that act through the typed owner surface. The Owner may
//! apply an asker's approved check-in in the erase's own writer.

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::memory::{MemoryError, MemoryResult};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::authority_attribution_erase::{
    AuthorityAttributionEraseRequest, AuthorityAttributionErased,
};

/// `vault.authority.attribution.erase`: the owner's erase of one subject's
/// authority attribution. The owner's proof is revalidated in the erase's
/// own writer; the signed rows stay and their scaffold still verifies.
pub fn erase_authority_attribution_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: AuthorityAttributionEraseRequest,
) -> MemoryResult<AuthorityAttributionErased> {
    let applied = super::shared::check_in_ref(input.check_in_ref.as_deref())?.map(|id| {
        crate::check_in::AppliedCheckIn {
            id,
            verb: "vault.authority.attribution.erase",
            effect_digest: crate::check_in::authority_attribution_erase_effect_digest(
                &input.subject,
            ),
        }
    });
    vault
        .erase_authority_attribution_as(owner, &input.subject, applied.as_ref())
        .map_err(MemoryError::from)
}
