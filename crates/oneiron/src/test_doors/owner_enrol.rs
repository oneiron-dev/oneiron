//! Doors for `tests/owner_enrol.rs` (OWNER-ENROL): the binding of an
//! Owner's own enrolled owner key, written by hand under the host root.

use crate::authority::{ACTOR_CLASS_HUMAN, AuthorityKey, AuthorityOp, HostSlipIssuer};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::vault::Vault;

/// Binds the enrolled owner key `public_key` to `person` as `human`, signed
/// by the host root `issuer`, at the first epoch: the binding an owner key
/// enrolment has to give an Owner whom no live binding names.
///
/// # Errors
/// The authority log's.
pub fn bind_owner_key(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    public_key: [u8; 32],
    person: EntityId,
) -> Result<()> {
    vault.log_host_op_for_test(
        issuer,
        AuthorityOp::BindActor {
            authority_key: AuthorityKey::Ed25519(public_key),
            actor_ref: person,
            actor_class: ACTOR_CLASS_HUMAN.into(),
            epoch: 1,
        },
    )
}
