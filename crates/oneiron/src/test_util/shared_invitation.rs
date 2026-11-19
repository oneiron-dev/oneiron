//! Founding-member acceptance for shared-vault fixtures: creating a shared
//! vault grants only its creator and invites every other founding member, who
//! holds no grant until it accepts its invitation.

use crate::entity_id::EntityId;
use crate::federation::FederationGrantRole;
use crate::vault::Vault;

/// Accepts `member`'s founding invitation at `role` in shared vault
/// `vault_id` through the invitee's own door, and returns the grant refs the
/// acceptance wrote.
pub(crate) fn accept_founding_invitation(
    vault: &Vault,
    vault_id: u64,
    member: EntityId,
    role: FederationGrantRole,
) -> Vec<String> {
    let proof = vault
        .authenticate_owner(
            member,
            &member.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )
        .expect("the invitee's person proof");
    let invitation = vault
        .shared_invitations(&proof, vault_id)
        .expect("the invitee's invitations")
        .into_iter()
        .find(|open| open.founding && open.role == role)
        .expect("the founding invitation");
    vault
        .accept_shared_invitation(&proof, vault_id, &invitation.id)
        .expect("the founding member accepts")
        .grants
}
