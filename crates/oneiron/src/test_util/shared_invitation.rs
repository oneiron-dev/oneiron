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

/// OF-063: scoped reads are default-deny, so a shared-vault writer needs an
/// explicit actor-bound `core:read` grant to name its own PERSON as a CLAIM
/// subject. Same shape as `conversation_dag::fixtures::grant_reads` (#9547):
/// a fixture-only test policy manifest folding beside the shipped default,
/// over `read_preset()`.
///
/// Call for writer members only, right after `accept_founding_invitation`.
/// Viewers and demoted/out-of-scope states keep no grant.
pub(crate) fn grant_founding_writer_reads(vault: &Vault, writer: EntityId) {
    let actor = crate::WriteActor::new(writer, crate::EdgeActorClass::Human);
    let policy = serde_json::json!({
        "schema_version": "1.2", "pack_id": "shared-fixture-read", "pack_version": "v1",
        "min_engine_version": env!("CARGO_PKG_VERSION"),
        "defaults": {}, "rules": [], "actor_ceilings": [],
        "scoped_grants": [{
            "actor_ref": writer.to_hex(),
            "effector": "core:read",
            "scope": crate::federation::scope_codec::read_preset(),
            "receipt_required": false,
        }],
    });
    crate::conversation_dag::test_support::put_test_policy_manifest(
        vault,
        actor,
        EntityId::now(),
        &policy,
    )
    .expect("the writer's fixture read grant");
}
