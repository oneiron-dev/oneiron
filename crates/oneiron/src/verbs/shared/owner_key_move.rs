//! The owner-key move rows of a shared act (row HOSTED-OWNER-MOVE-TWO-PHASE):
//! `vault.shared.owner_key_move_plan` answers the plan a device of the
//! executor confirms, and `vault.shared.owner_key_move_sign` signs that plan
//! on the Owner's own device. The wire carries each byte field of the plan in
//! lowercase hex.
use super::{
    SharedActRequest, SharedOwnerKeyMoveBinding, SharedOwnerKeyMoveConfirm, SharedOwnerKeyMovePlan,
    SharedOwnerKeyMoveSignRequest, SharedOwnerKeyMoveSigner, person_id,
};
use crate::Vault;
use crate::authority::{
    ActAuthority, ActSurface, AuthorityKey, HostSlipIssuer, OwnerKeyMoveBinding, OwnerKeyMovePlan,
    OwnerKeyMoveSigner,
};
use crate::consent::AuthenticatedOwner;
use crate::memory::{MemoryError, MemoryResult};

/// `vault.shared.owner_key_move_plan`: the plan a device of `executor`, a
/// live Owner who may run the act now, confirms the act's owner-key move
/// with (row HOSTED-OWNER-MOVE-TWO-PHASE): its answer is the input of
/// `vault.shared.owner_key_move_sign` on that device. A frontier join the
/// plan needs is signed by `slips` (or this install's live host issuer) and
/// kept; nothing else is written.
pub fn plan_shared_owner_key_move(
    vault: &Vault,
    executor: &AuthenticatedOwner,
    slips: Option<&HostSlipIssuer>,
    input: SharedActRequest,
) -> MemoryResult<SharedOwnerKeyMovePlan> {
    let plan = vault.owner_key_move_plan(executor, &input.act_id, slips)?;
    Ok(owner_key_move_plan_wire(plan))
}

/// `vault.shared.owner_key_move_sign`: the owner key this install holds for
/// `owner` signs the plan's revokes, after the plan is checked against this
/// install's copy of the vault (row HOSTED-OWNER-MOVE-TWO-PHASE). It runs on
/// the Owner's own device: a host holds none of an Owner's keys, so there it
/// answers the refusal. `input.member` is the member the Owner confirmed on
/// the device, from its own copy; a plan of another member signs nothing.
/// It writes nothing; the answer goes to `vault.shared.execute` as it is.
pub fn sign_shared_owner_key_move(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: SharedOwnerKeyMoveSignRequest,
) -> MemoryResult<SharedOwnerKeyMoveConfirm> {
    let member = person_id("member", &input.member)?;
    let plan = owner_key_move_plan_from_wire(input.plan)?;
    let authority = ActAuthority::Owner(owner.clone(), ActSurface::ThisInstall);
    let rows = vault.sign_owner_key_move_as(&authority, &plan, member)?;
    Ok(SharedOwnerKeyMoveConfirm {
        owner_key_revokes: rows.iter().map(|row| oneiron_hex::encode(row)).collect(),
    })
}

/// `plan` as the wire carries it: byte fields in lowercase hex.
fn owner_key_move_plan_wire(plan: OwnerKeyMovePlan) -> SharedOwnerKeyMovePlan {
    fn hex_all(values: &[[u8; 32]]) -> Vec<String> {
        values
            .iter()
            .map(|value| oneiron_hex::encode(value))
            .collect()
    }
    SharedOwnerKeyMovePlan {
        authority_vault_id: oneiron_hex::encode(&plan.vault_id),
        member: plan.member.to_hex(),
        parents: hex_all(&plan.parents),
        revoked: plan.revoked.iter().map(owner_key_hex).collect(),
        revoked_bindings: plan
            .revoked_bindings
            .iter()
            .map(|binding| SharedOwnerKeyMoveBinding {
                authority_key: owner_key_hex(&binding.authority_key),
                epoch: binding.epoch,
            })
            .collect(),
        signers: plan
            .signers
            .iter()
            .map(|signer| SharedOwnerKeyMoveSigner {
                public_key: oneiron_hex::encode(&signer.public_key),
                seq: signer.seq,
            })
            .collect(),
        at: plan.at,
        act_id: plan.act_id,
    }
}

/// An owner key, or a binding's key, as a plan's wire names it: its key
/// bytes in lowercase hex, 64 digits for an Ed25519 key, 66 for a passkey's
/// compressed P-256 key (row WEB-PASSKEY-OWNER-KEY).
fn owner_key_hex(key: &AuthorityKey) -> String {
    match key {
        AuthorityKey::Ed25519(bytes) => oneiron_hex::encode(bytes),
        AuthorityKey::P256(bytes) => oneiron_hex::encode(bytes),
    }
}

/// The plan the wire `plan` carries; a field that is not its hex is a bad
/// request.
fn owner_key_move_plan_from_wire(plan: SharedOwnerKeyMovePlan) -> MemoryResult<OwnerKeyMovePlan> {
    fn bytes32(field: &str, text: &str) -> MemoryResult<[u8; 32]> {
        oneiron_hex::decode(text)
            .ok_or_else(|| MemoryError::bad_request(format!("{field} is not 64 lowercase hex")))
    }
    fn bytes32_all(field: &str, texts: &[String]) -> MemoryResult<Vec<[u8; 32]>> {
        texts.iter().map(|text| bytes32(field, text)).collect()
    }
    fn owner_key(field: &str, text: &str) -> MemoryResult<AuthorityKey> {
        if let Some(bytes) = oneiron_hex::decode::<32>(text) {
            return Ok(AuthorityKey::Ed25519(bytes));
        }
        oneiron_hex::decode::<33>(text)
            .map(|bytes| AuthorityKey::P256(bytes.to_vec()))
            .ok_or_else(|| {
                MemoryError::bad_request(format!("{field} is not 64 or 66 lowercase hex"))
            })
    }
    Ok(OwnerKeyMovePlan {
        vault_id: bytes32("plan.authority_vault_id", &plan.authority_vault_id)?,
        member: person_id("plan.member", &plan.member)?,
        parents: bytes32_all("plan.parents", &plan.parents)?,
        revoked: plan
            .revoked
            .iter()
            .map(|text| owner_key("plan.revoked", text))
            .collect::<MemoryResult<_>>()?,
        revoked_bindings: plan
            .revoked_bindings
            .iter()
            .map(|binding| {
                Ok(OwnerKeyMoveBinding {
                    authority_key: owner_key(
                        "plan.revoked_bindings.authority_key",
                        &binding.authority_key,
                    )?,
                    epoch: binding.epoch,
                })
            })
            .collect::<MemoryResult<_>>()?,
        signers: plan
            .signers
            .iter()
            .map(|signer| {
                Ok(OwnerKeyMoveSigner {
                    public_key: bytes32("plan.signers.public_key", &signer.public_key)?,
                    seq: signer.seq,
                })
            })
            .collect::<MemoryResult<_>>()?,
        at: plan.at,
        act_id: plan.act_id,
    })
}
