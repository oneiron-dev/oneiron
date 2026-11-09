//! Authority for one proposed claim's review and settlement. A native
//! action Grant never supplies the holder's separate read capability.

use super::*;
use crate::memory::authorship::{
    CLAIM_REVIEW_GRANT_VERB, action_bound, is_root_owner, verify_live_actor,
};

#[derive(Clone, Copy)]
pub(super) enum ClaimSettler<'a> {
    Owner(&'a AuthenticatedOwner),
    Grant(&'a str),
}

pub(super) struct AuthorizedSettler {
    pub(super) actor: WriteActor,
    pub(super) owner_answer: Option<crate::consent::OwnerAuthoredWrite>,
    pub(super) grant_ref: Option<String>,
}

pub(super) fn named_grant(value: Option<&str>) -> MemoryResult<String> {
    let grant = value.ok_or_else(|| {
        MemoryError::bad_request("grant_ref names the holder's native claim-review Grant")
    })?;
    if grant.len() != 64 || !grant.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err(MemoryError::bad_request(
            "grant_ref is the native consent Grant's 64-hex digest",
        ));
    }
    Ok(grant.to_ascii_lowercase())
}

impl ClaimSettler<'_> {
    pub(super) const fn is_grant(self) -> bool {
        matches!(self, Self::Grant(_))
    }

    pub(super) fn authorize(
        self,
        memory: &Memory<'_>,
        txn: &heed::RoTxn<'_>,
        lane: &crate::claim::ScopedRead<'_>,
        id: EntityId,
        verb: &str,
    ) -> MemoryResult<AuthorizedSettler> {
        match self {
            Self::Owner(owner) => {
                let person = owner.revalidate_in_txn(memory.vault, txn)?;
                memory.require_settling_owner(person)?;
                Ok(AuthorizedSettler {
                    actor: WriteActor::new(person, EdgeActorClass::Human),
                    owner_answer: owner.owner_answer_in_txn(memory.vault, txn)?,
                    grant_ref: None,
                })
            }
            Self::Grant(grant_ref) => {
                let actor = WriteActor::new(memory.actor, memory.actor_class);
                verify_live_actor(memory.vault, txn, actor)?;
                match memory.presented_credential() {
                    Some(proof) => {
                        let claims = proof.claims();
                        if claims.holder_ref != memory.actor.to_hex()
                            || claims.actor_class.as_deref().unwrap_or("human")
                                != memory.actor_class.gate_actor_class()
                            || !memory.vault.capability_slip_is_live_in_txn(txn, proof)?
                        {
                            return Err(holder_refused());
                        }
                        let effective = memory.vault.current_view_scope_in_txn(txn, claims);
                        let verbs = match verb {
                            "vault.claims.review" => ["read", "core:read"],
                            "vault.claims.settle" => ["write", "core:write"],
                            _ => return Err(holder_refused()),
                        };
                        if !verbs
                            .iter()
                            .any(|verb| effective.verbs.contains(&(*verb).to_owned()))
                            || (verb == "vault.claims.settle"
                                && (!claims.records.is_empty() || !claims.channels.is_empty()))
                            || memory
                                .vault
                                .credential_read_key_in_txn(txn, proof, memory.actor, false)?
                                .is_none()
                        {
                            return Err(holder_refused());
                        }
                    }
                    None if memory.native_invocation() => {}
                    None => return Err(holder_refused()),
                }
                let required = action_bound(memory.vault, txn, actor, CLAIM_REVIEW_GRANT_VERB, id)?;
                let row = memory
                    .vault
                    .consent_grant_in_txn(txn, grant_ref)?
                    .ok_or_else(holder_refused)?;
                if !row.is_active()
                    || row.bypass.is_some()
                    || crate::consent::consent_grant_row_grant_ref(&row) != grant_ref
                    || !row.grant.bound().contains(&required)
                    || !is_root_owner(memory.vault, txn, row.owner_stamp.actor)?
                {
                    return Err(holder_refused());
                }
                let policy = lane.live_policy_manifest_in(txn)?;
                if !lane.is_ref_readable_with_policy_in(txn, &policy, &id)? {
                    return Err(MemoryError::not_found(
                        "no claim this caller may read has that ref",
                    ));
                }
                Ok(AuthorizedSettler {
                    actor: memory.write_actor(),
                    owner_answer: None,
                    grant_ref: Some(grant_ref.to_owned()),
                })
            }
        }
    }
}

fn holder_refused() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        "the caller's live native Grant must name this exact claim review action",
        &[
            "Use your own credential and an active ordinary claim-review Grant issued by a current root owner.",
        ],
    )
}
