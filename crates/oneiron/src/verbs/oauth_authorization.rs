//! The input and answer of `vault.oauth.authorization.answer` (FIX 4902), a host door: the
//! vault owner's answer to an outside app's OAuth sign-in request for this vault's `/mcp`, the
//! one-tap actions of the inbox ask the request sent him. A server runs it under the vault
//! owner's proof, with where his say-so reached it; an embedded handle runs it as its embedded
//! owner, on this install. An agent never answers a sign-in: no agent admits another.
//!
//! An allow admits the app as the owner's agent at the tier he gives (the one it asked for when
//! he names none), bound to one world when he names one: its own agent principal, its ceiling,
//! and an owner agent grant that `vault.consent.registry` lists with its one-tap revoke. The
//! authorize page then collects the code. A deny sends the app `access_denied`.
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::authority::{ActSurface, AgentTier};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::memory::MemoryResult;

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::oauth_authorization::{
    OAuthAuthorizationAnswer, OAuthAuthorizationAnswered,
};

/// `vault.oauth.authorization.answer` under the owner's proof, his acts recording `surface`.
pub fn answer_oauth_authorization_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    surface: ActSurface,
    input: OAuthAuthorizationAnswer,
) -> MemoryResult<OAuthAuthorizationAnswered> {
    let allowed = vault.answer_oauth_authorization(
        owner,
        surface,
        input.request_ref,
        input.allow,
        input.tier,
        input.world_ref,
        crate::unix_seconds_now(),
    )?;
    Ok(OAuthAuthorizationAnswered {
        request_ref: input.request_ref,
        allowed: allowed.is_some(),
        agent: allowed.map(|allowed| allowed.agent),
        grant_ref: allowed.map(|allowed| allowed.grant_ref),
        tier: allowed.map(|allowed| allowed.tier),
        world_ref: allowed.and_then(|allowed| allowed.world),
    })
}
