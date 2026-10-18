//! OF-606: the support delegation a customer's support slip carries, signed in
//! its claims beside `grant_ref` and `invitation_ref`.
//!
//! On our hosted cloud the operator root acts as nobody inside a customer's
//! vault (FIX 2222). The customer's owner instead mints a slip for our
//! support person or agent: a live, non-owner PERSON of their vault, bound to
//! that party's own key. Its delegation names why (purpose, ticket), who
//! approved it, when, and the wall-time deadline it ends at. That deadline is
//! judged on the store's nondecreasing recording clock, beside the slip's
//! ordinary authority-clock lifetime, so a vault that sleeps never stretches
//! a visit (DEC-0006, the delegation-clock note). Nothing here verifies or
//! admits a slip; `oneiron::authority` does.

use std::collections::BTreeSet;

use oneiron_contracts::error::Result;
use serde::{Deserialize, Serialize};

use super::invalid_authority;
use crate::federation::{Scope, ScopeAxis, SensitivityCeiling};

/// A support grant's lifetime when the owner names none: one hour (OF-606,
/// CALLS "support TTL").
pub const SUPPORT_GRANT_DEFAULT_TTL_SECS: u64 = 60 * 60;
/// The longest support grant an owner can mint: one day. More time is a
/// fresh owner mint; nothing renews one (OF-606, CALLS "support TTL").
pub const SUPPORT_GRANT_MAX_TTL_SECS: u64 = 24 * 60 * 60;
/// The longest purpose or ticket reference a delegation carries, in bytes.
pub const SUPPORT_DELEGATION_TEXT_MAX: usize = 256;

/// The classes a support slip may carry: reading, and the two write classes
/// the customer may select. A request that names no write class mints a
/// read-only slip (OF-606, CALLS "support bounds and never-list").
pub const SUPPORT_GRANTABLE_VERBS: [&str; 6] = [
    "read",
    "core:read",
    "propose",
    "core:propose",
    "write",
    "core:write",
];

/// What no support slip ever carries, whatever the request says: erase and
/// delete, keys and authority, recovery, policy widening, the catastrophe
/// floor and its bypass, export, outbound send and secrets, membership and
/// organization power. Matched as lowercase fragments of a verb.
const SUPPORT_NEVER_GRANTABLE: [&str; 20] = [
    "erase", "delete", "destroy", "key", "auth", "recover", "policy", "widen", "admin", "floor",
    "bypass", "export", "send", "outbound", "secret", "member", "org:", "inject", "lease", "owner",
];

/// The signed support delegation of one support slip (OF-606).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupportDelegation {
    /// Why the customer let support in, as the customer wrote it.
    pub purpose: String,
    /// The support ticket the visit serves, when there is one.
    pub ticket_ref: Option<String>,
    /// The owner PERSON (entity id hex) who approved the grant.
    pub owner_ref: String,
    /// The store recording time the owner minted it at (Unix seconds).
    pub approved_at: u64,
    /// The wall-time deadline (Unix seconds, recording clock): the slip
    /// stands only while recording time is before it, and ends at equality.
    pub wall_expires_at: u64,
}

impl SupportDelegation {
    /// The delegation's own shape: a purpose, a canonical owner ref, and a
    /// deadline after its approval by at most [`SUPPORT_GRANT_MAX_TTL_SECS`].
    pub fn validate(&self) -> Result<()> {
        let text_ok = |text: &str| {
            !text.trim().is_empty()
                && text.len() <= SUPPORT_DELEGATION_TEXT_MAX
                && !text.chars().any(char::is_control)
        };
        if !text_ok(&self.purpose)
            || self.ticket_ref.as_deref().is_some_and(|t| !text_ok(t))
            || !canonical_entity_hex(&self.owner_ref)
            || self.approved_at >= self.wall_expires_at
            || self.wall_expires_at - self.approved_at > SUPPORT_GRANT_MAX_TTL_SECS
        {
            return Err(invalid_authority());
        }
        Ok(())
    }
}

/// The one policy hook for what a support slip may be bounded to (OF-606
/// call 4). Every axis is explicit: no empty (bottom) axis, worlds named one
/// by one (never the vault top), a sensitivity ceiling, and verbs drawn from
/// [`SUPPORT_GRANTABLE_VERBS`] alone, none on the never-list. Records name
/// exact entities (canonical hex); no credential-door channel is ever
/// grantable, since channels are outbound effectors and secret doors.
///
/// # Errors
///
/// A static reason, which the owner door shows and the log's shape check
/// folds into its refusal.
pub fn support_scope_admissible(
    scope: &Scope,
    records: &BTreeSet<String>,
    channels: &BTreeSet<String>,
) -> std::result::Result<(), &'static str> {
    if !matches!(&scope.worlds, ScopeAxis::Some(worlds) if !worlds.is_empty()) {
        return Err("a support grant names its worlds one by one, never the whole vault");
    }
    if scope.facets.is_bottom() || scope.bands.is_bottom() || scope.audience.is_bottom() {
        return Err("a support grant leaves no bound empty");
    }
    if scope.sensitivity == SensitivityCeiling::Bottom {
        return Err("a support grant names a sensitivity ceiling");
    }
    let ScopeAxis::Some(verbs) = &scope.verbs else {
        return Err("a support grant names its classes one by one");
    };
    if verbs.is_empty() {
        return Err("a support grant names its classes one by one");
    }
    if verbs.iter().any(|verb| support_verb_never_grantable(verb)) {
        return Err(
            "erase, keys, authority, recovery, policy, the catastrophe floor, export, outbound send and secrets are never grantable to support",
        );
    }
    if verbs
        .iter()
        .any(|verb| !SUPPORT_GRANTABLE_VERBS.contains(&verb.as_str()))
    {
        return Err("a support grant carries read, and propose or write only when selected");
    }
    if !channels.is_empty() {
        return Err("no credential-door channel is grantable to support");
    }
    if records.iter().any(|record| !canonical_entity_hex(record)) {
        return Err("a support grant's records name exact entities by id");
    }
    Ok(())
}

/// Whether `verb` names something no support slip ever carries.
#[must_use]
pub fn support_verb_never_grantable(verb: &str) -> bool {
    let lower = verb.to_ascii_lowercase();
    crate::credential_door::names_a_floor(&lower)
        || SUPPORT_NEVER_GRANTABLE
            .iter()
            .any(|fragment| lower.contains(fragment))
}

fn canonical_entity_hex(value: &str) -> bool {
    oneiron_contracts::EntityId::from_hex(value).is_ok_and(|id| id.to_hex() == value)
}
