//! The owner's mint or revoke of an agent's Grant as a signed owner act (FIX
//! 5628, Engine 10-20 00:5x), and its wire codec.
//!
//! The owner grants a named agent an explicit verb list, or revokes one such
//! Grant, from any surface where he is authenticated as the owner. The
//! install that served him, a live machine of the vault in any role, signs
//! the record with its install key; the record carries his act
//! ([`OwnerAct`], kind `grant_mint` or `grant_revoke`, target the Grant) and
//! the exact change: the member, scope and expiry of a mint, the Grant alone
//! for a revoke. The scope rides the six-axis codec a slip's claims ride
//! (`slip_wire`), one codec in the log. A mint that gives the agent repo
//! bounds (FIX 6867) carries them under one more key, `repo_bounds`, in the
//! codec the Grant body uses; a mint without them and every revoke keep the
//! seven-key form. The FEDERATION_GRANT row is
//! the state; this record is the signed account of his will, a main-log
//! entry every machine the owner admits folds.
//!
//! Its `seen` is zero for both kinds ([`AGENT_GRANT_ACT_SEEN`]): a mint names
//! a fresh Grant nobody acted on, and an owner's revoke always lands, never
//! refused as stale. Only the owner's own say-so makes either: no Grant line
//! names them, and no ask answers them.

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::repo_scope::{decode_repo_bounds_value, repo_bounds_value};
use crate::federation::{RepoAccessBounds, Scope};

use super::*;

pub const OP_KIND_AGENT_GRANT_ACT: &str = "agent_grant_act";
const AGENT_GRANT_ACT_KEYS: [&str; 7] = [
    OP_KEY_KIND,
    OP_KEY_ACT,
    "machine",
    "grant",
    "member",
    "scope",
    "expires_at",
];
/// The mint form that carries repo bounds: the seven keys and `repo_bounds`.
const AGENT_GRANT_ACT_REPO_KEYS: [&str; 8] = [
    OP_KEY_KIND,
    OP_KEY_ACT,
    "machine",
    "grant",
    "member",
    "scope",
    "expires_at",
    KEY_REPO_BOUNDS,
];
const KEY_REPO_BOUNDS: &str = "repo_bounds";

/// The policy hook of CALLS "FIX 5628 grant act revision": the `seen` of
/// every agent Grant act. No per-Grant revision exists: a mint names a fresh
/// id, and an owner's revoke always lands.
pub const AGENT_GRANT_ACT_SEEN: [u8; 32] = [0; 32];

/// What one agent Grant act changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentGrantChange {
    /// The owner grants `member`, a live agent principal of the vault, the
    /// six-axis `scope` exactly as he gave it, until `expires_at`, or until
    /// he revokes it when `None`; with `repo_bounds`, the one repo, refs and
    /// read and edit globs he gave it besides (FIX 6867).
    Mint {
        member: EntityId,
        scope: Scope,
        expires_at: Option<u64>,
        repo_bounds: Option<RepoAccessBounds>,
    },
    /// The owner revokes the Grant.
    Revoke,
}

impl AgentGrantChange {
    /// The owner act kind that carries this change.
    #[must_use]
    pub fn act_kind(&self) -> OwnerActKind {
        match self {
            Self::Mint { .. } => OwnerActKind::GrantMint,
            Self::Revoke => OwnerActKind::GrantRevoke,
        }
    }
}

/// One owner mint or revoke of an agent's Grant, signed by the install key
/// of `machine`, a live machine of the vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentGrantActRecord {
    /// The owner's act: who decided and from which surface. Its kind is
    /// `grant_mint` or `grant_revoke`, as `change` is, and its target
    /// `grant`.
    pub act: OwnerAct,
    /// The carrier: the machine whose install key signed the record.
    pub machine: EntityId,
    /// The FEDERATION_GRANT row the act mints or revokes.
    pub grant: EntityId,
    /// The exact change.
    pub change: AgentGrantChange,
}

impl AgentGrantActRecord {
    pub fn validate(&self) -> Result<()> {
        self.act
            .validate_carried(self.change.act_kind(), self.grant)?;
        // The owner's own say-so alone: an agent never mints or revokes a
        // Grant, and no ask answers it.
        if self.act.by != ActBy::Owner
            || self.act.answer.is_some()
            || self.act.seen != AGENT_GRANT_ACT_SEEN
        {
            return Err(invalid_authority());
        }
        Ok(())
    }
}

pub(super) fn agent_grant_act_value(record: &AgentGrantActRecord) -> Value {
    let (member, scope, expires_at, repo_bounds) = match &record.change {
        AgentGrantChange::Mint {
            member,
            scope,
            expires_at,
            repo_bounds,
        } => (
            Value::from(member.to_hex()),
            super::slip_wire::scope_value(scope),
            expires_at.map_or(Value::Nil, Value::from),
            repo_bounds.as_ref(),
        ),
        AgentGrantChange::Revoke => (Value::Nil, Value::Nil, Value::Nil, None),
    };
    let mut entries = vec![
        (
            Value::from(OP_KEY_KIND),
            Value::from(OP_KIND_AGENT_GRANT_ACT),
        ),
        (
            Value::from(OP_KEY_ACT),
            super::owner_act::owner_act_value(&record.act),
        ),
        (Value::from("machine"), Value::from(record.machine.to_hex())),
        (Value::from("grant"), Value::from(record.grant.to_hex())),
        (Value::from("member"), member),
        (Value::from("scope"), scope),
        (Value::from("expires_at"), expires_at),
    ];
    if let Some(bounds) = repo_bounds {
        entries.push((Value::from(KEY_REPO_BOUNDS), repo_bounds_value(bounds)));
    }
    Value::Map(entries)
}

/// The act's kind names the change: a mint carries its member and scope (its
/// expiry nil for a Grant durable until revoked), a revoke none of the three.
/// Repo bounds ride a mint only, under their own key, and only when given.
/// The envelope's canonical re-encode then pins every value's form.
pub(super) fn decode_agent_grant_act(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    let repo_bounds = entries
        .iter()
        .find_map(|(key, value)| (key.as_str() == Some(KEY_REPO_BOUNDS)).then_some(value));
    if repo_bounds.is_some() {
        validate_keys(entries, &AGENT_GRANT_ACT_REPO_KEYS)?;
    } else {
        validate_keys(entries, &AGENT_GRANT_ACT_KEYS)?;
    }
    let act = super::owner_act::decode_owner_act(required(entries, OP_KEY_ACT)?)?;
    let member = required(entries, "member")?;
    let scope = required(entries, "scope")?;
    let expires_at = required(entries, "expires_at")?;
    let change = match act.act {
        OwnerActKind::GrantMint => AgentGrantChange::Mint {
            member: decode_canonical_id(member)?,
            scope: super::slip_wire::decode_scope(scope)?,
            expires_at: match expires_at {
                Value::Nil => None,
                value => Some(value.as_u64().ok_or_else(invalid_authority)?),
            },
            repo_bounds: repo_bounds
                .map(|value| decode_repo_bounds_value(value).ok_or_else(invalid_authority))
                .transpose()?,
        },
        OwnerActKind::GrantRevoke
            if member.is_nil()
                && scope.is_nil()
                && expires_at.is_nil()
                && repo_bounds.is_none() =>
        {
            AgentGrantChange::Revoke
        }
        _ => return Err(invalid_authority()),
    };
    Ok(AuthorityOp::AgentGrantAct(AgentGrantActRecord {
        act,
        machine: decode_canonical_id(required(entries, "machine")?)?,
        grant: decode_canonical_id(required(entries, "grant")?)?,
        change,
    }))
}
