//! MCP connector actor types: credentials, scopes, records, and resolution.

use super::surface::MCP_STREAM_CONNECTION_PREFIX;
use oneiron::context_board::{StreamConnectionId, SubscriptionScope};
use oneiron::{EdgeActorClass, EntityId, WriteActor};
use std::collections::BTreeSet;
use std::fmt;
use std::fmt::Write as _;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct McpCredentialHashKey(pub(super) [u8; 32]);

impl McpCredentialHashKey {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for McpCredentialHashKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("McpCredentialHashKey(<redacted>)")
    }
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct McpCredentialFingerprint(pub(super) [u8; 32]);

impl McpCredentialFingerprint {
    /// The process-local STREAM connection this credential owns.
    ///
    /// Derived from the FINGERPRINT and nothing else: no tool argument, header,
    /// or actor field can name another connector's stream, and the credential
    /// itself never appears in the id.
    pub(super) fn stream_connection(self) -> StreamConnectionId {
        let mut id = String::with_capacity(MCP_STREAM_CONNECTION_PREFIX.len() + 64);
        id.push_str(MCP_STREAM_CONNECTION_PREFIX);
        for byte in self.0 {
            let _ = write!(id, "{byte:02x}");
        }
        StreamConnectionId(id)
    }
}

impl fmt::Debug for McpCredentialFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("McpCredentialFingerprint(<redacted>)")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpConnectorScope {
    pub world_ref: Option<EntityId>,
    pub facet_ref: Option<EntityId>,
}

impl McpConnectorScope {
    #[must_use]
    pub const fn vault_wide() -> Self {
        Self {
            world_ref: None,
            facet_ref: None,
        }
    }

    #[must_use]
    pub const fn scoped(world_ref: Option<EntityId>, facet_ref: Option<EntityId>) -> Self {
        Self {
            world_ref,
            facet_ref,
        }
    }

    /// True when this credential was NARROWED to a world or a facet.
    #[must_use]
    pub const fn is_narrow(&self) -> bool {
        self.world_ref.is_some() || self.facet_ref.is_some()
    }

    /// The STREAM subscription ceiling this scope admits.
    ///
    /// A vault-wide credential may reach every category. A NARROWED credential
    /// gets the ARCH-0067 default lane only — my tasks, my children, consults
    /// to me — so `SubscriptionScope::ALL` can never be attached to a connector
    /// that was never granted the whole vault. The engine's own
    /// `BoardStreamRegistry::subscribe` refuses anything outside this set, so
    /// this is the enforced ceiling and not a label.
    #[must_use]
    pub fn subscription_ceiling(&self) -> BTreeSet<SubscriptionScope> {
        if self.is_narrow() {
            [
                SubscriptionScope::MyTasks,
                SubscriptionScope::MyChildren,
                SubscriptionScope::ConsultsToMe,
            ]
            .into_iter()
            .collect()
        } else {
            SubscriptionScope::ALL.into_iter().collect()
        }
    }
}

/// One board snapshot's identity: an epoch, and the STATE it is the epoch of.
///
/// The epoch is a state fence, not a timer. It advances only when the rendered
/// board state changes, so a clock that moves — forward or backward — cannot
/// stale a fresh frame or hide a same-second mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct McpBoardSnapshot {
    pub epoch: u64,
    pub state_hash: [u8; 32],
}

/// Hashes one rendered board's STATE: its scope label and its rows, in order.
#[must_use]
pub fn mcp_board_state_hash(scope_label: &str, rows: &[String]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron.mcp.board-state.v1");
    hasher.update(&(scope_label.len() as u64).to_be_bytes());
    hasher.update(scope_label.as_bytes());
    hasher.update(&(rows.len() as u64).to_be_bytes());
    for row in rows {
        hasher.update(&(row.len() as u64).to_be_bytes());
        hasher.update(row.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpConnectorActorRecord {
    pub(super) actor_ref: EntityId,
    pub(super) actor_class: EdgeActorClass,
    pub(super) scope: McpConnectorScope,
    /// The registered bound-verb ceiling (ARCH-0028 `bound_write_verbs`).
    ///
    /// `None` is "every tool the endpoint this call arrived on registered".
    /// `Some` is a strict subset fixed at REGISTRATION: no header, argument, or
    /// caller echo can widen it at call time.
    pub(super) bound_verbs: Option<BTreeSet<&'static str>>,
    pub(super) expires_at: Option<u64>,
    pub(super) revoked_at: Option<u64>,
}

impl McpConnectorActorRecord {
    #[must_use]
    pub const fn new(
        actor_ref: EntityId,
        actor_class: EdgeActorClass,
        scope: McpConnectorScope,
    ) -> Self {
        Self {
            actor_ref,
            actor_class,
            scope,
            bound_verbs: None,
            expires_at: None,
            revoked_at: None,
        }
    }

    /// Narrows this credential to an explicit set of registered tool names.
    #[must_use]
    pub fn with_bound_verbs(mut self, verbs: impl IntoIterator<Item = &'static str>) -> Self {
        self.bound_verbs = Some(verbs.into_iter().collect());
        self
    }

    #[must_use]
    pub const fn with_expiry(mut self, expires_at: u64) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    #[must_use]
    pub const fn with_revoked_at(mut self, revoked_at: u64) -> Self {
        self.revoked_at = Some(revoked_at);
        self
    }

    #[must_use]
    pub const fn gate_actor_class(&self) -> &'static str {
        self.actor_class.gate_actor_class()
    }

    #[must_use]
    pub fn gate_actor_ref(&self) -> String {
        self.actor_ref.to_hex()
    }

    #[must_use]
    pub const fn write_actor(&self) -> WriteActor {
        WriteActor::new(self.actor_ref, self.actor_class)
    }

    pub(super) const fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    pub(super) fn is_expired(&self, now: u64) -> bool {
        self.expires_at.is_some_and(|expires_at| now >= expires_at)
    }

    pub(super) fn is_stale(&self, now: u64) -> bool {
        self.revoked_at.is_some_and(|revoked_at| now >= revoked_at) || self.is_expired(now)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpResolvedActor {
    pub actor_ref: EntityId,
    pub actor_class: EdgeActorClass,
    pub gate_actor_class: &'static str,
    pub gate_actor_ref: String,
    pub scope: McpConnectorScope,
    /// The process-local STREAM connection bound to the REGISTERED credential
    /// fingerprint (ONE-1704/ONE-1701). Never derived from tool arguments, and
    /// detached by revoke, unregister, and prune.
    pub stream_connection: StreamConnectionId,
    /// The registered bound-verb ceiling. Copied from the record, never a
    /// request field.
    pub bound_verbs: Option<BTreeSet<&'static str>>,
    /// The STREAM subscription ceiling this credential was attached under.
    pub subscription_ceiling: BTreeSet<SubscriptionScope>,
}

impl McpResolvedActor {
    #[must_use]
    pub const fn write_actor(&self) -> WriteActor {
        WriteActor::new(self.actor_ref, self.actor_class)
    }

    /// True when this connector may call the named REGISTERED tool.
    ///
    /// An unbound verb is refused at call time; it never disappears from
    /// `tools/list`, which stays byte-identical for every credential.
    #[must_use]
    pub fn admits_tool(&self, name: &str) -> bool {
        self.bound_verbs
            .as_ref()
            .is_none_or(|bound| bound.contains(name))
    }

    /// The subscription set this connector may actually reach, intersected
    /// with what it asked for. A caller echo can only ever narrow.
    #[must_use]
    pub fn admitted_subscriptions(
        &self,
        requested: &BTreeSet<SubscriptionScope>,
    ) -> BTreeSet<SubscriptionScope> {
        requested
            .intersection(&self.subscription_ceiling)
            .copied()
            .collect()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum McpConnectorActorRegistrationError {
    #[error("credential must not be blank")]
    EmptyCredential,
    #[error("credential is already registered")]
    DuplicateCredential,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum McpConnectorActorResolutionError {
    #[error("credential not found")]
    UnknownCredential,
    #[error("credential has expired")]
    ExpiredCredential,
    #[error("credential has been revoked")]
    RevokedCredential,
    #[error("actor ceiling row not found")]
    MissingActorCeiling,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpConnectorActorRevokeStatus {
    Revoked,
    AlreadyRevoked { revoked_at: u64 },
}
