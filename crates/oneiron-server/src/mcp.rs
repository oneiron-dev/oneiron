//! MCP connector actor registry.
//!
//! The registry is deliberately not an authority carrier. It resolves an
//! external connector credential to the actor identity and scope that the MCP
//! gateway should attach to the existing vault write path. Approval authority
//! remains in Gate `actor_ceilings` policy rows.

use std::{collections::BTreeMap, fmt};

use oneiron::{EdgeActorClass, EntityId, WriteActor};

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct McpCredentialHashKey([u8; 32]);

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
struct McpCredentialFingerprint([u8; 32]);

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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpConnectorActorRecord {
    actor_ref: EntityId,
    actor_class: EdgeActorClass,
    scope: McpConnectorScope,
    expires_at: Option<u64>,
    revoked_at: Option<u64>,
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
            expires_at: None,
            revoked_at: None,
        }
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

    const fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    fn is_expired(&self, now: u64) -> bool {
        self.expires_at.is_some_and(|expires_at| now >= expires_at)
    }

    fn is_stale(&self, now: u64) -> bool {
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
}

impl McpResolvedActor {
    #[must_use]
    pub const fn write_actor(&self) -> WriteActor {
        WriteActor::new(self.actor_ref, self.actor_class)
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

#[derive(Clone, Eq, PartialEq)]
pub struct McpConnectorActorRegistry {
    credential_hash_key: McpCredentialHashKey,
    records: BTreeMap<McpCredentialFingerprint, McpConnectorActorRecord>,
}

impl fmt::Debug for McpConnectorActorRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpConnectorActorRegistry")
            .field("credential_hash_key", &"<redacted>")
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl McpConnectorActorRegistry {
    #[must_use]
    pub const fn new(credential_hash_key: McpCredentialHashKey) -> Self {
        Self {
            credential_hash_key,
            records: BTreeMap::new(),
        }
    }

    pub fn register(
        &mut self,
        credential: impl Into<String>,
        record: McpConnectorActorRecord,
    ) -> Result<(), McpConnectorActorRegistrationError> {
        let credential = credential.into();
        let Some(credential) = normalize_credential(&credential) else {
            return Err(McpConnectorActorRegistrationError::EmptyCredential);
        };
        let fingerprint = self.fingerprint_credential(credential);
        if self.records.contains_key(&fingerprint) {
            return Err(McpConnectorActorRegistrationError::DuplicateCredential);
        }
        self.records.insert(fingerprint, record);
        Ok(())
    }

    pub fn revoke(
        &mut self,
        credential: &str,
        revoked_at: u64,
    ) -> Result<McpConnectorActorRevokeStatus, McpConnectorActorResolutionError> {
        let Some(fingerprint) = self.fingerprint_lookup_credential(credential) else {
            return Err(McpConnectorActorResolutionError::UnknownCredential);
        };
        let record = self
            .records
            .get_mut(&fingerprint)
            .ok_or(McpConnectorActorResolutionError::UnknownCredential)?;

        if let Some(existing_revoked_at) = record.revoked_at {
            return Ok(McpConnectorActorRevokeStatus::AlreadyRevoked {
                revoked_at: existing_revoked_at,
            });
        }

        record.revoked_at = Some(revoked_at);
        Ok(McpConnectorActorRevokeStatus::Revoked)
    }

    pub fn resolve(
        &self,
        credential: &str,
        now: u64,
        actor_ceiling_exists: impl FnOnce(&str, &str) -> bool,
    ) -> Result<McpResolvedActor, McpConnectorActorResolutionError> {
        let Some(fingerprint) = self.fingerprint_lookup_credential(credential) else {
            return Err(McpConnectorActorResolutionError::UnknownCredential);
        };
        let record = self
            .records
            .get(&fingerprint)
            .ok_or(McpConnectorActorResolutionError::UnknownCredential)?;

        if record.is_revoked() {
            return Err(McpConnectorActorResolutionError::RevokedCredential);
        }
        if record.is_expired(now) {
            return Err(McpConnectorActorResolutionError::ExpiredCredential);
        }

        let gate_actor_class = record.gate_actor_class();
        let gate_actor_ref = record.gate_actor_ref();
        if !actor_ceiling_exists(gate_actor_class, &gate_actor_ref) {
            return Err(McpConnectorActorResolutionError::MissingActorCeiling);
        }

        Ok(McpResolvedActor {
            actor_ref: record.actor_ref,
            actor_class: record.actor_class,
            gate_actor_class,
            gate_actor_ref,
            scope: record.scope.clone(),
        })
    }

    pub fn unregister(&mut self, credential: &str) -> bool {
        let Some(fingerprint) = self.fingerprint_lookup_credential(credential) else {
            return false;
        };
        self.records.remove(&fingerprint).is_some()
    }

    pub fn prune_revoked_or_expired(&mut self, now: u64) -> usize {
        let before = self.records.len();
        self.records.retain(|_, record| !record.is_stale(now));
        before - self.records.len()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    fn fingerprint_lookup_credential(&self, credential: &str) -> Option<McpCredentialFingerprint> {
        normalize_credential(credential).map(|credential| self.fingerprint_credential(credential))
    }

    fn fingerprint_credential(&self, credential: &str) -> McpCredentialFingerprint {
        McpCredentialFingerprint(
            *blake3::keyed_hash(&self.credential_hash_key.0, credential.as_bytes()).as_bytes(),
        )
    }
}

fn normalize_credential(credential: &str) -> Option<&str> {
    let credential = credential.trim();
    (!credential.is_empty()).then_some(credential)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(seed: u128) -> EntityId {
        EntityId::from_bytes(seed.to_be_bytes()).expect("test id should be nonzero")
    }

    fn registry() -> McpConnectorActorRegistry {
        McpConnectorActorRegistry::new(McpCredentialHashKey::from_bytes([42; 32]))
    }

    fn actor_ceiling_for(
        actor_class: EdgeActorClass,
        actor_ref: EntityId,
    ) -> impl FnOnce(&str, &str) -> bool {
        let expected_actor_ref = actor_ref.to_hex();
        move |gate_actor_class, gate_actor_ref| {
            gate_actor_class == actor_class.gate_actor_class()
                && gate_actor_ref == expected_actor_ref
        }
    }

    fn unexpected_actor_ceiling_lookup(_: &str, _: &str) -> bool {
        panic!("actor ceiling lookup should not run after credential failure")
    }

    #[test]
    fn owner_key_resolves_to_human_gate_actor_identity() {
        let owner = id(0xA001);
        let mut registry = registry();
        registry
            .register(
                "owner-key",
                McpConnectorActorRecord::new(
                    owner,
                    EdgeActorClass::Human,
                    McpConnectorScope::vault_wide(),
                ),
            )
            .expect("owner key registration succeeds");

        let resolved = registry
            .resolve(
                "owner-key",
                10,
                actor_ceiling_for(EdgeActorClass::Human, owner),
            )
            .expect("owner resolves");

        assert_eq!(resolved.actor_ref, owner);
        assert_eq!(resolved.actor_class, EdgeActorClass::Human);
        assert_eq!(resolved.gate_actor_class, "human");
        assert_eq!(resolved.gate_actor_ref, owner.to_hex());
        assert_eq!(resolved.scope, McpConnectorScope::vault_wide());
        assert_eq!(
            resolved.write_actor(),
            WriteActor::new(owner, EdgeActorClass::Human)
        );
    }

    #[test]
    fn connector_key_resolves_to_agent_identity_and_scope() {
        let connector = id(0xB001);
        let world = id(0xB002);
        let facet = id(0xB003);
        let mut registry = registry();
        registry
            .register(
                "connector-key",
                McpConnectorActorRecord::new(
                    connector,
                    EdgeActorClass::Agent,
                    McpConnectorScope::scoped(Some(world), Some(facet)),
                )
                .with_expiry(20),
            )
            .expect("connector key registration succeeds");

        let resolved = registry
            .resolve(
                "connector-key",
                19,
                actor_ceiling_for(EdgeActorClass::Agent, connector),
            )
            .expect("connector resolves before expiry");

        assert_eq!(resolved.actor_ref, connector);
        assert_eq!(resolved.gate_actor_class, "agent");
        assert_eq!(resolved.gate_actor_ref, connector.to_hex());
        assert_eq!(
            resolved.scope,
            McpConnectorScope::scoped(Some(world), Some(facet))
        );
    }

    #[test]
    fn unknown_and_expired_connector_keys_fail_closed() {
        let mut registry = registry();
        registry
            .register(
                "expired-key",
                McpConnectorActorRecord::new(
                    id(0xC001),
                    EdgeActorClass::Agent,
                    McpConnectorScope::vault_wide(),
                )
                .with_expiry(20),
            )
            .expect("expired key registration succeeds");

        assert_eq!(
            registry.resolve("missing-key", 19, unexpected_actor_ceiling_lookup),
            Err(McpConnectorActorResolutionError::UnknownCredential)
        );
        assert_eq!(
            registry.resolve("expired-key", 20, unexpected_actor_ceiling_lookup),
            Err(McpConnectorActorResolutionError::ExpiredCredential)
        );
    }

    #[test]
    fn revoked_connector_key_fails_closed() {
        let mut registry = registry();
        registry
            .register(
                "revoked-key",
                McpConnectorActorRecord::new(
                    id(0xD001),
                    EdgeActorClass::Agent,
                    McpConnectorScope::vault_wide(),
                ),
            )
            .expect("revoked key registration succeeds");

        assert_eq!(
            registry.revoke("revoked-key", 12),
            Ok(McpConnectorActorRevokeStatus::Revoked)
        );

        assert_eq!(
            registry.resolve("revoked-key", 13, unexpected_actor_ceiling_lookup),
            Err(McpConnectorActorResolutionError::RevokedCredential)
        );
    }

    #[test]
    fn blank_and_duplicate_connector_keys_fail_closed() {
        let mut registry = registry();
        let record = McpConnectorActorRecord::new(
            id(0xE001),
            EdgeActorClass::Agent,
            McpConnectorScope::vault_wide(),
        );

        assert_eq!(
            registry.register("  ", record.clone()),
            Err(McpConnectorActorRegistrationError::EmptyCredential)
        );

        registry
            .register("connector-key", record.clone())
            .expect("first registration succeeds");
        assert_eq!(
            registry.register("connector-key", record),
            Err(McpConnectorActorRegistrationError::DuplicateCredential)
        );
    }

    #[test]
    fn credential_whitespace_is_canonicalized_for_all_lookups() {
        let actor = id(0xF001);
        let mut registry = registry();
        let record = McpConnectorActorRecord::new(
            actor,
            EdgeActorClass::Agent,
            McpConnectorScope::vault_wide(),
        );

        registry
            .register(" connector-key ", record.clone())
            .expect("registration trims credential");
        assert_eq!(
            registry.register("connector-key", record),
            Err(McpConnectorActorRegistrationError::DuplicateCredential)
        );

        assert_eq!(
            registry
                .resolve(
                    "\tconnector-key\n",
                    10,
                    actor_ceiling_for(EdgeActorClass::Agent, actor),
                )
                .expect("trimmed lookup resolves")
                .actor_ref,
            actor
        );
        assert_eq!(
            registry.revoke(" connector-key ", 11),
            Ok(McpConnectorActorRevokeStatus::Revoked)
        );
        assert_eq!(
            registry.resolve("connector-key", 12, unexpected_actor_ceiling_lookup),
            Err(McpConnectorActorResolutionError::RevokedCredential)
        );
    }

    #[test]
    fn registry_debug_does_not_print_credentials_or_hash_key() {
        let mut registry = registry();
        registry
            .register(
                "very-secret-connector-key",
                McpConnectorActorRecord::new(
                    id(0xF101),
                    EdgeActorClass::Agent,
                    McpConnectorScope::vault_wide(),
                ),
            )
            .expect("registration succeeds");

        let debug = format!("{registry:?}");
        assert!(debug.contains("record_count"));
        assert!(!debug.contains("very-secret-connector-key"));
        assert!(!debug.contains("42"));
    }

    #[test]
    fn double_revoke_preserves_original_timestamp() {
        let mut registry = registry();
        registry
            .register(
                "connector-key",
                McpConnectorActorRecord::new(
                    id(0xF201),
                    EdgeActorClass::Agent,
                    McpConnectorScope::vault_wide(),
                ),
            )
            .expect("registration succeeds");

        assert_eq!(
            registry.revoke("connector-key", 12),
            Ok(McpConnectorActorRevokeStatus::Revoked)
        );
        assert_eq!(
            registry.revoke("connector-key", 99),
            Ok(McpConnectorActorRevokeStatus::AlreadyRevoked { revoked_at: 12 })
        );
    }

    #[test]
    fn prune_and_unregister_remove_stale_credentials() {
        let mut registry = registry();
        registry
            .register(
                "expired-key",
                McpConnectorActorRecord::new(
                    id(0xF301),
                    EdgeActorClass::Agent,
                    McpConnectorScope::vault_wide(),
                )
                .with_expiry(10),
            )
            .expect("expired key registration succeeds");
        registry
            .register(
                "revoked-key",
                McpConnectorActorRecord::new(
                    id(0xF302),
                    EdgeActorClass::Agent,
                    McpConnectorScope::vault_wide(),
                )
                .with_revoked_at(11),
            )
            .expect("revoked key registration succeeds");
        registry
            .register(
                "active-key",
                McpConnectorActorRecord::new(
                    id(0xF303),
                    EdgeActorClass::Agent,
                    McpConnectorScope::vault_wide(),
                ),
            )
            .expect("active key registration succeeds");

        assert_eq!(registry.prune_revoked_or_expired(11), 2);
        assert_eq!(registry.len(), 1);
        assert!(registry.unregister(" active-key "));
        assert!(registry.is_empty());
    }

    #[test]
    fn resolved_actor_exposes_only_gate_actor_identity_not_authority() {
        let actor = id(0xF401);
        let mut registry = registry();
        registry
            .register(
                "connector-key",
                McpConnectorActorRecord::new(
                    actor,
                    EdgeActorClass::Agent,
                    McpConnectorScope::vault_wide(),
                ),
            )
            .expect("registration succeeds");

        let resolved = registry
            .resolve(
                "connector-key",
                10,
                actor_ceiling_for(EdgeActorClass::Agent, actor),
            )
            .expect("connector resolves");

        assert_eq!(resolved.gate_actor_class, "agent");
        assert_eq!(resolved.gate_actor_ref, actor.to_hex());
        assert_eq!(
            resolved.write_actor(),
            WriteActor::new(actor, EdgeActorClass::Agent)
        );
    }

    #[test]
    fn missing_actor_ceiling_fails_closed_after_credential_resolves() {
        let actor = id(0xF501);
        let mut registry = registry();
        registry
            .register(
                "connector-key",
                McpConnectorActorRecord::new(
                    actor,
                    EdgeActorClass::Agent,
                    McpConnectorScope::vault_wide(),
                ),
            )
            .expect("registration succeeds");

        assert_eq!(
            registry.resolve("connector-key", 10, |_, _| false),
            Err(McpConnectorActorResolutionError::MissingActorCeiling)
        );
    }
}
