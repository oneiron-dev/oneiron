//! MCP connector actor registry.
//!
//! The registry is deliberately not an authority carrier. It resolves an
//! external connector credential to the actor identity and scope that the MCP
//! gateway should attach to the existing vault write path. Approval authority
//! remains in Gate `actor_ceilings` policy rows.

use std::collections::BTreeMap;

use oneiron::{EdgeActorClass, EntityId, WriteActor};

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
    pub const fn revoked_at(mut self, revoked_at: u64) -> Self {
        self.revoked_at = Some(revoked_at);
        self
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpConnectorActorRegistrationError {
    EmptyCredential,
    DuplicateCredential,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpConnectorActorResolutionError {
    UnknownCredential,
    ExpiredCredential,
    RevokedCredential,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct McpConnectorActorRegistry {
    records: BTreeMap<String, McpConnectorActorRecord>,
}

impl McpConnectorActorRegistry {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            records: BTreeMap::new(),
        }
    }

    pub fn register(
        &mut self,
        credential: impl Into<String>,
        record: McpConnectorActorRecord,
    ) -> Result<(), McpConnectorActorRegistrationError> {
        let credential = credential.into();
        if credential.trim().is_empty() {
            return Err(McpConnectorActorRegistrationError::EmptyCredential);
        }
        if self.records.contains_key(&credential) {
            return Err(McpConnectorActorRegistrationError::DuplicateCredential);
        }
        self.records.insert(credential, record);
        Ok(())
    }

    pub fn revoke(&mut self, credential: &str, revoked_at: u64) -> bool {
        let Some(record) = self.records.get_mut(credential) else {
            return false;
        };
        record.revoked_at = Some(revoked_at);
        true
    }

    pub fn resolve(
        &self,
        credential: &str,
        now: u64,
    ) -> Result<McpResolvedActor, McpConnectorActorResolutionError> {
        let record = self
            .records
            .get(credential)
            .ok_or(McpConnectorActorResolutionError::UnknownCredential)?;

        if record.revoked_at.is_some() {
            return Err(McpConnectorActorResolutionError::RevokedCredential);
        }
        if record
            .expires_at
            .is_some_and(|expires_at| now >= expires_at)
        {
            return Err(McpConnectorActorResolutionError::ExpiredCredential);
        }

        Ok(McpResolvedActor {
            actor_ref: record.actor_ref,
            actor_class: record.actor_class,
            gate_actor_class: record.actor_class.gate_actor_class(),
            gate_actor_ref: record.actor_ref.to_hex(),
            scope: record.scope.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(seed: u128) -> EntityId {
        EntityId::from_bytes(seed.to_be_bytes()).expect("test id should be nonzero")
    }

    #[test]
    fn owner_key_resolves_to_human_gate_actor_identity() {
        let owner = id(0xA001);
        let mut registry = McpConnectorActorRegistry::new();
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

        let resolved = registry.resolve("owner-key", 10).expect("owner resolves");

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
        let mut registry = McpConnectorActorRegistry::new();
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
            .resolve("connector-key", 19)
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
        let mut registry = McpConnectorActorRegistry::new();
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
            registry.resolve("missing-key", 19),
            Err(McpConnectorActorResolutionError::UnknownCredential)
        );
        assert_eq!(
            registry.resolve("expired-key", 20),
            Err(McpConnectorActorResolutionError::ExpiredCredential)
        );
    }

    #[test]
    fn revoked_connector_key_fails_closed() {
        let mut registry = McpConnectorActorRegistry::new();
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

        assert!(registry.revoke("revoked-key", 12));

        assert_eq!(
            registry.resolve("revoked-key", 13),
            Err(McpConnectorActorResolutionError::RevokedCredential)
        );
    }

    #[test]
    fn blank_and_duplicate_connector_keys_fail_closed() {
        let mut registry = McpConnectorActorRegistry::new();
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
}
