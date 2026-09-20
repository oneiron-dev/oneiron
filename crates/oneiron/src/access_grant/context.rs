//! Relationship read authority built from live grants and stored membership evidence.
use super::{AccessGrant, AccessGrantCapability, decode_access_grant_body};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimSubject, claim_surfaceable, decode_claim_body};
use crate::error::{Error, Result};
use crate::registry::{
    ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_CLAIM, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_SUMMARY,
};
use crate::{EntityId, Vault};
use std::collections::BTreeSet;

/// Resolved authority, not caller-provided hints. Identity fields never imply membership.
#[derive(Debug, Clone)]
pub struct AccessContext {
    principal: Option<EntityId>,
    relationships: BTreeSet<EntityId>,
    grants: Vec<AccessGrant>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessLimited {
    pub suppressed_count: usize,
    pub required_action: String,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantedData<T> {
    pub granted_data: Vec<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_limited: Option<AccessLimited>,
}

impl AccessContext {
    pub(crate) fn load(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        principal: Option<EntityId>,
    ) -> Result<Self> {
        let mut context = Self {
            principal,
            relationships: BTreeSet::new(),
            grants: Vec::new(),
        };
        if principal.is_none() {
            return Ok(context);
        }
        for kind in [ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_CLAIM] {
            for row in vault.store.type_index.prefix_iter(txn, &[kind])? {
                let (key, _) = row?;
                let id = crate::vault::entity_id_from_type_index_key(&key)?;
                let raw = vault
                    .store
                    .entities
                    .get(txn, id.as_bytes())?
                    .ok_or(Error::CorruptedIndex("access context row"))?;
                let header = EntityMetadataHeader::parse(&raw)
                    .ok_or(Error::CorruptedIndex("access context header"))?;
                if header.entity_type != kind {
                    return Err(Error::CorruptedIndex("access context type"));
                }
                if kind == ENTITY_TYPE_ACCESS_GRANT {
                    let grant = decode_access_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
                    if Some(grant.principal_ref) == principal && grant.is_active() {
                        context.grants.push(grant);
                    }
                } else if raw.len() > ENTITY_METADATA_HEADER_LEN {
                    let body = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
                    if body.predicate == crate::federation::PREDICATE_RELATIONSHIP_PERSON_REF
                        && claim_surfaceable(&body)
                        && body
                            .value
                            .as_str()
                            .and_then(|v| EntityId::from_hex(v).ok())
                            .is_some_and(|id| Some(id) == principal)
                        && let ClaimSubject::Entity(space) = body.subject
                    {
                        // A member binding is only a relationship membership when its subject really is one.
                        if vault
                            .store
                            .entities
                            .get(txn, space.as_bytes())?
                            .and_then(|raw| EntityMetadataHeader::parse(&raw))
                            .is_some_and(|h| {
                                h.entity_type == crate::registry::ENTITY_TYPE_RELATIONSHIP
                            })
                        {
                            context.relationships.insert(space);
                        }
                    }
                }
            }
        }
        Ok(context)
    }

    /// Applies the C1-C3 matrix. Private rows cannot be shared by an AccessGrant.
    pub fn allows(&self, entity_type: u8, space: Option<EntityId>, private: bool) -> bool {
        if private {
            return false;
        }
        let Some(space) = space else {
            return !matches!(entity_type, ENTITY_TYPE_MESSAGE | ENTITY_TYPE_SUMMARY);
        };
        if self.relationships.contains(&space) {
            return true;
        }
        let capability = match entity_type {
            ENTITY_TYPE_MESSAGE => AccessGrantCapability::MessagesRead,
            ENTITY_TYPE_SUMMARY => AccessGrantCapability::SummariesRead,
            ENTITY_TYPE_CLAIM => AccessGrantCapability::RelationshipClaimsRead,
            _ => return false,
        };
        self.grants.iter().any(|grant| {
            grant.allows_relationship_read(
                self.principal
                    .expect("a grant is loaded only for a bound principal"),
                space,
                capability,
            )
        })
    }
}

impl Vault {
    pub fn access_context(&self, principal: EntityId) -> Result<AccessContext> {
        let txn = self.store.env.read_txn()?;
        AccessContext::load(self, &txn, Some(principal))
    }
}

impl<T> GrantedData<T> {
    /// Only authorized ids belong in this projection. Withheld ids are never disclosed.
    pub fn new(granted_data: Vec<T>, suppressed_count: usize) -> Self {
        Self {
            granted_data,
            access_limited: (suppressed_count > 0).then(|| AccessLimited {
                suppressed_count,
                required_action: "request_access".to_owned(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ScoredEntity;
    use crate::access_grant::{AccessGrantScope, AccessGrantStatus};
    use crate::claim::ScopedReadActorKey;
    #[test]
    fn granted_messages_are_returned_but_summary_and_expired_grants_are_limited() -> Result<()> {
        let (_dir, vault) =
            crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
        let principal = EntityId::now();
        let space = EntityId::now();
        let message = EntityId::now();
        let summary = EntityId::now();
        let body = rmp_serde::to_vec_named(
            &serde_json::json!({"rel":space.to_hex(), "text":"safe content"}),
        )
        .unwrap();
        let when = crate::TimeRange { start: 1, end: 1 };
        let author = EntityId::now();
        vault.put_entity(
            &author,
            crate::registry::ENTITY_TYPE_PERSON,
            when,
            1,
            b"author",
        )?;
        vault
            .memory(author, crate::EdgeActorClass::Human)
            .witness(&crate::memory::WitnessTurn {
                conversation_ref: EntityId::now().to_hex(),
                turn_ref: None,
                occurred_at: 1,
                messages: vec![crate::memory::WitnessMessage {
                    id: Some(message.to_hex()),
                    author: crate::memory::WitnessAuthor::User,
                    message_type: "dialogue".into(),
                    content: "safe content".into(),
                    metadata: Some(serde_json::json!({"rel":space.to_hex()})),
                    is_visible: true,
                    order: 0,
                }],
            })
            .expect("authenticated witness message");
        vault.put_entity(&summary, ENTITY_TYPE_SUMMARY, when, 1, &body)?;
        let grant_ref = EntityId::now();
        let mut grant = AccessGrant {
            principal_ref: principal,
            scope: AccessGrantScope::Messages { space_ref: space },
            capability: AccessGrantCapability::MessagesRead,
            status: AccessGrantStatus::Active,
            created_at: 1,
            revoked_at: None,
            expires_at: Some(u64::MAX),
        };
        vault.create_access_grant(&grant_ref, &grant)?;
        let context = vault.access_context(principal)?;
        assert!(!context.allows(ENTITY_TYPE_MESSAGE, None, false));
        assert!(!context.allows(ENTITY_TYPE_SUMMARY, None, false));
        let reader = vault.scoped_read(
            ScopedReadActorKey::new("reader")
                .unwrap()
                .require_access_grants(Some(principal)),
        );
        let result = reader.filter_scored_entities(vec![
            ScoredEntity {
                id: message,
                score: 1.0,
            },
            ScoredEntity {
                id: summary,
                score: 1.0,
            },
        ])?;
        assert_eq!(
            result.value.iter().map(|row| row.id).collect::<Vec<_>>(),
            vec![message]
        );
        let projected = GrantedData::new(result.value, result.receipt.suppressed_count);
        assert_eq!(projected.access_limited.unwrap().suppressed_count, 1);
        assert!(reader.get_entity_parts(&message)?.is_some());
        assert!(reader.get_entity_parts(&summary)?.is_none());
        let fs = reader.graph_fs(crate::graph_fs::GraphFsOptions::default());
        let found = fs.find("/entities", Some(0), None)?;
        let paths = String::from_utf8(found.bytes().to_vec()).unwrap();
        assert!(paths.contains(&message.to_hex()));
        assert!(!paths.contains(&summary.to_hex()));
        assert!(
            fs.find(&format!("/entities/{}", summary.to_hex()), None, None)?
                .bytes()
                .is_empty()
        );
        for fields in [
            vec![
                (rmpv::Value::from("rel"), rmpv::Value::Nil),
                (rmpv::Value::from("rel"), rmpv::Value::from(space.to_hex())),
            ],
            vec![
                (rmpv::Value::from("rel"), rmpv::Value::from(space.to_hex())),
                (rmpv::Value::from("scope"), rmpv::Value::from("private")),
            ],
        ] {
            let malformed = EntityId::now();
            let mut bytes = Vec::new();
            rmpv::encode::write_value(&mut bytes, &rmpv::Value::Map(fields)).unwrap();
            // Corrupt/legacy payloads cannot enter through today's witness door.
            // Seed only this read fixture, preserving the valid MESSAGE header.
            let mut txn = vault.store.env.write_txn()?;
            let raw = vault.store.entities.get(&txn, message.as_bytes())?.unwrap();
            let mut malformed_raw = raw[..ENTITY_METADATA_HEADER_LEN].to_vec();
            malformed_raw.extend_from_slice(&bytes);
            vault
                .store
                .entities
                .put(&mut txn, malformed.as_bytes(), &malformed_raw)?;
            txn.commit()?;
            assert!(
                reader
                    .filter_scored_entities(vec![ScoredEntity {
                        id: malformed,
                        score: 1.0
                    }])?
                    .value
                    .is_empty()
            );
            assert!(reader.get_entity_parts(&malformed)?.is_none());
        }
        grant.expires_at = Some(2);
        vault.put_access_grant(&grant_ref, &grant)?;
        assert!(reader.get_entity_parts(&message)?.is_none());
        let unbound = vault.scoped_read(
            ScopedReadActorKey::new("unbound")
                .unwrap()
                .require_access_grants(None),
        );
        assert!(unbound.get_entity_parts(&message)?.is_none());
        Ok(())
    }
}
