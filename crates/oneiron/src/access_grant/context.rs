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
#[derive(Clone)]
pub struct AccessContext<'v> {
    principal: Option<EntityId>,
    relationships: BTreeSet<EntityId>,
    grants: Vec<AccessGrant>,
    vault: &'v Vault,
    observed_at: u64,
}

impl std::fmt::Debug for AccessContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessContext")
            .field("principal", &self.principal)
            .field("relationships", &self.relationships)
            .field("grants", &self.grants)
            .field("observed_at", &self.observed_at)
            .finish_non_exhaustive()
    }
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

impl<'v> AccessContext<'v> {
    pub(crate) fn load(
        vault: &'v Vault,
        txn: &heed::RoTxn<'_>,
        principal: Option<EntityId>,
    ) -> Result<Self> {
        let now = crate::ports::authorization_floor_in_txn(&vault.store, txn)?;
        let mut context = Self {
            principal,
            relationships: BTreeSet::new(),
            grants: Vec::new(),
            vault,
            observed_at: now,
        };
        if principal.is_none() {
            return Ok(context);
        }
        let live = |id: &EntityId| -> Result<bool> {
            Ok(crate::vault::live_entity_row_in_txn(&vault.store, txn, id)?.is_live())
        };
        for kind in [ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_CLAIM] {
            for row in vault.store.type_index.prefix_iter(txn, &[kind])? {
                let (key, _) = row?;
                let id = crate::vault::entity_id_from_type_index_key(&key)?;
                let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &id)?
                    .ok_or(Error::CorruptedIndex("access context row"))?;
                let header = EntityMetadataHeader::parse(&raw)
                    .ok_or(Error::CorruptedIndex("access context header"))?;
                if header.entity_type != kind {
                    return Err(Error::CorruptedIndex("access context type"));
                }
                if kind == ENTITY_TYPE_ACCESS_GRANT {
                    // A deleted grant grants nothing, and the bodyless shell
                    // it may leave is not a corrupt grant.
                    if raw.len() == ENTITY_METADATA_HEADER_LEN && !live(&id)? {
                        continue;
                    }
                    let grant = decode_access_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
                    if Some(grant.principal_ref) == principal
                        && grant.effective_status_at(now) == super::AccessGrantStatus::Active
                        && live(&id)?
                    {
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
                        // A member binding is a membership only while it and its
                        // subject are live, and the subject is a relationship: a
                        // deleted one keeps its typed header.
                        if live(&id)?
                            && crate::vault::live_entity_row_in_txn(&vault.store, txn, &space)?
                                .live_type()
                                == Some(crate::registry::ENTITY_TYPE_RELATIONSHIP)
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
    pub fn allows(
        &self,
        entity_type: u8,
        space: Option<EntityId>,
        private: bool,
        record: &crate::federation::Scope,
    ) -> bool {
        // A retained context answers for now: authority is resolved again in a
        // fresh snapshot, so a later expiry, revocation or relationship delete
        // applies, and an observation that failed to reach the durable floor
        // is never exposed.
        self.vault.store.authorization_now().is_ok()
            && self
                .vault
                .store
                .env
                .read_txn()
                .ok()
                .and_then(|txn| Self::load(self.vault, &txn, self.principal).ok())
                .is_some_and(|current| {
                    current.allows_at_snapshot(entity_type, space, private, record)
                })
    }

    pub(crate) fn allows_at_snapshot(
        &self,
        entity_type: u8,
        space: Option<EntityId>,
        private: bool,
        record: &crate::federation::Scope,
    ) -> bool {
        self.allows_at(entity_type, space, private, record, self.observed_at)
    }

    fn allows_at(
        &self,
        entity_type: u8,
        space: Option<EntityId>,
        private: bool,
        record: &crate::federation::Scope,
        now: u64,
    ) -> bool {
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
                record,
                now,
            )
        })
    }
}

impl Vault {
    pub fn access_context(&self, principal: EntityId) -> Result<AccessContext<'_>> {
        self.store.authorization_now()?;
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
            authority_scope: crate::federation::scope_codec::read_preset(),
        };
        // The actual MESSAGE stamp is one kind at Sensitive, not All kinds
        // at Restricted. Narrowing to it must still admit the read.
        grant.authority_scope.bands =
            crate::federation::ScopeAxis::Some(std::collections::BTreeSet::from([
                ENTITY_TYPE_MESSAGE,
            ]));
        grant.authority_scope.sensitivity = crate::federation::SensitivityCeiling::AtMost(
            crate::federation::Sensitivity::Sensitive,
        );
        vault.create_access_grant(&grant_ref, &grant)?;
        let context = vault.access_context(principal)?;
        assert!(!context.allows(
            ENTITY_TYPE_MESSAGE,
            None,
            false,
            &crate::federation::Scope::top()
        ));
        assert!(!context.allows(
            ENTITY_TYPE_SUMMARY,
            None,
            false,
            &crate::federation::Scope::top()
        ));
        // A plain key reads nothing without a manifest grant; the relationship
        // grant under test only narrows what that base read admits.
        crate::test_util::authorize_readers(&vault, &["reader"]);
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
        let crate::claim::ScopedReadResult {
            value,
            receipt: _receipt,
        } = reader
            .read(&[crate::claim::PointRead::id(message)], None)?
            .single();
        assert!(value.is_some());
        let crate::claim::ScopedReadResult {
            value,
            receipt: _receipt,
        } = reader
            .read(&[crate::claim::PointRead::id(summary)], None)?
            .single();
        assert!(value.is_none());
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
            let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, &txn, &message)?
                .unwrap();
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
            let crate::claim::ScopedReadResult {
                value,
                receipt: _receipt,
            } = reader
                .read(&[crate::claim::PointRead::id(malformed)], None)?
                .single();
            assert!(value.is_none());
        }
        grant.expires_at = Some(2);
        vault.put_access_grant(&grant_ref, &grant)?;
        let crate::claim::ScopedReadResult {
            value,
            receipt: _receipt,
        } = reader
            .read(&[crate::claim::PointRead::id(message)], None)?
            .single();
        assert!(value.is_none());
        let unbound = vault.scoped_read(
            ScopedReadActorKey::new("unbound")
                .unwrap()
                .require_access_grants(None),
        );
        let crate::claim::ScopedReadResult {
            value,
            receipt: _receipt,
        } = unbound
            .read(&[crate::claim::PointRead::id(message)], None)?
            .single();
        assert!(value.is_none());
        Ok(())
    }

    #[test]
    fn relationship_claim_read_uses_claim_project_not_default_project() -> Result<()> {
        use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
        use crate::federation::{ScopeAxis, ScopeId};
        use rmpv::Value;
        use std::collections::BTreeSet;

        let (_dir, vault) =
            crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
        let principal = EntityId::now();
        let space = EntityId::now();
        let other_project = EntityId::now();
        let permitted = EntityId::now();
        let outside = EntityId::now();
        let when = crate::TimeRange { start: 1, end: 1 };
        vault.put_entity(
            &space,
            crate::registry::ENTITY_TYPE_RELATIONSHIP,
            when,
            1,
            b"relationship",
        )?;
        for (id, project) in [
            (permitted, crate::claim::default_project_id()),
            (outside, other_project),
        ] {
            let mut body = ClaimBody::new(
                "test.relationship_scope",
                ClaimSubject::Entity(space),
                Value::from("fact"),
                1.0,
                ClaimApprovalStatus::Approved,
                ClaimLifecycleStatus::Active,
            )
            .unwrap();
            body.rel = Some(space);
            body.scope_project = project;
            vault.put_claim(&id, &body, when, 1)?;
        }
        let mut grant = AccessGrant {
            authority_scope: crate::federation::scope_codec::read_preset(),
            principal_ref: principal,
            scope: AccessGrantScope::RelationshipClaims { space_ref: space },
            capability: AccessGrantCapability::RelationshipClaimsRead,
            status: AccessGrantStatus::Active,
            created_at: 1,
            revoked_at: None,
            expires_at: None,
        };
        grant.authority_scope.bands = ScopeAxis::Some(BTreeSet::from([ENTITY_TYPE_CLAIM]));
        grant.authority_scope.audience =
            ScopeAxis::Some(BTreeSet::from([
                ScopeId(crate::claim::default_project_id()),
            ]));
        vault.create_access_grant(&EntityId::now(), &grant)?;
        // The actor's manifest admits both projects; only the relationship
        // grant's stored Scope can refuse the out-of-project claim.
        crate::test_util::authorize_readers(&vault, &["reader"]);
        let broad = vault.scoped_read(ScopedReadActorKey::new("reader").unwrap());
        assert!(
            broad
                .read(&[crate::claim::PointRead::id(permitted)], None)?
                .single()
                .value
                .is_some()
        );
        assert!(
            broad
                .read(&[crate::claim::PointRead::id(outside)], None)?
                .single()
                .value
                .is_some()
        );
        let reader = vault.scoped_read(
            ScopedReadActorKey::new("reader")
                .unwrap()
                .require_access_grants(Some(principal)),
        );
        assert!(
            reader
                .read(&[crate::claim::PointRead::id(permitted)], None)?
                .single()
                .value
                .is_some()
        );
        assert!(
            reader
                .read(&[crate::claim::PointRead::id(outside)], None)?
                .single()
                .value
                .is_none()
        );
        Ok(())
    }

    /// A claim shared through relationship `space`, which its bound `member`
    /// reads through the scoped reader.
    struct RelationshipShare {
        space: EntityId,
        member: EntityId,
        #[cfg_attr(not(feature = "sync"), allow(dead_code))]
        binding: EntityId,
        shared: EntityId,
    }

    impl RelationshipShare {
        fn new(vault: &Vault) -> Self {
            Self::with_binding_world(vault, None)
        }

        /// The member binding is an ordinary claim, so it may name a world.
        fn with_binding_world(vault: &Vault, world: Option<EntityId>) -> Self {
            use crate::claim::{
                ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject,
            };

            let when = crate::TimeRange { start: 1, end: 1 };
            let space = EntityId::now();
            vault
                .put_entity(
                    &space,
                    crate::registry::ENTITY_TYPE_RELATIONSHIP,
                    when,
                    1,
                    b"relationship",
                )
                .expect("put the relationship");
            let member = EntityId::now();
            vault
                .put_entity(
                    &member,
                    crate::registry::ENTITY_TYPE_PERSON,
                    when,
                    1,
                    b"person",
                )
                .expect("put the member");
            // Bound before the shipped manifest is installed below: under it
            // the binding's predicate is critical and the write pends.
            let binding = match world {
                None => crate::federation::bind_member_person(vault, space, member, when, 1)
                    .expect("bind the member"),
                Some(world) => {
                    let binding = EntityId::now();
                    let mut body = ClaimBody::new(
                        crate::federation::PREDICATE_RELATIONSHIP_PERSON_REF,
                        ClaimSubject::Entity(space),
                        rmpv::Value::from(member.to_hex()),
                        1.0,
                        ClaimApprovalStatus::Approved,
                        ClaimLifecycleStatus::Active,
                    )
                    .unwrap();
                    body.world = Some(world);
                    vault
                        .put_claim(&binding, &body, when, 1)
                        .expect("bind the member in a world");
                    binding
                }
            };
            let shared = EntityId::now();
            let mut body = ClaimBody::new(
                "test.relationship_scope",
                ClaimSubject::Entity(space),
                rmpv::Value::from("fact"),
                1.0,
                ClaimApprovalStatus::Approved,
                ClaimLifecycleStatus::Active,
            )
            .unwrap();
            body.rel = Some(space);
            vault
                .put_claim(&shared, &body, when, 1)
                .expect("put the shared claim");
            crate::test_util::authorize_readers(vault, &["reader"]);
            Self {
                space,
                member,
                binding,
                shared,
            }
        }

        /// A read grant on the relationship's claims, from its id.
        fn grant(&self, vault: &Vault, principal: EntityId) -> Result<EntityId> {
            let id = EntityId::now();
            vault.create_access_grant(
                &id,
                &AccessGrant {
                    principal_ref: principal,
                    scope: AccessGrantScope::RelationshipClaims {
                        space_ref: self.space,
                    },
                    capability: AccessGrantCapability::RelationshipClaimsRead,
                    status: AccessGrantStatus::Active,
                    created_at: 1,
                    revoked_at: None,
                    expires_at: None,
                    authority_scope: crate::federation::scope_codec::read_preset(),
                },
            )?;
            Ok(id)
        }

        fn reads_as(&self, vault: &Vault, principal: EntityId) -> Result<bool> {
            let reader = vault.scoped_read(
                ScopedReadActorKey::new("reader")
                    .unwrap()
                    .require_access_grants(Some(principal)),
            );
            Ok(reader
                .read(&[crate::claim::PointRead::id(self.shared)], None)?
                .single()
                .value
                .is_some())
        }
    }

    /// Bug repro (#1307 census): a soft-deleted relationship must stop
    /// granting its members the reads its membership granted while live.
    #[test]
    fn a_deleted_relationship_grants_its_members_nothing() -> Result<()> {
        let (_dir, vault) =
            crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
        let share = RelationshipShare::new(&vault);
        let member = share.member;
        assert!(
            !share.reads_as(&vault, EntityId::now())?,
            "no membership, no read"
        );
        assert!(
            share.reads_as(&vault, member)?,
            "a live relationship grants its member the read"
        );
        let retained = vault.access_context(member)?;
        let retained_allows = || {
            retained.allows(
                ENTITY_TYPE_CLAIM,
                Some(share.space),
                false,
                &crate::federation::Scope::top(),
            )
        };
        assert!(retained_allows());

        assert!(vault.delete_entity(&share.space)?);
        assert!(
            !share.reads_as(&vault, member)?,
            "a deleted relationship grants nothing"
        );
        assert!(
            !retained_allows(),
            "nor does a context loaded before the delete"
        );
        Ok(())
    }

    /// Bug repro (#1307 census review): a relationship a peer deleted grants
    /// nothing here either, once its tombstone is applied: before the update
    /// carrying it is stored, and after, in a window with no snapshot yet.
    #[cfg(feature = "sync")]
    #[test]
    fn a_relationship_a_peer_deleted_grants_its_members_nothing() -> Result<()> {
        use crate::sync::bridge::{Materializer, persist_window_update, register_observer_b};
        use crate::sync::loro_support::{export_all_updates, import_doc, map_insert_bytes};
        use std::sync::Arc;

        let (_dir, vault) =
            crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
        let vault = Arc::new(vault);
        let share = RelationshipShare::new(&vault);
        assert!(share.reads_as(&vault, share.member)?);

        // The peer's soft tombstone from literal wire parts:
        // [reason 1 = user_delete][deleted_at: 8 LE][request_id: 16].
        let mut tombstone = vec![1u8];
        tombstone.extend_from_slice(&1_771_027_200u64.to_le_bytes());
        tombstone.extend_from_slice(&[0x5A; 16]);
        let peer = loro::LoroDoc::new();
        map_insert_bytes(
            &peer.get_map("tombstones"),
            &share.space.to_hex(),
            &tombstone,
        )?;
        peer.commit();

        let window = crate::deletion::window_label_from_timestamp(1);
        let doc = loro::LoroDoc::new();
        let _observer = register_observer_b(&doc, &vault, &Arc::new(Materializer::new()), &window);
        import_doc(&doc, &export_all_updates(&peer)?)?;
        assert!(
            !share.reads_as(&vault, share.member)?,
            "applied, its update not stored yet"
        );
        persist_window_update(&vault, &window, &export_all_updates(&doc)?)?;
        assert!(
            !share.reads_as(&vault, share.member)?,
            "applied and stored, no window snapshot"
        );
        Ok(())
    }

    /// Bug repro (#1307 census review): a deleted AccessGrant grants nothing,
    /// and the shell it leaves does not stop every other grant from loading.
    #[test]
    fn a_deleted_access_grant_grants_nothing_and_other_grants_still_load() -> Result<()> {
        let (_dir, vault) =
            crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
        let share = RelationshipShare::new(&vault);
        let kept = EntityId::now();
        let dropped = EntityId::now();
        share.grant(&vault, kept)?;
        let dropped_grant = share.grant(&vault, dropped)?;
        assert!(share.reads_as(&vault, kept)? && share.reads_as(&vault, dropped)?);

        assert!(vault.delete_entity(&dropped_grant)?);
        assert!(
            share.reads_as(&vault, kept)?,
            "another principal's grant still loads"
        );
        assert!(
            !share.reads_as(&vault, dropped)?,
            "a deleted grant grants nothing"
        );
        Ok(())
    }

    /// Whether the row stored under `id` still carries a body.
    #[cfg(feature = "sync")]
    fn has_body(vault: &Vault, id: &EntityId) -> Result<bool> {
        let txn = vault.store.env.read_txn()?;
        Ok(
            crate::ports::EntityStoreRead::port_entity_raw(&vault.store, &txn, id)?
                .is_some_and(|raw| raw.len() > ENTITY_METADATA_HEADER_LEN),
        )
    }

    /// A peer's soft tombstone from literal wire parts:
    /// [reason 1 = user_delete][deleted_at: 8 LE][request_id: 16].
    #[cfg(feature = "sync")]
    fn peer_soft_tombstone() -> Vec<u8> {
        let mut tombstone = vec![1u8];
        tombstone.extend_from_slice(&1_771_027_200u64.to_le_bytes());
        tombstone.extend_from_slice(&[0x5A; 16]);
        tombstone
    }

    /// The base month of the row stored under `id`, off its header.
    #[cfg(feature = "sync")]
    fn base_window(vault: &Vault, id: &EntityId) -> Result<String> {
        let txn = vault.store.env.read_txn()?;
        let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, &txn, id)?
            .expect("a stored row");
        let header = EntityMetadataHeader::parse(&raw).expect("a row header");
        Ok(crate::deletion::window_label_from_timestamp(
            header.learned_at,
        ))
    }

    /// A peer's soft deletes of `ids` reach window `window`, loaded with its
    /// observers, and every local apply fails: the bodies stay and `rm:`
    /// retries are flagged. The accepted update is then stored, under a window
    /// snapshot or as a lone `u:w:` update row.
    #[cfg(feature = "sync")]
    fn deliver_unapplied_peer_deletes(
        vault: &std::sync::Arc<Vault>,
        window: &str,
        ids: &[EntityId],
        snapshot: bool,
    ) -> Result<()> {
        use crate::sync::bridge::{Materializer, persist_window_update};
        use crate::sync::loro_support::{export_all_updates, import_doc, map_insert_bytes};
        use crate::sync::quarantine::INJECT_PURGE_FAILURES;

        let peer = loro::LoroDoc::new();
        for id in ids {
            map_insert_bytes(
                &peer.get_map("tombstones"),
                &id.to_hex(),
                &peer_soft_tombstone(),
            )?;
        }
        peer.commit();
        let loaded = crate::sync::window::LoadedWindow::new(
            "local",
            crate::sync::WindowKey::try_new(window).expect("a window key"),
            vault,
            &std::sync::Arc::new(Materializer::new()),
        );
        INJECT_PURGE_FAILURES.with(|cell| cell.set(u32::try_from(ids.len()).unwrap()));
        let imported = import_doc(&loaded.doc, &export_all_updates(&peer)?);
        INJECT_PURGE_FAILURES.with(|cell| cell.set(0));
        imported?;
        if snapshot {
            loaded.persist_state(vault)?;
        } else {
            persist_window_update(vault, window, &export_all_updates(&loaded.doc)?)?;
        }
        for id in ids {
            assert!(has_body(vault, id)?, "the failed apply left the body");
        }
        Ok(())
    }

    /// Bug repro (Astra #1322 finding 1): a peer that withdraws a soft delete,
    /// dropping the tombstone and putting the relationship's original body
    /// back, restores nothing. Delete wins here, whatever the window's
    /// tombstone map and the payload length now say, and through every door
    /// that takes a peer's row: the window's ingest and the explicit-tier
    /// replay alike.
    #[cfg(feature = "sync")]
    #[test]
    fn a_peer_cannot_withdraw_a_relationship_delete() -> Result<()> {
        use crate::sync::bridge::Materializer;
        use crate::sync::loro_support::{
            doc_from_snapshot, doc_version_vector, export_all_updates, export_snapshot,
            export_updates_since, import_doc, map_insert_bytes,
        };
        use std::sync::Arc;

        let (_dir, vault) =
            crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
        let vault = Arc::new(vault);
        let share = RelationshipShare::new(&vault);
        let original = {
            let txn = vault.store.env.read_txn()?;
            crate::ports::EntityStoreRead::port_entity_raw(&vault.store, &txn, &share.space)?
                .expect("the relationship row")
        };
        assert!(original.len() > ENTITY_METADATA_HEADER_LEN);

        let peer = loro::LoroDoc::new();
        map_insert_bytes(
            &peer.get_map("tombstones"),
            &share.space.to_hex(),
            &peer_soft_tombstone(),
        )?;
        peer.commit();
        let window = base_window(&vault, &share.space)?;
        let loaded = crate::sync::window::LoadedWindow::new(
            "local",
            crate::sync::WindowKey::try_new(&window).expect("a window key"),
            &vault,
            &Arc::new(Materializer::new()),
        );
        import_doc(&loaded.doc, &export_all_updates(&peer)?)?;
        loaded.persist_state(&vault)?;
        assert!(
            !share.reads_as(&vault, share.member)?,
            "the peer's delete applied"
        );

        // A fork of the causally complete window withdraws the delete.
        let fork = doc_from_snapshot(&export_snapshot(&loaded.doc)?)?;
        fork.get_map("tombstones")
            .delete(&share.space.to_hex())
            .expect("drop the tombstone");
        map_insert_bytes(&fork.get_map("entities"), &share.space.to_hex(), &original)?;
        fork.commit();
        import_doc(
            &loaded.doc,
            &export_updates_since(&fork, &doc_version_vector(&loaded.doc))?,
        )?;
        loaded.persist_state(&vault)?;
        assert!(
            !share.reads_as(&vault, share.member)?,
            "a withdrawn delete restores no membership"
        );

        // Nor does the explicit-tier import door, which replays a peer's row
        // without the window's ingest ladder.
        let replayed = crate::sync::replay::replay_entity(
            &vault,
            crate::sync::replay::ReplicatedEntity {
                id: share.space,
                entity_type: crate::registry::ENTITY_TYPE_RELATIONSHIP,
                occurred: crate::TimeRange { start: 1, end: 1 },
                learned_at: 1,
                body: &original[ENTITY_METADATA_HEADER_LEN..],
            },
            crate::sync::client::ImportTier::OwnDevice,
        );
        assert!(
            !share.reads_as(&vault, share.member)?,
            "a replayed body restores no membership"
        );
        assert!(replayed.is_err(), "the replicated put is refused");
        Ok(())
    }

    /// Bug repro (Astra #1322 finding 2): grants whose deletes this vault
    /// accepted but failed to apply, stored under a snapshot of their base
    /// window, authorize neither a companion profile read (the server's
    /// profile and context-assembly doors) nor a brief share, though their
    /// Active bodies are still stored.
    #[cfg(feature = "sync")]
    #[test]
    fn grants_a_peer_deleted_authorize_no_door() -> Result<()> {
        let (_dir, vault, issuer, share) =
            crate::share::tests::fixture_with_config(crate::test_util::embedding_test_config())?;
        let vault = std::sync::Arc::new(vault);
        let share_id = EntityId::now();
        let recipient = share.recipient_ref;
        vault.create_share(&share_id, &issuer, &share)?;
        let (principal, person, persona) = (EntityId::now(), EntityId::now(), EntityId::now());
        let profile_grant = EntityId::now();
        vault.create_access_grant(
            &profile_grant,
            &crate::AccessGrant::companion_profile_read(principal, person, persona, 10),
        )?;
        let profile = || vault.companion_profile_access_grant(&principal, &person, &persona);
        let brief = || vault.resolve_share_for_view(&share_id, &recipient, None, &[]);
        assert_eq!(profile()?, Some(profile_grant));
        assert!(brief()?.is_some());

        let window = base_window(&vault, &share_id)?;
        assert_eq!(base_window(&vault, &profile_grant)?, window);
        deliver_unapplied_peer_deletes(&vault, &window, &[share_id, profile_grant], true)?;
        assert_eq!(profile()?, None, "a deleted grant authorizes no profile");
        assert!(brief()?.is_none(), "a deleted share resolves no brief");
        Ok(())
    }

    /// Bug repro (Astra #1322 finding 3): a relationship delete this vault
    /// accepted but failed to apply, stored in a window holding only
    /// updates, grants nothing while its retry is pending.
    #[cfg(feature = "sync")]
    #[test]
    fn a_relationship_delete_that_failed_to_apply_grants_nothing() -> Result<()> {
        let (_dir, vault) =
            crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
        let vault = std::sync::Arc::new(vault);
        let share = RelationshipShare::new(&vault);
        assert!(share.reads_as(&vault, share.member)?);

        let window = base_window(&vault, &share.space)?;
        deliver_unapplied_peer_deletes(&vault, &window, &[share.space], false)?;
        assert!(
            !share.reads_as(&vault, share.member)?,
            "an accepted delete grants nothing before its retry lands"
        );
        Ok(())
    }

    /// Bug repro (Astra #1322 finding 4): a member binding that names a world
    /// lives in that world's window, and so does its tombstone. A peer's
    /// delete of it there, accepted but not applied, grants nothing.
    #[cfg(feature = "sync")]
    #[test]
    fn a_world_scoped_binding_a_peer_deleted_grants_nothing() -> Result<()> {
        let (_dir, vault) =
            crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
        let vault = std::sync::Arc::new(vault);
        let world = EntityId::now();
        let share = RelationshipShare::with_binding_world(&vault, Some(world));
        assert!(share.reads_as(&vault, share.member)?);

        let window = format!(
            "{}@{}",
            base_window(&vault, &share.binding)?,
            world.to_hex()
        );
        deliver_unapplied_peer_deletes(&vault, &window, &[share.binding], true)?;
        assert!(
            !share.reads_as(&vault, share.member)?,
            "a binding deleted in its world grants nothing"
        );
        Ok(())
    }

    /// Substrate check (Astra #1322 finding 4): the deletion resolver reads a
    /// world-scoped binding's published tombstone from the binding's world
    /// window, with no local apply to lean on, never from its base month.
    #[cfg(feature = "sync")]
    #[test]
    fn a_world_window_delete_is_read_from_the_bindings_world() -> Result<()> {
        use crate::sync::loro_support::{doc_version_vector, export_snapshot, map_insert_bytes};

        let (_dir, vault) =
            crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
        let world = EntityId::now();
        let share = RelationshipShare::with_binding_world(&vault, Some(world));
        assert!(share.reads_as(&vault, share.member)?);

        let state = loro::LoroDoc::new();
        map_insert_bytes(
            &state.get_map("tombstones"),
            &share.binding.to_hex(),
            &peer_soft_tombstone(),
        )?;
        state.commit();
        let window = format!(
            "{}@{}",
            base_window(&vault, &share.binding)?,
            world.to_hex()
        );
        let key = crate::sync::WindowKey::try_new(&window).expect("a window key");
        vault.with_write_txn(|txn| {
            crate::sync::window::persist_window_doc_in_txn(
                &vault,
                txn,
                &key,
                &export_snapshot(&state)?,
                &doc_version_vector(&state),
            )
        })?;
        assert!(has_body(&vault, &share.binding)?);
        assert!(
            !share.reads_as(&vault, share.member)?,
            "the world window's tombstone deletes the binding"
        );
        Ok(())
    }

    /// Bug repro (Astra #1322 finding 5): a relationship recreated at its id
    /// after a soft delete, with an empty body in a later month, is live
    /// again. A local recreation is sanctioned; only a peer's re-put is not.
    #[test]
    fn a_relationship_recreated_after_its_delete_grants_again() -> Result<()> {
        let (_dir, vault) =
            crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
        let share = RelationshipShare::new(&vault);
        assert!(vault.delete_entity(&share.space)?);
        assert!(!share.reads_as(&vault, share.member)?);

        // The original was learned at 1, in 1970-01.
        let later = 40 * 86_400;
        vault.put_entity(
            &share.space,
            crate::registry::ENTITY_TYPE_RELATIONSHIP,
            crate::TimeRange {
                start: later,
                end: later,
            },
            later,
            b"",
        )?;
        assert!(
            share.reads_as(&vault, share.member)?,
            "the recreated relationship grants its member again"
        );
        Ok(())
    }
}
