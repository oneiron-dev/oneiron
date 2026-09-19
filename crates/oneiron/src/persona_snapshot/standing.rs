//! Named (agent, world) standing blocks compiled from gated persona claims.
//! Handles are durable; compiled text is a node-local, disposable projection.
use crate::claim::ScopedReadActorKey;
use crate::consent::AuthenticatedOwner;
use crate::{
    ClaimApprovalStatus, ClaimCandidate, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EntityId, Error, Result, TimeRange, Vault, WriteActor, WriteEnvelope,
    WriteProvenance,
};
use rmpv::Value;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const PREFIX: &[u8] = b"standing.block.v1:";
const PERSONA_PREFIX: &str = "companion.standing.";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandingBlockHandle {
    handle: String,
    #[serde(with = "crate::serialize::entity_ref")]
    agent: EntityId,
    #[serde(with = "crate::serialize::entity_ref")]
    world: EntityId,
    name: String,
    token_floor: usize,
}
impl StandingBlockHandle {
    pub fn handle(&self) -> &str {
        &self.handle
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn token_floor(&self) -> usize {
        self.token_floor
    }
    pub fn agent(&self) -> EntityId {
        self.agent
    }
    pub fn world(&self) -> EntityId {
        self.world
    }
}
#[derive(Debug, Clone)]
pub enum StandingBlockEdit {
    Claim {
        field: String,
        value: Value,
        evidence: Value,
    },
    Text(String),
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandingBlockEviction {
    pub block: String,
    #[serde(with = "crate::serialize::entity_ref::sequence")]
    pub claims: Vec<EntityId>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandingBlockSession {
    pub block: String,
    pub reserved_tokens: usize,
    pub other_context_tokens: usize,
    pub compiled: Vec<u8>,
    pub eviction: StandingBlockEviction,
}
#[derive(Default)]
pub struct StandingBlockCache {
    compiled: BTreeMap<String, Vec<u8>>,
}
impl StandingBlockCache {
    pub fn get(&self, handle: &StandingBlockHandle) -> Option<&[u8]> {
        self.compiled.get(handle.handle()).map(Vec::as_slice)
    }
}
fn invalid() -> Error {
    Error::InvalidConfig(
        "standing block requires its stored handle and gated persona claims".into(),
    )
}
fn identity(agent: EntityId, world: EntityId) -> String {
    let mut hash = blake3::Hasher::new();
    hash.update(PREFIX);
    hash.update(agent.as_bytes());
    hash.update(world.as_bytes());
    hash.finalize().to_hex().to_string()
}
fn key(handle: &str) -> Vec<u8> {
    [PREFIX, handle.as_bytes()].concat()
}
fn decode(bytes: &[u8], expected: &str) -> Result<StandingBlockHandle> {
    let handle: StandingBlockHandle = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    if handle.handle != expected
        || identity(handle.agent, handle.world) != expected
        || handle.name.trim().is_empty()
        || handle.token_floor == 0
    {
        return Err(invalid());
    }
    Ok(handle)
}
impl Vault {
    /// Owner configuration, not a text editor. Reopening the pair returns the
    /// same handle; conflicting names/floors require an explicit configuration edit.
    pub fn open_standing_block(
        &self,
        _owner: &AuthenticatedOwner,
        agent: EntityId,
        world: EntityId,
        name: &str,
        token_floor: usize,
    ) -> Result<StandingBlockHandle> {
        if name.trim().is_empty() || name.len() > 128 || token_floor == 0 {
            return Err(invalid());
        }
        let handle = StandingBlockHandle {
            handle: identity(agent, world),
            agent,
            world,
            name: name.trim().into(),
            token_floor,
        };
        self.with_write_txn(|txn| {
            if self.store.entities.get(&*txn, agent.as_bytes())?.is_none()
                || self.store.entities.get(&*txn, world.as_bytes())?.is_none()
            {
                return Err(Error::EntityNotFound);
            }
            if let Some(raw) = self.store.vault_meta.get(&*txn, &key(&handle.handle))? {
                let stored = decode(&raw, &handle.handle)?;
                if stored != handle {
                    return Err(invalid());
                }
                return Ok(stored);
            }
            let bytes = serde_json::to_vec(&handle).map_err(|_| invalid())?;
            self.store
                .vault_meta
                .put(txn, &key(&handle.handle), &bytes)?;
            Ok(handle)
        })
    }
    pub fn standing_block(
        &self,
        agent: EntityId,
        world: EntityId,
    ) -> Result<Option<StandingBlockHandle>> {
        let reference = identity(agent, world);
        let txn = self.store.env.read_txn()?;
        self.store
            .vault_meta
            .get(&txn, &key(&reference))?
            .map(|bytes| decode(&bytes, &reference))
            .transpose()
    }
    fn check_standing_handle(&self, handle: &StandingBlockHandle) -> Result<()> {
        if self.standing_block(handle.agent, handle.world)?.as_ref() != Some(handle) {
            return Err(invalid());
        }
        Ok(())
    }
    /// Self edits are Generated, Proposed and persona-isolated. No body supplied
    /// by an agent can set approval, subject, world, author, or source.
    pub fn edit_standing_block(
        &self,
        handle: &StandingBlockHandle,
        actor: WriteActor,
        run_ref: &str,
        edit: StandingBlockEdit,
    ) -> Result<EntityId> {
        self.check_standing_handle(handle)?;
        if actor.entity_ref() != handle.agent
            || actor.actor_class() != EdgeActorClass::Agent
            || run_ref.trim().is_empty()
        {
            return Err(invalid());
        }
        let StandingBlockEdit::Claim {
            field,
            value,
            evidence,
        } = edit
        else {
            return Err(invalid());
        };
        if field.is_empty()
            || !field
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_')
        {
            return Err(invalid());
        }
        let envelope = WriteEnvelope::new(
            actor,
            ClaimSource::Generated,
            WriteProvenance::new(Value::Map(vec![
                (
                    Value::from("runner"),
                    Value::from(crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND),
                ),
                (Value::from("run_id"), Value::from(run_ref)),
                (
                    Value::from("standing_block"),
                    Value::from(handle.handle.as_str()),
                ),
            ]))?,
            ClaimApprovalStatus::Proposed,
        );
        let candidate = ClaimCandidate::new(
            format!("{PERSONA_PREFIX}{field}"),
            ClaimSubject::Entity(handle.agent),
            value,
            1.0,
        )
        .with_world(handle.world)
        .with_evidence(evidence);
        let id = EntityId::now();
        let now = crate::unix_seconds_now();
        self.batch()
            .claim_candidate(
                &id,
                candidate,
                &envelope,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
            )
            .commit()?;
        Ok(id)
    }
    /// Reserve this block before any other context fills. Whole claims are
    /// evicted least-salient first, then by id. No source claim is deleted.
    pub fn begin_standing_block_session(
        &self,
        handle: &StandingBlockHandle,
        reader: ScopedReadActorKey,
        total_tokens: usize,
        block_tokens: usize,
        cache: &mut StandingBlockCache,
    ) -> Result<StandingBlockSession> {
        self.check_standing_handle(handle)?;
        if reader.actor_ref() != handle.agent.to_hex()
            || block_tokens < handle.token_floor
            || block_tokens > total_tokens
        {
            return Err(invalid());
        }
        let scoped = self.scoped_read(reader);
        let mut claims = Vec::new();
        for id in self.claims_for_subject(&handle.agent)? {
            if !scoped.is_entity_readable(&id)? {
                continue;
            }
            let Some(body) = self.get_claim(&id)? else {
                continue;
            };
            if body.subject != ClaimSubject::Entity(handle.agent)
                || body.world != Some(handle.world)
                || !body.predicate.starts_with(PERSONA_PREFIX)
                || !matches!(
                    body.approval,
                    ClaimApprovalStatus::Approved | ClaimApprovalStatus::Auto
                )
                || body.lifecycle != ClaimLifecycleStatus::Active
                || body.stale
            {
                continue;
            }
            let Some(text) = body.value.as_str() else {
                return Err(invalid());
            };
            claims.push((
                id,
                body.salience.unwrap_or(0.0),
                format!("{}: {}", body.predicate, text),
            ));
        }
        claims.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let mut eviction = StandingBlockEviction {
            block: handle.handle.clone(),
            claims: Vec::new(),
        };
        let compiled = loop {
            let text = claims
                .iter()
                .map(|row| row.2.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            if crate::tokenizer::count_context_pack_tokens(&text) <= block_tokens {
                break text.into_bytes();
            }
            let Some((id, _, _)) = claims.pop() else {
                return Err(invalid());
            };
            eviction.claims.push(id);
        };
        cache
            .compiled
            .insert(handle.handle.clone(), compiled.clone());
        Ok(StandingBlockSession {
            block: handle.handle.clone(),
            reserved_tokens: block_tokens,
            other_context_tokens: total_tokens - block_tokens,
            compiled,
            eviction,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::ENTITY_TYPE_PERSON;
    use crate::test_util::{embedding_test_config, entity, open_test_vault_with};
    #[test]
    fn handles_refuse_text_and_session_floor_evictions_rebuild_deterministically() -> Result<()> {
        let (_dir, vault) = open_test_vault_with(embedding_test_config());
        let actor = entity(0x51);
        let world = entity(0x52);
        let at = TimeRange { start: 1, end: 1 };
        for id in [actor, world] {
            vault.put_entity(&id, ENTITY_TYPE_PERSON, at, 1, b"fixture")?;
        }
        let owner = vault.authenticate_owner(
            actor,
            &actor.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )?;
        let handle = vault.open_standing_block(&owner, actor, world, "identity", 4)?;
        assert_eq!(vault.standing_block(actor, world)?.as_ref(), Some(&handle));
        assert!(
            vault
                .edit_standing_block(
                    &handle,
                    WriteActor::new(actor, EdgeActorClass::Agent),
                    "run",
                    StandingBlockEdit::Text("bypass".into())
                )
                .is_err()
        );
        let mut note = crate::ClaimBody::new(
            "companion.standing.preference",
            ClaimSubject::Entity(actor),
            Value::from("A deliberately long persona claim that cannot fit in four tokens"),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        note.source = Some(ClaimSource::UserStated);
        note.world = Some(world);
        note.scope = Some(Value::Map(vec![(
            Value::from("sensitivity"),
            Value::from("public"),
        )]));
        let claim = entity(0x53);
        vault.put_claim(&claim, &note, at, 1)?;
        let reader = ScopedReadActorKey::new(actor.to_hex()).ok_or_else(invalid)?;
        let mut cache = StandingBlockCache::default();
        let first =
            vault.begin_standing_block_session(&handle, reader.clone(), 20, 4, &mut cache)?;
        let second = vault.begin_standing_block_session(
            &handle,
            reader,
            20,
            4,
            &mut StandingBlockCache::default(),
        )?;
        assert_eq!(first, second);
        assert_eq!(first.reserved_tokens, 4);
        assert_eq!(first.other_context_tokens, 16);
        assert_eq!(first.eviction.claims, vec![claim]);
        assert_eq!(cache.get(&handle), Some(first.compiled.as_slice()));
        assert!(vault.get_claim(&claim)?.is_some());
        Ok(())
    }
}
