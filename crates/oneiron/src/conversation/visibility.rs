//! The audience predicate shared by all ScopedRead paths.
use super::*;
use crate::{
    EdgeKind,
    registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_RELATIONSHIP},
};
use std::collections::{BTreeMap, BTreeSet};

/// Immutable ledger snapshots, keyed by the version read in the caller's
/// transaction. Reusing a ScopedRead after a kick cannot reuse stale authority.
#[derive(Default)]
pub(crate) struct AudienceCache {
    rows: BTreeMap<(EntityId, u64), Vec<MembershipRow>>,
    ledger_reads: usize,
}
impl AudienceCache {
    pub(crate) fn ledger_reads(&self) -> usize {
        self.ledger_reads
    }
}
impl AudienceCache {
    pub(crate) fn readable(
        &mut self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
        audience: &[EntityId],
    ) -> Result<bool> {
        self.readable_at_depth(vault, txn, id, audience, 0)
    }
    fn readable_at_depth(
        &mut self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
        audience: &[EntityId],
        depth: usize,
    ) -> Result<bool> {
        if depth > 64 {
            return Ok(false);
        }
        let Some(raw) = vault.store.entities.get(txn, id.as_bytes())? else {
            return Ok(false);
        };
        let h =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("audience header"))?;
        if let Some(room) = room_for_record_in(vault, txn, id)? {
            if audience.is_empty() {
                return Ok(false);
            }
            body::body_in(vault, txn, room)?;
            let revision = vault
                .store
                .vault_meta
                .get(txn, &key(b"conversation_membership:seq:v1:", room))?
                .map(|v| {
                    v.as_ref()
                        .try_into()
                        .map(u64::from_be_bytes)
                        .map_err(|_| Error::CorruptedIndex("membership revision"))
                })
                .transpose()?
                .unwrap_or(0);
            if !self.rows.contains_key(&(room, revision)) {
                if self.rows.len() >= 1024 {
                    self.rows.clear();
                }
                self.rows.insert(
                    (room, revision),
                    membership::rows_in(&vault.store, txn, room)?,
                );
                self.ledger_reads = self.ledger_reads.saturating_add(1);
            }
            let rows = self
                .rows
                .get(&(room, revision))
                .ok_or(Error::CorruptedIndex("audience snapshot"))?;
            for person in audience {
                if !membership::windows_rows(rows, *person)?
                    .iter()
                    .any(|w| w.contains(h.occurred_start))
                {
                    return Ok(false);
                }
            }
        }
        if h.entity_type == ENTITY_TYPE_CLAIM {
            let claim = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
            if claim.predicate == "conversation.summary" {
                let rmpv::Value::Map(entries) = &claim.value else {
                    return Ok(false);
                };
                let Some((_, rmpv::Value::Array(covers))) =
                    entries.iter().find(|(k, _)| k.as_str() == Some("covers"))
                else {
                    return Ok(false);
                };
                if covers.is_empty() {
                    return Ok(false);
                }
                for covered in covers {
                    let rmpv::Value::Binary(raw) = covered else {
                        return Ok(false);
                    };
                    let id = EntityId::from_bytes(
                        raw.as_slice()
                            .try_into()
                            .map_err(|_| invalid("summary coverage"))?,
                    )?;
                    if !self.readable_at_depth(vault, txn, id, audience, depth + 1)? {
                        return Ok(false);
                    }
                }
            }
            if let Some(relationship) = claim.rel {
                if audience.is_empty() {
                    return Ok(false);
                }
                let rel = require_kind(vault, txn, relationship, ENTITY_TYPE_RELATIONSHIP)?;
                let mut participants =
                    dag::peers(vault, txn, relationship, EdgeKind::ParticipatesIn, true)?;
                // Relationship participant ids are a read-path feed, not a
                // replacement for scope/tier authorization or room windows.
                if let Ok(value) = decode::<serde_json::Value>(&rel[ENTITY_METADATA_HEADER_LEN..])
                    && let Some(ids) = value.get("participant_ids")
                {
                    let body_ids: Vec<EntityId> = serde_json::from_value(ids.clone())
                        .map_err(|_| invalid("relationship participants"))?;
                    participants.extend(body_ids);
                }
                if audience.iter().any(|person| !participants.contains(person)) {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
}

pub(crate) fn room_for_record_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: EntityId,
) -> Result<Option<EntityId>> {
    let mut pending = vec![record];
    let mut seen = BTreeSet::new();
    let mut room = None;
    while let Some(id) = pending.pop() {
        if !seen.insert(id) {
            continue;
        }
        if seen.len() > MAX_ANCESTOR_DEPTH {
            return Err(state("room ancestor depth bound"));
        }
        let Some(raw) = vault.store.entities.get(txn, id.as_bytes())? else {
            return Err(Error::EntityNotFound);
        };
        let h = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("room ancestor"))?;
        if h.entity_type == ENTITY_TYPE_CONVERSATION {
            if room.is_some_and(|r| r != id) {
                return Err(state("ambiguous room"));
            }
            room = Some(id);
            continue;
        }
        for kind in [
            EdgeKind::ChildOf,
            EdgeKind::PartOf,
            EdgeKind::Parent,
            EdgeKind::RepliesTo,
            EdgeKind::SpawnedBy,
            EdgeKind::BelongsTo,
        ] {
            pending.extend(dag::peers(vault, txn, id, kind, false)?);
        }
        if h.entity_type == ENTITY_TYPE_CLAIM {
            let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
            if let crate::claim::ClaimSubject::Entity(subject) = body.subject {
                pending.push(subject);
            }
        }
    }
    Ok(room)
}
impl Vault {
    pub fn record_visible_to(&self, record: EntityId, person: EntityId) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        AudienceCache::default().readable(self, &txn, record, &[person])
    }
    /// The room audience is membership, never runtime presence.
    pub fn scoped_read_for_room(
        &self,
        actor: crate::claim::ScopedReadActorKey,
        room: EntityId,
    ) -> Result<crate::claim::ScopedRead<'_>> {
        Ok(self.scoped_read(actor).for_audience(&self.members(room)?))
    }
}
