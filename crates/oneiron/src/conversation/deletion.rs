//! Actor-bound room deletion and per-person erasure over the existing delete door.
use super::*;
use crate::conversation_dag::{actor_in_txn, conversation_of, edge_ids, require_type};
use crate::deletion::{DeleteEntityOutcome, DeleteReason, DeletionGateContext, GatedDeletion};
use crate::edge::EdgeKind;
use crate::ports::EntityStoreRead;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use rmpv::Value;
use std::collections::BTreeSet;

/// A host-local erasure fence: a completed sweep cannot be followed by a new
/// locally authored turn from the erased PERSON in this room.
pub(crate) fn erasure_key(room: EntityId, person: EntityId) -> Vec<u8> {
    [
        b"conversation:erased_person:v1:".as_slice(),
        room.as_bytes(),
        person.as_bytes(),
    ]
    .concat()
}

fn record_author(body: &[u8]) -> Result<EntityId> {
    let mut bytes = body;
    let Value::Map(fields) =
        rmpv::decode::read_value(&mut bytes).map_err(|_| invalid("invalid room record"))?
    else {
        return Err(invalid("invalid room record"));
    };
    if !bytes.is_empty() {
        return Err(invalid("trailing room record bytes"));
    }
    let mut authors = fields.iter().filter(|(k, _)| k.as_str() == Some("actor"));
    let author = authors
        .next()
        .and_then(|(_, value)| value.as_str())
        .ok_or(invalid("room record lacks author"))?;
    if authors.next().is_some() {
        return Err(invalid("duplicate room author"));
    }
    EntityId::from_hex(author).map_err(|_| invalid("invalid room author"))
}

fn check_delete(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    record: EntityId,
    actor: WriteActor,
    reason: DeleteReason,
    subject: Option<EntityId>,
) -> Result<RoomRole> {
    actor_in_txn(&vault.store, txn, actor)?;
    if conversation_of(&vault.store, txn, &record)? != room {
        return Err(denied());
    }
    let body = require_type(&vault.store, txn, &record, ENTITY_TYPE_TURN)?;
    let author = record_author(&body)?;
    match reason {
        DeleteReason::UserDelete | DeleteReason::UserHardDelete if author == actor.entity_ref() => {
            authorize(vault, txn, actor)?;
            Ok(RoomRole::Member)
        }
        DeleteReason::PolicyDelete => {
            let role = roles::role_in(vault, txn, room, actor)?;
            if matches!(role, RoomRole::Owner | RoomRole::Admin) {
                Ok(role)
            } else {
                Err(denied())
            }
        }
        DeleteReason::GdprDelete if subject == Some(author) => {
            let role = if actor.entity_ref() == author {
                authorize(vault, txn, actor)?;
                RoomRole::Member
            } else {
                let role = roles::role_in(vault, txn, room, actor)?;
                if !matches!(role, RoomRole::Owner | RoomRole::Admin) {
                    return Err(denied());
                }
                role
            };
            Ok(role)
        }
        _ => Err(denied()),
    }
}

/// Soft erase removes the author field before sync publication rechecks its
/// authority. The initial read and first scrub transaction already proved
/// the append-only author stamp. On the later shell, recheck the actor binding and
/// room link; never turn a missing/replaced target into an authorization.
fn reverify_record_delete(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    record: EntityId,
    actor: WriteActor,
    reason: DeleteReason,
    subject: Option<EntityId>,
) -> Result<()> {
    if reason == DeleteReason::UserDelete
        && matches!(
            crate::vault::live_entity_row_in_txn(&vault.store, txn, &record)?,
            crate::vault::LiveEntityRow::DeletedShell
        )
    {
        if edge_ids(&vault.store, txn, &record, EdgeKind::ChildOf, false, 2)? != [room] {
            return Err(denied());
        }
        body::body_in(vault, txn, room)?;
        return authorize(vault, txn, actor);
    }
    check_delete(vault, txn, room, record, actor, reason, subject).map(|_| ())
}

/// Capture derived claims that would otherwise have no surviving evidence.
/// Hide them first, before tearing the cited turns, so a failed sweep cannot
/// temporarily expose a free-floating claim. Internal history is erased too.
fn unsupported_claims(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    targets: &BTreeSet<EntityId>,
) -> Result<Vec<(EntityId, EntityId)>> {
    let mut claims = Vec::new();
    for (n, entry) in vault
        .store
        .port_entity_ids_by_type(txn, ENTITY_TYPE_CLAIM, None)?
        .enumerate()
    {
        if n >= 100_000 {
            return Err(Error::IndexOverflow("room erasure claim scan"));
        }
        let id = entry?;
        let Some(row) = vault.store.port_entity_record(txn, &id)? else {
            continue;
        };
        if row.entity_type != ENTITY_TYPE_CLAIM || row.body.is_empty() {
            continue;
        }
        let body = crate::claim::decode_claim_body(&row.body, true)?;
        let actor = crate::actor_claims::actor_archive_references(&body);
        let refs = if let Some(Some((_, turns))) = actor.map(|refs| refs.chat) {
            turns
        } else if crate::actor_claims::is_actor_claim_predicate(&body.predicate)
            && body.evidence.as_ref().is_some_and(|evidence| {
                evidence.as_map().is_some_and(|fields| {
                    fields
                        .iter()
                        .any(|(k, v)| k.as_str() == Some("lane") && v.as_str() == Some("chat"))
                })
            })
        {
            return Err(Error::InvalidClaimBody("invalid room chat evidence"));
        } else if let Some(evidence) = &body.evidence {
            match crate::dreamer_consolidation::decode_consolidation_evidence(evidence)? {
                Some(envelope) => envelope.refs,
                None => continue,
            }
        } else {
            continue;
        };
        let Some(anchor) = refs.iter().find(|id| targets.contains(id)).copied() else {
            continue;
        };
        let mut sole_erased = true;
        for reference in &refs {
            if !targets.contains(reference)
                && crate::vault::live_entity_row_in_txn(&vault.store, txn, reference)?.is_live()
            {
                sole_erased = false;
                break;
            }
        }
        if sole_erased {
            claims.push((id, anchor));
        }
    }
    Ok(claims)
}

impl Vault {
    fn hide_claims(
        &self,
        room: EntityId,
        actor: WriteActor,
        reason: DeleteReason,
        subject: Option<EntityId>,
        claims: Vec<(EntityId, EntityId)>,
    ) -> Result<()> {
        for (claim, anchor) in claims {
            let txn = self.store.env.read_txn()?;
            let role = check_delete(self, &txn, room, anchor, actor, reason, subject)?;
            let policy = crate::gate::resolve_policy_manifest(&self.store, &txn)?;
            let context = DeletionGateContext::new_room(
                actor.entity_ref(),
                actor.actor_class(),
                crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
                policy.read_frontier_hash()?,
                room,
                role,
            );
            drop(txn);
            let reverify = |txn: &heed::RoTxn<'_>| {
                check_delete(self, txn, room, anchor, actor, reason, subject).map(|_| ())
            };
            self.delete_entity_with_reason_gated(
                &claim,
                reason,
                GatedDeletion::new(context, &reverify),
            )?;
        }
        Ok(())
    }

    fn delete_room_record_as(
        &self,
        room: EntityId,
        record: EntityId,
        actor: WriteActor,
        reason: DeleteReason,
        subject: Option<EntityId>,
    ) -> Result<DeleteEntityOutcome> {
        let txn = self.store.env.read_txn()?;
        let role = check_delete(self, &txn, room, record, actor, reason, subject)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &txn)?;
        let context = DeletionGateContext::new_room(
            actor.entity_ref(),
            actor.actor_class(),
            crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
            policy.read_frontier_hash()?,
            room,
            role,
        );
        drop(txn);
        let reverify = |txn: &heed::RoTxn<'_>| {
            reverify_record_delete(self, txn, room, record, actor, reason, subject)
        };
        self.delete_entity_with_reason_gated(
            &record,
            reason,
            GatedDeletion::new(context, &reverify),
        )
    }

    /// Deletes a room record as its author, or as a room owner/admin for policy.
    /// The underlying receipt is correlated to the actor/role gate decision.
    pub fn delete_room_record(
        &self,
        room: EntityId,
        record: EntityId,
        actor: WriteActor,
        reason: DeleteReason,
    ) -> Result<DeleteEntityOutcome> {
        if !matches!(
            reason,
            DeleteReason::UserDelete | DeleteReason::UserHardDelete | DeleteReason::PolicyDelete
        ) {
            return Err(denied());
        }
        let txn = self.store.env.read_txn()?;
        check_delete(self, &txn, room, record, actor, reason, None)?;
        let claims = unsupported_claims(self, &txn, &BTreeSet::from([record]))?;
        drop(txn);
        self.hide_claims(room, actor, reason, None, claims)?;
        self.delete_room_record_as(room, record, actor, reason, None)
    }

    /// Hard-erases all live records this PERSON authored in the room, including
    /// thread and retained sub-session turns. A partial failure is retryable:
    /// already-erased ids disappear from the ChildOf traversal, not the ledger.
    pub fn erase_room_person(
        &self,
        room: EntityId,
        person: EntityId,
        actor: WriteActor,
    ) -> Result<Vec<DeleteEntityOutcome>> {
        // Collect and fence against new local appends in ONE writer snapshot.
        // A retry sees the fence and completes any work left by a failure.
        let (targets, claims) = self.with_write_txn(|txn| {
            require_kind(self, txn, person, ENTITY_TYPE_PERSON)?;
            if person != actor.entity_ref() {
                let role = roles::role_in(self, txn, room, actor)?;
                if !matches!(role, RoomRole::Owner | RoomRole::Admin) {
                    return Err(denied());
                }
            } else {
                authorize(self, txn, actor)?;
            }
            body::body_in(self, txn, room)?;
            let ids = edge_ids(
                &self.store,
                txn,
                &room,
                EdgeKind::ChildOf,
                true,
                crate::limits::MAX_ANCESTOR_DEPTH,
            )?;
            let mut targets = Vec::new();
            for id in ids {
                if !crate::vault::live_entity_row_in_txn(&self.store, txn, &id)?.is_live() {
                    continue;
                }
                if record_author(&require_type(&self.store, txn, &id, ENTITY_TYPE_TURN)?)? == person
                {
                    targets.push(id);
                }
            }
            let targets_set: BTreeSet<_> = targets.iter().copied().collect();
            let claims = unsupported_claims(self, txn, &targets_set)?;
            self.store
                .vault_meta
                .put(txn, &erasure_key(room, person), &[1])?;
            Ok((targets, claims))
        })?;
        self.hide_claims(room, actor, DeleteReason::GdprDelete, Some(person), claims)?;
        targets
            .into_iter()
            .map(|record| {
                self.delete_room_record_as(
                    room,
                    record,
                    actor,
                    DeleteReason::GdprDelete,
                    Some(person),
                )
            })
            .collect()
    }
}
