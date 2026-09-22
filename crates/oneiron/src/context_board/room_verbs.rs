//! The rooms.* facade family delegates to existing reads, witness and claim gates.

use super::room::{RoomBar, RoomMode, RoomPosture, RoomPresence, RoomSection, room_scope};
use crate::EntityId;
use crate::memory::{ClaimListFilter, EntityView, Memory, MemoryError, MemoryResult};

impl Memory<'_> {
    /// Presence is host state, while membership, authority and rules are fresh
    /// vault reads. No copy of the board or of posture is stored anywhere.
    pub fn rooms_render(
        &self,
        room: EntityId,
        presence: &[RoomPresence],
    ) -> MemoryResult<RoomSection> {
        let members = require_member(self, room)?;
        let present: std::collections::BTreeSet<_> =
            presence.iter().map(|entry| entry.actor).collect();
        if !presence
            .iter()
            .any(|entry| entry.actor == self.actor() && entry.present)
            || present.len() != presence.len()
            || presence.iter().any(|entry| !members.contains(&entry.actor))
        {
            return Err(MemoryError::bad_request_with(
                "room presence must name unique current members",
                &[],
            ));
        }
        let now = crate::unix_seconds_now();
        let txn = self
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        for member in presence.iter().filter(|member| member.present) {
            let kind = self
                .vault()
                .get_entity_type_in_txn(&txn, &member.actor)?
                .ok_or_else(|| MemoryError::bad_request_with("missing room actor", &[]))?;
            let class = member.actor_class.ok_or_else(|| {
                MemoryError::bad_request_with(
                    "present room actor requires authenticated class",
                    &[],
                )
            })?;
            crate::provenance::validate_actor_class(kind, class)?;
            if member.actor == self.actor() && class != self.actor_class() {
                return Err(MemoryError::bad_request_with(
                    "room actor class differs from bound caller",
                    &[],
                ));
            }
            crate::pipeline::resolve_world_authority(
                &self.vault().store,
                &txn,
                &crate::pipeline::ActiveWorldSelection {
                    agent_ref: member.actor,
                    selected: Some(member.active_worlds.clone()),
                },
                now,
            )?;
        }
        drop(txn);
        let scope = room_scope(presence)?;
        let mut roster = presence.to_vec();
        for member in members {
            if !present.contains(&member) {
                roster.push(RoomPresence {
                    actor: member,
                    actor_class: None,
                    label: member.to_hex(),
                    present: false,
                    active_worlds: Default::default(),
                });
            }
        }
        roster.sort_by_key(|member| member.actor);
        let key = crate::claim::ScopedReadActorKey::with_actor_class(
            self.actor().to_hex(),
            self.actor_class().gate_actor_class(),
        )
        .ok_or_else(|| MemoryError::bad_request_with("invalid room actor", &[]))?;
        let read = self.vault().scoped_read(key);
        // The roster meets both world authority above and each participant's
        // ordinary read grants here. A host label cannot widen a participant.
        let peers: Vec<_> = presence
            .iter()
            .filter(|member| member.present && member.actor != self.actor())
            .map(|member| {
                crate::claim::ScopedReadActorKey::with_actor_class(
                    member.actor.to_hex(),
                    member
                        .actor_class
                        .ok_or_else(|| {
                            MemoryError::bad_request_with(
                                "present room actor requires authenticated class",
                                &[],
                            )
                        })?
                        .gate_actor_class(),
                )
                .map(|key| self.vault().scoped_read(key))
                .ok_or_else(|| MemoryError::bad_request_with("invalid room actor", &[]))
            })
            .collect::<MemoryResult<_>>()?;
        let mut claims = Vec::new();
        let mut posture = RoomPosture::default();
        let mut has_bar = false;
        for claim in self.claim_list(&ClaimListFilter {
            subject_ref: Some(room.to_hex()),
            predicate: None,
            lifecycle: Some("active".into()),
            // The native subject scan fails closed at its work bound. Room
            // output spends its own cap only after all visibility predicates.
            limit: crate::vault::MAX_EDGE_QUERY_RESULTS,
        })? {
            let id = EntityId::from_hex(&claim.claim_ref)?;
            if read.get(&id)?.is_none()
                || claim
                    .world_ref
                    .as_deref()
                    .map_or(!scope.include_base(), |id| {
                        EntityId::from_hex(id).map_or(true, |id| !scope.worlds().contains(&id))
                    })
            {
                continue;
            }
            let mut peers_admit = true;
            for peer in &peers {
                if peer.get(&id)?.is_none() {
                    peers_admit = false;
                    break;
                }
            }
            if !peers_admit {
                continue;
            }
            if claims.len() == 1000 {
                return Err(crate::Error::IndexOverflow("visible room claims").into());
            }
            match (claim.predicate.as_str(), claim.value.as_str()) {
                ("room.posture.mode", Some(mode)) => {
                    posture.mode = posture.mode.max(match mode {
                        "chime" => RoomMode::Chime,
                        "asked_only" => RoomMode::AskedOnly,
                        "silent" => RoomMode::Silent,
                        _ => {
                            return Err(MemoryError::bad_request_with(
                                "invalid room posture mode",
                                &[],
                            ));
                        }
                    });
                }
                ("room.posture.bar", Some(bar)) => {
                    let bar = match bar {
                        "low" => RoomBar::Low,
                        "med" => RoomBar::Med,
                        "high" => RoomBar::High,
                        _ => {
                            return Err(MemoryError::bad_request_with(
                                "invalid room posture bar",
                                &[],
                            ));
                        }
                    };
                    posture.bar = if has_bar { posture.bar.max(bar) } else { bar };
                    has_bar = true;
                }
                _ => {}
            }
            claims.push(claim);
        }
        claims.sort_by(|a, b| a.claim_ref.cmp(&b.claim_ref));
        Ok(RoomSection {
            room,
            roster,
            scope,
            posture,
            claims,
        })
    }
}

fn require_member(memory: &Memory<'_>, id: EntityId) -> MemoryResult<Vec<EntityId>> {
    let view = memory
        .get_entity(&id.to_hex())?
        .ok_or_else(|| MemoryError::bad_request_with("unknown room", &[]))?;
    let members = member_ids(&view)?;
    if !members.contains(&memory.actor()) {
        return Err(MemoryError::bad_request_with(
            "room actor is not a member",
            &[],
        ));
    }
    Ok(members)
}
fn member_ids(view: &EntityView) -> MemoryResult<Vec<EntityId>> {
    if view.kind != "CONVERSATION"
        || view
            .body
            .as_ref()
            .and_then(|body| body.get("kind"))
            .and_then(serde_json::Value::as_str)
            != Some("channel")
    {
        return Err(MemoryError::bad_request_with(
            "room must be a channel Conversation",
            &[],
        ));
    }
    let members = view
        .body
        .as_ref()
        .and_then(|body| body.get("memberIds"))
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| MemoryError::bad_request_with("channel memberIds must be an array", &[]))?;
    if members.len() > 1000 {
        return Err(MemoryError::bad_request_with(
            "room roster exceeds bound",
            &[],
        ));
    }
    members
        .iter()
        .map(|id| {
            id.as_str()
                .ok_or_else(|| {
                    MemoryError::bad_request_with("room member must be an entity ref", &[])
                })
                .and_then(|id| EntityId::from_hex(id).map_err(MemoryError::from))
        })
        .collect()
}

/// Checks current channel membership in the write transaction, not a prior
/// view. Used by both of the existing gated facade writers.
pub(crate) fn require_room_member_in_txn(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
) -> MemoryResult<()> {
    let raw = memory
        .vault()
        .get_raw_in(txn, &room)?
        .ok_or_else(|| MemoryError::bad_request_with("unknown room", &[]))?;
    let header = crate::batch::EntityMetadataHeader::parse(&raw)
        .ok_or(crate::Error::CorruptedIndex("room entity header"))?;
    if header.entity_type != crate::registry::ENTITY_TYPE_CONVERSATION {
        return Err(MemoryError::bad_request_with(
            "room must be a channel Conversation",
            &[],
        ));
    }
    let body = crate::companion::companion_value_to_json(
        &rmpv::decode::read_value(&mut &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])
            .map_err(|_| MemoryError::bad_request_with("invalid room body", &[]))?,
    );
    let members = body.get("memberIds").and_then(serde_json::Value::as_array);
    if body.get("kind").and_then(serde_json::Value::as_str) != Some("channel")
        || members.is_none_or(|members| {
            members.len() > 1000
                || !members.iter().any(|value| {
                    value.as_str().and_then(|id| EntityId::from_hex(id).ok())
                        == Some(memory.actor())
                })
        })
    {
        return Err(MemoryError::bad_request_with(
            "room actor is not a member",
            &[],
        ));
    }
    Ok(())
}
