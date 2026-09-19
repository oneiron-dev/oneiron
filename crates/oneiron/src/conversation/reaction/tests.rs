//! CONV-09 behavioral acceptance, replay, and batch-read laws.
use super::*;
use crate::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_REACTION};
use crate::{EdgeActorClass, EdgeKind, EntityId, Vault, VaultConfig};
use proptest::prelude::*;

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    people: Vec<EntityId>,
    room: EntityId,
    messages: Vec<EntityId>,
}
impl Fixture {
    fn new(count: usize) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
        let mut people = vec![];
        for byte in 1..=4 {
            let id = EntityId::from_bytes([byte; 16]).unwrap();
            vault
                .put_entity(
                    &id,
                    ENTITY_TYPE_PERSON,
                    crate::temporal::TimeRange { start: 1, end: 1 },
                    1,
                    b"person",
                )
                .unwrap();
            people.push(id);
        }
        let room = EntityId::from_bytes([15; 16]).unwrap();
        let memory = vault.memory(people[0], EdgeActorClass::Human);
        let witnessed = memory
            .witness(&WitnessTurn {
                conversation_ref: room.to_hex(),
                turn_ref: None,
                occurred_at: 100,
                messages: (0..count)
                    .map(|order| WitnessMessage {
                        id: None,
                        author: WitnessAuthor::User,
                        message_type: "dialogue".into(),
                        content: format!("message {order}"),
                        metadata: None,
                        is_visible: true,
                        order: order as u32,
                    })
                    .collect(),
            })
            .unwrap();
        let messages = witnessed
            .message_short_ids
            .iter()
            .map(|r| EntityId::from_hex(&memory.get_entity(r).unwrap().unwrap().id_hex).unwrap())
            .collect();
        for person in &people {
            vault
                .batch()
                .edge_with_created_at(person, EdgeKind::ParticipatesIn, &room, 1.0, 50)
                .commit()
                .unwrap();
        }
        Self {
            _dir: dir,
            vault,
            people,
            room,
            messages,
        }
    }
    fn input(&self, message: usize, person: usize, glyph: &str) -> ReactInput {
        ReactInput {
            message: self.messages[message],
            by: self.people[person],
            glyph: glyph.into(),
            at: 200,
            ext: None,
        }
    }
    fn toggle(&self, message: usize, person: usize, glyph: &str) -> ReactOutcome {
        self.vault
            .react(&self.people[person], self.input(message, person, glyph))
            .unwrap()
    }
    fn pills(&self, message: usize, viewer: usize) -> Vec<ReactionPill> {
        self.vault
            .grouped_reaction_pills(&[self.messages[message]], &self.people[viewer])
            .unwrap()
            .remove(0)
            .pills
    }
}

#[test]
fn t1_t2_toggle_appends_tombstones_and_rebuilds_put_and_revoked_signals() {
    let f = Fixture::new(1);
    let first = f.toggle(0, 1, "👀");
    assert_eq!(first.state, ReactionState::Put);
    assert_eq!(f.pills(0, 0)[0].count, 1);
    let revoked = f.toggle(0, 1, "👀");
    assert_eq!(
        revoked,
        ReactOutcome {
            state: ReactionState::Revoked,
            reaction_id: first.reaction_id
        }
    );
    assert!(f.pills(0, 0).is_empty());
    // Tombstone keeps the original record as audit data, not a mutable flag.
    let body = decode_reaction_body(&f.vault.get(&first.reaction_id).unwrap().unwrap()).unwrap();
    assert_eq!(body.by, f.people[1]);
    assert_eq!(body.at, 200);
    let signals = f.vault.reactions_since(&f.people[0], 0).unwrap();
    assert_eq!(signals.len(), 2);
    assert!(signals.iter().any(|s| s.kind == ReactionSignalKind::Put));
    assert!(
        signals
            .iter()
            .any(|s| s.kind == ReactionSignalKind::Revoked)
    );
    f.vault
        .with_write_txn(|txn| {
            let keys: Vec<Vec<u8>> = f
                .vault
                .store
                .vault_meta
                .prefix_iter(txn, REACTION_INBOX_KEY_PREFIX)?
                .map(|e| e.map(|(k, _)| k.to_vec()))
                .collect::<std::result::Result<_, _>>()?;
            for k in keys {
                f.vault.store.vault_meta.delete(txn, &k)?;
            }
            Ok(())
        })
        .unwrap();
    f.vault.rebuild_reaction_inbox().unwrap();
    assert_eq!(f.vault.reactions_since(&f.people[0], 0).unwrap(), signals);
    let next = f.toggle(0, 1, "👀");
    assert_ne!(next.reaction_id, first.reaction_id);
    assert_eq!(f.pills(0, 1)[0].count, 1);
}

#[test]
fn t3_external_delivery_is_same_record_even_after_revoke_and_capability_controls_queue() {
    let f = Fixture::new(1);
    let mut input = f.input(0, 1, "💚");
    input.ext = Some(ReactionExternalId {
        connector: "slack".into(),
        id: "reaction-42".into(),
    });
    let first = f.vault.react(&f.people[1], input.clone()).unwrap();
    assert_eq!(f.vault.react(&f.people[1], input.clone()).unwrap(), first);
    let body = decode_reaction_body(&f.vault.get(&first.reaction_id).unwrap().unwrap()).unwrap();
    assert_eq!(body.ext, input.ext);
    assert!(
        crate::attempt_queue::AttemptQueue::new(&f.vault)
            .list()
            .unwrap()
            .iter()
            .all(|r| r.kind != "reaction.outbound")
    );
    f.toggle(0, 1, "💚");
    assert_eq!(
        f.vault.react(&f.people[1], input).unwrap().state,
        ReactionState::Revoked
    );
    assert!(f.pills(0, 0).is_empty());
    assert_eq!(
        f.vault.reactions_outbound(&f.room).unwrap(),
        ReactionsOutbound::FirstPartyOnly
    );
    let mut bytes = vec![];
    rmpv::encode::write_value(
        &mut bytes,
        &rmpv::Value::Map(vec![("room_connector".into(), "slack".into())]),
    )
    .unwrap();
    f.vault
        .put_entity(
            &f.room,
            crate::registry::ENTITY_TYPE_CONVERSATION,
            crate::temporal::TimeRange {
                start: 100,
                end: 100,
            },
            100,
            &bytes,
        )
        .unwrap();
    assert_eq!(
        f.vault.reactions_outbound(&f.room).unwrap(),
        ReactionsOutbound::Mirrored
    );
    f.toggle(0, 2, "👀");
    f.toggle(0, 2, "👀");
    let jobs: Vec<_> = crate::attempt_queue::AttemptQueue::new(&f.vault)
        .list()
        .unwrap()
        .into_iter()
        .filter(|r| r.kind == "reaction.outbound")
        .collect();
    assert_eq!(jobs.len(), 2);
    let states: Vec<_> = jobs
        .iter()
        .map(|j| {
            serde_json::from_slice::<serde_json::Value>(&j.payload).unwrap()["state"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert!(states.contains(&"put".into()));
    assert!(states.contains(&"revoked".into()));
}

#[test]
fn t4_visibility_uses_room_join_not_person_creation_and_removal_closes_history() {
    let f = Fixture::new(1);
    f.toggle(0, 1, "👀");
    // The late member's PERSON existed at time 1. Its room membership starts
    // after message 100; using PERSON learned_at here would leak the pill.
    f.vault
        .delete_edge(&f.people[2], EdgeKind::ParticipatesIn, &f.room)
        .unwrap();
    f.vault
        .batch()
        .edge_with_created_at(&f.people[2], EdgeKind::ParticipatesIn, &f.room, 1.0, 150)
        .commit()
        .unwrap();
    assert!(f.pills(0, 2).is_empty());
    assert!(
        !f.vault
            .conversation_message_visible_to(&f.messages[0], &f.people[2])
            .unwrap()
    );
    assert!(f.vault.react(&f.people[2], f.input(0, 2, "👀")).is_err());
    assert_eq!(f.pills(0, 3)[0].count, 1);
    f.vault
        .delete_edge(&f.people[3], EdgeKind::ParticipatesIn, &f.room)
        .unwrap();
    assert!(f.pills(0, 3).is_empty());
    f.vault.delete_entity(&f.messages[0]).unwrap();
    assert!(f.pills(0, 0).is_empty());
    assert!(f.vault.reactions_since(&f.people[0], 0).unwrap().is_empty());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(12))]
    #[test]
    fn t5_random_toggles_equal_raw_records(ops in prop::collection::vec((0usize..3,0usize..4,0usize..3),1..50)) {
        let f=Fixture::new(3);let glyphs=["👀","👍","💚"];
        let mut expected=std::collections::BTreeMap::new();
        for (m,p,g) in ops {
            let outcome=f.toggle(m,p,glyphs[g]);
            let key=(m,p,g);
            if expected.remove(&key).is_none() {prop_assert_eq!(outcome.state,ReactionState::Put);expected.insert(key,outcome.reaction_id);} else {prop_assert_eq!(outcome.state,ReactionState::Revoked);}
            for message in 0..3 {
                let mut raw=expected.iter().filter(|((m,_,_),_)|*m==message).map(|((_,person,glyph),id)|(*id,*person,*glyph)).collect::<Vec<_>>();raw.sort_by_key(|(id,_,_)|*id);
                let mut pills:Vec<ReactionPill>=vec![];
                for (id,person,glyph) in raw {
                    let body=decode_reaction_body(&f.vault.get(&id).unwrap().unwrap()).unwrap();prop_assert_eq!(body.by,f.people[person]);
                    let index=match pills.iter().position(|p|p.glyph==glyphs[glyph]) {Some(i)=>i,None=>{pills.push(ReactionPill{glyph:glyphs[glyph].into(),count:0,by:vec![],mine:false});pills.len()-1}};
                    pills[index].count+=1;pills[index].by.push(f.people[person].to_hex());pills[index].mine|=person==0;
                }
                prop_assert_eq!(f.pills(message,0),pills);
            }
        }
    }
}

#[test]
fn t6_agent_person_uses_same_reaction_door_and_inbox_is_its_own_messages() {
    let f = Fixture::new(1);
    let agent = f.vault.memory(f.people[1], EdgeActorClass::Agent);
    let receipt = agent
        .react_to_message(crate::memory::ReactToMessageInput {
            message_ref: f.messages[0].to_hex(),
            by_ref: None,
            glyph: "👀".into(),
            at: 200,
            ext: None,
        })
        .unwrap();
    assert_eq!(receipt.state, "put");
    assert!(agent.reactions_since(None, 0).unwrap().is_empty());
    assert!(
        agent
            .reactions_since(Some(f.people[0].to_hex()), 0)
            .is_err()
    );
    let own = agent
        .witness(&WitnessTurn {
            conversation_ref: f.room.to_hex(),
            turn_ref: None,
            occurred_at: 300,
            messages: vec![WitnessMessage {
                id: None,
                author: WitnessAuthor::Companion,
                message_type: "dialogue".into(),
                content: "agent message".into(),
                metadata: None,
                is_visible: true,
                order: 0,
            }],
        })
        .unwrap();
    let message = EntityId::from_hex(
        &agent
            .get_entity(&own.message_short_ids[0])
            .unwrap()
            .unwrap()
            .id_hex,
    )
    .unwrap();
    f.vault
        .react(
            &f.people[0],
            ReactInput {
                message,
                by: f.people[0],
                glyph: "👍".into(),
                at: 400,
                ext: None,
            },
        )
        .unwrap();
    let signals = agent.reactions_since(None, 0).unwrap();
    assert_eq!(signals.len(), 1);
    assert_eq!(signals[0].message, message.to_hex());
}

#[test]
fn t7_registry_codec_bounds_and_all_write_doors() {
    let f = Fixture::new(1);
    assert_eq!(ENTITY_TYPE_REACTION, 107);
    let entry = crate::registry::entity_type_registry_entry(107).unwrap();
    assert_eq!(entry.short_id_prefix, Some("rx"));
    assert_eq!(
        entry.classification,
        crate::registry::EntityClassification::Pack
    );
    assert!(crate::registry::validate_public_entity_type(107).is_ok());
    assert!(validate_reaction_glyph("").is_err());
    assert!(validate_reaction_glyph(&"🦀".repeat(65)).is_err());
    assert!(validate_reaction_glyph(&"🦀".repeat(64)).is_ok());
    let body = ReactionBody {
        msg: f.messages[0],
        by: f.people[1],
        glyph: "👀".into(),
        at: 200,
        ext: None,
    };
    let encoded = encode_reaction_body(&body).unwrap();
    assert_eq!(decode_reaction_body(&encoded).unwrap(), body);
    let mut value = rmpv::decode::read_value(&mut encoded.as_slice()).unwrap();
    if let rmpv::Value::Map(ref mut pairs) = value {
        pairs.retain(|(k, _)| k.as_str() != Some("v"));
    }
    let mut invalid = vec![];
    rmpv::encode::write_value(&mut invalid, &value).unwrap();
    assert!(decode_reaction_body(&invalid).is_err());
    let id = EntityId::now();
    assert!(
        f.vault
            .put_entity(
                &id,
                107,
                crate::temporal::TimeRange {
                    start: 200,
                    end: 200
                },
                200,
                &encoded
            )
            .is_err()
    );
    let put = f.toggle(0, 1, "👀");
    assert!(
        f.vault
            .put_edge(&put.reaction_id, EdgeKind::About, &f.people[1], 1.0)
            .is_err()
    );
    assert!(
        f.vault
            .delete_edge(&put.reaction_id, EdgeKind::About, &f.messages[0])
            .is_err()
    );
    assert_eq!(f.vault.edges_out(&put.reaction_id).unwrap().len(), 2);
    let mut not_room = f.input(0, 1, "👍");
    not_room.message = f.people[2];
    assert!(f.vault.react(&f.people[1], not_room).is_err());
    f.vault
        .delete_edge(&f.messages[0], EdgeKind::BelongsTo, &f.room)
        .unwrap();
    assert!(f.vault.react(&f.people[1], f.input(0, 1, "👍")).is_err());
}

#[test]
fn t8_fifty_messages_120_reactions_are_one_batched_read_with_zero_followups() {
    let f = Fixture::new(50);
    for n in 0..120 {
        f.toggle(n % 50, (n / 50) + 1, "👀");
    }
    f.vault.test_hooks().trace_reaction_reads();
    let page = f
        .vault
        .grouped_reaction_pills(&f.messages, &f.people[0])
        .unwrap();
    let calls = f.vault.test_hooks().take_reaction_reads();
    assert_eq!(calls, vec!["reaction.batch"]);
    assert_eq!(page.len(), 50);
    assert_eq!(
        page.iter()
            .flat_map(|g| &g.pills)
            .map(|p| p.count)
            .sum::<usize>(),
        120
    );
}

#[test]
fn replay_puts_rebuild_edges_and_inbox_and_immutable_records_refuse_overwrite() {
    let f = Fixture::new(1);
    let id = EntityId::now();
    let body = ReactionBody {
        msg: f.messages[0],
        by: f.people[1],
        glyph: "👀".into(),
        at: 200,
        ext: None,
    };
    let encoded = encode_reaction_body(&body).unwrap();
    f.vault
        .batch()
        .put_replicated(
            &id,
            107,
            crate::temporal::TimeRange {
                start: 200,
                end: 200,
            },
            250,
            &encoded,
        )
        .commit()
        .unwrap();
    assert_eq!(f.vault.edges_out(&id).unwrap().len(), 2);
    assert_eq!(
        f.vault.reactions_since(&f.people[0], 0).unwrap()[0].recorded_at,
        250
    );
    let changed = encode_reaction_body(&ReactionBody {
        glyph: "👍".into(),
        ..body
    })
    .unwrap();
    assert!(
        f.vault
            .batch()
            .put_replicated(
                &id,
                107,
                crate::temporal::TimeRange {
                    start: 200,
                    end: 200
                },
                250,
                &changed
            )
            .commit()
            .is_err()
    );
    let duplicate = EntityId::now();
    assert!(
        f.vault
            .batch()
            .put_replicated(
                &duplicate,
                107,
                crate::temporal::TimeRange {
                    start: 200,
                    end: 200
                },
                250,
                &encoded
            )
            .commit()
            .is_err()
    );
    let tombstone = crate::deletion::TombstoneValueV2 {
        reason: crate::deletion::DeleteReason::UserDelete.into(),
        deleted_at: 300,
        request_id: [12; 16],
    };
    f.vault
        .apply_replayed_tombstone(&id, &tombstone.encode())
        .unwrap();
    assert!(f.pills(0, 0).is_empty());
    f.vault.rebuild_reaction_inbox().unwrap();
    assert!(
        f.vault
            .reactions_since(&f.people[0], 251)
            .unwrap()
            .iter()
            .any(|s| s.kind == ReactionSignalKind::Revoked && s.at == 300)
    );
}

#[cfg(feature = "sync")]
#[test]
fn fresh_receiver_recovers_soft_tombstone_audit_and_hard_tombstone_never_recovers_body() {
    let f = Fixture::new(1);
    let id = EntityId::now();
    let body = encode_reaction_body(&ReactionBody {
        msg: f.messages[0],
        by: f.people[1],
        glyph: "👀".into(),
        at: 200,
        ext: None,
    })
    .unwrap();
    let mut blob = vec![107];
    for stamp in [200u64, 200, 250] {
        blob.extend_from_slice(&stamp.to_be_bytes());
    }
    blob.extend_from_slice(&body);
    let doc = loro::LoroDoc::new();
    let map = doc.get_map("tombstones");
    let soft = crate::deletion::TombstoneValueV2 {
        reason: crate::deletion::DeleteReason::UserDelete.into(),
        deleted_at: 300,
        request_id: [15; 16],
    };
    crate::sync::loro_support::map_insert_bytes(&map, &id.to_hex(), &soft.encode()).unwrap();
    assert!(
        f.vault
            .with_write_txn(|txn| super::materialize_soft_audit(&f.vault, txn, &map, &id, &blob))
            .unwrap()
    );
    assert!(f.pills(0, 0).is_empty());
    assert_eq!(f.vault.get(&id).unwrap().unwrap(), body);
    f.vault.rebuild_reaction_inbox().unwrap();
    let signals = f.vault.reactions_since(&f.people[0], 0).unwrap();
    assert_eq!(signals.len(), 2);
    assert_eq!(signals[1].kind, ReactionSignalKind::Revoked);
    let hard = crate::deletion::TombstoneValueV2 {
        reason: crate::deletion::DeleteReason::UserHardDelete.into(),
        ..soft
    };
    crate::sync::loro_support::map_insert_bytes(&map, &id.to_hex(), &hard.encode()).unwrap();
    f.vault
        .apply_replayed_tombstone(&id, &hard.encode())
        .unwrap();
    assert!(
        !f.vault
            .with_write_txn(|txn| super::materialize_soft_audit(&f.vault, txn, &map, &id, &blob))
            .unwrap()
    );
    assert!(f.vault.get(&id).unwrap().is_none());
    assert!(f.vault.reactions_since(&f.people[0], 0).unwrap().is_empty());
}
