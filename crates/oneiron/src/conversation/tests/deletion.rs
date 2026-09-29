use super::*;
use std::collections::BTreeMap;

fn second(vault: &Vault) -> WriteActor {
    let bob = EntityId::now();
    vault
        .put_entity(
            &bob,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 0, end: 0 },
            0,
            &encode(&serde_json::json!({})).unwrap(),
        )
        .unwrap();
    let actor = WriteActor::new(bob, EdgeActorClass::Human);
    crate::conversation_dag::fixtures::grant(vault, actor, true);
    actor
}

#[test]
fn role_codec_and_authority_are_bound_to_local_membership() {
    let (_dir, vault, owner, room, _) = fixture();
    let bob = second(&vault);
    let mut body = vault.conversation_body(room).unwrap();
    body.member_ids.push(bob.entity_ref());
    body.roles = BTreeMap::from([(bob.entity_ref().to_hex(), RoomRole::Admin)]);
    assert_eq!(
        body.to_bytes()
            .and_then(|bytes| ConversationBody::from_bytes(&bytes))
            .unwrap(),
        body
    );
    let unknown = EntityId::now();
    body.roles.insert(unknown.to_hex(), RoomRole::Owner);
    assert_eq!(
        body.to_bytes().unwrap_err().kind(),
        ErrorKind::InvalidConversationBody
    );
    vault
        .join_member(room, bob.entity_ref(), owner, 2, HistoryChoice::Share)
        .unwrap();
    let mut forged = vault.conversation_body(room).unwrap();
    forged
        .roles
        .insert(bob.entity_ref().to_hex(), RoomRole::Admin);
    assert_eq!(
        vault
            .batch()
            .put(
                &room,
                ENTITY_TYPE_CONVERSATION,
                TimeRange { start: 1, end: 1 },
                1,
                &forged.to_bytes().unwrap()
            )
            .commit()
            .unwrap_err()
            .kind(),
        ErrorKind::ConversationState
    );
    vault
        .set_room_role(room, bob.entity_ref(), RoomRole::Admin, owner)
        .unwrap();
    assert_eq!(
        vault.conversation_body(room).unwrap().roles[&bob.entity_ref().to_hex()],
        RoomRole::Admin
    );
    let txn = vault.store.env.read_txn().unwrap();
    assert_eq!(
        roles::role_in(&vault, &txn, room, bob).unwrap(),
        RoomRole::Admin
    );
    drop(txn);
    vault
        .leave_member(room, bob.entity_ref(), owner, 3)
        .unwrap();
    assert!(
        !vault
            .conversation_body(room)
            .unwrap()
            .roles
            .contains_key(&bob.entity_ref().to_hex())
    );
    let txn = vault.store.env.read_txn().unwrap();
    assert_eq!(
        roles::role_in(&vault, &txn, room, bob).unwrap_err().kind(),
        ErrorKind::ConversationDenied
    );
}

#[test]
fn author_and_admin_delete_require_authority_and_write_role_receipts() {
    let (_dir, vault, owner, room, _) = fixture();
    let bob = second(&vault);
    vault
        .join_member(room, bob.entity_ref(), owner, 2, HistoryChoice::Share)
        .unwrap();
    let first = vault
        .append_dag_record(&record(&vault, room, bob, 4))
        .unwrap()
        .id;
    assert_eq!(
        vault
            .delete_room_record(room, first, owner, crate::DeleteReason::UserDelete)
            .unwrap_err()
            .kind(),
        ErrorKind::ConversationDenied
    );
    assert_eq!(
        vault
            .delete_room_record(room, first, bob, crate::DeleteReason::PolicyDelete)
            .unwrap_err()
            .kind(),
        ErrorKind::ConversationDenied
    );
    let second = vault
        .append_dag_record(&record(&vault, room, owner, 5))
        .unwrap()
        .id;
    assert_eq!(
        vault
            .delete_entity_with_reason(&first, crate::DeleteReason::UserDelete)
            .unwrap_err()
            .kind(),
        ErrorKind::ConversationDenied
    );
    assert!(
        vault
            .delete_room_record(room, first, bob, crate::DeleteReason::UserDelete)
            .unwrap()
            .existed
    );
    assert!(vault.is_deleted_shell(&first).unwrap());
    vault
        .set_room_role(room, bob.entity_ref(), RoomRole::Admin, owner)
        .unwrap();
    let result = vault
        .delete_room_record(room, second, bob, crate::DeleteReason::PolicyDelete)
        .unwrap();
    assert!(result.existed);
    let receipt = result.receipt_id.unwrap();
    let raw = vault.get_raw_unsealed(&receipt).unwrap().unwrap();
    let body = crate::deletion::decode_redaction_audit_receipt(
        &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
    )
    .unwrap();
    assert_eq!(body.reason, "policy_delete");
    assert_eq!(
        body.actor_ref.as_deref(),
        Some(bob.entity_ref().to_hex().as_str())
    );
    assert_eq!(body.room_ref.as_deref(), Some(room.to_hex().as_str()));
    assert_eq!(body.room_role, Some(RoomRole::Admin));
    assert!(vault.get(&second).unwrap().is_none());
}

#[test]
fn erasure_covers_trunk_thread_and_sub_session_without_rewriting_ledger() {
    let (_dir, vault, owner, room, _) = fixture();
    let bob = second(&vault);
    vault
        .join_member(room, bob.entity_ref(), owner, 2, HistoryChoice::Share)
        .unwrap();
    let root = vault
        .append_dag_record(&record(&vault, room, owner, 4))
        .unwrap()
        .id;
    let trunk = vault
        .append_dag_record(&record(&vault, room, bob, 5))
        .unwrap()
        .id;
    let thread = vault
        .reply_in_thread(root, &record(&vault, room, bob, 6))
        .unwrap()
        .id;
    let session = vault.spawn_dag_sub_session(&root, owner).unwrap();
    let mut worker = record(&vault, room, bob, 7);
    worker.parent = Some(root);
    worker.session = Some(session);
    worker.advance = false;
    let worker = vault.append_dag_record(&worker).unwrap().id;
    let mut reply = record(&vault, room, owner, 8);
    reply.reply_to = Some(trunk);
    reply.parent = Some(trunk);
    let pointer = vault.append_dag_record(&reply).unwrap().id;
    let only_erased = crate::actor_claims::write_actor_claim(
        &vault,
        crate::actor_claims::ActorClaimRow::Lesson {
            actor: bob.entity_ref(),
            text: "sole erased evidence".into(),
        },
        &crate::actor_claims::ActorClaimEvidence::chat(session, vec![worker], 10).unwrap(),
    )
    .unwrap();
    let corroborated = crate::actor_claims::write_actor_claim(
        &vault,
        crate::actor_claims::ActorClaimRow::Lesson {
            actor: bob.entity_ref(),
            text: "other surviving evidence".into(),
        },
        &crate::actor_claims::ActorClaimEvidence::chat(session, vec![worker, root], 10).unwrap(),
    )
    .unwrap();
    let ledger = vault.membership_ledger(room).unwrap();
    let outcomes = vault
        .erase_room_person(room, bob.entity_ref(), owner)
        .unwrap();
    // The audit/history door retains the derived row. Caller-facing claim
    // visibility suppresses the sole-erased evidence (pinned separately by
    // the scoped-read/retrieval regressions).
    assert!(vault.get_claim(&only_erased).unwrap().is_some());
    assert!(vault.get_claim(&corroborated).unwrap().is_some());
    assert_eq!(outcomes.len(), 3);
    for id in [trunk, thread, worker] {
        assert!(vault.get(&id).unwrap().is_none());
    }
    assert!(vault.get(&root).unwrap().is_some());
    assert_eq!(vault.membership_ledger(room).unwrap(), ledger);
    assert!(
        vault
            .erase_room_person(room, bob.entity_ref(), owner)
            .unwrap()
            .is_empty()
    );
    let append = AppendRecord {
        conversation: room,
        parent: Some(root),
        reply_to: None,
        address: crate::conversation_dag::AddressMode::Broadcast,
        recipients: vec![],
        kind: crate::registry::ENTITY_TYPE_TURN,
        session: None,
        text: vec![],
        advance: false,
        body: encode(&serde_json::json!({"txt":"must not return"})).unwrap(),
        occurred: TimeRange { start: 11, end: 11 },
        learned_at: 11,
        actor: bob,
    };
    let fresh = vault.append_dag_record(&append).unwrap().id;
    assert!(vault.get(&fresh).unwrap().is_some());
    let strip = vault.reply_strip(&pointer).unwrap().unwrap();
    assert!(strip.redacted && strip.stale && strip.text.is_none());
    for outcome in outcomes {
        let receipt = outcome.receipt_id.unwrap();
        let raw = vault.get_raw_unsealed(&receipt).unwrap().unwrap();
        assert_eq!(raw[0], crate::registry::ENTITY_TYPE_REDACTION_AUDIT);
        let body = crate::deletion::decode_redaction_audit_receipt(
            &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
        )
        .unwrap();
        assert_eq!(body.reason, "gdpr_delete");
        assert_eq!(body.room_role, Some(RoomRole::Owner));
    }
}

fn independent_root(seed: u8) -> crate::authority::AuthorityLogEntry {
    use crate::authority::{
        AuthorityAttestation, AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature,
        AuthorityTier, DeviceAuthority, GenesisRecoveryStep, ROLE_ADMIN, ROLE_OWNER,
    };
    use ed25519_dalek::Signer;
    let signing = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let key = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let mut entry = AuthorityLogEntry {
        schema_version: crate::authority::AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: None,
        seq: 0,
        parent_hashes: Vec::new(),
        op: AuthorityOp::Genesis {
            device: DeviceAuthority {
                key: key.clone(),
                transport_key_binding: [7; 32],
                attestation: AuthorityAttestation {
                    kind: "SoftwareArgon2id".to_owned(),
                    evidence: vec![1, 2, 3],
                },
                tier: AuthorityTier::Software,
                roles: ROLE_OWNER | ROLE_ADMIN,
            },
            genesis_nonce: [seed.wrapping_add(10); 32],
            recovery: GenesisRecoveryStep::Saved([1; 32]),
            tier_floor: AuthorityTier::Software,
            pending_widen_delay_secs: crate::authority::DEFAULT_PENDING_WIDEN_DELAY_SECS,
        },
        signer: AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: 100,
    };
    let transcript = crate::authority::authority_transcript(&entry).unwrap();
    entry.signer.signature = signing.sign(&transcript).to_bytes().to_vec();
    entry
}

#[test]
fn conflicted_roots_never_restore_local_creator_or_initial_role_powers() {
    let (_dir, vault, owner, room, _) = fixture();
    let bob = second(&vault);
    vault
        .join_member(room, bob.entity_ref(), owner, 2, HistoryChoice::Share)
        .unwrap();
    let record = vault
        .append_dag_record(&record(&vault, room, bob, 3))
        .unwrap()
        .id;
    let saved = vault.get(&record).unwrap();
    vault
        .put_authority_log_entries(&[
            (independent_root(0x74), TimeRange { start: 1, end: 1 }, 1),
            (independent_root(0x75), TimeRange { start: 2, end: 2 }, 2),
        ])
        .unwrap();
    assert!(vault.authority_fold().unwrap().vault_root_is_conflicted());
    for err in [
        vault
            .set_room_role(room, bob.entity_ref(), RoomRole::Admin, owner)
            .unwrap_err(),
        vault
            .delete_room_record(room, record, owner, crate::DeleteReason::PolicyDelete)
            .unwrap_err(),
        vault
            .erase_room_person(room, bob.entity_ref(), owner)
            .unwrap_err(),
    ] {
        assert_eq!(err.kind(), ErrorKind::ConversationDenied);
    }
    let initial = ConversationBody {
        member_ids: vec![owner.entity_ref()],
        roles: BTreeMap::from([(owner.entity_ref().to_hex(), RoomRole::Owner)]),
        ..Default::default()
    };
    assert_eq!(
        vault
            .create_conversation(EntityId::now(), &initial, owner, 4)
            .unwrap_err()
            .kind(),
        ErrorKind::ConversationDenied
    );
    assert_eq!(vault.get(&record).unwrap(), saved);
    assert!(vault.conversation_body(room).unwrap().roles.is_empty());
    let txn = vault.store.env.read_txn().unwrap();
    assert!(
        !ROOM_ERASURES
            .contains(&vault.store, &txn, &(room, bob.entity_ref()))
            .unwrap()
    );
}

#[test]
fn agent_person_creator_can_delegate_and_policy_delete_in_unrooted_room() {
    let (_dir, vault, _, _, _) = fixture();
    let agent_id = EntityId::now();
    vault
        .put_entity(
            &agent_id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            &encode(&serde_json::json!({})).unwrap(),
        )
        .unwrap();
    let agent = WriteActor::new(agent_id, EdgeActorClass::Agent);
    let bob = second(&vault);
    let room = EntityId::now();
    let body = ConversationBody {
        member_ids: vec![agent_id, bob.entity_ref()],
        roles: BTreeMap::from([(agent_id.to_hex(), RoomRole::Owner)]),
        ..Default::default()
    };
    vault.create_conversation(room, &body, agent, 2).unwrap();
    vault
        .set_room_role(room, bob.entity_ref(), RoomRole::Admin, agent)
        .unwrap();
    let record = vault
        .append_dag_record(&record(&vault, room, bob, 3))
        .unwrap()
        .id;
    let result = vault
        .delete_room_record(room, record, agent, crate::DeleteReason::PolicyDelete)
        .unwrap();
    assert!(result.existed && result.receipt_id.is_some());
}

#[test]
fn room_soft_shell_escalates_through_authorized_gdpr_and_keeps_dag_usable() {
    let (_dir, vault, owner, room, _) = fixture();
    let bob = second(&vault);
    vault
        .join_member(room, bob.entity_ref(), owner, 2, HistoryChoice::Share)
        .unwrap();
    let first = vault
        .append_dag_record(&record(&vault, room, bob, 3))
        .unwrap()
        .id;
    let next = vault
        .append_dag_record(&record(&vault, room, owner, 4))
        .unwrap()
        .id;
    vault
        .delete_room_record(room, first, bob, crate::DeleteReason::UserDelete)
        .unwrap();
    assert!(vault.is_deleted_shell(&first).unwrap());
    assert_eq!(
        vault
            .main_line(&room, Default::default())
            .unwrap()
            .main_line,
        vec![next]
    );
    let erased = vault
        .erase_room_person(room, bob.entity_ref(), owner)
        .unwrap();
    assert_eq!(erased.len(), 1);
    assert!(erased[0].receipt_id.is_some());
    assert!(erased[0].sweep_key.is_some());
    assert!(vault.get_raw_unsealed(&first).unwrap().is_none());
    assert_eq!(
        vault
            .main_line(&room, Default::default())
            .unwrap()
            .main_line,
        vec![next]
    );
    assert!(
        vault
            .erase_room_person(room, bob.entity_ref(), owner)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn deleting_root_middle_or_head_keeps_live_trunk_and_append() {
    for removed in 0..3 {
        let (_dir, vault, owner, room, _) = fixture();
        let first = vault
            .append_dag_record(&record(&vault, room, owner, 3))
            .unwrap()
            .id;
        let middle = vault
            .append_dag_record(&record(&vault, room, owner, 4))
            .unwrap()
            .id;
        let head = vault
            .append_dag_record(&record(&vault, room, owner, 5))
            .unwrap()
            .id;
        let rows = [first, middle, head];
        vault
            .delete_room_record(
                room,
                rows[removed],
                owner,
                crate::DeleteReason::PolicyDelete,
            )
            .unwrap();
        let remaining: Vec<_> = rows
            .into_iter()
            .enumerate()
            .filter_map(|(i, id)| (i != removed).then_some(id))
            .collect();
        assert_eq!(
            vault
                .main_line(&room, Default::default())
                .unwrap()
                .main_line,
            remaining
        );
        assert_eq!(
            vault
                .resolve_dag_scope(&crate::conversation_dag::ScopeSelector {
                    conversation: room,
                    session: None,
                    path: crate::conversation_dag::ScopePath::Canonical,
                    include_forks: false,
                })
                .unwrap()
                .records,
            remaining
        );
        vault.rebuild_conversation_canonical(&room).unwrap();
        vault.move_head(&room, &remaining[0]).unwrap();
        vault.move_head(&room, remaining.last().unwrap()).unwrap();
        let appended = vault
            .append_dag_record(&record(&vault, room, owner, 6))
            .unwrap()
            .id;
        assert_eq!(
            vault
                .main_line(&room, Default::default())
                .unwrap()
                .main_line,
            [remaining.as_slice(), &[appended]].concat()
        );
    }
}

#[test]
fn imported_turn_has_unknown_person_author_but_owner_can_policy_delete_it() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    let owner_id = vault.ensure_embedded_owner_actor().unwrap();
    let owner = WriteActor::new(owner_id, EdgeActorClass::Human);
    let bob = EntityId::now();
    vault
        .put_entity(
            &bob,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            &encode(&serde_json::json!({})).unwrap(),
        )
        .unwrap();
    let crate::calendar::transcript::TranscriptIngestOutcome::Session { turn_refs, .. } =
        crate::calendar::transcript::ingest_file_drop_transcript(
            &vault,
            crate::calendar::transcript::TranscriptFileDropRequest {
                source_blob_ref: EntityId::now(),
                decoded_text: "Ada: hello",
                arrived_at_ms: 200_000,
            },
        )
        .unwrap()
    else {
        panic!("expected transcript turns")
    };
    let turn = turn_refs[0];
    let room = vault
        .edges_out(&turn)
        .unwrap()
        .into_iter()
        .find(|e| e.kind == EdgeKind::ChildOf)
        .unwrap()
        .target;
    assert!(
        vault
            .erase_room_person(room, bob, owner)
            .unwrap()
            .is_empty()
    );
    assert!(
        vault
            .delete_room_record(room, turn, owner, crate::DeleteReason::PolicyDelete)
            .unwrap()
            .receipt_id
            .is_some()
    );
}

#[test]
fn replayed_soft_then_hard_room_tombstone_keeps_surviving_line() {
    let (_dir, vault, owner, room, _) = fixture();
    let root = vault
        .append_dag_record(&record(&vault, room, owner, 3))
        .unwrap()
        .id;
    let child = vault
        .append_dag_record(&record(&vault, room, owner, 4))
        .unwrap()
        .id;
    let request = *uuid::Uuid::now_v7().as_bytes();
    let soft = crate::deletion::TombstoneValueV2 {
        reason: crate::deletion::TombstoneReason::UserDelete,
        deleted_at: 5,
        request_id: request,
    };
    // Observer B runs after the window tombstone has become visibility truth.
    vault
        .with_write_txn(|txn| {
            crate::ports::TombstoneStore::port_tombstone_create(&vault, txn, &root, soft)
        })
        .unwrap();
    vault
        .apply_replayed_tombstone(&root, &soft.encode())
        .unwrap();
    assert!(vault.is_deleted_shell(&root).unwrap());
    assert_eq!(
        vault
            .main_line(&room, Default::default())
            .unwrap()
            .main_line,
        vec![child]
    );
    vault
        .apply_replayed_tombstone(
            &root,
            &crate::deletion::TombstoneValueV2 {
                reason: crate::deletion::TombstoneReason::GdprDelete,
                deleted_at: 6,
                request_id: request,
            }
            .encode(),
        )
        .unwrap();
    assert!(vault.get_raw_unsealed(&root).unwrap().is_none());
    assert_eq!(
        vault
            .main_line(&room, Default::default())
            .unwrap()
            .main_line,
        vec![child]
    );
    assert!(
        vault
            .resolve_dag_scope(&crate::conversation_dag::ScopeSelector {
                conversation: room,
                session: None,
                path: crate::conversation_dag::ScopePath::Canonical,
                include_forks: false,
            })
            .unwrap()
            .records
            == [child]
    );
}

#[test]
fn room_admin_can_policy_hard_delete_an_authors_soft_shell() {
    let (_dir, vault, owner, room, _) = fixture();
    let bob = second(&vault);
    vault
        .join_member(room, bob.entity_ref(), owner, 2, HistoryChoice::Share)
        .unwrap();
    vault
        .set_room_role(room, bob.entity_ref(), RoomRole::Admin, owner)
        .unwrap();
    let root = vault
        .append_dag_record(&record(&vault, room, owner, 3))
        .unwrap()
        .id;
    vault
        .delete_room_record(room, root, owner, crate::DeleteReason::UserDelete)
        .unwrap();
    let outcome = vault
        .delete_room_record(room, root, bob, crate::DeleteReason::PolicyDelete)
        .unwrap();
    assert!(outcome.receipt_id.is_some());
    assert!(vault.get_raw_unsealed(&root).unwrap().is_none());
    assert!(
        vault
            .main_line(&room, Default::default())
            .unwrap()
            .main_line
            .is_empty()
    );
}

#[test]
fn erasure_pages_over_mixed_authors_and_soft_shells_without_skipping() {
    let (_dir, vault, owner, room, _) = fixture();
    let bob = second(&vault);
    vault
        .join_member(room, bob.entity_ref(), owner, 2, HistoryChoice::Share)
        .unwrap();
    let mut theirs = Vec::new();
    let mut retained = Vec::new();
    for at in 3..10 {
        let writer = if at % 2 == 0 { bob } else { owner };
        let id = vault
            .append_dag_record(&record(&vault, room, writer, at))
            .unwrap()
            .id;
        if writer == bob {
            theirs.push(id);
        } else {
            retained.push(id);
        }
    }
    vault
        .delete_room_record(room, theirs[0], bob, crate::DeleteReason::UserDelete)
        .unwrap();
    let ledger = vault.membership_ledger(room).unwrap();
    let outcomes = vault
        .erase_room_person(room, bob.entity_ref(), owner)
        .unwrap();
    assert_eq!(outcomes.len(), theirs.len());
    assert!(outcomes.iter().all(|outcome| outcome.receipt_id.is_some()));
    for id in theirs {
        assert!(vault.get(&id).unwrap().is_none());
    }
    for id in &retained {
        assert!(vault.get(id).unwrap().is_some());
    }
    assert_eq!(
        vault
            .main_line(&room, Default::default())
            .unwrap()
            .main_line,
        retained
    );
    assert_eq!(vault.membership_ledger(room).unwrap(), ledger);
    assert!(
        vault
            .erase_room_person(room, bob.entity_ref(), owner)
            .unwrap()
            .is_empty()
    );
}

fn room_rule(
    action: &str,
    roles: &[&str],
    allow: bool,
    room: Option<EntityId>,
    precedence: &str,
) -> rmpv::Value {
    let mut fields = vec![
        ("action".into(), action.into()),
        (
            "roles".into(),
            rmpv::Value::Array(roles.iter().map(|role| (*role).into()).collect()),
        ),
        ("allow".into(), allow.into()),
        ("precedence".into(), precedence.into()),
    ];
    if let Some(room) = room {
        fields.push(("room_ref".into(), room.to_hex().into()));
    }
    rmpv::Value::Map(fields)
}

fn install_room_rules(vault: &Vault, rows: Vec<rmpv::Value>) {
    let manifest = rmpv::Value::Map(vec![
        ("schema_version".into(), "1.2".into()),
        ("pack_id".into(), "room-policy-test".into()),
        ("pack_version".into(), "1".into()),
        ("min_engine_version".into(), "0.0.0".into()),
        ("defaults".into(), rmpv::Value::Map(vec![])),
        ("rules".into(), rmpv::Value::Array(vec![])),
        ("actor_ceilings".into(), rmpv::Value::Array(vec![])),
        ("room_policy_rows".into(), rmpv::Value::Array(rows)),
    ]);
    crate::test_util::put_policy_manifest_bytes(
        vault,
        EntityId::now(),
        &encode(&manifest).unwrap(),
    )
    .unwrap();
}

#[test]
fn vault_room_policy_narrows_admin_delete_and_owner_role_delegation() {
    let (_dir, vault, owner, room, _) = fixture();
    let bob = second(&vault);
    vault
        .join_member(room, bob.entity_ref(), owner, 2, HistoryChoice::Share)
        .unwrap();
    vault
        .set_room_role(room, bob.entity_ref(), RoomRole::Admin, owner)
        .unwrap();
    let root = vault
        .append_dag_record(&record(&vault, room, owner, 3))
        .unwrap()
        .id;
    install_room_rules(
        &vault,
        vec![
            room_rule("policy_delete", &["owner"], true, None, "nested_narrowing"),
            room_rule("delegate", &["owner"], false, None, "nested_narrowing"),
        ],
    );
    assert_eq!(
        vault
            .delete_room_record(room, root, bob, crate::DeleteReason::PolicyDelete)
            .unwrap_err()
            .kind(),
        ErrorKind::ConversationDenied
    );
    assert_eq!(
        vault
            .set_room_role(room, bob.entity_ref(), RoomRole::Owner, owner)
            .unwrap_err()
            .kind(),
        ErrorKind::ConversationDenied
    );
    assert!(vault.get(&root).unwrap().is_some());
    assert!(
        vault
            .delete_room_record(room, root, owner, crate::DeleteReason::PolicyDelete)
            .unwrap()
            .existed
    );
}

#[test]
fn completed_room_erasure_uses_current_vault_policy_for_fresh_ids() {
    let (_dir, vault, owner, room, _) = fixture();
    let bob = second(&vault);
    vault
        .join_member(room, bob.entity_ref(), owner, 2, HistoryChoice::Share)
        .unwrap();
    let root = vault
        .append_dag_record(&record(&vault, room, owner, 3))
        .unwrap()
        .id;
    let prior = vault
        .append_dag_record(&record(&vault, room, bob, 4))
        .unwrap()
        .id;
    assert_eq!(
        vault
            .erase_room_person(room, bob.entity_ref(), owner)
            .unwrap()
            .len(),
        1
    );
    assert!(vault.get(&prior).unwrap().is_none());
    let mut fresh = record(&vault, room, bob, 5);
    fresh.parent = Some(root);
    fresh.advance = false;
    assert!(
        vault.append_dag_record(&fresh).is_ok(),
        "shipped policy permits fresh IDs after the completed sweep"
    );
    install_room_rules(
        &vault,
        vec![room_rule(
            "post_erasure_append",
            &[],
            false,
            None,
            "nested_narrowing",
        )],
    );
    assert_eq!(
        vault.append_dag_record(&fresh).unwrap_err().kind(),
        ErrorKind::InvalidConversationDag
    );
    assert!(
        vault
            .append_dag_record(&record(&vault, room, owner, 6))
            .is_ok()
    );
}

#[test]
fn room_holder_override_cannot_widen_vault_delete_ceiling() {
    let (_dir, vault, owner, room, _) = fixture();
    let bob = second(&vault);
    vault
        .join_member(room, bob.entity_ref(), owner, 2, HistoryChoice::Share)
        .unwrap();
    vault
        .set_room_role(room, bob.entity_ref(), RoomRole::Admin, owner)
        .unwrap();
    let record = vault
        .append_dag_record(&record(&vault, room, owner, 3))
        .unwrap()
        .id;
    install_room_rules(
        &vault,
        vec![
            room_rule("policy_delete", &["owner"], true, None, "nested_narrowing"),
            room_rule(
                "policy_delete",
                &["admin"],
                true,
                Some(room),
                "holder_override",
            ),
        ],
    );
    assert_eq!(
        vault
            .delete_room_record(room, record, bob, crate::DeleteReason::PolicyDelete)
            .unwrap_err()
            .kind(),
        ErrorKind::ConversationDenied
    );
    assert_eq!(
        vault
            .delete_room_record(room, record, owner, crate::DeleteReason::PolicyDelete)
            .unwrap_err()
            .kind(),
        ErrorKind::ConversationDenied
    );
    assert!(vault.get(&record).unwrap().is_some());
}

#[test]
fn manifest_seeded_before_room_rows_uses_shipped_room_defaults() {
    let (_dir, vault, owner, room, _) = fixture();
    let bob = second(&vault);
    vault
        .join_member(room, bob.entity_ref(), owner, 2, HistoryChoice::Share)
        .unwrap();
    // An existing vault keeps the manifest it was first seeded with; open
    // never reseeds one that predates `room_policy_rows`.
    let rmpv::Value::Map(fields) =
        rmpv::decode::read_value(&mut crate::gate::default_policy_manifest().unwrap().as_slice())
            .unwrap()
    else {
        unreachable!()
    };
    let legacy = rmpv::Value::Map(
        fields
            .into_iter()
            .filter(|(key, _)| key.as_str() != Some("room_policy_rows"))
            .collect(),
    );
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        crate::gate::default_policy_manifest_id().unwrap(),
        &encode(&legacy).unwrap(),
    )
    .unwrap();
    let owned = vault
        .append_dag_record(&record(&vault, room, owner, 3))
        .unwrap()
        .id;
    let bobs = vault
        .append_dag_record(&record(&vault, room, bob, 4))
        .unwrap()
        .id;
    assert!(
        vault
            .delete_room_record(room, bobs, bob, crate::DeleteReason::UserDelete)
            .unwrap()
            .existed,
        "the shipped default lets an author delete their own record"
    );
    assert_eq!(
        vault
            .delete_room_record(room, owned, bob, crate::DeleteReason::PolicyDelete)
            .unwrap_err()
            .kind(),
        ErrorKind::ConversationDenied,
        "the shipped default still limits policy deletion to owner/admin"
    );
    assert!(
        vault
            .delete_room_record(room, owned, owner, crate::DeleteReason::PolicyDelete)
            .unwrap()
            .receipt_id
            .is_some()
    );
}
