use super::*;
use rmpv::Value;

use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::config::VaultConfig;
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::error::SyncError;
use crate::off_record::OffRecordBackendClass;
use crate::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_TURN};
use crate::temporal::TimeRange;

fn test_vault() -> (tempfile::TempDir, Arc<Vault>) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
    (dir, vault)
}

fn delegated_identity_fixture(
    vault: &Vault,
    name: &str,
    address: &str,
    learned_at: u64,
) -> Result<(
    crate::channel_identity::DelegatedGrant,
    crate::channel_identity::ChannelIdentityBinding,
)> {
    use crate::channel_identity::{DelegatedGrant, DelegatedGrantScope, delegated_custody_scopes};
    use crate::secret_custody::{
        CustodyClass, CustodyTier, SECRET_CUSTODY_SCHEMA_VERSION, SecretBinding,
        SecretCustodyFloor, SecretCustodyRecord, SecretCustodyStatus,
    };

    let record = SecretCustodyRecord {
        schema_version: SECRET_CUSTODY_SCHEMA_VERSION,
        name: name.to_owned(),
        class: CustodyClass::CustodyDeviceBound,
        device_only: true,
        value_bytes: b"locally-held-oauth-token".to_vec(),
        status: SecretCustodyStatus::Active,
        registered_at: learned_at,
        rotated_at: None,
        rotation_generation: 0,
        bindings: vec![SecretBinding {
            effector: "connector:gmail".to_owned(),
            tier_ceiling: CustodyTier::T0Doored,
            scopes: delegated_custody_scopes("email", address),
        }],
        manifest_ref: String::new(),
        declared_paths: Vec::new(),
        policy_floor_snapshot: SecretCustodyFloor::default(),
    };
    vault.register_secret(record)?;
    let grant = DelegatedGrant::new(name, vec![DelegatedGrantScope::MailRead]);
    vault.verify_delegated_custody("email", address, &grant)?;
    Ok((
        grant,
        crate::channel_identity::ChannelIdentityBinding::agent(EntityId::from_bytes([0xA1; 16])?),
    ))
}

fn release_local_delegated_identity(
    vault: &Vault,
    id: EntityId,
    learned_at: u64,
    address: &str,
    grant: crate::channel_identity::DelegatedGrant,
    binding: crate::channel_identity::ChannelIdentityBinding,
) -> Result<(
    crate::channel_identity::ChannelIdentity,
    crate::channel_identity::ChannelIdentity,
)> {
    use crate::channel_identity::{
        ChannelIdentityFulfillment, ChannelIdentityStep, DelegatedProvisionRequest,
    };

    vault.provision_delegated_identity(
        &id,
        DelegatedProvisionRequest {
            channel: "email".to_owned(),
            address_or_handle: address.to_owned(),
            binding,
            grant,
        },
        learned_at,
    )?;
    vault.step_channel_identity(
        &id,
        ChannelIdentityStep::Bind(ChannelIdentityFulfillment::Manual),
        learned_at + 1,
    )?;
    let active = vault.step_channel_identity(&id, ChannelIdentityStep::Fulfill, learned_at + 2)?;
    let retired = vault.step_channel_identity(&id, ChannelIdentityStep::Release, learned_at + 3)?;
    Ok((retired, active))
}

#[test]
fn typed_addressing_edge_survives_reverse_and_forward_replay_but_forged_peer_edge_does_not()
-> Result<()> {
    let (_dir, source, conversation, actor) = crate::conversation_dag::fixtures::fixture();
    let recipient = EntityId::now();
    let forged = EntityId::now();
    for person in [recipient, forged] {
        source.put_entity(
            &person,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            &crate::conversation_dag::fixtures::body("person"),
        )?;
    }
    let mut input = crate::conversation_dag::fixtures::input(conversation, None, true, actor);
    input.address = crate::conversation_dag::AddressMode::Direct;
    input.recipients = vec![recipient];
    let record = source.append_dag_record(&input)?.id;
    let key = WindowKey::from_timestamp(input.learned_at);
    let doc = create_window_doc("addressing-source", &key);
    reverse_rematerialize(&source, &doc, &key)?;
    let honest = format_edge_key(&record, EdgeKind::AddressedTo, &recipient);
    assert!(map_contains_binary(&doc.get_map("edges"), &honest));
    let forged_key = format_edge_key(&record, EdgeKind::AddressedTo, &forged);
    map_insert_bytes(
        &doc.get_map("edges"),
        &forged_key,
        &encode_edge_value_for_crdt(EdgeKind::AddressedTo, 1.0, input.learned_at, None, None)?,
    )?;
    doc.commit();
    let (_peer_dir, peer) = test_vault();
    forward_rematerialize(&peer, &doc, &Materializer::new(), &key)?;
    assert_eq!(
        peer.targets(&record, EdgeKind::AddressedTo, None)?,
        [recipient]
    );
    assert!(!peer.edge_exists(&record, EdgeKind::AddressedTo, &forged)?);
    let rejected = crate::sync::quarantine::quarantined_records(&peer)?;
    assert!(
        rejected
            .iter()
            .any(|(_, row)| row.container == QuarantineContainer::Edges
                && row.reason_code == "ReservedEdgeKind")
    );
    // An untrusted edges-map removal cannot tear a locally stamped edge.
    let materializer = std::sync::Arc::new(Materializer::new());
    let _subscription =
        crate::sync::bridge::register_observer_b(&doc, &peer, &materializer, key.as_str());
    crate::sync::loro_support::map_delete(&doc.get_map("edges"), &honest)?;
    doc.commit();
    assert!(peer.edge_exists(&record, EdgeKind::AddressedTo, &recipient)?);
    Ok(())
}

#[test]
fn typed_addressing_recovery_restores_only_body_proved_edges() -> Result<()> {
    let (_dir, source, conv, actor) = crate::conversation_dag::fixtures::fixture();
    let person = EntityId::now();
    source.put_entity(
        &person,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        &crate::conversation_dag::fixtures::body("recipient"),
    )?;
    let mut input = crate::conversation_dag::fixtures::input(conv, None, true, actor);
    input.address = crate::conversation_dag::AddressMode::Direct;
    input.recipients = vec![person];
    let record = source.append_dag_record(&input)?.id;
    let key = WindowKey::from_timestamp(input.learned_at);
    let doc = create_window_doc("source", &key);
    // Keep the artifact at the conversation boundary: a test policy fixture
    // minted for the append door is not a recovery dependency of the TURN.
    for id in [conv, actor.entity_ref(), person, record] {
        map_insert_bytes(
            &doc.get_map("entities"),
            &id.to_hex(),
            &source.get_raw_unsealed(&id)?.unwrap(),
        )?;
    }
    for edge in source.edges_out(&record)? {
        let raw = encode_edge_value_for_crdt(
            edge.kind,
            edge.weight,
            edge.created_at,
            edge.vad,
            edge.provenance,
        )?;
        map_insert_bytes(
            &doc.get_map("edges"),
            &format_edge_key(&record, edge.kind, &edge.target),
            &raw,
        )?;
    }
    doc.commit();
    let snapshot = crate::recovery::capture_canonical_window(&source, key.as_str(), &doc)?;
    assert!(
        snapshot
            .base_edges
            .iter()
            .any(|edge| edge.source == *record.as_bytes()
                && edge.kind == EdgeKind::AddressedTo as u8
                && edge.target == *person.as_bytes())
    );
    let dest_dir = tempfile::tempdir()?;
    let peer = Vault::open(dest_dir.path(), VaultConfig::device())?;
    let path = dest_dir.path().join("manifest");
    std::fs::write(&path, b"corrupt")?;
    crate::recovery::recover_vault_window(
        &peer,
        &Materializer::new(),
        &path,
        &snapshot,
        crate::recovery::RecoveryBudget::default(),
    )?;
    assert_eq!(
        peer.targets(&record, EdgeKind::AddressedTo, None)?,
        [person]
    );
    let mut forged = snapshot;
    let entry = forged
        .base_edges
        .iter_mut()
        .find(|edge| edge.source == *record.as_bytes() && edge.kind == EdgeKind::AddressedTo as u8)
        .unwrap();
    entry.target = *actor.entity_ref().as_bytes();
    forged
        .base_edges
        .sort_by_key(|row| (row.source, row.kind, row.target));
    let fresh_dir = tempfile::tempdir()?;
    let fresh = Vault::open(fresh_dir.path(), VaultConfig::device())?;
    assert!(
        crate::recovery::recover_vault_window(
            &fresh,
            &Materializer::new(),
            fresh_dir.path().join("manifest"),
            &forged,
            crate::recovery::RecoveryBudget::default(),
        )
        .is_err()
    );
    assert_eq!(fresh.get_entity_type(&record)?, None);
    Ok(())
}

#[test]
fn soft_deleted_addressed_turn_keeps_its_edge_across_canonical_recovery() -> Result<()> {
    let (_dir, source, conv, actor) = crate::conversation_dag::fixtures::fixture();
    let recipient = EntityId::now();
    source.put_entity(
        &recipient,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        &crate::conversation_dag::fixtures::body("person"),
    )?;
    let mut input = crate::conversation_dag::fixtures::input(conv, None, true, actor);
    input.address = crate::conversation_dag::AddressMode::Direct;
    input.recipients = vec![recipient];
    let record = source.append_dag_record(&input)?.id;
    let tombstone = crate::deletion::TombstoneValueV2 {
        reason: crate::deletion::TombstoneReason::UserDelete,
        deleted_at: 100,
        request_id: *EntityId::now().as_bytes(),
    }
    .encode();
    source.apply_replayed_tombstone(&record, &tombstone)?;
    assert_eq!(
        source.get_raw_unsealed(&record)?.unwrap().len(),
        crate::batch::ENTITY_METADATA_HEADER_LEN
    );
    assert_eq!(
        source.targets(&record, EdgeKind::AddressedTo, None)?,
        [recipient]
    );
    let key = WindowKey::from_timestamp(input.learned_at);
    let doc = create_window_doc("source", &key);
    for id in [conv, actor.entity_ref(), recipient] {
        map_insert_bytes(
            &doc.get_map("entities"),
            &id.to_hex(),
            &source.get_raw_unsealed(&id)?.unwrap(),
        )?;
    }
    apply_tombstone_to_window_doc(&doc, &record, &tombstone)?;
    doc.commit();
    let snapshot = crate::recovery::capture_canonical_window(&source, key.as_str(), &doc)?;
    assert!(
        snapshot
            .base_edges
            .iter()
            .any(|edge| edge.source == *record.as_bytes()
                && edge.kind == EdgeKind::AddressedTo as u8
                && edge.target == *recipient.as_bytes())
    );
    let dir = tempfile::tempdir()?;
    let peer = Vault::open(dir.path(), VaultConfig::device())?;
    let path = dir.path().join("manifest");
    std::fs::write(&path, b"corrupt")?;
    crate::recovery::recover_vault_window(
        &peer,
        &Materializer::new(),
        &path,
        &snapshot,
        crate::recovery::RecoveryBudget::default(),
    )?;
    assert_eq!(
        peer.get_raw_unsealed(&record)?.unwrap().len(),
        crate::batch::ENTITY_METADATA_HEADER_LEN
    );
    assert_eq!(
        peer.targets(&record, EdgeKind::AddressedTo, None)?,
        [recipient]
    );
    let mut forged = snapshot;
    let edge = forged
        .base_edges
        .iter_mut()
        .find(|edge| edge.source == *record.as_bytes() && edge.kind == EdgeKind::AddressedTo as u8)
        .unwrap();
    edge.value[..4].copy_from_slice(&0.0_f32.to_le_bytes()); // not the door's 1.0 weight
    let other_dir = tempfile::tempdir()?;
    let other = Vault::open(other_dir.path(), VaultConfig::device())?;
    assert!(
        crate::recovery::recover_vault_window(
            &other,
            &Materializer::new(),
            other_dir.path().join("manifest"),
            &forged,
            crate::recovery::RecoveryBudget::default()
        )
        .is_err()
    );
    assert_eq!(other.get_entity_type(&record)?, None);
    Ok(())
}

#[test]
fn soft_addressing_recovers_across_monthly_recipient_window() -> Result<()> {
    let (_dir, source, conv, actor) = crate::conversation_dag::fixtures::fixture();
    let jan = 1_768_435_200_u64; // 2026-01-15 UTC
    let feb = 1_771_113_600_u64; // 2026-02-15 UTC
    let recipient = EntityId::now();
    source.put_entity(
        &recipient,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange {
            start: jan,
            end: jan,
        },
        jan,
        &crate::conversation_dag::fixtures::body("recipient"),
    )?;
    let mut input = crate::conversation_dag::fixtures::input(conv, None, true, actor);
    input.occurred = TimeRange {
        start: feb,
        end: feb,
    };
    input.learned_at = feb;
    input.address = crate::conversation_dag::AddressMode::Direct;
    input.recipients = vec![recipient];
    let record = source.append_dag_record(&input)?.id;
    let jan_key = WindowKey::from_timestamp(jan);
    let jan_doc = create_window_doc("source", &jan_key);
    reverse_rematerialize(&source, &jan_doc, &jan_key)?;
    assert!(map_contains_binary(
        &jan_doc.get_map("entities"),
        &recipient.to_hex()
    ));
    let feb_key = WindowKey::from_timestamp(feb);
    let feb_doc = create_window_doc("source", &feb_key);
    reverse_rematerialize(&source, &feb_doc, &feb_key)?;
    assert!(!map_contains_binary(
        &feb_doc.get_map("entities"),
        &recipient.to_hex()
    ));
    let tombstone = crate::deletion::TombstoneValueV2 {
        reason: crate::deletion::TombstoneReason::UserDelete,
        deleted_at: feb + 10,
        request_id: *EntityId::now().as_bytes(),
    }
    .encode();
    source.apply_replayed_tombstone(&record, &tombstone)?;
    apply_tombstone_to_window_doc(&feb_doc, &record, &tombstone)?;
    feb_doc.commit();
    let snapshot = crate::recovery::capture_canonical_window(&source, feb_key.as_str(), &feb_doc)?;
    assert!(
        !snapshot
            .entity_blobs
            .iter()
            .any(|row| row.id == *recipient.as_bytes())
    );
    assert!(
        snapshot
            .base_edges
            .iter()
            .any(|row| row.source == *record.as_bytes()
                && row.kind == EdgeKind::AddressedTo as u8
                && row.target == *recipient.as_bytes())
    );
    let wrong_dir = tempfile::tempdir()?;
    let wrong = Vault::open(wrong_dir.path(), VaultConfig::device())?;
    for id in [conv, actor.entity_ref()] {
        let raw = source.get_raw_unsealed(&id)?.unwrap();
        let header = crate::batch::EntityMetadataHeader::parse(&raw).unwrap();
        wrong
            .batch()
            .put_replicated(
                &id,
                header.entity_type,
                TimeRange {
                    start: header.occurred_start,
                    end: header.occurred_end,
                },
                header.learned_at,
                &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
            )
            .commit()?;
    }
    wrong.put_entity(
        &recipient,
        crate::registry::ENTITY_TYPE_CONVERSATION,
        TimeRange {
            start: jan,
            end: jan,
        },
        jan,
        &crate::conversation_dag::fixtures::body("wrong-kind"),
    )?;
    assert!(
        crate::recovery::recover_vault_window(
            &wrong,
            &Materializer::new(),
            wrong_dir.path().join("feb-manifest"),
            &snapshot,
            crate::recovery::RecoveryBudget::default()
        )
        .is_err()
    );
    assert_eq!(wrong.get_entity_type(&record)?, None);
    let dir = tempfile::tempdir()?;
    let peer = Vault::open(dir.path(), VaultConfig::device())?;
    for id in [conv, actor.entity_ref()] {
        let raw = source.get_raw_unsealed(&id)?.unwrap();
        let header = crate::batch::EntityMetadataHeader::parse(&raw).unwrap();
        peer.batch()
            .put_replicated(
                &id,
                header.entity_type,
                TimeRange {
                    start: header.occurred_start,
                    end: header.occurred_end,
                },
                header.learned_at,
                &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
            )
            .commit()?;
    }
    forward_rematerialize(&peer, &jan_doc, &Materializer::new(), &jan_key)?;
    assert_eq!(
        peer.get_entity_type(&recipient)?,
        Some(crate::registry::ENTITY_TYPE_PERSON)
    );
    crate::recovery::recover_vault_window(
        &peer,
        &Materializer::new(),
        dir.path().join("feb-manifest"),
        &snapshot,
        crate::recovery::RecoveryBudget::default(),
    )?;
    assert_eq!(
        peer.get_raw_unsealed(&record)?.unwrap().len(),
        crate::batch::ENTITY_METADATA_HEADER_LEN
    );
    assert_eq!(
        peer.targets(&record, EdgeKind::AddressedTo, None)?,
        [recipient]
    );
    assert_eq!(
        source.targets(&record, EdgeKind::AddressedTo, None)?,
        [recipient]
    );
    Ok(())
}

#[test]
fn deleted_recipient_recovery_keeps_conversation_readable_without_resurrecting_hard_edge()
-> Result<()> {
    for reason in [
        crate::deletion::TombstoneReason::UserDelete,
        crate::deletion::TombstoneReason::GdprDelete,
    ] {
        let (_dir, source, conv, actor) = crate::conversation_dag::fixtures::fixture();
        let recipient = EntityId::now();
        source.put_entity(
            &recipient,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            &crate::conversation_dag::fixtures::body("person"),
        )?;
        let mut input = crate::conversation_dag::fixtures::input(conv, None, true, actor);
        input.address = crate::conversation_dag::AddressMode::Direct;
        input.recipients = vec![recipient];
        let record = source.append_dag_record(&input)?.id;
        let tombstone = crate::deletion::TombstoneValueV2 {
            reason,
            deleted_at: 100,
            request_id: *EntityId::now().as_bytes(),
        }
        .encode();
        source.apply_replayed_tombstone(&recipient, &tombstone)?;
        let key = WindowKey::from_timestamp(input.learned_at);
        let doc = create_window_doc("source", &key);
        for id in [conv, actor.entity_ref(), record] {
            map_insert_bytes(
                &doc.get_map("entities"),
                &id.to_hex(),
                &source.get_raw_unsealed(&id)?.unwrap(),
            )?;
        }
        for edge in source.edges_out(&record)? {
            let bytes = encode_edge_value_for_crdt(
                edge.kind,
                edge.weight,
                edge.created_at,
                edge.vad,
                edge.provenance,
            )?;
            map_insert_bytes(
                &doc.get_map("edges"),
                &format_edge_key(&record, edge.kind, &edge.target),
                &bytes,
            )?;
        }
        apply_tombstone_to_window_doc(&doc, &recipient, &tombstone)?;
        doc.commit();
        let mut snapshot = crate::recovery::capture_canonical_window(&source, key.as_str(), &doc)?;
        // This bounded fixture captures the room's record graph, not other
        // outgoing PERSON substrate edges whose targets were not imported.
        snapshot.base_edges.retain(|edge| {
            edge.source == *record.as_bytes()
                && (edge.target == *conv.as_bytes() || edge.target == *recipient.as_bytes())
        });
        let dir = tempfile::tempdir()?;
        let peer = Vault::open(dir.path(), VaultConfig::device())?;
        crate::recovery::recover_vault_window(
            &peer,
            &Materializer::new(),
            dir.path().join("manifest"),
            &snapshot,
            crate::recovery::RecoveryBudget::default(),
        )?;
        assert_eq!(
            peer.main_line(&conv, Default::default())?.main_line,
            [record]
        );
        assert_eq!(peer.head(&conv)?, Some(record));
        let restored = peer.targets(&record, EdgeKind::AddressedTo, None)?;
        if reason == crate::deletion::TombstoneReason::UserDelete {
            assert_eq!(restored, [recipient]);
        } else {
            assert!(
                restored.is_empty(),
                "hard deletion must not restore addressing edge"
            );
        }
    }
    Ok(())
}

/// Pinned 25-byte entity envelope: type u8 + occurred_start/end u64 BE +
/// learned_at u64 BE + body (`occurred == learned` so CRDT-vs-LMDB
/// byte-equality is exact).
fn make_entity_blob(entity_type: u8, learned_at: u64, data: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(25 + data.len());
    blob.push(entity_type);
    blob.extend_from_slice(&learned_at.to_be_bytes());
    blob.extend_from_slice(&learned_at.to_be_bytes());
    blob.extend_from_slice(&learned_at.to_be_bytes());
    blob.extend_from_slice(data);
    blob
}

/// THE EGRESS REGRESSION (ARCH-0052 P6, ONE-1731 / R-20260807-06).
///
/// The sync window-packing door skips live session-overlay members through
/// BOTH packing paths, while an ordinary base write COMMISSIONED during the
/// same live session packs normally. That asymmetry is the whole contract:
/// the door asks about membership in a room, not about whether a room exists.
///
/// A `pm:` marker for an excluded id stays PENDING rather than being cleared,
/// so a later P5 promote releases the turn to sync through this same ordinary
/// path instead of needing a special release verb.
///
/// The fixture takes an already-base-resident id into the overlay directly,
/// because that is the only way to hand the DOOR an id that packing can also
/// see. Production never reaches that state — the K4 taint guard refuses a
/// base write at a live overlay id — which is exactly why an unexercised door
/// would be an untested one.
#[test]
fn window_packing_door_skips_overlay_members_and_packs_commissioned_writes() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let learned_at = window_key.start_timestamp().unwrap() + 60;
    let room_member = EntityId::from_bytes([0x41; 16])?;
    let commissioned = EntityId::from_bytes([0x43; 16])?;

    for id in [&room_member, &commissioned] {
        vault.put_entity(
            id,
            ENTITY_TYPE_TURN,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            b"packing fixture turn",
        )?;
    }

    let session = vault
        .off_record_session_vault()
        .enter("sess-egress-door", OffRecordBackendClass::Local)?;
    let overlay = session.overlay();
    let segment = overlay.install_txn_segment()?;
    overlay.put(
        crate::session_overlay::OverlayKeyspace::Entities,
        room_member.as_bytes(),
        b"live session overlay entity",
    )?;
    segment.commit()?;

    assert!(crate::sync::window::window_packing_excludes_entity(
        &vault,
        &Default::default(),
        &room_member
    )?);
    assert!(!crate::sync::window::window_packing_excludes_entity(
        &vault,
        &Default::default(),
        &commissioned
    )?);

    let member_marker = format!("pm:{window_key}:{}", room_member.to_hex());
    let commissioned_marker = format!("pm:{window_key}:{}", commissioned.to_hex());
    vault.sync_state_put(&member_marker, &[1])?;
    vault.sync_state_put(&commissioned_marker, &[1])?;

    let doc = create_window_doc("source", &window_key);
    let entities = doc.get_map("entities");

    // Path 1 — pm: replay. The commissioned write mirrors and clears its
    // marker; the overlay member neither mirrors nor loses its marker.
    assert_eq!(replay_pending_mirrors(&vault, &doc, &window_key)?, 1);
    assert!(map_get_bytes(&entities, &room_member.to_hex()).is_none());
    assert!(map_get_bytes(&entities, &commissioned.to_hex()).is_some());
    assert!(vault.sync_state_get(&member_marker)?.is_some());
    assert!(vault.sync_state_get(&commissioned_marker)?.is_none());

    // Path 2 — reverse rematerialization. Same verdict, and re-running is a
    // standing predicate rather than a one-shot skip.
    assert_eq!(reverse_rematerialize(&vault, &doc, &window_key)?, 0);
    assert!(map_get_bytes(&entities, &room_member.to_hex()).is_none());

    // Closing the room drops membership, and the deferred turn joins sync
    // through the ordinary path with no release verb of its own.
    session.close()?;
    assert!(!crate::sync::window::window_packing_excludes_entity(
        &vault,
        &Default::default(),
        &room_member
    )?);
    assert_eq!(replay_pending_mirrors(&vault, &doc, &window_key)?, 1);
    assert!(map_get_bytes(&entities, &room_member.to_hex()).is_some());
    assert!(vault.sync_state_get(&member_marker)?.is_none());
    Ok(())
}

fn put_local_type_76_event(
    vault: &Vault,
    learned_at: u64,
    participant_seed: u8,
) -> Result<(EntityId, Vec<u8>)> {
    use crate::identity_topology::{
        IdentityOpEvidence, IdentityOpOutcome, IdentityOpWrite, IdentityTopologyOp, MergeOp,
        SurvivorshipPlan,
    };

    let source = EntityId::from_bytes([participant_seed; 16])?;
    let survivor = EntityId::from_bytes([participant_seed.wrapping_add(1); 16])?;
    for id in [&source, &survivor] {
        vault.put_entity(
            id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"protected outbound fixture",
        )?;
    }
    let outcome = vault.apply_identity_topology_op(
        &IdentityTopologyOp::Merge(MergeOp {
            sources: vec![source],
            survivor,
            evidence: IdentityOpEvidence {
                refs: Vec::new(),
                rationale: "protected outbound tombstone fixture".to_owned(),
            },
            survivorship_plan: SurvivorshipPlan::ReadThrough,
        }),
        &IdentityOpWrite::auto(ClaimSource::Inferred),
        learned_at,
    )?;
    let event = match outcome {
        IdentityOpOutcome::Applied { event, .. } => event,
        other => panic!("fixture merge must apply, got {other:?}"),
    };
    let raw = vault.get_raw(&event)?.expect("type-76 event carrier");
    Ok((event, raw))
}

fn commit_entity(window: &LoadedWindow, learned_at: u64, data: &[u8]) -> EntityId {
    let id = EntityId::now();
    map_insert_bytes(
        &window.doc.get_map("entities"),
        &id.to_hex(),
        &make_entity_blob(1, learned_at, data),
    )
    .unwrap();
    window.doc.commit();
    id
}

/// ONE-1151 prune: `persist_state` deletes exactly the `u:w:{key}:*`
/// rows its snapshot subsumed — in the same transaction as the `d:w:`
/// write — while `m:u_seq:w:{key}` keeps its high-water mark
/// (ARCH-0023b: monotonic, missing=0) and every other row family
/// survives byte-identical: the neighbor window's `u:w:` rows, a
/// prefix-adjacent `u:w:` key (exact `u:w:{key}:` scope, not a sloppy
/// substring match), the `dt:` local hard-delete marker (sync_state),
/// and the `q:`/`d:`/`h:` sync_queue families a delete-bearing path
/// owns. The window must then reopen from `d:w:` ALONE.
#[test]
fn persist_state_prunes_subsumed_rows_and_spares_other_families() {
    let (_dir, vault) = test_vault();
    let materializer = Arc::new(Materializer::new());
    let key = WindowKey::new("2026-03");
    let t = key.start_timestamp().unwrap() + 60;

    let window = LoadedWindow::new("local", key.clone(), &vault, &materializer);
    let id_a = commit_entity(&window, t, b"prune-a");
    let id_b = commit_entity(&window, t, b"prune-b");

    // Observer A persisted the contract rows (ARCH-0023b key table).
    assert!(
        vault
            .sync_state_get("u:w:2026-03:00000001")
            .unwrap()
            .is_some()
    );
    assert!(
        vault
            .sync_state_get("u:w:2026-03:00000002")
            .unwrap()
            .is_some()
    );
    assert_eq!(
        vault
            .sync_state_get("m:u_seq:w:2026-03")
            .unwrap()
            .as_deref(),
        Some(2u32.to_le_bytes().as_slice())
    );

    // Sentinels the prune must NOT touch. sync_state families:
    vault
        .sync_state_put("u:w:2026-02:00000001", b"neighbor-window-update")
        .unwrap();
    vault
        .sync_state_put("u:w:2026-030:00000001", b"prefix-adjacent-update")
        .unwrap();
    let dt_key = format!("dt:{}", EntityId::now().to_hex());
    vault.sync_state_put(&dt_key, &[2u8; 26]).unwrap();
    // sync_queue families (`q:{seq:8BE}` update row, `d:{seq:8BE}`
    // delete-bearing sidecar, `h:{seq:8BE}` hard-erase sweep job):
    let q_key = [b'q', b':', 0, 0, 0, 0, 0, 0, 0, 1];
    let d_key = [b'd', b':', 0, 0, 0, 0, 0, 0, 0, 1];
    let h_key = [b'h', b':', 0, 0, 0, 0, 0, 0, 0, 1];
    {
        let mut wtxn = vault.store.env.write_txn().unwrap();
        vault
            .store
            .sync_queue
            .put(&mut wtxn, &q_key, &[1u8])
            .unwrap();
        vault
            .store
            .sync_queue
            .put(&mut wtxn, &d_key, &[1u8])
            .unwrap();
        vault
            .store
            .sync_queue
            .put(&mut wtxn, &h_key, &[7u8])
            .unwrap();
        wtxn.commit().unwrap();
    }

    window.persist_state(&vault).unwrap();

    // Subsumed rows pruned; the high-water mark is NOT reset.
    assert!(
        vault
            .sync_state_get("u:w:2026-03:00000001")
            .unwrap()
            .is_none(),
        "subsumed u:w: row must be pruned after the snapshot persist"
    );
    assert!(
        vault
            .sync_state_get("u:w:2026-03:00000002")
            .unwrap()
            .is_none()
    );
    assert_eq!(
        vault
            .sync_state_get("m:u_seq:w:2026-03")
            .unwrap()
            .as_deref(),
        Some(2u32.to_le_bytes().as_slice()),
        "m:u_seq:w: must stay monotonic — never reset by the prune"
    );
    assert!(vault.sync_state_get("d:w:2026-03").unwrap().is_some());
    // Positive control for the ONE-1151 svf recompute: with every u:w:
    // row subsumed and pruned, the post-prune probe finds zero rows, so
    // freshness is written FRESH ([1]) — proving the fix is not a blanket
    // svf=0 (see persist_state_marks_svf_stale_when_a_post_merge_uw_row_survives
    // for the surviving-row counterpart).
    assert_eq!(
        vault.sync_state_get("svf:w:2026-03").unwrap().as_deref(),
        Some([1u8].as_slice()),
        "all rows subsumed → svf recomputes FRESH"
    );

    // Every sentinel survives byte-identical.
    assert_eq!(
        vault
            .sync_state_get("u:w:2026-02:00000001")
            .unwrap()
            .as_deref(),
        Some(b"neighbor-window-update".as_slice()),
        "the neighbor window's u:w: rows are out of scope"
    );
    assert_eq!(
        vault
            .sync_state_get("u:w:2026-030:00000001")
            .unwrap()
            .as_deref(),
        Some(b"prefix-adjacent-update".as_slice()),
        "prune scope is exactly `u:w:{{key}}:` — never a substring match"
    );
    assert_eq!(
        vault.sync_state_get(&dt_key).unwrap().as_deref(),
        Some([2u8; 26].as_slice()),
        "dt: local hard-delete markers are out of scope (delete safety)"
    );
    {
        let rtxn = vault.store.env.read_txn().unwrap();
        assert_eq!(
            vault
                .store
                .sync_queue
                .get(&rtxn, &q_key)
                .unwrap()
                .as_deref(),
            Some([1u8].as_slice()),
            "q: update rows are out of scope"
        );
        assert_eq!(
            vault
                .store
                .sync_queue
                .get(&rtxn, &d_key)
                .unwrap()
                .as_deref(),
            Some([1u8].as_slice()),
            "d: delete-bearing sidecars are out of scope (delete safety)"
        );
        assert_eq!(
            vault
                .store
                .sync_queue
                .get(&rtxn, &h_key)
                .unwrap()
                .as_deref(),
            Some([7u8].as_slice()),
            "h: hard-erase sweep rows are out of scope (delete safety)"
        );
    }

    // The window reopens from d:w: ALONE (no u:w: rows left to replay).
    drop(window);
    assert_eq!(
        vault
            .sync_state_keys_with_prefix("u:w:2026-03:")
            .unwrap()
            .len(),
        0
    );
    let reloaded = load_window_from_state(&vault, "local", &key).unwrap();
    let entities = reloaded.get_map("entities");
    assert_eq!(
        map_get_bytes(&entities, &id_a.to_hex()).as_deref(),
        Some(make_entity_blob(1, t, b"prune-a").as_slice()),
        "pruned ops must reload from the d:w: snapshot"
    );
    assert!(map_get_bytes(&entities, &id_b.to_hex()).is_some());
}

#[test]
fn forward_remat_never_materializes_public_legacy_persona_facet() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let learned_at = window_key.start_timestamp().unwrap() + 90;
    let id = EntityId::from_bytes([0x33; 16]).unwrap();
    let person = EntityId::from_bytes([0x3D; 16]).unwrap();
    let body = crate::companion::tests::support::retired_persona_facet_body(person);
    let doc = create_window_doc("remote", &window_key);
    map_insert_bytes(
        &doc.get_map("entities"),
        &id.to_hex(),
        &make_entity_blob(ENTITY_TYPE_FACET, learned_at, &body),
    )?;
    doc.commit();
    let materializer = Materializer::new();
    let _ = forward_rematerialize(&vault, &doc, &materializer, &window_key)?;
    assert!(vault.get(&id)?.is_none());
    assert!(vault.get(&person)?.is_none());
    assert!(map_get_bytes(&doc.get_map("entities"), &id.to_hex()).is_none());
    Ok(())
}

/// ONE-1151 concurrency seam: a `u:w:` row persisted AFTER the merge
/// captured its subsumption inventory (a transient delete-path doc
/// persisting in parallel — its ops are in neither the merged set nor
/// the exported snapshot) gets a higher seq, is absent from the merged
/// key list, and MUST survive the prune; recovery still replays it.
#[test]
fn prune_spares_updates_persisted_after_the_merge() {
    let (_dir, vault) = test_vault();
    let materializer = Arc::new(Materializer::new());
    let key = WindowKey::new("2026-03");
    let t = key.start_timestamp().unwrap() + 60;

    let window = LoadedWindow::new("local", key.clone(), &vault, &materializer);
    commit_entity(&window, t, b"merged-op");

    // Snapshot-persist sequence as persist_state runs it, with a
    // concurrent writer landing BETWEEN the merge and the write txn.
    let merged = merge_persisted_state_into_doc(&vault, &window.doc, &key).unwrap();
    assert_eq!(merged, vec!["u:w:2026-03:00000001".to_string()]);

    let transient = create_window_doc("transient", &key);
    let late_id = EntityId::now();
    map_insert_bytes(
        &transient.get_map("entities"),
        &late_id.to_hex(),
        &make_entity_blob(1, t, b"late-op"),
    )
    .unwrap();
    transient.commit();
    let late_bytes = export_updates_from(&transient, &loro::VersionVector::default()).unwrap();
    bridge::persist_window_update(&vault, "2026-03", &late_bytes).unwrap();

    let state = export_snapshot(&window.doc).unwrap();
    let vv = doc_version_vector(&window.doc);
    vault
        .with_write_txn(|wtxn| {
            persist_window_doc_in_txn(&vault, wtxn, &key, &state, &vv)?;
            prune_subsumed_window_updates_in_txn(&vault, wtxn, &key, &merged)
        })
        .unwrap();

    assert!(
        vault
            .sync_state_get("u:w:2026-03:00000001")
            .unwrap()
            .is_none(),
        "the merged row is subsumed and pruned"
    );
    assert_eq!(
        vault
            .sync_state_get("u:w:2026-03:00000002")
            .unwrap()
            .as_deref(),
        Some(late_bytes.as_slice()),
        "a row persisted after the merge is NOT in the snapshot and must survive"
    );

    // Recovery = d:w: + surviving u:w: replay — the late op is intact.
    let recovered = load_window_from_state(&vault, "local", &key).unwrap();
    assert!(
        map_get_bytes(&recovered.get_map("entities"), &late_id.to_hex()).is_some(),
        "recovery must replay the surviving post-merge row"
    );
}

/// ONE-1151 svf-freshness fix: the prune_spares scenario driven through
/// the production `persist_state` path. A post-merge `u:w:` row lands
/// DURING the merge import (a one-shot subscription standing in for the
/// transient delete-path writer that persists in parallel), so it is
/// absent from the prune's subsumed-key inventory and survives. Because a
/// pending `u:w:` row then sits on top of `sv:w:`, `svf:w:` MUST be
/// written STALE (`[0]`) — a plausible-wrong impl that keeps the old
/// unconditional `svf=1` fails on the literal `[0]`.
#[test]
fn persist_state_marks_svf_stale_when_a_post_merge_uw_row_survives() {
    use loro::ContainerTrait;
    use std::sync::atomic::{AtomicBool, Ordering};

    let (_dir, vault) = test_vault();
    let materializer = Arc::new(Materializer::new());
    let key = WindowKey::new("2026-03");
    let t = key.start_timestamp().unwrap() + 60;

    let window = LoadedWindow::new("local", key.clone(), &vault, &materializer);

    // Pre-seed `u:w:2026-03:00000001` with an op the LIVE doc does NOT
    // hold, so `persist_state`'s merge import produces a diff (and fires
    // the injection below). This row IS in the merge inventory → pruned.
    let seed = create_window_doc("seed", &key);
    let seed_id = EntityId::now();
    map_insert_bytes(
        &seed.get_map("entities"),
        &seed_id.to_hex(),
        &make_entity_blob(1, t, b"seed-op"),
    )
    .unwrap();
    seed.commit();
    let seed_bytes = export_updates_from(&seed, &loro::VersionVector::default()).unwrap();
    bridge::persist_window_update(&vault, "2026-03", &seed_bytes).unwrap();

    // The survivor op (transient parallel writer): not in the merge
    // inventory, not in the exported snapshot.
    let late = create_window_doc("late", &key);
    let late_id = EntityId::now();
    map_insert_bytes(
        &late.get_map("entities"),
        &late_id.to_hex(),
        &make_entity_blob(1, t, b"late-op"),
    )
    .unwrap();
    late.commit();
    let late_bytes = export_updates_from(&late, &loro::VersionVector::default()).unwrap();

    // Inject the survivor row DURING the merge import (after the prune's
    // inventory was captured, before the write txn) — exactly the seam
    // prune_spares models manually, now exercised through persist_state.
    let injected = Arc::new(AtomicBool::new(false));
    let cb_vault = Arc::clone(&vault);
    let cb_bytes = late_bytes;
    let cb_flag = Arc::clone(&injected);
    let entities_cid = window.doc.get_map("entities").id();
    let _inj = window.doc.subscribe(
        &entities_cid,
        Arc::new(move |_event| {
            if cb_flag.swap(true, Ordering::SeqCst) {
                return;
            }
            bridge::persist_window_update(&cb_vault, "2026-03", &cb_bytes)
                .expect("inject post-merge survivor row");
        }),
    );

    window.persist_state(&vault).unwrap();
    assert!(injected.load(Ordering::SeqCst), "injection must have fired");

    // The merged row is pruned …
    assert!(
        vault
            .sync_state_get("u:w:2026-03:00000001")
            .unwrap()
            .is_none(),
        "the merged row is subsumed and pruned"
    );
    // … the post-merge row survives …
    assert!(
        vault
            .sync_state_get("u:w:2026-03:00000002")
            .unwrap()
            .is_some(),
        "a row persisted during the merge import escapes the prune"
    );
    // … the high-water mark stays monotonic …
    assert_eq!(
        vault
            .sync_state_get("m:u_seq:w:2026-03")
            .unwrap()
            .as_deref(),
        Some(2u32.to_le_bytes().as_slice()),
        "m:u_seq:w: must stay monotonic"
    );
    // … and svf is STALE: the fast-reconnect reader must NOT trust sv:w:.
    assert_eq!(
        vault.sync_state_get("svf:w:2026-03").unwrap().as_deref(),
        Some([0u8].as_slice()),
        "a surviving post-merge u:w: row forces svf STALE ([0])"
    );
}

/// ONE-1151 scope extension: the soft-only `pt:` replay branch keeps the
/// merged `u:w:` rows (only the hard branch scrubs them), so after a soft
/// replay a pending row still sits on top of `sv:w:` — `svf:w:` MUST be
/// written STALE. A wrong impl that writes `svf=1` in the soft branch
/// fails. (Delete-safety-adjacent.)
#[test]
fn replay_pending_tombstones_soft_keeps_svf_stale_when_merged_uw_survives() {
    let (_dir, vault) = test_vault();
    let materializer = Arc::new(Materializer::new());
    let key = WindowKey::new("2026-03");
    let t = key.start_timestamp().unwrap() + 60;

    // A live window with one committed entity → Observer A persists a
    // `u:w:` row the SOFT branch must NOT scrub.
    let window = LoadedWindow::new("local", key.clone(), &vault, &materializer);
    let _id = commit_entity(&window, t, b"keep-me");
    assert!(
        vault
            .sync_state_get("u:w:2026-03:00000001")
            .unwrap()
            .is_some()
    );

    // A SOFT pending-tombstone marker (user_delete, wire byte 1 = soft).
    let victim = EntityId::now();
    let mut soft = vec![1_u8]; // user_delete (soft)
    soft.extend_from_slice(&t.to_le_bytes());
    soft.extend_from_slice(&[0x11; 16]);
    let marker_key = format!("pt:2026-03:{}", victim.to_hex());
    vault.sync_state_put(&marker_key, &soft).unwrap();

    let replayed = replay_pending_tombstones(&vault, &window.doc, &key).unwrap();
    assert_eq!(replayed, 1);

    // The merged u:w: row survives the soft branch …
    assert!(
        vault
            .sync_state_get("u:w:2026-03:00000001")
            .unwrap()
            .is_some(),
        "soft replay must not scrub surviving u:w: rows"
    );
    // … so svf is STALE.
    assert_eq!(
        vault.sync_state_get("svf:w:2026-03").unwrap().as_deref(),
        Some([0u8].as_slice()),
        "a surviving u:w: row after a soft replay forces svf STALE"
    );
    // fr:w: full-resync is a HARD-only concern — untouched by soft replay.
    assert!(vault.sync_state_get("fr:w:2026-03").unwrap().is_none());
}

/// Fail-closed scope guard: a key outside the window's own
/// `u:w:{key}:` family is a TYPED error and the transaction deletes
/// nothing — not even the in-scope keys validated alongside it.
#[test]
fn prune_refuses_keys_outside_the_window_family() {
    let (_dir, vault) = test_vault();
    let key = WindowKey::new("2026-03");
    vault
        .sync_state_put("u:w:2026-03:00000001", b"in-scope")
        .unwrap();
    vault
        .sync_state_put("u:w:2026-02:00000001", b"foreign")
        .unwrap();

    let keys = vec![
        "u:w:2026-03:00000001".to_string(),
        "u:w:2026-02:00000001".to_string(),
    ];
    let err = vault
        .with_write_txn(|wtxn| prune_subsumed_window_updates_in_txn(&vault, wtxn, &key, &keys))
        .expect_err("a foreign key must fail the prune closed");
    assert!(
        matches!(
            err,
            Error::Sync(SyncError::SyncProtocolError {
                context: SyncProtocolValidation::ScopedPrune { .. }
            })
        ),
        "typed error, got: {err:?}"
    );
    assert_eq!(
        vault
            .sync_state_get("u:w:2026-03:00000001")
            .unwrap()
            .as_deref(),
        Some(b"in-scope".as_slice()),
        "validate-before-delete: the aborted txn must delete nothing"
    );
    assert_eq!(
        vault
            .sync_state_get("u:w:2026-02:00000001")
            .unwrap()
            .as_deref(),
        Some(b"foreign".as_slice())
    );
}

/// The single constructor of [`DeleteBearingUpdate`] (ONE-1135 review
/// item 14): a no-op tombstone commit exports nothing (no q:/d: rows
/// queued); a real tombstone commit exports a non-empty delta.
#[test]
fn export_tombstone_commit_delta_none_on_noop_some_on_commit() {
    let doc = create_window_doc("local", &WindowKey::from_timestamp(1_750_000_000_000));
    let vv_before = doc.oplog_vv();
    assert!(
        export_tombstone_commit_delta(&doc, &vv_before)
            .unwrap()
            .is_none(),
        "unchanged doc must export no delete-bearing update"
    );

    let id = EntityId::now();
    apply_tombstone_to_window_doc(&doc, &id, &[1, 2, 3]).unwrap();
    doc.commit();
    let delta = export_tombstone_commit_delta(&doc, &vv_before)
        .unwrap()
        .expect("tombstone commit must export a delete-bearing update");
    assert!(!delta.as_bytes().is_empty());
}

#[test]
fn default_policy_manifest_not_mirrored_to_crdt() {
    let (_dir, vault) = test_vault();
    let manifest_id = crate::gate::default_policy_manifest_id().unwrap();
    let window_key = WindowKey::from_timestamp(crate::gate::DEFAULT_POLICY_MANIFEST_TIMESTAMP);
    let doc = create_window_doc("local", &window_key);

    reverse_rematerialize(&vault, &doc, &window_key).unwrap();

    // ONE-1890's seeded AGENT_DEF rows share this timestamp-0 window and DO
    // mirror — they are ordinary byte-17 entities whose user edits must sync.
    // The manifest is the one engine-seeded row held back.
    assert!(
        map_get_bytes(&doc.get_map("entities"), &manifest_id.to_hex()).is_none(),
        "the engine-seeded policy manifest must stay out of ordinary sync windows"
    );
}

#[test]
fn default_policy_manifest_tombstone_not_replayed_from_crdt() {
    let (_dir, vault) = test_vault();
    let materializer = Materializer::new();
    let manifest_id = crate::gate::default_policy_manifest_id().unwrap();
    let window_key = WindowKey::from_timestamp(crate::gate::DEFAULT_POLICY_MANIFEST_TIMESTAMP);
    let doc = create_window_doc("remote", &window_key);
    apply_tombstone_to_window_doc(&doc, &manifest_id, &[1, 2, 3]).unwrap();
    doc.commit();

    let rematerialized = forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap();

    assert_eq!(rematerialized, 0);
    assert!(
        vault.get_raw(&manifest_id).unwrap().is_some(),
        "incoming policy-manifest tombstones must not delete local engine policy"
    );
}

#[test]
fn finalized_receipt_not_mirrored_to_crdt() {
    use crate::deletion::{
        RedactionReceiptInput, RedactionScope, decode_redaction_audit_receipt,
        encode_redaction_audit_receipt,
    };
    use crate::registry::ENTITY_TYPE_REDACTION_AUDIT;
    use crate::temporal::TimeRange;
    use ed25519_dalek::SigningKey;

    let (_dir, vault) = test_vault();
    let learned_at = 1_772_400_000u64;
    let window_key = WindowKey::from_timestamp(learned_at);
    let occurred = TimeRange {
        start: learned_at,
        end: learned_at,
    };
    let identity = crate::identity::DeviceIdentity {
        client_id: 0x0123_4567_89ab_cdefu64,
        signing_key: SigningKey::from_bytes(&[44u8; 32]),
    };

    let make_receipt_body = |receipt_id: &EntityId, subject: &EntityId, request_id: &str| {
        encode_redaction_audit_receipt(
            RedactionReceiptInput {
                actor_principal: None,
                room_authority: None,
                request_id: request_id.to_owned(),
                scope: RedactionScope::entity(subject),
                reason: crate::DeleteReason::GdprDelete,
                requested_at: learned_at - 10,
                soft_complete_at: learned_at - 9,
                hard_purge_complete_at: learned_at,
                sweep_queued_at: Some(learned_at - 8),
            },
            receipt_id,
            &identity,
        )
        .unwrap()
    };

    let finalized_id = EntityId::now();
    let finalized_subject = EntityId::now();
    let finalized_pre_body = make_receipt_body(
        &finalized_id,
        &finalized_subject,
        "018f3a2b-7c4d-7e5f-8a9b-0c1d2e3f4a5b",
    );
    let mut finalized_receipt = decode_redaction_audit_receipt(&finalized_pre_body).unwrap();
    finalized_receipt.sweep_complete_at = Some(learned_at + 1);
    let finalized_body = rmp_serde::to_vec_named(&finalized_receipt).unwrap();
    vault
        .batch()
        .put_replicated(
            &finalized_id,
            ENTITY_TYPE_REDACTION_AUDIT,
            occurred,
            learned_at,
            &finalized_body,
        )
        .commit()
        .unwrap();

    let pending_id = EntityId::now();
    let pending_subject = EntityId::now();
    let pending_body = make_receipt_body(
        &pending_id,
        &pending_subject,
        "018f3a2b-7c4d-7e5f-8a9b-0c1d2e3f4a5c",
    );
    vault
        .batch()
        .put_replicated(
            &pending_id,
            ENTITY_TYPE_REDACTION_AUDIT,
            occurred,
            learned_at,
            &pending_body,
        )
        .commit()
        .unwrap();

    let corrupt_id = EntityId::now();
    vault
        .batch()
        .put_replicated(
            &corrupt_id,
            ENTITY_TYPE_REDACTION_AUDIT,
            occurred,
            learned_at,
            b"invalid-receipt-body",
        )
        .commit()
        .unwrap();

    let ordinary_id = EntityId::now();
    vault
        .batch()
        .put_replicated(&ordinary_id, 1, occurred, learned_at, b"ordinary-body")
        .commit()
        .unwrap();

    let doc = create_window_doc("local", &window_key);
    let mirrored = reverse_rematerialize(&vault, &doc, &window_key).unwrap();
    assert_eq!(
        mirrored, 2,
        "only the pending receipt and ordinary entity should mirror"
    );

    let entities = doc.get_map("entities");
    assert!(
        map_get_bytes(&entities, &finalized_id.to_hex()).is_none(),
        "finalized REDACTION_AUDIT receipt is local-only and must not mirror"
    );
    assert!(
        map_get_bytes(&entities, &corrupt_id.to_hex()).is_none(),
        "undecodable REDACTION_AUDIT receipt must fail closed instead of mirroring raw"
    );

    let pending_raw =
        map_get_bytes(&entities, &pending_id.to_hex()).expect("pending receipt should mirror");
    assert_eq!(
        pending_raw,
        vault.get_raw(&pending_id).unwrap().expect("pending raw"),
        "non-finalized REDACTION_AUDIT receipt mirrors byte-exactly"
    );
    let pending_receipt =
        decode_redaction_audit_receipt(&pending_raw[ENTITY_METADATA_HEADER_LEN..]).unwrap();
    assert!(pending_receipt.sweep_complete_at.is_none());

    let ordinary_raw =
        map_get_bytes(&entities, &ordinary_id.to_hex()).expect("ordinary entity should mirror");
    assert_eq!(
        ordinary_raw,
        vault.get_raw(&ordinary_id).unwrap().expect("ordinary raw"),
        "ordinary entities mirror exactly as before"
    );
}

#[test]
fn finalized_receipt_not_mirrored_by_pending_mirror_replay() {
    use crate::deletion::{
        RedactionReceiptInput, RedactionScope, decode_redaction_audit_receipt,
        encode_redaction_audit_receipt,
    };
    use crate::registry::ENTITY_TYPE_REDACTION_AUDIT;
    use crate::temporal::TimeRange;
    use ed25519_dalek::SigningKey;

    let (_dir, vault) = test_vault();
    let learned_at = 1_772_400_000u64;
    let window_key = WindowKey::from_timestamp(learned_at);
    let occurred = TimeRange {
        start: learned_at,
        end: learned_at,
    };
    let identity = crate::identity::DeviceIdentity {
        client_id: 0x0123_4567_89ab_cdefu64,
        signing_key: SigningKey::from_bytes(&[44u8; 32]),
    };

    let make_receipt_body = |receipt_id: &EntityId, subject: &EntityId, request_id: &str| {
        encode_redaction_audit_receipt(
            RedactionReceiptInput {
                actor_principal: None,
                room_authority: None,
                request_id: request_id.to_owned(),
                scope: RedactionScope::entity(subject),
                reason: crate::DeleteReason::GdprDelete,
                requested_at: learned_at - 10,
                soft_complete_at: learned_at - 9,
                hard_purge_complete_at: learned_at,
                sweep_queued_at: Some(learned_at - 8),
            },
            receipt_id,
            &identity,
        )
        .unwrap()
    };

    let finalized_id = EntityId::now();
    let finalized_subject = EntityId::now();
    let finalized_pre_body = make_receipt_body(
        &finalized_id,
        &finalized_subject,
        "018f3a2b-7c4d-7e5f-8a9b-0c1d2e3f4a5b",
    );
    let mut finalized_receipt = decode_redaction_audit_receipt(&finalized_pre_body).unwrap();
    finalized_receipt.sweep_complete_at = Some(learned_at + 1);
    let finalized_body = rmp_serde::to_vec_named(&finalized_receipt).unwrap();
    vault
        .batch()
        .put_replicated(
            &finalized_id,
            ENTITY_TYPE_REDACTION_AUDIT,
            occurred,
            learned_at,
            &finalized_body,
        )
        .commit()
        .unwrap();

    let pending_id = EntityId::now();
    let pending_subject = EntityId::now();
    let pending_body = make_receipt_body(
        &pending_id,
        &pending_subject,
        "018f3a2b-7c4d-7e5f-8a9b-0c1d2e3f4a5c",
    );
    vault
        .batch()
        .put_replicated(
            &pending_id,
            ENTITY_TYPE_REDACTION_AUDIT,
            occurred,
            learned_at,
            &pending_body,
        )
        .commit()
        .unwrap();

    let corrupt_id = EntityId::now();
    vault
        .batch()
        .put_replicated(
            &corrupt_id,
            ENTITY_TYPE_REDACTION_AUDIT,
            occurred,
            learned_at,
            b"invalid-receipt-body",
        )
        .commit()
        .unwrap();

    let ordinary_id = EntityId::now();
    vault
        .batch()
        .put_replicated(&ordinary_id, 1, occurred, learned_at, b"ordinary-body")
        .commit()
        .unwrap();

    for id in [&finalized_id, &pending_id, &corrupt_id, &ordinary_id] {
        vault
            .sync_state_put(&format!("pm:{window_key}:{}", id.to_hex()), &[1u8])
            .unwrap();
    }

    let doc = create_window_doc("local", &window_key);
    let replayed = replay_pending_mirrors(&vault, &doc, &window_key).unwrap();
    assert_eq!(
        replayed, 2,
        "only the pending receipt and ordinary entity should replay"
    );

    let entities = doc.get_map("entities");
    assert!(
        map_get_bytes(&entities, &finalized_id.to_hex()).is_none(),
        "finalized REDACTION_AUDIT receipt is local-only and must not replay"
    );
    assert!(
        map_get_bytes(&entities, &corrupt_id.to_hex()).is_none(),
        "undecodable REDACTION_AUDIT receipt must fail closed instead of replaying raw"
    );

    let pending_raw =
        map_get_bytes(&entities, &pending_id.to_hex()).expect("pending receipt should replay");
    assert_eq!(
        pending_raw,
        vault.get_raw(&pending_id).unwrap().expect("pending raw"),
        "non-finalized REDACTION_AUDIT receipt replays byte-exactly"
    );
    let pending_receipt =
        decode_redaction_audit_receipt(&pending_raw[ENTITY_METADATA_HEADER_LEN..]).unwrap();
    assert!(pending_receipt.sweep_complete_at.is_none());

    let ordinary_raw =
        map_get_bytes(&entities, &ordinary_id.to_hex()).expect("ordinary entity should replay");
    assert_eq!(
        ordinary_raw,
        vault.get_raw(&ordinary_id).unwrap().expect("ordinary raw"),
        "ordinary entities replay exactly as before"
    );

    for id in [&finalized_id, &pending_id, &corrupt_id, &ordinary_id] {
        assert!(
            vault
                .sync_state_get(&format!("pm:{window_key}:{}", id.to_hex()))
                .unwrap()
                .is_none(),
            "processed pm marker should be cleared for {}",
            id.to_hex()
        );
    }
}

#[test]
fn forward_remat_quarantines_receipt_when_lease_revoked_between_check_and_write() {
    use ed25519_dalek::SigningKey;

    let (_dir, vault) = test_vault();
    let materializer = Materializer::new();
    let learned_at = 1_772_400_000u64;
    let window_key = WindowKey::from_timestamp(learned_at);
    let receipt_id = EntityId::from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
    let subject = EntityId::from_hex("101112131415161718191a1b1c1d1e1f").unwrap();
    let client_id = 0x0123_4567_89ab_cdefu64;
    let signing_key = SigningKey::from_bytes(&[44u8; 32]);
    let pubkey = signing_key.verifying_key().to_bytes();
    let identity = crate::identity::DeviceIdentity {
        client_id,
        signing_key,
    };
    let vault_id = crate::sync::lease::DEFAULT_LEASE_VAULT_ID;
    let input = crate::deletion::RedactionReceiptInput {
        actor_principal: None,
        room_authority: None,
        request_id: "018f3a2b-7c4d-7e5f-8a9b-0c1d2e3f4a5b".to_owned(),
        scope: crate::deletion::RedactionScope::entity(&subject),
        reason: crate::DeleteReason::GdprDelete,
        requested_at: 100,
        soft_complete_at: 101,
        hard_purge_complete_at: learned_at,
        sweep_queued_at: Some(102),
    };
    let body =
        crate::deletion::encode_redaction_audit_receipt(input, &receipt_id, &identity).unwrap();
    let mut blob = crate::deletion::receipt_envelope_header(learned_at).to_vec();
    blob.extend_from_slice(&body);

    let active = crate::sync::lease::LeaseRecord {
        vault_id,
        status: crate::sync::lease::LeaseStatus::Active,
        pubkey,
        granted_at: 1,
        renewed_at: 2,
        expires_at: 3,
    };
    let revoked = crate::sync::lease::LeaseRecord {
        status: crate::sync::lease::LeaseStatus::Revoked,
        ..active
    };
    let lease_key = crate::sync::lease::lease_key(vault_id, client_id);
    vault
        .sync_state_put(
            &lease_key,
            &crate::sync::lease::encode_lease_record(&active),
        )
        .unwrap();

    let doc = create_window_doc("local", &window_key);
    doc.get_map("entities")
        .insert(receipt_id.to_hex().as_str(), blob.as_slice())
        .unwrap();
    doc.commit();

    test_hooks::arm_receipt_revocation_race(
        lease_key,
        crate::sync::lease::encode_lease_record(&revoked).to_vec(),
    );
    let count = forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap();
    assert_eq!(count, 0, "the revoked receipt is quarantined, not written");
    assert!(
        vault.get_raw(&receipt_id).unwrap().is_none(),
        "the stale-read race must not write the receipt entity"
    );
    let records = quarantine::quarantined_records(&vault).unwrap();
    assert_eq!(records.len(), 1);
    let record = &records[0].1;
    assert_eq!(record.window_key, window_key.as_str());
    assert_eq!(record.container, QuarantineContainer::Entities);
    assert_eq!(record.reason_code, "ReceiptLeaseRevoked");
}

#[test]
fn forward_remat_quarantines_divergent_receipt_landing_mid_flight() {
    use ed25519_dalek::SigningKey;

    let (_dir, vault) = test_vault();
    let materializer = Materializer::new();
    let learned_at = 1_772_400_000u64;
    let window_key = WindowKey::from_timestamp(learned_at);
    let receipt_id = EntityId::from_hex("202122232425262728292a2b2c2d2e2f").unwrap();
    let subject = EntityId::from_hex("303132333435363738393a3b3c3d3e3f").unwrap();
    let client_id = 0x0fed_cba9_8765_4321u64;
    let vault_id = crate::sync::lease::DEFAULT_LEASE_VAULT_ID;
    let signing_key = SigningKey::from_bytes(&[45u8; 32]);
    let pubkey = signing_key.verifying_key().to_bytes();
    let identity = crate::identity::DeviceIdentity {
        client_id,
        signing_key,
    };

    let remote_input = crate::deletion::RedactionReceiptInput {
        actor_principal: None,
        room_authority: None,
        request_id: "018f3a2b-7c4d-7e5f-8a9b-0c1d2e3f4a5c".to_owned(),
        scope: crate::deletion::RedactionScope::entity(&subject),
        reason: crate::DeleteReason::GdprDelete,
        requested_at: 100,
        soft_complete_at: 101,
        hard_purge_complete_at: learned_at,
        sweep_queued_at: Some(102),
    };
    let remote_body =
        crate::deletion::encode_redaction_audit_receipt(remote_input, &receipt_id, &identity)
            .unwrap();
    let mut remote_blob = crate::deletion::receipt_envelope_header(learned_at).to_vec();
    remote_blob.extend_from_slice(&remote_body);

    let local_input = crate::deletion::RedactionReceiptInput {
        actor_principal: None,
        room_authority: None,
        request_id: "018f3a2b-7c4d-7e5f-8a9b-0c1d2e3f4a5d".to_owned(),
        scope: crate::deletion::RedactionScope::entity(&subject),
        reason: crate::DeleteReason::GdprDelete,
        requested_at: 100,
        soft_complete_at: 101,
        hard_purge_complete_at: learned_at,
        sweep_queued_at: Some(102),
    };
    let local_body =
        crate::deletion::encode_redaction_audit_receipt(local_input, &receipt_id, &identity)
            .unwrap();
    let mut local_blob = crate::deletion::receipt_envelope_header(learned_at).to_vec();
    local_blob.extend_from_slice(&local_body);
    assert_ne!(local_blob, remote_blob);

    let active = crate::sync::lease::LeaseRecord {
        vault_id,
        status: crate::sync::lease::LeaseStatus::Active,
        pubkey,
        granted_at: 1,
        renewed_at: 2,
        expires_at: 3,
    };
    vault
        .sync_state_put(
            &crate::sync::lease::lease_key(vault_id, client_id),
            &crate::sync::lease::encode_lease_record(&active),
        )
        .unwrap();

    let doc = create_window_doc("local", &window_key);
    doc.get_map("entities")
        .insert(receipt_id.to_hex().as_str(), remote_blob.as_slice())
        .unwrap();
    doc.commit();

    test_hooks::arm_receipt_local_write_race(receipt_id, local_blob.clone());
    let count = forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap();
    assert_eq!(
        count, 0,
        "the divergent remote receipt is quarantined, not written"
    );
    assert_eq!(
        vault.get_raw(&receipt_id).unwrap().as_deref(),
        Some(local_blob.as_slice()),
        "the in-txn recheck must keep the mid-flight local receipt bytes"
    );
    let records = quarantine::quarantined_records(&vault).unwrap();
    assert_eq!(records.len(), 1);
    let record = &records[0].1;
    assert_eq!(record.window_key, window_key.as_str());
    assert_eq!(record.container, QuarantineContainer::Entities);
    assert_eq!(record.reason_code, "RedactionReceiptDivergence");
}

/// MS-01 (ARCH-0055 trust perimeter): forward rematerialization routes
/// type-76 identity-topology events through the SAME fail-closed
/// single-writer ingest door as Observer B — an accepted record derives its
/// shell edge, DIVERGENT remote bytes quarantine-and-continue instead of
/// LWW-overwriting the accepted local event (the pre-fix generic
/// `put_replicated` arm), and an unledgered reserved-kind edges-map row is
/// quarantined, never materialized.
#[test]
fn forward_rematerialization_routes_type_76_through_the_ingest_door() -> Result<()> {
    use crate::identity_topology::{
        EntityLifecycleState, StoredIdentityOpAction, StoredIdentityOpEvent,
    };

    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let survivor = EntityId::from_bytes([0x61; 16])?;
    let loser = EntityId::from_bytes([0x62; 16])?;
    let stranger = EntityId::from_bytes([0x63; 16])?;
    for id in [&survivor, &loser, &stranger] {
        vault.put_entity(
            id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person fixture",
        )?;
    }

    let event_id = EntityId::from_bytes([0x70; 16])?;
    let record = StoredIdentityOpEvent {
        seq: 50,

        validated_at_write: false,

        invalidated: false,
        at: 200,
        actor: None,
        source: ClaimSource::Inferred,
        approval: ClaimApprovalStatus::Auto,
        confidence: 1.0,
        evidence: None,
        action: StoredIdentityOpAction::Merge {
            sources: vec![loser],
            survivor,
        },
    };
    let body = crate::identity_topology::encode_identity_topology_event_body(&record)?;
    let doc = create_window_doc("remote", &window_key);
    let entities = doc.get_map("entities");
    let edges = doc.get_map("edges");
    map_insert_bytes(
        &entities,
        &event_id.to_hex(),
        &make_entity_blob(
            crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
            200,
            &body,
        ),
    )?;
    let (fact_id, fact) =
        crate::identity_topology::signed_validated_row_for_test(&vault, event_id, &record)?;
    let fact_body = crate::identity_topology::encode_identity_topology_event_body(&fact)?;
    map_insert_bytes(
        &entities,
        &fact_id.to_hex(),
        &make_entity_blob(
            crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
            200,
            &fact_body,
        ),
    )?;
    // A forged reserved-kind row no ledger event mandates.
    let forged_key = format_edge_key(&stranger, EdgeKind::MergedInto, &survivor);
    map_insert_bytes(
        &edges,
        &forged_key,
        &encode_edge_value_for_crdt(EdgeKind::MergedInto, 0.3, 10, None, None)?,
    )?;
    doc.commit();

    forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;

    // The accepted record materialized AND derived its shell edge; the
    // forged row never landed but left quarantine evidence.
    assert!(vault.identity_topology_event(&event_id)?.is_some());
    assert!(vault.edge_exists(&loser, EdgeKind::MergedInto, &survivor)?);
    assert_eq!(
        vault.entity_lifecycle_state(&loser)?,
        EntityLifecycleState::Merged
    );
    assert!(!vault.edge_exists(&stranger, EdgeKind::MergedInto, &survivor)?);
    assert!(
        !crate::sync::quarantine::quarantined_records(&vault)?.is_empty(),
        "the forged shell row must leave hashed quarantine evidence"
    );

    // Divergent bytes for the SAME event id: the door keeps the accepted
    // local bytes and quarantines-and-continues — remat must not abort and
    // must not silently LWW-overwrite.
    let mut divergent = record;
    divergent.at = 999;
    let divergent_body = crate::identity_topology::encode_identity_topology_event_body(&divergent)?;
    map_insert_bytes(
        &entities,
        &event_id.to_hex(),
        &make_entity_blob(
            crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
            200,
            &divergent_body,
        ),
    )?;
    doc.commit();
    forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
    assert_eq!(
        vault.identity_topology_event(&event_id)?.map(|r| r.at),
        Some(200),
        "divergent remote bytes must never overwrite the accepted event"
    );
    assert!(
        vault.edge_exists(&loser, EdgeKind::MergedInto, &survivor)?,
        "the mandated shell edge survives the rejected divergence"
    );
    Ok(())
}

#[test]
fn forward_rematerialization_quarantines_forged_shell_and_continues_edge_pass() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let forged_source = EntityId::from_bytes([0x81; 16])?;
    let ordinary_source = EntityId::from_bytes([0x82; 16])?;
    let target = EntityId::from_bytes([0x83; 16])?;
    for id in [&forged_source, &ordinary_source, &target] {
        vault.put_entity(
            id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person fixture",
        )?;
    }

    let doc = create_window_doc("remote", &window_key);
    let edges = doc.get_map("edges");
    let forged_key = format_edge_key(&forged_source, EdgeKind::MergedInto, &target);
    let forged_value = encode_edge_value_for_crdt(EdgeKind::MergedInto, 0.3, 10, None, None)?;
    map_insert_bytes(&edges, &forged_key, &forged_value)?;
    let ordinary_key = format_edge_key(&ordinary_source, EdgeKind::Mentions, &target);
    let ordinary_value = encode_edge_value_for_crdt(EdgeKind::Mentions, 0.4, 11, None, None)?;
    map_insert_bytes(&edges, &ordinary_key, &ordinary_value)?;
    doc.commit();

    let count = forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
    assert_eq!(
        count, 1,
        "the forged shell is skipped while the other N-1 edge still heals"
    );
    assert!(
        !vault.edge_exists(&forged_source, EdgeKind::MergedInto, &target)?,
        "an unledgered reserved edge must never land"
    );
    assert!(
        vault.edge_exists(&ordinary_source, EdgeKind::Mentions, &target)?,
        "one poisoned edge must not abort the rest of the rematerialization pass"
    );
    let quarantined = crate::sync::quarantine::quarantined_records(&vault)?;
    assert_eq!(quarantined.len(), 1);
    let record = &quarantined[0].1;
    assert_eq!(record.container, QuarantineContainer::Edges);
    assert_eq!(record.reason_code, "ReservedEdgeKind");
    assert_eq!(
        (record.crdt_key_hash, record.crdt_key_len),
        crate::sync::quarantine::crdt_key_metadata(&forged_key)
    );
    assert_eq!(
        record.payload_hash,
        crate::sync::quarantine::payload_hash(&forged_value)
    );
    Ok(())
}

#[test]
fn replicated_delegated_channel_identity_is_rejected_after_local_retirement() -> Result<()> {
    use crate::channel_identity::{
        ChannelIdentity, ChannelIdentityState, encode_channel_identity_body,
    };

    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let learned_at = window_key.start_timestamp().unwrap() + 60;
    let address = "member@example.test";
    let (grant, binding) =
        delegated_identity_fixture(&vault, "member-custody", address, learned_at)?;
    let retired_id = EntityId::from_bytes([0xB1; 16])?;
    let (retired, peer_identity) = release_local_delegated_identity(
        &vault,
        retired_id,
        learned_at,
        address,
        grant.clone(),
        binding,
    )?;
    assert_eq!(retired.state(), ChannelIdentityState::Released);
    // The local custody record remains active and really covers this mailbox;
    // it is not missing custody that makes the peer's row invalid.
    vault.verify_delegated_custody("email", address, &grant)?;

    // A peer can replay the byte-exact ACTIVE body this vault previously held
    // under a fresh id. It names the freed key and locally valid custody, but
    // the peer did not perform this vault's provision/bind/fulfillment.
    let peer_body = encode_channel_identity_body(&peer_identity)?;
    let peer_id = EntityId::from_bytes([0xB2; 16])?;

    // Self-held identities remain ordinary replicated rows.
    let self_held_id = EntityId::from_bytes([0xB3; 16])?;
    let self_held = ChannelIdentity::own_app_home(EntityId::from_bytes([0xB4; 16])?, learned_at);
    let self_held_body = encode_channel_identity_body(&self_held)?;
    let doc = create_window_doc("peer-authored", &window_key);
    let entities = doc.get_map("entities");
    map_insert_bytes(
        &entities,
        &peer_id.to_hex(),
        &make_entity_blob(
            crate::registry::ENTITY_TYPE_CHANNEL_IDENTITY,
            learned_at + 4,
            &peer_body,
        ),
    )?;
    map_insert_bytes(
        &entities,
        &self_held_id.to_hex(),
        &make_entity_blob(
            crate::registry::ENTITY_TYPE_CHANNEL_IDENTITY,
            learned_at,
            &self_held_body,
        ),
    )?;
    doc.commit();

    let count = forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
    assert_eq!(count, 1, "the self-held control row still replays");
    assert!(
        vault.get_raw_unsealed(&peer_id)?.is_none(),
        "a peer-authored delegated row must not occupy the freed assignment key"
    );
    assert_eq!(
        vault
            .get_channel_identity(&self_held_id)?
            .map(|row| row.state()),
        Some(ChannelIdentityState::Active),
        "self-held active identity replication stays supported"
    );
    let rejected = crate::sync::quarantine::quarantined_records(&vault)?;
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0].1.reason_code, "InvalidChannelIdentityBody");
    Ok(())
}

#[test]
fn malformed_channel_identity_carriers_are_scrubbed_before_export() -> Result<()> {
    use crate::channel_identity::{
        ChannelIdentity, DelegatedGrant, DelegatedGrantScope, encode_channel_identity_body,
    };
    let (_dir, vault) = test_vault();
    let window = WindowKey::new("2026-03");
    let at = window.start_timestamp().expect("window") + 60;
    let grant = DelegatedGrant::new("oauth/gmail/member", vec![DelegatedGrantScope::MailRead]);
    let (grant, binding) =
        delegated_identity_fixture(&vault, &grant.custody_record_ref, "member@example.test", at)?;
    let id = EntityId::from_bytes([0xD8; 16])?;
    let (_, active) =
        release_local_delegated_identity(&vault, id, at, "member@example.test", grant, binding)?;
    let valid_delegated = encode_channel_identity_body(&active)?;
    let mut damaged = valid_delegated;
    // MessagePack fixmap: claim one additional entry but leave all existing
    // grant-ref/scope bytes intact. Neither strict nor fallback decode succeeds.
    match damaged[0] {
        0x80..=0x8e => damaged[0] += 1,
        0xde => {
            let count = u16::from_be_bytes([damaged[1], damaged[2]]) + 1;
            damaged[1..3].copy_from_slice(&count.to_be_bytes());
        }
        0xdf => {
            let count = u32::from_be_bytes(damaged[1..5].try_into().expect("map32 header")) + 1;
            damaged[1..5].copy_from_slice(&count.to_be_bytes());
        }
        other => panic!("identity body is not a MessagePack map: {other:#x}"),
    }
    assert!(crate::channel_identity::decode_channel_identity_body(&damaged).is_err());
    let damaged_blob =
        make_entity_blob(crate::registry::ENTITY_TYPE_CHANNEL_IDENTITY, at, &damaged);
    let healthy = ChannelIdentity::own_app_home(EntityId::from_bytes([0xD9; 16])?, at);
    let healthy_blob = make_entity_blob(
        crate::registry::ENTITY_TYPE_CHANNEL_IDENTITY,
        at,
        &encode_channel_identity_body(&healthy)?,
    );
    assert!(!is_delegated_channel_identity_carrier(&healthy_blob));
    assert!(is_delegated_channel_identity_carrier(&damaged_blob));
    for (label, key) in [
        ("canonical", EntityId::from_bytes([0xDA; 16])?.to_hex()),
        ("noncanonical", "not-an-entity-key".to_owned()),
    ] {
        let doc = create_window_doc(label, &window);
        let entities = doc.get_map("entities");
        let edges = doc.get_map("edges");
        map_insert_bytes(&entities, &key, &damaged_blob)?;
        let healthy_id = EntityId::from_bytes([0xDB; 16])?;
        map_insert_bytes(&entities, &healthy_id.to_hex(), &healthy_blob)?;
        let edge_key = format_edge_key(
            &EntityId::from_bytes([0xDA; 16])?,
            EdgeKind::Mentions,
            &healthy_id,
        );
        if label == "canonical" {
            map_insert_bytes(
                &edges,
                &edge_key,
                &encode_edge_value_for_crdt(EdgeKind::Mentions, 1.0, at, None, None)?,
            )?;
        }
        doc.commit();
        // Even a peer at the initial frontier receives only a history-free
        // snapshot. Import it to prove the damaged carrier and incident edge
        // cannot be reconstructed from the exported bytes.
        let exported =
            export_window_updates_since(&vault, &window, &doc, &VersionVector::default().encode())?;
        let peer = LoroDoc::new();
        import_doc(&peer, &exported)?;
        assert!(
            peer.is_shallow(),
            "scrubbed history never goes out as raw deltas"
        );
        assert!(map_get_bytes(&peer.get_map("entities"), &key).is_none());
        assert!(map_get_bytes(&peer.get_map("entities"), &healthy_id.to_hex()).is_some());
        if label == "canonical" {
            assert!(map_get_bytes(&peer.get_map("edges"), &edge_key).is_none());
        }
        assert!(history_free_window_required(&vault, &window)?);
        assert!(
            map_get_bytes(&entities, &key).is_none(),
            "{label} damaged identity removed"
        );
        assert!(
            map_get_bytes(&entities, &healthy_id.to_hex()).is_some(),
            "valid self-held identity stays portable"
        );
        if label == "canonical" {
            assert!(
                map_get_bytes(&edges, &edge_key).is_none(),
                "incident edge removed"
            );
        }
    }
    Ok(())
}

#[test]
fn forward_remat_quarantines_replicated_secret_custody_carrier() -> Result<()> {
    // C1 APPLY-TIME SEAL, end to end: a peer files a SECRET_CUSTODY body in
    // the window doc. The generic `put_replicated` arm used to admit byte 77
    // straight into LMDB (the replicated type gate named only POLICY_MANIFEST
    // / ACCESS_GRANT / OUTBOUND_GRANT), materializing peer-authored plaintext
    // `value_bytes`. It must now quarantine the row and continue the pass.
    use crate::secret_custody::{
        CustodyClass, SECRET_CUSTODY_SCHEMA_VERSION, SecretCustodyFloor, SecretCustodyRecord,
        SecretCustodyStatus, encode_secret_custody_body,
    };

    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let learned_at = window_key.start_timestamp().unwrap() + 60;
    let custody_id = EntityId::from_bytes([0x51; 16])?;
    let ordinary_id = EntityId::from_bytes([0x52; 16])?;

    let body = encode_secret_custody_body(&SecretCustodyRecord {
        schema_version: SECRET_CUSTODY_SCHEMA_VERSION,
        name: "peer-authored".to_owned(),
        class: CustodyClass::CustodyDeviceBound,
        device_only: false,
        value_bytes: b"peer-plaintext-value".to_vec(),
        status: SecretCustodyStatus::Active,
        registered_at: learned_at,
        rotated_at: None,
        rotation_generation: 0,
        bindings: Vec::new(),
        manifest_ref: String::new(),
        declared_paths: Vec::new(),
        policy_floor_snapshot: SecretCustodyFloor::default(),
    })?;
    let custody_blob = make_entity_blob(ENTITY_TYPE_SECRET_CUSTODY, learned_at, &body);
    let ordinary_blob = make_entity_blob(ENTITY_TYPE_TURN, learned_at, b"ordinary turn body");

    let doc = create_window_doc("remote", &window_key);
    let entities = doc.get_map("entities");
    map_insert_bytes(&entities, &custody_id.to_hex(), &custody_blob)?;
    map_insert_bytes(&entities, &ordinary_id.to_hex(), &ordinary_blob)?;
    doc.commit();

    let count = forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;

    assert_eq!(count, 1, "the ordinary row still materializes");
    assert!(
        vault
            .store
            .entities
            .get(&vault.store.env.read_txn()?, custody_id.as_bytes())?
            .is_none(),
        "a replicated custody body must never reach LMDB"
    );
    assert!(
        vault.get_raw(&ordinary_id)?.is_some(),
        "one sealed custody row must not wedge the rest of the pass"
    );
    let quarantined = crate::sync::quarantine::quarantined_records(&vault)?;
    assert_eq!(quarantined.len(), 1);
    assert_eq!(quarantined[0].1.container, QuarantineContainer::Entities);
    assert_eq!(
        quarantined[0].1.reason_code, "InvalidSecretCustodyBody",
        "the custody seal must classify as a remote rejection, not a local failure"
    );
    Ok(())
}

#[test]
fn forward_rematerialization_admits_byte_exact_mandated_shell_echo() -> Result<()> {
    use crate::identity_topology::{
        IdentityOpEvidence, IdentityOpOutcome, IdentityOpWrite, IdentityTopologyOp, MergeOp,
        SurvivorshipPlan,
    };

    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let survivor = EntityId::from_bytes([0x91; 16])?;
    let loser = EntityId::from_bytes([0x92; 16])?;
    for id in [&survivor, &loser] {
        vault.put_entity(
            id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person fixture",
        )?;
    }
    let outcome = vault.apply_identity_topology_op(
        &IdentityTopologyOp::Merge(MergeOp {
            sources: vec![loser],
            survivor,
            evidence: IdentityOpEvidence {
                refs: Vec::new(),
                rationale: "mandated echo fixture".to_owned(),
            },
            survivorship_plan: SurvivorshipPlan::ReadThrough,
        }),
        &IdentityOpWrite::auto(ClaimSource::Inferred),
        200,
    )?;
    assert!(matches!(outcome, IdentityOpOutcome::Applied { .. }));
    assert!(vault.edge_exists(&loser, EdgeKind::MergedInto, &survivor)?);

    // Simulate a replica whose ledger event survived but whose derived edge
    // indexes did not. Only the byte-exact door echo in the CRDT may heal it.
    let out_key = Store::encode_edge_key(&loser, EdgeKind::MergedInto, &survivor);
    let in_key = Store::encode_edge_key(&survivor, EdgeKind::MergedInto, &loser);
    vault.with_write_txn(|wtxn| {
        vault.store.edges_out.delete(wtxn, &out_key)?;
        vault.store.edges_in.delete(wtxn, &in_key)?;
        Ok(())
    })?;
    assert!(!vault.edge_exists(&loser, EdgeKind::MergedInto, &survivor)?);

    let doc = create_window_doc("remote", &window_key);
    let shell_key = format_edge_key(&loser, EdgeKind::MergedInto, &survivor);
    let shell_value = encode_edge_value_for_crdt(
        EdgeKind::MergedInto,
        EdgeKind::MergedInto.default_weight().expect("shell weight"),
        200,
        None,
        None,
    )?;
    map_insert_bytes(&doc.get_map("edges"), &shell_key, &shell_value)?;
    doc.commit();

    let count = forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
    assert_eq!(count, 1, "the mandated echo must heal the missing edge");
    assert!(vault.edge_exists(&loser, EdgeKind::MergedInto, &survivor)?);
    let rtxn = vault.store.env.read_txn()?;
    let healed_out = vault
        .store
        .edges_out
        .get(&rtxn, &out_key)?
        .expect("outbound shell index healed");
    let healed_in = vault
        .store
        .edges_in
        .get(&rtxn, &in_key)?
        .expect("inbound shell index healed");
    assert_eq!(healed_out.as_ref(), shell_value.as_slice());
    assert_eq!(healed_in.as_ref(), shell_value.as_slice());
    drop(rtxn);
    assert!(
        crate::sync::quarantine::quarantined_records(&vault)?.is_empty(),
        "a byte-exact mandated echo must be admitted, not quarantined"
    );
    Ok(())
}

#[test]
fn reverse_rematerialization_restores_protected_row_against_hostile_tombstone() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let learned_at = window_key.start_timestamp().unwrap() + 60;
    // Seed a NON-reserved participant id: [0xA1;16]..[0xA5;16] are the
    // write-door-reserved system-agent preset ids (batch.rs put guard), so
    // put_entity on 0xA1/0xA2 fails InvalidKey in setup. 0xB1 is the sibling's.
    let (event, raw) = put_local_type_76_event(&vault, learned_at, 0xC1)?;
    let tombstone = learned_at.to_be_bytes();

    // Model a hostile peer update that retained only delete authority in the
    // window. Reverse recovery must type-classify the local row before that
    // tombstone can suppress its carrier fleet-wide.
    let doc = create_window_doc("hostile-reverse", &window_key);
    map_insert_bytes(&doc.get_map("tombstones"), &event.to_hex(), &tombstone)?;
    doc.commit();

    assert_eq!(
        reverse_rematerialize(&vault, &doc, &window_key)?,
        2,
        "the immutable decision and its signed admission fact are both recovered"
    );
    assert_eq!(
        map_get_bytes(&doc.get_map("entities"), &event.to_hex()),
        Some(raw),
        "reverse recovery must restore the protected type-76 carrier"
    );
    assert!(
        tombstone_map_contains_id(&doc.get_map("tombstones"), &event),
        "recovery denies delete authority without rewriting remote history"
    );
    let quarantined = quarantine::quarantined_records(&vault)?;
    assert_eq!(quarantined.len(), 1);
    assert_eq!(quarantined[0].1.container, QuarantineContainer::Tombstones);
    assert_eq!(quarantined[0].1.reason_code, "MaintenanceKindNotWritable");
    assert_eq!(
        quarantined[0].1.payload_hash,
        quarantine::payload_hash(&tombstone)
    );
    Ok(())
}

#[test]
fn pending_mirror_replays_protected_row_against_hostile_tombstone() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let learned_at = window_key.start_timestamp().unwrap() + 60;
    let (event, raw) = put_local_type_76_event(&vault, learned_at, 0xB1)?;
    let marker = format!("pm:{window_key}:{}", event.to_hex());
    vault.sync_state_put(&marker, &[1])?;
    let tombstone = learned_at.to_be_bytes();

    let doc = create_window_doc("hostile-pending", &window_key);
    map_insert_bytes(&doc.get_map("tombstones"), &event.to_hex(), &tombstone)?;
    doc.commit();

    assert_eq!(replay_pending_mirrors(&vault, &doc, &window_key)?, 1);
    assert_eq!(
        map_get_bytes(&doc.get_map("entities"), &event.to_hex()),
        Some(raw),
        "pending recovery must mirror the protected type-76 carrier"
    );
    assert!(
        vault.sync_state_get(&marker)?.is_none(),
        "the pending marker clears only after the protected carrier is mirrored"
    );
    let quarantined = quarantine::quarantined_records(&vault)?;
    assert_eq!(quarantined.len(), 1);
    assert_eq!(quarantined[0].1.container, QuarantineContainer::Tombstones);
    assert_eq!(quarantined[0].1.reason_code, "MaintenanceKindNotWritable");
    assert_eq!(
        quarantined[0].1.payload_hash,
        quarantine::payload_hash(&tombstone)
    );
    Ok(())
}

#[test]
fn forward_rematerialization_quarantines_concurrent_type_76_tombstone() -> Result<()> {
    use crate::identity_topology::{StoredIdentityOpAction, StoredIdentityOpEvent};

    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let event_id = EntityId::from_bytes([0x70; 16])?;
    let record = StoredIdentityOpEvent {
        seq: 50,

        validated_at_write: false,

        invalidated: false,
        at: 200,
        actor: None,
        source: ClaimSource::Inferred,
        approval: ClaimApprovalStatus::Auto,
        confidence: 1.0,
        evidence: None,
        action: StoredIdentityOpAction::Merge {
            sources: vec![EntityId::from_bytes([0x61; 16])?],
            survivor: EntityId::from_bytes([0x62; 16])?,
        },
    };
    let body = crate::identity_topology::encode_identity_topology_event_body(&record)?;
    let event_blob = make_entity_blob(
        crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
        record.at,
        &body,
    );
    let doc = create_window_doc("remote", &window_key);
    map_insert_bytes(&doc.get_map("entities"), &event_id.to_hex(), &event_blob)?;
    map_insert_bytes(
        &doc.get_map("tombstones"),
        &event_id.to_hex(),
        &record.at.to_be_bytes(),
    )?;
    doc.commit();

    let expected_event = record.clone();
    forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
    assert_eq!(
        vault.identity_topology_event(&event_id)?,
        Some(expected_event),
        "the protected entity blob must materialize despite its hostile concurrent tombstone"
    );
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .sync_state
            .get(&rtxn, &crate::deletion::local_hard_delete_key(&event_id))?
            .is_none(),
        "a protected-record tombstone must not mint a permanent dt: poison marker"
    );
    drop(rtxn);
    let quarantined = crate::sync::quarantine::quarantined_records(&vault)?;
    assert_eq!(quarantined.len(), 1);
    assert_eq!(quarantined[0].1.container, QuarantineContainer::Tombstones);
    assert_eq!(quarantined[0].1.reason_code, "MaintenanceKindNotWritable");

    // A replica that ran the pre-fix headerless tombstone path may already
    // carry a `dt:` marker. Protected event arrival must bypass AND
    // neutralize that stale poison: it never represented valid delete
    // authority for a type-76 row.
    let (_poison_dir, poisoned_vault) = test_vault();
    let poisoned_id = EntityId::from_bytes([0x71; 16])?;
    poisoned_vault.with_write_txn(|wtxn| {
        poisoned_vault.store.sync_state.put(
            wtxn,
            &crate::deletion::local_hard_delete_key(&poisoned_id),
            &[0_u8; crate::deletion::TOMBSTONE_VALUE_V2_LEN],
        )?;
        Ok(())
    })?;
    let poisoned_doc = create_window_doc("remote-poisoned", &window_key);
    map_insert_bytes(
        &poisoned_doc.get_map("entities"),
        &poisoned_id.to_hex(),
        &event_blob,
    )?;
    poisoned_doc.commit();
    let expected_poisoned_event = record;
    forward_rematerialize(
        &poisoned_vault,
        &poisoned_doc,
        &Materializer::new(),
        &window_key,
    )?;
    assert_eq!(
        poisoned_vault.identity_topology_event(&poisoned_id)?,
        Some(expected_poisoned_event),
        "a preexisting dt: marker must not suppress a later protected event"
    );
    let rtxn = poisoned_vault.store.env.read_txn()?;
    assert!(
        poisoned_vault
            .store
            .sync_state
            .get(&rtxn, &crate::deletion::local_hard_delete_key(&poisoned_id))?
            .is_none(),
        "protected event admission must neutralize a preexisting dt: poison marker"
    );
    Ok(())
}

#[test]
fn forward_rematerialization_malformed_type_76_envelope_preserves_delete_wins() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let entity_id = EntityId::from_bytes([0x72; 16])?;
    let tombstone = crate::deletion::TombstoneValueV2 {
        reason: crate::deletion::TombstoneReason::UserHardDelete,
        deleted_at: 200,
        request_id: [0x42; 16],
    }
    .encode();
    let doc = create_window_doc("remote-malformed-protected", &window_key);
    map_insert_bytes(
        &doc.get_map("entities"),
        &entity_id.to_hex(),
        &make_entity_blob(
            crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
            200,
            b"malformed type-76 body",
        ),
    )?;
    map_insert_bytes(&doc.get_map("tombstones"), &entity_id.to_hex(), &tombstone)?;
    doc.commit();

    forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
    assert!(vault.get(&entity_id)?.is_none());
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault.local_hard_delete_marker_exists_in_txn(&rtxn, &entity_id)?,
        "a malformed protected envelope must run the normal tombstone path"
    );
    drop(rtxn);

    doc.get_map("tombstones")
        .delete(&entity_id.to_hex())
        .unwrap();
    map_insert_bytes(
        &doc.get_map("entities"),
        &entity_id.to_hex(),
        &make_entity_blob(
            crate::registry::ENTITY_TYPE_TASK,
            201,
            &crate::habit::task_body_for_test(crate::habit::TaskRole::Task),
        ),
    )?;
    doc.commit();

    forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
    assert!(
        vault.get(&entity_id)?.is_none(),
        "the permanent dt: marker must block later ordinary resurrection"
    );
    Ok(())
}

#[cfg(feature = "sync")]
fn authority_genesis_fixture_for_window(seed: u8) -> crate::authority::AuthorityLogEntry {
    use ed25519_dalek::{Signer, SigningKey};

    let signing = SigningKey::from_bytes(&[seed; 32]);
    let key = crate::authority::AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let mut entry = crate::authority::AuthorityLogEntry {
        schema_version: crate::authority::AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: None,
        seq: 0,
        parent_hashes: Vec::new(),
        op: crate::authority::AuthorityOp::Genesis {
            device: crate::authority::DeviceAuthority {
                key: key.clone(),
                transport_key_binding: [0; 32],
                attestation: crate::authority::AuthorityAttestation {
                    kind: "SoftwareArgon2id".to_owned(),
                    evidence: vec![1, 2, 3],
                },
                tier: crate::authority::AuthorityTier::Software,
                roles: crate::authority::ROLE_OWNER,
            },
            genesis_nonce: [seed.wrapping_add(1); 32],
            recovery: crate::authority::GenesisRecoveryStep::Saved([1; 32]),
            tier_floor: crate::authority::AuthorityTier::Software,
            pending_widen_delay_secs: crate::authority::DEFAULT_PENDING_WIDEN_DELAY_SECS,
        },
        signer: crate::authority::AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: u64::from(seed),
    };
    let transcript = crate::authority::authority_transcript(&entry).expect("transcript");
    entry.signer.signature = signing.sign(&transcript).to_bytes().to_vec();
    entry
}

/// A cosigned RevokeDevice naming `revoked_seed`'s key, parented on `genesis`.
/// `put_authority_log_entry` validates canonical bytes + origin signature +
/// the store-key bind, so this needs no full roster ancestry to materialize —
/// which is all the reverse-remat door reads.
#[cfg(feature = "sync")]
fn authority_revoke_fixture_for_window(
    genesis: &crate::authority::AuthorityLogEntry,
    signer_seed: u8,
    cosigner_seed: u8,
    revoked_seed: u8,
) -> crate::authority::AuthorityLogEntry {
    use ed25519_dalek::{Signer, SigningKey};

    let ed_key = |seed: u8| SigningKey::from_bytes(&[seed; 32]);
    let authority_key = |signing: &SigningKey| {
        crate::authority::AuthorityKey::Ed25519(signing.verifying_key().to_bytes())
    };
    let signature_for =
        |key: &crate::authority::AuthorityKey| crate::authority::AuthoritySignature {
            suite: key.suite(),
            public_key: key.clone(),
            signature: vec![0; 64],
        };

    let (signer, cosigner) = (ed_key(signer_seed), ed_key(cosigner_seed));
    let (signer_key, cosigner_key) = (authority_key(&signer), authority_key(&cosigner));
    let mut entry = crate::authority::AuthorityLogEntry {
        schema_version: crate::authority::AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(crate::authority::genesis_vault_id(genesis).expect("vault id")),
        seq: 1,
        parent_hashes: vec![crate::authority::authority_entry_hash(genesis).expect("genesis hash")],
        op: crate::authority::AuthorityOp::RevokeDevice {
            revoked_key: authority_key(&ed_key(revoked_seed)),
        },
        signer: signature_for(&signer_key),
        cosigns: vec![signature_for(&cosigner_key)],
        ts: 900,
    };
    let transcript = crate::authority::authority_transcript(&entry).expect("transcript");
    entry.signer.signature = signer.sign(&transcript).to_bytes().to_vec();
    for cosign in &mut entry.cosigns {
        cosign.signature = cosigner.sign(&transcript).to_bytes().to_vec();
    }
    entry
}

/// Wraps `data` in the pinned 25-byte envelope with an explicitly chosen
/// occurred range, so a test can mint the INVERTED range a hostile peer parks
/// on a CRDT carrier (`put_replicated` rejects `start > end` with
/// `InvalidTimeRange` before the authority validator ever runs).
#[cfg(feature = "sync")]
fn make_entity_blob_with_range(
    entity_type: u8,
    occurred_start: u64,
    occurred_end: u64,
    learned_at: u64,
    data: &[u8],
) -> Vec<u8> {
    let mut blob = Vec::with_capacity(25 + data.len());
    blob.push(entity_type);
    blob.extend_from_slice(&occurred_start.to_be_bytes());
    blob.extend_from_slice(&occurred_end.to_be_bytes());
    blob.extend_from_slice(&learned_at.to_be_bytes());
    blob.extend_from_slice(data);
    blob
}

/// Rewrites a MessagePack authority payload into its LEGACY-GENESIS shape by
/// dropping the `pending_widen_delay_secs` field wherever it appears (only the
/// genesis op map carries it). That is exactly the delta between the current
/// and legacy encodings/transcripts, so signing over the stripped transcript
/// mints a genuinely legacy-signed entry without reaching into the private
/// authority encoders.
#[cfg(feature = "sync")]
fn strip_genesis_delay_field(value: &Value) -> Value {
    match value {
        Value::Map(fields) => Value::Map(
            fields
                .iter()
                .filter(|(key, _)| key.as_str() != Some("pending_widen_delay_secs"))
                .map(|(key, val)| (key.clone(), strip_genesis_delay_field(val)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(strip_genesis_delay_field).collect()),
        other => other.clone(),
    }
}

/// ONE-1604-D1/D5 T9 (fix-leg 1, P2-b): the window-path twin of the bridge
/// tombstone regression, covering the neutralize-parity call this lane adds
/// to the window's AUTHORITY_LOG arm — pinned at the state the pre-fix code
/// could NOT repair.
///
/// The replica is in the exact pre-fix shape: the authority row is already
/// materialized BYTE-FOR-BYTE (local blob == CRDT blob, so the fast path
/// fires) while a tombstone-first replay left a `dt:` marker behind. When the
/// byte comparison ran in the shared pre-door pass, this replica returned
/// early and kept the false delete marker forever — and the ARCH-0038
/// hard-erase sweep would later treat the id as erased and scrub append-only
/// authority evidence. Routing the comparison through this door's own write
/// txn (type-76 parity) lets the exact match still neutralize the marker.
#[cfg(feature = "sync")]
#[test]
fn window_authority_row_admission_neutralizes_stale_dt_marker() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let genesis = authority_genesis_fixture_for_window(0x67);
    let id = crate::authority::authority_log_entity_id(&genesis)?;
    let body = crate::authority::encode_authority_log_entry_body(&genesis)?;

    // `make_entity_blob` stamps occurred_start == occurred_end == learned_at,
    // so putting with the same value makes the local row and the CRDT
    // carrier byte-identical — the fast path this fix must not exit through.
    let blob = make_entity_blob(ENTITY_TYPE_AUTHORITY_LOG, 2, &body);
    vault.put_authority_log_entry(&genesis, TimeRange { start: 2, end: 2 }, 2)?;
    assert_eq!(
        vault.get_raw(&id)?.as_deref(),
        Some(blob.as_slice()),
        "the local row must be byte-identical to the arriving carrier"
    );

    // A tombstone-first replay on this replica left `dt:` poison behind.
    vault.with_write_txn(|wtxn| {
        vault.store.sync_state.put(
            wtxn,
            &crate::deletion::local_hard_delete_key(&id),
            &[0_u8; crate::deletion::TOMBSTONE_VALUE_V2_LEN],
        )?;
        Ok(())
    })?;

    let doc = create_window_doc("remote-poisoned-authority", &window_key);
    map_insert_bytes(&doc.get_map("entities"), &id.to_hex(), &blob)?;
    map_insert_bytes(
        &doc.get_map("tombstones"),
        &id.to_hex(),
        &2_u64.to_be_bytes(),
    )?;
    doc.commit();
    forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;

    assert_eq!(
        vault.get_authority_log_entry(&id)?,
        Some(genesis),
        "the authority row must survive a stale dt: marker"
    );
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .sync_state
            .get(&rtxn, &crate::deletion::local_hard_delete_key(&id))?
            .is_none(),
        "a byte-identical authority carrier must still neutralize the stale dt: poison marker"
    );
    drop(rtxn);
    let quarantined = quarantine::quarantined_records(&vault)?;
    assert_eq!(quarantined.len(), 1);
    assert_eq!(quarantined[0].1.container, QuarantineContainer::Tombstones);
    assert_eq!(quarantined[0].1.reason_code, "MaintenanceKindNotWritable");
    Ok(())
}

/// ONE-1604-D1 (fix-leg 1, P2-a — outbound half): the presence-only carrier
/// check let a cross-type squatter keep the CRDT slot at an authority row's
/// content-derived key even after the local write door evicted it. That
/// re-exports the row the authority substrate refused and re-imports it onto
/// peers that have not seen the entry yet. A local AUTHORITY_LOG row now
/// overwrites a NON-authority carrier at its own key; ordinary rows keep
/// presence-only semantics.
#[cfg(feature = "sync")]
#[test]
fn reverse_rematerialization_replaces_cross_type_authority_key_squatter() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let learned_at = window_key.start_timestamp().unwrap() + 60;
    let genesis = authority_genesis_fixture_for_window(0x68);
    let id = crate::authority::authority_log_entity_id(&genesis)?;
    vault.put_authority_log_entry(
        &genesis,
        TimeRange {
            start: learned_at,
            end: learned_at,
        },
        learned_at,
    )?;
    let local = vault.get_raw(&id)?.expect("authority row stored");

    // The window still carries the attacker's ordinary row at that key.
    let doc = create_window_doc("squatted-window", &window_key);
    let squatter = make_entity_blob(crate::registry::ENTITY_TYPE_EVENT, learned_at, b"squatter");
    map_insert_bytes(&doc.get_map("entities"), &id.to_hex(), &squatter)?;
    doc.commit();

    reverse_rematerialize(&vault, &doc, &window_key)?;

    assert_eq!(
        map_get_bytes(&doc.get_map("entities"), &id.to_hex()),
        Some(local),
        "the validated authority row must replace the cross-type carrier at its derived key"
    );
    Ok(())
}

/// ONE-1604-D1 (fix-leg 4, outbound half): replacing the dominated carrier's
/// ENTITY row left its INCIDENT EDGES behind. Edge entries are keyed
/// independently of the entity (`src:kind:tgt`), so the squatter's graph
/// residue survived the overwrite and kept traversing on every peer that
/// imported the window — the exact residue the LMDB door already sweeps with
/// `delete_related_edges`. Both directions are asserted: the squatter as edge
/// SOURCE and as edge TARGET.
#[cfg(feature = "sync")]
#[test]
fn reverse_rematerialization_evicts_dominated_squatter_incident_edges() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let learned_at = window_key.start_timestamp().unwrap() + 60;
    let genesis = authority_genesis_fixture_for_window(0x6A);
    let id = crate::authority::authority_log_entity_id(&genesis)?;
    let neighbor = EntityId::from_bytes([0xC2; 16])?;
    vault.put_authority_log_entry(
        &genesis,
        TimeRange {
            start: learned_at,
            end: learned_at,
        },
        learned_at,
    )?;
    let local = vault.get_raw(&id)?.expect("authority row stored");

    let doc = create_window_doc("squatted-window", &window_key);
    let squatter = make_entity_blob(crate::registry::ENTITY_TYPE_EVENT, learned_at, b"squatter");
    map_insert_bytes(&doc.get_map("entities"), &id.to_hex(), &squatter)?;
    let out_key = format_edge_key(&id, EdgeKind::Mentions, &neighbor);
    let in_key = format_edge_key(&neighbor, EdgeKind::Mentions, &id);
    let edge_value = encode_edge_value_for_crdt(EdgeKind::Mentions, 0.7, 1, None, None)?;
    for key in [&out_key, &in_key] {
        map_insert_bytes(&doc.get_map("edges"), key, &edge_value)?;
    }
    doc.commit();

    reverse_rematerialize(&vault, &doc, &window_key)?;

    assert_eq!(
        map_get_bytes(&doc.get_map("entities"), &id.to_hex()),
        Some(local),
        "the validated authority row must still replace the carrier"
    );
    let edges = doc.get_map("edges");
    assert!(
        map_get_bytes(&edges, &out_key).is_none(),
        "the squatter's outbound edge carrier must go with the dominated entity"
    );
    assert!(
        map_get_bytes(&edges, &in_key).is_none(),
        "the squatter's inbound edge carrier must go with the dominated entity"
    );
    Ok(())
}

/// ONE-1604-D1 (fix-leg 5, P2 — phase ordering): the dominance sweep deletes
/// EVERY CRDT edge incident to the evicted id, and cannot tell the dominated
/// carrier's residue apart from a LOCALLY BACKED inbound edge. While the
/// sweep and the `edges_out` backfill were interleaved in one `learned_at`
/// walk, a legitimate local source ordered BEFORE the attacker-parked
/// authority id had its valid `S→A` edge swept after its own backfill, and
/// only `edges_out(A)` replayed afterwards — so the locally backed edge
/// stayed deleted and the committed update propagated that
/// attacker-triggered deletion to every peer.
///
/// The fixture pins exactly that order: `source` learns 60 s before the
/// authority row, holds a real LMDB `source→authority` edge, and its CRDT
/// carrier already exists (the shape a peer would lose). Unbacked squatter
/// residue in both directions must still be swept.
#[cfg(feature = "sync")]
#[test]
fn reverse_rematerialization_keeps_locally_backed_edges_into_a_dominated_key() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let source_learned_at = window_key.start_timestamp().unwrap() + 60;
    let authority_learned_at = source_learned_at + 60;
    let genesis = authority_genesis_fixture_for_window(0x6C);
    let id = crate::authority::authority_log_entity_id(&genesis)?;
    let source = EntityId::from_bytes([0xC4; 16])?;
    let residue_peer = EntityId::from_bytes([0xC5; 16])?;

    // The legitimate local source is learned FIRST, so `entities_in_range`
    // hands it to the walk before the authority id.
    vault.put_entity(
        &source,
        crate::registry::ENTITY_TYPE_EVENT,
        TimeRange {
            start: source_learned_at,
            end: source_learned_at,
        },
        source_learned_at,
        b"legitimate local source",
    )?;
    vault.put_authority_log_entry(
        &genesis,
        TimeRange {
            start: authority_learned_at,
            end: authority_learned_at,
        },
        authority_learned_at,
    )?;
    let local = vault.get_raw(&id)?.expect("authority row stored");
    vault.put_edge(&source, EdgeKind::Mentions, &id, 0.5)?;
    let backed = vault
        .edges_out(&source)?
        .into_iter()
        .find(|edge| edge.target == id)
        .expect("local source→authority edge stored");
    let backed_value = encode_edge_value_for_crdt(
        backed.kind,
        backed.weight,
        backed.created_at,
        backed.vad,
        backed.provenance,
    )?;

    let doc = create_window_doc("squatted-window", &window_key);
    let squatter = make_entity_blob(
        crate::registry::ENTITY_TYPE_EVENT,
        authority_learned_at,
        b"squatter",
    );
    map_insert_bytes(&doc.get_map("entities"), &id.to_hex(), &squatter)?;
    let backed_key = format_edge_key(&source, EdgeKind::Mentions, &id);
    let residue_in = format_edge_key(&residue_peer, EdgeKind::Mentions, &id);
    let residue_out = format_edge_key(&id, EdgeKind::Mentions, &residue_peer);
    let residue_value = encode_edge_value_for_crdt(EdgeKind::Mentions, 0.7, 1, None, None)?;
    map_insert_bytes(&doc.get_map("edges"), &backed_key, &backed_value)?;
    for key in [&residue_in, &residue_out] {
        map_insert_bytes(&doc.get_map("edges"), key, &residue_value)?;
    }
    doc.commit();

    reverse_rematerialize(&vault, &doc, &window_key)?;

    let edges = doc.get_map("edges");
    assert_eq!(
        map_get_bytes(&doc.get_map("entities"), &id.to_hex()),
        Some(local),
        "the validated authority row must still replace the dominated carrier"
    );
    assert_eq!(
        map_get_bytes(&edges, &backed_key),
        Some(backed_value),
        "an LMDB-backed inbound edge must survive the dominance sweep — a \
         squatter must never trigger deletion of replicated local graph state"
    );
    assert!(
        map_get_bytes(&edges, &residue_in).is_none(),
        "unbacked inbound squatter residue must still be swept"
    );
    assert!(
        map_get_bytes(&edges, &residue_out).is_none(),
        "unbacked outbound squatter residue must still be swept"
    );
    Ok(())
}

/// ONE-1604-D1 (fix-leg 4, negative half): the edge sweep is scoped to the
/// DOMINANCE verdict, never to mere presence at an authority key. A carrier
/// every peer's replay door would admit keeps presence-only semantics, and
/// its edges must survive untouched — otherwise the sweep would silently
/// erase replicated graph state on ordinary convergence.
#[cfg(feature = "sync")]
#[test]
fn reverse_rematerialization_preserves_edges_of_an_admissible_authority_carrier() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let learned_at = window_key.start_timestamp().unwrap() + 60;
    let genesis = authority_genesis_fixture_for_window(0x6B);
    let id = crate::authority::authority_log_entity_id(&genesis)?;
    let neighbor = EntityId::from_bytes([0xC3; 16])?;
    vault.put_authority_log_entry(
        &genesis,
        TimeRange {
            start: learned_at,
            end: learned_at,
        },
        learned_at,
    )?;
    let local = vault.get_raw(&id)?.expect("authority row stored");

    // Byte-different but fully admissible: same signed body, a different
    // (valid, non-inverted) occurred range.
    let admissible = make_entity_blob_with_range(
        ENTITY_TYPE_AUTHORITY_LOG,
        learned_at - 30,
        learned_at,
        learned_at,
        &local[crate::batch::ENTITY_METADATA_HEADER_LEN..],
    );
    let doc = create_window_doc("admissible-window", &window_key);
    map_insert_bytes(&doc.get_map("entities"), &id.to_hex(), &admissible)?;
    let in_key = format_edge_key(&neighbor, EdgeKind::Mentions, &id);
    let edge_value = encode_edge_value_for_crdt(EdgeKind::Mentions, 0.7, 1, None, None)?;
    map_insert_bytes(&doc.get_map("edges"), &in_key, &edge_value)?;
    doc.commit();

    reverse_rematerialize(&vault, &doc, &window_key)?;

    assert_eq!(
        map_get_bytes(&doc.get_map("entities"), &id.to_hex()),
        Some(admissible),
        "an admissible carrier must still be preserved"
    );
    assert_eq!(
        map_get_bytes(&doc.get_map("edges"), &in_key),
        Some(edge_value),
        "edges at a non-dominated authority key must survive untouched"
    );
    Ok(())
}

/// ONE-1604-D1 (fix-leg 3, P2 — the external probe's exact assertion pair):
/// the dominance check was TYPE-BYTE-blind. It preserved any carrier whose
/// envelope header read AUTHORITY_LOG, resting on "two authority rows at one key
/// are byte-identical by construction" — an invariant that holds only for
/// rows through the VALIDATED write path. A raw CRDT carrier bypasses
/// `apply_put`, so a hostile peer can park a POISONED AUTHORITY_LOG row at a
/// revocation's derived key: here, the revocation's own valid body wrapped in
/// an INVERTED occurred range. Every receiving peer's replay door rejects
/// that envelope with `InvalidTimeRange` before the authority validator runs,
/// so preserving it exported the rejection and left downstream peers MISSING
/// the revocation entirely (probe: local_replaced_fake=false,
/// fake_survived=true).
#[cfg(feature = "sync")]
#[test]
fn reverse_rematerialization_replaces_poisoned_authority_carrier_with_inverted_range() -> Result<()>
{
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let learned_at = window_key.start_timestamp().unwrap() + 60;
    let genesis = authority_genesis_fixture_for_window(0x71);
    let revoke = authority_revoke_fixture_for_window(&genesis, 0x71, 0x72, 0x73);
    let id = crate::authority::authority_log_entity_id(&revoke)?;
    vault.put_authority_log_entry(
        &revoke,
        TimeRange {
            start: learned_at,
            end: learned_at,
        },
        learned_at,
    )?;
    let local = vault.get_raw(&id)?.expect("authority row stored");

    // Same valid signed body, poisoned envelope: occurred_start > occurred_end.
    let poisoned = make_entity_blob_with_range(
        ENTITY_TYPE_AUTHORITY_LOG,
        learned_at + 1,
        learned_at,
        learned_at,
        &local[crate::batch::ENTITY_METADATA_HEADER_LEN..],
    );
    assert_ne!(
        poisoned, local,
        "the poisoned carrier must genuinely differ"
    );
    assert_eq!(
        poisoned[0], ENTITY_TYPE_AUTHORITY_LOG,
        "the carrier must read as AUTHORITY_LOG — that is what made it type-byte-invisible"
    );
    let doc = create_window_doc("poisoned-authority-window", &window_key);
    map_insert_bytes(&doc.get_map("entities"), &id.to_hex(), &poisoned)?;
    doc.commit();

    reverse_rematerialize(&vault, &doc, &window_key)?;

    let carrier = map_get_bytes(&doc.get_map("entities"), &id.to_hex());
    assert_eq!(
        carrier.as_deref(),
        Some(local.as_slice()),
        "local_replaced_fake: the fully validated local row must replace the poisoned carrier"
    );
    assert_ne!(
        carrier.as_deref(),
        Some(poisoned.as_slice()),
        "fake_survived: the inadmissible carrier must NOT reach peers"
    );
    Ok(())
}

/// ONE-1604-D1 (fix-leg 3, P2 — regression 2): the other half of the poisoned
/// AUTHORITY_LOG surface. A carrier with a well-formed envelope but a DIVERGENT or
/// MALFORMED body is equally unreplayable — it fails
/// `decode_authority_log_entry_body` (canonical encoding + origin signature),
/// or clears decode but hashes to a different content-derived key, so it
/// could never be admitted under this id. Both shapes are dominated.
#[cfg(feature = "sync")]
#[test]
fn reverse_rematerialization_replaces_divergent_and_malformed_authority_bodies() -> Result<()> {
    let window_key = WindowKey::new("2026-03");
    let learned_at = window_key.start_timestamp().unwrap() + 60;
    let genesis = authority_genesis_fixture_for_window(0x74);
    let revoke = authority_revoke_fixture_for_window(&genesis, 0x74, 0x75, 0x76);
    let id = crate::authority::authority_log_entity_id(&revoke)?;

    // A DIFFERENT valid, fully signed authority entry — it decodes cleanly,
    // but its content-derived key is not this one, so the key bind rejects it.
    let foreign = authority_genesis_fixture_for_window(0x77);
    let foreign_body = crate::authority::encode_authority_log_entry_body(&foreign)?;
    assert_ne!(
        crate::authority::authority_log_entity_id(&foreign)?,
        id,
        "the divergent body must derive a different store key"
    );

    for (label, body) in [
        ("divergent", foreign_body),
        ("malformed", b"not messagepack at all".to_vec()),
    ] {
        let (_dir, vault) = test_vault();
        vault.put_authority_log_entry(
            &revoke,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
        )?;
        let local = vault.get_raw(&id)?.expect("authority row stored");

        let poisoned = make_entity_blob_with_range(
            ENTITY_TYPE_AUTHORITY_LOG,
            learned_at,
            learned_at,
            learned_at,
            &body,
        );
        let doc = create_window_doc("divergent-authority-window", &window_key);
        map_insert_bytes(&doc.get_map("entities"), &id.to_hex(), &poisoned)?;
        doc.commit();

        reverse_rematerialize(&vault, &doc, &window_key)?;

        assert_eq!(
            map_get_bytes(&doc.get_map("entities"), &id.to_hex()),
            Some(local),
            "a {label} AUTHORITY_LOG body at the derived key must be dominated"
        );
    }
    Ok(())
}

/// ONE-1604-D1 (fix-leg 3, P2 — regression 3): dominance is ADMISSIBILITY-
/// based, never byte-difference-based, so presence-only survives untouched
/// for a carrier every peer's replay door would admit. Here the carrier
/// shares the local row's signed body but declares a DIFFERENT (still valid,
/// non-inverted) occurred range: byte-different, fully admissible, preserved.
#[cfg(feature = "sync")]
#[test]
fn reverse_rematerialization_preserves_admissible_authority_carrier() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let learned_at = window_key.start_timestamp().unwrap() + 60;
    let genesis = authority_genesis_fixture_for_window(0x79);
    let id = crate::authority::authority_log_entity_id(&genesis)?;
    vault.put_authority_log_entry(
        &genesis,
        TimeRange {
            start: learned_at,
            end: learned_at,
        },
        learned_at,
    )?;
    let local = vault.get_raw(&id)?.expect("authority row stored");

    let admissible = make_entity_blob_with_range(
        ENTITY_TYPE_AUTHORITY_LOG,
        learned_at - 30,
        learned_at,
        learned_at,
        &local[crate::batch::ENTITY_METADATA_HEADER_LEN..],
    );
    assert_ne!(
        admissible, local,
        "the carrier must be byte-different for this to test the admissibility rule"
    );
    let doc = create_window_doc("admissible-authority-window", &window_key);
    map_insert_bytes(&doc.get_map("entities"), &id.to_hex(), &admissible)?;
    doc.commit();

    reverse_rematerialize(&vault, &doc, &window_key)?;

    assert_eq!(
        map_get_bytes(&doc.get_map("entities"), &id.to_hex()),
        Some(admissible),
        "an admissible carrier must be PRESERVED — byte difference alone never dominates"
    );
    Ok(())
}

/// ONE-1645 REPLAY door for the `FacetOf` type table.
///
/// The local batch door (`batch::validate_facet_of_edge` on `BatchOp::Edge` /
/// `PublicEdgeWithCreatedAt`) aborts an off-table facet stamp atomically, but
/// the replicated arm `BatchOp::EdgeWithCreatedAt` is deliberately UNGATED —
/// a hard abort on a replay shape would wedge sync permanently (H2). Forward
/// rematerialization therefore runs the table itself at the write chokepoint
/// and QUARANTINES the off-table row.
///
/// Why it matters: a member/guest peer replaying a `PERSON -> FACET` stamp — a
/// shape no local public writer can produce — would otherwise land it in LMDB,
/// the retrieval truth every local disclosure surface reads. The federation
/// selector mirrors this same table on its read side
/// (`selector::facet_scope_by_source`) and so ignores such a source, but
/// keeping the unwritable shape out of storage is this door's job. That is an
/// authorization bypass through replay, not a mere schema violation.
///
/// Both arms of the table are pinned in ONE window: the off-table PERSON
/// stamp quarantines with the typed reason while the on-table EVENT stamp
/// (admitted since the ONE-1645 widening) writes normally, and an unrelated
/// ordinary edge in the same pass still heals — one forged row must never
/// starve the other N-1.
#[test]
fn forward_remat_quarantines_off_table_facet_of_and_admits_the_on_table_row() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let person = EntityId::from_bytes([0xD1; 16])?;
    let event = EntityId::from_bytes([0xD2; 16])?;
    let facet = EntityId::from_bytes([0xD3; 16])?;
    let ordinary_src = EntityId::from_bytes([0xD4; 16])?;
    for (id, entity_type) in [
        (&person, crate::registry::ENTITY_TYPE_PERSON),
        (&event, crate::registry::ENTITY_TYPE_EVENT),
        (&facet, crate::registry::ENTITY_TYPE_FACET),
        (&ordinary_src, crate::registry::ENTITY_TYPE_PERSON),
    ] {
        vault.put_entity(
            id,
            entity_type,
            TimeRange { start: 1, end: 1 },
            1,
            b"fixture",
        )?;
    }

    let doc = create_window_doc("remote", &window_key);
    let edges = doc.get_map("edges");
    // The injected off-table stamp: PERSON -> FACET. `vault.put_edge` cannot
    // write this shape at all, which is exactly why replay must not.
    let forged_key = format_edge_key(&person, EdgeKind::FacetOf, &facet);
    let forged_value = encode_edge_value_for_crdt(EdgeKind::FacetOf, 0.7, 10, None, None)?;
    map_insert_bytes(&edges, &forged_key, &forged_value)?;
    // On-table control: EVENT -> FACET is admitted by the widened table.
    let admitted_key = format_edge_key(&event, EdgeKind::FacetOf, &facet);
    map_insert_bytes(
        &edges,
        &admitted_key,
        &encode_edge_value_for_crdt(EdgeKind::FacetOf, 0.7, 11, None, None)?,
    )?;
    // Unrelated control: a plain edge that shares the window but not the kind.
    let ordinary_key = format_edge_key(&ordinary_src, EdgeKind::Mentions, &facet);
    map_insert_bytes(
        &edges,
        &ordinary_key,
        &encode_edge_value_for_crdt(EdgeKind::Mentions, 0.4, 12, None, None)?,
    )?;
    doc.commit();

    let count = forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
    assert_eq!(
        count, 2,
        "the off-table stamp is skipped while the other N-1 edges still heal"
    );
    assert!(
        !vault.edge_exists(&person, EdgeKind::FacetOf, &facet)?,
        "a PERSON-sourced facet stamp must never land through replay: the \
         federation selector would treat it as a facet seed"
    );
    assert!(
        vault.edge_exists(&event, EdgeKind::FacetOf, &facet)?,
        "the on-table EVENT stamp must replicate normally"
    );
    assert!(
        vault.edge_exists(&ordinary_src, EdgeKind::Mentions, &facet)?,
        "one off-table row must not abort the rest of the rematerialization pass"
    );

    let quarantined = crate::sync::quarantine::quarantined_records(&vault)?;
    assert_eq!(
        quarantined.len(),
        1,
        "exactly the forged row is quarantined"
    );
    let record = &quarantined[0].1;
    assert_eq!(record.container, QuarantineContainer::Edges);
    assert_eq!(
        record.reason_code, "InvalidFacetOfEdge",
        "the peer's row must carry the typed table reason, not a generic one"
    );
    assert_eq!(
        (record.crdt_key_hash, record.crdt_key_len),
        crate::sync::quarantine::crdt_key_metadata(&forged_key)
    );
    assert_eq!(
        record.payload_hash,
        crate::sync::quarantine::payload_hash(&forged_value)
    );
    Ok(())
}

/// ONE-1604-D1 (fix-leg 3, P2 — regression 3, legacy-genesis leg): the
/// decode layer's dual-encoding posture must reach the dominance verdict
/// UNCHANGED. `decode_authority_log_entry_body` admits both the exact
/// canonical AND the exact legacy-genesis encoding (whose signed bytes omit
/// `pending_widen_delay_secs`), and `authority_entry_hash` keys off whichever
/// of the two actually verifies. So:
///
/// * a legacy-encoded carrier AT ITS OWN derived key is ADMISSIBLE and is
///   preserved as-is — the codebase never normalizes legacy bytes, it keys
///   off them (`authority/tests.rs::legacy_signed_genesis_derives_a_stable_
///   store_key_from_its_legacy_bytes`), so there is no re-encode posture to
///   follow here;
/// * the current re-encoding of that same legacy-signed entry carries no
///   verifying signature, so it fails the BODY check and is dominated — for
///   INADMISSIBILITY, not for differing from the local bytes.
///
/// Asserted at the admissibility helper rather than through a full
/// reverse-remat pass because no live door can put a legacy-signed row into a
/// vault: `put_authority_log_entry` re-encodes canonically, and the
/// replicated door needs a local authority root that a genesis row is itself
/// the only source of. The helper is the whole dominance predicate, so its
/// verdict IS the preserve/dominate decision.
#[cfg(feature = "sync")]
#[test]
fn legacy_genesis_carrier_is_admissible_and_its_current_reencoding_is_not() -> Result<()> {
    use ed25519_dalek::{Signer, SigningKey};

    const DOMAIN_LEN: usize = 20; // b"oneiron/authority/v1"
    let mut legacy = authority_genesis_fixture_for_window(0x7A);
    let signing = SigningKey::from_bytes(&[0x7A; 32]);

    // Re-sign over the delay-free transcript, then encode the delay-free
    // body: exactly the legacy-genesis pair the decode layer still accepts.
    let canonical_transcript = crate::authority::authority_transcript(&legacy)?;
    let mut cursor = std::io::Cursor::new(&canonical_transcript[DOMAIN_LEN..]);
    let legacy_transcript_value =
        strip_genesis_delay_field(&rmpv::decode::read_value(&mut cursor).expect("transcript"));
    let mut legacy_transcript = canonical_transcript[..DOMAIN_LEN].to_vec();
    rmpv::encode::write_value(&mut legacy_transcript, &legacy_transcript_value)
        .expect("legacy transcript");
    legacy.signer.signature = signing.sign(&legacy_transcript).to_bytes().to_vec();

    let current_body = crate::authority::encode_authority_log_entry_body(&legacy)?;
    let mut cursor = std::io::Cursor::new(current_body.as_slice());
    let legacy_value =
        strip_genesis_delay_field(&rmpv::decode::read_value(&mut cursor).expect("body"));
    let mut legacy_body = Vec::new();
    rmpv::encode::write_value(&mut legacy_body, &legacy_value).expect("legacy body");
    assert_ne!(
        legacy_body, current_body,
        "the two encodings must genuinely differ for this to test the dual-encoding path"
    );

    let id = crate::authority::authority_log_entity_id(&legacy)?;
    let envelope =
        |body: &[u8]| make_entity_blob_with_range(ENTITY_TYPE_AUTHORITY_LOG, 5, 9, 9, body);

    assert!(
        crdt_carrier_is_admissible_authority_row(&id, &envelope(&legacy_body)),
        "a legacy-encoded carrier at its own derived key must be ADMISSIBLE (preserved, not normalized)"
    );
    assert!(
        !crdt_carrier_is_admissible_authority_row(&id, &envelope(&current_body)),
        "the current re-encoding carries no verifying signature — dominated for inadmissibility"
    );
    // Same legacy bytes, inverted envelope: the envelope leg is independent
    // of the body leg, so a legacy body cannot launder a poisoned range.
    assert!(
        !crdt_carrier_is_admissible_authority_row(
            &id,
            &make_entity_blob_with_range(ENTITY_TYPE_AUTHORITY_LOG, 9, 5, 9, &legacy_body)
        ),
        "an inverted occurred range must dominate even a legacy-valid body"
    );
    Ok(())
}

/// The replay door must never turn an ORDERING accident into a permanent
/// rejection. The type table reads endpoint types from entity rows, so it is
/// deliberately placed AFTER the endpoint-existence check: a facet stamp whose
/// endpoints have not arrived yet DEFERS (stays in the CRDT, no `x:` row) and
/// materializes on the next pass once the endpoints land.
///
/// Without this ordering an out-of-order but perfectly legitimate TURN
/// stamp would be read as `src_type = None` — the fail-closed
/// "unknowable type" arm — and quarantined forever. That is the H2 wedge the
/// batch arm exists to avoid, reintroduced one layer up.
#[test]
fn forward_remat_defers_facet_of_with_absent_endpoints_instead_of_quarantining() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let turn_src = EntityId::from_bytes([0xE1; 16])?;
    let facet = EntityId::from_bytes([0xE2; 16])?;

    let doc = create_window_doc("remote", &window_key);
    map_insert_bytes(
        &doc.get_map("edges"),
        &format_edge_key(&turn_src, EdgeKind::FacetOf, &facet),
        &encode_edge_value_for_crdt(EdgeKind::FacetOf, 0.7, 10, None, None)?,
    )?;
    doc.commit();

    forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
    assert!(
        crate::sync::quarantine::quarantined_records(&vault)?.is_empty(),
        "an edge whose endpoints have not arrived defers; it is not a table rejection"
    );
    assert!(!vault.edge_exists(&turn_src, EdgeKind::FacetOf, &facet)?);

    // The endpoints arrive in a later window pass; the same CRDT row now
    // materializes because the table can finally read real types.
    vault.put_entity(
        &turn_src,
        ENTITY_TYPE_TURN,
        TimeRange { start: 1, end: 1 },
        1,
        b"turn fixture",
    )?;
    vault.put_entity(
        &facet,
        crate::registry::ENTITY_TYPE_FACET,
        TimeRange { start: 1, end: 1 },
        1,
        b"facet fixture",
    )?;

    forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
    assert!(
        vault.edge_exists(&turn_src, EdgeKind::FacetOf, &facet)?,
        "a deferred on-table stamp must heal once its endpoints exist"
    );
    assert!(
        crate::sync::quarantine::quarantined_records(&vault)?.is_empty(),
        "a legitimate deferred replay must never leave quarantine evidence"
    );
    Ok(())
}

/// ONE-1124 fail-closed split at the replay table (P3 retrofit).
///
/// `validate_facet_of_edge` surfaces TWO error classes: the remote-op
/// rejection `InvalidFacetOfEdge` (off-table stamp — quarantine and continue)
/// and LOCAL faults, notably `CorruptedIndex("entity header")` when a STORED
/// endpoint row will not parse. The pre-retrofit code quarantined every `Err`
/// alike, which is wrong twice over: it swallows the engine's own storage
/// defect behind a continue instead of aborting the drain, and the `x:` row it
/// writes is PERMANENT false evidence blaming the peer for a forgery it never
/// sent.
///
/// Fixture: an endpoint row whose stored bytes are shorter than the 25-byte
/// entity envelope. The endpoint EXISTS (so the pass clears the
/// endpoint-existence check and reaches the table), but its header cannot be
/// read — exactly the local-defect shape.
#[test]
fn forward_remat_aborts_on_corrupted_endpoint_header_instead_of_quarantining() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let turn_src = EntityId::from_bytes([0xF1; 16])?;
    let facet = EntityId::from_bytes([0xF2; 16])?;
    vault.put_entity(
        &turn_src,
        ENTITY_TYPE_TURN,
        TimeRange { start: 1, end: 1 },
        1,
        b"turn fixture",
    )?;
    // A row too short to carry the entity header — a LOCAL corruption, not a
    // missing endpoint (which would defer) and not a wrong type (which would
    // quarantine).
    vault.with_write_txn(|wtxn| {
        vault.store.entities.put(wtxn, facet.as_bytes(), b"trunc")?;
        Ok(())
    })?;

    let doc = create_window_doc("remote", &window_key);
    map_insert_bytes(
        &doc.get_map("edges"),
        &format_edge_key(&turn_src, EdgeKind::FacetOf, &facet),
        &encode_edge_value_for_crdt(EdgeKind::FacetOf, 0.7, 10, None, None)?,
    )?;
    doc.commit();

    let err = forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)
        .expect_err("a corrupted stored endpoint header must ABORT the drain");
    assert_eq!(
        err.kind(),
        crate::error::ErrorKind::CorruptedIndex,
        "the local defect must propagate typed, not be re-cast as a peer rejection"
    );
    assert!(
        crate::sync::quarantine::quarantined_records(&vault)?.is_empty(),
        "a LOCAL fault must never leave an x: row misattributing it to the peer"
    );
    Ok(())
}

/// The retrofit's other arm, pinned in the same neighborhood so a future
/// refactor cannot satisfy the abort test by disabling the gate entirely: an
/// off-table PERSON -> FACET stamp — both endpoints present and parseable —
/// still QUARANTINES and lets the window continue.
#[test]
fn forward_remat_still_quarantines_off_table_when_endpoint_rows_are_healthy() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let person = EntityId::from_bytes([0xF3; 16])?;
    let facet = EntityId::from_bytes([0xF4; 16])?;
    for (id, entity_type) in [
        (&person, crate::registry::ENTITY_TYPE_PERSON),
        (&facet, crate::registry::ENTITY_TYPE_FACET),
    ] {
        vault.put_entity(
            id,
            entity_type,
            TimeRange { start: 1, end: 1 },
            1,
            b"fixture",
        )?;
    }

    let doc = create_window_doc("remote", &window_key);
    map_insert_bytes(
        &doc.get_map("edges"),
        &format_edge_key(&person, EdgeKind::FacetOf, &facet),
        &encode_edge_value_for_crdt(EdgeKind::FacetOf, 0.7, 10, None, None)?,
    )?;
    doc.commit();

    forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)
        .expect("an off-table stamp quarantines; it must never abort (H2)");
    assert!(!vault.edge_exists(&person, EdgeKind::FacetOf, &facet)?);
    let records = crate::sync::quarantine::quarantined_records(&vault)?;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].1.reason_code, "InvalidFacetOfEdge");
    Ok(())
}

// ---------------------------------------------------------------------------
// SECRET_CUSTODY (byte 77) ONE-1865 seal — FIX1 CHOKEPOINT
// ---------------------------------------------------------------------------

/// Builds a live custody record in the vault via the door and returns its raw
/// stored bytes (header + body), mirrored exactly as `reverse_rematerialize`
/// would read them back.
fn seed_secret_custody(
    vault: &Vault,
    window_key: &WindowKey,
    name: &str,
    value: &[u8],
) -> Result<(EntityId, Vec<u8>)> {
    let learned_at = window_key.start_timestamp().unwrap() + 60;
    let rec = crate::secret_custody::SecretCustodyRecord {
        schema_version: crate::secret_custody::SECRET_CUSTODY_SCHEMA_VERSION,
        name: name.to_owned(),
        class: crate::secret_custody::CustodyClass::CustodyDeviceBound,
        device_only: false,
        value_bytes: value.to_vec(),
        status: crate::secret_custody::SecretCustodyStatus::Active,
        registered_at: learned_at,
        rotated_at: None,
        rotation_generation: 0,
        bindings: vec![crate::secret_custody::SecretBinding {
            effector: "door:receive-pack".to_owned(),
            tier_ceiling: crate::secret_custody::CustodyTier::T0Doored,
            scopes: vec!["read".to_owned()],
        }],
        manifest_ref: "secrets.toml".to_owned(),
        declared_paths: vec![".secrets/api.key".to_owned()],
        policy_floor_snapshot: crate::secret_custody::SecretCustodyFloor::default(),
    };
    let id = vault.register_secret(rec)?;
    // The sealed public `get_raw` denies byte 77 by design; this fixture needs
    // the on-disk bytes to plant a carrier, so it reads through the same
    // crate-internal unsealed reader the scrub passes use.
    let raw = vault.get_raw_unsealed(&id)?.expect("custody row present");
    Ok((id, raw))
}

/// Reverse re-materialization must never mirror a custody record into the
/// canonical window doc, and must scrub any custody carrier (and its incident
/// edges) that landed before the pass ran.
#[test]
fn secret_custody_never_enters_doc_via_reverse_rematerialize() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let learned_at = window_key.start_timestamp().unwrap() + 60;
    let secret_value = b"hunter2-secret";
    let (custody, custody_raw) = seed_secret_custody(&vault, &window_key, "api-key", secret_value)?;

    // An ordinary control entity proves the pass still mirrors other rows.
    let ordinary = EntityId::from_bytes([0x47; 16])?;
    vault.put_entity(
        &ordinary,
        ENTITY_TYPE_TURN,
        TimeRange {
            start: learned_at,
            end: learned_at,
        },
        learned_at,
        b"ordinary turn",
    )?;

    let doc = create_window_doc("source", &window_key);
    let entities = doc.get_map("entities");
    let edge_key = format_edge_key(&ordinary, EdgeKind::Mentions, &custody);
    let edge_val = encode_edge_value_for_crdt(EdgeKind::Mentions, 0.5, learned_at, None, None)?;

    // Pre-seed a custody carrier + incident edge as if they landed before the
    // seal: reverse remat must scrub BOTH, not merely skip the insert.
    map_insert_bytes(&entities, &custody.to_hex(), &custody_raw)?;
    map_insert_bytes(&doc.get_map("edges"), &edge_key, &edge_val)?;
    doc.commit();

    // Count = 1: only the ordinary control mirrors. The custody row is sealed.
    assert_eq!(reverse_rematerialize(&vault, &doc, &window_key)?, 1);
    assert!(
        map_get_bytes(&entities, &ordinary.to_hex()).is_some(),
        "ordinary entity still mirrors through reverse remat"
    );
    assert!(
        map_get_bytes(&entities, &custody.to_hex()).is_none(),
        "custody record body must be scrubbed from the canonical doc"
    );
    assert!(
        map_get_bytes(&doc.get_map("edges"), &edge_key).is_none(),
        "custody incident edge must be scrubbed from the canonical doc"
    );
    Ok(())
}

/// The export path runs the same seal: a custody carrier already resident in
/// the doc must be scrubbed and the window forced onto history-free snapshot
/// transport, so exported bytes never carry the secret value.
#[test]
fn secret_custody_never_leaves_doc_via_export() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let learned_at = window_key.start_timestamp().unwrap() + 60;
    let secret_value = b"hunter2-secret";
    let (custody, custody_raw) = seed_secret_custody(&vault, &window_key, "api-key", secret_value)?;

    let ordinary = EntityId::from_bytes([0x48; 16])?;
    vault.put_entity(
        &ordinary,
        ENTITY_TYPE_TURN,
        TimeRange {
            start: learned_at,
            end: learned_at,
        },
        learned_at,
        b"ordinary turn",
    )?;

    let doc = create_window_doc("source", &window_key);
    map_insert_bytes(&doc.get_map("entities"), &custody.to_hex(), &custody_raw)?;
    map_insert_bytes(
        &doc.get_map("entities"),
        &ordinary.to_hex(),
        &make_entity_blob(ENTITY_TYPE_TURN, learned_at, b"ordinary turn"),
    )?;
    doc.commit();

    // Export to a fresh peer: the custody body must not survive, the ordinary
    // control must.
    let export = export_window_updates_since(
        &vault,
        &window_key,
        &doc,
        &VersionVector::default().encode(),
    )?;
    let peer = create_window_doc("peer", &window_key);
    import_doc(&peer, &export)?;
    assert!(
        map_get_bytes(&peer.get_map("entities"), &custody.to_hex()).is_none(),
        "exported window must not carry the custody record body"
    );
    assert!(
        map_get_bytes(&peer.get_map("entities"), &ordinary.to_hex()).is_some(),
        "ordinary entity still exports"
    );
    // The local doc was scrubbed in place too.
    assert!(
        map_get_bytes(&doc.get_map("entities"), &custody.to_hex()).is_none(),
        "local doc scrubbed before export"
    );
    // And the window is now pinned history-free, so the pre-scrub set-op bytes
    // in Loro history can never take a raw delta/snapshot path later.
    assert!(
        history_free_window_required(&vault, &window_key)?,
        "custody carrier scrub pins the window to history-free transport"
    );
    Ok(())
}

/// C2 EXPORT-SCRUB BYPASS: the map key is peer-chosen, the type byte is not.
/// Parsing the key before classifying the body let a custody carrier filed
/// under a non-canonical key skip the scrub and ship its plaintext in the
/// export.
#[test]
fn secret_custody_under_malformed_key_never_leaves_doc_via_export() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let learned_at = window_key.start_timestamp().unwrap() + 60;
    let secret_value = b"hunter2-malformed-key";
    let (_custody, custody_raw) =
        seed_secret_custody(&vault, &window_key, "api-key", secret_value)?;

    // A key no `EntityId::from_hex` can parse — exactly what a hostile or
    // buggy peer is free to write into the entities map.
    let malformed_key = "not-a-canonical-entity-id";
    let ordinary = EntityId::from_bytes([0x49; 16])?;
    vault.put_entity(
        &ordinary,
        ENTITY_TYPE_TURN,
        TimeRange {
            start: learned_at,
            end: learned_at,
        },
        learned_at,
        b"ordinary turn",
    )?;

    let doc = create_window_doc("source", &window_key);
    map_insert_bytes(&doc.get_map("entities"), malformed_key, &custody_raw)?;
    map_insert_bytes(
        &doc.get_map("entities"),
        &ordinary.to_hex(),
        &make_entity_blob(ENTITY_TYPE_TURN, learned_at, b"ordinary turn"),
    )?;
    doc.commit();

    let export = export_window_updates_since(
        &vault,
        &window_key,
        &doc,
        &VersionVector::default().encode(),
    )?;

    // The load-bearing assertion: the secret value is not anywhere in the bytes
    // that go on the wire.
    assert!(
        !export
            .windows(secret_value.len())
            .any(|w| w == secret_value.as_slice()),
        "exported bytes must not carry the secret value"
    );

    let peer = create_window_doc("peer", &window_key);
    import_doc(&peer, &export)?;
    assert!(
        map_get_bytes(&peer.get_map("entities"), malformed_key).is_none(),
        "a malformed-key custody carrier must not reach the peer"
    );
    assert!(
        map_get_bytes(&peer.get_map("entities"), &ordinary.to_hex()).is_some(),
        "ordinary entity still exports"
    );
    assert!(
        map_get_bytes(&doc.get_map("entities"), malformed_key).is_none(),
        "local doc scrubbed before export"
    );
    assert!(
        history_free_window_required(&vault, &window_key)?,
        "the scrub pins the window to history-free transport"
    );

    let quarantined = crate::sync::quarantine::quarantined_records(&vault)?;
    assert_eq!(quarantined.len(), 1);
    assert_eq!(quarantined[0].1.container, QuarantineContainer::Entities);
    assert_eq!(quarantined[0].1.reason_code, "InvalidSecretCustodyBody");
    assert_eq!(
        (
            quarantined[0].1.crdt_key_hash,
            quarantined[0].1.crdt_key_len
        ),
        crate::sync::quarantine::crdt_key_metadata(malformed_key)
    );
    Ok(())
}

/// ONE-1608 — READINESS EDGES ARE LOCAL-ONLY IN V1.
///
/// `reverse_rematerialize` mirrors local `edges_out` straight into the
/// replicated edges map, so without an explicit exclusion the ARCH-0050 L2
/// readiness edge would federate itself the moment a window covered its
/// endpoints. That is exactly what byte 24 is NOT: `blocks` is authority-gated
/// on the LOCAL actor entity and acyclic against the LOCAL graph, and neither
/// property survives a peer that never ran those doors. Federated readiness is
/// banked owner-slate work.
///
/// The exclusion is send-side ONLY: inbound quarantine and admission aborts
/// stay untouched, so a non-compliant peer that ships a `blocks` row still
/// fails closed on receive.
///
/// The sibling `child_of` row in the same fixture is the control — it proves
/// the pass really did back-fill this source's edges, so a zero `blocks` count
/// cannot be the vacuous result of an unmirrored source.
#[test]
fn blocks_edges_are_local_only_when_rematerialized() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let learned_at = window_key.start_timestamp().unwrap() + 60;

    let blocker = EntityId::from_bytes([0x4B; 16])?;
    let blocked = EntityId::from_bytes([0x4C; 16])?;
    let actor = EntityId::from_bytes([0x4D; 16])?;
    for (id, entity_type) in [
        (&blocker, crate::registry::ENTITY_TYPE_CODE_SYMBOL),
        (&blocked, crate::registry::ENTITY_TYPE_CODE_SYMBOL),
        (&actor, crate::registry::ENTITY_TYPE_PERSON),
    ] {
        vault.put_entity(
            id,
            entity_type,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            b"local",
        )?;
    }

    let write_actor = crate::write_envelope::WriteActor::new(actor, EdgeActorClass::Human);
    vault.insert_blocks_edge(
        blocker,
        blocked,
        crate::code_memory::BlocksWriteContext {
            actor: &write_actor,
            source: ClaimSource::UserStated,
        },
    )?;
    // Control: an ordinary structural edge from the SAME source, which the
    // pass must mirror.
    vault.put_edge(&blocker, EdgeKind::DerivedFrom, &blocked, 0.2)?;

    let doc = create_window_doc("blocks-local-only", &window_key);
    reverse_rematerialize(&vault, &doc, &window_key)?;

    let edges = doc.get_map("edges");
    assert!(
        map_contains_binary(
            &edges,
            &format_edge_key(&blocker, EdgeKind::DerivedFrom, &blocked)
        ),
        "the control edge proves this source really was back-filled"
    );

    let blocks_infix = format!(":{:02}:", EdgeKind::Blocks as u8);
    let mut blocks_rows = 0usize;
    map_for_each_bytes(&edges, |key, _| {
        if key.contains(blocks_infix.as_str()) {
            blocks_rows += 1;
        }
    });
    assert_eq!(
        blocks_rows, 0,
        "reverse rematerialization must mirror zero Blocks rows into the CRDT"
    );
    assert!(
        !map_contains_binary(
            &edges,
            &format_edge_key(&blocker, EdgeKind::Blocks, &blocked)
        ),
        "the readiness edge itself is absent by key"
    );
    Ok(())
}

/// Counts replicated edge rows whose key carries the `blocks` kind byte,
/// using the same `src:kind:tgt` key grammar `format_edge_key` writes.
fn blocks_rows_in(edges: &LoroMap) -> usize {
    let blocks_infix = format!(":{:02}:", EdgeKind::Blocks as u8);
    let mut rows = 0usize;
    map_for_each_bytes(edges, |key, _| {
        if key.contains(blocks_infix.as_str()) {
            rows += 1;
        }
    });
    rows
}

/// ONE-1608 — THE SECOND SEND-SIDE EGRESS.
///
/// `reverse_rematerialize` is not the only path that copies local `edges_out`
/// rows into the replicated edges map: `replay_pending_mirrors` does it too,
/// in BOTH of its backfill loops (the byte-equal branch that repairs a crash
/// between the entity insert and its edge inserts, and the full-mirror branch
/// that writes the carrier for the first time). Either one would federate a
/// locally inserted readiness edge — authority-gated on the LOCAL actor entity
/// and acyclic against the LOCAL graph, neither of which survives a peer that
/// never ran those doors.
///
/// The `derived_from` sibling in the same fixture is the control on both
/// branches: it proves the replay really did back-fill this source's edges, so
/// a zero `blocks` count can never be the vacuous result of an idle pass.
#[test]
fn blocks_edges_are_local_only_when_pending_mirrors_replay() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let learned_at = window_key.start_timestamp().unwrap() + 60;

    let blocker = EntityId::from_bytes([0x5B; 16])?;
    let blocked = EntityId::from_bytes([0x5C; 16])?;
    let actor = EntityId::from_bytes([0x5D; 16])?;
    for (id, entity_type) in [
        (&blocker, crate::registry::ENTITY_TYPE_CODE_SYMBOL),
        (&blocked, crate::registry::ENTITY_TYPE_CODE_SYMBOL),
        (&actor, crate::registry::ENTITY_TYPE_PERSON),
    ] {
        vault.put_entity(
            id,
            entity_type,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            b"local",
        )?;
    }

    let write_actor = crate::write_envelope::WriteActor::new(actor, EdgeActorClass::Human);
    vault.insert_blocks_edge(
        blocker,
        blocked,
        crate::code_memory::BlocksWriteContext {
            actor: &write_actor,
            source: ClaimSource::UserStated,
        },
    )?;
    vault.put_edge(&blocker, EdgeKind::DerivedFrom, &blocked, 0.2)?;

    let marker_key = format!("pm:{window_key}:{}", blocker.to_hex());
    vault.sync_state_put(&marker_key, &[1])?;

    let doc = create_window_doc("blocks-pending-mirror", &window_key);
    let edges = doc.get_map("edges");
    let control_key = format_edge_key(&blocker, EdgeKind::DerivedFrom, &blocked);

    // FULL-MIRROR branch: the CRDT holds no carrier for this id yet.
    assert_eq!(replay_pending_mirrors(&vault, &doc, &window_key)?, 1);
    assert!(
        map_contains_binary(&edges, &control_key),
        "the control edge proves the full-mirror branch really back-filled this source"
    );
    assert_eq!(
        blocks_rows_in(&edges),
        0,
        "the full-mirror branch must mirror zero blocks rows into the CRDT"
    );

    // BYTE-EQUAL branch: the entity bytes already reached the CRDT, so the
    // replay only backfills MISSING edges. Dropping the control edge is what
    // gives that branch work to do; the readiness edge must still stay out.
    map_delete(&edges, &control_key)?;
    doc.commit();
    vault.sync_state_put(&marker_key, &[1])?;

    assert_eq!(replay_pending_mirrors(&vault, &doc, &window_key)?, 1);
    assert!(
        map_contains_binary(&edges, &control_key),
        "the control edge proves the byte-equal branch really back-filled this source"
    );
    assert_eq!(
        blocks_rows_in(&edges),
        0,
        "the byte-equal branch must mirror zero blocks rows into the CRDT"
    );
    assert!(
        !map_contains_binary(
            &edges,
            &format_edge_key(&blocker, EdgeKind::Blocks, &blocked)
        ),
        "the readiness edge itself is absent by key after both branches ran"
    );
    Ok(())
}

/// A canonical six-axis witness MESSAGE body, through the engine's ONE encoder.
fn replicated_witness_message_body(author: &str, content: &str) -> Vec<u8> {
    crate::gate::canonical_witness_message_body_for_test(author, "dialogue", content, true, 0)
        .expect("encode witness message body")
}

/// ONE-1929: forward rematerialization is the OTHER sync door into LMDB, and it
/// must refuse the same peer MESSAGE bodies Observer B refuses.
///
/// A door that only guarded the live observer would leave every restart replay
/// as the way in: the CRDT mirror keeps the rejected bytes, and this pass is
/// what re-offers them. Both paths converge on `batch::apply_put`, so the one
/// check there covers both — an unattributed `system` row, an attributed row
/// with no local actor binding, and a body that is not the canonical six-axis
/// envelope are all quarantined here with the same typed body rejection, while
/// an unrelated non-MESSAGE row still materializes: one poisoned transcript row
/// must not wedge the window.
#[test]
fn forward_remat_refuses_replicated_message_bodies_before_any_mutation() -> Result<()> {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new("2026-03");
    let learned_at = window_key.start_timestamp().unwrap() + 60;

    let attributed = EntityId::from_bytes([0x71; 16])?;
    let forged_system = EntityId::from_bytes([0x72; 16])?;
    let malformed = EntityId::from_bytes([0x73; 16])?;
    let ordinary_turn = EntityId::from_bytes([0x74; 16])?;

    let mut not_an_envelope = Vec::new();
    rmpv::encode::write_value(
        &mut not_an_envelope,
        &Value::Map(vec![(Value::from("content"), Value::from("bare prose"))]),
    )
    .expect("encode non-envelope body");

    let doc = create_window_doc("remote", &window_key);
    let entities = doc.get_map("entities");
    for (id, body) in [
        (
            attributed,
            replicated_witness_message_body(
                crate::gate::WITNESS_AUTHOR_COMPANION,
                "an attributed peer bubble",
            ),
        ),
        (
            forged_system,
            replicated_witness_message_body(
                crate::gate::WITNESS_AUTHOR_SYSTEM,
                "peer speaking in the engine's voice",
            ),
        ),
        (malformed, not_an_envelope),
    ] {
        map_insert_bytes(
            &entities,
            &id.to_hex(),
            &make_entity_blob(crate::registry::ENTITY_TYPE_MESSAGE, learned_at, &body),
        )?;
    }
    map_insert_bytes(
        &entities,
        &ordinary_turn.to_hex(),
        &make_entity_blob(ENTITY_TYPE_TURN, learned_at, b"ordinary turn body"),
    )?;
    doc.commit();

    let count = forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;

    assert_eq!(
        count, 1,
        "the unrelated turn still materializes; every peer MESSAGE is refused"
    );
    assert!(vault.get_raw(&ordinary_turn)?.is_some());
    assert!(
        vault.get_raw(&forged_system)?.is_none(),
        "an unattributed system row must never reach LMDB through replication"
    );
    assert!(
        vault.get_raw(&attributed)?.is_none(),
        "an attributed row has no local actor binding over replication"
    );
    assert!(
        vault.get_raw(&malformed)?.is_none(),
        "a body that is not a witness envelope must never reach LMDB"
    );

    let quarantined = crate::sync::quarantine::quarantined_records(&vault)?;
    assert_eq!(quarantined.len(), 3);
    for (_, record) in &quarantined {
        assert_eq!(record.container, QuarantineContainer::Entities);
        assert_eq!(
            record.reason_code, "InvalidWitnessMessageBody",
            "a refused peer MESSAGE classifies as a remote rejection"
        );
    }
    Ok(())
}

#[test]
fn replicated_lww_overwrite_removes_loser_bm25f_before_idle() -> Result<()> {
    use crate::memory::ReadMode;
    let (_dir, vault) = test_vault();
    // Vault::open seeds the bootstrap skills with staged revisions; publish
    // them first so the idle report below covers only this entity.
    vault.set_indexed_idle_delay_ms(0)?;
    vault.refresh_staged_indexed_at_idle(u64::MAX)?;
    let id = EntityId::now();
    vault.put_entity(
        &id,
        ENTITY_TYPE_TURN,
        TimeRange { start: 1, end: 1 },
        1,
        b"old",
    )?;
    vault.with_write_txn(|txn| {
        crate::bm25::index_text(
            &vault.store,
            txn,
            &vault.analyzer,
            &id,
            &[("body".to_owned(), "loseruniquetoken".to_owned())],
        )?;
        Ok(())
    })?;
    vault.with_write_txn(|txn| {
        vault
            .batch_in()
            .put_replicated(
                &id,
                ENTITY_TYPE_TURN,
                TimeRange { start: 2, end: 2 },
                2,
                b"winner",
            )
            .apply(txn)?;
        let row = vault.store.entities.get(txn, id.as_bytes())?.unwrap();
        assert_eq!(&row[crate::batch::ENTITY_METADATA_HEADER_LEN..], b"winner");
        assert!(vault.store.text_forward.get(txn, id.as_bytes())?.is_none());
        for item in vault.store.text_postings.iter(txn)? {
            let (_term, posting) = item?;
            assert!(!posting.starts_with(id.as_bytes()));
        }
        Ok(())
    })?;
    // The old indexed frontier is still readable, but a replicated LWW loser
    // cannot be retrieved by its postings while publication awaits idle.
    assert!(vault.search_text("loseruniquetoken", 10)?.is_empty());
    let indexed = vault.get_raw_with_mode(&id, ReadMode::Indexed)?.unwrap();
    assert_eq!(&indexed[crate::batch::ENTITY_METADATA_HEADER_LEN..], b"old");
    let live = vault.get_raw_with_mode(&id, ReadMode::Live)?.unwrap();
    assert_eq!(&live[crate::batch::ENTITY_METADATA_HEADER_LEN..], b"winner");

    let report = vault.refresh_staged_indexed_at_idle(u64::MAX)?;
    assert_eq!(report.refreshed.len(), 1);
    assert_eq!(report.refreshed[0].0, id);
    assert!(report.failed.is_empty());
    assert!(report.superseded.is_empty());
    assert_eq!(vault.get_raw_with_mode(&id, ReadMode::Indexed)?, Some(live));
    assert!(vault.search_text("loseruniquetoken", 10)?.is_empty());
    vault.with_write_txn(|txn| {
        // Idle publication removes every old text-index component together.
        assert!(vault.store.text_forward.get(txn, id.as_bytes())?.is_none());
        assert!(
            vault
                .store
                .text_doc_field_lengths
                .get(txn, id.as_bytes())?
                .is_none()
        );
        for item in vault.store.text_postings.iter(txn)? {
            let (_term, posting) = item?;
            assert!(!posting.starts_with(id.as_bytes()));
        }
        let row = vault.store.entities.get(txn, id.as_bytes())?.unwrap();
        assert_eq!(&row[crate::batch::ENTITY_METADATA_HEADER_LEN..], b"winner");
        Ok(())
    })
}

#[test]
fn diagnostic_carriers_never_leave_window_in_live_state_or_history() -> Result<()> {
    let (_dir, vault) = test_vault();
    let key = WindowKey::new("2026-03");
    let learned_at = key.start_timestamp().unwrap() + 60;
    let diagnostic = EntityId::from_bytes([0x71; 16])?;
    let ordinary = EntityId::from_bytes([0x72; 16])?;
    let marker = b"local-only-diagnostic-observation";
    let doc = create_window_doc("source", &key);
    let diagnostic_blob =
        make_entity_blob(crate::registry::ENTITY_TYPE_DIAGNOSTIC, learned_at, marker);
    for raw_key in [diagnostic.to_hex(), "malformed-diagnostic-id".to_owned()] {
        map_insert_bytes(&doc.get_map("entities"), &raw_key, &diagnostic_blob)?;
    }
    map_insert_bytes(
        &doc.get_map("entities"),
        &ordinary.to_hex(),
        &make_entity_blob(ENTITY_TYPE_TURN, learned_at, b"ordinary"),
    )?;
    doc.commit();

    // A second export must stay history-free after the live rows are gone.
    for _ in 0..2 {
        let update =
            export_window_updates_since(&vault, &key, &doc, &VersionVector::default().encode())?;
        assert!(!update.windows(marker.len()).any(|bytes| bytes == marker));
        let peer = LoroDoc::new();
        import_doc(&peer, &update)?;
        assert!(peer.is_shallow());
        assert!(map_get_bytes(&peer.get_map("entities"), &diagnostic.to_hex()).is_none());
        assert!(map_get_bytes(&peer.get_map("entities"), "malformed-diagnostic-id").is_none());
        assert!(map_get_bytes(&peer.get_map("entities"), &ordinary.to_hex()).is_some());
    }
    assert!(history_free_window_required(&vault, &key)?);
    Ok(())
}

#[test]
fn diagnostic_update_admission_is_side_effect_free_and_checks_hidden_history() -> Result<()> {
    let key = WindowKey::new("2026-03");
    let doc = create_window_doc("receiver", &key);
    map_insert_bytes(&doc.get_map("entities"), "ordinary", b"previously accepted")?;
    doc.commit();
    let before = doc.oplog_vv();
    let diagnostic = make_entity_blob(crate::registry::ENTITY_TYPE_DIAGNOSTIC, 1, b"private");
    for malformed_key in [false, true] {
        let source = doc.fork();
        let id = EntityId::from_bytes([0x71; 16])?.to_hex();
        let raw_key = if malformed_key {
            "malformed-diagnostic-id"
        } else {
            &id
        };
        map_insert_bytes(&source.get_map("entities"), raw_key, &diagnostic)?;
        source.commit();
        let live = source.export(loro::ExportMode::updates(&before)).unwrap();
        assert!(matches!(
            validate_window_update_locality(&doc, &live),
            Err(Error::InvalidConfig(_))
        ));
        let shallow = source
            .export(loro::ExportMode::shallow_snapshot(
                &source.oplog_frontiers(),
            ))
            .unwrap();
        assert!(matches!(
            validate_window_update_locality(&doc, &shallow),
            Err(Error::InvalidConfig(_))
        ));
        map_delete(&source.get_map("entities"), raw_key)?;
        source.commit();
        let hidden = source.export(loro::ExportMode::updates(&before)).unwrap();
        assert!(matches!(
            validate_window_update_locality(&doc, &hidden),
            Err(Error::InvalidConfig(_))
        ));
        assert_eq!(doc.oplog_vv(), before);
        assert!(map_get_bytes(&doc.get_map("entities"), raw_key).is_none());
    }
    let ordinary = doc.fork();
    map_insert_bytes(&ordinary.get_map("entities"), "second", b"ordinary")?;
    ordinary.commit();
    let update = ordinary.export(loro::ExportMode::updates(&before)).unwrap();
    validate_window_update_locality(&doc, &update)?;
    let snapshot = ordinary
        .export(loro::ExportMode::shallow_snapshot(
            &ordinary.oplog_frontiers(),
        ))
        .unwrap();
    validate_window_update_locality(&doc, &snapshot)?;
    let unrelated = LoroDoc::new();
    map_insert_bytes(&unrelated.get_map("entities"), "dependency", b"first")?;
    unrelated.commit();
    let missing = unrelated.oplog_vv();
    map_insert_bytes(
        &unrelated.get_map("entities"),
        "deferred-diagnostic",
        &diagnostic,
    )?;
    unrelated.commit();
    let pending = unrelated
        .export(loro::ExportMode::updates(&missing))
        .unwrap();
    assert!(matches!(
        validate_window_update_locality(&doc, &pending),
        Err(Error::InvalidConfig(_))
    ));
    assert_eq!(doc.oplog_vv(), before);
    assert!(map_get_bytes(&doc.get_map("entities"), "second").is_none());
    Ok(())
}

/// A WORLD flagged device-only and a claim in it with an `About` edge to a
/// PERSON, all learned in `window`.
fn device_only_world_fixture(vault: &Vault, window: &WindowKey) -> Result<(EntityId, EntityId)> {
    let at = window.start_timestamp().unwrap() + 60;
    let occurred = TimeRange { start: at, end: at };
    let world = EntityId::from_bytes([0x71; 16])?;
    let person = EntityId::from_bytes([0x72; 16])?;
    let claim = EntityId::from_bytes([0x73; 16])?;
    vault.put_entity(
        &world,
        crate::registry::ENTITY_TYPE_WORLD,
        occurred,
        at,
        b"world",
    )?;
    vault.put_entity(
        &person,
        crate::registry::ENTITY_TYPE_PERSON,
        occurred,
        at,
        b"person",
    )?;
    vault.set_world_device_only(world, true)?;
    let mut body = crate::claim::ClaimBody::new(
        "test.device_only",
        crate::claim::ClaimSubject::Entity(person),
        Value::from("fact"),
        1.0,
        ClaimApprovalStatus::Proposed,
        crate::claim::ClaimLifecycleStatus::Active,
    )?;
    body.world = Some(world);
    vault.put_claim(&claim, &body, occurred, at)?;
    vault
        .batch()
        .edge(&claim, EdgeKind::About, &person, 1.0)
        .commit()?;
    Ok((world, claim))
}

fn packed_device_only_window(vault: &Vault) -> Result<(LoroDoc, EntityId, EntityId)> {
    let key = WindowKey::new("2026-03");
    let (world, claim) = device_only_world_fixture(vault, &key)?;
    let doc = crate::sync::schema::create_window_doc("device-only", &key);
    reverse_rematerialize(vault, &doc, &key)?;
    Ok((doc, world, claim))
}

#[test]
fn packing_withholds_a_claim_in_a_device_only_world() -> Result<()> {
    let (_dir, vault) = test_vault();
    let (doc, _, claim) = packed_device_only_window(&vault)?;

    assert!(map_get_bytes(&doc.get_map("entities"), &claim.to_hex()).is_none());
    Ok(())
}

#[test]
fn packing_withholds_the_world_row_flagged_device_only() -> Result<()> {
    let (_dir, vault) = test_vault();
    let (doc, world, _) = packed_device_only_window(&vault)?;

    assert!(map_get_bytes(&doc.get_map("entities"), &world.to_hex()).is_none());
    Ok(())
}

#[test]
fn packing_withholds_edges_that_touch_a_device_only_world_row() -> Result<()> {
    let (_dir, vault) = test_vault();
    let (doc, _, claim) = packed_device_only_window(&vault)?;
    let mut named = false;
    crate::sync::loro_support::map_for_each_value_bytes(&doc.get_map("edges"), |key, _| {
        named |= key.contains(&claim.to_hex());
    });

    assert!(!named);
    Ok(())
}

/// Forward rematerialization must apply the same MACHINE origin-proof verdict
/// as Observer B, without checking whether the signer was locally enrolled.
#[test]
fn forward_remat_quarantines_bad_machine_proof_and_commits_signed_sibling() -> Result<()> {
    use crate::authority::HostSlipIssuer;
    use crate::claim::ClaimSubject;
    use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_MACHINE};
    use crate::write_envelope::{
        ClaimCandidate, MachineWriteSignature, WriteActor, WriteEnvelope, WriteProvenance,
    };
    use ed25519_dalek::{Signer, SigningKey};

    let (_dir, vault) = test_vault();
    let machine = EntityId::from_bytes([0x40; 16])?;
    let bad_id = EntityId::from_bytes([0x41; 16])?;
    let good_id = EntityId::from_bytes([0x42; 16])?;
    vault.put_entity(
        &machine,
        ENTITY_TYPE_MACHINE,
        TimeRange { start: 1, end: 1 },
        1,
        b"stored machine",
    )?;
    vault.ensure_host_root_slip(&HostSlipIssuer::from_secret(b"forward machine root")?)?;
    let signing = SigningKey::from_bytes(&[0x45; 32]);
    let candidate = ClaimCandidate::new(
        "test.machine.replay",
        ClaimSubject::Entity(machine),
        Value::from("signed fact"),
        1.0,
    );
    let envelope = WriteEnvelope::new(
        WriteActor::new(machine, EdgeActorClass::System),
        ClaimSource::Observed,
        WriteProvenance::new(Value::from("peer observation"))?,
        ClaimApprovalStatus::Proposed,
    );
    let transcript = vault.machine_claim_transcript(&good_id, &candidate, &envelope)?;
    let signed = envelope.with_machine_signature(MachineWriteSignature {
        public_key: signing.verifying_key().to_bytes(),
        signature: signing.sign(&transcript).to_bytes(),
    });
    let facet = crate::claim::default_facet_in(&vault.store, &vault.store.env.read_txn()?)?;
    let body = crate::claim::encode_claim_body(&candidate.into_claim_body(&signed, facet)?)?;
    let at = 1_772_400_000;
    let blob = make_entity_blob(ENTITY_TYPE_CLAIM, at, &body);
    let window_key = WindowKey::new("2026-03");
    let doc = create_window_doc("remote-machine-proof", &window_key);
    let entities = doc.get_map("entities");
    map_insert_bytes(&entities, &bad_id.to_hex(), &blob)?;
    map_insert_bytes(&entities, &good_id.to_hex(), &blob)?;
    doc.commit();

    let count = forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
    assert_eq!(
        count, 1,
        "the sibling must commit despite the rejected proof"
    );
    assert!(vault.get_raw(&bad_id)?.is_none());
    assert_eq!(vault.get_raw(&good_id)?.as_deref(), Some(blob.as_slice()));
    let records = crate::sync::quarantine::quarantined_records(&vault)?;
    assert_eq!(records.len(), 1);
    let rejected = &records[0].1;
    assert_eq!(rejected.container, QuarantineContainer::Entities);
    assert_eq!(rejected.reason_code, "InvalidMachineClaimProof");
    assert_eq!(
        (rejected.crdt_key_hash, rejected.crdt_key_len),
        crate::sync::quarantine::crdt_key_metadata(&bad_id.to_hex())
    );
    assert_eq!(
        rejected.payload_hash,
        crate::sync::quarantine::payload_hash(&blob)
    );
    Ok(())
}

#[test]
fn forward_rematerialization_quarantines_in_range_project_depth_edit() -> Result<()> {
    let (_dir, vault) = test_vault();
    let root = vault.root_project()?;
    let person = EntityId::now();
    vault.put_entity(
        &person,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let writer = crate::write_envelope::WriteActor::new(person, EdgeActorClass::Human);
    let revoke = crate::subject_model::tests::authorization::root_owner(&vault, writer, 0xB2)?;
    crate::workspace_roster::set_project_depth_signed_for_test(&vault, root, 0, &writer, 2, 0xB2)?;
    vault.put_authority_log_entry(
        &revoke,
        TimeRange {
            start: 102,
            end: 102,
        },
        102,
    )?;
    let (edit, mut forged) = crate::gate::project_depth::contributions_for_test(&vault, root)?
        .into_iter()
        .find(|(_, bytes)| {
            matches!(
                crate::gate::project_depth::decode_contribution(bytes).ok(),
                Some(crate::gate::project_depth::ProjectDepthContribution::Edit(
                    _
                ))
            )
        })
        .expect("signed edit");
    forged.push(0x01);
    let window_key = WindowKey::new("2026-03");
    let doc = create_window_doc("remote", &window_key);
    let stamp = window_key.start_timestamp().expect("window start") + 60;
    doc.get_map("entities")
        .insert(
            edit.to_hex().as_str(),
            make_entity_blob(crate::registry::ENTITY_TYPE_POLICY_MANIFEST, stamp, &forged)
                .as_slice(),
        )
        .expect("forged manifest");
    doc.commit();
    assert_eq!(
        forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?,
        0
    );
    assert_eq!(vault.project(root)?.unwrap().depth, 0);
    assert!(
        quarantine::quarantined_records(&vault)?
            .iter()
            .any(|(_, row)| row.reason_code == "InvalidProjectBody")
    );
    Ok(())
}

#[test]
fn signed_owner_project_depth_replays_to_existing_and_new_replicas() -> Result<()> {
    let (_a_dir, a) = test_vault();
    let root_a = a.root_project()?;
    let lead = EntityId::from_hex(&a.project(root_a)?.unwrap().leader)?;
    let project = EntityId::now();
    let owner_id = EntityId::now();
    a.put_entity(
        &owner_id,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"person",
    )?;
    let owner = crate::write_envelope::WriteActor::new(owner_id, EdgeActorClass::Human);
    crate::subject_model::tests::authorization::root_owner(&a, owner, 0xB6)?;
    crate::workspace_roster::create_project_signed_for_test(
        &a, project, root_a, lead, &owner, 1, 0xB6,
    )?;
    let history = a.export_signed_authority_history()?;
    crate::workspace_roster::set_project_depth_signed_for_test(&a, project, 2, &owner, 2, 0xB6)?;
    assert_eq!(a.project(project)?.unwrap().depth, 2);
    let contributions = crate::gate::project_depth::contributions_for_test(&a, project)?;
    assert_eq!(contributions.len(), 2); // immutable birth + signed edit
    let key = WindowKey::new("2026-03");
    let stamp = key.start_timestamp().expect("window timestamp") + 60;
    let body = rmp_serde::to_vec_named(&a.project(project)?.unwrap()).expect("member body");

    let prepare = |b: &Vault, existing: bool| -> Result<()> {
        let root_b = b.root_project()?;
        let leader = EntityId::from_hex(&b.project(root_b)?.unwrap().leader)?;
        b.put_project(
            root_a,
            &crate::workspace_roster::ProjectRecord::new(root_a, Some(root_b), root_b, leader)
                .unwrap(),
            1,
        )?;
        b.put_entity(
            &owner_id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )?;
        b.import_signed_authority_history(&history)?;
        if existing {
            let (birth_id, birth_bytes) = contributions
                .iter()
                .find(|(_, bytes)| {
                    matches!(
                        crate::gate::project_depth::decode_contribution(bytes).ok(),
                        Some(crate::gate::project_depth::ProjectDepthContribution::Birth(
                            _
                        ))
                    )
                })
                .ok_or(Error::EntityNotFound)?;
            b.with_write_txn(|txn| {
                b.batch_in()
                    .put_replicated(
                        birth_id,
                        crate::registry::ENTITY_TYPE_POLICY_MANIFEST,
                        TimeRange { start: 1, end: 1 },
                        1,
                        birth_bytes,
                    )
                    .apply(txn)
            })?;
            b.put_project(
                project,
                &crate::workspace_roster::ProjectRecord::new(project, Some(root_a), root_a, leader)
                    .unwrap(),
                1,
            )?;
        }
        Ok(())
    };
    for existing in [true, false] {
        let (dir, b) = test_vault();
        prepare(&b, existing)?;
        let doc = create_window_doc("owner-edit", &key);
        for (id, bytes) in &contributions {
            doc.get_map("entities")
                .insert(
                    id.to_hex().as_str(),
                    make_entity_blob(crate::registry::ENTITY_TYPE_POLICY_MANIFEST, stamp, bytes)
                        .as_slice(),
                )
                .expect("policy fact");
        }
        doc.get_map("entities")
            .insert(
                project.to_hex().as_str(),
                make_entity_blob(b.project_type_byte()?, stamp, &body).as_slice(),
            )
            .expect("project membership");
        doc.commit();
        let materializer = Materializer::new();
        forward_rematerialize(&b, &doc, &materializer, &key)?;
        forward_rematerialize(&b, &doc, &materializer, &key)?; // dependency order is immaterial
        assert_eq!(b.project(project)?.unwrap().depth, 2);
        drop(b);
        let reopened = Vault::open(dir.path(), VaultConfig::device())?;
        assert_eq!(reopened.project(project)?.unwrap().depth, 2);
        forward_rematerialize(&reopened, &doc, &Materializer::new(), &key)?;
        assert_eq!(reopened.project(project)?.unwrap().depth, 2);
        // The immutable birth and edit survive deletion of the mutable
        // membership row. The unchanged synchronized window can restore it.
        reopened.batch().delete(&project).commit()?;
        assert!(reopened.project(project)?.is_none());
        forward_rematerialize(&reopened, &doc, &Materializer::new(), &key)?;
        assert_eq!(reopened.project(project)?.unwrap().depth, 2);
    }
    let (_forged_dir, forged_vault) = test_vault();
    prepare(&forged_vault, false)?;
    let tampered_doc = create_window_doc("tampered-owner-edit", &key);
    for (id, bytes) in &contributions {
        let mut raw = bytes.clone();
        if id == &contributions[1].0 {
            raw.push(0x01);
        } // content id/codec cannot change
        tampered_doc
            .get_map("entities")
            .insert(
                id.to_hex().as_str(),
                make_entity_blob(crate::registry::ENTITY_TYPE_POLICY_MANIFEST, stamp, &raw)
                    .as_slice(),
            )
            .expect("tampered policy fact");
    }
    tampered_doc
        .get_map("entities")
        .insert(
            project.to_hex().as_str(),
            make_entity_blob(forged_vault.project_type_byte()?, stamp, &body).as_slice(),
        )
        .expect("project membership");
    tampered_doc.commit();
    forward_rematerialize(&forged_vault, &tampered_doc, &Materializer::new(), &key)?;
    assert_ne!(
        forged_vault.project(project)?.map(|body| body.depth),
        Some(2)
    );
    assert!(
        quarantine::quarantined_records(&forged_vault)?
            .iter()
            .any(|(_, row)| row.reason_code == "InvalidProjectBody")
    );
    Ok(())
}

#[test]
fn project_depth_edit_waits_for_owner_binding_through_retry_drain() -> Result<()> {
    let (_source_dir, source) = test_vault();
    let source_root = source.root_project()?;
    let leader = EntityId::from_hex(&source.project(source_root)?.unwrap().leader)?;
    let id = EntityId::now();
    source.put_project(
        id,
        &crate::workspace_roster::ProjectRecord::new(id, Some(source_root), source_root, leader)
            .unwrap(),
        1,
    )?;
    let human = EntityId::now();
    source.put_entity(
        &human,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let writer = crate::write_envelope::WriteActor::new(human, EdgeActorClass::Human);
    crate::subject_model::tests::authorization::root_owner(&source, writer, 0xBA)?;
    let history = source.export_signed_authority_history()?;
    assert_eq!(history.len(), 2);
    crate::workspace_roster::set_project_depth_signed_for_test(&source, id, 2, &writer, 2, 0xBA)?;
    let (edit, body) = crate::gate::project_depth::contributions_for_test(&source, id)?
        .into_iter()
        .find(|(_, bytes)| {
            matches!(
                crate::gate::project_depth::decode_contribution(bytes).ok(),
                Some(crate::gate::project_depth::ProjectDepthContribution::Edit(
                    _
                ))
            )
        })
        .expect("signed depth contribution");

    let (_target_dir, target) = test_vault();
    let target_root = target.root_project()?;
    let target_leader = EntityId::from_hex(&target.project(target_root)?.unwrap().leader)?;
    target.put_project(
        source_root,
        &crate::workspace_roster::ProjectRecord::new(
            source_root,
            Some(target_root),
            target_root,
            target_leader,
        )
        .unwrap(),
        1,
    )?;
    target.put_project(
        id,
        &crate::workspace_roster::ProjectRecord::new(
            id,
            Some(source_root),
            source_root,
            target_leader,
        )
        .unwrap(),
        1,
    )?;
    target.put_entity(
        &human,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    target.import_signed_authority_history(&history[..1])?; // rooted, but no BindActor
    let key = WindowKey::new("2026-03");
    let stamp = key.start_timestamp().expect("window start") + 60;
    let doc = create_window_doc("project-first", &key);
    doc.get_map("entities")
        .insert(
            edit.to_hex().as_str(),
            make_entity_blob(crate::registry::ENTITY_TYPE_POLICY_MANIFEST, stamp, &body).as_slice(),
        )
        .expect("insert signed depth fact");
    doc.commit();
    let materializer = Materializer::new();
    forward_rematerialize(&target, &doc, &materializer, &key)?;
    assert_eq!(target.project(id)?.unwrap().depth, 0);
    assert!(
        target.get(&edit)?.is_some(),
        "contribution persists while signer dependency is missing"
    );
    forward_rematerialize(&target, &doc, &materializer, &key)?;
    assert_eq!(target.project(id)?.unwrap().depth, 0);
    target.import_signed_authority_history(&history[1..])?;
    assert_eq!(target.project(id)?.unwrap().depth, 2);
    Ok(())
}

#[test]
fn concurrent_signed_project_depth_facts_follow_loro_winner_in_either_exchange_order() -> Result<()>
{
    // The Loro winner is now the union of independent manifest keys, NOT one
    // whole-project blob. Equal/unequal offline edit counts must fold alike.
    for unequal in [false, true] {
        for reverse in [false, true] {
            let (_a_dir, a) = test_vault();
            let (_b_dir, b) = test_vault();
            let root_a = a.root_project()?;
            let root_b = b.root_project()?;
            let leader = EntityId::from_hex(&a.project(root_a)?.unwrap().leader)?;
            let leader_b = EntityId::from_hex(&b.project(root_b)?.unwrap().leader)?;
            b.put_project(
                root_a,
                &crate::workspace_roster::ProjectRecord::new(
                    root_a,
                    Some(root_b),
                    root_b,
                    leader_b,
                )
                .unwrap(),
                1,
            )?;
            let project = EntityId::now();
            let base =
                crate::workspace_roster::ProjectRecord::new(project, Some(root_a), root_a, leader)
                    .unwrap();
            let owner_id = EntityId::now();
            let writer = crate::write_envelope::WriteActor::new(owner_id, EdgeActorClass::Human);
            for vault in [&a, &b] {
                vault.put_entity(
                    &owner_id,
                    crate::registry::ENTITY_TYPE_PERSON,
                    TimeRange { start: 1, end: 1 },
                    1,
                    b"owner",
                )?;
            }
            crate::subject_model::tests::authorization::root_owner(&a, writer, 0xBC)?;
            let authority = a.export_signed_authority_history()?;
            b.import_signed_authority_history(&authority)?;
            crate::workspace_roster::create_project_signed_for_test(
                &a, project, root_a, leader, &writer, 1, 0xBC,
            )?;
            crate::workspace_roster::create_project_signed_for_test(
                &b, project, root_a, leader_b, &writer, 1, 0xBC,
            )?;
            crate::workspace_roster::set_project_depth_signed_for_test(
                &a, project, 2, &writer, 2, 0xBC,
            )?;
            if unequal {
                crate::workspace_roster::set_project_depth_signed_for_test(
                    &a, project, 6, &writer, 3, 0xBC,
                )?;
            }
            crate::workspace_roster::set_project_depth_signed_for_test(
                &b, project, 0, &writer, 2, 0xBC,
            )?;
            assert_eq!(
                a.project(project)?.unwrap().depth,
                if unequal { 6 } else { 2 }
            );
            assert_eq!(b.project(project)?.unwrap().depth, 0);
            let from_a = crate::gate::project_depth::contributions_for_test(&a, project)?;
            let from_b = crate::gate::project_depth::contributions_for_test(&b, project)?;
            assert_eq!(from_a.len(), if unequal { 3 } else { 2 });
            assert_eq!(from_b.len(), 2);
            let window = WindowKey::new("2026-03");
            let stamp = window.start_timestamp().expect("window start") + 60;
            let doc_a = create_window_doc("offline-a", &window);
            let doc_b = create_window_doc("offline-b", &window);
            doc_a.set_peer_id(1).expect("peer A");
            doc_b.set_peer_id(2).expect("peer B");
            for (doc, entries) in [(&doc_a, &from_a), (&doc_b, &from_b)] {
                for (id, bytes) in entries {
                    doc.get_map("entities")
                        .insert(
                            id.to_hex().as_str(),
                            make_entity_blob(
                                crate::registry::ENTITY_TYPE_POLICY_MANIFEST,
                                stamp,
                                bytes,
                            )
                            .as_slice(),
                        )
                        .expect("immutable contribution");
                }
                doc.get_map("entities")
                    .insert(
                        project.to_hex().as_str(),
                        make_entity_blob(
                            a.project_type_byte()?,
                            stamp,
                            &rmp_serde::to_vec_named(&base).expect("project members"),
                        )
                        .as_slice(),
                    )
                    .expect("mutable membership");
                doc.commit();
            }
            let update_a = loro_support::export_all_updates(&doc_a)?;
            let update_b = loro_support::export_all_updates(&doc_b)?;
            let first = create_window_doc("first-merge", &window);
            let second = create_window_doc("second-merge", &window);
            if reverse {
                import_doc(&first, &update_b)?;
                import_doc(&first, &update_a)?;
                import_doc(&second, &update_a)?;
                import_doc(&second, &update_b)?;
            } else {
                import_doc(&first, &update_a)?;
                import_doc(&first, &update_b)?;
                import_doc(&second, &update_b)?;
                import_doc(&second, &update_a)?;
            }
            let mut ids = std::collections::BTreeSet::new();
            for (id, _) in from_a.iter().chain(from_b.iter()) {
                ids.insert(*id);
            }
            for id in ids {
                let first_body =
                    loro_support::map_get_bytes(&first.get_map("entities"), &id.to_hex());
                let second_body =
                    loro_support::map_get_bytes(&second.get_map("entities"), &id.to_hex());
                assert!(first_body.is_some());
                assert_eq!(
                    first_body, second_body,
                    "every immutable fact survives both Loro orders"
                );
            }
            // Observer B applies the merged map to A while it still holds its
            // permissive local branch. Forward materialization applies it to B.
            let observer_doc = create_window_doc("observer", &window);
            let materializer = std::sync::Arc::new(Materializer::new());
            let _subscriptions =
                bridge::register_observer_b(&observer_doc, &a, &materializer, window.as_str());
            import_doc(&observer_doc, &update_a)?;
            import_doc(&observer_doc, &update_b)?;
            forward_rematerialize(&a, &observer_doc, &Materializer::new(), &window)?;
            forward_rematerialize(&b, &second, &Materializer::new(), &window)?;
            assert_eq!(a.project(project)?.unwrap().depth, 0);
            assert_eq!(b.project(project)?.unwrap().depth, 0);
            // A third replica first sees the already-merged contribution set.
            let (dir, fresh) = test_vault();
            let root_f = fresh.root_project()?;
            let lead_f = EntityId::from_hex(&fresh.project(root_f)?.unwrap().leader)?;
            fresh.put_project(
                root_a,
                &crate::workspace_roster::ProjectRecord::new(root_a, Some(root_f), root_f, lead_f)
                    .unwrap(),
                1,
            )?;
            fresh.put_entity(
                &owner_id,
                crate::registry::ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"owner",
            )?;
            fresh.import_signed_authority_history(&authority)?;
            for _ in 0..2 {
                forward_rematerialize(&fresh, &first, &Materializer::new(), &window)?;
            }
            assert_eq!(fresh.project(project)?.unwrap().depth, 0);
            drop(fresh);
            let fresh = Vault::open(dir.path(), VaultConfig::device())?;
            assert_eq!(fresh.project(project)?.unwrap().depth, 0);
            let agent = EntityId::from_hex(&a.project(root_a)?.unwrap().leader)?;
            for (vault, local_root) in [(&*a, root_a), (&*b, root_b), (&fresh, root_f)] {
                let dispatcher = crate::agent_dispatch::AgentDispatcher::new(vault);
                let root = dispatcher.dispatch(crate::agent_dispatch::DispatchAgent {
                    target: crate::agent_dispatch::AgentDispatchTarget::Custom(agent),
                    parent_attempt: None,
                    dedupe_key: None,
                    run_id: None,
                    now: 4,
                })?;
                let crate::agent_dispatch::AgentDispatchOutcome::Dispatched(root) = root else {
                    panic!("root")
                };
                let parent = if local_root == root_a {
                    root.attempt.id
                } else {
                    let intermediate = dispatcher.dispatch_with_context(
                        crate::agent_dispatch::DispatchAgent {
                            target: crate::agent_dispatch::AgentDispatchTarget::Custom(agent),
                            parent_attempt: Some(root.attempt.id),
                            dedupe_key: None,
                            run_id: None,
                            now: 5,
                        },
                        crate::agent_dispatch::AgentSpawnContext::default().with_project(root_a),
                    )?;
                    let crate::agent_dispatch::AgentDispatchOutcome::Dispatched(intermediate) =
                        intermediate
                    else {
                        panic!("ancestor")
                    };
                    intermediate.attempt.id
                };
                let child = dispatcher.dispatch_with_context(
                    crate::agent_dispatch::DispatchAgent {
                        target: crate::agent_dispatch::AgentDispatchTarget::Custom(agent),
                        parent_attempt: Some(parent),
                        dedupe_key: None,
                        run_id: None,
                        now: 6,
                    },
                    crate::agent_dispatch::AgentSpawnContext::default().with_project(project),
                )?;
                let crate::agent_dispatch::AgentDispatchOutcome::Dispatched(child) = child else {
                    panic!("child")
                };
                assert_eq!(child.input.depth_remaining, Some(0));
            }
        }
    }
    Ok(())
}

/// ARCH-0040's revoke-then-regrant window: an edit signed before the owner's
/// revoke stays non-authorizing after the regrant on a replica, through the
/// forward pass and through Observer B, until an edit that observed the
/// regrant supersedes it.
#[test]
fn pre_regrant_depth_edit_stays_refused_through_both_replay_doors() -> Result<()> {
    use ed25519_dalek::Signer;
    let (_a_dir, a) = test_vault();
    let root_a = a.root_project()?;
    let owner_id = EntityId::now();
    a.put_entity(
        &owner_id,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"person",
    )?;
    let owner = crate::write_envelope::WriteActor::new(owner_id, EdgeActorClass::Human);
    crate::subject_model::tests::authorization::root_owner(&a, owner, 0xC7)?;
    // The root's birth is implicit, so the pre-revoke edit is its only fact.
    crate::workspace_roster::set_project_depth_signed_for_test(&a, root_a, 12, &owner, 2, 0xC7)?;
    let stale = crate::gate::project_depth::contributions_for_test(&a, root_a)?;
    assert_eq!(stale.len(), 1);
    let signing = ed25519_dalek::SigningKey::from_bytes(&[0xC7; 32]);
    let bind: crate::authority::AuthorityLogEntry =
        crate::authority::decode_authority_log_entry_body(
            &a.export_signed_authority_history()?[1],
        )?;
    let mut revoke = crate::authority::AuthorityLogEntry {
        schema_version: bind.schema_version,
        vault_id: bind.vault_id,
        seq: 2,
        parent_hashes: vec![crate::authority::authority_entry_hash(&bind)?],
        op: crate::authority::AuthorityOp::RevokeActor {
            authority_key: bind.signer.public_key.clone(),
            epoch: 1,
        },
        signer: bind.signer.clone(),
        cosigns: Vec::new(),
        ts: 102,
    };
    revoke.signer.signature = signing
        .sign(&crate::authority::authority_transcript(&revoke)?)
        .to_bytes()
        .to_vec();
    a.put_authority_log_entry(
        &revoke,
        TimeRange {
            start: 102,
            end: 102,
        },
        102,
    )?;
    let mut regrant = crate::authority::AuthorityLogEntry {
        schema_version: bind.schema_version,
        vault_id: bind.vault_id,
        seq: 3,
        parent_hashes: vec![crate::authority::authority_entry_hash(&revoke)?],
        op: crate::authority::AuthorityOp::BindActor {
            authority_key: bind.signer.public_key.clone(),
            actor_ref: owner_id,
            actor_class: "human".into(),
            epoch: 2,
        },
        signer: bind.signer,
        cosigns: Vec::new(),
        ts: 103,
    };
    regrant.signer.signature = signing
        .sign(&crate::authority::authority_transcript(&regrant)?)
        .to_bytes()
        .to_vec();
    a.put_authority_log_entry(
        &regrant,
        TimeRange {
            start: 103,
            end: 103,
        },
        103,
    )?;
    let history = a.export_signed_authority_history()?;
    assert_eq!(a.project(root_a)?.unwrap().depth, 0);
    let current = a.observed_write_actor(owner)?;
    crate::workspace_roster::set_project_depth_signed_for_test(&a, root_a, 5, &current, 4, 0xC7)?;
    assert_eq!(a.project(root_a)?.unwrap().depth, 5);
    let observed: Vec<_> = crate::gate::project_depth::contributions_for_test(&a, root_a)?
        .into_iter()
        .filter(|(id, _)| !stale.iter().any(|(old, _)| old == id))
        .collect();
    assert_eq!(observed.len(), 1);
    let key = WindowKey::new("2026-03");
    let stamp = key.start_timestamp().expect("window timestamp") + 60;
    let source = create_window_doc("regrant-source", &key);
    let insert = |facts: &[(EntityId, Vec<u8>)]| {
        for (id, bytes) in facts {
            source
                .get_map("entities")
                .insert(
                    id.to_hex().as_str(),
                    make_entity_blob(crate::registry::ENTITY_TYPE_POLICY_MANIFEST, stamp, bytes)
                        .as_slice(),
                )
                .expect("policy fact");
        }
        source.commit();
    };
    insert(&stale);
    let stage_stale = loro_support::export_all_updates(&source)?;
    insert(&observed);
    let stage_observed = loro_support::export_all_updates(&source)?;
    for observer in [false, true] {
        let (_b_dir, b) = test_vault();
        let root_b = b.root_project()?;
        let leader = EntityId::from_hex(&b.project(root_b)?.unwrap().leader)?;
        b.put_project(
            root_a,
            &crate::workspace_roster::ProjectRecord::new(root_a, Some(root_b), root_b, leader)
                .unwrap(),
            1,
        )?;
        b.put_entity(
            &owner_id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )?;
        b.import_signed_authority_history(&history)?;
        assert_eq!(b.project(root_a)?.unwrap().depth, 10);
        let live = create_window_doc("regrant-live", &key);
        let materializer = Arc::new(Materializer::new());
        let _subscriptions =
            observer.then(|| bridge::register_observer_b(&live, &b, &materializer, key.as_str()));
        for (stage, depth) in [(&stage_stale, 0), (&stage_observed, 5)] {
            import_doc(&live, stage)?;
            if !observer {
                forward_rematerialize(&b, &live, &materializer, &key)?;
            }
            assert_eq!(
                b.project(root_a)?.unwrap().depth,
                depth,
                "observer={observer}: a regrant never blesses a pre-regrant edit"
            );
        }
    }
    Ok(())
}

#[test]
fn signed_project_edit_before_predecessor_survives_forward_retry_drain() -> Result<()> {
    let (_source_dir, source) = test_vault();
    let root = source.root_project()?;
    let leader = EntityId::from_hex(&source.project(root)?.unwrap().leader)?;
    let person = EntityId::now();
    source.put_entity(
        &person,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let writer = crate::write_envelope::WriteActor::new(person, EdgeActorClass::Human);
    crate::subject_model::tests::authorization::root_owner(&source, writer, 0xC2)?;
    let project = EntityId::now();
    crate::workspace_roster::create_project_signed_for_test(
        &source, project, root, leader, &writer, 1, 0xC2,
    )?;
    crate::workspace_roster::set_project_depth_signed_for_test(
        &source, project, 2, &writer, 2, 0xC2,
    )?;
    crate::workspace_roster::set_project_depth_signed_for_test(
        &source, project, 12, &writer, 3, 0xC2,
    )?;
    let mut birth = None;
    let mut first = None;
    let mut second = None;
    for (id, body) in crate::gate::project_depth::contributions_for_test(&source, project)? {
        match crate::gate::project_depth::decode_contribution(&body)? {
            crate::gate::project_depth::ProjectDepthContribution::Birth(_) => {
                birth = Some((id, body));
            }
            crate::gate::project_depth::ProjectDepthContribution::Edit(edit) if edit.depth == 2 => {
                first = Some((id, body));
            }
            crate::gate::project_depth::ProjectDepthContribution::Edit(edit)
                if edit.depth == 12 =>
            {
                second = Some((id, body));
            }
            _ => return Err(Error::InvalidConfig("project predecessor fixture".into())),
        }
    }
    let (birth, first, second) = (
        birth.ok_or(Error::EntityNotFound)?,
        first.ok_or(Error::EntityNotFound)?,
        second.ok_or(Error::EntityNotFound)?,
    );
    let (_target_dir, target) = test_vault();
    let local_root = target.root_project()?;
    let local_leader = EntityId::from_hex(&target.project(local_root)?.unwrap().leader)?;
    target.put_project(
        root,
        &crate::workspace_roster::ProjectRecord::new(
            root,
            Some(local_root),
            local_root,
            local_leader,
        )
        .unwrap(),
        1,
    )?;
    target.put_entity(
        &person,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    target.import_signed_authority_history(&source.export_signed_authority_history()?)?;
    let window = WindowKey::new("2026-03");
    let stamp = window.start_timestamp().expect("window start") + 60;
    let doc = create_window_doc("out-of-order-project-policy", &window);
    let manifest_blob =
        |body: &[u8]| make_entity_blob(crate::registry::ENTITY_TYPE_POLICY_MANIFEST, stamp, body);
    doc.get_map("entities")
        .insert(
            birth.0.to_hex().as_str(),
            manifest_blob(&birth.1).as_slice(),
        )
        .expect("birth");
    doc.get_map("entities")
        .insert(
            project.to_hex().as_str(),
            make_entity_blob(
                target.project_type_byte()?,
                stamp,
                &rmp_serde::to_vec_named(&source.project(project)?.unwrap()).expect("member body"),
            )
            .as_slice(),
        )
        .expect("member row");
    doc.commit();
    let materializer = Materializer::new();
    for _ in 0..2 {
        forward_rematerialize(&target, &doc, &materializer, &window)?;
    }
    assert_eq!(target.project(project)?.unwrap().depth, 10);
    doc.get_map("entities")
        .insert(
            second.0.to_hex().as_str(),
            manifest_blob(&second.1).as_slice(),
        )
        .expect("later edit arrives first");
    doc.commit();
    forward_rematerialize(&target, &doc, &materializer, &window)?;
    assert_eq!(target.project(project)?.unwrap().depth, 0);
    forward_rematerialize(&target, &doc, &materializer, &window)?; // retry drain before predecessor
    assert_eq!(target.project(project)?.unwrap().depth, 0);
    assert!(
        target.get(&second.0)?.is_some(),
        "dependency-pending fact remains stored"
    );
    doc.get_map("entities")
        .insert(
            first.0.to_hex().as_str(),
            manifest_blob(&first.1).as_slice(),
        )
        .expect("predecessor arrives later");
    doc.commit();
    forward_rematerialize(&target, &doc, &materializer, &window)?;
    assert_eq!(target.project(project)?.unwrap().depth, 12);
    Ok(())
}

/// An erased author is absent from LMDB, revisions, live CRDT state, and both
/// empty/populated outbound snapshots. The immutable topology decision stays.
#[test]
fn identity_author_redaction_scrubs_personal_carriers_and_loro_history() -> Result<()> {
    use crate::identity_topology::{
        IdentityOpEvidence, IdentityOpOutcome, IdentityOpWrite, IdentityTopologyOp, MergeOp,
        StoredIdentityOpAction, SurvivorshipPlan,
    };
    use crate::write_envelope::WriteActor;

    let (_dir, vault) = test_vault();
    let key = WindowKey::new("2026-03");
    let at = key.start_timestamp().unwrap() + 60;
    let author = EntityId::from_bytes([0x91; 16])?;
    let source = EntityId::from_bytes([0x92; 16])?;
    let survivor = EntityId::from_bytes([0x93; 16])?;
    for id in [author, source, survivor] {
        vault.put_entity(
            &id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person fixture",
        )?;
    }
    let outcome = vault.apply_identity_topology_op(
        &IdentityTopologyOp::Merge(MergeOp {
            sources: vec![source],
            survivor,
            evidence: IdentityOpEvidence::default(),
            survivorship_plan: SurvivorshipPlan::ReadThrough,
        }),
        &IdentityOpWrite::auto(ClaimSource::Inferred)
            .with_actor(WriteActor::new(author, EdgeActorClass::Human)),
        at,
    )?;
    let IdentityOpOutcome::Applied { event, .. } = outcome else {
        panic!("authored merge must apply");
    };
    let decision_before = vault.get_raw(&event)?.expect("decision row");
    let (carrier_id, carrier_bytes) = {
        let txn = vault.store.env.read_txn()?;
        let mut found = None;
        for entry in vault.store.type_index.prefix_iter(
            &txn,
            &[crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT],
        )? {
            let (index_key, _) = entry?;
            let id = crate::vault::entity_id_from_type_index_key(&index_key)?;
            let raw = vault
                .store
                .entities
                .get(&txn, id.as_bytes())?
                .expect("indexed row");
            let row = crate::identity_topology::decode_identity_topology_event_body(
                &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
            )?;
            if matches!(row.action, StoredIdentityOpAction::AuthorAttribution { target, .. } if target == event)
            {
                found = Some((id, raw.to_vec()));
            }
        }
        found.expect("independent author carrier")
    };
    let revision = vault.pin_entity_revision(&carrier_id)?;
    vault.with_write_txn(|txn| {
        crate::identity_topology::redact_author_attribution_in_txn(&vault, txn, event, at + 1)?;
        Ok(())
    })?;
    assert!(vault.get_raw(&carrier_id)?.is_none());
    assert_eq!(vault.get_raw(&event)?, Some(decision_before.clone()));
    assert!(vault.edge_exists(&source, EdgeKind::MergedInto, &survivor)?);
    let txn = vault.store.env.read_txn()?;
    assert!(
        crate::identity_topology::effective_author_in_txn(&vault.store, &txn, event)?.is_none()
    );
    drop(txn);
    assert!(
        vault
            .get_raw_with_mode(&carrier_id, crate::vault::ReadMode::Pinned(revision))?
            .is_none()
    );

    // Simulate a pre-erasure mirror, including a personal row in old Loro
    // history. The full snapshot and subsequent empty-live-state delta must
    // never carry that history to a fresh peer.
    let doc = create_window_doc("source", &key);
    map_insert_bytes(&doc.get_map("entities"), &event.to_hex(), &decision_before)?;
    map_insert_bytes(
        &doc.get_map("entities"),
        &carrier_id.to_hex(),
        &carrier_bytes,
    )?;
    doc.commit();
    for populated in [true, false] {
        let bytes =
            export_window_updates_since(&vault, &key, &doc, &VersionVector::default().encode())?;
        let peer = LoroDoc::new();
        import_doc(&peer, &bytes)?;
        assert!(peer.is_shallow());
        assert!(map_get_bytes(&peer.get_map("entities"), &carrier_id.to_hex()).is_none());
        assert_eq!(
            map_get_bytes(&peer.get_map("entities"), &event.to_hex()),
            populated.then(|| decision_before.clone())
        );
        assert!(
            !bytes
                .windows(carrier_bytes.len())
                .any(|window| window == carrier_bytes)
        );
        if populated {
            map_delete(&doc.get_map("entities"), &event.to_hex())?;
            doc.commit();
        }
    }
    assert!(history_free_window_required(&vault, &key)?);
    Ok(())
}

#[test]
fn world_month_recovery_mirrors_only_its_project_and_base_excludes_world_claims() -> Result<()> {
    let (_dir, vault) = test_vault();
    let month = WindowKey::new("2026-03");
    let at = month.start_timestamp().unwrap() + 60;
    let occurred = TimeRange { start: at, end: at };
    let person = EntityId::from_bytes([0x51; 16])?;
    vault.put_entity(
        &person,
        crate::registry::ENTITY_TYPE_PERSON,
        occurred,
        at,
        b"person",
    )?;
    let mut pairs = Vec::new();
    for i in 1..=5 {
        let world = EntityId::from_bytes([i; 16])?;
        let claim = EntityId::from_bytes([i + 20; 16])?;
        vault.put_entity(
            &world,
            crate::registry::ENTITY_TYPE_WORLD,
            occurred,
            at,
            b"world",
        )?;
        let mut body = crate::claim::ClaimBody::new(
            "test.project_fact",
            crate::claim::ClaimSubject::Entity(person),
            Value::from("fact"),
            1.0,
            ClaimApprovalStatus::Proposed,
            crate::claim::ClaimLifecycleStatus::Active,
        )
        .unwrap();
        body.world = Some(world);
        vault.put_claim(&claim, &body, occurred, at)?;
        vault
            .batch()
            .edge(&claim, EdgeKind::About, &person, 1.0)
            .commit()?;
        pairs.push((world, claim));
    }
    let base = crate::sync::schema::create_window_doc("owner", &month);
    reverse_rematerialize(&vault, &base, &month)?;
    for (_, claim) in &pairs {
        assert!(base.get_map("entities").get(&claim.to_hex()).is_none());
        let edge = crate::sync::bridge::format_edge_key(claim, EdgeKind::About, &person);
        assert!(base.get_map("edges").get(&edge).is_none());
    }
    for (world, claim) in &pairs {
        let key = WindowKey::for_month_world(&month, *world);
        let doc = crate::sync::schema::create_window_doc("owner", &key);
        reverse_rematerialize(&vault, &doc, &key)?;
        assert!(doc.get_map("entities").get(&claim.to_hex()).is_some());
        let edge = crate::sync::bridge::format_edge_key(claim, EdgeKind::About, &person);
        assert!(doc.get_map("edges").get(&edge).is_some());
        for (_, other) in &pairs {
            if other != claim {
                assert!(doc.get_map("entities").get(&other.to_hex()).is_none());
            }
        }
    }
    Ok(())
}

#[test]
fn world_window_admission_refuses_other_project_even_hidden_history() -> Result<()> {
    let world_a = EntityId::from_bytes([0x31; 16])?;
    let world_b = EntityId::from_bytes([0x32; 16])?;
    let claim = EntityId::from_bytes([0x33; 16])?;
    let key = WindowKey::for_month_world(&WindowKey::new("2026-03"), world_a);
    let mut body = crate::claim::ClaimBody::new(
        "test.window_boundary",
        crate::claim::ClaimSubject::Entity(world_b),
        Value::from("other world"),
        1.0,
        ClaimApprovalStatus::Proposed,
        crate::claim::ClaimLifecycleStatus::Active,
    )
    .unwrap();
    body.world = Some(world_b);
    let raw = make_entity_blob(
        crate::registry::ENTITY_TYPE_CLAIM,
        key.start_timestamp().unwrap() + 1,
        &crate::claim::encode_claim_body(&body)?,
    );
    let source = create_window_doc("source", &key);
    map_insert_bytes(&source.get_map("entities"), &claim.to_hex(), &raw)?;
    source.commit();
    let target = create_window_doc("target", &key);
    let snapshot = source.export(loro::ExportMode::snapshot()).unwrap();
    assert!(validate_window_update_residence(&target, &snapshot, &key).is_err());
    // The same world still cannot smuggle a March row into February's doc.
    let own_world_key = WindowKey::for_month_world(&WindowKey::new("2026-03"), world_b);
    let same_world = create_window_doc("source", &own_world_key);
    map_insert_bytes(&same_world.get_map("entities"), &claim.to_hex(), &raw)?;
    same_world.commit();
    let same_world_snapshot = same_world.export(loro::ExportMode::snapshot()).unwrap();
    let february = own_world_key.previous_month().unwrap();
    assert!(
        validate_window_update_residence(
            &create_window_doc("target", &february),
            &same_world_snapshot,
            &february,
        )
        .is_err()
    );
    let before = source.oplog_vv();
    map_delete(&source.get_map("entities"), &claim.to_hex())?;
    source.commit();
    let updates = source.export(loro::ExportMode::all_updates()).unwrap();
    assert!(validate_window_update_residence(&target, &updates, &key).is_err());
    assert_ne!(before, source.oplog_vv());
    assert_eq!(target.get_map("entities").len(), 0);
    Ok(())
}

#[test]
fn foreign_and_unknown_world_tombstones_do_not_delete_or_poison_other_projects() -> Result<()> {
    let (_dir, vault) = test_vault();
    let materializer = Arc::new(Materializer::new());
    let world_a = EntityId::from_bytes([0x61; 16])?;
    let world_b = EntityId::from_bytes([0x62; 16])?;
    let existing = EntityId::from_bytes([0x63; 16])?;
    let absent = EntityId::from_bytes([0x64; 16])?;
    let month = WindowKey::new("2026-03");
    let key = WindowKey::for_month_world(&month, world_a);
    let at = month.start_timestamp().unwrap() + 60;
    let occurred = TimeRange { start: at, end: at };
    vault.put_entity(
        &world_b,
        crate::registry::ENTITY_TYPE_WORLD,
        occurred,
        at,
        b"project",
    )?;
    let mut body = crate::claim::ClaimBody::new(
        "test.world_tombstone",
        crate::claim::ClaimSubject::Entity(world_b),
        Value::from("world B"),
        1.0,
        ClaimApprovalStatus::Proposed,
        crate::claim::ClaimLifecycleStatus::Active,
    )
    .unwrap();
    body.world = Some(world_b);
    vault.put_claim(&existing, &body, occurred, at)?;
    let window = LoadedWindow::new("owner", key, &vault, &materializer);
    let tombstone = crate::deletion::TombstoneValueV2 {
        reason: crate::deletion::TombstoneReason::UserHardDelete,
        deleted_at: at,
        request_id: [0x39; 16],
    }
    .encode();
    for id in [existing, absent] {
        map_insert_bytes(&window.doc.get_map("tombstones"), &id.to_hex(), &tombstone)?;
        window.doc.commit();
    }
    assert!(vault.get_raw_unsealed(&existing)?.is_some());
    let txn = vault.store.env.read_txn()?;
    for id in [existing, absent] {
        assert!(
            vault
                .store
                .sync_state
                .get(&txn, &crate::deletion::local_hard_delete_key(&id))?
                .is_none()
        );
        assert!(
            vault
                .store
                .sync_state
                .get(&txn, &format!("m:dw:{}", id.to_hex()))?
                .is_none()
        );
    }
    drop(txn);
    // The unproven A tombstone may stay in A's CRDT, but cannot poison the
    // globally keyed delete marker before a later valid B claim arrives.
    vault.put_claim(&absent, &body, occurred, at)?;
    assert!(vault.get_raw_unsealed(&absent)?.is_some());
    Ok(())
}

#[test]
fn world_window_admission_rejects_cross_project_edges_before_relay() -> Result<()> {
    let (_dir, vault) = test_vault();
    let month = WindowKey::new("2026-03");
    let at = month.start_timestamp().unwrap() + 60;
    let occurred = TimeRange { start: at, end: at };
    let world_a = EntityId::from_bytes([0x41; 16])?;
    let world_b = EntityId::from_bytes([0x42; 16])?;
    let claim_a = EntityId::from_bytes([0x43; 16])?;
    let claim_b = EntityId::from_bytes([0x44; 16])?;
    let person = EntityId::from_bytes([0x45; 16])?;
    vault.put_entity(
        &person,
        crate::registry::ENTITY_TYPE_PERSON,
        occurred,
        at,
        b"person",
    )?;
    for (world, claim) in [(world_a, claim_a), (world_b, claim_b)] {
        vault.put_entity(
            &world,
            crate::registry::ENTITY_TYPE_WORLD,
            occurred,
            at,
            b"project",
        )?;
        let mut body = crate::claim::ClaimBody::new(
            "test.edge_residence",
            crate::claim::ClaimSubject::Entity(person),
            Value::from("fact"),
            1.0,
            ClaimApprovalStatus::Proposed,
            crate::claim::ClaimLifecycleStatus::Active,
        )
        .unwrap();
        body.world = Some(world);
        vault.put_claim(&claim, &body, occurred, at)?;
    }
    let key = WindowKey::for_month_world(&month, world_a);
    let source = create_window_doc("source", &key);
    let good = crate::sync::bridge::format_edge_key(&claim_a, EdgeKind::About, &person);
    let foreign = crate::sync::bridge::format_edge_key(&claim_a, EdgeKind::About, &claim_b);
    map_insert_bytes(&source.get_map("edges"), &good, b"value")?;
    source.commit();
    let target = create_window_doc("target", &key);
    assert!(
        validate_window_update_residence_with_vault(
            &vault,
            &target,
            &source.export(loro::ExportMode::all_updates()).unwrap(),
            &key
        )
        .is_ok()
    );
    map_insert_bytes(&source.get_map("edges"), &foreign, b"value")?;
    source.commit();
    map_delete(&source.get_map("edges"), &foreign)?;
    source.commit();
    assert!(
        validate_window_update_residence_with_vault(
            &vault,
            &target,
            &source.export(loro::ExportMode::all_updates()).unwrap(),
            &key
        )
        .is_err()
    );
    assert!(target.get_map("edges").get(&foreign).is_none());
    Ok(())
}

#[test]
fn world_export_does_not_pick_up_a_shared_note_from_the_same_month() -> Result<()> {
    let (_dir, source) = test_vault();
    let owner = source.ensure_embedded_owner_actor().unwrap();
    let actor = crate::write_envelope::WriteActor::new(owner, EdgeActorClass::Human);
    let note = source
        .create_note("research", "shared note", actor)
        .unwrap();
    let raw = source.get_raw_unsealed(&note)?.unwrap();
    let at = crate::batch::EntityMetadataHeader::parse(&raw)
        .unwrap()
        .learned_at;
    let world = EntityId::now();
    let claim = EntityId::now();
    let occurred = TimeRange { start: at, end: at };
    source.put_entity(
        &world,
        crate::registry::ENTITY_TYPE_WORLD,
        occurred,
        at,
        b"world",
    )?;
    let mut body = crate::claim::ClaimBody::new(
        "test.note_partition",
        crate::claim::ClaimSubject::Entity(world),
        Value::from("world fact"),
        1.0,
        ClaimApprovalStatus::Proposed,
        crate::claim::ClaimLifecycleStatus::Active,
    )
    .unwrap();
    body.world = Some(world);
    source.put_claim(&claim, &body, occurred, at)?;
    let world_key = WindowKey::for_world(at, world);
    let world_doc = create_window_doc("owner", &world_key);
    reverse_rematerialize(&source, &world_doc, &world_key)?;
    let exported = export_window_updates_since(
        &source,
        &world_key,
        &world_doc,
        &VersionVector::default().encode(),
    )?;
    let (_peer_dir, peer) = test_vault();
    // The shared base endpoint is already loaded before its world edge.
    peer.put_entity(
        &world,
        crate::registry::ENTITY_TYPE_WORLD,
        occurred,
        at,
        b"world",
    )?;
    let received = create_window_doc("peer", &world_key);
    validate_window_update_residence_with_vault(&peer, &received, &exported, &world_key)?;
    import_doc(&received, &exported)?;
    assert!(received.get_map("entities").get(&claim.to_hex()).is_some());
    assert!(received.get_map("entities").get(&note.to_hex()).is_none());

    let base_key = WindowKey::from_timestamp(at);
    let base = create_window_doc("owner", &base_key);
    reverse_rematerialize(&source, &base, &base_key)?;
    export_window_updates_since(
        &source,
        &base_key,
        &base,
        &VersionVector::default().encode(),
    )?;
    assert!(base.get_map("entities").get(&note.to_hex()).is_some());
    Ok(())
}

#[test]
fn late_follow_accepts_deleted_world_claim_edge_history_without_foreign_edges() -> Result<()> {
    for reason in [
        crate::deletion::TombstoneReason::UserDelete,
        crate::deletion::TombstoneReason::UserHardDelete,
    ] {
        let (_dir, source) = test_vault();
        let (_peer_dir, peer) = test_vault();
        let key = WindowKey::for_world(1_771_027_200, EntityId::from_bytes([0x91; 16])?);
        let world = key.world().unwrap();
        let person = EntityId::from_bytes([0x92; 16])?;
        let deleted = EntityId::from_bytes([0x93; 16])?;
        let survivor = EntityId::from_bytes([0x94; 16])?;
        let at = key.start_timestamp().unwrap() + 60;
        let occurred = TimeRange { start: at, end: at };
        for vault in [&source, &peer] {
            vault.put_entity(
                &world,
                crate::registry::ENTITY_TYPE_WORLD,
                occurred,
                at,
                b"world",
            )?;
            vault.put_entity(
                &person,
                crate::registry::ENTITY_TYPE_PERSON,
                occurred,
                at,
                b"person",
            )?;
        }
        for id in [deleted, survivor] {
            let mut body = crate::claim::ClaimBody::new(
                "test.world_history",
                crate::claim::ClaimSubject::Entity(person),
                Value::from("fact"),
                1.0,
                ClaimApprovalStatus::Proposed,
                crate::claim::ClaimLifecycleStatus::Active,
            )
            .unwrap();
            body.world = Some(world);
            source.put_claim(&id, &body, occurred, at)?;
        }
        source
            .batch()
            .edge(&deleted, EdgeKind::About, &person, 1.0)
            .commit()?;
        let doc = create_window_doc("source", &key);
        reverse_rematerialize(&source, &doc, &key)?;
        let value = crate::deletion::TombstoneValueV2 {
            reason,
            deleted_at: at + 1,
            request_id: [7; 16],
        }
        .encode();
        apply_tombstone_to_window_doc(&doc, &deleted, &value)?;
        doc.commit();
        let update =
            export_window_updates_since(&source, &key, &doc, &VersionVector::default().encode())?;
        let received = create_window_doc("peer", &key);
        validate_window_update_residence_with_vault(&peer, &received, &update, &key)?;
        import_doc(&received, &update)?;
        forward_rematerialize(&peer, &received, &Materializer::new(), &key)?;
        assert!(
            received
                .get_map("tombstones")
                .get(&deleted.to_hex())
                .is_some()
        );
        assert_eq!(peer.get(&survivor)?, source.get(&survivor)?);
    }
    Ok(())
}
