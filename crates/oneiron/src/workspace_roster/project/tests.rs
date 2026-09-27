use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::edge::EdgeKind;
use rmpv::Value;

use super::*;

pub(crate) fn sign_project(
    vault: &Vault,
    id: EntityId,
    body: &mut ProjectRecord,
    actor: EntityId,
) -> Result<ProjectWriteProof> {
    let issuer = crate::authority::HostSlipIssuer::from_secret(b"project fixture authority")?;
    let root = vault.ensure_host_root_slip(&issuer)?;
    let mut claims = root.claims;
    claims.slip_id = *blake3::hash(EntityId::now().as_bytes()).as_bytes();
    claims.parent_id = None;
    claims.holder_ref = if body.parents.is_empty()
        && vault.project(id)?.is_some_and(|prior| {
            prior.slice.attenuate(body.slice.clone()).is_err()
                || prior.depth_limit < body.depth_limit
                || prior.depth_remaining < body.depth_remaining
                || prior.leader != body.leader
        }) {
        "host".into()
    } else {
        actor.to_hex()
    };
    let actor_is_host = claims.holder_ref == "host";
    let signer = ed25519_dalek::SigningKey::from_bytes(blake3::hash(actor.as_bytes()).as_bytes());
    if !actor_is_host {
        claims.binding_key = signer.verifying_key().to_bytes();
    }
    let mut slip = vault.mint_capability_slip(&issuer, claims)?;
    if !actor_is_host {
        let project = if vault.project(id)?.is_none() {
            EntityId::from_hex(body.parents.first().ok_or_else(invalid)?)?
        } else {
            id
        };
        let mut scope = crate::federation::Scope::top();
        scope.audience = crate::federation::ScopeAxis::Some(std::collections::BTreeSet::from([
            crate::federation::ScopeId(project),
        ]));
        scope.verbs = crate::federation::ScopeAxis::Some(std::collections::BTreeSet::from([
            "project.write".into(),
        ]));
        slip.attenuate(
            crate::authority::SlipCaveat {
                scope: Some(scope),
                ..Default::default()
            },
            &signer,
        )?;
    }
    let challenge = body.write_challenge(id)?;
    let holder_signature = if actor_is_host {
        issuer.binding_proof(&slip, &challenge)?
    } else {
        use ed25519_dalek::Signer;
        signer
            .sign(&slip.binding_transcript(&challenge)?)
            .to_bytes()
            .to_vec()
    };
    let proof = ProjectWriteProof {
        slip_wire: slip.to_token()?,
        holder_signature,
    };
    body.write_proof = Some(proof.clone());
    Ok(proof)
}

pub(crate) fn put_signed_project(
    vault: &Vault,
    id: EntityId,
    body: &mut ProjectRecord,
    actor: EntityId,
    now: u64,
) -> Result<()> {
    if !body.parents.is_empty()
        && vault.project(id)?.is_none()
        && !body.board.contains(&actor.to_hex())
    {
        body.board.push(actor.to_hex());
    }
    sign_project(vault, id, body, actor)?;
    vault.put_project(id, body, now)
}
fn spawn_signed(
    vault: &Vault,
    parent_id: EntityId,
    child_id: EntityId,
    actor: EntityId,
    leader: EntityId,
    slice: crate::llm::Scope,
    now: u64,
) -> Result<ProjectRecord> {
    let parent = vault.project(parent_id)?.ok_or(Error::EntityNotFound)?;
    let mut body = ProjectRecord::new(
        child_id,
        Some(parent_id),
        EntityId::from_hex(&parent.claims_scope_ref)?,
        leader,
    );
    body.slice = slice.clone();
    body.depth_limit = parent.depth_limit;
    body.depth_remaining = parent.depth_remaining.saturating_sub(1);
    body.board.push(actor.to_hex());
    let proof = sign_project(vault, child_id, &mut body, actor)?;
    vault.spawn_subproject(parent_id, child_id, leader, slice, proof, now)
}

#[test]
fn project_root_child_members_and_home_room_are_atomic() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let root_id = vault.root_project()?;
    let root = vault.project(root_id)?.expect("root");
    let house_room = EntityId::from_hex(&root.home_room)?;
    assert_eq!(
        vault.project_room(house_room)?.unwrap().project_id,
        root_id.to_hex()
    );
    let child_id = EntityId::now();
    let leader = EntityId::from_hex(&root.leader)?;
    let mut child = ProjectRecord::new(child_id, Some(root_id), root_id, leader);
    child.sessions = vec![EntityId::now().to_hex()];
    child.tasks = vec![EntityId::now().to_hex()];
    child.branches = vec![EntityId::now().to_hex()];
    child.skill_forks = vec![EntityId::now().to_hex()];
    child.goal = Some(EntityId::now().to_hex());
    child.budget = Some(EntityId::now().to_hex());
    child.asks = vec![EntityId::now().to_hex()];
    put_signed_project(&vault, child_id, &mut child, leader, 10)?;
    assert_eq!(vault.project(child_id)?, Some(child.clone()));
    let room_id = EntityId::from_hex(&child.home_room)?;
    assert_eq!(
        vault.project_room(room_id)?.unwrap().member_ids,
        child.roster
    );
    child.roster.push(EntityId::now().to_hex());
    put_signed_project(&vault, child_id, &mut child, leader, 11)?;
    assert_eq!(
        vault.project_room(room_id)?.unwrap().member_ids,
        child.roster
    );
    let changes = vault.project_room_changes(child_id)?;
    assert_eq!(changes.len(), 2);
    assert_eq!(changes[1].previous_members, vec![leader.to_hex()]);
    assert_eq!(changes[1].member_ids, child.roster);
    assert!(
        vault
            .put_entity(
                &room_id,
                ENTITY_TYPE_CONVERSATION,
                TimeRange { start: 12, end: 12 },
                12,
                b"{}"
            )
            .is_err()
    );
    let mut forged_room = vault.project_room(room_id)?.unwrap();
    forged_room.member_ids.push(EntityId::now().to_hex());
    assert!(
        vault
            .put_entity(
                &room_id,
                ENTITY_TYPE_CONVERSATION,
                TimeRange { start: 12, end: 12 },
                12,
                &encode(&forged_room)?
            )
            .is_err()
    );
    let mut cycle = root.clone();
    cycle.parents.push(child_id.to_hex());
    assert!(vault.put_project(root_id, &cycle, 12).is_err());
    drop(vault);
    let reopened = Vault::open(dir.path(), crate::VaultConfig::default())?;
    assert_eq!(reopened.root_project()?, root_id);
    assert_eq!(reopened.project(root_id)?, Some(root));
    assert_eq!(reopened.project_room_changes(root_id)?.len(), 1);
    Ok(())
}

#[test]
fn project_binding_does_not_hijack_a_preexisting_crm_slot() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let campaign = EntityId::now();
    {
        let vault = Vault::open_unseeded_for_test(dir.path(), crate::VaultConfig::device())?;
        crate::campaign::register_crm_pack(
            &vault,
            107,
            108,
            crate::registry::TypeByteFamily::Productivity,
        )?;
        vault.put_entity(
            &campaign,
            107,
            TimeRange { start: 1, end: 1 },
            1,
            b"existing campaign",
        )?;
    }
    let vault = Vault::open(dir.path(), crate::VaultConfig::device())?;
    // The static re-key freed 103; occupied CRM slots are not a lower bound.
    assert_eq!(vault.project_type_byte()?, 103);
    assert_eq!(vault.get_entity_type(&campaign)?, Some(107));
    let root = vault.root_project()?;
    assert_eq!(vault.get_entity_type(&root)?, Some(103));
    let project = vault.project(root)?.unwrap();
    assert!(
        vault
            .project_room(EntityId::from_hex(&project.home_room)?)?
            .is_some()
    );
    Ok(())
}

#[test]
fn deleting_project_removes_derived_room_and_member_access() -> Result<()> {
    for door in [0, 1, 2] {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
        let root = vault.root_project()?;
        let owner = EntityId::now();
        vault.put_entity(
            &owner,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"member",
        )?;
        let id = EntityId::now();
        let mut project = ProjectRecord::new(id, Some(root), root, owner);
        let leader = EntityId::from_hex(&vault.project(root)?.unwrap().leader)?;
        put_signed_project(&vault, id, &mut project, leader, 2)?;
        let room = EntityId::from_hex(&project.home_room)?;
        let memory = vault.memory(owner, crate::edge::EdgeActorClass::Human);
        assert!(
            memory
                .rooms_list()
                .unwrap()
                .iter()
                .any(|(id, _)| *id == room)
        );
        if door == 0 {
            vault.batch().delete(&id).commit()?;
        } else if door == 1 {
            vault.delete_entity_with_reason(&id, crate::DeleteReason::UserDelete)?;
        } else {
            assert!(vault.delete_entity_with_options(
                &id,
                crate::deletion::DeleteEntityOptions { purge: true }
            )?);
        }
        if door != 1 {
            assert!(vault.project(id)?.is_none());
        }
        assert!(vault.get(&room)?.is_none());
        assert!(vault.project_room(room)?.is_none());
        assert!(
            !memory
                .rooms_list()
                .unwrap()
                .iter()
                .any(|(id, _)| *id == room)
        );
        assert!(memory.rooms_messages(room).is_err());
        assert!(vault.bind_room_handle(room, "@old", owner).is_err());
        // No stale owner marker treats a reused ordinary conversation as a room.
        // The ordinary conversation still needs its validated MessagePack body.
        vault.put_entity(
            &room,
            ENTITY_TYPE_CONVERSATION,
            TimeRange { start: 3, end: 3 },
            3,
            &crate::conversation::ConversationBody::default().to_bytes()?,
        )?;
    }
    Ok(())
}

#[test]
fn root_and_parent_projects_cannot_be_deleted_at_any_door() -> Result<()> {
    for door in [0, 1, 2] {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
        let root = vault.root_project()?;
        let leader = EntityId::from_hex(&vault.project(root)?.unwrap().leader)?;
        let parent = EntityId::now();
        let mut parent_body = ProjectRecord::new(parent, Some(root), root, leader);
        parent_body.depth_remaining = 9;
        put_signed_project(&vault, parent, &mut parent_body, leader, 1)?;
        let child = EntityId::now();
        let mut child_body = ProjectRecord::new(child, Some(parent), root, leader);
        put_signed_project(&vault, child, &mut child_body, leader, 2)?;
        for id in [root, parent] {
            let before = vault.project(id)?.unwrap();
            let error = match door {
                0 => vault.batch().delete(&id).commit().unwrap_err(),
                1 => vault
                    .delete_entity_with_reason(&id, crate::DeleteReason::UserDelete)
                    .unwrap_err(),
                _ => vault
                    .delete_entity_with_options(
                        &id,
                        crate::deletion::DeleteEntityOptions { purge: true },
                    )
                    .unwrap_err(),
            };
            assert_eq!(error.kind(), crate::error::ErrorKind::InvalidProjectBody);
            assert_eq!(vault.project(id)?, Some(before.clone()));
            assert!(
                vault
                    .project_room(EntityId::from_hex(&before.home_room)?)?
                    .is_some()
            );
        }
        drop(vault);
        let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
        assert_eq!(vault.root_project()?, root);
        assert!(vault.project(root)?.is_some());
    }
    Ok(())
}

#[test]
fn erased_parent_is_invalid_not_a_pending_dependency() -> Result<()> {
    for hard in [false, true] {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
        let root = vault.root_project()?;
        let leader = EntityId::from_hex(&vault.project(root)?.unwrap().leader)?;
        let parent = EntityId::now();
        let mut parent_body = ProjectRecord::new(parent, Some(root), root, leader);
        parent_body.depth_remaining = 9;
        put_signed_project(&vault, parent, &mut parent_body, leader, 1)?;
        if hard {
            vault.delete_entity_with_options(
                &parent,
                crate::deletion::DeleteEntityOptions { purge: true },
            )?;
        } else {
            vault.delete_entity_with_reason(&parent, crate::DeleteReason::UserDelete)?;
        }
        let child = EntityId::now();
        let body = ProjectRecord::new(child, Some(parent), root, leader);
        let error = vault.put_project(child, &body, 2).unwrap_err();
        assert_eq!(error.kind(), crate::error::ErrorKind::InvalidProjectBody);
        assert!(vault.get(&child)?.is_none());
        assert!(vault.get(&EntityId::from_hex(&body.home_room)?)?.is_none());
    }
    Ok(())
}

#[test]
fn project_dag_accepts_two_parents_and_diamond_but_rejects_secondary_cycles() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let root = vault.root_project()?;
    let leader = EntityId::from_hex(&vault.project(root)?.unwrap().leader)?;
    let left = EntityId::now();
    let right = EntityId::now();
    for parent in [left, right] {
        let mut parent_body = ProjectRecord::new(parent, Some(root), root, leader);
        parent_body.depth_remaining = 9;
        put_signed_project(&vault, parent, &mut parent_body, leader, 1)?;
    }
    let shared = EntityId::now();
    let mut child = ProjectRecord::new(shared, Some(left), root, leader);
    child.role = ProjectRole::Corpus;
    child.parents.push(right.to_hex());
    put_signed_project(&vault, shared, &mut child, leader, 2)?;
    assert_eq!(vault.project(shared)?.unwrap().parents, child.parents);
    let linked = vault.targets(&shared, crate::edge::EdgeKind::BelongsTo, None)?;
    assert_eq!(linked.len(), 2);
    assert!(linked.contains(&left) && linked.contains(&right));
    for edge in vault.edges_out(&shared)? {
        assert_eq!(edge.weight, HUB_MEMBERSHIP_WEIGHT);
    }
    let mut cyclic = vault.project(right)?.unwrap();
    cyclic.parents.push(shared.to_hex());
    assert_eq!(
        vault.put_project(right, &cyclic, 3).unwrap_err().kind(),
        crate::error::ErrorKind::InvalidProjectBody
    );
    assert_eq!(vault.project(right)?.unwrap().parents, vec![root.to_hex()]);
    let mut duplicate = child.clone();
    duplicate.parents.push(left.to_hex());
    assert_eq!(
        vault.put_project(shared, &duplicate, 3).unwrap_err().kind(),
        crate::error::ErrorKind::InvalidProjectBody
    );
    for parent in [left, right] {
        assert_eq!(
            vault.batch().delete(&parent).commit().unwrap_err().kind(),
            crate::error::ErrorKind::InvalidProjectBody
        );
    }
    child.parents.retain(|parent| parent != &right.to_hex());
    put_signed_project(&vault, shared, &mut child, leader, 4)?;
    assert_eq!(
        vault.targets(&shared, crate::edge::EdgeKind::BelongsTo, None)?,
        vec![left]
    );
    vault.batch().delete(&right).commit()?;
    Ok(())
}

fn stored_claim(vault: &Vault) -> Result<EntityId> {
    let subject = EntityId::now();
    vault.put_entity(
        &subject,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"person",
    )?;
    let claim = EntityId::now();
    vault.put_claim(
        &claim,
        &ClaimBody::new(
            "test.project_membership",
            ClaimSubject::Entity(subject),
            Value::from("fixture"),
            0.9,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        ),
        TimeRange { start: 2, end: 2 },
        2,
    )?;
    Ok(claim)
}

#[test]
fn generic_edges_cannot_invent_or_retire_project_parents() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let root = vault.root_project()?;
    let leader = EntityId::from_hex(&vault.project(root)?.unwrap().leader)?;
    let child = EntityId::now();
    let mut body = ProjectRecord::new(child, Some(root), root, leader);
    put_signed_project(&vault, child, &mut body, leader, 1)?;
    for result in [
        vault.put_edge(&root, EdgeKind::BelongsTo, &child, 0.05),
        vault
            .batch()
            .edge(&root, EdgeKind::BelongsTo, &child, 0.05)
            .commit(),
        vault
            .batch()
            .delete_edge(&child, EdgeKind::BelongsTo, &root)
            .commit(),
        vault
            .delete_edge(&child, EdgeKind::BelongsTo, &root)
            .map(|_| ()),
        vault.set_edge_weight(&child, EdgeKind::BelongsTo, &root, 1.0),
    ] {
        assert_eq!(
            result.unwrap_err().kind(),
            crate::error::ErrorKind::InvalidProjectBody
        );
    }
    assert!(!vault.edge_exists(&root, EdgeKind::BelongsTo, &child)?);
    assert!(vault.edge_exists(&child, EdgeKind::BelongsTo, &root)?);
    let other = EntityId::now();
    let mut other_body = ProjectRecord::new(other, Some(root), root, leader);
    other_body.depth_remaining = 9;
    put_signed_project(&vault, other, &mut other_body, leader, 2)?;
    let mut new_body = vault.project(child)?.unwrap();
    new_body.parents = vec![other.to_hex()];
    put_signed_project(&vault, child, &mut new_body, leader, 3)?;
    assert!(!vault.edge_exists(&child, EdgeKind::BelongsTo, &root)?);
    assert_eq!(
        vault
            .put_edge(&child, EdgeKind::BelongsTo, &root, 0.05)
            .unwrap_err()
            .kind(),
        crate::error::ErrorKind::InvalidProjectBody
    );
    assert_eq!(
        vault.targets(&child, EdgeKind::BelongsTo, None)?,
        vec![other]
    );
    // Ordinary non-project belongs_to edges remain writable.
    let a = EntityId::now();
    let b = EntityId::now();
    vault.put_edge(&a, EdgeKind::BelongsTo, &b, 0.7)?;
    assert!(vault.delete_edge(&a, EdgeKind::BelongsTo, &b)?);
    Ok(())
}

#[test]
fn generic_and_replay_edges_cannot_link_claims_to_hubs() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let root = vault.root_project()?;
    let claim = stored_claim(&vault)?;
    assert_eq!(
        vault.get_entity_type(&claim)?,
        Some(crate::registry::ENTITY_TYPE_CLAIM)
    );
    for result in [
        vault.put_project_member(claim, root),
        vault.put_edge(&claim, EdgeKind::BelongsTo, &root, 0.05),
        vault
            .batch()
            .edge(&claim, EdgeKind::BelongsTo, &root, 0.05)
            .commit(),
        vault.with_write_txn(|txn| {
            vault
                .batch_in()
                .edge_with_value_fields(
                    &claim,
                    EdgeKind::BelongsTo,
                    &root,
                    crate::batch::EdgeValueFields {
                        weight: 0.05,
                        created_at: 2,
                        vad: crate::affect::Vad::NEUTRAL,
                        provenance: None,
                    },
                )
                .apply(txn)
        }),
    ] {
        assert!(result.is_err());
    }
    assert!(!vault.edge_exists(&claim, EdgeKind::BelongsTo, &root)?);
    assert!(!vault.edge_exists(&root, EdgeKind::BelongsTo, &claim)?);
    assert_eq!(
        vault
            .put_edge(&EntityId::now(), EdgeKind::BelongsTo, &root, 0.05)
            .unwrap_err()
            .kind(),
        crate::error::ErrorKind::InvalidProjectBody
    );
    // A future project ID can receive an ordinary edge while it is untyped,
    // but its project body must not later turn that edge into a CLAIM hub link.
    let future = EntityId::now();
    vault.put_edge(&claim, EdgeKind::BelongsTo, &future, 0.05)?;
    let leader = EntityId::from_hex(&vault.project(root)?.unwrap().leader)?;
    assert_eq!(
        vault
            .put_project(
                future,
                &ProjectRecord::new(future, Some(root), root, leader),
                3,
            )
            .unwrap_err()
            .kind(),
        crate::error::ErrorKind::InvalidProjectBody
    );
    assert!(vault.project(future)?.is_none());
    Ok(())
}

#[test]
fn collection_membership_is_low_weight_and_never_accepts_claims() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let root = vault.root_project()?;
    let asset = EntityId::now();
    vault.put_entity(
        &asset,
        crate::registry::ENTITY_TYPE_ASSET,
        TimeRange { start: 1, end: 1 },
        1,
        b"document",
    )?;
    vault.put_project_member(asset, root)?;
    let edge = vault
        .edges_out(&asset)?
        .into_iter()
        .find(|edge| edge.kind == crate::edge::EdgeKind::BelongsTo && edge.target == root)
        .expect("asset belongs to collection");
    assert_eq!(edge.weight, HUB_MEMBERSHIP_WEIGHT);
    assert_eq!(
        vault.sources(&root, crate::edge::EdgeKind::BelongsTo, None)?,
        vec![asset]
    );
    let claim = stored_claim(&vault)?;
    let err = vault.put_project_member(claim, root).unwrap_err();
    assert!(matches!(err, Error::InvalidConfig(_)));
    let err = vault
        .put_project_member(asset, EntityId::now())
        .unwrap_err();
    assert!(matches!(err, Error::InvalidConfig(_)));
    Ok(())
}

#[test]
fn project_body_updates_preserve_venture_org_edge_and_retire_only_old_project_parent() -> Result<()>
{
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let root = vault.root_project()?;
    let leader = EntityId::from_hex(&vault.project(root)?.unwrap().leader)?;
    let second_parent = EntityId::now();
    let mut second_body = ProjectRecord::new(second_parent, Some(root), root, leader);
    second_body.depth_remaining = 9;
    put_signed_project(&vault, second_parent, &mut second_body, leader, 1)?;
    let venture = EntityId::now();
    let mut original = ProjectRecord::new(venture, Some(root), root, leader);
    put_signed_project(&vault, venture, &mut original, leader, 2)?;
    let org = EntityId::now();
    vault.put_entity(
        &org,
        crate::registry::ENTITY_TYPE_ORG,
        TimeRange { start: 3, end: 3 },
        3,
        b"org",
    )?;
    vault.put_edge(&venture, EdgeKind::BelongsTo, &org, 0.7)?;
    let org_edge = vault
        .edges_out(&venture)?
        .into_iter()
        .find(|edge| edge.kind == EdgeKind::BelongsTo && edge.target == org)
        .expect("venture belongs to org");
    let check = |vault: &Vault, parent: EntityId| -> Result<()> {
        let edges = vault.edges_out(&venture)?;
        let org_after = edges
            .iter()
            .find(|edge| edge.kind == EdgeKind::BelongsTo && edge.target == org)
            .expect("org link survives");
        assert_eq!(org_after.weight, org_edge.weight);
        assert_eq!(org_after.created_at, org_edge.created_at);
        assert_eq!(org_after.vad, org_edge.vad);
        assert_eq!(org_after.provenance, org_edge.provenance);
        assert_eq!(vault.targets(&venture, EdgeKind::BelongsTo, None)?.len(), 2);
        assert!(vault.edge_exists(&venture, EdgeKind::BelongsTo, &parent)?);
        Ok(())
    };
    check(&vault, root)?;
    vault.put_project(venture, &original, 4)?;
    check(&vault, root)?;
    let mut edited = original;
    edited.roster.push(EntityId::now().to_hex());
    put_signed_project(&vault, venture, &mut edited, leader, 5)?;
    check(&vault, root)?;
    // Same shared projection door as replay, with a replicated body op.
    vault
        .batch()
        .put_replicated(
            &venture,
            vault.project_type_byte()?,
            TimeRange { start: 6, end: 6 },
            6,
            &encode(&edited)?,
        )
        .commit()?;
    check(&vault, root)?;
    edited.parents = vec![second_parent.to_hex()];
    put_signed_project(&vault, venture, &mut edited, leader, 7)?;
    check(&vault, second_parent)?;
    assert!(!vault.edge_exists(&venture, EdgeKind::BelongsTo, &root)?);
    Ok(())
}

#[test]
fn updating_project_cannot_recreate_its_soft_deleted_home_room() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let root = vault.root_project()?;
    let leader = EntityId::from_hex(&vault.project(root)?.unwrap().leader)?;
    let id = EntityId::now();
    let mut project = ProjectRecord::new(id, Some(root), root, leader);
    put_signed_project(&vault, id, &mut project, leader, 1)?;
    let room = EntityId::from_hex(&project.home_room)?;
    let changes = vault.project_room_changes(id)?;
    vault.delete_entity_with_reason(&room, crate::DeleteReason::UserDelete)?;
    let mut updated = project.clone();
    updated.roster.push(EntityId::now().to_hex());
    assert!(vault.put_project(id, &updated, 2).is_err());
    assert_eq!(vault.project(id)?, Some(project));
    assert!(vault.project_room(room)?.is_none());
    assert_eq!(vault.project_room_changes(id)?, changes);
    Ok(())
}

#[test]
fn only_leader_spawns_with_narrower_slice_and_decremented_depth() -> Result<()> {
    use crate::llm::{Scope, ScopeResource};
    use std::collections::BTreeSet;

    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let root_id = vault.root_project()?;
    let mut root = vault.project(root_id)?.expect("root project");
    let actor = EntityId::from_hex(&root.leader)?;
    let bucket = ScopeResource::Bucket {
        key: "allowed".into(),
    };
    let denied = ScopeResource::Bucket {
        key: "outside".into(),
    };
    root.slice.readable = BTreeSet::from([bucket.clone()]);
    put_signed_project(&vault, root_id, &mut root, actor, 1)?;

    let narrow = Scope {
        project: Some(EntityId::now()),
        readable: BTreeSet::from([bucket.clone()]),
        ..Scope::default()
    };
    let child_id = EntityId::now();
    let other_leader = EntityId::now();
    let child = spawn_signed(
        &vault,
        root_id,
        child_id,
        actor,
        other_leader,
        narrow.clone(),
        2,
    )?;
    assert_eq!(child.parents, vec![root_id.to_hex()]);
    assert_eq!(child.leader, other_leader.to_hex());
    assert_eq!(child.board, vec![actor.to_hex()]);
    assert_eq!(child.depth_remaining, root.depth_remaining - 1);
    assert_eq!(vault.project(child_id)?, Some(child.clone()));
    assert_eq!(
        vault
            .project_room(EntityId::from_hex(&child.home_room)?)?
            .unwrap()
            .member_ids,
        child.roster
    );

    // An occupied id is not an upsert: a second leader cannot replace this one.
    let error = vault
        .spawn_subproject(
            root_id,
            child_id,
            EntityId::now(),
            narrow.clone(),
            child.write_proof.clone().unwrap(),
            3,
        )
        .unwrap_err();
    assert_eq!(error.kind(), crate::error::ErrorKind::InvalidProjectBody);
    assert_eq!(vault.project(child_id)?, Some(child.clone()));
    let error = spawn_signed(
        &vault,
        root_id,
        EntityId::now(),
        other_leader,
        other_leader,
        narrow.clone(),
        3,
    )
    .unwrap_err();
    assert_eq!(error.kind(), crate::error::ErrorKind::InvalidProjectBody);

    let mut wider = narrow;
    wider.readable.insert(denied);
    let rejected_id = EntityId::now();
    let error = vault
        .spawn_subproject(
            root_id,
            rejected_id,
            other_leader,
            wider.clone(),
            child.write_proof.unwrap(),
            3,
        )
        .unwrap_err();
    assert_eq!(error.kind(), crate::error::ErrorKind::InvalidProjectBody);
    assert!(vault.project(rejected_id)?.is_none());
    assert!(vault.project_room(home_room_id(rejected_id))?.is_none());

    // The common projector also refuses forged direct or batch writes.
    let mut forged = ProjectRecord::new(rejected_id, Some(root_id), root_id, other_leader);
    forged.slice = wider;
    forged.depth_remaining = root.depth_remaining - 1;
    assert_eq!(
        vault
            .put_project(rejected_id, &forged, 4)
            .unwrap_err()
            .kind(),
        crate::error::ErrorKind::InvalidProjectBody
    );
    assert_eq!(
        vault
            .batch()
            .put(
                &rejected_id,
                vault.project_type_byte()?,
                TimeRange { start: 4, end: 4 },
                4,
                &encode(&forged)?
            )
            .commit()
            .unwrap_err()
            .kind(),
        crate::error::ErrorKind::InvalidProjectBody
    );
    assert!(vault.project(rejected_id)?.is_none());

    // Moving a parent inward cannot leave its live child wider.
    root.slice.readable.clear();
    sign_project(&vault, root_id, &mut root, actor)?;
    assert_eq!(
        vault.put_project(root_id, &root, 5).unwrap_err().kind(),
        crate::error::ErrorKind::InvalidProjectBody
    );
    assert_eq!(
        vault.project(root_id)?.unwrap().slice.readable,
        BTreeSet::from([bucket])
    );
    Ok(())
}

#[test]
fn project_depth_is_bounded_by_its_row_and_zero_refuses_spawn() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let root_id = vault.root_project()?;
    let mut root = vault.project(root_id)?.expect("root");
    let actor = EntityId::from_hex(&root.leader)?;
    assert_eq!((root.depth_limit, root.depth_remaining), (10, 10));
    root.depth_limit = 1;
    root.depth_remaining = 1;
    put_signed_project(&vault, root_id, &mut root, actor, 1)?;
    let child_id = EntityId::now();
    let child = spawn_signed(
        &vault,
        root_id,
        child_id,
        actor,
        actor,
        root.slice.clone(),
        2,
    )?;
    assert_eq!(child.depth_remaining, 0);
    let grandchild_id = EntityId::now();
    let error = vault
        .spawn_subproject(
            child_id,
            grandchild_id,
            actor,
            root.slice.clone(),
            child.write_proof.clone().unwrap(),
            3,
        )
        .unwrap_err();
    assert_eq!(error.kind(), crate::error::ErrorKind::InvalidProjectBody);
    assert!(vault.project(grandchild_id)?.is_none());
    let mut too_deep = child;
    too_deep.depth_remaining = 1;
    assert_eq!(
        vault
            .put_project(child_id, &too_deep, 4)
            .unwrap_err()
            .kind(),
        crate::error::ErrorKind::InvalidProjectBody
    );
    too_deep = root;
    too_deep.depth_remaining = 2;
    assert_eq!(
        vault.put_project(root_id, &too_deep, 5).unwrap_err().kind(),
        crate::error::ErrorKind::InvalidProjectBody
    );
    Ok(())
}

#[test]
fn project_slice_entity_refs_cannot_publish_live_off_record_ids() -> Result<()> {
    use crate::llm::ScopeResource;
    use crate::off_record::OffRecordBackendClass;
    use crate::session_overlay::OverlayKeyspace;

    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let root_id = vault.root_project()?;
    let original = vault.project(root_id)?.unwrap();
    let room_id = EntityId::from_hex(&original.home_room)?;
    let original_room = vault.project_room(room_id)?;
    let tainted = EntityId::now();
    let session = vault
        .off_record_session_vault()
        .enter("project-slice-taint", OffRecordBackendClass::Local)?;
    let overlay = session.overlay();
    let segment = overlay.install_txn_segment()?;
    overlay.put(OverlayKeyspace::Entities, tainted.as_bytes(), b"overlay")?;
    segment.commit()?;
    for field in 0..6 {
        let mut body = original.clone();
        match field {
            0 => body.slice.world = Some(tainted),
            1 => body.slice.facet = Some(tainted),
            2 => body.slice.relationship = Some(tainted),
            3 => body.slice.project = Some(tainted),
            4 => {
                body.slice.readable.insert(ScopeResource::DocumentVersion {
                    document: tainted,
                    version: "rev".into(),
                });
            }
            _ => {
                body.slice.writable.insert(ScopeResource::DocumentVersion {
                    document: tainted,
                    version: "rev".into(),
                });
            }
        }
        let bytes = encode(&body)?;
        for door in 0..2 {
            let err = if door == 0 {
                vault.put_project(root_id, &body, 1).unwrap_err()
            } else {
                vault
                    .batch()
                    .put(
                        &root_id,
                        vault.project_type_byte()?,
                        TimeRange { start: 1, end: 1 },
                        1,
                        &bytes,
                    )
                    .commit()
                    .unwrap_err()
            };
            assert_eq!(
                err.kind(),
                crate::error::ErrorKind::OffRecordTaintedBaseWrite,
                "field {field}, door {door}"
            );
            assert_eq!(vault.project(root_id)?, Some(original.clone()));
            assert_eq!(vault.project_room(room_id)?, original_room);
        }
    }
    session.close()?;
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn project_slice_replay_refuses_live_off_record_id() -> Result<()> {
    use crate::off_record::OffRecordBackendClass;
    use crate::session_overlay::OverlayKeyspace;

    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let root_id = vault.root_project()?;
    let original = vault.project(root_id)?.unwrap();
    let room_id = EntityId::from_hex(&original.home_room)?;
    let room = vault.project_room(room_id)?;
    let tainted = EntityId::now();
    let session = vault
        .off_record_session_vault()
        .enter("project-replay-taint", OffRecordBackendClass::Local)?;
    let overlay = session.overlay();
    let segment = overlay.install_txn_segment()?;
    overlay.put(OverlayKeyspace::Entities, tainted.as_bytes(), b"overlay")?;
    segment.commit()?;
    let mut body = original.clone();
    body.slice.project = Some(tainted);
    let err = vault
        .with_write_txn(|txn| {
            vault
                .batch_in()
                .put_replicated(
                    &root_id,
                    vault.project_type_byte()?,
                    TimeRange { start: 2, end: 2 },
                    2,
                    &encode(&body)?,
                )
                .apply(txn)
        })
        .unwrap_err();
    assert_eq!(
        err.kind(),
        crate::error::ErrorKind::OffRecordTaintedBaseWrite
    );
    assert_eq!(vault.project(root_id)?, Some(original));
    assert_eq!(vault.project_room(room_id)?, room);
    session.close()?;
    Ok(())
}

#[test]
fn project_authority_rejects_forged_birth_and_depth_restore_at_every_write_door() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let root_id = vault.root_project()?;
    let root = vault.project(root_id)?.unwrap();
    let leader = EntityId::from_hex(&root.leader)?;
    let child_id = EntityId::now();
    let mut forged = ProjectRecord::new(child_id, Some(root_id), root_id, leader);
    forged.depth_remaining = 9;
    for door in 0..3 {
        let result = match door {
            0 => vault.put_project(child_id, &forged, 1),
            1 => vault
                .batch()
                .put(
                    &child_id,
                    vault.project_type_byte()?,
                    TimeRange { start: 1, end: 1 },
                    1,
                    &encode(&forged)?,
                )
                .commit(),
            _ => {
                #[cfg(feature = "sync")]
                {
                    vault.with_write_txn(|txn| {
                        vault
                            .batch_in()
                            .put_replicated(
                                &child_id,
                                vault.project_type_byte()?,
                                TimeRange { start: 1, end: 1 },
                                1,
                                &encode(&forged)?,
                            )
                            .apply(txn)
                    })
                }
                #[cfg(not(feature = "sync"))]
                {
                    continue;
                }
            }
        };
        assert_eq!(
            result.unwrap_err().kind(),
            crate::error::ErrorKind::InvalidProjectBody
        );
        assert!(vault.project(child_id)?.is_none());
        assert!(vault.project_room(home_room_id(child_id))?.is_none());
    }
    let child = spawn_signed(&vault, root_id, child_id, leader, leader, root.slice, 2)?;
    let room = vault.project_room(home_room_id(child_id))?;
    let mut narrowed = child;
    narrowed.depth_remaining = 0;
    sign_project(&vault, child_id, &mut narrowed, leader)?;
    vault.put_project(child_id, &narrowed, 3)?;
    let mut restored = narrowed.clone();
    restored.depth_remaining = 9;
    for door in 0..3 {
        let result = match door {
            0 => vault.put_project(child_id, &restored, 4),
            1 => vault
                .batch()
                .put(
                    &child_id,
                    vault.project_type_byte()?,
                    TimeRange { start: 4, end: 4 },
                    4,
                    &encode(&restored)?,
                )
                .commit(),
            _ => {
                #[cfg(feature = "sync")]
                {
                    vault.with_write_txn(|txn| {
                        vault
                            .batch_in()
                            .put_replicated(
                                &child_id,
                                vault.project_type_byte()?,
                                TimeRange { start: 4, end: 4 },
                                4,
                                &encode(&restored)?,
                            )
                            .apply(txn)
                    })
                }
                #[cfg(not(feature = "sync"))]
                {
                    continue;
                }
            }
        };
        assert_eq!(
            result.unwrap_err().kind(),
            crate::error::ErrorKind::InvalidProjectBody
        );
        assert_eq!(vault.project(child_id)?, Some(narrowed.clone()));
        assert_eq!(vault.project_room(home_room_id(child_id))?, room);
    }
    // The parent leader sits on the child's board. Its verified holder proof
    // may restore depth, but the same signed body cannot be forged or detached.
    sign_project(&vault, child_id, &mut restored, leader)?;
    vault.put_project(child_id, &restored, 5)?;
    assert_eq!(vault.project(child_id)?.unwrap().depth_remaining, 9);
    let mut detached = restored.clone();
    detached.parents.clear();
    detached.depth_remaining = 10;
    assert_eq!(
        vault
            .put_project(child_id, &detached, 6)
            .unwrap_err()
            .kind(),
        crate::error::ErrorKind::InvalidProjectBody
    );
    assert_eq!(vault.project(child_id)?, Some(restored));
    Ok(())
}

#[test]
fn leader_signed_spawn_verifies_from_a_copied_vault_without_the_issuer() -> Result<()> {
    fn copy_tree(from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()> {
        for entry in std::fs::read_dir(from)? {
            let entry = entry?;
            let target = to.join(entry.file_name());
            if entry.file_type()?.is_dir() {
                std::fs::create_dir_all(&target)?;
                copy_tree(&entry.path(), &target)?;
            } else if entry.file_type()?.is_file() {
                std::fs::copy(entry.path(), target)?;
            }
        }
        Ok(())
    }
    let origin = tempfile::tempdir()?;
    let copy = tempfile::tempdir()?;
    let vault = Vault::open(origin.path(), crate::VaultConfig::default())?;
    let root_id = vault.root_project()?;
    let root = vault.project(root_id)?.unwrap();
    let actor = EntityId::from_hex(&root.leader)?;
    let child_id = EntityId::now();
    let mut child = ProjectRecord::new(child_id, Some(root_id), root_id, actor);
    child.depth_remaining = 9;
    child.board.push(actor.to_hex());
    sign_project(&vault, child_id, &mut child, actor)?;
    drop(vault);
    copy_tree(origin.path(), copy.path())?;
    let replica = Vault::open(copy.path(), crate::VaultConfig::default())?;
    assert_eq!(replica.root_project()?, root_id);
    replica.put_project(child_id, &child, 1)?;
    assert_eq!(replica.project(child_id)?, Some(child.clone()));
    assert!(replica.project_room(home_room_id(child_id))?.is_some());
    let mut tampered = child;
    tampered.depth_remaining = 0;
    let error = replica.put_project(child_id, &tampered, 2).unwrap_err();
    assert_eq!(error.kind(), crate::error::ErrorKind::InvalidProjectBody);
    assert_eq!(replica.project(child_id)?.unwrap().depth_remaining, 9);
    Ok(())
}

#[test]
fn signed_slip_scope_cannot_hide_an_off_record_reference() -> Result<()> {
    use crate::off_record::OffRecordBackendClass;
    use crate::session_overlay::OverlayKeyspace;
    use ed25519_dalek::Signer;
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let id = vault.root_project()?;
    let before = vault.project(id)?.unwrap();
    let room = EntityId::from_hex(&before.home_room)?;
    let prior_room = vault.project_room(room)?;
    let overlay_id = EntityId::now();
    let session = vault
        .off_record_session_vault()
        .enter("project-slip-taint", OffRecordBackendClass::Local)?;
    let overlay = session.overlay();
    let segment = overlay.install_txn_segment()?;
    overlay.put(OverlayKeyspace::Entities, overlay_id.as_bytes(), b"overlay")?;
    segment.commit()?;
    let issuer = crate::authority::HostSlipIssuer::from_secret(b"project slip taint fixture")?;
    let root = vault.ensure_host_root_slip(&issuer)?;
    let actor = EntityId::from_hex(&before.leader)?;
    let signing = ed25519_dalek::SigningKey::from_bytes(blake3::hash(actor.as_bytes()).as_bytes());
    let mut claims = root.claims;
    claims.slip_id = *blake3::hash(EntityId::now().as_bytes()).as_bytes();
    claims.holder_ref = actor.to_hex();
    claims.binding_key = signing.verifying_key().to_bytes();
    claims.scope.worlds = crate::federation::ScopeAxis::Some(std::collections::BTreeSet::from([
        crate::federation::ScopeId(overlay_id),
    ]));
    let slip = vault.mint_capability_slip(&issuer, claims)?;
    let mut changed = before.clone();
    let challenge = changed.write_challenge(id)?;
    changed.write_proof = Some(ProjectWriteProof {
        slip_wire: slip.to_token()?,
        holder_signature: signing
            .sign(&slip.binding_transcript(&challenge)?)
            .to_bytes()
            .to_vec(),
    });
    assert_eq!(
        vault.put_project(id, &changed, 1).unwrap_err().kind(),
        crate::error::ErrorKind::OffRecordTaintedBaseWrite
    );
    assert_eq!(vault.project(id)?, Some(before));
    assert_eq!(vault.project_room(room)?, prior_room);
    session.close()?;
    Ok(())
}
