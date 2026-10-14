//! Signed project history across transport and lifecycle (PR 3 checks 3, 8
//! and 10): a window carries every revision of the project rows it holds,
//! a squatter or a poisoned carrier never hides one, and delete or restore
//! never drops one.
use super::super::revision::{
    PROJECT_REVISION_BACKFILL, project_revision_type, revision_entity_id,
};
use super::super::*;
use super::authority::{
    child_body, replay_authority, replay_project, root_leader, sign_with, spawn_signed,
};
use super::history::{
    board_signed_s0, copy_of, head_of, ids, open, seats_of, signed_over, without,
};
use crate::sync::bridge::Materializer;
use crate::sync::loro_support::map_insert_bytes;
use crate::sync::schema::create_window_doc;
use crate::sync::types::WindowKey;
use crate::sync::window::{forward_rematerialize, reverse_rematerialize};
use std::sync::Arc;

fn blob(kind: u8, at: u64, body: &[u8]) -> Vec<u8> {
    let mut blob = vec![kind];
    for field in [at, at, at] {
        blob.extend_from_slice(&field.to_be_bytes());
    }
    blob.extend_from_slice(body);
    blob
}

fn materialize(vault: &Arc<Vault>, doc: &loro::LoroDoc, key: &WindowKey) -> Result<()> {
    forward_rematerialize(vault, doc, &Arc::new(Materializer::new()), key).map(drop)
}

fn exported(vault: &Vault, key: &WindowKey) -> Result<loro::LoroDoc> {
    let doc = create_window_doc("project-history", key);
    reverse_rematerialize(vault, &doc, key)?;
    Ok(doc)
}

fn leader_tie_at(vault: &Vault, id: EntityId, anchor: ProjectRevisionHash) -> Result<bool> {
    Ok(matches!(
        vault.project_frontier(id)?.map(|frontier| frontier.disposition),
        Some(ProjectDisposition::Fork { anchor: at, rank: ProjectRank::Leader, .. }) if at == anchor
    ))
}

/// Bug repro: the origin writes S0 and S1 in one month and the sibling S2
/// in the next. A joiner that materializes only the later month seats X on
/// main; the window carries the whole history, so it folds the tie.
#[cfg(feature = "sync")]
#[test]
fn a_late_joiner_folds_the_sibling_it_never_saw_across_months() -> Result<()> {
    let next_month = 40 * 86_400;
    let origin = tempfile::tempdir()?;
    // Every device of the vault shares its authority root.
    open(&origin)?.ensure_host_root_slip(&crate::authority::HostSlipIssuer::from_secret(
        super::authority::FIXTURE_HOST,
    )?)?;
    let (joiner_dir, joiner) = copy_of(&origin)?;
    let (delta_dir, delta) = copy_of(&origin)?;
    let vault = open(&origin)?;
    let (x, y) = (EntityId::now(), EntityId::now());
    let project = board_signed_s0(&vault, &[x, y], &[], |_| {})?;
    let (id, leader) = (project.id, project.leader);
    let s1 = signed_over(&vault, id, &project.s0, leader, without(x))?;
    vault.put_project(id, &s1, 3)?;
    let s2 = signed_over(&vault, id, &project.s0, leader, without(y))?;
    replay_project(&vault, id, &s2, next_month)?;
    let anchor = head_of(id, &project.s0)?;

    let key = WindowKey::from_timestamp(next_month);
    let doc = exported(&vault, &key)?;
    replay_authority(&vault, &joiner)?;
    let joiner = Arc::new(joiner);
    materialize(&joiner, &doc, &key)?;
    replay_authority(&vault, &delta)?;
    for (at, row) in [(2, &project.s0), (3, &s1), (next_month, &s2)] {
        replay_project(&delta, id, row, at)?;
    }
    for replica in [&*joiner, &delta] {
        assert_eq!(seats_of(replica, id), ids(&[leader]));
        assert!(leader_tie_at(replica, id, anchor)?);
    }
    drop((joiner, delta));
    for dir in [&joiner_dir, &delta_dir] {
        let reopened = open(dir)?;
        assert_eq!(seats_of(&reopened, id), ids(&[leader]));
        assert!(leader_tie_at(&reopened, id, anchor)?);
    }
    Ok(())
}

/// Bug repro: the board's removal S1 exists only as a companion; the stored
/// row is the leader's stale sibling. A squatter at S1's derived id, or a
/// malformed carrier of S1's kind in a window, must not hide the removal.
#[cfg(feature = "sync")]
#[test]
fn a_squatter_or_poisoned_carrier_never_hides_the_signed_removal() -> Result<()> {
    let x = EntityId::now();
    let origin = tempfile::tempdir()?;
    let project = board_signed_s0(&open(&origin)?, &[x], &[], |_| {})?;
    let (_replica_dir, replica) = copy_of(&origin)?;
    let (_late_dir, late) = copy_of(&origin)?;
    let vault = open(&origin)?;
    let (id, leader) = (project.id, project.leader);
    let s1 = signed_over(&vault, id, &project.s0, project.board, without(x))?;
    vault.put_project(id, &s1, 3)?;
    let s2 = signed_over(&vault, id, &project.s0, leader, |row| {
        row.depth_remaining -= 1
    })?;
    replay_project(&vault, id, &s2, 4)?;
    assert_eq!(seats_of(&vault, id), ids(&[leader]));
    let s1_row = revision_entity_id(head_of(id, &s1)?)?;
    let key = WindowKey::new("1970-01");

    // A forger squats S1's id on the replica before the window arrives.
    replica.put_entity(
        &s1_row,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 3, end: 3 },
        3,
        b"squatter",
    )?;
    replay_authority(&vault, &replica)?;
    let replica = Arc::new(replica);
    materialize(&replica, &exported(&vault, &key)?, &key)?;
    assert_eq!(seats_of(&replica, id), ids(&[leader]));

    // A malformed carrier of the kind at S1's id is replaced on export.
    let kind = project_revision_type(&vault.store).ok_or_else(invalid)?;
    let poisoned = create_window_doc("poisoned", &key);
    map_insert_bytes(
        &poisoned.get_map("entities"),
        &s1_row.to_hex(),
        &blob(kind, 3, b"not a revision"),
    )?;
    reverse_rematerialize(&vault, &poisoned, &key)?;
    replay_authority(&vault, &late)?;
    let late = Arc::new(late);
    materialize(&late, &poisoned, &key)?;
    assert_eq!(seats_of(&late, id), ids(&[leader]));

    // An ordinary put, a generic delete and a peer tombstone all leave it.
    assert!(
        vault
            .put_entity(
                &s1_row,
                crate::registry::ENTITY_TYPE_PERSON,
                TimeRange { start: 5, end: 5 },
                5,
                b"squatter",
            )
            .is_err()
    );
    assert!(vault.batch().delete(&s1_row).commit().is_err());
    let tombstoned = create_window_doc("tombstone", &key);
    let value = crate::deletion::TombstoneValueV2 {
        reason: crate::deletion::TombstoneReason::UserDelete,
        deleted_at: 6,
        request_id: [6; 16],
    };
    map_insert_bytes(
        &tombstoned.get_map("tombstones"),
        &s1_row.to_hex(),
        &value.encode(),
    )?;
    materialize(&late, &tombstoned, &key)?;
    for holder in [&vault, &*late] {
        assert!(holder.get(&s1_row)?.is_some());
        assert_eq!(seats_of(holder, id), ids(&[leader]));
    }
    Ok(())
}

/// Bug repro: a board removal that a vault from before this PR stored with
/// no companion is lost on main when the project is deleted, and a replayed
/// older row or a restore brings the removed member back. Here history
/// outlives the row, and a second birth at the id waits for the owner.
#[cfg(feature = "sync")]
#[test]
fn a_deleted_or_restored_project_keeps_its_history() -> Result<()> {
    let x = EntityId::now();
    let dir = tempfile::tempdir()?;
    let vault = open(&dir)?;
    let project = board_signed_s0(&vault, &[x], &[], |_| {})?;
    let (id, leader) = (project.id, project.leader);
    let images = tempfile::tempdir()?;
    let image = images.path().join("before-removal");
    vault.snapshot_checkpoint(&image, 5)?;
    let s1 = signed_over(&vault, id, &project.s0, project.board, without(x))?;
    // A vault from before this PR: S1 stored with no companion, and no
    // backfill run yet.
    let kind = vault.project_type_byte()?;
    vault.with_write_txn(|txn| {
        vault
            .store
            .entities
            .put(txn, id.as_bytes(), &blob(kind, 6, &encode(&s1)?))?;
        PROJECT_REVISION_BACKFILL.delete(&vault.store, txn, &())?;
        Ok(())
    })?;
    drop(vault);
    let vault = open(&dir)?;
    vault.batch().delete(&id).commit()?;

    // The live doors refuse a new birth at the id.
    let (root_id, root, holder) = root_leader(&vault)?;
    assert!(
        vault
            .put_project(
                id,
                &ProjectRecord::new(id, Some(root_id), root_id, holder)?,
                7
            )
            .is_err()
    );
    assert!(spawn_signed(&vault, root_id, id, holder, holder, root.slice.clone(), 7).is_err());
    // A replayed older row does not bring X back.
    replay_project(&vault, id, &project.s0, 8)?;
    assert_eq!(seats_of(&vault, id), ids(&[leader]));
    // Nor does a restore of a checkpoint from before the removal, under the
    // current authority.
    let restored_dir = tempfile::tempdir()?;
    if let Ok((restored, _)) = Vault::restore_checkpoint_keeping_authority(
        &image,
        &restored_dir.path().join("restored"),
        crate::VaultConfig::default(),
        &vault,
        20,
    ) {
        assert!(!seats_of(&restored, id).contains(&x));
    }

    // A second birth at the id: no leader spawns and no seat is served
    // until the owner seals one.
    let second = EntityId::now();
    let mut birth = child_body(&vault, root_id, id, holder, second, root.slice.clone())?;
    sign_with(&vault, id, &mut birth, Some(holder), None, None)?;
    replay_project(&vault, id, &birth, 9)?;
    assert!(matches!(
        vault
            .project_frontier(id)?
            .map(|frontier| frontier.disposition),
        Some(ProjectDisposition::ConflictingBirths { .. })
    ));
    assert!(seats_of(&vault, id).is_empty());
    assert!(
        spawn_signed(
            &vault,
            id,
            EntityId::now(),
            second,
            second,
            root.slice.clone(),
            10
        )
        .is_err()
    );
    let actor = vault.ensure_embedded_owner_actor().expect("owner actor");
    let owner = vault.authenticate_owner(
        actor,
        &actor.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let mut authority = birth.authority_at(ProjectProofVersion::V3);
    authority.roster = Some(BTreeSet::from([second.to_hex()]));
    let issuer = crate::authority::HostSlipIssuer::from_secret(super::authority::FIXTURE_HOST)?;
    let mut claims = vault.ensure_host_root_slip(&issuer)?.claims;
    claims.slip_id = *blake3::hash(EntityId::now().as_bytes()).as_bytes();
    claims.parent_id = None;
    claims.holder_ref = "host".into();
    let slip = vault.mint_capability_slip(&issuer, claims)?;
    vault.seal_project(
        &owner,
        id,
        authority,
        head_of(id, &birth)?,
        slip.to_token()?,
        |challenge| issuer.binding_proof(&slip, challenge),
    )?;
    assert!(matches!(
        vault
            .project_frontier(id)?
            .map(|frontier| frontier.disposition),
        Some(ProjectDisposition::Settled)
    ));
    assert_eq!(seats_of(&vault, id), ids(&[second]));
    Ok(())
}
