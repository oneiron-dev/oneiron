//! Signed project history at the doors (PR 3 checks 5, 9 and 11): the live
//! door builds on the folded head, a stale row never moves a project, and a
//! bad stored winner never hides the authority its history still holds.
use super::super::*;
use super::authority::{
    child_body, replay_authority, replay_project, replay_rows, root_leader, sign_with, spawn_signed,
};
use super::history::{
    board_signed_s0, copy_of, head_of, ids, open, seats_of, signed_over, without,
};
use crate::error::ErrorKind;

/// Bug repro: the board's S1 is held and the leader's valid stale sibling
/// S2 lands last as the stored row. Main lets the next revision build on S2
/// and refuses one over S1; the door builds on the folded head instead.
#[cfg(feature = "sync")]
#[test]
fn the_live_door_builds_on_the_effective_head() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = open(&dir)?;
    let x = EntityId::now();
    let project = board_signed_s0(&vault, &[x], &[], |_| {})?;
    // Control: an ordinary chain.
    let s1 = signed_over(&vault, project.id, &project.s0, project.board, |row| {
        row.depth_remaining -= 1;
    })?;
    vault.put_project(project.id, &s1, 3)?;
    // Control: a stale anchor is refused live.
    let s2 = signed_over(&vault, project.id, &project.s0, project.leader, without(x))?;
    assert_eq!(
        vault.put_project(project.id, &s2, 4).unwrap_err().kind(),
        ErrorKind::InvalidProjectBody
    );
    replay_project(&vault, project.id, &s2, 5)?;
    let over_s2 = signed_over(&vault, project.id, &s2, project.board, |row| {
        row.depth_remaining -= 2;
    })?;
    assert!(
        vault.put_project(project.id, &over_s2, 6).is_err(),
        "a revision over the stale stored row landed"
    );
    let over_s1 = signed_over(&vault, project.id, &s1, project.board, |row| {
        row.depth_remaining -= 1;
    })?;
    vault.put_project(project.id, &over_s1, 7)?;
    assert_eq!(seats_of(&vault, project.id), ids(&[project.leader, x]));
    Ok(())
}

/// Bug repro: the owner moves P from parent A to parent B and replaces its
/// leader; the old leader's valid stale narrowing lands last, so the stored
/// row names A and the old leader. Every consumer reads B and the new leader.
#[cfg(feature = "sync")]
#[test]
fn a_rollback_never_moves_a_projects_parent_or_leader() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = open(&dir)?;
    let (root_id, root, holder) = root_leader(&vault)?;
    let (a, b) = (EntityId::now(), EntityId::now());
    let a_leader = EntityId::now();
    spawn_signed(&vault, root_id, a, holder, a_leader, root.slice.clone(), 1)?;
    spawn_signed(&vault, root_id, b, holder, EntityId::now(), root.slice, 2)?;
    let (p, old, new) = (EntityId::now(), EntityId::now(), EntityId::now());
    let s0 = spawn_signed(
        &vault,
        a,
        p,
        a_leader,
        old,
        vault.project(a)?.ok_or(Error::EntityNotFound)?.slice,
        3,
    )?;
    let mut s1 = s0.clone();
    s1.parents = vec![b.to_hex()];
    s1.leader = new.to_hex();
    s1.roster = vec![new.to_hex()];
    sign_with(&vault, p, &mut s1, None, Some(s0.anchor()), None)?;
    vault.put_project(p, &s1, 4)?;
    let stale = signed_over(&vault, p, &s0, old, |row| row.depth_remaining -= 1)?;
    replay_project(&vault, p, &stale, 5)?;
    assert_eq!(
        vault.project(p)?.ok_or(Error::EntityNotFound)?.leader,
        old.to_hex()
    );

    let txn = vault.store.env.read_txn()?;
    // Dispatch admits P only under a parent its view names.
    let (_, spawn) = vault.project_for_spawn_in_txn(&txn, Some(p))?;
    assert_eq!(spawn.parents, vec![b.to_hex()]);
    // Leader chat, the widen ask and the goal interview act for the new
    // leader, and the widen ask climbs the new lineage.
    let lineage = super::super::leader_chat::lineage(&vault, &txn, p)?;
    assert!(lineage.contains(&b) && !lineage.contains(&a), "{lineage:?}");
    assert_eq!(
        super::super::leader_chat::project_in(&vault, &txn, p)?.leader,
        new.to_hex()
    );
    let (_, view) = vault
        .effective_project_in_txn(&txn, p)?
        .ok_or(Error::EntityNotFound)?;
    assert_eq!(view.leader, new.to_hex());
    drop(txn);
    assert_eq!(seats_of(&vault, p), ids(&[new]));
    assert!(
        vault.batch().delete(&b).commit().is_err(),
        "a parent with a live child was deleted"
    );
    vault.batch().delete(&a).commit()?;
    Ok(())
}

/// Bug repro: an outsider's row and then a row whose signature does not
/// verify are replayed as the stored winner. Main hides the whole project;
/// the history keeps its last valid authority and lists each bad revision.
#[cfg(feature = "sync")]
#[test]
fn a_bad_raw_winner_never_hides_a_projects_valid_signed_authority() -> Result<()> {
    let origin = tempfile::tempdir()?;
    let x = EntityId::now();
    // The root is an unsigned owner-door project.
    let (project, unsigned, owner_row) = {
        let vault = open(&origin)?;
        let project = board_signed_s0(&vault, &[x], &[], |_| {})?;
        let (root_id, root, _) = root_leader(&vault)?;
        (project, root_id, root)
    };
    let (_copy_dir, copy) = copy_of(&origin)?;
    let (_late_dir, late) = copy_of(&origin)?;
    let vault = open(&origin)?;
    let s1 = signed_over(&vault, project.id, &project.s0, project.leader, without(x))?;
    vault.put_project(project.id, &s1, 3)?;
    let outsider = EntityId::now();
    let takeover = signed_over(&vault, project.id, &s1, outsider, |row| {
        row.leader = outsider.to_hex();
        row.roster.push(outsider.to_hex());
    })?;
    let mut unverified = s1.clone();
    unverified.roster.push(x.to_hex());
    replay_project(&vault, project.id, &takeover, 4)?;
    replay_project(&vault, project.id, &unverified, 5)?;
    // A board act that drops every parent escapes no bound (Wonder r6 F3).
    let parentless = signed_over(&vault, project.id, &s1, project.board, |row| {
        row.parents.clear();
        row.depth_remaining = row.depth_limit;
    })?;
    replay_project(&vault, project.id, &parentless, 6)?;

    let room = home_room_id(project.id)?;
    assert_eq!(seats_of(&vault, project.id), ids(&[project.leader]));
    vault.bind_room_handle(room, "@leader", project.leader)?;
    assert!(vault.bind_room_handle(room, "@removed", x).is_err());
    assert!(vault.quarantined_projects()?.is_empty());
    let listed: std::collections::BTreeMap<_, _> =
        vault.project_revisions(project.id)?.into_iter().collect();
    assert!(matches!(
        listed.get(&head_of(project.id, &takeover)?),
        Some(ProjectVerdict::Quarantined(_))
    ));
    assert_eq!(
        listed.get(&head_of(project.id, &unverified)?),
        Some(&ProjectVerdict::Quarantined(
            "project revision signature does not verify"
        ))
    );
    assert_eq!(
        listed.get(&head_of(project.id, &parentless)?),
        Some(&ProjectVerdict::Quarantined(
            "a parentless project is not this vault's root"
        ))
    );

    // Controls. A signed birth waiting for its mint is pending, then visible.
    let (root_id, root, holder) = root_leader(&vault)?;
    let child = EntityId::now();
    spawn_signed(
        &vault,
        root_id,
        child,
        holder,
        holder,
        root.slice.clone(),
        6,
    )?;
    let born = vault.project(child)?.ok_or(Error::EntityNotFound)?;
    replay_project(&copy, child, &born, 6)?;
    assert!(matches!(
        copy.project_frontier(child)?.map(|f| f.disposition),
        Some(ProjectDisposition::Pending { .. })
    ));
    replay_authority(&vault, &copy)?;
    assert!(copy.project(child)?.is_some());
    // A history whose every revision is invalid serves no authority.
    let forged = EntityId::now();
    let mut body = child_body(
        &vault,
        root_id,
        forged,
        outsider,
        outsider,
        root.slice.clone(),
    )?;
    sign_with(&vault, forged, &mut body, Some(outsider), None, None)?;
    replay_project(&vault, forged, &body, 7)?;
    assert!(vault.project(forged)?.is_none());
    assert!(seats_of(&vault, forged).is_empty());
    // A companion under a slip this vault never saw minted does not hide an
    // unsigned owner-door project.
    let mut signed = owner_row.clone();
    signed.depth_limit += 1;
    signed.depth_remaining += 1;
    sign_with(
        &late,
        unsigned,
        &mut signed,
        None,
        Some(owner_row.anchor()),
        None,
    )?;
    late.put_project(unsigned, &signed, 9)?;
    replay_rows(
        &late,
        &vault,
        &[super::super::revision::revision_entity_id(head_of(
            unsigned, &signed,
        )?)?],
    )?;
    assert_eq!(vault.project(unsigned)?, Some(owner_row));
    // A host-signed revision wider than its parent stays visible.
    let mut wide = born.clone();
    wide.slice
        .readable
        .insert(crate::llm::ScopeResource::Bucket {
            key: "wider".into(),
        });
    sign_with(&vault, child, &mut wide, None, Some(born.anchor()), None)?;
    vault.put_project(child, &wide, 10)?;
    assert_eq!(vault.project(child)?.map(|row| row.slice), Some(wide.slice));
    Ok(())
}
