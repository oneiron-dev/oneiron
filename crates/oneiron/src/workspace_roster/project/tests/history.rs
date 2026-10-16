//! Signed project history (PR 3 checks 1, 2, 4 and 13): sibling branches
//! over one anchor fold by rank on every replica, whatever order they arrive
//! in, and a tie seats only what every branch's frontier keeps.
use super::super::revision::revisions_of_row;
use super::super::*;
use super::authority::{
    child_body, copy_tree, replay_authority, replay_project, root_leader, seated, sign_with,
    spawn_signed,
};
use crate::error::ErrorKind;
use crate::llm::{Scope, ScopeResource};

pub(super) fn open(dir: &tempfile::TempDir) -> Result<Vault> {
    Vault::open(dir.path(), crate::VaultConfig::default())
}

/// Another device of the vault in `dir`, as it stands now. The vault in
/// `dir` must be closed.
pub(super) fn copy_of(dir: &tempfile::TempDir) -> Result<(tempfile::TempDir, Vault)> {
    let copy = tempfile::tempdir()?;
    copy_tree(dir.path(), copy.path())?;
    let vault = open(&copy)?;
    Ok((copy, vault))
}

/// The revision a row's own proof signs.
pub(super) fn head_of(id: EntityId, row: &ProjectRecord) -> Result<ProjectRevisionHash> {
    revisions_of_row(id, row)?
        .last()
        .map(|(hash, _)| *hash)
        .ok_or_else(invalid)
}

/// `base` edited and signed by `signer` over `base`.
pub(super) fn signed_over(
    vault: &Vault,
    id: EntityId,
    base: &ProjectRecord,
    signer: EntityId,
    edit: impl FnOnce(&mut ProjectRecord),
) -> Result<ProjectRecord> {
    let mut next = base.clone();
    edit(&mut next);
    sign_with(
        vault,
        id,
        &mut next,
        Some(signer),
        Some(base.anchor()),
        None,
    )?;
    Ok(next)
}

/// A child project of the root whose board holds the root's leader and
/// `board`: the root's leader spawns it under `leader`, then signs S0 with
/// `members` on its roster and `board` beside it on the board.
pub(super) struct Project {
    pub(super) id: EntityId,
    pub(super) board: EntityId,
    pub(super) leader: EntityId,
    pub(super) s0: ProjectRecord,
}

pub(super) fn board_signed_s0(
    vault: &Vault,
    members: &[EntityId],
    board: &[EntityId],
    edit: impl FnOnce(&mut ProjectRecord),
) -> Result<Project> {
    let (root_id, root, holder) = root_leader(vault)?;
    let id = EntityId::now();
    let leader = EntityId::now();
    let birth = spawn_signed(vault, root_id, id, holder, leader, root.slice, 1)?;
    let s0 = signed_over(vault, id, &birth, holder, |row| {
        row.roster.extend(members.iter().map(EntityId::to_hex));
        row.board.extend(board.iter().map(EntityId::to_hex));
        edit(row);
    })?;
    vault.put_project(id, &s0, 2)?;
    Ok(Project {
        id,
        board: holder,
        leader,
        s0,
    })
}

pub(super) fn without(member: EntityId) -> impl FnOnce(&mut ProjectRecord) {
    move |row| row.roster.retain(|seat| *seat != member.to_hex())
}

/// The seats a project's home room serves; none when it serves no authority.
pub(super) fn seats_of(vault: &Vault, project: EntityId) -> BTreeSet<EntityId> {
    seated(vault, project).unwrap_or_default()
}

pub(super) fn ids(members: &[EntityId]) -> BTreeSet<EntityId> {
    members.iter().copied().collect()
}

fn frontier(vault: &Vault, id: EntityId) -> Result<ProjectFrontier> {
    vault.project_frontier(id)?.ok_or(Error::EntityNotFound)
}

fn effective(vault: &Vault, id: EntityId) -> Result<ProjectEffective> {
    frontier(vault, id)?.effective.ok_or(Error::EntityNotFound)
}

/// Checks the leader-rank tie of check 1 on `vault`.
fn assert_leader_tie(
    vault: &Vault,
    project: &Project,
    removed: [EntityId; 2],
    anchor: ProjectRevisionHash,
) -> Result<()> {
    assert_eq!(seats_of(vault, project.id), ids(&[project.leader]));
    let room = home_room_id(project.id)?;
    for member in removed {
        assert!(
            vault.bind_room_handle(room, "@removed", member).is_err(),
            "a member one sibling removed binds a handle"
        );
    }
    assert!(matches!(
        frontier(vault, project.id)?.disposition,
        ProjectDisposition::Fork { anchor: at, rank: ProjectRank::Leader, .. } if at == anchor
    ));
    let forks = vault.project_forks();
    assert_eq!(forks.len(), 1, "{forks:?}");
    assert_eq!(forks[0].anchor, anchor);
    assert_eq!(
        forks[0].outcome,
        ProjectForkOutcome::Tied {
            rank: ProjectRank::Leader
        }
    );
    assert!(forks[0].on_path);
    Ok(())
}

/// Bug repro (Astra on #1420): the leader removes X (S1) and, over the same
/// state, removes Y (S2). Main seats X again when S2 lands last; the fold
/// seats neither, in both arrival orders and after reopen.
#[cfg(feature = "sync")]
#[test]
fn astra_fixture_a_leader_cannot_reseat_a_removed_member_in_either_order() -> Result<()> {
    let (x, y) = (EntityId::now(), EntityId::now());
    let origin = tempfile::tempdir()?;
    let project = board_signed_s0(&open(&origin)?, &[x, y], &[], |_| {})?;
    let copies = [copy_of(&origin)?, copy_of(&origin)?];
    let vault = open(&origin)?;
    let s1 = signed_over(&vault, project.id, &project.s0, project.leader, without(x))?;
    vault.put_project(project.id, &s1, 3)?;
    let s2 = signed_over(&vault, project.id, &project.s0, project.leader, without(y))?;
    // Control: the live door refuses S2 over the current S1.
    assert_eq!(
        vault.put_project(project.id, &s2, 4).unwrap_err().kind(),
        ErrorKind::InvalidProjectBody
    );
    let anchor = head_of(project.id, &project.s0)?;
    for ((dir, replica), order) in copies.into_iter().zip([[&s1, &s2], [&s2, &s1]]) {
        replay_authority(&vault, &replica)?;
        for (at, row) in (10..).zip(order) {
            replay_project(&replica, project.id, row, at)?;
        }
        assert_leader_tie(&replica, &project, [x, y], anchor)?;
        drop(replica);
        assert_leader_tie(&open(&dir)?, &project, [x, y], anchor)?;
    }
    Ok(())
}

/// Bug repro: the board replaces leader L with L2 (S1) while L, over the
/// same state, keeps itself (S2). Main restores L when S2 lands last; the
/// board's revision outranks the leader's in both orders.
#[cfg(feature = "sync")]
#[test]
fn a_deposed_leader_cannot_sign_itself_back_in_either_order() -> Result<()> {
    let (successor, member) = (EntityId::now(), EntityId::now());
    let origin = tempfile::tempdir()?;
    let project = board_signed_s0(&open(&origin)?, &[member], &[], |_| {})?;
    let copies = [copy_of(&origin)?, copy_of(&origin)?];
    let vault = open(&origin)?;
    let s1 = signed_over(&vault, project.id, &project.s0, project.board, |row| {
        row.leader = successor.to_hex();
        row.roster = vec![successor.to_hex()];
    })?;
    vault.put_project(project.id, &s1, 3)?;
    let s2 = signed_over(
        &vault,
        project.id,
        &project.s0,
        project.leader,
        without(member),
    )?;
    let (anchor, winner) = (head_of(project.id, &project.s0)?, head_of(project.id, &s1)?);
    let slice = project.s0.slice.clone();
    for ((_dir, replica), order) in copies.into_iter().zip([[&s1, &s2], [&s2, &s1]]) {
        replay_authority(&vault, &replica)?;
        for (at, row) in (10..).zip(order) {
            replay_project(&replica, project.id, row, at)?;
        }
        assert_eq!(effective(&replica, project.id)?.leader, successor.to_hex());
        let spawn = |actor| {
            spawn_signed(
                &replica,
                project.id,
                EntityId::now(),
                actor,
                actor,
                slice.clone(),
                20,
            )
        };
        assert!(spawn(project.leader).is_err(), "the deposed leader spawned");
        spawn(successor)?;
        let forks = replica.project_forks();
        assert_eq!(forks.len(), 1, "{forks:?}");
        assert_eq!(forks[0].anchor, anchor);
        assert_eq!(forks[0].outcome, ProjectForkOutcome::Ranked { winner });
    }
    Ok(())
}

/// Bug repro: two leader siblings over S0 install neither. The tie seats
/// what every contender keeps and holds the narrowest slice and depth, so a
/// spawn that only S0's slice admits is refused. Below a suppressed branch a
/// tie is still recorded, off the served path.
#[cfg(feature = "sync")]
#[test]
fn two_leader_siblings_install_neither_meet_their_bounds_and_a_board_sibling_resolves() -> Result<()>
{
    let dir = tempfile::tempdir()?;
    let vault = open(&dir)?;
    let (root_id, mut root, holder) = root_leader(&vault)?;
    let (kept, dropped) = (
        ScopeResource::Bucket { key: "kept".into() },
        ScopeResource::Bucket {
            key: "dropped".into(),
        },
    );
    root.slice.readable = BTreeSet::from([kept.clone(), dropped.clone()]);
    super::authority::put_signed_project(&vault, root_id, &mut root, holder, 1)?;
    let (x, y) = (EntityId::now(), EntityId::now());
    let project = board_signed_s0(&vault, &[x, y], &[], |row| {
        row.slice.readable = BTreeSet::from([kept.clone(), dropped.clone()]);
        row.depth_remaining = 3;
    })?;
    let leader = project.leader;
    let c1 = signed_over(&vault, project.id, &project.s0, leader, |row| {
        row.slice.readable = BTreeSet::from([kept.clone()]);
        row.depth_remaining = 1;
        row.roster.retain(|seat| *seat != x.to_hex());
    })?;
    vault.put_project(project.id, &c1, 3)?;
    let c2 = signed_over(&vault, project.id, &project.s0, leader, without(y))?;
    replay_project(&vault, project.id, &c2, 4)?;

    assert_eq!(seats_of(&vault, project.id), ids(&[leader]));
    let view = effective(&vault, project.id)?;
    assert_eq!(view.leader, leader.to_hex());
    assert_eq!(view.depth_remaining, 1);
    // A child that S0's slice admits and C1's does not.
    let child = |slice: BTreeSet<ScopeResource>| -> Result<(EntityId, ProjectRecord)> {
        let id = EntityId::now();
        let scope = Scope {
            readable: slice,
            ..Scope::default()
        };
        let mut body = child_body(&vault, project.id, id, leader, leader, scope)?;
        body.depth_remaining = 0;
        sign_with(&vault, id, &mut body, Some(leader), None, None)?;
        Ok((id, body))
    };
    let (wide_id, wide) = child(BTreeSet::from([dropped]))?;
    let refused = vault.spawn_subproject(
        project.id,
        wide_id,
        leader,
        wide.slice.clone(),
        wide.write_proof.clone().ok_or_else(invalid)?,
        5,
    );
    assert!(
        refused.is_err(),
        "a spawn wider than the tie's slice landed"
    );
    replay_project(&vault, wide_id, &wide, 5)?;
    assert!(vault.project(wide_id)?.is_none());
    let (narrow_id, narrow) = child(BTreeSet::from([kept]))?;
    vault.spawn_subproject(
        project.id,
        narrow_id,
        leader,
        narrow.slice,
        narrow.write_proof.ok_or_else(invalid)?,
        6,
    )?;

    // Leader siblings under C1, then a board sibling over S0 that installs.
    let d1 = signed_over(&vault, project.id, &c1, leader, |row| {
        row.depth_remaining = 0;
    })?;
    let d2 = signed_over(&vault, project.id, &c1, leader, without(y))?;
    replay_project(&vault, project.id, &d1, 7)?;
    replay_project(&vault, project.id, &d2, 7)?;
    let board = signed_over(&vault, project.id, &project.s0, project.board, without(x))?;
    vault.put_project(project.id, &board, 8)?;
    assert_eq!(seats_of(&vault, project.id), ids(&[leader, y]));
    let (anchor, c1_hash) = (head_of(project.id, &project.s0)?, head_of(project.id, &c1)?);
    // Evidence publishes from a fold over a committed read.
    frontier(&vault, project.id)?;
    let forks = vault.project_forks();
    let at_s0: Vec<_> = forks.iter().filter(|fork| fork.anchor == anchor).collect();
    assert!(
        at_s0.iter().any(|fork| fork.on_path
            && fork.outcome
                == ProjectForkOutcome::Ranked {
                    winner: head_of(project.id, &board).unwrap()
                }),
        "{forks:?}"
    );
    assert!(
        forks.iter().any(|fork| fork.anchor == c1_hash
            && !fork.on_path
            && fork.outcome
                == ProjectForkOutcome::Tied {
                    rank: ProjectRank::Leader
                }),
        "{forks:?}"
    );
    Ok(())
}

/// Checks the board act of check 13 standing on `vault`.
fn assert_board_act_stands(
    vault: &Vault,
    project: &Project,
    successor: EntityId,
    removed: EntityId,
    head: ProjectRevisionHash,
) -> Result<()> {
    let served = frontier(vault, project.id)?;
    assert_eq!(served.disposition, ProjectDisposition::Settled);
    assert_eq!(served.witness.map(|witness| witness.head), Some(head));
    assert_eq!(effective(vault, project.id)?.leader, successor.to_hex());
    assert!(!seats_of(vault, project.id).contains(&removed));
    let room = home_room_id(project.id)?;
    assert!(
        vault.bind_room_handle(room, "@removed", removed).is_err(),
        "a member the board removed binds a handle"
    );
    let spawn = |actor| {
        spawn_signed(
            vault,
            project.id,
            EntityId::now(),
            actor,
            actor,
            project.s0.slice.clone(),
            30,
        )
    };
    assert!(spawn(project.leader).is_err(), "the deposed leader spawned");
    spawn(successor)?;
    Ok(())
}

/// Bug repro (Astra #1434 F1): over board-signed S0 the leader L narrows
/// (S1), the board deposes L and removes X over S1 (S2), and L signs a stale
/// sibling S3 over S0. The fork at S0 compared only S1 and S3, both leader
/// rank, so S2 never took part: L led again and X sat again. S1's branch
/// holds a board act, so it outranks S3's, and L, deposed there, takes no
/// authority from S3, in both arrival orders and after reopen.
#[cfg(feature = "sync")]
#[test]
fn a_stale_leader_sibling_never_undoes_a_later_board_act_in_either_order() -> Result<()> {
    let (x, y, z, successor) = (
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
    );
    let origin = tempfile::tempdir()?;
    let project = board_signed_s0(&open(&origin)?, &[x, y, z], &[], |_| {})?;
    let copies = [copy_of(&origin)?, copy_of(&origin)?];
    let vault = open(&origin)?;
    let id = project.id;
    let s1 = signed_over(&vault, id, &project.s0, project.leader, without(y))?;
    vault.put_project(id, &s1, 3)?;
    let s2 = signed_over(&vault, id, &s1, project.board, |row| {
        row.leader = successor.to_hex();
        row.roster = vec![successor.to_hex(), z.to_hex()];
    })?;
    vault.put_project(id, &s2, 4)?;
    let s3 = signed_over(&vault, id, &project.s0, project.leader, without(z))?;
    // Control: the live door refuses S3 over the current S2.
    assert!(vault.put_project(id, &s3, 5).is_err());
    let head = head_of(id, &s2)?;
    for ((dir, replica), order) in copies.into_iter().zip([[&s1, &s2, &s3], [&s3, &s1, &s2]]) {
        replay_authority(&vault, &replica)?;
        for (at, row) in (10..).zip(order) {
            replay_project(&replica, id, row, at)?;
        }
        assert_board_act_stands(&replica, &project, successor, x, head)?;
        drop(replica);
        assert_board_act_stands(&open(&dir)?, &project, successor, x, head)?;
    }
    Ok(())
}

/// Checks the leader tie of check 13's narrowing case on `vault`.
fn assert_frontiers_meet(
    vault: &Vault,
    project: &Project,
    removed: EntityId,
    anchor: ProjectRevisionHash,
    kept: &ScopeResource,
) -> Result<()> {
    assert_eq!(seats_of(vault, project.id), ids(&[project.leader]));
    let room = home_room_id(project.id)?;
    assert!(
        vault.bind_room_handle(room, "@removed", removed).is_err(),
        "a member the leader removed binds a handle"
    );
    let view = effective(vault, project.id)?;
    assert_eq!(view.leader, project.leader.to_hex());
    assert_eq!(view.depth_remaining, 1);
    assert_eq!(
        view.slice.map(|slice| slice.readable),
        Some(BTreeSet::from([kept.clone()]))
    );
    assert!(matches!(
        frontier(vault, project.id)?.disposition,
        ProjectDisposition::Fork { anchor: at, rank: ProjectRank::Leader, .. } if at == anchor
    ));
    Ok(())
}

/// Bug repro (Astra #1434 F1, its narrowing case): the leader narrows S0
/// (S1), then removes X and narrows the slice and depth over S1 (S2), and
/// signs a stale sibling S3 over S0. The honest leader tie still meets, now
/// with each branch at its frontier: X stays out, and the slice and depth
/// stay narrowed, in both arrival orders and after reopen.
#[cfg(feature = "sync")]
#[test]
fn a_leader_tie_meets_each_branch_at_its_frontier_in_either_order() -> Result<()> {
    let (x, y, z) = (EntityId::now(), EntityId::now(), EntityId::now());
    let (kept, dropped) = (
        ScopeResource::Bucket { key: "kept".into() },
        ScopeResource::Bucket {
            key: "dropped".into(),
        },
    );
    let wide = BTreeSet::from([kept.clone(), dropped]);
    let origin = tempfile::tempdir()?;
    let project = {
        let vault = open(&origin)?;
        let (root_id, mut root, holder) = root_leader(&vault)?;
        root.slice.readable = wide.clone();
        super::authority::put_signed_project(&vault, root_id, &mut root, holder, 1)?;
        board_signed_s0(&vault, &[x, y, z], &[], |row| {
            row.slice.readable = wide;
            row.depth_remaining = 3;
        })?
    };
    let copies = [copy_of(&origin)?, copy_of(&origin)?];
    let vault = open(&origin)?;
    let (id, leader) = (project.id, project.leader);
    let s1 = signed_over(&vault, id, &project.s0, leader, without(y))?;
    vault.put_project(id, &s1, 3)?;
    let s2 = signed_over(&vault, id, &s1, leader, |row| {
        row.roster.retain(|seat| *seat != x.to_hex());
        row.slice.readable = BTreeSet::from([kept.clone()]);
        row.depth_remaining = 1;
    })?;
    vault.put_project(id, &s2, 4)?;
    let s3 = signed_over(&vault, id, &project.s0, leader, without(z))?;
    let anchor = head_of(id, &project.s0)?;
    for ((dir, replica), order) in copies.into_iter().zip([[&s1, &s2, &s3], [&s3, &s2, &s1]]) {
        replay_authority(&vault, &replica)?;
        for (at, row) in (10..).zip(order) {
            replay_project(&replica, id, row, at)?;
        }
        assert_frontiers_meet(&replica, &project, x, anchor, &kept)?;
        drop(replica);
        assert_frontiers_meet(&open(&dir)?, &project, x, anchor, &kept)?;
    }
    Ok(())
}

/// Bug repro (Astra #1434 r10 F2, Sol r10 F2): S0's leader L also sits on
/// its board. The board holder H replaces L as leader and drops it from the
/// board (D), then restores L to both (E), and L removes X (N). D deposes L
/// once, though from two roles, and it is N's own ancestor: N installs live
/// and on two replicas in both orders, and X stays out.
#[cfg(feature = "sync")]
#[test]
fn a_leader_on_its_own_board_reappointed_after_a_deposition_still_acts() -> Result<()> {
    let x = EntityId::now();
    let origin = tempfile::tempdir()?;
    let project = board_signed_s0(&open(&origin)?, &[x], &[], |row| {
        let leader = row.leader.clone();
        row.board.push(leader);
    })?;
    let (id, holder, leader) = (project.id, project.board, project.leader);
    let copies = [copy_of(&origin)?, copy_of(&origin)?];
    let vault = open(&origin)?;
    let d = signed_over(&vault, id, &project.s0, holder, |row| {
        row.leader = holder.to_hex();
        row.board = vec![holder.to_hex()];
        row.roster = vec![holder.to_hex(), x.to_hex()];
    })?;
    vault.put_project(id, &d, 3)?;
    let e = signed_over(&vault, id, &d, holder, |row| {
        row.leader = leader.to_hex();
        row.board = vec![holder.to_hex(), leader.to_hex()];
        row.roster = vec![leader.to_hex(), holder.to_hex(), x.to_hex()];
    })?;
    vault.put_project(id, &e, 4)?;
    let n = signed_over(&vault, id, &e, leader, without(x))?;
    vault.put_project(id, &n, 5)?;
    let head = head_of(id, &n)?;
    for ((_dir, replica), order) in copies.into_iter().zip([[&d, &e, &n], [&n, &e, &d]]) {
        replay_authority(&vault, &replica)?;
        for (at, row) in (10..).zip(order) {
            replay_project(&replica, id, row, at)?;
        }
        let served = frontier(&replica, id)?;
        assert_eq!(served.disposition, ProjectDisposition::Settled);
        assert_eq!(served.witness.map(|witness| witness.head), Some(head));
        assert_eq!(effective(&replica, id)?.leader, leader.to_hex());
        assert!(!seats_of(&replica, id).contains(&x));
    }
    Ok(())
}

/// Bug repro (Sol #1434 r10 F3): the board replaces L (S1) while L removes
/// Y (S2) and, over S2, removes X (D1) or lowers the depth (D2). S1 excludes
/// S2 with its subtree, yet the fork at S2 is still recorded, off the served
/// path, in both orders.
#[cfg(feature = "sync")]
#[test]
fn a_fork_under_an_excluded_act_is_still_recorded_in_either_order() -> Result<()> {
    let (successor, x, y) = (EntityId::now(), EntityId::now(), EntityId::now());
    let origin = tempfile::tempdir()?;
    let project = board_signed_s0(&open(&origin)?, &[x, y], &[], |_| {})?;
    let id = project.id;
    let copies = [copy_of(&origin)?, copy_of(&origin)?];
    let vault = open(&origin)?;
    let s1 = signed_over(&vault, id, &project.s0, project.board, |row| {
        row.leader = successor.to_hex();
        row.roster = vec![successor.to_hex()];
    })?;
    let s2 = signed_over(&vault, id, &project.s0, project.leader, without(y))?;
    let d1 = signed_over(&vault, id, &s2, project.leader, without(x))?;
    let d2 = signed_over(&vault, id, &s2, project.leader, |row| {
        row.depth_remaining -= 1;
    })?;
    let (anchor, winner, excluded) = (
        head_of(id, &project.s0)?,
        head_of(id, &s1)?,
        head_of(id, &s2)?,
    );
    let children = BTreeSet::from([head_of(id, &d1)?, head_of(id, &d2)?]);
    for ((_dir, replica), order) in copies
        .into_iter()
        .zip([[&s1, &s2, &d1, &d2], [&d2, &d1, &s2, &s1]])
    {
        replay_authority(&vault, &replica)?;
        for (at, row) in (10..).zip(order) {
            replay_project(&replica, id, row, at)?;
        }
        assert_eq!(effective(&replica, id)?.leader, successor.to_hex());
        let forks = replica.project_forks();
        assert_eq!(forks.len(), 2, "{forks:?}");
        let at = |hash| forks.iter().find(|fork| fork.anchor == hash);
        assert!(at(anchor).is_some_and(
            |fork| fork.on_path && fork.outcome == ProjectForkOutcome::Ranked { winner }
        ));
        assert!(at(excluded).is_some_and(|fork| !fork.on_path
            && fork.children == children
            && fork.outcome == ProjectForkOutcome::Excluded));
    }
    Ok(())
}
