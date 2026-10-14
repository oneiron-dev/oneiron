//! Signed project history (PR 3 checks 1, 2 and 4): siblings over one anchor
//! fold by rank on every replica, whatever order they arrive in, and a tie
//! seats only what every contender keeps.
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
