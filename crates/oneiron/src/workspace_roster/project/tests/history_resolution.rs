//! A board fork and its resolution (PR 3 check 6): board holders tie, one
//! of them signs a resolution naming the tie and a fresh successor, and every
//! replica installs it in any arrival order.
use super::super::revision::{ProjectRevision, project_revision_type, revision_entity_id};
use super::super::*;
use super::authority::{FIXTURE_HOST, holder_key, replay_authority, replay_project, replay_rows};
use super::history::{
    board_signed_s0, copy_of, head_of, ids, open, seats_of, signed_over, without,
};
use crate::authority::{CapabilitySlip, HostSlipIssuer, SlipCaveat};
use ed25519_dalek::Signer;

/// A slip for `holder`, narrowed to `project.write` on `project`.
pub(super) fn holder_slip(
    vault: &Vault,
    holder: EntityId,
    project: EntityId,
) -> Result<CapabilitySlip> {
    let issuer = HostSlipIssuer::from_secret(FIXTURE_HOST)?;
    let mut claims = vault.ensure_host_root_slip(&issuer)?.claims;
    claims.slip_id = *blake3::hash(EntityId::now().as_bytes()).as_bytes();
    claims.parent_id = None;
    claims.holder_ref = holder.to_hex();
    claims.binding_key = holder_key(holder).verifying_key().to_bytes();
    let mut slip = vault.mint_capability_slip(&issuer, claims)?;
    let mut scope = crate::federation::Scope::top();
    scope.audience =
        crate::federation::ScopeAxis::Some(BTreeSet::from([crate::federation::ScopeId(project)]));
    scope.verbs = crate::federation::ScopeAxis::Some(BTreeSet::from(["project.write".into()]));
    slip.attenuate(
        SlipCaveat {
            scope: Some(scope),
            ..Default::default()
        },
        &holder_key(holder),
    )?;
    Ok(slip)
}

/// A resolution at `anchor` signed by `holder`.
pub(super) fn resolution(
    vault: &Vault,
    project: EntityId,
    holder: EntityId,
    anchor: ProjectRevisionHash,
    prior: Vec<ProjectRevisionHash>,
    contenders: Vec<ProjectRevisionHash>,
    next: ProjectRevisionHash,
) -> Result<ProjectResolution> {
    let slip = holder_slip(vault, holder, project)?;
    let mut resolution = ProjectResolution {
        anchor,
        prior,
        contenders,
        next,
        slip_wire: slip.to_token()?,
        holder_signature: Vec::new(),
        signed_at: slip.claims.issued_at,
    };
    resolution.holder_signature = holder_key(holder)
        .sign(&slip.binding_transcript(&resolution.challenge(project)?)?)
        .to_bytes()
        .to_vec();
    Ok(resolution)
}

/// Delivers a revision companion as transport would.
pub(super) fn put_companion(vault: &Vault, revision: &ProjectRevision, at: u64) -> Result<()> {
    let kind = project_revision_type(&vault.store).ok_or_else(invalid)?;
    vault.with_write_txn(|txn| {
        vault
            .batch_in()
            .put_replicated(
                &revision_entity_id(revision.hash()?)?,
                kind,
                TimeRange { start: at, end: at },
                at,
                &revision.canonical_bytes()?,
            )
            .apply(txn)
    })
}

pub(super) fn envelope(project: EntityId, resolution: ProjectResolution) -> ProjectRevision {
    ProjectRevision::Resolution {
        project,
        resolution,
    }
}

pub(super) fn sorted(mut hashes: Vec<ProjectRevisionHash>) -> Vec<ProjectRevisionHash> {
    hashes.sort();
    hashes
}

fn leader_of(vault: &Vault, id: EntityId) -> Result<Option<String>> {
    Ok(vault
        .project_frontier(id)?
        .and_then(|frontier| frontier.effective)
        .map(|view| view.leader))
}

fn verdict_in(
    vault: &Vault,
    id: EntityId,
    hash: ProjectRevisionHash,
) -> Result<Option<ProjectVerdict>> {
    Ok(vault
        .project_revisions(id)?
        .into_iter()
        .find_map(|(held, verdict)| (held == hash).then_some(verdict)))
}

/// Bug repro: board holders B1 and B2 sign competing successors of S0. Main
/// installs whichever row lands last; the fold ties them until a board
/// holder's resolution names the tie and a fresh successor N.
#[cfg(feature = "sync")]
#[test]
fn a_board_resolution_settles_a_board_fork_and_conflicting_resolutions_settle_nothing() -> Result<()>
{
    let (b1, b2, member, z) = (
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
    );
    let origin = tempfile::tempdir()?;
    let project = board_signed_s0(&open(&origin)?, &[member], &[b1, b2], |_| {})?;
    let id = project.id;
    let copies = [copy_of(&origin)?, copy_of(&origin)?, copy_of(&origin)?];
    let (_crossed_dir, crossed) = copy_of(&origin)?;
    let vault = open(&origin)?;
    let s0 = &project.s0;
    let anchor = head_of(id, s0)?;
    let (l1, l2, ln) = (EntityId::now(), EntityId::now(), EntityId::now());
    let c1 = signed_over(&vault, id, s0, b1, |row| {
        row.leader = l1.to_hex();
        row.roster.push(l1.to_hex());
        row.board.push(z.to_hex());
    })?;
    vault.put_project(id, &c1, 3)?;
    let c2 = signed_over(&vault, id, s0, b2, |row| {
        row.leader = l2.to_hex();
        row.roster = vec![l2.to_hex(), member.to_hex()];
    })?;
    replay_project(&vault, id, &c2, 4)?;
    assert_eq!(leader_of(&vault, id)?, Some(project.leader.to_hex()));
    assert_eq!(seats_of(&vault, id), ids(&[member]));
    // Z sits on C1's board only: its revision over C1 installs nothing, but
    // the tie meets C1's branch at its frontier, so its removal holds
    // (Astra #1434 F1).
    let by_z = signed_over(&vault, id, &c1, z, without(member))?;
    replay_project(&vault, id, &by_z, 5)?;
    assert_eq!(leader_of(&vault, id)?, Some(project.leader.to_hex()));
    assert_eq!(seats_of(&vault, id), ids(&[]));
    let tied = |vault: &Vault| {
        vault
            .project_forks()
            .into_iter()
            .filter(|fork| {
                fork.anchor == anchor
                    && fork.outcome
                        == ProjectForkOutcome::Tied {
                            rank: ProjectRank::Board,
                        }
            })
            .count()
    };
    assert_eq!(tied(&vault), 1);

    // B1 settles the tie with a fresh successor N.
    let n = signed_over(&vault, id, s0, b1, |row| {
        row.leader = ln.to_hex();
        row.roster = vec![ln.to_hex(), member.to_hex()];
    })?;
    let (h1, h2, hn) = (head_of(id, &c1)?, head_of(id, &c2)?, head_of(id, &n)?);
    let settle = resolution(&vault, id, b1, anchor, vec![], sorted(vec![h1, h2]), hn)?;
    let env = envelope(id, settle.clone());
    vault.resolve_project_fork(id, n.clone(), settle)?;
    assert_eq!(leader_of(&vault, id)?, Some(ln.to_hex()));
    let resolved = |vault: &Vault| {
        vault
            .project_forks()
            .into_iter()
            .filter(|fork| {
                matches!(fork.outcome, ProjectForkOutcome::Resolved { winner, .. } if winner == hn)
            })
            .count()
    };
    assert_eq!(resolved(&vault), 1);

    // Every arrival order installs N, the envelope first included.
    let row_of = |hash| revision_entity_id(hash);
    let (rc1, rc2, rn, renv) = (row_of(h1)?, row_of(h2)?, row_of(hn)?, row_of(env.hash()?)?);
    for ((_dir, replica), order) in copies.into_iter().zip([
        [renv, rc1, rc2, rn],
        [rn, rc2, renv, rc1],
        [rc2, rn, rc1, renv],
    ]) {
        replay_authority(&vault, &replica)?;
        for (step, row) in order.iter().enumerate() {
            replay_rows(&vault, &replica, &[*row])?;
            if step == 0 && *row == renv {
                assert!(matches!(
                    verdict_in(&replica, id, env.hash()?)?,
                    Some(ProjectVerdict::Pending(_))
                ));
            }
        }
        assert_eq!(leader_of(&replica, id)?, Some(ln.to_hex()), "{order:?}");
        assert_eq!(resolved(&replica), 1);
    }

    // An ordinary revision over N installs live.
    let after = signed_over(&vault, id, &n, ln, |row| row.depth_remaining -= 1)?;
    vault.put_project(id, &after, 6)?;
    assert_eq!(leader_of(&vault, id)?, Some(ln.to_hex()));

    // Refused at admission: unsorted contenders, or fewer than two.
    let mut unsorted = sorted(vec![h1, h2]);
    unsorted.reverse();
    for contenders in [unsorted, vec![h1]] {
        let bad = resolution(&vault, id, b1, anchor, vec![], contenders, hn)?;
        assert!(put_companion(&vault, &envelope(id, bad), 7).is_err());
    }
    // Quarantined: a contender of another anchor, a signer off S0's board.
    let stranger = resolution(
        &vault,
        id,
        b1,
        anchor,
        vec![],
        sorted(vec![h1, head_of(id, &by_z)?]),
        hn,
    )?;
    let off_board = resolution(
        &vault,
        id,
        project.leader,
        anchor,
        vec![],
        sorted(vec![h1, h2]),
        hn,
    )?;
    for bad in [stranger, off_board] {
        let bad = envelope(id, bad);
        put_companion(&vault, &bad, 8)?;
        assert!(matches!(
            verdict_in(&vault, id, bad.hash()?)?,
            Some(ProjectVerdict::Quarantined(_))
        ));
    }
    assert_eq!(leader_of(&vault, id)?, Some(ln.to_hex()));

    // A late board child nobody named reopens the tie.
    let c3 = signed_over(&vault, id, s0, b2, |row| row.depth_remaining -= 1)?;
    replay_project(&vault, id, &c3, 9)?;
    assert!(matches!(
        vault.project_frontier(id)?.map(|frontier| frontier.disposition),
        Some(ProjectDisposition::Fork { rank: ProjectRank::Board, anchor: at, .. }) if at == anchor
    ));

    // Two resolutions that each name the other's successor settle nothing;
    // one whose prior names both settles it.
    replay_authority(&vault, &crossed)?;
    let n1 = signed_over(&vault, id, s0, b1, |row| {
        row.leader = l1.to_hex();
        row.roster.push(l1.to_hex());
    })?;
    let n2 = signed_over(&vault, id, s0, b2, |row| {
        row.leader = l2.to_hex();
        row.roster.push(l2.to_hex());
    })?;
    let (hn1, hn2) = (head_of(id, &n1)?, head_of(id, &n2)?);
    replay_authority(&vault, &crossed)?;
    for (at, row) in (10..).zip([&c1, &c2, &n1, &n2]) {
        replay_project(&crossed, id, row, at)?;
    }
    let r1 = resolution(
        &vault,
        id,
        b1,
        anchor,
        vec![],
        sorted(vec![h1, h2, hn2]),
        hn1,
    )?;
    let r2 = resolution(
        &vault,
        id,
        b2,
        anchor,
        vec![],
        sorted(vec![h1, h2, hn1]),
        hn2,
    )?;
    replay_authority(&vault, &crossed)?;
    let (e1, e2) = (envelope(id, r1), envelope(id, r2));
    put_companion(&crossed, &e1, 20)?;
    put_companion(&crossed, &e2, 21)?;
    assert!(matches!(
        crossed
            .project_frontier(id)?
            .map(|frontier| frontier.disposition),
        Some(ProjectDisposition::Fork {
            rank: ProjectRank::Board,
            ..
        })
    ));
    assert_eq!(seats_of(&crossed, id), ids(&[member]));
    let r3 = resolution(
        &vault,
        id,
        b1,
        anchor,
        sorted(vec![e1.hash()?, e2.hash()?]),
        sorted(vec![h1, h2, hn2]),
        hn1,
    )?;
    replay_authority(&vault, &crossed)?;
    put_companion(&crossed, &envelope(id, r3), 22)?;
    assert_eq!(leader_of(&crossed, id)?, Some(l1.to_hex()));
    Ok(())
}

/// Engine ruling on F1's cycle (Astra #1434): B1 removes B2 from the board
/// and X from the room (C1) while B2, over the same S0, removes B1 and Y
/// (C2). Each deposes the other's signer, so neither is excluded: they tie
/// at board rank, both removals hold, the anchor's leader and board stay,
/// and a board resolution settles it. Two replicas converge in both
/// arrival orders.
#[cfg(feature = "sync")]
#[test]
fn mutual_board_removals_tie_keep_both_narrowings_and_a_resolution_settles_them() -> Result<()> {
    let (b1, b2, x, y, ln) = (
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
    );
    let origin = tempfile::tempdir()?;
    let project = board_signed_s0(&open(&origin)?, &[x, y], &[b1, b2], |_| {})?;
    let id = project.id;
    let copies = [copy_of(&origin)?, copy_of(&origin)?];
    let vault = open(&origin)?;
    let s0 = &project.s0;
    let anchor = head_of(id, s0)?;
    let removes = |holder: EntityId, member: EntityId| {
        move |row: &mut ProjectRecord| {
            row.board.retain(|seat| *seat != holder.to_hex());
            row.roster.retain(|seat| *seat != member.to_hex());
        }
    };
    let c1 = signed_over(&vault, id, s0, b1, removes(b2, x))?;
    vault.put_project(id, &c1, 3)?;
    let c2 = signed_over(&vault, id, s0, b2, removes(b1, y))?;
    replay_project(&vault, id, &c2, 4)?;
    let tied = |vault: &Vault| -> Result<()> {
        assert!(matches!(
            vault.project_frontier(id)?.map(|frontier| frontier.disposition),
            Some(ProjectDisposition::Fork { anchor: at, rank: ProjectRank::Board, .. }) if at == anchor
        ));
        let view = vault
            .project_frontier(id)?
            .and_then(|frontier| frontier.effective)
            .ok_or(Error::EntityNotFound)?;
        assert_eq!(view.leader, project.leader.to_hex());
        assert_eq!(view.board, s0.board);
        assert_eq!(seats_of(vault, id), ids(&[project.leader]));
        Ok(())
    };
    tied(&vault)?;
    let n = signed_over(&vault, id, s0, b1, |row| {
        row.leader = ln.to_hex();
        row.roster = vec![ln.to_hex()];
    })?;
    let (h1, h2, hn) = (head_of(id, &c1)?, head_of(id, &c2)?, head_of(id, &n)?);
    let settle = resolution(&vault, id, b1, anchor, vec![], sorted(vec![h1, h2]), hn)?;
    let env = envelope(id, settle.clone());
    vault.resolve_project_fork(id, n, settle)?;
    assert_eq!(leader_of(&vault, id)?, Some(ln.to_hex()));
    let served = |vault: &Vault| -> Result<Option<ProjectEffective>> {
        Ok(vault
            .project_frontier(id)?
            .and_then(|frontier| frontier.effective))
    };
    let row_of = |hash| revision_entity_id(hash);
    let (rc1, rc2, rn, renv) = (row_of(h1)?, row_of(h2)?, row_of(hn)?, row_of(env.hash()?)?);
    for ((_dir, replica), (tie, settles)) in copies
        .into_iter()
        .zip([([rc1, rc2], [rn, renv]), ([rc2, rc1], [renv, rn])])
    {
        replay_authority(&vault, &replica)?;
        replay_rows(&vault, &replica, &tie)?;
        tied(&replica)?;
        replay_rows(&vault, &replica, &settles)?;
        assert_eq!(leader_of(&replica, id)?, Some(ln.to_hex()));
        assert_eq!(served(&replica)?, served(&vault)?);
    }
    Ok(())
}

/// `row` without `holder` on its board.
pub(super) fn off_board(holder: EntityId) -> impl FnOnce(&mut ProjectRecord) {
    move |row| row.board.retain(|seat| *seat != holder.to_hex())
}

/// The board-rank tie at S0 of checks 15 and 16, with X out.
fn board_tie_keeps_x_out(
    vault: &Vault,
    project: &super::history::Project,
    x: EntityId,
    anchor: ProjectRevisionHash,
) -> Result<()> {
    assert!(matches!(
        vault.project_frontier(project.id)?.map(|frontier| frontier.disposition),
        Some(ProjectDisposition::Fork { anchor: at, rank: ProjectRank::Board, .. }) if at == anchor
    ));
    assert_eq!(leader_of(vault, project.id)?, Some(project.leader.to_hex()));
    assert_eq!(seats_of(vault, project.id), ids(&[project.leader]));
    let room = home_room_id(project.id)?;
    assert!(
        vault.bind_room_handle(room, "@removed", x).is_err(),
        "a member a tied branch removed binds a handle"
    );
    Ok(())
}

/// Bug repro (Astra #1434 r9 F3, Sol r9 F1): B1 removes X (A) and L
/// removes Y (C) over S0; over C, B3 drops B2 from the board (E) while B2
/// drops B1 (D). E excludes D at C, so D's deposition of B1 must not exclude
/// A at S0: the board tie at S0 keeps X out, in both arrival orders.
#[cfg(feature = "sync")]
#[test]
fn an_act_a_nested_fork_excludes_never_excludes_an_older_sibling_in_either_order() -> Result<()> {
    let (b1, b2, b3, x, y) = (
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
    );
    let origin = tempfile::tempdir()?;
    let project = board_signed_s0(&open(&origin)?, &[x, y], &[b1, b2, b3], |_| {})?;
    let (id, s0) = (project.id, &project.s0);
    let copies = [copy_of(&origin)?, copy_of(&origin)?];
    let vault = open(&origin)?;
    let a = signed_over(&vault, id, s0, b1, without(x))?;
    let c = signed_over(&vault, id, s0, project.leader, without(y))?;
    let e = signed_over(&vault, id, &c, b3, off_board(b2))?;
    let d = signed_over(&vault, id, &c, b2, off_board(b1))?;
    let anchor = head_of(id, s0)?;
    for ((_dir, replica), order) in copies.into_iter().zip([[&a, &c, &e, &d], [&d, &e, &c, &a]]) {
        replay_authority(&vault, &replica)?;
        for (at, row) in (10..).zip(order) {
            replay_project(&replica, id, row, at)?;
        }
        board_tie_keeps_x_out(&replica, &project, x, anchor)?;
    }
    Ok(())
}

/// Bug repro (Astra #1434 r9 F2): B1 drops B2 from the board (A) and, over
/// the same S0, removes Y (C); over C, B1 removes X (D1) and signs a sibling
/// that keeps X (D2). B2, deposed by A, resolves C's tie for D2: its
/// resolution settles nothing, so C's tie still meets D1 and X stays out,
/// in both arrival orders.
#[cfg(feature = "sync")]
#[test]
fn a_deposed_board_holders_resolution_settles_nothing_in_either_order() -> Result<()> {
    let (b1, b2, x, y) = (
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
    );
    let origin = tempfile::tempdir()?;
    let project = board_signed_s0(&open(&origin)?, &[x, y], &[b1, b2], |_| {})?;
    let (id, s0) = (project.id, &project.s0);
    let copies = [copy_of(&origin)?, copy_of(&origin)?];
    let vault = open(&origin)?;
    let a = signed_over(&vault, id, s0, b1, off_board(b2))?;
    let c = signed_over(&vault, id, s0, b1, without(y))?;
    let d1 = signed_over(&vault, id, &c, b1, without(x))?;
    let d2 = signed_over(&vault, id, &c, b1, |row| row.depth_remaining -= 1)?;
    let (h1, h2) = (head_of(id, &d1)?, head_of(id, &d2)?);
    let settle = envelope(
        id,
        resolution(
            &vault,
            id,
            b2,
            head_of(id, &c)?,
            vec![],
            sorted(vec![h1, h2]),
            h2,
        )?,
    );
    let anchor = head_of(id, s0)?;
    for ((_dir, replica), settle_first) in copies.into_iter().zip([false, true]) {
        replay_authority(&vault, &replica)?;
        if settle_first {
            put_companion(&replica, &settle, 9)?;
        }
        let order = if settle_first {
            [&d2, &d1, &c, &a]
        } else {
            [&a, &c, &d1, &d2]
        };
        for (at, row) in (10..).zip(order) {
            replay_project(&replica, id, row, at)?;
        }
        if !settle_first {
            put_companion(&replica, &settle, 20)?;
        }
        board_tie_keeps_x_out(&replica, &project, x, anchor)?;
    }
    Ok(())
}

/// Bug repro (Astra #1434 r10 F1): L removes Y (A) over S0; over A, B2
/// drops B1 (D) and lowers the depth (E), and B3 settles A's tie for E.
/// Over S0, B1 removes X (C), B2 drops B4 (U), and B4 drops B3 (T). U
/// excludes T, so T never unsettles B3's resolution: D stays superseded,
/// C's removal holds, and X stays out, in both arrival orders.
#[cfg(feature = "sync")]
#[test]
fn an_excluded_act_never_unsettles_a_resolution_in_either_order() -> Result<()> {
    let (b1, b2, b3, b4, x, y) = (
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
    );
    let origin = tempfile::tempdir()?;
    let project = board_signed_s0(&open(&origin)?, &[x, y], &[b1, b2, b3, b4], |_| {})?;
    let (id, s0) = (project.id, &project.s0);
    let copies = [copy_of(&origin)?, copy_of(&origin)?];
    let vault = open(&origin)?;
    let a = signed_over(&vault, id, s0, project.leader, without(y))?;
    let d = signed_over(&vault, id, &a, b2, off_board(b1))?;
    let e = signed_over(&vault, id, &a, b2, |row| row.depth_remaining -= 1)?;
    let c = signed_over(&vault, id, s0, b1, without(x))?;
    let u = signed_over(&vault, id, s0, b2, off_board(b4))?;
    let t = signed_over(&vault, id, s0, b4, off_board(b3))?;
    let he = head_of(id, &e)?;
    let settle = envelope(
        id,
        resolution(
            &vault,
            id,
            b3,
            head_of(id, &a)?,
            vec![],
            sorted(vec![head_of(id, &d)?, he]),
            he,
        )?,
    );
    let anchor = head_of(id, s0)?;
    for ((_dir, replica), settle_first) in copies.into_iter().zip([false, true]) {
        replay_authority(&vault, &replica)?;
        if settle_first {
            put_companion(&replica, &settle, 9)?;
        }
        let order = if settle_first {
            [&t, &u, &c, &e, &d, &a]
        } else {
            [&a, &d, &e, &c, &u, &t]
        };
        for (at, row) in (10..).zip(order) {
            replay_project(&replica, id, row, at)?;
        }
        if !settle_first {
            put_companion(&replica, &settle, 20)?;
        }
        board_tie_keeps_x_out(&replica, &project, x, anchor)?;
    }
    Ok(())
}
