//! What may tie projects into one decision, and what a decision may cost
//! (Sol and Astra on #1434, round 14): a frozen member keeps its saved checks,
//! an orphan boundary or a pending malformed companion names no parent, a
//! dissolved cycle takes its owner question with it, and a ring past the
//! decision's work budget serves nothing and asks the owner once; a room's
//! facet is the one its project's folded authority names.
use super::super::fold::reason;
use super::super::history_policy::ProjectHistoryPolicy;
use super::super::read::ProjectVerdict;
use super::super::revision::{ProjectRevision, revisions_of_row};
use super::super::*;
use super::authority::{FIXTURE_HOST, replay_project, root_leader, spawn_signed};
use super::cycle_model::{self as model, Graph, KEPT, Rank, Rev};
use super::history::{copy_of, open, signed_over};
use super::history_cycles::{doors, owner, scaffold, set_bound};
use super::history_resolution::put_companion;
use crate::authority::{CapabilitySlip, HostSlipIssuer};

fn rev(project: usize, prior: Option<usize>, parent: Option<usize>, mask: u8, depth: u8) -> Rev {
    Rev {
        project,
        prior,
        parent,
        mask,
        depth,
        signer: Rank::Board,
        withheld: false,
    }
}

fn slip_id(row: &ProjectRecord) -> Result<[u8; 32]> {
    let proof = row.write_proof.as_ref().ok_or_else(invalid)?;
    Ok(CapabilitySlip::from_token(&proof.slip_wire)?.claims.slip_id)
}

fn lit(vault: &Vault, id: EntityId) -> Result<bool> {
    let frontier = vault.project_frontier(id)?.ok_or(Error::EntityNotFound)?;
    Ok(frontier.effective.is_some())
}

/// Bug repro (Sol r14 F2, Astra r14 F1): C, frozen at C3, rests on C1 under
/// P. P's leader narrows P below C1, and C serves nothing. P's board then
/// puts P under C, which ties the two into one decision: C1 is still checked
/// under P's served view, and C stays refused.
#[cfg(feature = "sync")]
#[test]
fn a_frozen_member_of_a_component_keeps_its_saved_checks() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = open(&dir)?;
    let (root, root_row, holder) = root_leader(&vault)?;
    let (p, c, lead) = (EntityId::now(), EntityId::now(), EntityId::now());
    let p0 = spawn_signed(&vault, root, p, holder, lead, root_row.slice.clone(), 2)?;
    let c0 = spawn_signed(&vault, root, c, holder, lead, root_row.slice.clone(), 3)?;
    let c1 = signed_over(&vault, c, &c0, holder, |row| {
        row.parents = vec![p.to_hex()];
        row.depth_remaining = 3;
    })?;
    vault.put_project(c, &c1, 4)?;
    let c2 = signed_over(&vault, c, &c1, holder, |row| {
        row.parents = vec![root.to_hex()];
    })?;
    vault.put_project(c, &c2, 5)?;
    let c3 = signed_over(&vault, c, &c2, holder, |row| row.depth_remaining = 2)?;
    vault.put_project(c, &c3, 6)?;
    vault.set_project_history_policy(
        &owner(&vault)?,
        ProjectHistoryPolicy {
            max_revisions: 3,
            ..ProjectHistoryPolicy::default()
        },
    )?;
    assert!(matches!(
        vault
            .project_frontier(c)?
            .map(|frontier| frontier.disposition),
        Some(ProjectDisposition::OverBudget { .. })
    ));
    assert!(lit(&vault, c)?);
    let narrow = signed_over(&vault, p, &p0, lead, |row| row.depth_remaining = 2)?;
    replay_project(&vault, p, &narrow, 7)?;
    assert!(!lit(&vault, c)?);
    let under_c = signed_over(&vault, p, &p0, holder, |row| {
        row.parents = vec![c.to_hex()];
        row.depth_remaining = 1;
    })?;
    replay_project(&vault, p, &under_c, 8)?;
    assert!(!lit(&vault, c)?);
    Ok(())
}

/// Bug repro (Astra r14 F2): B, born under A, holds ten board siblings that
/// keep A as parent. A boundary row for A naming B, which no signed state
/// builds on, names no parent: A and B serve what they served before it.
#[cfg(feature = "sync")]
#[test]
fn an_orphan_boundary_names_no_parent() -> Result<()> {
    let graph = Graph {
        projects: 2,
        born_under: vec![None, Some(0)],
        revs: (0..10).map(|_| rev(1, None, Some(0), KEPT, 7)).collect(),
        bound: 64,
    };
    let scaffold = scaffold(&graph)?;
    let all: Vec<usize> = (0..graph.revs.len()).collect();
    let (_dir, vault) = scaffold.replica(&all)?;
    let before = scaffold.public(&vault)?;
    assert!(before.iter().all(Option::is_some), "{before:?}");
    let a = scaffold.ids[0];
    let mut authority =
        (vault.project(a)?.ok_or(Error::EntityNotFound)?).authority_at(ProjectProofVersion::V2);
    authority.parents = vec![scaffold.ids[1].to_hex()];
    put_companion(
        &vault,
        &ProjectRevision::Boundary {
            project: a,
            authority,
        },
        30,
    )?;
    assert_eq!(scaffold.public(&vault)?, before);
    assert_eq!(vault.project_cycle_questions()?, Vec::new());
    Ok(())
}

/// Bug repro (Astra r14 F5): a companion for A over its birth, naming a
/// parent that is no project id, waits for its slip's mint. B then moves
/// under its former child A: the pending row joins no decision, and the
/// move installs as it does without it, in either order.
#[cfg(feature = "sync")]
#[test]
fn a_pending_malformed_companion_never_blocks_a_component() -> Result<()> {
    let graph = Graph {
        projects: 2,
        born_under: vec![None, Some(0)],
        revs: vec![rev(1, None, None, KEPT, 5), rev(0, None, Some(1), KEPT, 4)],
        bound: 64,
    };
    let reference = model::solve(&graph, &[true, true]);
    let scaffold = scaffold(&graph)?;
    let a = scaffold.ids[1];
    // Signed on another copy, so this replica holds no mint for its slip.
    let (_minted_dir, minted) = copy_of(&scaffold.dir)?;
    let birth = minted.project(a)?.ok_or(Error::EntityNotFound)?;
    let junk = signed_over(&minted, a, &birth, scaffold.leaders[1], |row| {
        row.parents = vec!["not-a-project".into()];
    })?;
    let (hash, junk) = revisions_of_row(a, &junk)?.pop().ok_or_else(invalid)?;
    for order in [[0, 1], [1, 0]] {
        let (_dir, vault) = copy_of(&scaffold.dir)?;
        put_companion(&vault, &junk, 5)?;
        scaffold.deliver(&vault, &order)?;
        let wrong = doors(&scaffold, &vault, &graph, &reference, &[true, true])?;
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
        let listed = vault.project_revisions(a)?;
        assert!(
            matches!(
                listed.iter().find(|(at, _)| *at == hash),
                Some((_, ProjectVerdict::Pending(_)))
            ),
            "{listed:?}"
        );
    }
    Ok(())
}

/// Bug repro (Astra r14 F7): A and B name each other past a bound of one
/// world, and the owner holds one question. Revoking B1's slip dissolves the
/// cycle; B's next refresh clears the question for both.
#[cfg(feature = "sync")]
#[test]
fn a_dissolved_cycle_takes_its_question_with_it() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = open(&dir)?;
    set_bound(&vault, 1)?;
    let (root, root_row, holder) = root_leader(&vault)?;
    let (a, b) = (EntityId::now(), EntityId::now());
    let a0 = spawn_signed(&vault, root, a, holder, holder, root_row.slice.clone(), 2)?;
    let b0 = spawn_signed(&vault, root, b, holder, holder, root_row.slice.clone(), 3)?;
    let a1 = signed_over(&vault, a, &a0, holder, |row| {
        row.parents = vec![b.to_hex()];
        row.depth_remaining = 0;
    })?;
    replay_project(&vault, a, &a1, 4)?;
    let b1 = signed_over(&vault, b, &b0, holder, |row| {
        row.parents = vec![a.to_hex()];
        row.depth_remaining = 5;
    })?;
    // A companion: the stored rows hold no cycle.
    let (_, companion) = revisions_of_row(b, &b1)?.pop().ok_or_else(invalid)?;
    put_companion(&vault, &companion, 5)?;
    assert!(!lit(&vault, a)? && !lit(&vault, b)?);
    assert_eq!(vault.project_cycle_questions()?.len(), 1);
    let issuer = HostSlipIssuer::from_secret(FIXTURE_HOST)?;
    vault.revoke_capability_slip(&issuer, slip_id(&b1)?)?;
    vault.with_write_txn(|txn| {
        super::super::refresh_project_frontiers(
            &vault.store,
            txn,
            vault.privacy_posture(),
            &BTreeSet::from([b]),
        )
    })?;
    assert_eq!(vault.project_cycle_questions()?, Vec::new());
    assert!(lit(&vault, a)? && lit(&vault, b)?);
    Ok(())
}

/// The decision's work budget (Engine ruling on r14 F4): a ring of twelve
/// projects, each with one successor over its birth naming the next at depth
/// 0, stays lit under the default budget. Scaled below the work the ring
/// takes, the budget darkens every member, and the owner holds one question
/// naming the ring.
#[cfg(feature = "sync")]
#[test]
fn a_ring_past_its_work_budget_serves_nothing_and_asks_once() -> Result<()> {
    use super::super::joint::WORK_SCALE;
    let n = 12;
    let graph = Graph {
        projects: n,
        born_under: vec![None; n],
        revs: (0..n)
            .map(|at| rev(at, None, Some((at + 1) % n), KEPT, 0))
            .collect(),
        bound: 2,
    };
    let scaffold = scaffold(&graph)?;
    let all: Vec<usize> = (0..n).collect();
    let (_lit_dir, lit) = scaffold.replica(&all)?;
    let served = scaffold.public(&lit)?;
    assert!(served.iter().all(Option::is_some), "{served:?}");
    assert_eq!(lit.project_cycle_questions()?, Vec::new());
    WORK_SCALE.with(|scale| scale.set(Some(1)));
    let (_dark_dir, dark) = scaffold.replica(&all)?;
    let mut dispositions = Vec::new();
    for id in &scaffold.ids {
        let frontier = dark.project_frontier(*id)?.ok_or(Error::EntityNotFound)?;
        dispositions.push((frontier.effective, frontier.disposition));
    }
    let questions = dark.project_cycle_questions()?;
    WORK_SCALE.with(|scale| scale.set(None));
    let bound = ProjectDisposition::Unauthorized {
        reason: reason::CYCLE_BOUND.into(),
    };
    assert_eq!(dispositions, vec![(None, bound); n]);
    let mut members = scaffold.ids.clone();
    members.sort();
    assert_eq!(questions.len(), 1);
    assert_eq!(questions[0].members, members);
    Ok(())
}

/// FACET-READ's room facet (#1432) is the facet of the authority the history
/// folds to: a replayed older row naming another facet never moves a room's
/// facet, and a project dark past the cycle bound names none.
#[cfg(feature = "sync")]
#[test]
fn a_rooms_facet_is_the_one_its_project_serves() -> Result<()> {
    use crate::federation::{ScopeAxis, ScopeId};
    let dir = tempfile::tempdir()?;
    let vault = open(&dir)?;
    set_bound(&vault, 1)?;
    let (root, root_row, holder) = root_leader(&vault)?;
    let (work, home) = (EntityId::now(), EntityId::now());
    for facet in [work, home] {
        let at = TimeRange { start: 1, end: 1 };
        vault.put_entity(
            &facet,
            crate::registry::ENTITY_TYPE_FACET,
            at,
            1,
            b"fixture",
        )?;
    }
    let slice = crate::llm::Scope {
        facet: Some(work),
        ..root_row.slice.clone()
    };
    let facet_of = |row: &ProjectRecord| -> Result<Option<ScopeAxis<ScopeId>>> {
        let txn = vault.store.env.read_txn()?;
        room_facets_in(&vault, &txn, EntityId::from_hex(&row.home_room)?)
    };
    let (a, b) = (EntityId::now(), EntityId::now());
    let a0 = spawn_signed(&vault, root, a, holder, holder, slice.clone(), 2)?;
    let a1 = signed_over(&vault, a, &a0, holder, |row| row.slice.facet = Some(home))?;
    vault.put_project(a, &a1, 3)?;
    let at_home = Some(ScopeAxis::Some([ScopeId(home)].into()));
    assert_eq!(facet_of(&a1)?, at_home);
    replay_project(&vault, a, &a0, 4)?;
    assert_eq!(facet_of(&a1)?, at_home);
    // A and B name each other past a bound of one world: dark, no facet.
    let b0 = spawn_signed(&vault, root, b, holder, holder, slice, 5)?;
    let a2 = signed_over(&vault, a, &a1, holder, |row| {
        row.parents = vec![b.to_hex()];
        row.depth_remaining = 0;
    })?;
    vault.put_project(a, &a2, 6)?;
    let b1 = signed_over(&vault, b, &b0, holder, |row| {
        row.parents = vec![a.to_hex()];
        row.depth_remaining = 5;
    })?;
    let (_, companion) = revisions_of_row(b, &b1)?.pop().ok_or_else(invalid)?;
    put_companion(&vault, &companion, 7)?;
    assert!(!lit(&vault, a)? && !lit(&vault, b)?);
    assert_eq!(facet_of(&a2)?, None);
    assert_eq!(facet_of(&b0)?, None);
    Ok(())
}
