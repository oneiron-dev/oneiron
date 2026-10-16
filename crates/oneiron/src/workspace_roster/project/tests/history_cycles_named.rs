//! The named parent-cycle checks (Astra #1434b and the Engine's rulings on
//! it): Astra's fixture, the second undefined sibling, both settle legs, the
//! conduit's narrow edges, a positive control, the two causal-future shapes,
//! the world bound with its owner question and seal exit, a chain still in
//! the cycle, and a long chain's linear cost.
//! Each shape is a reference graph; the doors must serve the ruled answer
//! (which the reference also gives) in both orders on two replicas.
use super::super::history_policy::PROJECT_FRONTIER;
use super::super::read::ProjectVerdict;
use super::super::*;
use super::authority::{child_body, sign_with};
use super::cycle_model::{self as model, EXTRA, Graph, KEPT, Label, Rank, Rev, View};
use super::history_cycles::{Scaffold, doors, readable, scaffold, set_bound};
use crate::llm::Scope;

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

const fn view(mask: u8, depth: u8, parent: Option<usize>) -> View {
    View {
        mask,
        depth,
        parent,
    }
}

/// Astra's fixture plus `more` (A = 0, B = 1; revisions 0-3 are A0, B0, B1, A1).
fn astra(more: Vec<Rev>) -> Graph {
    let mut graph = model::astra();
    graph.revs[2].withheld = false;
    graph.revs.extend(more);
    graph
}

/// Delivers `graph` in `order` on a replica of `scaffold`, then checks the
/// persisted records before any read, and every door from every entry.
fn holds(
    scaffold: &Scaffold,
    graph: &Graph,
    order: &[usize],
    served: &[Option<View>],
    labels: &[Label],
) -> Result<()> {
    let all = vec![true; graph.revs.len()];
    let reference = model::solve(graph, &all);
    assert_eq!(
        reference.served, served,
        "the reference disagrees with the ruling"
    );
    assert_eq!(
        reference.labels, labels,
        "the reference disagrees with the ruling"
    );
    let (_dir, vault) = scaffold.replica(order)?;
    {
        let txn = vault.store.env.read_txn()?;
        for (project, id) in scaffold.ids.iter().enumerate() {
            let record = PROJECT_FRONTIER.get(&vault.store, &txn, id)?;
            let persisted = scaffold.view(record.as_ref().and_then(|r| r.effective.as_ref()));
            assert_eq!(
                persisted, served[project],
                "the batch-end record of {project}"
            );
        }
    }
    let wrong = doors(scaffold, &vault, graph, &reference, &all)?;
    assert!(wrong.is_empty(), "order {order:?}:\n{}", wrong.join("\n"));
    Ok(())
}

fn both_orders(
    graph: &Graph,
    served: &[Option<View>],
    labels: &[Label],
) -> Result<(Scaffold, tempfile::TempDir, Vault)> {
    let scaffold = scaffold(graph)?;
    let forward: Vec<usize> = (0..graph.revs.len()).collect();
    let backward: Vec<usize> = forward.iter().rev().copied().collect();
    holds(&scaffold, graph, &backward, served, labels)?;
    holds(&scaffold, graph, &forward, served, labels)?;
    let (dir, vault) = scaffold.replica(&forward)?;
    Ok((scaffold, dir, vault))
}

/// L, B's leader, spawns a child of B under `slice` at `depth`.
fn spawn(scaffold: &Scaffold, vault: &Vault, mask: u8, depth: u8) -> Result<ProjectRecord> {
    let (parent, leader, child) = (scaffold.ids[1], scaffold.leaders[1], EntityId::now());
    let scope = Scope {
        readable: readable(mask),
        ..Scope::default()
    };
    let mut body = child_body(vault, parent, child, leader, leader, scope.clone())?;
    body.depth_remaining = depth;
    let proof = sign_with(vault, child, &mut body, Some(leader), None, None)?;
    vault.spawn_subproject(parent, child, leader, scope, proof, 90)
}

use Label::{Invalid, Undefined, Valid};

/// Bug repro (Astra #1434b): B1 (B under A, kept and extra, depth 2) replays
/// after A1 (A under B, kept, depth 0). The read stack decided the cycle,
/// so B served B1 when read first, and L could spawn a child with extra at
/// depth 1. Both now stay undefined in either order and from every door: A
/// keeps A1's narrowing under R, B serves only kept at depth 1.
#[cfg(feature = "sync")]
#[test]
fn a_companion_parent_cycle_serves_one_narrow_answer_at_every_door() -> Result<()> {
    let graph = astra(Vec::new());
    let served = [Some(view(KEPT, 0, None)), Some(view(KEPT, 1, None))];
    let (scaffold, _dir, vault) =
        both_orders(&graph, &served, &[Valid, Valid, Undefined, Undefined])?;
    assert!(
        spawn(&scaffold, &vault, KEPT | EXTRA, 1).is_err(),
        "L spawned extra at depth 1 under B"
    );
    spawn(&scaffold, &vault, KEPT, 0)?;
    Ok(())
}

/// A second board sibling B2 over B0 that also names A: the definition
/// leaves A1, B1 and B2 undefined (the two-fold would have decided A1).
#[cfg(feature = "sync")]
#[test]
fn a_second_undefined_sibling_keeps_the_cycle_undefined() -> Result<()> {
    let graph = astra(vec![rev(1, Some(1), Some(0), KEPT, 0)]);
    let served = [Some(view(KEPT, 0, None)), Some(view(KEPT, 0, None))];
    both_orders(
        &graph,
        &served,
        &[Valid, Valid, Undefined, Undefined, Undefined],
    )?;
    Ok(())
}

/// The settle leg, over B0 and over B1 (the board conduit): B's board
/// re-parents B to R, the cycle clears, A1 installs under it, and nothing
/// widens.
#[cfg(feature = "sync")]
#[test]
fn a_board_re_parent_over_either_prior_settles_the_cycle() -> Result<()> {
    for prior in [1, 2] {
        let graph = astra(vec![rev(1, Some(prior), None, KEPT, 1)]);
        let served = [Some(view(KEPT, 0, Some(1))), Some(view(KEPT, 1, None))];
        both_orders(&graph, &served, &[Valid, Valid, Invalid, Valid, Valid])?;
    }
    Ok(())
}

/// The conduit is narrow: a leader's successor over B1, and a board
/// successor over B1 that still names A, stay undefined.
#[cfg(feature = "sync")]
#[test]
fn a_leader_successor_or_one_still_in_the_cycle_stays_undefined() -> Result<()> {
    let leader = Rev {
        signer: Rank::Leader,
        ..rev(1, Some(2), Some(0), KEPT, 1)
    };
    let still = rev(1, Some(2), Some(0), KEPT, 1);
    for successor in [leader, still] {
        let graph = astra(vec![successor]);
        let served = [Some(view(KEPT, 0, None)), Some(view(KEPT, 1, None))];
        both_orders(
            &graph,
            &served,
            &[Valid, Valid, Undefined, Undefined, Undefined],
        )?;
    }
    Ok(())
}

/// Positive control: without A1, B1 is an acyclic board re-parent under A
/// and installs its widening.
#[cfg(feature = "sync")]
#[test]
fn an_acyclic_re_parent_still_installs() -> Result<()> {
    let mut graph = model::astra();
    graph.revs.truncate(3);
    graph.revs[2].withheld = false;
    let served = [
        Some(view(KEPT | EXTRA, 3, None)),
        Some(view(KEPT | EXTRA, 2, Some(0))),
    ];
    let (scaffold, _dir, vault) = both_orders(&graph, &served, &[Valid, Valid, Valid])?;
    spawn(&scaffold, &vault, KEPT | EXTRA, 1)?;
    Ok(())
}

/// Causal future (Engine ruling): C was spawned under A and moved to R; A's
/// board then put A under C. A's view under C names C, so it came after
/// C's birth and does not judge it: C stays visible and A installs.
#[cfg(feature = "sync")]
#[test]
fn a_parent_moving_under_its_former_child_keeps_the_child_lit() -> Result<()> {
    let graph = Graph {
        projects: 2,
        born_under: vec![None, Some(0)],
        revs: vec![rev(1, None, None, KEPT, 5), rev(0, None, Some(1), KEPT, 4)],
        bound: 64,
    };
    let served = [Some(view(KEPT, 4, Some(1))), Some(view(KEPT, 5, None))];
    both_orders(&graph, &served, &[Valid, Valid])?;
    Ok(())
}

/// Causal future with a long history: A was born under B and edited there,
/// moved to R, and B then moved under A. A's birth stands, its move to R
/// conduits onto it, and the component stays lit (B = 0, A = 1).
#[cfg(feature = "sync")]
#[test]
fn a_long_history_under_a_later_child_stays_lit() -> Result<()> {
    let mut revs = vec![rev(1, None, Some(0), KEPT | EXTRA, 7)];
    for at in 1..5 {
        revs.push(rev(
            1,
            Some(at - 1),
            Some(0),
            KEPT | EXTRA,
            7 - (at as u8 % 2),
        ));
    }
    revs.push(rev(1, Some(4), None, KEPT | EXTRA, 6));
    revs.push(rev(0, None, Some(1), KEPT, 2));
    let graph = Graph {
        projects: 2,
        born_under: vec![None, Some(0)],
        revs,
        bound: 64,
    };
    let mut labels = vec![Invalid; 5];
    labels.extend([Valid, Valid]);
    let served = [
        Some(view(KEPT, 2, Some(1))),
        Some(view(KEPT | EXTRA, 6, None)),
    ];
    both_orders(&graph, &served, &labels)?;
    Ok(())
}

/// The world bound (Engine ruling, a policy row): a cycle with more views
/// than the bound serves no authority in either project, still lists every
/// held revision, and the owner holds one question naming it until it
/// serves again: once the bound is raised, or once the owner seals B over
/// B0, which leaves B1 outside the seal (Sol r14 F1, Astra r14 F3).
#[cfg(feature = "sync")]
#[test]
fn a_cycle_past_its_world_bound_serves_nothing_and_asks_the_owner() -> Result<()> {
    use super::super::fold::reason::CYCLE_BOUND;
    let mut graph = astra(vec![rev(1, Some(1), None, KEPT, 1)]);
    graph.bound = 1;
    let first = [true, true, true, true, false];
    assert_eq!(model::solve(&graph, &first).dark, vec![true, true]);
    let scaffold = scaffold(&graph)?;
    let (_dir, vault) = scaffold.replica(&[0, 1, 2, 3])?;
    for id in &scaffold.ids {
        let frontier = vault.project_frontier(*id)?.ok_or(Error::EntityNotFound)?;
        assert_eq!(frontier.effective, None);
        assert_eq!(
            frontier.disposition,
            ProjectDisposition::Unauthorized {
                reason: CYCLE_BOUND.into()
            }
        );
    }
    // A0 and B0 stand; B1 and A1 are past the bound.
    let listed = [
        ProjectVerdict::Visible,
        ProjectVerdict::Visible,
        ProjectVerdict::Quarantined(CYCLE_BOUND),
        ProjectVerdict::Quarantined(CYCLE_BOUND),
    ];
    for (index, verdict) in listed.into_iter().enumerate() {
        let project = scaffold.ids[graph.revs[index].project];
        let revisions = vault.project_revisions(project)?;
        let hash = scaffold.revisions[index].0;
        assert!(
            revisions.contains(&(hash, verdict)),
            "{index}: {revisions:?}"
        );
    }
    let mut members = scaffold.ids.clone();
    members.sort();
    let questions = vault.project_cycle_questions()?;
    assert_eq!(questions.len(), 1);
    assert_eq!(questions[0].members, members);
    seal_exit(&scaffold)?;
    // Raised, the bound lets the settle decide, and the question clears.
    set_bound(&vault, 64)?;
    scaffold.deliver(&vault, &[4])?;
    graph.bound = 64;
    let all = vec![true; graph.revs.len()];
    let reference = model::solve(&graph, &all);
    assert_eq!(
        reference.served,
        [Some(view(KEPT, 0, Some(1))), Some(view(KEPT, 1, None))]
    );
    let wrong = doors(&scaffold, &vault, &graph, &reference, &all)?;
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    assert_eq!(vault.project_cycle_questions()?, Vec::new());
    Ok(())
}

/// The owner seals B over B0, keeping B0's bounds, with the bound still at
/// one: B serves the seal, A1 fits under it, and the question clears.
fn seal_exit(scaffold: &Scaffold) -> Result<()> {
    use super::authority::FIXTURE_HOST;
    use crate::authority::HostSlipIssuer;
    let (_dir, vault) = scaffold.replica(&[0, 1, 2, 3])?;
    let b = scaffold.ids[1];
    let (b0, b0_row) = &scaffold.revisions[1];
    let authority = b0_row.authority().ok_or_else(invalid)?.clone();
    let issuer = HostSlipIssuer::from_secret(FIXTURE_HOST)?;
    let mut claims = vault.ensure_host_root_slip(&issuer)?.claims;
    claims.slip_id = *blake3::hash(EntityId::now().as_bytes()).as_bytes();
    claims.parent_id = None;
    claims.holder_ref = "host".into();
    let slip = vault.mint_capability_slip(&issuer, claims)?;
    // The door commits only a seal that installs as B's settled head.
    vault.seal_project(
        &super::history_cycles::owner(&vault)?,
        b,
        authority,
        *b0,
        slip.to_token()?,
        |challenge| issuer.binding_proof(&slip, challenge),
    )?;
    assert_eq!(
        scaffold.public(&vault)?,
        [Some(view(KEPT, 0, Some(1))), Some(view(KEPT, 1, None))]
    );
    assert_eq!(vault.project_cycle_questions()?, Vec::new());
    Ok(())
}

/// Bug repro (Sol r14 F3): B's board signs a chain of ten successors over
/// B0, each naming A, and A1 names B. No successor leaves the cycle, so none
/// is a conduit: B's assignments are the chain's eleven prefixes, and the
/// component serves the cycle's meet rather than passing the bound.
#[cfg(feature = "sync")]
#[test]
fn a_chain_still_in_the_cycle_stays_a_chain() -> Result<()> {
    let mut revs = vec![
        rev(0, None, None, KEPT | EXTRA, 3),
        rev(1, None, None, KEPT, 1),
    ];
    for at in 1..=10 {
        revs.push(rev(1, Some(at), Some(0), KEPT | EXTRA, 2));
    }
    revs.push(rev(0, Some(0), Some(1), KEPT, 0));
    let graph = Graph {
        projects: 2,
        born_under: vec![None, None],
        revs,
        bound: 64,
    };
    let mut labels = vec![Valid, Valid];
    labels.extend([Undefined; 11]);
    let served = [Some(view(KEPT, 0, None)), Some(view(KEPT, 1, None))];
    both_orders(&graph, &served, &labels)?;
    Ok(())
}

/// Bug repro (Astra r15 F7): the owner signs B2 over B1, still under A with
/// kept and extra at depth 2, and a peer replays it before or after Astra's
/// fixture. A host successor reads no parent's bounds, but it names a parent
/// in the component, so it is no conduit: it stands only on B1, and every
/// door still serves A1's narrowing. (The reference has no host signer.)
#[cfg(feature = "sync")]
#[test]
fn a_host_successor_still_in_the_cycle_is_no_conduit() -> Result<()> {
    use super::super::fold::reason;
    use super::super::revision::revisions_of_row;
    use super::history::{copy_of, open};
    use super::history_resolution::put_companion;
    let graph = astra(Vec::new());
    let scaffold = scaffold(&graph)?;
    let b = scaffold.ids[1];
    let (b2, row) = {
        let vault = open(&scaffold.dir)?;
        let b1 = &scaffold.records[graph.projects + 2];
        let mut b2 = b1.clone();
        sign_with(&vault, b, &mut b2, None, Some(b1.anchor()), None)?;
        revisions_of_row(b, &b2)?.pop().ok_or_else(invalid)?
    };
    let all = vec![true; graph.revs.len()];
    let reference = model::solve(&graph, &all);
    assert_eq!(
        reference.served,
        [Some(view(KEPT, 0, None)), Some(view(KEPT, 1, None))]
    );
    for first in [true, false] {
        let (_dir, vault) = copy_of(&scaffold.dir)?;
        if first {
            put_companion(&vault, &row, 9)?;
        }
        scaffold.deliver(&vault, &[0, 1, 2, 3])?;
        if !first {
            put_companion(&vault, &row, 20)?;
        }
        let wrong = doors(&scaffold, &vault, &graph, &reference, &all)?;
        assert!(wrong.is_empty(), "B2 first: {first}\n{}", wrong.join("\n"));
        let listed = vault.project_revisions(b)?;
        assert!(
            listed.contains(&(b2, ProjectVerdict::Quarantined(reason::CYCLE))),
            "{listed:?}"
        );
    }
    Ok(())
}

/// Linear cost (Engine ruling, the 200-chain check): each member holds `n`
/// board revisions over its birth, with the cycle edges at the tips (A1 over
/// A's first naming B, B1 over B's first naming A). One reader folds the
/// component: it verifies each revision once, each member keeps two worlds,
/// and its fold visits grow linearly over n = 100, 200 and 400.
#[cfg(feature = "sync")]
#[test]
fn a_component_of_long_histories_folds_in_linear_visits() -> Result<()> {
    use super::super::joint::WORLD_FOLDS;
    use super::super::read::{ProjectReader, REVISIONS_VERIFIED};
    use super::super::validity::FOLD_VISITS;
    let count = || {
        (
            REVISIONS_VERIFIED.with(std::cell::Cell::get),
            WORLD_FOLDS.with(std::cell::Cell::get),
            FOLD_VISITS.with(std::cell::Cell::get),
        )
    };
    let mut runs = Vec::new();
    for n in [100, 200, 400] {
        let mut revs = Vec::new();
        for project in 0..2 {
            revs.extend((0..n).map(|_| rev(project, None, None, KEPT, 1)));
        }
        revs.push(rev(0, Some(0), Some(1), KEPT, 0));
        revs.push(rev(1, Some(n), Some(0), KEPT, 0));
        let graph = Graph {
            projects: 2,
            born_under: vec![None, None],
            revs,
            bound: 64,
        };
        let reference = model::solve(&graph, &vec![true; graph.revs.len()]);
        assert_eq!(reference.labels[2 * n..], [Undefined, Undefined]);
        let scaffold = scaffold(&graph)?;
        let (_dir, vault) = super::history::copy_of(&scaffold.dir)?;
        scaffold.deliver_batch(&vault)?;
        let txn = vault.store.env.read_txn()?;
        let before = count();
        let reader =
            ProjectReader::new(&vault.store, &txn, vault.privacy_posture())?.ok_or_else(invalid)?;
        let mut served = Vec::new();
        for id in &scaffold.ids {
            let frontier = reader.frontier(*id)?;
            served.push(scaffold.view(frontier.as_ref().and_then(|f| f.effective.as_ref())));
        }
        let after = count();
        assert_eq!(served, reference.served, "n = {n}");
        // Long histories stay lit: within the decision's work budget.
        assert!(served.iter().all(Option::is_some), "n = {n}: {served:?}");
        assert_eq!(reader.cycle_hits(), 0);
        runs.push((
            n as u64,
            after.0 - before.0,
            after.1 - before.1,
            after.2 - before.2,
        ));
    }
    eprintln!("(n, verified, world folds, fold visits): {runs:?}");
    // Verified once each: the 2n revisions, the births, A1, B1 and the root.
    assert!(runs.iter().all(|run| run.1 == 2 * run.0 + 5), "{runs:?}");
    // World folds: independent of n.
    assert!(runs.iter().all(|run| run.2 == runs[0].2), "{runs:?}");
    // Visits: the step from 200 to 400 is at most twice the step from 100
    // to 200 (a quadratic fold makes it four times).
    let (first, second) = (runs[1].3 - runs[0].3, runs[2].3 - runs[1].3);
    assert!(first > 0 && second <= 2 * first + first / 10, "{runs:?}");
    Ok(())
}
