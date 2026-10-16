//! The parent-bounds fall (Engine ruling on #1434, after the oracle's seeds
//! 3, 12 and 61): a revision that falls only for its parent's bounds, over a
//! standing prior, hands no authority back to that prior or to a sibling it
//! does not lose to. A parent's narrowing never widens the child, as main's
//! stored-row rule failed closed. A fall on the revision's own lineage still
//! hands back to its prior.
use super::super::fold::reason;
use super::super::*;
use super::authority::{put_signed_project, replay_project, root_leader, spawn_signed};
use super::cycle_model::{self as model, EXTRA, Graph, KEPT, Label, Rank, Rev, View};
use super::history::{head_of, open, signed_over};
use super::history_cycles::{readable, replay, scaffold};

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

fn leader(rev: Rev) -> Rev {
    Rev {
        signer: Rank::Leader,
        ..rev
    }
}

fn withheld(rev: Rev) -> Rev {
    Rev {
        withheld: true,
        ..rev
    }
}

/// Replays `graph`'s withheld revisions in both orders: no door disagrees
/// with the reference or widens a project, and `dark` serves no authority
/// after the replay, for its parent's bounds, though it served before.
fn falls_dark(graph: &Graph, dark: usize) -> Result<()> {
    let all = vec![true; graph.revs.len()];
    assert_eq!(model::solve(graph, &all).served[dark], None);
    let scaffold = scaffold(graph)?;
    let forward: Vec<usize> = (0..graph.revs.len()).collect();
    for order in [forward.clone(), forward.into_iter().rev().collect()] {
        let replay = replay(&scaffold, graph, &order)?;
        assert!(replay.wrong.is_empty(), "{}", replay.wrong.join("\n"));
        assert!(replay.before[dark].is_some());
        assert_eq!(replay.after[dark], None);
        let frontier = (replay.vault)
            .project_frontier(scaffold.ids[dark])?
            .ok_or(Error::EntityNotFound)?;
        assert!(
            matches!(&frontier.disposition, ProjectDisposition::Unauthorized { reason: why }
                if why == reason::EXCEEDS_PARENT || why == reason::PARENT_HIDDEN),
            "{:?}",
            frontier.disposition
        );
    }
    Ok(())
}

/// Seed 3: C (0) re-parents under P (1) with `{extra}`, depth 4; P's
/// leader's withheld narrowing to depth 3 replays. C's re-parent no longer
/// fits, and C used to fall back to its birth (`{kept, extra}`, depth 9
/// under R). It now serves nothing.
#[cfg(feature = "sync")]
#[test]
fn a_parents_replayed_narrowing_never_widens_a_child_under_it() -> Result<()> {
    let graph = Graph {
        projects: 3,
        born_under: vec![None, None, None],
        revs: vec![
            rev(1, None, None, KEPT | EXTRA, 5),
            withheld(leader(rev(2, None, None, KEPT | EXTRA, 0))),
            rev(2, Some(1), None, KEPT | EXTRA, 3),
            withheld(leader(rev(1, Some(0), None, KEPT | EXTRA, 3))),
            rev(0, None, Some(1), EXTRA, 4),
        ],
        bound: 64,
    };
    falls_dark(&graph, 0)
}

/// Seed 12: P (1) sits under C (0) with `{kept}`, depth 2; C's withheld
/// board siblings replay, one to R at depth 0, so no view of C P could stay
/// under fits it. P used to fall back to its birth under R; it now serves
/// nothing.
#[cfg(feature = "sync")]
#[test]
fn a_replayed_narrowing_of_a_parent_in_a_cycle_never_widens_its_child() -> Result<()> {
    let graph = Graph {
        projects: 2,
        born_under: vec![None, None],
        revs: vec![
            withheld(rev(0, None, Some(1), KEPT, 5)),
            withheld(rev(0, None, None, KEPT | EXTRA, 0)),
            rev(1, None, Some(0), KEPT, 2),
            withheld(rev(0, None, Some(1), KEPT, 8)),
            rev(0, Some(0), Some(1), EXTRA, 5),
        ],
        bound: 64,
    };
    falls_dark(&graph, 1)
}

/// Seed 61: Q (2) under P (1) with `{extra}`, depth 7, while P sits under Q:
/// Q served the meet. P's leader's withheld sibling to R at depth 2 replays,
/// the only view of P clear of Q, and Q's re-parent falls on its bounds. Q
/// used to widen to its birth; it now serves nothing.
#[cfg(feature = "sync")]
#[test]
fn a_cycle_undefined_re_parent_that_falls_on_its_bounds_never_widens() -> Result<()> {
    let graph = Graph {
        projects: 3,
        born_under: vec![None, None, None],
        revs: vec![
            rev(0, None, Some(1), EXTRA, 8),
            rev(0, None, Some(1), KEPT | EXTRA, 5),
            rev(2, None, Some(1), EXTRA, 7),
            rev(0, Some(1), None, KEPT | EXTRA, 5),
            rev(0, Some(3), Some(1), KEPT | EXTRA, 8),
            rev(1, None, Some(2), KEPT, 1),
            withheld(leader(rev(1, None, None, KEPT | EXTRA, 2))),
        ],
        bound: 64,
    };
    falls_dark(&graph, 2)
}

/// A fall on the revision's own lineage still hands back to its prior: a
/// leader's widening over C1 is refused for its signer, and C serves C1.
#[cfg(feature = "sync")]
#[test]
fn a_lineage_fall_still_hands_back_to_the_prior() -> Result<()> {
    let graph = Graph {
        projects: 1,
        born_under: vec![None],
        revs: vec![
            rev(0, None, None, KEPT | EXTRA, 5),
            withheld(leader(rev(0, Some(0), None, KEPT | EXTRA, 6))),
        ],
        bound: 64,
    };
    let reference = model::solve(&graph, &[true, true]);
    assert_eq!(reference.labels, [Label::Valid, Label::Invalid]);
    let served = Some(View {
        mask: KEPT | EXTRA,
        depth: 5,
        parent: None,
    });
    assert_eq!(reference.served, [served]);
    let scaffold = scaffold(&graph)?;
    for order in [[0, 1], [1, 0]] {
        let replay = replay(&scaffold, &graph, &order)?;
        assert!(replay.wrong.is_empty(), "{}", replay.wrong.join("\n"));
        assert_eq!(replay.after, [served]);
    }
    Ok(())
}

/// A removed board holder cannot darken the project this way: B2 removes B1
/// from C's board (C1), and B1 then signs a sibling over S0 that re-parents
/// C under P, wider than P. It falls on P's bounds, but C1 deposes its
/// signer off its line, so it takes nothing and C serves C1. The same
/// sibling from B2, whom nothing deposes, serves no authority.
#[cfg(feature = "sync")]
#[test]
fn a_deposed_signers_fallen_sibling_never_darkens_the_project() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = open(&dir)?;
    let (root, mut root_row, holder) = root_leader(&vault)?;
    root_row.slice.readable = readable(KEPT | EXTRA);
    put_signed_project(&vault, root, &mut root_row, holder, 1)?;
    let narrow = crate::llm::Scope {
        readable: readable(KEPT),
        ..root_row.slice.clone()
    };
    let p = EntityId::now();
    spawn_signed(&vault, root, p, holder, EntityId::now(), narrow, 2)?;
    let (c, lead) = (EntityId::now(), EntityId::now());
    let birth = spawn_signed(&vault, root, c, holder, lead, root_row.slice.clone(), 3)?;
    let (b1, b2) = (EntityId::now(), EntityId::now());
    let s0 = signed_over(&vault, c, &birth, holder, |row| {
        row.board.extend([b1.to_hex(), b2.to_hex()]);
    })?;
    vault.put_project(c, &s0, 4)?;
    let c1 = signed_over(&vault, c, &s0, b2, |row| {
        row.board.retain(|seat| *seat != b1.to_hex());
    })?;
    vault.put_project(c, &c1, 5)?;
    let under_p = |row: &mut ProjectRecord| row.parents = vec![p.to_hex()];
    let stale = signed_over(&vault, c, &s0, b1, under_p)?;
    replay_project(&vault, c, &stale, 6)?;
    let served = vault.project_frontier(c)?.ok_or(Error::EntityNotFound)?;
    assert_eq!(served.disposition, ProjectDisposition::Settled);
    assert_eq!(
        served.witness.map(|witness| witness.head),
        Some(head_of(c, &c1)?)
    );
    let live = signed_over(&vault, c, &s0, b2, under_p)?;
    replay_project(&vault, c, &live, 7)?;
    let served = vault.project_frontier(c)?.ok_or(Error::EntityNotFound)?;
    assert_eq!(served.effective, None);
    assert_eq!(
        served.disposition,
        ProjectDisposition::Unauthorized {
            reason: reason::EXCEEDS_PARENT.into()
        }
    );
    Ok(())
}
