//! The delete cascade over a small, tested timing subset (ARCH-0077,
//! "Animation dependencies"). Only effects in the main sequence's
//! click-step / with-group / effect nesting are removed, and only when every
//! shape they name is deleted:
//! - a click step whose effects all go is removed whole;
//! - a `withEffect` goes from a with-group that keeps other effects;
//! - when the main sequence empties, `p:timing` goes if nothing else is
//!   timed in it.
//!
//! Build entries naming a deleted shape go with it (and an emptied
//! `p:bldLst`). Triggers, effects that also name a surviving shape, an
//! effect that leads its step, a step whose removal would shift a later
//! with-group, and any other shape of timing refuse.
use crate::edit::EditRefusal;
use crate::edit::xml::{self, P};
use crate::ooxml::XmlTree;

const BUILDS: [&str; 4] = ["bldP", "bldGraphic", "bldDgm", "bldOleChart"];

fn unsupported(why: &'static str) -> EditRefusal {
    EditRefusal::AnimationDependencyUnsupported(why)
}

/// `at` and every element inside it, in document order.
pub(super) fn subtree(tree: &XmlTree, at: usize) -> impl Iterator<Item = usize> + '_ {
    let span = tree.nodes[at].span.clone();
    (at..tree.nodes.len()).take_while(move |&n| tree.nodes[n].span.start < span.end || n == at)
}

/// Every `spid` the element names (effect and condition targets and
/// builds); `None` for an unreadable one.
fn named(tree: &XmlTree, at: usize) -> Vec<Option<u32>> {
    subtree(tree, at)
        .filter(|&n| {
            let node = &tree.nodes[n];
            node.namespace == P && (node.name == "spTgt" || BUILDS.contains(&node.name.as_str()))
        })
        .map(|n| tree.nodes[n].attr("spid").and_then(|id| id.parse().ok()))
        .collect()
}

/// The element names at least one shape, and only deleted ones.
pub(super) fn gone(tree: &XmlTree, at: usize, deleted: &[u32]) -> bool {
    let named = named(tree, at);
    !named.is_empty()
        && named
            .iter()
            .all(|id| id.is_some_and(|id| deleted.contains(&id)))
}

fn ancestors(tree: &XmlTree, at: usize) -> impl Iterator<Item = usize> + '_ {
    std::iter::successors(tree.nodes[at].parent, |&up| tree.nodes[up].parent)
}

/// A `p:par` whose `p:cTn` carries a preset class: one effect.
fn is_effect(tree: &XmlTree, at: usize) -> bool {
    tree.nodes[at].is(P, "par")
        && xml::child(tree, at, P, "cTn")
            .is_some_and(|ctn| tree.nodes[ctn].attr("presetClass").is_some())
}

fn node_type(tree: &XmlTree, par: usize) -> Option<&str> {
    xml::child(tree, par, P, "cTn").and_then(|ctn| tree.nodes[ctn].attr("nodeType"))
}

/// The `p:par` two levels up (`p:par/p:cTn/p:childTnLst/p:par`).
fn outer_par(tree: &XmlTree, par: usize) -> Option<usize> {
    let list = tree.nodes[par].parent?;
    let ctn = tree.nodes[list].parent?;
    let outer = tree.nodes[ctn].parent?;
    (tree.nodes[list].is(P, "childTnLst")
        && tree.nodes[ctn].is(P, "cTn")
        && tree.nodes[outer].is(P, "par"))
    .then_some(outer)
}

/// The `p:par` children of a par's `p:cTn/p:childTnLst`.
fn inner_pars(tree: &XmlTree, par: usize) -> Vec<usize> {
    xml::path(tree, par, &[(P, "cTn"), (P, "childTnLst")]).map_or_else(Vec::new, |list| {
        tree.nodes[list]
            .children
            .iter()
            .copied()
            .filter(|&n| tree.nodes[n].is(P, "par"))
            .collect()
    })
}

/// The main-sequence `p:cTn` a click step sits in.
fn main_sequence(tree: &XmlTree, step: usize) -> Option<usize> {
    let list = tree.nodes[step].parent?;
    let ctn = tree.nodes[list].parent?;
    (tree.nodes[ctn].is(P, "cTn") && tree.nodes[ctn].attr("nodeType") == Some("mainSeq"))
        .then_some(ctn)
}

/// The timing elements to remove with the shapes `deleted`.
pub(super) fn cascade(tree: &XmlTree, deleted: &[u32]) -> Result<Vec<usize>, EditRefusal> {
    let Some(timing) = xml::child(tree, 0, P, "timing") else {
        return Ok(Vec::new());
    };
    let mut effects = Vec::new();
    for hit in subtree(tree, timing).filter(|&n| {
        tree.nodes[n].is(P, "spTgt")
            && tree.nodes[n]
                .attr("spid")
                .and_then(|id| id.parse().ok())
                .is_some_and(|id| deleted.contains(&id))
    }) {
        let chain: Vec<usize> = ancestors(tree, hit).take_while(|&n| n != timing).collect();
        if chain.iter().any(|&n| tree.nodes[n].is(P, "cond")) {
            return Err(unsupported("a trigger names the shape"));
        }
        let effect = chain
            .iter()
            .copied()
            .find(|&n| is_effect(tree, n))
            .ok_or(unsupported("an effect outside the tested timing subset"))?;
        if !gone(tree, effect, deleted) {
            return Err(unsupported("an effect also names a surviving shape"));
        }
        if !effects.contains(&effect) {
            effects.push(effect);
        }
    }
    let mut steps = Vec::new();
    for &effect in &effects {
        let step = outer_par(tree, effect)
            .and_then(|with| outer_par(tree, with))
            .filter(|&step| main_sequence(tree, step).is_some())
            .ok_or(unsupported("an effect outside the tested timing subset"))?;
        if !steps.contains(&step) {
            steps.push(step);
        }
    }
    let mut removed = Vec::new();
    for &step in &steps {
        let all: Vec<usize> = subtree(tree, step)
            .filter(|&n| is_effect(tree, n))
            .collect();
        if all.iter().all(|e| effects.contains(e)) {
            removed.push(step);
            continue;
        }
        for with in inner_pars(tree, step) {
            let inner: Vec<usize> = inner_pars(tree, with)
                .into_iter()
                .filter(|&n| is_effect(tree, n))
                .collect();
            let going: Vec<usize> = inner
                .iter()
                .copied()
                .filter(|e| effects.contains(e))
                .collect();
            if going.is_empty() {
                continue;
            }
            if going.len() == inner.len() {
                return Err(unsupported("a later timing step would shift"));
            }
            if going
                .iter()
                .any(|&e| node_type(tree, e) != Some("withEffect"))
            {
                return Err(unsupported("the effect leads its step"));
            }
            removed.extend(going);
        }
    }
    let builds = xml::child(tree, timing, P, "bldLst");
    let entries: Vec<usize> =
        builds.map_or_else(Vec::new, |list| tree.nodes[list].children.clone());
    let doomed: Vec<usize> = entries
        .iter()
        .copied()
        .filter(|&n| gone(tree, n, deleted))
        .collect();
    let sequence = steps.first().and_then(|&step| main_sequence(tree, step));
    if let Some(sequence) = sequence
        && inner_pars_of_ctn(tree, sequence)
            .iter()
            .all(|step| removed.contains(step))
    {
        // The main sequence empties: drop the timing only when nothing else
        // is timed in it.
        let alone = xml::path(
            tree,
            timing,
            &[(P, "tnLst"), (P, "par"), (P, "cTn"), (P, "childTnLst")],
        )
        .is_some_and(|list| tree.nodes[list].children.len() == 1)
            && tree.nodes[timing]
                .children
                .iter()
                .all(|&n| tree.nodes[n].is(P, "tnLst") || tree.nodes[n].is(P, "bldLst"))
            && doomed.len() == entries.len();
        if !alone {
            return Err(unsupported("the main sequence would empty"));
        }
        return Ok(vec![timing]);
    }
    match builds {
        Some(list) if !doomed.is_empty() && doomed.len() == entries.len() => removed.push(list),
        _ => removed.extend(doomed),
    }
    Ok(removed)
}

/// The `p:par` children of a `p:cTn/p:childTnLst`.
fn inner_pars_of_ctn(tree: &XmlTree, ctn: usize) -> Vec<usize> {
    xml::child(tree, ctn, P, "childTnLst").map_or_else(Vec::new, |list| {
        tree.nodes[list]
            .children
            .iter()
            .copied()
            .filter(|&n| tree.nodes[n].is(P, "par"))
            .collect()
    })
}

/// The `p:cTn` ids inside the removed elements.
pub(super) fn ids(tree: &XmlTree, removed: &[usize]) -> Vec<u32> {
    removed
        .iter()
        .flat_map(|&at| subtree(tree, at))
        .filter(|&n| tree.nodes[n].is(P, "cTn"))
        .filter_map(|n| tree.nodes[n].attr("id")?.parse().ok())
        .collect()
}
