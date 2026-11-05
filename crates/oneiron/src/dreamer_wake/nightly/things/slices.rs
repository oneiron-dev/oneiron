//! A nightly thing's children: one per project (FIX 8724). Every
//! conversation the thing appears in is one part, and the parts read in one
//! project make one child. A PERSON-grouped thing also keeps each exact
//! exposure cohort in a separate child, splitting its TURNs before parts
//! are built; an unknown exposure stays alone. Each child lists its project's
//! prior claims as a one-project branch always has. A part whose project is
//! not known (one of
//! its TURNs has no exposure) is a child of its own, as before. Inside a
//! child each part is sliced on a line: a bound thing puts the parts whose
//! exposure agrees (`exposure`) on one line, a private audience's thing only
//! the parts its whole audience reads, turn by turn (FIX 7730), and every
//! other part, as each part of a structural topic, is a line of its own.
//! The child's extraction never puts TURNs of two lines in one slice, and
//! cuts each line into slices of its configured TURN size, so what were
//! sibling children of one project before are slices inside one child: a
//! thing's agent reads them all, and the per-slice path runs them as it ran
//! before.

use std::collections::BTreeMap;

use super::super::exposure::Exposure;
use super::{Draft, NightlyThingPlan};
use crate::EntityId;
use crate::dreamer_consolidation::{
    ConsolidationBranchPlan, ConsolidationPartitionPlan, ConversationPart, PartitionAudience,
    WorkingSetTurn,
};

/// One part as it gathers: its exposure class, when its thing combines
/// parts and its TURNs agree on one.
type Gathered = (Option<Exposure>, ConversationPart);

/// A drafted thing as its children: its TURNs as one part per partition,
/// in the partitions' spending order, one child per project and, for a
/// PERSON-grouped thing, exact exposure. Each part is on its child's slice
/// line. A child's axes are its thing's.
pub(super) fn cut(
    partitions: &[ConsolidationPartitionPlan],
    draft: Draft,
    exposures: &BTreeMap<EntityId, Option<Exposure>>,
) -> NightlyThingPlan {
    let combines = draft.key.entity.is_some();
    // Private parts combine only where the same audience reads every TURN
    // of each: never beside words fewer or other people read.
    let private = draft.key.audience.is_some();
    let person = matches!(draft.key.audience, Some(PartitionAudience::Person(_)));
    let mut children: Vec<Vec<Gathered>> = Vec::new();
    let mut projects: BTreeMap<(EntityId, Option<Exposure>), usize> = BTreeMap::new();
    for (index, turns) in draft.turns {
        let partition = &partitions[index];
        let cohorts = if person {
            person_cohorts(turns, exposures)
        } else {
            vec![(None, turns)]
        };
        for (cohort, turns) in cohorts {
            let of: Vec<Option<&Exposure>> = turns
                .iter()
                .map(|turn| exposures.get(&turn.turn_id).and_then(Option::as_ref))
                .collect();
            let class = if combines {
                Exposure::of_part(&of).filter(|class| !private || class.readers.is_some())
            } else {
                None
            };
            let project = part_project(&of);
            let part = ConversationPart {
                conversation_ref: partition.key.conversation_ref,
                turns,
                watermark_last_learned_at: partition.watermark_last_learned_at,
                line: 0,
            };
            match project {
                Some(project) if !person || cohort.is_some() => {
                    let at = *projects.entry((project, cohort)).or_insert_with(|| {
                        children.push(Vec::new());
                        children.len() - 1
                    });
                    children[at].push((class, part));
                }
                _ => children.push(vec![(class, part)]),
            }
        }
    }
    let thing = Some(draft.key.payload());
    NightlyThingPlan {
        key: draft.key,
        spans: draft.spans,
        children: children
            .into_iter()
            .map(|parts| ConsolidationBranchPlan {
                world_ref: draft.key.world,
                facet_ref: draft.key.facet,
                thing,
                parts: lined(parts),
            })
            .collect(),
    }
}

/// Split before making conversation parts: unequal private reader sets or
/// other exposures cannot share a part, even within the same conversation.
/// Without a proven complete exposure, each TURN keeps a child of its own.
fn person_cohorts(
    turns: Vec<WorkingSetTurn>,
    exposures: &BTreeMap<EntityId, Option<Exposure>>,
) -> Vec<(Option<Exposure>, Vec<WorkingSetTurn>)> {
    let mut cohorts: Vec<(Option<Exposure>, Vec<WorkingSetTurn>)> = Vec::new();
    let mut classes = BTreeMap::new();
    for turn in turns {
        let exposure = exposures
            .get(&turn.turn_id)
            .and_then(Option::as_ref)
            .filter(|exposure| exposure.readers.is_some());
        if let Some(exposure) = exposure {
            let at = *classes.entry(exposure.clone()).or_insert_with(|| {
                cohorts.push((Some(exposure.clone()), Vec::new()));
                cohorts.len() - 1
            });
            cohorts[at].1.push(turn);
        } else {
            cohorts.push((None, vec![turn]));
        }
    }
    cohorts
}

/// One child's parts, each on its line: the parts of one exposure class
/// share one, and every part with none opens its own, numbered from zero
/// in part order.
fn lined(parts: Vec<Gathered>) -> Vec<ConversationPart> {
    let mut classes: BTreeMap<Exposure, u32> = BTreeMap::new();
    let mut lines = 0_u32;
    parts
        .into_iter()
        .map(|(class, mut part)| {
            part.line = match class {
                Some(class) => *classes
                    .entry(class)
                    .or_insert_with(|| open_line(&mut lines)),
                None => open_line(&mut lines),
            };
            part
        })
        .collect()
}

/// The one project every TURN of a part is read in, when each has an
/// exposure and they agree.
fn part_project(exposures: &[Option<&Exposure>]) -> Option<EntityId> {
    let mut projects = exposures
        .iter()
        .map(|exposure| exposure.map(|exposure| exposure.project));
    let first = projects.next()??;
    projects
        .all(|project| project == Some(first))
        .then_some(first)
}

/// The next line's number, counting it as opened.
fn open_line(lines: &mut u32) -> u32 {
    let line = *lines;
    *lines = lines.saturating_add(1);
    line
}
