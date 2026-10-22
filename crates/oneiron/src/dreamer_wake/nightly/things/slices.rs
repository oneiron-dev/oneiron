//! A nightly thing's children: one per project (FIX 8724). Every
//! conversation the thing appears in is one part, and the parts read in one
//! project make one child, which lists that project's prior claims as a
//! one-project branch always has. A part whose project is not known (one of
//! its TURNs has no exposure) is a child of its own, as before. Inside a
//! child each part is sliced on a line: a bound thing off any private
//! thread puts the parts whose exposure agrees (`exposure`) on one line,
//! and every other part, as each part of a structural topic or of a private
//! thread's thing, is a line of its own. The child's extraction never puts
//! TURNs of two lines in one slice, and cuts each line into slices of its
//! configured TURN size, so what were sibling children of one project
//! before are slices inside one child: a thing's agent reads them all, and
//! the per-slice path runs them as it ran before.

use std::collections::BTreeMap;

use super::super::exposure::Exposure;
use super::{Draft, NightlyThingPlan};
use crate::EntityId;
use crate::dreamer_consolidation::{
    ConsolidationBranchPlan, ConsolidationPartitionPlan, ConversationPart,
};

/// One part as it gathers: its exposure class, when its thing combines
/// parts and its TURNs agree on one.
type Gathered = (Option<Exposure>, ConversationPart);

/// A drafted thing as its children: its TURNs as one part per partition,
/// in the partitions' spending order, one child per project, each part on
/// its child's slice line. A child's axes are its thing's.
pub(super) fn cut(
    partitions: &[ConsolidationPartitionPlan],
    draft: Draft,
    exposures: &BTreeMap<EntityId, Option<Exposure>>,
) -> NightlyThingPlan {
    let combines = draft.key.entity.is_some() && draft.key.audience.is_none();
    let mut children: Vec<Vec<Gathered>> = Vec::new();
    let mut projects: BTreeMap<EntityId, usize> = BTreeMap::new();
    for (index, turns) in draft.turns {
        let partition = &partitions[index];
        let of: Vec<Option<&Exposure>> = turns
            .iter()
            .map(|turn| exposures.get(&turn.turn_id).and_then(Option::as_ref))
            .collect();
        let class = if combines {
            Exposure::of_part(&of)
        } else {
            None
        };
        let part = ConversationPart {
            conversation_ref: partition.key.conversation_ref,
            turns,
            watermark_last_learned_at: partition.watermark_last_learned_at,
            line: 0,
        };
        match part_project(&of) {
            Some(project) => {
                let at = *projects.entry(project).or_insert_with(|| {
                    children.push(Vec::new());
                    children.len() - 1
                });
                children[at].push((class, part));
            }
            None => children.push(vec![(class, part)]),
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
