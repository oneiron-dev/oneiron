//! One nightly thing per entity or topic (OF-498c, ARCH-0026 Nightly). The
//! spans a night spends group by thing: its world, its facet, the private
//! thread its turns are of, and the entity a span's reading bound, else the
//! structural topic. No conversation is in the key, so a thing may span
//! conversations; every exposure boundary stays in it, and a private
//! thread's turns share a thing only with turns of that same thread.
//!
//! Every TURN lands in exactly one thing: the entity of its highest scored
//! bound span, else its partition's topic. Each spent span rides with its
//! TURN's thing. A bound thing's child holds it across every conversation it
//! appears in (FIX 7524): one part per conversation, combined only where the
//! parts' exposure agrees (`exposure`), and past `CHILD_TURNS` of total TURN
//! work into sibling children of that size. A structural topic, a private
//! thread's thing and a part whose exposure does not agree stay in their own
//! conversation's child. Each child names its thing in its payload. Nothing
//! is dropped, and the number of entities, things or conversations is not
//! bounded.

use std::collections::BTreeMap;

use super::exposure::Exposure;
use crate::dreamer_consolidation::{
    ConsolidationBranchPlan, ConsolidationPartitionKey, ConsolidationPartitionPlan,
    ConversationPart, DEFAULT_MESO_ROUND_TURN_CAP, PartitionThing, WorkingSetTurn,
};
use crate::dreamer_wake::sieve::SieveSpan;
use crate::{EntityId, Result, Vault};

/// The most TURNs one child carries: what one wake prepares at its head
/// (the wake plan's prepared-TURN bound is this same round size). A child
/// past it would make a wake read it whole, so a thing past it splits. The
/// child's extraction slices its TURNs again, as it did before.
const CHILD_TURNS: usize = DEFAULT_MESO_ROUND_TURN_CAP;

/// What one nightly thing is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct NightlyThingKey {
    pub(super) world: Option<EntityId>,
    pub(super) facet: Option<EntityId>,
    /// The private thread its turns are of; `None` off any private thread.
    pub(super) audience: Option<EntityId>,
    /// The entity a spent span's reading bound. `None` is the structural
    /// topic: the TURNs none of whose spent spans is bound.
    pub(super) entity: Option<EntityId>,
}

impl NightlyThingKey {
    /// The thing as its children's payloads name it.
    pub(super) fn payload(self) -> PartitionThing {
        PartitionThing {
            entity: self.entity,
            audience: self.audience,
        }
    }
}

/// One thing's share of a night: every span it spends and its children.
#[derive(Debug)]
pub(super) struct NightlyThingPlan {
    pub(super) key: NightlyThingKey,
    /// Every spent span whose TURN is this thing's, in queue order.
    pub(super) spans: Vec<SieveSpan>,
    /// The thing's TURNs as branches over its conversation parts, in the
    /// partitions' spending order, each part in partition order and every
    /// child cut at `CHILD_TURNS` of total work.
    pub(super) children: Vec<ConsolidationBranchPlan>,
}

/// One thing as it gathers, before its children are cut.
struct Draft {
    key: NightlyThingKey,
    spans: Vec<SieveSpan>,
    /// Its TURNs by the index of the partition they fall in.
    turns: BTreeMap<usize, Vec<WorkingSetTurn>>,
}

/// Where a TURN's room-thread binding puts it.
enum Thread {
    Trunk,
    Of {
        root: EntityId,
        names_audience: bool,
    },
    Unread,
}

/// Each planned TURN's private thread: the root of the room-thread binding
/// its body carries (`workspace_roster::thread_binding`, the binding the
/// private-thread walk reads) when the root's binding names an audience.
/// `None` on the trunk or a public thread. A TURN whose binding does not
/// read is its own audience, and a thread whose root does not read is
/// private: either stays apart, never dropped.
pub(super) fn audiences_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    partitions: &[ConsolidationPartitionPlan],
) -> Result<BTreeMap<EntityId, Option<EntityId>>> {
    let mut roots = BTreeMap::new();
    let mut audiences = BTreeMap::new();
    for turn in partitions.iter().flat_map(|partition| &partition.turns) {
        let audience = match thread_in(vault, txn, &turn.turn_id)? {
            Thread::Trunk => None,
            Thread::Unread => Some(turn.turn_id),
            Thread::Of {
                root,
                names_audience,
            } => {
                let private = if root == turn.turn_id {
                    names_audience
                } else {
                    root_private_in(vault, txn, root, &mut roots)?
                };
                private.then_some(root)
            }
        };
        audiences.insert(turn.turn_id, audience);
    }
    Ok(audiences)
}

/// Whether the thread rooted at `root` names an audience, read once.
fn root_private_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    root: EntityId,
    roots: &mut BTreeMap<EntityId, bool>,
) -> Result<bool> {
    if let Some(private) = roots.get(&root) {
        return Ok(*private);
    }
    let private = match thread_in(vault, txn, &root)? {
        Thread::Of {
            names_audience: root_names,
            ..
        } => root_names,
        Thread::Trunk | Thread::Unread => true,
    };
    roots.insert(root, private);
    Ok(private)
}

fn thread_in(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<Thread> {
    let Some(raw) = vault.get_raw_in(txn, id)? else {
        return Ok(Thread::Unread);
    };
    let body = raw
        .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
        .unwrap_or_default();
    Ok(match crate::workspace_roster::thread_binding(body) {
        Ok(None) => Thread::Trunk,
        Ok(Some(binding)) => Thread::Of {
            root: binding.root,
            names_audience: binding.audience.is_some(),
        },
        Err(_) => Thread::Unread,
    })
}

/// The things `partitions` hold, each first met at its highest scored span.
/// `spans` is the night's queue readout, highest score first; a span that
/// still owes a rung is neither placed nor spent here. `audiences` is
/// [`audiences_in_txn`] and `exposures` `exposure::exposures_in_txn` over the
/// same partitions.
pub(super) fn plan_things(
    partitions: &[ConsolidationPartitionPlan],
    spans: &[SieveSpan],
    audiences: &BTreeMap<EntityId, Option<EntityId>>,
    exposures: &BTreeMap<EntityId, Option<Exposure>>,
) -> Vec<NightlyThingPlan> {
    let homes = turn_homes(partitions, spans);
    let audience = |turn: &EntityId| audiences.get(turn).copied().flatten();
    let mut slots = BTreeMap::new();
    let mut drafts = Vec::new();
    for span in spans.iter().filter(|span| span.owed.is_empty()) {
        if let Some(&(index, entity)) = homes.get(&span.turn) {
            let key = thing_key(&partitions[index].key, audience(&span.turn), entity);
            let at = slot(&mut slots, &mut drafts, key);
            drafts[at].spans.push(span.clone());
        }
    }
    for (index, partition) in partitions.iter().enumerate() {
        for turn in &partition.turns {
            let entity = homes.get(&turn.turn_id).and_then(|&(_, entity)| entity);
            let key = thing_key(&partition.key, audience(&turn.turn_id), entity);
            let at = slot(&mut slots, &mut drafts, key);
            drafts[at].turns.entry(index).or_default().push(*turn);
        }
    }
    drafts
        .into_iter()
        .map(|draft| cut(partitions, draft, exposures))
        .collect()
}

fn thing_key(
    partition: &ConsolidationPartitionKey,
    audience: Option<EntityId>,
    entity: Option<EntityId>,
) -> NightlyThingKey {
    NightlyThingKey {
        world: partition.world_ref,
        facet: partition.facet_ref,
        audience,
        entity,
    }
}

/// Each planned TURN's partition, by index, and the entity of its highest
/// scored bound spent span. A TURN no spent span of which is bound keeps
/// `None`: the structural topic.
fn turn_homes(
    partitions: &[ConsolidationPartitionPlan],
    spans: &[SieveSpan],
) -> BTreeMap<EntityId, (usize, Option<EntityId>)> {
    let mut homes = BTreeMap::new();
    for (index, partition) in partitions.iter().enumerate() {
        for turn in &partition.turns {
            homes.insert(turn.turn_id, (index, None));
        }
    }
    for span in spans.iter().filter(|span| span.owed.is_empty()) {
        if let Some((_, entity)) = homes.get_mut(&span.turn)
            && entity.is_none()
        {
            *entity = span.entity;
        }
    }
    homes
}

/// The draft of `key`, opened the first time it is met.
fn slot(
    slots: &mut BTreeMap<NightlyThingKey, usize>,
    drafts: &mut Vec<Draft>,
    key: NightlyThingKey,
) -> usize {
    *slots.entry(key).or_insert_with(|| {
        drafts.push(Draft {
            key,
            spans: Vec::new(),
            turns: BTreeMap::new(),
        });
        drafts.len() - 1
    })
}

/// A drafted thing, its TURNs as one part per partition, and its parts
/// combined into children past `CHILD_TURNS` of total work. A bound thing
/// off any private thread combines the parts whose exposure agrees; any
/// other part keeps a child line of its own, as a structural topic's and a
/// private thread's do. A child's axes are its thing's.
fn cut(
    partitions: &[ConsolidationPartitionPlan],
    draft: Draft,
    exposures: &BTreeMap<EntityId, Option<Exposure>>,
) -> NightlyThingPlan {
    let combines = draft.key.entity.is_some() && draft.key.audience.is_none();
    let mut lines: Vec<Vec<ConversationPart>> = Vec::new();
    let mut classes: BTreeMap<Exposure, usize> = BTreeMap::new();
    for (index, turns) in draft.turns {
        let partition = &partitions[index];
        let class = if combines {
            let of: Vec<Option<&Exposure>> = turns
                .iter()
                .map(|turn| exposures.get(&turn.turn_id).and_then(Option::as_ref))
                .collect();
            Exposure::of_part(&of)
        } else {
            None
        };
        let part = ConversationPart {
            conversation_ref: partition.key.conversation_ref,
            turns,
            watermark_last_learned_at: partition.watermark_last_learned_at,
        };
        match class {
            Some(class) => {
                let at = *classes.entry(class).or_insert_with(|| {
                    lines.push(Vec::new());
                    lines.len() - 1
                });
                lines[at].push(part);
            }
            None => lines.push(vec![part]),
        }
    }
    let thing = Some(draft.key.payload());
    let mut children = Vec::new();
    for parts in lines {
        children.extend(
            sized(parts)
                .into_iter()
                .map(|parts| ConsolidationBranchPlan {
                    world_ref: draft.key.world,
                    facet_ref: draft.key.facet,
                    thing,
                    parts,
                }),
        );
    }
    NightlyThingPlan {
        key: draft.key,
        spans: draft.spans,
        children,
    }
}

/// `parts` cut into children of at most `CHILD_TURNS` TURNs in total, in
/// order: a part that does not fit continues in the next child.
fn sized(parts: Vec<ConversationPart>) -> Vec<Vec<ConversationPart>> {
    let mut children = Vec::new();
    let mut child = Vec::new();
    let mut size = 0_usize;
    for part in parts {
        let mut rest = part.turns.as_slice();
        while !rest.is_empty() {
            let (taken, left) = rest.split_at(rest.len().min(CHILD_TURNS - size));
            child.push(ConversationPart {
                conversation_ref: part.conversation_ref,
                turns: taken.to_vec(),
                watermark_last_learned_at: part.watermark_last_learned_at,
            });
            size += taken.len();
            rest = left;
            if size == CHILD_TURNS {
                children.push(std::mem::take(&mut child));
                size = 0;
            }
        }
    }
    if !child.is_empty() {
        children.push(child);
    }
    children
}
