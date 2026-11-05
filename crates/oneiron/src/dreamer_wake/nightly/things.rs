//! One nightly thing per entity or topic (OF-498c, ARCH-0026 Nightly). The
//! spans a night spends group by thing: its world, its facet, its private
//! audience identity, and the entity a span's reading bound, else the
//! structural topic. No conversation is in the key, so a thing may span
//! conversations. Private threads whose whole current audiences name the
//! same live PERSON share a thing; unresolved or group audiences stay per
//! thread. Every actual reader and exposure boundary stays per part.
//!
//! Each spent span is its OWN bound entity's (FIX 8723): a TURN whose spans
//! bind several entities lands in each of their things, so no entity loses
//! its thing or the neighbourhood its child reads. An unbound span rides
//! with its TURN's highest scored bound entity, and a TURN none of whose
//! spans is bound is its partition's topic's. Each thing is one child per
//! project it is read in (FIX 8724, `slices`), so each child lists its own
//! project's priors: every conversation it appears in is one part, and the
//! lines its parts are sliced in keep each exposure boundary inside the
//! child, where a slice never crosses one. Each child names its thing in
//! its payload. Nothing is dropped, and the number of entities, things or
//! conversations is not bounded.

use std::collections::BTreeMap;

use super::exposure::Exposure;
use crate::dreamer_consolidation::{
    ConsolidationBranchPlan, ConsolidationPartitionKey, ConsolidationPartitionPlan,
    PartitionAudience, PartitionThing, WorkingSetTurn,
};
use crate::dreamer_wake::sieve::SieveSpan;
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_PERSON};
use crate::{EntityId, Result, Vault};

mod slices;

/// What one nightly thing is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct NightlyThingKey {
    pub(super) world: Option<EntityId>,
    pub(super) facet: Option<EntityId>,
    /// One PERSON named by the whole private audience, else its thread;
    /// `None` off any private thread. Never a reader set or a grant.
    pub(super) audience: Option<PartitionAudience>,
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
    /// Every spent span that is this thing's, in queue order.
    pub(super) spans: Vec<SieveSpan>,
    /// The thing's TURNs as branches over its conversation parts, one per
    /// project they are read in (a part of no known project on its own), in
    /// the partitions' spending order, each part on its slice line (FIX
    /// 8724).
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
        room: EntityId,
        names_audience: bool,
    },
    Unread,
}

/// Each planned TURN's private grouping identity. A private thread's whole
/// current audience may name one live PERSON, directly or through native
/// pen subject anchors; otherwise its root keeps it separate. Public turns
/// keep no private identity. Unread bindings stay separate by TURN as before.
pub(super) fn audiences_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    partitions: &[ConsolidationPartitionPlan],
) -> Result<BTreeMap<EntityId, Option<PartitionAudience>>> {
    let mut roots = BTreeMap::new();
    let mut people = BTreeMap::new();
    let mut audiences = BTreeMap::new();
    for turn in partitions.iter().flat_map(|partition| &partition.turns) {
        let audience = match thread_in(vault, txn, &turn.turn_id)? {
            Thread::Trunk => None,
            Thread::Unread => Some(PartitionAudience::Thread(turn.turn_id)),
            Thread::Of {
                root,
                room,
                names_audience,
            } => {
                let private = if root == turn.turn_id {
                    names_audience
                } else {
                    root_private_in(vault, txn, root, &mut roots)?
                };
                if private {
                    let person = people.entry(root).or_insert_with(|| {
                        audience_person_in(vault, txn, room, root).unwrap_or_default()
                    });
                    Some(
                        (*person)
                            .map_or(PartitionAudience::Thread(root), PartitionAudience::Person),
                    )
                } else {
                    None
                }
            }
        };
        audiences.insert(turn.turn_id, audience);
    }
    Ok(audiences)
}

/// A grouping key only: failure leaves the existing thread identity intact.
/// Actual CONTENT eligibility and reader equality stay in `exposure`/`slices`.
fn audience_person_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    root: EntityId,
) -> Result<Option<EntityId>> {
    let Some(audience) = crate::workspace_roster::thread_audience_now_in(vault, txn, room, root)?
    else {
        return Ok(None);
    };
    let at = crate::ports::job_recorded_at_in_txn(&vault.store, txn)?;
    let mut person = None;
    for member in audience {
        if !crate::vault::live_entity_row_in_txn(&vault.store, txn, &member)?.is_live() {
            return Ok(None);
        }
        let subject = match vault.get_entity_type_in_txn(txn, &member)? {
            Some(ENTITY_TYPE_PERSON) => member,
            Some(ENTITY_TYPE_AGENT_DEF) => {
                let Some(anchor) =
                    crate::subject_model::actor_subject_anchor_in_txn(vault, txn, &member, at)?
                else {
                    return Ok(None);
                };
                if anchor.subject_kind != crate::write_envelope::subject_record::SubjectKind::Person
                {
                    return Ok(None);
                }
                anchor.subject_ref
            }
            _ => return Ok(None),
        };
        if vault.get_entity_type_in_txn(txn, &subject)? != Some(ENTITY_TYPE_PERSON)
            || !crate::vault::live_entity_row_in_txn(&vault.store, txn, &subject)?.is_live()
            || person.is_some_and(|prior| prior != subject)
        {
            return Ok(None);
        }
        person = Some(subject);
    }
    Ok(person)
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
            room: binding.room,
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
    audiences: &BTreeMap<EntityId, Option<PartitionAudience>>,
    exposures: &BTreeMap<EntityId, Option<Exposure>>,
) -> Vec<NightlyThingPlan> {
    let homes = turn_homes(partitions, spans);
    let audience = |turn: &EntityId| audiences.get(turn).copied().flatten();
    let mut slots = BTreeMap::new();
    let mut drafts = Vec::new();
    for span in spans.iter().filter(|span| span.owed.is_empty()) {
        if let Some(home) = homes.get(&span.turn) {
            let key = thing_key(
                &partitions[home.partition].key,
                audience(&span.turn),
                home.thing_of(span),
            );
            let at = slot(&mut slots, &mut drafts, key);
            drafts[at].spans.push(span.clone());
        }
    }
    for (index, partition) in partitions.iter().enumerate() {
        for turn in &partition.turns {
            let bound = homes
                .get(&turn.turn_id)
                .map_or(&[][..], |home| home.entities.as_slice());
            // Each entity its spans bind holds it; with none, its topic does.
            let entities: Vec<Option<EntityId>> = if bound.is_empty() {
                vec![None]
            } else {
                bound.iter().copied().map(Some).collect()
            };
            for entity in entities {
                let key = thing_key(&partition.key, audience(&turn.turn_id), entity);
                let at = slot(&mut slots, &mut drafts, key);
                drafts[at].turns.entry(index).or_default().push(*turn);
            }
        }
    }
    drafts
        .into_iter()
        .map(|draft| slices::cut(partitions, draft, exposures))
        .collect()
}

fn thing_key(
    partition: &ConsolidationPartitionKey,
    audience: Option<PartitionAudience>,
    entity: Option<EntityId>,
) -> NightlyThingKey {
    NightlyThingKey {
        world: partition.world_ref,
        facet: partition.facet_ref,
        audience,
        entity,
    }
}

/// Where a planned TURN sits: its partition, by index, and every entity its
/// spent spans bind, highest scored first. None bound is the structural
/// topic.
struct Home {
    partition: usize,
    entities: Vec<EntityId>,
}

impl Home {
    /// The thing `span`, one of this TURN's, is spent in: its own bound
    /// entity's; an unbound span's, its TURN's highest scored bound entity,
    /// else its topic (`None`).
    fn thing_of(&self, span: &SieveSpan) -> Option<EntityId> {
        span.entity.or_else(|| self.entities.first().copied())
    }
}

/// Each planned TURN's [`Home`].
fn turn_homes(
    partitions: &[ConsolidationPartitionPlan],
    spans: &[SieveSpan],
) -> BTreeMap<EntityId, Home> {
    let mut homes = BTreeMap::new();
    for (index, partition) in partitions.iter().enumerate() {
        for turn in &partition.turns {
            homes.insert(
                turn.turn_id,
                Home {
                    partition: index,
                    entities: Vec::new(),
                },
            );
        }
    }
    for span in spans.iter().filter(|span| span.owed.is_empty()) {
        if let Some(home) = homes.get_mut(&span.turn)
            && let Some(entity) = span.entity
            && !home.entities.contains(&entity)
        {
            home.entities.push(entity);
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
