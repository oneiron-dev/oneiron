//! The engine's person mint (FIX 7506, ARCH-0026 row 1): a reply declares a
//! person it names as `new:P<n>`, never with an id. Each declaration binds
//! once per reply, before any candidate is read, to an id the engine
//! derives, and every candidate naming that label reads that one id.
//!
//! The id is `EntityId::derive` under [`DREAMER_PERSON`] over the parent
//! extraction namespace (the nightly parent when the attempt has one, so
//! its children and retry chunks share it; else the first try of the
//! attempt's retry lineage, so a fresh `retry_of` try keeps the ids its
//! original minted, FIX 7579), the
//! exposure axes the source is admitted under, the normalized name, and
//! the declaration's canonical mention anchor: the smallest of its sources,
//! with the byte range of the name's first exact occurrence in the text the
//! call showed of it, when it occurs there. Nothing is random or clocked;
//! no two mentions merge by name alone. A replay of the same reply under
//! the same call binds the same ids.
//!
//! A declaration that cannot bind (a name the writer refuses, a source
//! label the call did not show) binds nothing, and a candidate naming it is
//! skipped as `PersonBindingUnavailable`. Whether a bound person is written
//! stays the writer's (`super::mint_extracted_people`).

use std::collections::{BTreeMap, BTreeSet};

use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::dreamer_consolidation::call_labels::{CallSources, new_person};
use crate::dreamer_consolidation::executor::extraction::ExtractedPerson;
use crate::dreamer_consolidation::support::invalid_consolidation;
use crate::entity_id::derived_domains::DREAMER_PERSON;
use crate::error::Result;
use crate::{EntityId, Vault};

/// Where one extraction's people are minted: the parent extraction it
/// belongs to and the exposure axes its sources are admitted under. The
/// project is each anchor source's own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::dreamer_consolidation) struct MintNamespace {
    extraction: AttemptId,
    world: Option<EntityId>,
    facet: Option<EntityId>,
    relationship: Option<EntityId>,
}

impl MintNamespace {
    /// The namespace of an attempt whose queued parent is `parent`: that
    /// parent's when it has one, else `attempt`'s own; a caller passes the
    /// first try of its retry lineage ([`original_try`]) as `attempt`.
    pub(in crate::dreamer_consolidation) fn new(
        attempt: AttemptId,
        parent: Option<AttemptId>,
        world: Option<EntityId>,
        facet: Option<EntityId>,
        relationship: Option<EntityId>,
    ) -> Self {
        Self {
            extraction: parent.unwrap_or(attempt),
            world,
            facet,
            relationship,
        }
    }

    /// The namespace's bytes, as a request's label binding names them.
    pub(in crate::dreamer_consolidation) fn identity(&self) -> Vec<u8> {
        let mut bytes = self.extraction.as_bytes().to_vec();
        for axis in [self.world, self.facet, self.relationship] {
            bytes.extend(optional(axis));
        }
        bytes
    }
}

/// The try `attempt`'s retry lineage began at (FIX 7579): `attempt` itself
/// when it retries none. Each `retry_of` hop is followed while its row
/// reads, so every try of one lineage names the same first try, and the
/// people a reply declares in the original and in a fresh retry bind one
/// id. A compaction relinks `retry_of` past the tries it folds; a lineage
/// whose first try it folded begins at its oldest kept try. A cycle ends
/// where it closes.
///
/// # Errors
///
/// The queue's read errors.
pub(in crate::dreamer_consolidation) fn original_try(
    vault: &Vault,
    attempt: AttemptId,
) -> Result<AttemptId> {
    let queue = AttemptQueue::new(vault);
    let txn = vault.store.env.read_txn()?;
    let mut seen = BTreeSet::from([*attempt.as_bytes()]);
    let mut first = attempt;
    while let Some(record) = queue.get_in_txn(&txn, first)? {
        let Some(previous) = record.retry_of else {
            break;
        };
        if !seen.insert(*previous.as_bytes()) {
            break;
        }
        first = previous;
    }
    Ok(first)
}

/// One declaration's binding.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PersonBinding {
    Bound(BoundPerson),
    Unavailable,
}

/// A declared person the engine bound an id to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::dreamer_consolidation) struct BoundPerson {
    /// The id the engine derived.
    pub(in crate::dreamer_consolidation) id: EntityId,
    /// The name as the reply wrote it, trimmed.
    pub(in crate::dreamer_consolidation) name: String,
    /// The sources its declaration names, in id order.
    pub(in crate::dreamer_consolidation) sources: Vec<EntityId>,
}

/// Every person one reply declares, by its `new:P<n>` number.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(in crate::dreamer_consolidation) struct PersonBindings {
    declared: BTreeMap<usize, PersonBinding>,
}

impl PersonBindings {
    /// The id a candidate naming `new:P<number>` takes; refused as
    /// `PersonBindingUnavailable` when the reply declared no such person or
    /// its declaration bound no id.
    pub(in crate::dreamer_consolidation) fn subject(&self, number: usize) -> Result<EntityId> {
        match self.declared.get(&number) {
            Some(PersonBinding::Bound(person)) => Ok(person.id),
            _ => Err(invalid_consolidation(
                "extracted candidate's declared person bound no id (PersonBindingUnavailable)",
            )),
        }
    }

    /// The people bound, in declaration-number order.
    pub(in crate::dreamer_consolidation) fn bound(&self) -> impl Iterator<Item = &BoundPerson> {
        self.declared.values().filter_map(|binding| match binding {
            PersonBinding::Bound(person) => Some(person),
            PersonBinding::Unavailable => None,
        })
    }
}

/// Binds each of `persons` through its call's `sources` under `namespace`.
/// A label declared twice binds by its first declaration; a later one is
/// not read, as a second mint of one id was a no-op before.
pub(in crate::dreamer_consolidation) fn bind_people(
    persons: &[ExtractedPerson],
    sources: &dyn CallSources,
    namespace: &MintNamespace,
) -> PersonBindings {
    let mut declared = BTreeMap::new();
    for person in persons {
        let Some(number) = new_person(&person.id) else {
            continue;
        };
        declared
            .entry(number)
            .or_insert_with(|| bind_one(person, sources, namespace));
    }
    PersonBindings { declared }
}

fn bind_one(
    person: &ExtractedPerson,
    sources: &dyn CallSources,
    namespace: &MintNamespace,
) -> PersonBinding {
    let name = person.name.trim();
    let normalized = super::normalize_name_span(name);
    if name.is_empty() || !normalized.chars().any(char::is_alphabetic) {
        return PersonBinding::Unavailable;
    }
    let mut named = Vec::with_capacity(person.evidence_turn_refs.len());
    for label in &person.evidence_turn_refs {
        let Some(source) = sources.named(label) else {
            return PersonBinding::Unavailable;
        };
        named.push(source);
    }
    named.sort_unstable_by_key(|(id, _)| *id);
    named.dedup_by_key(|(id, _)| *id);
    let Some((anchor, shown)) = named.first() else {
        return PersonBinding::Unavailable;
    };
    let range = shown
        .text
        .and_then(|text| text.find(name).map(|start| (start, start + name.len())));
    let range = range.map_or_else(Vec::new, |(start, end)| {
        let mut bytes = vec![1];
        bytes.extend_from_slice(&(start as u64).to_be_bytes());
        bytes.extend_from_slice(&(end as u64).to_be_bytes());
        bytes
    });
    let (world, facet, relationship, project) = (
        optional(namespace.world),
        optional(namespace.facet),
        optional(namespace.relationship),
        optional(shown.project),
    );
    let parts: [&[u8]; 8] = [
        namespace.extraction.as_bytes(),
        &world,
        &facet,
        &relationship,
        &project,
        normalized.as_bytes(),
        anchor.as_bytes(),
        &range,
    ];
    match EntityId::derive(DREAMER_PERSON, &parts) {
        Ok(id) => PersonBinding::Bound(BoundPerson {
            id,
            name: name.to_owned(),
            sources: named.iter().map(|(id, _)| *id).collect(),
        }),
        Err(_) => PersonBinding::Unavailable,
    }
}

/// An optional axis as a derive part: empty when absent, `0x01` and its
/// bytes when present.
fn optional(id: Option<EntityId>) -> Vec<u8> {
    id.map_or_else(Vec::new, |id| [&[1_u8][..], &id.as_bytes()[..]].concat())
}
