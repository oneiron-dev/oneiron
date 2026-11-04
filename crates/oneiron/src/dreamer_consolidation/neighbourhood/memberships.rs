//! Relationship units named by a listed PERSON's admitted membership claims.

use super::{KnownEntity, ListedRows, MembershipPins, document_version};
use crate::claim::{ClaimSubject, ScopedRead, claim_surfaceable, decode_claim_body};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON, ENTITY_TYPE_RELATIONSHIP};
use crate::settings::ReadDestination;
use crate::{EntityId, Result, Vault};
use oneiron_model::llm::{Scope, ScopeResource};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq)]
pub(super) struct KnownMembership {
    pub(super) unit: EntityId,
    pub(super) binding: EntityId,
    binding_version: ScopeResource,
    unit_version: ScopeResource,
}

impl super::Neighbourhood {
    pub(in crate::dreamer_consolidation) fn membership_versions(
        &self,
    ) -> impl Iterator<Item = (EntityId, &ScopeResource)> {
        self.entities.iter().flat_map(|entity| {
            entity.memberships.iter().flat_map(|membership| {
                [
                    (membership.binding, &membership.binding_version),
                    (membership.unit, &membership.unit_version),
                ]
            })
        })
    }
}

impl super::pages::ListingPage<'_> {
    pub(in crate::dreamer_consolidation) fn member_relationships(
        &self,
    ) -> impl Iterator<Item = EntityId> + '_ {
        self.entities()
            .iter()
            .flat_map(|(entity, _)| entity.memberships.iter().map(|membership| membership.unit))
    }

    /// Backing claims for the relationship units already named in the label map.
    pub(in crate::dreamer_consolidation) fn membership_bindings(
        &self,
    ) -> impl Iterator<Item = EntityId> + '_ {
        self.entities().iter().flat_map(|(entity, _)| {
            entity
                .memberships
                .iter()
                .map(|membership| membership.binding)
        })
    }
}

/// Read through the listing's real reader, not the principal's private
/// authority context. A replay uses only the binding/unit pairs it pinned.
pub(super) fn capture_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    read: &ScopedRead<'_>,
    entities: &mut [KnownEntity],
    bound: Option<&Scope>,
    destination: &ReadDestination,
    pinned: Option<&BTreeMap<EntityId, MembershipPins>>,
    gone: &mut BTreeSet<EntityId>,
) -> Result<ListedRows> {
    let persons: BTreeSet<_> = entities
        .iter()
        .filter(|entity| entity.kind == ENTITY_TYPE_PERSON)
        .map(|entity| entity.id)
        .collect();
    if persons.is_empty() {
        return Ok(Vec::new());
    }
    let ids = match pinned {
        Some(pinned) => persons
            .iter()
            .filter_map(|person| pinned.get(person))
            .flatten()
            .map(|(_, binding)| *binding)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        None => crate::claim::claim_ids_for_predicate_in_txn(
            &vault.store,
            txn,
            crate::claim::relationship_predicates::PREDICATE_RELATIONSHIP_PERSON_REF,
        )?,
    };
    #[cfg(feature = "sync")]
    let device_only = crate::settings::device_local_worlds_for(vault, txn, destination)?;
    #[cfg(not(feature = "sync"))]
    let device_only = {
        let _ = destination;
        BTreeSet::new()
    };
    let mut bindings = Vec::new();
    for (id, row) in ids
        .iter()
        .copied()
        .zip(read.get_entities_parts_in_txn(txn, &ids)?)
    {
        let Some(row) = row else {
            if pinned.is_some() {
                gone.insert(id);
            }
            continue;
        };
        if row.0 != ENTITY_TYPE_CLAIM {
            continue;
        }
        let Ok(body) = decode_claim_body(&row.2, true) else {
            continue;
        };
        if body.predicate
            != crate::claim::relationship_predicates::PREDICATE_RELATIONSHIP_PERSON_REF
            || !claim_surfaceable(&body)
            || body.world.is_some_and(|world| device_only.contains(&world))
            || !crate::gate::claim_critical_confirm_settled_in_txn(&vault.store, txn, &id)?
            || !crate::vault::live_entity_row_in_txn(&vault.store, txn, &id)?.is_live()
        {
            continue;
        }
        let Some(person) = body
            .value
            .as_str()
            .and_then(|value| EntityId::from_hex(value).ok())
        else {
            continue;
        };
        let ClaimSubject::Entity(unit) = body.subject else {
            continue;
        };
        if !persons.contains(&person)
            || pinned.is_some_and(|pinned| {
                !pinned
                    .get(&person)
                    .is_some_and(|pairs| pairs.contains(&(unit, id)))
            })
        {
            continue;
        }
        let version = document_version(id, &row.2);
        if bound.is_some_and(|bound| !bound.allows_read(&version)) {
            continue;
        }
        bindings.push((person, unit, id, version, row));
    }
    let units: Vec<_> = bindings
        .iter()
        .map(|(_, unit, _, _, _)| *unit)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut admitted_units = BTreeMap::new();
    for (unit, row) in units
        .iter()
        .copied()
        .zip(read.get_entities_parts_in_txn(txn, &units)?)
    {
        let Some(row) = row else {
            if pinned.is_some() {
                gone.insert(unit);
            }
            continue;
        };
        if row.0 != ENTITY_TYPE_RELATIONSHIP
            || crate::vault::live_entity_row_in_txn(&vault.store, txn, &unit)?.live_type()
                != Some(ENTITY_TYPE_RELATIONSHIP)
        {
            continue;
        }
        let version = document_version(unit, &row.2);
        if bound.is_some_and(|bound| !bound.allows_read(&version)) {
            continue;
        }
        admitted_units.insert(unit, (version, row));
    }
    let mut rows = BTreeMap::new();
    for (person, unit, binding, binding_version, binding_row) in bindings {
        let Some((unit_version, unit_row)) = admitted_units.get(&unit) else {
            continue;
        };
        if let Some(entity) = entities.iter_mut().find(|entity| entity.id == person) {
            entity.memberships.push(KnownMembership {
                unit,
                binding,
                binding_version,
                unit_version: unit_version.clone(),
            });
            rows.insert(binding, binding_row);
            rows.entry(unit).or_insert_with(|| unit_row.clone());
        }
    }
    Ok(rows.into_iter().collect())
}
