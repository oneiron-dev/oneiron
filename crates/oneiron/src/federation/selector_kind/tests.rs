use super::*;
use crate::federation::{
    FederationDirectionScope, FederationPactScope, ScopeAxis, decode_federation_pact_scope,
    encode_federation_pact_scope,
};
use crate::registry::ENTITY_TYPE_REGISTRY;

#[test]
fn replication_sets_do_not_change_when_bytes_move() {
    let scopes = [
        SelectorRange::Semantic,
        SelectorRange::Core,
        SelectorRange::Maintenance,
        SelectorRange::Family(TypeByteFamily::Companion),
        SelectorRange::Family(TypeByteFamily::People),
        SelectorRange::Family(TypeByteFamily::Documents),
    ];
    for scope in scopes {
        let before: Vec<_> = ENTITY_TYPE_REGISTRY
            .iter()
            .filter_map(|entry| {
                SelectorRange::for_entry(entry)
                    .filter(|identity| scope.includes(*identity))
                    .map(|_| entry.kind)
            })
            .collect();
        let after: Vec<_> = ENTITY_TYPE_REGISTRY
            .iter()
            .filter_map(|entry| {
                let moved = EntityTypeRegistryEntry {
                    type_byte: entry.type_byte.wrapping_add(113),
                    ..*entry
                };
                SelectorRange::for_entry(&moved)
                    .filter(|identity| scope.includes(*identity))
                    .map(|_| moved.kind)
            })
            .collect();
        assert_eq!(before, after);
    }
    assert_eq!(selector_range_of(255), None);
    assert_eq!(selector_range_of(128), None);
}

#[test]
fn family_scopes_roundtrip_and_obey_classification_ceiling() {
    for family in crate::registry::TYPE_BYTE_FAMILIES {
        let band = SelectorRange::Family(family.family);
        assert_eq!(SelectorRange::from_wire_name(band.wire_name()), Some(band));
        let direction = FederationDirectionScope {
            worlds: ScopeAxis::All,
            facets: ScopeAxis::All,
            bands: ScopeAxis::from_iter([band]),
        };
        let scope = FederationPactScope {
            lo_to_hi: direction.clone(),
            hi_to_lo: direction.clone(),
        };
        assert_eq!(
            decode_federation_pact_scope(&encode_federation_pact_scope(&scope).unwrap()).unwrap(),
            scope
        );
        let core = FederationDirectionScope {
            bands: ScopeAxis::from_iter([SelectorRange::Core]),
            ..direction.clone()
        };
        assert_eq!(
            direction.is_narrowing_of(&core),
            family.family.classification() == EntityClassification::Core
        );
        assert_eq!(
            direction.intersect(&core).bands,
            if family.family.classification() == EntityClassification::Core {
                direction.bands
            } else {
                ScopeAxis::Bottom
            }
        );
    }
    assert_eq!(SelectorRange::from_wire_name("crm"), None);
}

#[test]
fn classification_is_required_even_when_the_family_matches() {
    let row =
        *crate::registry::entity_type_registry_entry(crate::registry::ENTITY_TYPE_PERSON).unwrap();
    let forged = EntityTypeRegistryEntry {
        classification: EntityClassification::Pack,
        ..row
    };
    assert_eq!(SelectorRange::for_entry(&forged), None);
}
