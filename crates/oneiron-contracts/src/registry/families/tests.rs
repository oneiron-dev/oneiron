use super::*;

#[test]
fn allocation_uses_lowest_gap_then_zone_overflow() {
    assert_eq!(
        allocate_type_byte(TypeByteFamily::Conversation, &[7, 9]),
        Some(6)
    );
    assert_eq!(
        allocate_type_byte(TypeByteFamily::People, &[14, 16]),
        Some(15)
    );
    assert_eq!(
        allocate_type_byte(TypeByteFamily::Conversation, &[6, 7, 8, 9, 50]),
        Some(51)
    );
    assert_eq!(
        allocate_type_byte(TypeByteFamily::Documents, &[112, 113, 114, 120]),
        Some(121)
    );
    assert_eq!(
        allocate_type_byte(TypeByteFamily::AuthorityPolicyCustody, &[69, 70, 71]),
        None
    );
    assert_eq!(
        allocate_type_byte(TypeByteFamily::Documents, &(100..=125).collect::<Vec<_>>()),
        None
    );
}

#[test]
fn declared_families_and_prefixes_survive_relocation() {
    for row in ENTITY_TYPE_REGISTRY {
        assert_eq!(family_of(row.type_byte), row.family);
        if let Some(family) = row.family {
            assert_eq!(family.classification(), row.classification);
            let moved = EntityTypeRegistryEntry {
                type_byte: 50,
                ..*row
            };
            assert!(family_matches(&moved, family));
            assert_eq!(moved.short_id_prefix, row.short_id_prefix);
        }
    }
    for byte in 128..=247 {
        assert_eq!(family_of(byte), None);
    }
}
