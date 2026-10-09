//! Relationship-scope filter, demotion, and facet/world conjunction.

use super::*;

fn relationship_body(rel: Option<EntityId>) -> ClaimBody {
    let mut body = ClaimBody::new(
        "test.relationship_scope",
        crate::claim::ClaimSubject::Entity(crate::test_util::entity(0xD1)),
        rmpv::Value::from("value"),
        0.9,
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Active,
    )
    .unwrap();
    body.rel = rel;
    body
}

#[test]
fn relationship_claim_body_key_is_strict_16_byte_binary() -> Result<()> {
    let subject = entity_id(0xD6);
    let facet = crate::claim::substrate_facet_id(subject)?;
    let project = crate::claim::default_project_id();
    let base_world = crate::claim::base_world_id();
    // REQUIRED v2 stamps on every hand-built body: `worldId` is the reserved
    // base id, the facet derives from the subject, and the project is the
    // reserved default. `scopeRelationshipId` is `all` or a singleton array
    // of one 16-byte id — the legacy bare-`rel` binary shape is gone.
    let body_with_relationship = |relationship: Option<rmpv::Value>| -> Vec<u8> {
        let mut fields = vec![
            (
                rmpv::Value::from("pred"),
                rmpv::Value::from("test.relationship_scope"),
            ),
            (rmpv::Value::from("val"), rmpv::Value::from("value")),
            (rmpv::Value::from("conf"), rmpv::Value::F32(0.9)),
            (
                rmpv::Value::from("worldId"),
                rmpv::Value::Binary(base_world.as_bytes().to_vec()),
            ),
        ];
        if let Some(relationship) = relationship {
            fields.push((rmpv::Value::from("scopeRelationshipId"), relationship));
        }
        fields.extend([
            (
                rmpv::Value::from("subj"),
                rmpv::Value::Binary(subject.as_bytes().to_vec()),
            ),
            (rmpv::Value::from("appr"), rmpv::Value::from("auto")),
            (rmpv::Value::from("life"), rmpv::Value::from("active")),
            (
                rmpv::Value::from("scopeFacetId"),
                rmpv::Value::Binary(facet.as_bytes().to_vec()),
            ),
            (
                rmpv::Value::from("scopeProjectId"),
                rmpv::Value::Binary(project.as_bytes().to_vec()),
            ),
            (rmpv::Value::from("scopeVersion"), rmpv::Value::from(2_u64)),
        ]);
        let mut encoded = Vec::new();
        rmpv::encode::write_value(&mut encoded, &rmpv::Value::Map(fields))
            .expect("encode relationship claim body");
        encoded
    };
    let singleton = |id: crate::entity_id::EntityId| -> rmpv::Value {
        rmpv::Value::Array(vec![rmpv::Value::Binary(id.as_bytes().to_vec())])
    };

    let absent = crate::claim::encode_claim_body(&relationship_body(None))?;
    let decoded_absent = crate::claim::decode_claim_body(&absent, true)?;
    assert_eq!(decoded_absent.rel, None);
    let encoded_value = rmpv::decode::read_value(&mut std::io::Cursor::new(&absent))
        .expect("decode encoded relationship claim body");
    let rmpv::Value::Map(entries) = encoded_value else {
        panic!("encoded relationship claim body is a map");
    };
    assert_eq!(
        entries
            .iter()
            .find(|(key, _)| key.as_str() == Some("scopeRelationshipId"))
            .map(|(_, value)| value),
        Some(&rmpv::Value::from("all")),
        "scope-relaxed claims must stamp scopeRelationshipId=all"
    );
    assert!(
        entries
            .iter()
            .all(|(key, _)| !matches!(key.as_str(), Some("rel" | "world"))),
        "legacy rel/world keys must not appear on the wire"
    );

    let relationship = entity_id(0xD8);
    let hand_built = body_with_relationship(Some(singleton(relationship)));
    assert_eq!(
        crate::claim::decode_claim_body(&hand_built, true)?.rel,
        Some(relationship)
    );
    // The `all` string is the other legal shape for the same None.
    assert_eq!(
        crate::claim::decode_claim_body(
            &body_with_relationship(Some(rmpv::Value::from("all"))),
            true
        )?
        .rel,
        None
    );
    let round_trip = crate::claim::encode_claim_body(&relationship_body(Some(relationship)))?;
    assert_eq!(
        crate::claim::decode_claim_body(&round_trip, true)?.rel,
        Some(relationship)
    );
    // Missing scopeRelationshipId is corruption, not a relaxed claim.
    assert_matches!(
        crate::claim::decode_claim_body(&body_with_relationship(None), true),
        Err(Error::InvalidClaimBody(_))
    );
    for invalid in [
        body_with_relationship(Some(rmpv::Value::Array(vec![rmpv::Value::Binary(
            vec![0xD8; 15],
        )]))),
        body_with_relationship(Some(rmpv::Value::from("relationship"))),
        body_with_relationship(Some(rmpv::Value::Array(vec![rmpv::Value::Binary(vec![
            0;
            16
        ])]))),
        // Singleton only: zero or two ids never validate.
        body_with_relationship(Some(rmpv::Value::Array(vec![]))),
        body_with_relationship(Some(rmpv::Value::Array(vec![
            rmpv::Value::Binary(relationship.as_bytes().to_vec()),
            rmpv::Value::Binary(entity_id(0xD9).as_bytes().to_vec()),
        ]))),
        // Legacy bare-binary shape is no longer on the wire.
        body_with_relationship(Some(rmpv::Value::Binary(relationship.as_bytes().to_vec()))),
    ] {
        assert_matches!(
            crate::claim::decode_claim_body(&invalid, true),
            Err(Error::InvalidClaimBody(_))
        );
    }
    Ok(())
}
