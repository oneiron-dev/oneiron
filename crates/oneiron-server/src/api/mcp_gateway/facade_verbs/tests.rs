use super::*;
#[test]
fn navigation_projection_rechecks_private_notes_even_if_nominated() {
    let dir = tempfile::tempdir().unwrap();
    let vault = oneiron::Vault::open(dir.path(), oneiron::VaultConfig::default()).unwrap();
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    let receipt = vault
        .memory(owner, oneiron::EdgeActorClass::Human)
        .author_note(&oneiron::note::NoteWriteEnvelope {
            kind: oneiron::note::NoteKind::parse("diary").expect("shipped kind"),
            scope: oneiron::note::NoteScope::ActorPrivate { owner_ref: owner },
            source_revision_ref: [0x75; 16],
            markdown: "private diary canary".into(),
            mask: None,
        })
        .unwrap();
    let id = oneiron::EntityId::from_hex(&receipt.id_hex).unwrap();
    let reader =
        vault.scoped_read(oneiron::claim::ScopedReadActorKey::new(owner.to_hex()).unwrap());
    let mut results = reader.search_text("private diary", 10, None).unwrap();
    let mut absent = results.clone();
    // Even a stale or overbroad nomination cannot bypass final projection.
    results.value = vec![oneiron::ScoredEntity { id, score: 1.0 }];
    let (items, receipt) = project_nav_results(&reader, results).unwrap();
    assert!(items.is_empty());
    // A privately denied NOTE is opaque-absent: its receipt must match a
    // missing id and never count it as a suppression (ONE-2110).
    absent.value = vec![oneiron::ScoredEntity {
        id: oneiron::EntityId::now(),
        score: 1.0,
    }];
    let (absent_items, absent_receipt) = project_nav_results(&reader, absent).unwrap();
    assert!(absent_items.is_empty());
    assert_eq!(receipt.suppressed_count, 0);
    assert_eq!(receipt, absent_receipt);
}

#[test]
fn navigation_projection_uses_indexed_body_while_live_edit_is_pending() {
    let dir = tempfile::tempdir().unwrap();
    let vault = oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap();
    let id = oneiron::EntityId::now();
    let subject = oneiron::EntityId::now();
    vault
        .put_entity(
            &subject,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"subject",
        )
        .unwrap();
    // A claim revision carries its own record scope. An edited non-claim
    // revision has no digest-bound stamp left to prove its historical read.
    let claim = |predicate: &str| {
        oneiron::ClaimBody::new(
            predicate,
            oneiron::ClaimSubject::Entity(subject),
            rmpv::Value::from(predicate),
            1.0,
            oneiron::ClaimApprovalStatus::Auto,
            oneiron::ClaimLifecycleStatus::Active,
        )
        .unwrap()
    };
    let at = |second| oneiron::TimeRange {
        start: second,
        end: second,
    };
    vault
        .put_claim(&id, &claim("navanchor.original"), at(1), 1)
        .unwrap();
    vault
        .batch()
        .text(&id, &[("name", "navanchor original")])
        .commit()
        .unwrap();
    vault
        .put_claim(&id, &claim("unmatched.replacement"), at(2), 2)
        .unwrap();
    let reader = vault.scoped_read(crate::test_credentials::host_reader(&vault));
    let hits = reader.search_text("navanchor", 10, None).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].id, id);
    let (items, _receipt) = project_nav_results(&reader, hits).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["label"], "navanchor.original");
    let live = reader
        .read(&[oneiron::claim::PointRead::id(id)], None)
        .unwrap()
        .single()
        .value
        .unwrap()
        .body
        .unwrap();
    let live: rmpv::Value = rmp_serde::from_slice(&live).unwrap();
    assert_eq!(live["pred"].as_str(), Some("unmatched.replacement"));
}
