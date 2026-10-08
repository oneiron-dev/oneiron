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
