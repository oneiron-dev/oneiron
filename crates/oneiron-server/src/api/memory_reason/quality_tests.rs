use super::*;

#[test]
fn evidence_keeps_the_ranked_revision_when_idle_publication_wins_the_race() {
    let dir = tempfile::tempdir().unwrap();
    let vault = oneiron::Vault::open(dir.path(), oneiron::VaultConfig::default()).unwrap();
    // First open seeds the bootstrap skills, whose activation edits wait for
    // idle publication too. Publish them so the race observes only this row.
    vault.set_indexed_idle_delay_ms(0).unwrap();
    vault.refresh_staged_indexed_at_idle(u64::MAX).unwrap();
    let id = EntityId::now();
    let subject = EntityId::now();
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
    let put = |text: &str, at: u64| {
        let body = oneiron::ClaimBody::new(
            "evidence.race",
            oneiron::ClaimSubject::Entity(subject),
            rmpv::Value::from(text),
            1.0,
            oneiron::ClaimApprovalStatus::Auto,
            oneiron::ClaimLifecycleStatus::Active,
        )
        .unwrap();
        vault
            .put_claim(&id, &body, oneiron::TimeRange { start: at, end: at }, at)
            .unwrap();
    };
    put("ranked zebra", 1);
    vault
        .batch()
        .text(&id, &[("content", "ranked zebra")])
        .commit()
        .unwrap();
    let before = vault.indexed_revision(&id).unwrap().unwrap();
    let scoped = vault.scoped_read(crate::test_credentials::host_reader(&vault));
    let mut retrieved = scoped
        .search_with_effort(&DepthSearchRequest {
            probe: SearchProbe::Text {
                query: "zebra".into(),
            },
            effort: Effort::Light,
            limit: 10,
            session_scope: None,
            lease: None,
            backend: None,
            token_budget: None,
            deadline: None,
        })
        .unwrap();
    assert_eq!(retrieved.hits.len(), 1);
    assert_eq!(retrieved.revisions.get(&id), Some(&before));
    put("published yak", 2);
    vault.set_indexed_idle_delay_ms(0).unwrap();
    assert_eq!(
        vault
            .refresh_staged_indexed_at_idle(u64::MAX)
            .unwrap()
            .refreshed
            .len(),
        1
    );
    assert_ne!(vault.indexed_revision(&id).unwrap(), Some(before));
    let evidence = collect_evidence(&vault, &scoped, &mut retrieved).unwrap();
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].text, "ranked zebra");
    assert_eq!(
        evidence[0].short_id,
        vault
            .pinned_short_ref_with_mode(&id, oneiron::memory::ReadMode::Pinned(before))
            .unwrap()
    );
}
