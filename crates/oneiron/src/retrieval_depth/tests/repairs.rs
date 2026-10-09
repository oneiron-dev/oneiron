use super::*;

#[test]
fn session_scope_cannot_admit_a_hidden_document_at_any_effort() -> TestResult {
    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
    super::authorize_readers(&vault, &[READER]);
    let hidden = entity(0xB1);
    let body = ClaimBody::new(
        "facet.scope_test",
        ClaimSubject::Entity(entity(0xB2)),
        Value::from("launch"),
        0.9,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    )?;
    vault
        .batch()
        .put_replicated(
            &hidden,
            ENTITY_TYPE_CLAIM,
            range(1),
            1,
            &encode_claim_body(&body)?,
        )
        .text(&hidden, &[("body", "launch")])
        .commit()?;
    let scoped = vault.scoped_read(ScopedReadActorKey::new(READER).expect("actor key"));
    let scope = SessionScope {
        document_short_ids: vec![short_ref_or_hex(&vault, &hidden)?],
        ..SessionScope::default()
    };
    let lease = minted_lease();
    for effort in [Effort::Light, Effort::Medium, Effort::Max] {
        let backend = ScriptedBackend::new(Vec::new());
        let request = DepthSearchRequest {
            probe: SearchProbe::Text {
                query: "launch".to_owned(),
            },
            effort,
            limit: 1,
            session_scope: Some(&scope),
            lease: Some(&lease),
            backend: Some(&backend),
            deadline: None,
            token_budget: None,
        };
        assert!(scoped.search_with_effort(&request)?.hits.is_empty());
        assert_eq!(backend.calls().rerank, 0);
    }
    Ok(())
}

#[test]
fn depth_revision_is_captured_before_host_reranking_can_publish_an_edit() -> TestResult {
    struct PublishingBackend<'a> {
        vault: &'a Vault,
        id: EntityId,
        replacement: Vec<u8>,
    }
    impl DeepSearchBackend for PublishingBackend<'_> {
        fn decompose(
            &self,
            _: &str,
            _: &[String],
            _: usize,
            _: Option<u64>,
            _: &BudgetLease,
        ) -> RetrievalResult<BackendSpend<Vec<String>>> {
            Ok(BackendSpend::free(Vec::new()))
        }
        fn rerank(
            &self,
            _: &str,
            candidates: &[RerankCandidate<'_>],
            _: Option<u64>,
            _: &BudgetLease,
        ) -> RetrievalResult<BackendSpend<Vec<f32>>> {
            self.vault
                .batch()
                .put_replicated(&self.id, ENTITY_TYPE_CLAIM, range(2), 2, &self.replacement)
                .text(&self.id, &[("content", "replacement yak")])
                .commit()?;
            self.vault.refresh_staged_indexed_at_idle(u64::MAX)?;
            Ok(BackendSpend::free(vec![1.0; candidates.len()]))
        }
    }
    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
    super::authorize_readers(&vault, &[READER]);
    let (id, subject) = (entity(0x72), entity(0x73));
    // A claim revision carries its own record scope. An edited non-claim
    // revision has no digest-bound stamp left to prove its historical read.
    let claim = |value: &str| {
        encode_claim_body(&ClaimBody::new(
            "core.fact",
            ClaimSubject::Entity(subject),
            Value::from(value),
            0.9,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )?)
    };
    let body = claim("ranked zebra")?;
    vault
        .batch()
        .put_replicated(&id, ENTITY_TYPE_CLAIM, range(1), 1, &body)
        .text(&id, &[("content", "ranked zebra")])
        .commit()?;
    vault.set_indexed_idle_delay_ms(0)?;
    let before = vault.indexed_revision(&id)?.unwrap();
    let scoped = vault.scoped_read(ScopedReadActorKey::new(READER).unwrap());
    let lease = minted_lease();
    let backend = PublishingBackend {
        vault: &vault,
        id,
        replacement: claim("replacement yak")?,
    };
    let request = hosted_request("zebra", Effort::High, Some(&lease), Some(&backend));
    let result = scoped.search_with_effort(&request)?;
    assert_eq!(hit_ids(&result), vec![id]);
    assert_ne!(vault.indexed_revision(&id)?, Some(before));
    assert_eq!(result.revisions.get(&id), Some(&before));
    let pinned = scoped
        .read(
            &[crate::claim::PointRead::id(id).at(crate::vault::ReadMode::Pinned(before))],
            None,
        )?
        .single();
    assert_eq!(pinned.value.and_then(|row| row.body), Some(body));
    Ok(())
}

#[test]
fn session_world_scope_follows_the_ranked_revision_during_debounce() -> TestResult {
    use crate::vault::ReadMode;
    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
    super::authorize_readers(&vault, &[READER]);
    crate::test_util::publish_seeded_revisions(&vault);
    let (id, subject, world_a, world_b) = (entity(0xB1), entity(0xB2), entity(0xB3), entity(0xB4));
    let mut body = ClaimBody::new(
        "core.fact",
        ClaimSubject::Entity(subject),
        Value::from("world A content"),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    body.world = Some(world_a);
    vault
        .batch()
        .put_replicated(
            &id,
            ENTITY_TYPE_CLAIM,
            range(1),
            1,
            &encode_claim_body(&body)?,
        )
        .text(&id, &[("body", "scopefrontier original")])
        .commit()?;
    let old_pin = vault.indexed_revision(&id)?.expect("indexed birth");
    // A claim keeps the scope it was born with: moving it to world B by an
    // edit is refused, so the edit below stays in world A.
    body.world = Some(world_b);
    body.value = Value::from("world B content");
    assert!(matches!(
        vault
            .batch()
            .put(
                &id,
                ENTITY_TYPE_CLAIM,
                range(2),
                2,
                &encode_claim_body(&body)?,
            )
            .commit(),
        Err(crate::Error::InvalidClaimBody(
            "record scope restamp refused"
        ))
    ));
    body.world = Some(world_a);
    body.value = Value::from("world A edited");
    // A local edit retains its old indexed revision until idle publication.
    // Replicated overwrites instead remove the losing posting immediately.

    vault
        .batch()
        .put(
            &id,
            ENTITY_TYPE_CLAIM,
            range(2),
            2,
            &encode_claim_body(&body)?,
        )
        .text(&id, &[("body", "scopefrontier edited")])
        .commit()?;
    let new_pin = vault.pin_entity_revision(&id)?;
    assert_ne!(old_pin, new_pin);
    let scoped = vault.scoped_read(ScopedReadActorKey::new(READER).expect("actor key"));
    let search = |world| {
        let scope = SessionScope {
            world_ref: Some(world),
            ..Default::default()
        };
        scoped.search_with_effort(&DepthSearchRequest {
            session_scope: Some(&scope),
            ..text_request("scopefrontier", Effort::Light)
        })
    };
    assert!(search(world_b)?.hits.is_empty());
    let old_result = search(world_a)?;
    assert_eq!(hit_ids(&old_result), vec![id]);
    assert_eq!(old_result.revisions[&id], old_pin);
    let pinned = scoped
        .read(
            &[crate::claim::PointRead::id(id).at(ReadMode::Pinned(old_pin))],
            None,
        )?
        .single();
    assert!(old_result.narrowing.contains(&pinned.receipt));
    let pinned_body = pinned
        .value
        .and_then(|row| row.body)
        .expect("selected body");
    let pinned_claim = crate::claim::decode_claim_body(&pinned_body, true)?;
    assert_eq!(pinned_claim.world, Some(world_a));
    assert_eq!(pinned_claim.value, Value::from("world A content"));
    vault.set_indexed_idle_delay_ms(0)?;
    assert_eq!(
        vault.refresh_staged_indexed_at_idle(u64::MAX)?.refreshed,
        vec![(id, new_pin)]
    );
    assert!(search(world_b)?.hits.is_empty());
    let current_result = search(world_a)?;
    assert_eq!(hit_ids(&current_result), vec![id]);
    assert_eq!(current_result.revisions[&id], new_pin);
    Ok(())
}
