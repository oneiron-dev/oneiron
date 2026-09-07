use super::*;

#[test]
fn vector_grounding_does_not_run_standard_lexical_channels() -> TestResult {
    let (_dir, vault, anchor, _, _) = seeded_vault();
    let scoped = vault.scoped_read(ScopedReadActorKey::new(READER).expect("actor key"));
    let embedding = vec![0.1; VaultConfig::default().dimensions];
    let lease = minted_lease();
    for effort in [Effort::Minimal, Effort::Standard, Effort::Deep] {
        let backend = ScriptedBackend::new(Vec::new());
        let request = DepthSearchRequest {
            probe: SearchProbe::Vector {
                embedding: embedding.clone(),
                query_text: Some("launch date".to_owned()),
            },
            effort,
            limit: 10,
            session_scope: None,
            lease: Some(&lease),
            backend: Some(&backend),
            token_budget: None,
        };
        let result = scoped.search_with_effort(&request)?;
        // There are text hits but no vectors. Grounding must not retrieve them.
        assert!(
            scoped
                .search_text("launch", 10, None)?
                .iter()
                .any(|hit| hit.id == anchor)
        );
        assert!(result.hits.is_empty(), "{effort:?}: {result:?}");
        assert!(result.queries_run.is_empty(), "{effort:?}: {result:?}");
        assert!(!result.signals_used.contains(&"subqueries".to_owned()));
        assert_eq!(
            backend.calls().decompose,
            usize::from(effort == Effort::Deep)
        );
    }
    Ok(())
}

#[test]
fn deep_passes_the_same_admitted_lease_to_every_backend_call() -> TestResult {
    let (_dir, vault, _, _, _) = seeded_vault();
    let scoped = vault.scoped_read(ScopedReadActorKey::new(READER).expect("actor key"));
    let lease = minted_lease();
    let backend = ScriptedBackend::new(vec![vec!["inventory".to_owned()], Vec::new()]);
    let request = hosted_request("launch", Effort::Deep, Some(&lease), Some(&backend));
    scoped.search_with_effort(&request)?;
    let calls = backend.calls();
    assert_eq!(calls.decompose, 2);
    assert_eq!(calls.rerank, 1);
    assert_eq!(calls.leases_seen, vec![lease; 3]);
    Ok(())
}

#[test]
fn score_fusion_ranks_expansion_and_score_improvements_before_cutoff() {
    let (first, improved, expansion, tied) = (entity(1), entity(2), entity(3), entity(4));
    let mut acc = DepthAccumulator::default();
    acc.merge(vec![
        ScoredEntity {
            id: first,
            score: 0.2,
        },
        ScoredEntity {
            id: improved,
            score: 0.1,
        },
    ]);
    acc.merge(vec![
        ScoredEntity {
            id: expansion,
            score: 0.9,
        },
        ScoredEntity {
            id: improved,
            score: 0.8,
        },
        ScoredEntity {
            id: tied,
            score: 0.8,
        },
    ]);
    acc.fuse();
    assert_eq!(acc.order, vec![expansion, improved, tied, first]);
    let result = acc.finish(2);
    assert_eq!(hit_ids(&result), vec![expansion, improved]);
    assert_eq!(result.hits[1].score, 0.8);
    assert_eq!(result.candidates_scanned, 5);
}

#[test]
fn standard_fusion_can_replace_a_saturated_direct_page() -> TestResult {
    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
    let (first, second, neighbor) = (entity(0x61), entity(0x62), entity(0x63));
    vault
        .batch()
        .put(&first, ENTITY_TYPE_PERSON, range(1), 1, b"first")
        .text(&first, &[("body", "launch")])
        .put(&second, ENTITY_TYPE_PERSON, range(1), 1, b"second")
        .text(&second, &[("body", "launch")])
        .put(&neighbor, ENTITY_TYPE_PERSON, range(1), 1, b"neighbor")
        .edge(&first, crate::edge::EdgeKind::Supports, &neighbor, 1.0)
        .edge(&second, crate::edge::EdgeKind::Supports, &neighbor, 1.0)
        .commit()?;
    let scoped = vault.scoped_read(ScopedReadActorKey::new(READER).expect("actor key"));
    let mut request = text_request("launch", Effort::Minimal);
    request.limit = 2;
    let direct = scoped.search_with_effort(&request)?;
    assert_eq!(direct.hits.len(), 2);
    assert!(!hit_ids(&direct).contains(&neighbor));
    // Scoped text uses the neutral pipeline blend, not raw BM25 scores.
    assert!(direct.hits.iter().all(|hit| hit.score == 1.0));
    request.effort = Effort::Standard;
    // Supports alone gives the neighbor 0.85: leading PPR is not enough to
    // replace a direct hit at 1.0 under actual max-score fusion.
    let supports_only = scoped.search_with_effort(&request)?;
    assert_eq!(supports_only.hits, direct.hits);

    // Distinct kinds have independent budgets. With equal seed mass and
    // neutral VAD, Supports + Mentions gives (1.0 + 0.6) * 0.85 = 1.36.
    // More weight of the same kind would normalize away, not add evidence.
    vault
        .batch()
        .edge(&first, crate::edge::EdgeKind::Mentions, &neighbor, 1.0)
        .edge(&second, crate::edge::EdgeKind::Mentions, &neighbor, 1.0)
        .commit()?;
    let expanded = scoped.search_with_effort(&request)?;
    assert_eq!(expanded.hits.len(), 2);
    assert_eq!(expanded.hits[0].id, neighbor, "{expanded:?}");
    let expected = (1.0 + 0.6) * (1.0 - STANDARD_PPR_ALPHA);
    assert!(
        (expanded.hits[0].score - expected).abs() < 1e-6,
        "{expanded:?}"
    );
    assert!(!expanded.backend_used);
    Ok(())
}

#[test]
fn graph_expansion_uses_configured_vad_alpha_at_each_effort() -> TestResult {
    let (_dir, mut vault, anchor, _, neighbor) = seeded_vault();
    vault.set_edge_vad(
        &anchor,
        crate::edge::EdgeKind::Mentions,
        &neighbor,
        crate::affect::Vad {
            valence: -1.0,
            arousal: 1.0,
            dominance: 0.0,
        },
    )?;
    let lease = minted_lease();
    for alpha in [0.0, 0.2, 0.4] {
        vault.config.ppr_vad_alpha = alpha;
        let scoped = vault.scoped_read(ScopedReadActorKey::new(READER).expect("actor key"));
        // Only the anchor matches; the neighbor's score comes solely from PPR.
        let direct = scoped.search_text("date", 10, None)?;
        assert_eq!(ids_of(&direct), vec![anchor]);
        for effort in [Effort::Minimal, Effort::Standard, Effort::Deep] {
            let backend = ScriptedBackend::new(Vec::new());
            let request = hosted_request("date", effort, Some(&lease), Some(&backend));
            let result = scoped.search_with_effort(&request)?;
            if effort == Effort::Minimal {
                assert_eq!(result.hits, direct);
                assert!(!result.signals_used.contains(&"ppr".to_owned()));
            } else {
                let hit = result
                    .hits
                    .iter()
                    .find(|hit| hit.id == neighbor)
                    .expect("one-hop neighbor");
                let expected = 0.6 * (1.0 + alpha) * (1.0 - STANDARD_PPR_ALPHA);
                assert!(
                    (hit.score - expected).abs() < 1e-6,
                    "{effort:?}, alpha={alpha}: {hit:?}, expected {expected}"
                );
            }
            assert_eq!(result.backend_used, effort == Effort::Deep);
            assert_eq!(result.tokens_used, 0);
        }
    }
    Ok(())
}

#[test]
fn session_scope_precedes_text_topk_and_deep_candidate_bodies() -> TestResult {
    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
    let (outside, inside, extra) = (entity(0x71), entity(0x72), entity(0x73));
    let (world, other_world, facet) = (entity(0x74), entity(0x75), entity(0x76));
    vault
        .batch()
        .put(
            &facet,
            crate::registry::ENTITY_TYPE_FACET,
            range(1),
            1,
            b"facet",
        )
        .commit()?;
    for (id, claim_world, text) in [
        (outside, other_world, "launch remote"),
        (inside, world, "launch archive context detail record"),
        (extra, world, "inventory"),
    ] {
        let mut body = ClaimBody::new(
            "facet.scope_test",
            ClaimSubject::Entity(entity(0x77)),
            Value::from(text),
            0.9,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        body.world = Some(claim_world);
        vault
            .batch()
            .put_replicated(
                &id,
                ENTITY_TYPE_CLAIM,
                range(1),
                1,
                &encode_claim_body(&body)?,
            )
            .text(&id, &[("body", text)])
            .commit()?;
    }
    vault
        .batch()
        .edge(&inside, crate::edge::EdgeKind::FacetOf, &facet, 1.0)
        .edge(&inside, crate::edge::EdgeKind::Mentions, &outside, 1.0)
        .commit()?;
    let scoped = vault.scoped_read(ScopedReadActorKey::new(READER).expect("actor key"));
    assert_eq!(scoped.search_text("launch", 1, None)?[0].id, outside);
    let scopes = [
        SessionScope {
            world_ref: Some(world),
            ..SessionScope::default()
        },
        SessionScope {
            facet_ref: Some(facet),
            ..SessionScope::default()
        },
        SessionScope {
            document_short_ids: vec![short_ref_or_hex(&vault, &inside)?],
            ..SessionScope::default()
        },
    ];
    let lease = minted_lease();
    for scope in &scopes {
        for effort in [Effort::Minimal, Effort::Standard, Effort::Deep] {
            // The deep query can find an out-of-scope body; it must be filtered too.
            let backend = ScriptedBackend::new(vec![vec!["remote".to_owned()], Vec::new()]);
            let request = DepthSearchRequest {
                probe: SearchProbe::Text {
                    query: "launch".to_owned(),
                },
                effort,
                limit: 1,
                session_scope: Some(scope),
                lease: Some(&lease),
                backend: Some(&backend),
                token_budget: None,
            };
            let result = scoped.search_with_effort(&request)?;
            assert_eq!(hit_ids(&result), vec![inside], "{effort:?}, {scope:?}");
            if effort == Effort::Deep {
                assert_eq!(backend.calls().candidate_ids, vec![inside]);
            }
        }
    }
    Ok(())
}

#[test]
fn session_scope_precedes_vector_topk() -> TestResult {
    let config = VaultConfig {
        dimensions: 4,
        embedding_model: Some("scope/test@v1".to_owned()),
        ..VaultConfig::default()
    };
    let (_dir, vault) = open_test_vault_with(config);
    let (outside, inside) = (entity(0x81), entity(0x82));
    vault
        .batch()
        .put(&outside, ENTITY_TYPE_PERSON, range(1), 1, b"outside")
        .vector(&outside, &[1.0, 0.0, 0.0, 0.0])
        .put(&inside, ENTITY_TYPE_PERSON, range(1), 1, b"inside")
        .vector(&inside, &[0.8, 0.2, 0.0, 0.0])
        .commit()?;
    let scoped = vault.scoped_read(ScopedReadActorKey::new(READER).expect("actor key"));
    let embedding = vec![1.0, 0.0, 0.0, 0.0];
    assert_eq!(scoped.search_vector(&embedding, 1, None)?[0].id, outside);
    let scope = SessionScope {
        document_short_ids: vec![short_ref_or_hex(&vault, &inside)?],
        ..SessionScope::default()
    };
    let request = DepthSearchRequest {
        probe: SearchProbe::Vector {
            embedding,
            query_text: None,
        },
        effort: Effort::Minimal,
        limit: 1,
        session_scope: Some(&scope),
        lease: None,
        backend: None,
        token_budget: None,
    };
    assert_eq!(hit_ids(&scoped.search_with_effort(&request)?), vec![inside]);
    Ok(())
}

#[test]
fn standard_specificity_ignores_unreadable_inbound_mentions() -> TestResult {
    let (_dir, vault, anchor, sibling, neighbor) = seeded_vault();
    let scoped = vault.scoped_read(ScopedReadActorKey::new(READER).expect("actor key"));
    let request = text_request("launch", Effort::Standard);
    let baseline = scoped.search_with_effort(&request)?;
    assert!(hit_ids(&baseline).contains(&neighbor));
    for byte in [0x91, 0x92, 0x93] {
        let hidden = entity(byte);
        let body = ClaimBody::new(
            "facet.scope_test",
            ClaimSubject::Entity(sibling),
            Value::from("unreadable mention"),
            0.9,
            ClaimApprovalStatus::Proposed,
            ClaimLifecycleStatus::Active,
        );
        vault
            .batch()
            .put_replicated(
                &hidden,
                ENTITY_TYPE_CLAIM,
                range(1),
                1,
                &encode_claim_body(&body)?,
            )
            .edge(&hidden, crate::edge::EdgeKind::Mentions, &anchor, 1.0)
            .commit()?;
        assert!(scoped.get(&hidden)?.is_none());
    }
    let after = scoped.search_with_effort(&request)?;
    assert_eq!(
        after, baseline,
        "hidden edges must not change visible scores or order"
    );
    Ok(())
}

#[test]
fn session_scope_cannot_admit_a_hidden_document_at_any_effort() -> TestResult {
    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
    let hidden = entity(0xB1);
    let body = ClaimBody::new(
        "facet.scope_test",
        ClaimSubject::Entity(entity(0xB2)),
        Value::from("launch"),
        0.9,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    );
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
    for effort in [Effort::Minimal, Effort::Standard, Effort::Deep] {
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
            token_budget: None,
        };
        assert!(scoped.search_with_effort(&request)?.hits.is_empty());
        assert_eq!(backend.calls().rerank, 0);
    }
    Ok(())
}
