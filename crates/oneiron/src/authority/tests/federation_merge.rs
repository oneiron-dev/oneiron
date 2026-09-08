//! Federation DAG merges, grant divergence healing and tiebreaks.

use super::support::*;
use super::*;

struct LifecycleDag {
    fixture: PactFixture,
    entries: Vec<AuthorityLogEntry>,
    pact_two: [u8; 32],
    pact_three: [u8; 32],
    pact_four: [u8; 32],
    pact_five: [u8; 32],
    pact_six: [u8; 32],
    grant_four_a: EntityId,
    grant_four_b: EntityId,
    grant_six: [EntityId; 3],
    low_scope: FederationPactScope,
    low_digest: [u8; 32],
    scope_three: FederationPactScope,
    digest_three: [u8; 32],
}

/// Seventeen-entry lifecycle+device DAG exercising the merge shapes:
/// concurrent narrows (intersection incl. band ⊥), concurrent divergent
/// repacts (Suspended), Disconnect vs higher-epoch repact (terminal wins),
/// concurrent Connects binding one pact id to two grants (Suspended, both
/// grants denied), one grant bound to TWO pacts (activation folds over
/// every binding — an Active second pact must not mask a suspended one),
/// and a THREE-way binding divergence (heal target = global lex-min under
/// every merge tree).
fn lifecycle_dag() -> LifecycleDag {
    let facet = scope_entity;
    let fixture = pact_fixture_with_scope(
        200,
        symmetric_scope(
            crate::federation::FederationScopeFacets::Some(vec![
                facet(0x21),
                facet(0x22),
                facet(0x23),
            ]),
            crate::federation::FederationScopeBands::All,
        ),
    );
    let genesis_hash = authority_entry_hash(&fixture.genesis).unwrap();
    let connect = lifecycle_entry(&fixture, vec![genesis_hash], 1, connect_action(&fixture));
    let connect_hash = authority_entry_hash(&connect).unwrap();
    let narrow_left = lifecycle_entry(
        &fixture,
        vec![connect_hash],
        2,
        narrow_action_with(
            &fixture,
            fixture.pact_id,
            fixture.grant_ref,
            1,
            FederationDirectionScope {
                worlds: crate::federation::FederationScopeWorlds::All,
                facets: crate::federation::FederationScopeFacets::Some(vec![
                    facet(0x21),
                    facet(0x22),
                ]),
                bands: crate::federation::FederationScopeBands::Some(vec![SelectorRange::Semantic]),
            },
        ),
    );
    let narrow_right = lifecycle_entry(
        &fixture,
        vec![connect_hash],
        3,
        narrow_action_with(
            &fixture,
            fixture.pact_id,
            fixture.grant_ref,
            1,
            FederationDirectionScope {
                worlds: crate::federation::FederationScopeWorlds::All,
                facets: crate::federation::FederationScopeFacets::Some(vec![
                    facet(0x22),
                    facet(0x23),
                ]),
                bands: crate::federation::FederationScopeBands::Some(vec![SelectorRange::Core]),
            },
        ),
    );
    let enroll = enroll_entry(
        fixture.vault_id,
        &fixture.genesis,
        &fixture.owner,
        210,
        4,
        50,
    );

    let pact_two = [0xB2; 32];
    let grant_two = scope_entity(0x32);
    let scope_two = symmetric_scope(
        crate::federation::FederationScopeFacets::All,
        crate::federation::FederationScopeBands::All,
    );
    let connect_two = lifecycle_entry(
        &fixture,
        vec![connect_hash],
        5,
        connect_action_with(&fixture, pact_two, grant_two, &scope_two, [0x71; 16]),
    );
    let connect_two_hash = authority_entry_hash(&connect_two).unwrap();
    let left_scope = symmetric_scope(
        crate::federation::FederationScopeFacets::Some(vec![facet(0x21)]),
        crate::federation::FederationScopeBands::All,
    );
    let left_nonce = [0x72; 16];
    let repact_left = lifecycle_entry(
        &fixture,
        vec![connect_two_hash],
        6,
        repact_action_with(&fixture, pact_two, grant_two, 2, &left_scope, left_nonce),
    );
    let right_scope = symmetric_scope(
        crate::federation::FederationScopeFacets::Some(vec![facet(0x22)]),
        crate::federation::FederationScopeBands::All,
    );
    let right_nonce = [0x73; 16];
    let repact_right = lifecycle_entry(
        &fixture,
        vec![connect_two_hash],
        7,
        repact_action_with(&fixture, pact_two, grant_two, 2, &right_scope, right_nonce),
    );
    let left_digest = scope_digest_for(&left_scope, &left_nonce);
    let right_digest = scope_digest_for(&right_scope, &right_nonce);
    let (low_scope, low_digest) = if left_digest < right_digest {
        (left_scope, left_digest)
    } else {
        (right_scope, right_digest)
    };

    let pact_three = [0xB3; 32];
    let grant_three = scope_entity(0x33);
    let scope_three = symmetric_scope(
        crate::federation::FederationScopeFacets::All,
        crate::federation::FederationScopeBands::All,
    );
    let nonce_three = [0x74; 16];
    let connect_three = lifecycle_entry(
        &fixture,
        vec![connect_two_hash],
        8,
        connect_action_with(&fixture, pact_three, grant_three, &scope_three, nonce_three),
    );
    let connect_three_hash = authority_entry_hash(&connect_three).unwrap();
    let repact_three = lifecycle_entry(
        &fixture,
        vec![connect_three_hash],
        9,
        repact_action_with(
            &fixture,
            pact_three,
            grant_three,
            2,
            &symmetric_scope(
                crate::federation::FederationScopeFacets::Some(vec![facet(0x23)]),
                crate::federation::FederationScopeBands::All,
            ),
            [0x75; 16],
        ),
    );
    let disconnect_three = lifecycle_entry(
        &fixture,
        vec![connect_three_hash],
        10,
        unilateral_action_with(
            &fixture,
            pact_three,
            grant_three,
            FederationLifecycleKind::Disconnect,
            1,
        ),
    );

    // Concurrent Connects binding one pact id to two different grants: the
    // transcript carries no grant_ref, so one honest gesture covers both.
    let pact_four = [0xB4; 32];
    let grant_four_a = scope_entity(0x34);
    let grant_four_b = scope_entity(0x35);
    let scope_four = symmetric_scope(
        crate::federation::FederationScopeFacets::All,
        crate::federation::FederationScopeBands::All,
    );
    let nonce_four = [0x76; 16];
    let connect_four_a = lifecycle_entry(
        &fixture,
        vec![connect_two_hash],
        11,
        connect_action_with(&fixture, pact_four, grant_four_a, &scope_four, nonce_four),
    );
    let connect_four_b = lifecycle_entry(
        &fixture,
        vec![connect_two_hash],
        12,
        connect_action_with(&fixture, pact_four, grant_four_b, &scope_four, nonce_four),
    );
    // grant_four_b bound to a SECOND pact on a branch that never saw the
    // P4 bindings: P5 folds Active with grant_four_b operative, but the
    // activation must still deny grant_four_b through suspended P4.
    let pact_five = [0xB5; 32];
    let connect_five = lifecycle_entry(
        &fixture,
        vec![connect_two_hash],
        13,
        connect_action_with(&fixture, pact_five, grant_four_b, &scope_four, [0x77; 16]),
    );

    // THREE-way binding divergence on one pact: the merge must fold to the
    // GLOBAL lex-min grant (the heal target) under every merge tree, not to
    // whichever pair happened to suspend first.
    let pact_six = [0xB6; 32];
    let grant_six = [scope_entity(0x36), scope_entity(0x37), scope_entity(0x38)];
    let nonce_six = [0x79; 16];
    let connect_six_a = lifecycle_entry(
        &fixture,
        vec![connect_two_hash],
        14,
        connect_action_with(&fixture, pact_six, grant_six[0], &scope_four, nonce_six),
    );
    let connect_six_b = lifecycle_entry(
        &fixture,
        vec![connect_two_hash],
        15,
        connect_action_with(&fixture, pact_six, grant_six[1], &scope_four, nonce_six),
    );
    let connect_six_c = lifecycle_entry(
        &fixture,
        vec![connect_two_hash],
        16,
        connect_action_with(&fixture, pact_six, grant_six[2], &scope_four, nonce_six),
    );

    let digest_three = scope_digest_for(&scope_three, &nonce_three);
    let entries = vec![
        fixture.genesis.clone(),
        connect,
        narrow_left,
        narrow_right,
        enroll,
        connect_two,
        repact_left,
        repact_right,
        connect_three,
        repact_three,
        disconnect_three,
        connect_four_a,
        connect_four_b,
        connect_five,
        connect_six_a,
        connect_six_b,
        connect_six_c,
    ];
    LifecycleDag {
        fixture,
        entries,
        pact_two,
        pact_three,
        pact_four,
        pact_five,
        pact_six,
        grant_four_a,
        grant_four_b,
        grant_six,
        low_scope,
        low_digest,
        scope_three,
        digest_three,
    }
}

#[test]
fn federation_lifecycle_dag_merges_pacts_fail_closed() {
    let dag = lifecycle_dag();
    let fold = fold_authority_log_without_seen_time_delay(&dag.entries);
    assert!(
        fold.issues.is_empty(),
        "unexpected issues: {:?}",
        fold.issues
    );
    assert_eq!(fold.valid_entries.len(), dag.entries.len());
    assert!(
        fold.roster
            .contains_key(&authority_key_from_ed(&ed_key(210)))
    );

    // P1: concurrent unilateral narrows merge to the INTERSECTION; the
    // disjoint band sets meet at the kind-tagged ⊥, never at all-bands.
    let p1 = &fold.federation_pacts[&dag.fixture.pact_id];
    assert_eq!(p1.status, FederationPactStatus::Active);
    assert_eq!(p1.pact_epoch, 1);
    assert_eq!(
        p1.effective_scope,
        FederationDirectionScope {
            worlds: crate::federation::FederationScopeWorlds::All,
            facets: crate::federation::FederationScopeFacets::Some(vec![scope_entity(0x22)]),
            bands: crate::federation::FederationScopeBands::Bottom,
        }
    );

    // P2: concurrent equal-epoch divergent-digest repacts suspend, with the
    // min-digest side's scope fields (determinism-only pick).
    let p2 = &fold.federation_pacts[&dag.pact_two];
    assert_eq!(p2.status, FederationPactStatus::Suspended);
    assert_eq!(p2.pact_epoch, 2);
    assert_eq!(p2.scope_digest, dag.low_digest);
    assert_eq!(p2.pact_scope, dag.low_scope);
    assert_eq!(p2.successor_vault_id, None);
    assert_eq!(p2.terminal_epoch, None);

    // P3: concurrent Disconnect + higher-epoch repact merges to Disconnected
    // (terminal beats epoch), keeping the terminal side's fields verbatim.
    let p3 = &fold.federation_pacts[&dag.pact_three];
    assert_eq!(p3.status, FederationPactStatus::Disconnected);
    assert_eq!(p3.pact_epoch, 1);
    assert_eq!(p3.terminal_epoch, Some(1));
    assert_eq!(p3.scope_digest, dag.digest_three);
    assert_eq!(p3.pact_scope, dag.scope_three);

    // P4: concurrent Connects binding one pact id to two grants suspend the
    // pact and deny BOTH grants — the discarded binding must never fall back
    // to Unpacted legacy-allow.
    let p4 = &fold.federation_pacts[&dag.pact_four];
    assert_eq!(p4.status, FederationPactStatus::Suspended);
    assert_eq!(p4.pact_epoch, 1);
    assert_eq!(p4.grant_ref, dag.grant_four_a.min(dag.grant_four_b));

    // P5: Active with grant_four_b operative — but activation folds over
    // EVERY pact the grant was ever bound to, so suspended P4 still denies
    // grant_four_b; a second live pact never masks a conflicted one.
    let p5 = &fold.federation_pacts[&dag.pact_five];
    assert_eq!(p5.status, FederationPactStatus::Active);
    assert_eq!(p5.grant_ref, dag.grant_four_b);
    for grant in [dag.grant_four_a, dag.grant_four_b] {
        assert_eq!(
            federation_grant_activation(&fold, &grant),
            FederationGrantActivation::Inactive(FederationPactStatus::Suspended)
        );
    }

    // P6: three-way binding divergence folds to the GLOBAL lex-min grant —
    // the heal target must not depend on which pair suspended first.
    let p6 = &fold.federation_pacts[&dag.pact_six];
    assert_eq!(p6.status, FederationPactStatus::Suspended);
    assert_eq!(p6.pact_epoch, 1);
    assert_eq!(
        p6.grant_ref,
        dag.grant_six.iter().copied().min().unwrap(),
        "heal target must be the global tie-break winner"
    );
    for grant in dag.grant_six {
        assert_eq!(
            federation_grant_activation(&fold, &grant),
            FederationGrantActivation::Inactive(FederationPactStatus::Suspended)
        );
    }
}

#[test]
fn lifecycle_entries_use_existing_type_122_doors() {
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let fixture = pact_fixture(190);
    let genesis_hash = authority_entry_hash(&fixture.genesis).unwrap();
    let connect = lifecycle_entry(&fixture, vec![genesis_hash], 1, connect_action(&fixture));

    vault
        .put_authority_log_entry(&fixture.genesis, TimeRange { start: 1, end: 1 }, 1)
        .unwrap();
    let connect_id = vault
        .put_authority_log_entry(&connect, TimeRange { start: 2, end: 2 }, 2)
        .unwrap();
    assert_eq!(
        vault.get_authority_log_entry(&connect_id).unwrap(),
        Some(connect.clone()),
        "lifecycle entry must round-trip through the AUTHORITY_LOG write door"
    );
    let fold = vault.authority_fold().unwrap();
    assert_eq!(
        fold.federation_pacts[&fixture.pact_id].status,
        FederationPactStatus::Active
    );

    let body = encode_authority_log_entry_body(&connect).unwrap();
    let err = vault
        .batch()
        .put(
            &scope_entity(0x53),
            ENTITY_TYPE_AUTHORITY_LOG,
            TimeRange { start: 3, end: 3 },
            3,
            &body,
        )
        .commit()
        .expect_err("generic public AUTHORITY_LOG put must stay rejected");
    assert_eq!(
        err.kind(),
        crate::error::ErrorKind::MaintenanceKindNotWritable
    );
}

proptest! {
    #[test]
    fn federation_lifecycle_fold_is_permutation_invariant(
        perm in prop::collection::vec(0_usize..17, 17),
    ) {
        let dag = lifecycle_dag();
        let baseline = fold_authority_log_without_seen_time_delay(&dag.entries);
        prop_assert!(baseline.issues.is_empty());

        let mut permuted = Vec::new();
        for index in perm {
            if let Some(entry) = dag.entries.get(index % dag.entries.len()) {
                permuted.push(entry.clone());
            }
        }
        for entry in &dag.entries {
            if !permuted.iter().any(|candidate| candidate == entry) {
                permuted.push(entry.clone());
            }
        }

        let folded = fold_authority_log_without_seen_time_delay(&permuted);
        // The HEAL TARGET (the grant_ref an epoch+1 repact must name) is
        // anchored to the GLOBAL tie-break winner under every permutation —
        // an absolute check, not just baseline equality, so a consistently
        // order-biased merge cannot pass.
        prop_assert_eq!(
            folded.federation_pacts[&dag.pact_four].grant_ref,
            dag.grant_four_a.min(dag.grant_four_b)
        );
        prop_assert_eq!(
            folded.federation_pacts[&dag.pact_six].grant_ref,
            dag.grant_six.iter().copied().min().unwrap()
        );
        prop_assert_eq!(folded, baseline);
    }
}

#[test]
fn federation_lifecycle_rejects_all_zero_peer_vault_id() {
    let fixture = pact_fixture(164);
    let mut action = connect_action(&fixture);
    action.peer_vault_id = [0; 32];
    // Unsigned entry (zeroed signature): the all-zero peer vault id must fail
    // closed in validate_op on Connect, before any signature work.
    let entry = unsigned_entry(
        Some(fixture.vault_id),
        1,
        vec![authority_entry_hash(&fixture.genesis).unwrap()],
        AuthorityOp::FederationLifecycle(action),
        authority_key_from_ed(&fixture.owner),
        101,
    );
    let err = encode_authority_log_entry_body(&entry)
        .expect_err("all-zero peer vault id must fail closed");
    assert_eq!(err.kind(), crate::error::ErrorKind::InvalidAuthorityLogBody);

    // Same rejection on the gesture-free kinds sharing the common key set.
    let mut disconnect = unilateral_action_with(
        &fixture,
        fixture.pact_id,
        fixture.grant_ref,
        FederationLifecycleKind::Disconnect,
        1,
    );
    disconnect.peer_vault_id = [0; 32];
    let entry = unsigned_entry(
        Some(fixture.vault_id),
        2,
        vec![authority_entry_hash(&fixture.genesis).unwrap()],
        AuthorityOp::FederationLifecycle(disconnect),
        authority_key_from_ed(&fixture.owner),
        102,
    );
    let err = encode_authority_log_entry_body(&entry)
        .expect_err("all-zero peer vault id must fail closed for unilateral kinds");
    assert_eq!(err.kind(), crate::error::ErrorKind::InvalidAuthorityLogBody);
}

#[test]
fn federation_divergent_grant_bindings_suspend_and_deny_both_grants() {
    let fixture = pact_fixture(168);
    let genesis_hash = authority_entry_hash(&fixture.genesis).unwrap();
    let grant_a = fixture.grant_ref;
    let grant_b = scope_entity(0x45);
    // Same pact id, same scope/nonce (equal digests) — the pact transcript
    // carries no grant_ref, so ONE honest peer gesture covers both bindings;
    // divergence detection must not ride the digest check.
    let connect_a = lifecycle_entry(&fixture, vec![genesis_hash], 1, connect_action(&fixture));
    let connect_b = lifecycle_entry(
        &fixture,
        vec![genesis_hash],
        2,
        connect_action_with(
            &fixture,
            fixture.pact_id,
            grant_b,
            &fixture.scope,
            fixture.pact_nonce,
        ),
    );

    let fold = fold_authority_log_without_seen_time_delay(&[
        fixture.genesis.clone(),
        connect_a,
        connect_b,
    ]);
    assert!(
        fold.issues.is_empty(),
        "both connects fold valid on their branches"
    );
    let pact = &fold.federation_pacts[&fixture.pact_id];
    assert_eq!(
        pact.status,
        FederationPactStatus::Suspended,
        "divergent grant bindings must suspend, never silently keep one"
    );
    assert_eq!(pact.pact_epoch, 1);
    assert_eq!(
        pact.grant_ref,
        grant_a.min(grant_b),
        "deterministic tie-break"
    );
    for grant in [grant_a, grant_b] {
        assert_eq!(
            federation_grant_activation(&fold, &grant),
            FederationGrantActivation::Inactive(FederationPactStatus::Suspended),
            "no Unpacted escape for a grant that appeared in a pact binding"
        );
        assert!(
            fold.federation_grant_bindings[&grant].contains(&fixture.pact_id),
            "both bindings must be registered"
        );
    }
}

#[test]
fn federation_divergent_binding_heals_under_the_surviving_grant_only() {
    let fixture = pact_fixture(172);
    let genesis_hash = authority_entry_hash(&fixture.genesis).unwrap();
    let grant_a = fixture.grant_ref;
    let grant_b = scope_entity(0x46);
    let connect_a = lifecycle_entry(&fixture, vec![genesis_hash], 1, connect_action(&fixture));
    let connect_b = lifecycle_entry(
        &fixture,
        vec![genesis_hash],
        2,
        connect_action_with(
            &fixture,
            fixture.pact_id,
            grant_b,
            &fixture.scope,
            fixture.pact_nonce,
        ),
    );
    let connect_a_hash = authority_entry_hash(&connect_a).unwrap();
    let connect_b_hash = authority_entry_hash(&connect_b).unwrap();
    // Equal digests: the surviving binding is the lexicographic-min grant.
    let winner = grant_a.min(grant_b);
    let loser = grant_a.max(grant_b);

    // A repact naming the DISCARDED binding must not heal.
    let heal_scope = symmetric_scope(
        crate::federation::FederationScopeFacets::All,
        crate::federation::FederationScopeBands::All,
    );
    let bad_heal = lifecycle_entry(
        &fixture,
        vec![connect_a_hash, connect_b_hash],
        3,
        repact_action_with(&fixture, fixture.pact_id, loser, 2, &heal_scope, [0x6E; 16]),
    );
    let bad_heal_hash = authority_entry_hash(&bad_heal).unwrap();
    let fold = fold_authority_log_without_seen_time_delay(&[
        fixture.genesis.clone(),
        connect_a.clone(),
        connect_b.clone(),
        bad_heal,
    ]);
    assert_eq!(
        lifecycle_rejection(&fold, bad_heal_hash),
        Some(FederationLifecycleRejection::GrantAlreadyBound)
    );
    assert_eq!(
        fold.federation_pacts[&fixture.pact_id].status,
        FederationPactStatus::Suspended
    );

    // An epoch+1 dual-signed repact naming the surviving grant restores
    // exactly that grant; the discarded binding stays denied.
    let heal_nonce = [0x6F; 16];
    let heal = lifecycle_entry(
        &fixture,
        vec![connect_a_hash, connect_b_hash],
        4,
        repact_action_with(
            &fixture,
            fixture.pact_id,
            winner,
            2,
            &heal_scope,
            heal_nonce,
        ),
    );
    // Nor can the discarded binding be re-covered by a fresh pact.
    let rebind = lifecycle_entry(
        &fixture,
        vec![connect_a_hash, connect_b_hash],
        5,
        connect_action_with(&fixture, [0xD4; 32], loser, &fixture.scope, [0x70; 16]),
    );
    let rebind_hash = authority_entry_hash(&rebind).unwrap();
    let fold = fold_authority_log_without_seen_time_delay(&[
        fixture.genesis.clone(),
        connect_a,
        connect_b,
        heal,
        rebind,
    ]);
    let pact = &fold.federation_pacts[&fixture.pact_id];
    assert_eq!(pact.status, FederationPactStatus::Active);
    assert_eq!(pact.pact_epoch, 2);
    assert_eq!(pact.grant_ref, winner);
    assert_eq!(
        federation_grant_activation(&fold, &winner),
        FederationGrantActivation::Active
    );
    assert_eq!(
        federation_grant_activation(&fold, &loser),
        FederationGrantActivation::Inactive(FederationPactStatus::Active),
        "the discarded binding never returns to Unpacted or Active"
    );
    assert_eq!(
        lifecycle_rejection(&fold, rebind_hash),
        Some(FederationLifecycleRejection::GrantAlreadyBound)
    );
}

#[test]
fn federation_activation_denies_grant_bound_to_any_non_active_pact() {
    // The residual fail-open shape: grant G bound to pact P AND pact Q via
    // concurrent Connects (validate-time GrantAlreadyBound cannot stop a
    // merge of two independently folded branches). P also binds H with
    // H < G, so P suspends with H as its operative binding — P is then
    // invisible to an operative-state scan for G, and only the binding
    // registry knows G↔P. Activation must fold over EVERY registered pact:
    // Q being Active must never mask P.
    let fixture = pact_fixture(176);
    let genesis_hash = authority_entry_hash(&fixture.genesis).unwrap();
    // Deliberate exception to the default 0x47 → 0x67 test-seed mapping:
    // this fixture requires H < G (0x48) to exercise the tie-break premise.
    let grant_h = scope_entity(0x46);
    let grant_g = scope_entity(0x48);
    let pact_p = fixture.pact_id;
    let pact_q = [0xD5; 32];

    let connect_p_g = lifecycle_entry(
        &fixture,
        vec![genesis_hash],
        1,
        connect_action_with(
            &fixture,
            pact_p,
            grant_g,
            &fixture.scope,
            fixture.pact_nonce,
        ),
    );
    let connect_p_h = lifecycle_entry(
        &fixture,
        vec![genesis_hash],
        2,
        connect_action_with(
            &fixture,
            pact_p,
            grant_h,
            &fixture.scope,
            fixture.pact_nonce,
        ),
    );
    let connect_q_g = lifecycle_entry(
        &fixture,
        vec![genesis_hash],
        3,
        connect_action_with(&fixture, pact_q, grant_g, &fixture.scope, [0x78; 16]),
    );
    let connect_p_g_hash = authority_entry_hash(&connect_p_g).unwrap();
    let connect_p_h_hash = authority_entry_hash(&connect_p_h).unwrap();

    let fold = fold_authority_log_without_seen_time_delay(&[
        fixture.genesis.clone(),
        connect_p_g.clone(),
        connect_p_h.clone(),
        connect_q_g.clone(),
    ]);
    assert!(fold.issues.is_empty());
    // P suspended with H operative (equal digests, H < G); Q Active with G
    // operative — so the operative-state scan for G sees ONLY Q.
    assert_eq!(
        fold.federation_pacts[&pact_p].status,
        FederationPactStatus::Suspended
    );
    assert_eq!(fold.federation_pacts[&pact_p].grant_ref, grant_h);
    assert_eq!(
        fold.federation_pacts[&pact_q].status,
        FederationPactStatus::Active
    );
    assert_eq!(
        fold.pact_for_grant(&grant_g).map(|pact| pact.status),
        Some(FederationPactStatus::Active),
        "operative-state scan alone would authorize G — activation is the gate"
    );
    assert_eq!(
        federation_grant_activation(&fold, &grant_g),
        FederationGrantActivation::Inactive(FederationPactStatus::Suspended),
        "suspended P must deny G despite Active Q"
    );
    assert_eq!(
        federation_grant_activation(&fold, &grant_h),
        FederationGrantActivation::Inactive(FederationPactStatus::Suspended)
    );

    // Terminal revocation of P (unilateral Disconnect under its operative
    // binding) must keep G denied: no survival via Q.
    let disconnect_p = lifecycle_entry(
        &fixture,
        vec![connect_p_g_hash, connect_p_h_hash],
        4,
        unilateral_action_with(
            &fixture,
            pact_p,
            grant_h,
            FederationLifecycleKind::Disconnect,
            1,
        ),
    );
    let fold = fold_authority_log_without_seen_time_delay(&[
        fixture.genesis,
        connect_p_g,
        connect_p_h,
        connect_q_g,
        disconnect_p,
    ]);
    assert_eq!(
        fold.federation_pacts[&pact_p].status,
        FederationPactStatus::Disconnected
    );
    assert_eq!(
        fold.federation_pacts[&pact_q].status,
        FederationPactStatus::Active
    );
    assert_eq!(
        federation_grant_activation(&fold, &grant_g),
        FederationGrantActivation::Inactive(FederationPactStatus::Disconnected),
        "G must not survive P's revocation through Q"
    );
}

#[test]
fn federation_three_way_divergence_heals_to_global_tiebreak_winner() {
    // Three concurrent Connects binding one pact to three grants with equal
    // digests: the tie-break is purely the grant_ref, and the merged carried
    // binding — the only grant an epoch+1 heal may name — must be the GLOBAL
    // minimum regardless of which pair the fold happened to merge first.
    let fixture = pact_fixture(184);
    let genesis_hash = authority_entry_hash(&fixture.genesis).unwrap();
    let grants = [scope_entity(0x49), scope_entity(0x4A), scope_entity(0x4B)];
    let winner = grants.iter().copied().min().unwrap();
    let connects: Vec<AuthorityLogEntry> = grants
        .iter()
        .enumerate()
        .map(|(index, grant)| {
            lifecycle_entry(
                &fixture,
                vec![genesis_hash],
                1 + index as u64,
                connect_action_with(
                    &fixture,
                    fixture.pact_id,
                    *grant,
                    &fixture.scope,
                    fixture.pact_nonce,
                ),
            )
        })
        .collect();
    let connect_hashes: Vec<AuthorityEntryHash> = connects
        .iter()
        .map(|entry| authority_entry_hash(entry).unwrap())
        .collect();

    let mut entries = vec![fixture.genesis.clone()];
    entries.extend(connects.iter().cloned());
    let fold = fold_authority_log_without_seen_time_delay(&entries);
    let pact = &fold.federation_pacts[&fixture.pact_id];
    assert_eq!(pact.status, FederationPactStatus::Suspended);
    assert_eq!(pact.grant_ref, winner, "heal target = global lex-min grant");
    for grant in grants {
        assert_eq!(
            federation_grant_activation(&fold, &grant),
            FederationGrantActivation::Inactive(FederationPactStatus::Suspended)
        );
    }

    // A heal naming a non-winner rejects; the winner heal restores exactly
    // the winner.
    let heal_scope = symmetric_scope(
        crate::federation::FederationScopeFacets::All,
        crate::federation::FederationScopeBands::All,
    );
    let loser = grants.iter().copied().max().unwrap();
    let bad_heal = lifecycle_entry(
        &fixture,
        connect_hashes.clone(),
        4,
        repact_action_with(&fixture, fixture.pact_id, loser, 2, &heal_scope, [0x7B; 16]),
    );
    let bad_heal_hash = authority_entry_hash(&bad_heal).unwrap();
    let mut with_bad_heal = entries.clone();
    with_bad_heal.push(bad_heal);
    let fold = fold_authority_log_without_seen_time_delay(&with_bad_heal);
    assert_eq!(
        lifecycle_rejection(&fold, bad_heal_hash),
        Some(FederationLifecycleRejection::GrantAlreadyBound)
    );

    let heal = lifecycle_entry(
        &fixture,
        connect_hashes,
        5,
        repact_action_with(
            &fixture,
            fixture.pact_id,
            winner,
            2,
            &heal_scope,
            [0x7C; 16],
        ),
    );
    entries.push(heal);
    let fold = fold_authority_log_without_seen_time_delay(&entries);
    let pact = &fold.federation_pacts[&fixture.pact_id];
    assert_eq!(pact.status, FederationPactStatus::Active);
    assert_eq!(pact.pact_epoch, 2);
    assert_eq!(pact.grant_ref, winner);
    assert_eq!(
        federation_grant_activation(&fold, &winner),
        FederationGrantActivation::Active
    );
    for grant in grants {
        if grant == winner {
            continue;
        }
        assert_eq!(
            federation_grant_activation(&fold, &grant),
            FederationGrantActivation::Inactive(FederationPactStatus::Active)
        );
    }
}

#[test]
fn federation_equal_key_merge_picks_peer_fields_by_total_order() {
    // Two concurrent Connects with an identical (scope_digest, grant_ref)
    // key can still be dual-signed with DIFFERENT peers: the combined state
    // must pick the peer fields by a total order, never by which side the
    // fold happened to hold on the left.
    let fixture = pact_fixture(192);
    let genesis_hash = authority_entry_hash(&fixture.genesis).unwrap();
    let connect_a = lifecycle_entry(&fixture, vec![genesis_hash], 1, connect_action(&fixture));

    let other_peer = ed_key(212);
    let other_peer_vault_id = genesis_vault_id(&genesis_entry(212, 86_400, 1)).unwrap();
    let connect_b = lifecycle_entry(
        &fixture,
        vec![genesis_hash],
        2,
        FederationLifecycleAction {
            kind: FederationLifecycleKind::Connect,
            pact_id: fixture.pact_id,
            grant_ref: fixture.grant_ref,
            peer_vault_id: other_peer_vault_id,
            pact_epoch: 1,
            pact_scope: Some(fixture.scope.clone()),
            effective_scope: None,
            scope_digest: Some(fixture.scope_digest),
            gesture: Some(ed_pact_gesture(
                FederationLifecycleKind::Connect,
                &fixture.pact_id,
                &fixture.vault_id,
                &other_peer_vault_id,
                1,
                &fixture.scope_digest,
                None,
                &fixture.pact_nonce,
                &other_peer,
            )),
            successor_vault_id: None,
            pact_nonce: fixture.pact_nonce,
        },
    );

    let fold = fold_authority_log_without_seen_time_delay(&[
        fixture.genesis.clone(),
        connect_a,
        connect_b,
    ]);
    assert!(fold.issues.is_empty());
    let pact = &fold.federation_pacts[&fixture.pact_id];
    assert_eq!(pact.status, FederationPactStatus::Active);
    assert_eq!(
        pact.peer_vault_id,
        fixture.peer_vault_id.min(other_peer_vault_id)
    );
    assert_eq!(
        pact.peer_owner_key,
        authority_key_from_ed(&fixture.peer).min(authority_key_from_ed(&other_peer))
    );
    assert_eq!(pact.pact_scope, fixture.scope);
}
