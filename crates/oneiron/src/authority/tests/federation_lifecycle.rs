//! Federation pact lifecycle transitions and totality table.

use super::support::*;
use super::*;

#[test]
fn federation_connect_activates_pact_on_both_sides() {
    let fixture = pact_fixture(120);
    let genesis_hash = authority_entry_hash(&fixture.genesis).unwrap();
    let connect = lifecycle_entry(&fixture, vec![genesis_hash], 1, connect_action(&fixture));

    let fold =
        fold_authority_log_without_seen_time_delay(&[fixture.genesis.clone(), connect.clone()]);
    assert!(
        fold.valid_entries
            .contains(&authority_entry_hash(&connect).unwrap())
    );
    let pact = fold
        .federation_pacts
        .get(&fixture.pact_id)
        .expect("connect must activate the pact");
    assert_eq!(pact.status, FederationPactStatus::Active);
    assert_eq!(pact.pact_epoch, 1);
    assert_eq!(pact.grant_ref, fixture.grant_ref);
    assert_eq!(pact.peer_vault_id, fixture.peer_vault_id);
    assert_eq!(
        pact.peer_owner_key,
        authority_key_from_ed(&fixture.peer),
        "peer key must be pinned at connect"
    );
    assert_eq!(pact.scope_digest, fixture.scope_digest);
    assert_eq!(pact.pact_scope, fixture.scope);
    let expected_half = if fixture.vault_id <= fixture.peer_vault_id {
        fixture.scope.lo_to_hi.clone()
    } else {
        fixture.scope.hi_to_lo.clone()
    };
    assert_eq!(pact.effective_scope, expected_half);
    assert_eq!(pact.successor_vault_id, None);
    assert_eq!(pact.terminal_epoch, None);
    assert_eq!(fold.pact_for_grant(&fixture.grant_ref), Some(pact));
    assert_eq!(
        federation_grant_activation(&fold, &fixture.grant_ref),
        FederationGrantActivation::Active
    );
    assert_eq!(
        federation_grant_activation(&fold, &scope_entity(0x77)),
        FederationGrantActivation::Unpacted
    );

    // Symmetric entry on B: same pact id, same digest, gesture signed by A's
    // owner over the identical (sorted-vault) transcript.
    let symmetric_grant = scope_entity(0x41);
    let symmetric_action = FederationLifecycleAction {
        kind: FederationLifecycleKind::Connect,
        pact_id: fixture.pact_id,
        grant_ref: symmetric_grant,
        peer_vault_id: fixture.vault_id,
        pact_epoch: 1,
        pact_scope: Some(fixture.scope.clone()),
        effective_scope: None,
        scope_digest: Some(fixture.scope_digest),
        gesture: Some(ed_pact_gesture(
            FederationLifecycleKind::Connect,
            &fixture.pact_id,
            &fixture.vault_id,
            &fixture.peer_vault_id,
            1,
            &fixture.scope_digest,
            None,
            &fixture.pact_nonce,
            &fixture.owner,
        )),
        successor_vault_id: None,
        pact_nonce: fixture.pact_nonce,
    };
    let symmetric_connect = sign_ed(
        unsigned_entry(
            Some(fixture.peer_vault_id),
            1,
            vec![authority_entry_hash(&fixture.peer_genesis).unwrap()],
            AuthorityOp::FederationLifecycle(symmetric_action),
            authority_key_from_ed(&fixture.peer),
            2,
        ),
        &fixture.peer,
    );
    let peer_fold = fold_authority_log_without_seen_time_delay(&[
        fixture.peer_genesis.clone(),
        symmetric_connect,
    ]);
    let peer_pact = peer_fold
        .federation_pacts
        .get(&fixture.pact_id)
        .expect("symmetric connect must activate on B");
    assert_eq!(peer_pact.status, FederationPactStatus::Active);
    assert_eq!(
        peer_pact.peer_owner_key,
        authority_key_from_ed(&fixture.owner)
    );
    let expected_peer_half = if fixture.peer_vault_id <= fixture.vault_id {
        fixture.scope.lo_to_hi.clone()
    } else {
        fixture.scope.hi_to_lo.clone()
    };
    assert_eq!(peer_pact.effective_scope, expected_peer_half);
    assert_eq!(
        federation_grant_activation(&peer_fold, &symmetric_grant),
        FederationGrantActivation::Active
    );
}

#[test]
fn federation_connect_digest_mismatch_never_activates() {
    // (a) Gesture signed over digest Y while the entry claims X: the scope
    // recomputes to X, so the gesture check fails.
    let fixture = pact_fixture(124);
    let genesis_hash = authority_entry_hash(&fixture.genesis).unwrap();
    let mut action = connect_action(&fixture);
    action.gesture = Some(ed_pact_gesture(
        FederationLifecycleKind::Connect,
        &fixture.pact_id,
        &fixture.vault_id,
        &fixture.peer_vault_id,
        1,
        &[0xEE; 32],
        None,
        &fixture.pact_nonce,
        &fixture.peer,
    ));
    let entry = lifecycle_entry(&fixture, vec![genesis_hash], 1, action);
    let entry_hash = authority_entry_hash(&entry).unwrap();
    let fold = fold_authority_log_without_seen_time_delay(&[fixture.genesis.clone(), entry]);
    assert!(fold.federation_pacts.is_empty(), "no pact state may form");
    assert_eq!(fold.pact_for_grant(&fixture.grant_ref), None);
    assert_eq!(
        lifecycle_rejection(&fold, entry_hash),
        Some(FederationLifecycleRejection::GestureInvalid)
    );

    // (b) Entry's pact_scope tampered: the recompute no longer matches the
    // claimed (and gesture-signed) digest.
    let fixture = pact_fixture(126);
    let genesis_hash = authority_entry_hash(&fixture.genesis).unwrap();
    let mut action = connect_action(&fixture);
    action.pact_scope = Some(symmetric_scope(
        crate::federation::FederationScopeFacets::Bottom,
        crate::federation::FederationScopeBands::All,
    ));
    let entry = lifecycle_entry(&fixture, vec![genesis_hash], 1, action);
    let entry_hash = authority_entry_hash(&entry).unwrap();
    let fold = fold_authority_log_without_seen_time_delay(&[fixture.genesis.clone(), entry]);
    assert!(fold.federation_pacts.is_empty(), "no pact state may form");
    assert_eq!(
        lifecycle_rejection(&fold, entry_hash),
        Some(FederationLifecycleRejection::ScopeDigestMismatch)
    );
    assert_eq!(
        federation_grant_activation(&fold, &fixture.grant_ref),
        FederationGrantActivation::Unpacted
    );
}

#[test]
fn federation_rescope_narrow_and_repact_rules() {
    let ceiling_facets = crate::federation::FederationScopeFacets::Some(vec![
        scope_entity(0x21),
        scope_entity(0x22),
    ]);
    let fixture = pact_fixture_with_scope(
        128,
        symmetric_scope(ceiling_facets, crate::federation::FederationScopeBands::All),
    );
    let genesis_hash = authority_entry_hash(&fixture.genesis).unwrap();
    let connect = lifecycle_entry(&fixture, vec![genesis_hash], 1, connect_action(&fixture));
    let connect_hash = authority_entry_hash(&connect).unwrap();

    // Widen attempt: effective facets = All escapes the Some([...]) ceiling.
    let widen = lifecycle_entry(
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
                facets: crate::federation::FederationScopeFacets::All,
                bands: crate::federation::FederationScopeBands::All,
            },
        ),
    );
    let widen_hash = authority_entry_hash(&widen).unwrap();
    let fold = fold_authority_log_without_seen_time_delay(&[
        fixture.genesis.clone(),
        connect.clone(),
        widen,
    ]);
    assert_eq!(
        lifecycle_rejection(&fold, widen_hash),
        Some(FederationLifecycleRejection::WidenWithoutGesture)
    );
    let pact = &fold.federation_pacts[&fixture.pact_id];
    assert_eq!(
        pact.effective_scope, fixture.scope.lo_to_hi,
        "rejected widen must leave the effective scope unchanged"
    );

    // Narrowing rescope (⊑ ceiling, epoch == cur) replaces effective_scope.
    let narrowed = FederationDirectionScope {
        worlds: crate::federation::FederationScopeWorlds::Base,
        facets: crate::federation::FederationScopeFacets::Some(vec![scope_entity(0x21)]),
        bands: crate::federation::FederationScopeBands::Some(vec![SelectorRange::Semantic]),
    };
    let narrow = lifecycle_entry(
        &fixture,
        vec![connect_hash],
        3,
        narrow_action_with(
            &fixture,
            fixture.pact_id,
            fixture.grant_ref,
            1,
            narrowed.clone(),
        ),
    );
    let narrow_hash = authority_entry_hash(&narrow).unwrap();
    let fold = fold_authority_log_without_seen_time_delay(&[
        fixture.genesis.clone(),
        connect.clone(),
        narrow.clone(),
    ]);
    let pact = &fold.federation_pacts[&fixture.pact_id];
    assert_eq!(pact.status, FederationPactStatus::Active);
    assert_eq!(pact.pact_epoch, 1);
    assert_eq!(pact.effective_scope, narrowed);

    // Dual-signed repact at epoch+1 replaces ceiling + digest wholesale.
    let new_scope = symmetric_scope(
        crate::federation::FederationScopeFacets::Some(vec![scope_entity(0x23)]),
        crate::federation::FederationScopeBands::All,
    );
    let new_nonce = [0x5A; 16];
    let repact = lifecycle_entry(
        &fixture,
        vec![narrow_hash],
        4,
        repact_action_with(
            &fixture,
            fixture.pact_id,
            fixture.grant_ref,
            2,
            &new_scope,
            new_nonce,
        ),
    );
    let fold = fold_authority_log_without_seen_time_delay(&[
        fixture.genesis.clone(),
        connect,
        narrow,
        repact,
    ]);
    let pact = &fold.federation_pacts[&fixture.pact_id];
    assert_eq!(pact.status, FederationPactStatus::Active);
    assert_eq!(pact.pact_epoch, 2);
    assert_eq!(pact.pact_scope, new_scope);
    assert_eq!(pact.scope_digest, scope_digest_for(&new_scope, &new_nonce));
    assert_eq!(pact.effective_scope, new_scope.lo_to_hi);
}

#[test]
fn federation_disconnect_is_terminal_for_every_subsequent_op() {
    let fixture = pact_fixture(132);
    let genesis_hash = authority_entry_hash(&fixture.genesis).unwrap();
    let connect = lifecycle_entry(&fixture, vec![genesis_hash], 1, connect_action(&fixture));
    let connect_hash = authority_entry_hash(&connect).unwrap();
    let disconnect = lifecycle_entry(
        &fixture,
        vec![connect_hash],
        2,
        unilateral_action_with(
            &fixture,
            fixture.pact_id,
            fixture.grant_ref,
            FederationLifecycleKind::Disconnect,
            1,
        ),
    );
    let disconnect_hash = authority_entry_hash(&disconnect).unwrap();

    let fold = fold_authority_log_without_seen_time_delay(&[
        fixture.genesis.clone(),
        connect.clone(),
        disconnect.clone(),
    ]);
    let pact = &fold.federation_pacts[&fixture.pact_id];
    assert_eq!(pact.status, FederationPactStatus::Disconnected);
    assert_eq!(pact.terminal_epoch, Some(1));
    assert_eq!(
        federation_grant_activation(&fold, &fixture.grant_ref),
        FederationGrantActivation::Inactive(FederationPactStatus::Disconnected)
    );

    // Every subsequent lifecycle op on P parented after the disconnect.
    let followups = vec![
        (
            "connect",
            lifecycle_entry(&fixture, vec![disconnect_hash], 3, connect_action(&fixture)),
        ),
        (
            "narrow",
            lifecycle_entry(
                &fixture,
                vec![disconnect_hash],
                4,
                narrow_action_with(
                    &fixture,
                    fixture.pact_id,
                    fixture.grant_ref,
                    1,
                    fixture.scope.hi_to_lo.clone(),
                ),
            ),
        ),
        (
            "repact",
            lifecycle_entry(
                &fixture,
                vec![disconnect_hash],
                5,
                repact_action_with(
                    &fixture,
                    fixture.pact_id,
                    fixture.grant_ref,
                    2,
                    &fixture.scope,
                    [0x66; 16],
                ),
            ),
        ),
        (
            "promote",
            lifecycle_entry(
                &fixture,
                vec![disconnect_hash],
                6,
                promote_action_with(
                    &fixture,
                    fixture.pact_id,
                    fixture.grant_ref,
                    2,
                    fixture.scope_digest,
                    [0xCC; 32],
                ),
            ),
        ),
        (
            "dissolve",
            lifecycle_entry(
                &fixture,
                vec![disconnect_hash],
                7,
                unilateral_action_with(
                    &fixture,
                    fixture.pact_id,
                    fixture.grant_ref,
                    FederationLifecycleKind::Dissolve,
                    1,
                ),
            ),
        ),
        (
            "second disconnect",
            lifecycle_entry(
                &fixture,
                vec![disconnect_hash],
                8,
                unilateral_action_with(
                    &fixture,
                    fixture.pact_id,
                    fixture.grant_ref,
                    FederationLifecycleKind::Disconnect,
                    1,
                ),
            ),
        ),
    ];

    let mut entries = vec![fixture.genesis.clone(), connect, disconnect];
    let mut followup_hashes = Vec::new();
    for (name, entry) in followups {
        followup_hashes.push((name, authority_entry_hash(&entry).unwrap()));
        entries.push(entry);
    }
    let fold = fold_authority_log_without_seen_time_delay(&entries);
    for (name, hash) in followup_hashes {
        assert_eq!(
            lifecycle_rejection(&fold, hash),
            Some(FederationLifecycleRejection::TerminalPact),
            "{name} after disconnect must reject TerminalPact"
        );
    }
    let pact = &fold.federation_pacts[&fixture.pact_id];
    assert_eq!(pact.status, FederationPactStatus::Disconnected);
    assert_eq!(pact.terminal_epoch, Some(1));
    assert_eq!(pact.pact_epoch, 1);
    assert_eq!(fold.federation_pacts.len(), 1);

    // Re-covering the SAME grant_ref under a NEW pact id stays rejected even
    // though the binding pact is terminal: revoked access never resurrects.
    let rebind = lifecycle_entry(
        &fixture,
        vec![disconnect_hash],
        9,
        connect_action_with(
            &fixture,
            [0xD1; 32],
            fixture.grant_ref,
            &fixture.scope,
            [0x67; 16],
        ),
    );
    let rebind_hash = authority_entry_hash(&rebind).unwrap();
    entries.push(rebind);
    let fold = fold_authority_log_without_seen_time_delay(&entries);
    assert_eq!(
        lifecycle_rejection(&fold, rebind_hash),
        Some(FederationLifecycleRejection::GrantAlreadyBound)
    );
    assert_eq!(fold.federation_pacts.len(), 1);
}

#[test]
fn federation_connect_rejects_rebinding_an_actively_bound_grant() {
    let fixture = pact_fixture(136);
    let genesis_hash = authority_entry_hash(&fixture.genesis).unwrap();
    let connect = lifecycle_entry(&fixture, vec![genesis_hash], 1, connect_action(&fixture));
    let connect_hash = authority_entry_hash(&connect).unwrap();
    let rebind = lifecycle_entry(
        &fixture,
        vec![connect_hash],
        2,
        connect_action_with(
            &fixture,
            [0xD2; 32],
            fixture.grant_ref,
            &fixture.scope,
            [0x68; 16],
        ),
    );
    let rebind_hash = authority_entry_hash(&rebind).unwrap();

    let fold =
        fold_authority_log_without_seen_time_delay(&[fixture.genesis.clone(), connect, rebind]);
    assert_eq!(
        lifecycle_rejection(&fold, rebind_hash),
        Some(FederationLifecycleRejection::GrantAlreadyBound)
    );
    assert_eq!(fold.federation_pacts.len(), 1);
    assert_eq!(
        fold.federation_pacts[&fixture.pact_id].status,
        FederationPactStatus::Active
    );
}

#[test]
fn federation_promote_records_successor_and_is_terminal() {
    let fixture = pact_fixture(140);
    let genesis_hash = authority_entry_hash(&fixture.genesis).unwrap();
    let connect = lifecycle_entry(&fixture, vec![genesis_hash], 1, connect_action(&fixture));
    let connect_hash = authority_entry_hash(&connect).unwrap();
    let successor = [0xCD; 32];
    let promote = lifecycle_entry(
        &fixture,
        vec![connect_hash],
        2,
        promote_action_with(
            &fixture,
            fixture.pact_id,
            fixture.grant_ref,
            2,
            fixture.scope_digest,
            successor,
        ),
    );
    let promote_hash = authority_entry_hash(&promote).unwrap();
    let after = lifecycle_entry(
        &fixture,
        vec![promote_hash],
        3,
        narrow_action_with(
            &fixture,
            fixture.pact_id,
            fixture.grant_ref,
            2,
            fixture.scope.hi_to_lo.clone(),
        ),
    );
    let after_hash = authority_entry_hash(&after).unwrap();

    let fold = fold_authority_log_without_seen_time_delay(&[
        fixture.genesis.clone(),
        connect,
        promote,
        after,
    ]);
    let pact = &fold.federation_pacts[&fixture.pact_id];
    assert_eq!(pact.status, FederationPactStatus::Promoted);
    assert_eq!(pact.successor_vault_id, Some(successor));
    assert_eq!(pact.terminal_epoch, Some(2));
    assert_eq!(pact.pact_epoch, 2);
    assert_eq!(
        lifecycle_rejection(&fold, after_hash),
        Some(FederationLifecycleRejection::TerminalPact)
    );
    assert_eq!(
        federation_grant_activation(&fold, &fixture.grant_ref),
        FederationGrantActivation::Inactive(FederationPactStatus::Promoted)
    );

    // Promote with a digest that differs from the stored one never lands.
    let fixture = pact_fixture(144);
    let genesis_hash = authority_entry_hash(&fixture.genesis).unwrap();
    let connect = lifecycle_entry(&fixture, vec![genesis_hash], 1, connect_action(&fixture));
    let connect_hash = authority_entry_hash(&connect).unwrap();
    let bad_promote = lifecycle_entry(
        &fixture,
        vec![connect_hash],
        2,
        promote_action_with(
            &fixture,
            fixture.pact_id,
            fixture.grant_ref,
            2,
            [0xEF; 32],
            successor,
        ),
    );
    let bad_hash = authority_entry_hash(&bad_promote).unwrap();
    let fold = fold_authority_log_without_seen_time_delay(&[
        fixture.genesis.clone(),
        connect,
        bad_promote,
    ]);
    assert_eq!(
        lifecycle_rejection(&fold, bad_hash),
        Some(FederationLifecycleRejection::ScopeDigestMismatch)
    );
    assert_eq!(
        fold.federation_pacts[&fixture.pact_id].status,
        FederationPactStatus::Active
    );
}

#[test]
fn federation_dissolve_is_terminal_and_never_recovered() {
    let fixture = pact_fixture(148);
    let genesis_hash = authority_entry_hash(&fixture.genesis).unwrap();
    let connect = lifecycle_entry(&fixture, vec![genesis_hash], 1, connect_action(&fixture));
    let connect_hash = authority_entry_hash(&connect).unwrap();
    let dissolve = lifecycle_entry(
        &fixture,
        vec![connect_hash],
        2,
        unilateral_action_with(
            &fixture,
            fixture.pact_id,
            fixture.grant_ref,
            FederationLifecycleKind::Dissolve,
            1,
        ),
    );
    let dissolve_hash = authority_entry_hash(&dissolve).unwrap();
    let repact_after = lifecycle_entry(
        &fixture,
        vec![dissolve_hash],
        3,
        repact_action_with(
            &fixture,
            fixture.pact_id,
            fixture.grant_ref,
            2,
            &fixture.scope,
            [0x69; 16],
        ),
    );
    let repact_hash = authority_entry_hash(&repact_after).unwrap();
    let rebind = lifecycle_entry(
        &fixture,
        vec![dissolve_hash],
        4,
        connect_action_with(
            &fixture,
            [0xD3; 32],
            fixture.grant_ref,
            &fixture.scope,
            [0x6A; 16],
        ),
    );
    let rebind_hash = authority_entry_hash(&rebind).unwrap();

    let fold = fold_authority_log_without_seen_time_delay(&[
        fixture.genesis.clone(),
        connect,
        dissolve,
        repact_after,
        rebind,
    ]);
    let pact = &fold.federation_pacts[&fixture.pact_id];
    assert_eq!(pact.status, FederationPactStatus::Dissolved);
    assert_eq!(pact.terminal_epoch, Some(1));
    assert_eq!(
        lifecycle_rejection(&fold, repact_hash),
        Some(FederationLifecycleRejection::TerminalPact)
    );
    assert_eq!(
        lifecycle_rejection(&fold, rebind_hash),
        Some(FederationLifecycleRejection::GrantAlreadyBound)
    );
    assert_eq!(
        federation_grant_activation(&fold, &fixture.grant_ref),
        FederationGrantActivation::Inactive(FederationPactStatus::Dissolved)
    );
}

#[test]
fn federation_suspended_pact_heals_via_fresh_repact() {
    let fixture = pact_fixture(152);
    let genesis_hash = authority_entry_hash(&fixture.genesis).unwrap();
    let connect = lifecycle_entry(&fixture, vec![genesis_hash], 1, connect_action(&fixture));
    let connect_hash = authority_entry_hash(&connect).unwrap();
    let left_scope = symmetric_scope(
        crate::federation::FederationScopeFacets::Some(vec![scope_entity(0x21)]),
        crate::federation::FederationScopeBands::All,
    );
    let right_scope = symmetric_scope(
        crate::federation::FederationScopeFacets::Some(vec![scope_entity(0x22)]),
        crate::federation::FederationScopeBands::All,
    );
    let left = lifecycle_entry(
        &fixture,
        vec![connect_hash],
        2,
        repact_action_with(
            &fixture,
            fixture.pact_id,
            fixture.grant_ref,
            2,
            &left_scope,
            [0x6B; 16],
        ),
    );
    let right = lifecycle_entry(
        &fixture,
        vec![connect_hash],
        3,
        repact_action_with(
            &fixture,
            fixture.pact_id,
            fixture.grant_ref,
            2,
            &right_scope,
            [0x6C; 16],
        ),
    );
    let left_hash = authority_entry_hash(&left).unwrap();
    let right_hash = authority_entry_hash(&right).unwrap();

    let fold = fold_authority_log_without_seen_time_delay(&[
        fixture.genesis.clone(),
        connect.clone(),
        left.clone(),
        right.clone(),
    ]);
    let pact = &fold.federation_pacts[&fixture.pact_id];
    assert_eq!(
        pact.status,
        FederationPactStatus::Suspended,
        "divergent equal-epoch repacts must suspend"
    );
    assert_eq!(pact.pact_epoch, 2);
    assert_eq!(
        federation_grant_activation(&fold, &fixture.grant_ref),
        FederationGrantActivation::Inactive(FederationPactStatus::Suspended)
    );

    // Narrow/Promote on the suspended pact reject SuspendedPact.
    let narrow_on_suspended = lifecycle_entry(
        &fixture,
        vec![left_hash, right_hash],
        4,
        narrow_action_with(
            &fixture,
            fixture.pact_id,
            fixture.grant_ref,
            2,
            fixture.scope.hi_to_lo.clone(),
        ),
    );
    let narrow_hash = authority_entry_hash(&narrow_on_suspended).unwrap();
    let fold = fold_authority_log_without_seen_time_delay(&[
        fixture.genesis.clone(),
        connect.clone(),
        left.clone(),
        right.clone(),
        narrow_on_suspended,
    ]);
    assert_eq!(
        lifecycle_rejection(&fold, narrow_hash),
        Some(FederationLifecycleRejection::SuspendedPact)
    );

    // A fresh dual-signed repact at epoch+1 heals the suspension.
    let heal_scope = symmetric_scope(
        crate::federation::FederationScopeFacets::Some(vec![scope_entity(0x23)]),
        crate::federation::FederationScopeBands::All,
    );
    let heal_nonce = [0x6D; 16];
    let heal = lifecycle_entry(
        &fixture,
        vec![left_hash, right_hash],
        5,
        repact_action_with(
            &fixture,
            fixture.pact_id,
            fixture.grant_ref,
            3,
            &heal_scope,
            heal_nonce,
        ),
    );
    let fold = fold_authority_log_without_seen_time_delay(&[
        fixture.genesis.clone(),
        connect,
        left,
        right,
        heal,
    ]);
    let pact = &fold.federation_pacts[&fixture.pact_id];
    assert_eq!(pact.status, FederationPactStatus::Active);
    assert_eq!(pact.pact_epoch, 3);
    assert_eq!(pact.pact_scope, heal_scope);
    assert_eq!(
        pact.scope_digest,
        scope_digest_for(&heal_scope, &heal_nonce)
    );
    assert_eq!(
        federation_grant_activation(&fold, &fixture.grant_ref),
        FederationGrantActivation::Active
    );
}

#[test]
fn federation_lifecycle_transition_table_is_total() {
    let fixture = pact_fixture(156);
    let statuses = [
        None,
        Some(FederationPactStatus::Active),
        Some(FederationPactStatus::Suspended),
        Some(FederationPactStatus::Promoted),
        Some(FederationPactStatus::Disconnected),
        Some(FederationPactStatus::Dissolved),
    ];
    for status in statuses {
        for (name, action) in totality_ops(&fixture) {
            let mut state = fold_state_with_pact(&fixture, status);
            let before = state.federation_pacts.clone();
            let storage = LocalFoldContext::default();
            let result = apply_federation_lifecycle(&mut state, &action, storage.context());
            match expected_transition(status, name) {
                Ok(next) => {
                    assert_eq!(result, Ok(()), "({status:?}, {name}) must apply");
                    assert_eq!(
                        state.federation_pacts[&fixture.pact_id].status, next,
                        "({status:?}, {name}) next status"
                    );
                }
                Err(reason) => {
                    assert_eq!(result, Err(reason), "({status:?}, {name}) rejection");
                    assert_eq!(
                        state.federation_pacts, before,
                        "({status:?}, {name}) rejected op must not mutate state"
                    );
                }
            }
        }
    }
}
