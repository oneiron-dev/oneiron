//! External-effect grants: scoped, standing, and outbound MCP grants plus counterparty contacts.

use super::*;

#[test]
fn external_effect_scoped_grant_allows_and_records_receipt() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let data = encode_policy_manifest(vec![external_effect_scoped_grant_entry(
        "sender",
        "external:send",
        Value::Map(vec![(
            Value::from(EXTERNAL_EFFECT_SCOPE_CHANNEL_KEY),
            Value::from("line"),
        )]),
        None,
    )]);
    put_policy_manifest_bytes(&vault, test_id(0xD0), &data)?;
    let policy = resolve(&vault)?;
    let effect = external_effect_gate_input("sender", "send", "line");

    let (_decision_id, decision, _effector_charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy_with_budget(&vault.store, wtxn, &effect, &policy, true)
    })?;

    assert_eq!(decision.outcome(), GateOutcome::Allow);
    assert_eq!(gate_reason_strs(&decision), vec!["gate.allow"]);

    let decisions = vault.store.gate_decisions(10)?;
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].outcome, "allow");
    assert_eq!(decisions[0].reason_codes, vec!["gate.allow"]);
    assert_eq!(decisions[0].actor_class, "first_party");
    assert_eq!(decisions[0].actor_ref.as_deref(), Some("sender"));
    assert_eq!(decisions[0].content_kind, "external_effect");
    assert_eq!(decisions[0].claim_id, None);
    assert!(!decisions[0].diff_handle.is_empty());
    assert_eq!(
        decisions[0].read_frontier_hash,
        policy.read_frontier_hash()?
    );
    Ok(())
}

#[test]
fn standing_outbound_grant_allows_in_scope_external_effect_and_records_join() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xD8), &encode_policy_manifest(vec![]))?;

    let grant_id = test_id(0xD9);
    let intent = GrantMintIntent {
        principal_ref: "sender".to_owned(),
        origin_component_id: "ask-1".to_owned(),
        origin_action_id: "escalate_always_this_verb_class".to_owned(),
        origin_receipt_ref: Some("gate:ask-1".to_owned()),
        scope: GrantMintIntentScope::VerbClass {
            verb_class: "send".to_owned(),
        },
    };
    vault.mint_standing_outbound_grant(&grant_id, &intent, 10)?;
    let policy = resolve(&vault)?;

    let mut effect = external_effect_gate_input("sender", "send", "line");
    effect.has_opted_in = false;
    let (_decision_id, decision, _effector_charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy_with_budget(&vault.store, wtxn, &effect, &policy, true)
    })?;

    assert_eq!(decision.outcome(), GateOutcome::Allow);
    let grant = vault
        .get_standing_outbound_grant(&grant_id)?
        .expect("grant stored");
    assert!(grant.last_used_at.is_some());

    let decisions = vault.store.gate_decisions(10)?;
    let grant_ref = format!("grant:{}", grant_id.to_hex());
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].grant_ref.as_deref(), Some(grant_ref.as_str()));

    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))?;
    assert_eq!(
        receipts[0].fields.get("grant_ref").map(String::as_str),
        Some(grant_ref.as_str())
    );
    let projection = vault.receipt_projection_by_grant(grant_ref, ReceiptQuery::new(10))?;
    assert_eq!(projection.receipts.len(), 2);
    assert!(
        projection
            .receipts
            .iter()
            .any(|receipt| receipt.receipt_kind == ReceiptKind::Gate)
    );
    Ok(())
}

#[test]
fn standing_outbound_grant_lookup_uses_principal_index_before_type_scan() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xDD), &encode_policy_manifest(vec![]))?;

    let grant_id = test_id(0xDE);
    let intent = GrantMintIntent {
        principal_ref: "sender".to_owned(),
        origin_component_id: "ask-1".to_owned(),
        origin_action_id: "escalate_always_this_verb_class".to_owned(),
        origin_receipt_ref: Some("gate:ask-1".to_owned()),
        scope: GrantMintIntentScope::VerbClass {
            verb_class: "send".to_owned(),
        },
    };
    vault.mint_standing_outbound_grant(&grant_id, &intent, 10)?;
    let policy = resolve(&vault)?;

    // Persist an incomplete-index fixture: the grant and its principal association
    // remain stored, but its type-index row is absent. Such a grant must remain
    // usable by its owner.
    vault.with_write_txn(|wtxn| {
        let type_key = Store::encode_type_key(ENTITY_TYPE_OUTBOUND_GRANT, &grant_id);
        vault.store.type_index.delete(wtxn, &type_key)?;
        Ok(())
    })?;

    let mut effect = external_effect_gate_input("sender", "send", "line");
    effect.has_opted_in = false;
    let (_decision_id, decision, _effector_charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &effect, &policy, true)
    })?;

    assert_eq!(decision.outcome(), GateOutcome::Allow);
    Ok(())
}

#[test]
fn forged_standing_grant_ref_does_not_authorize_external_effect() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let default_manifest_id = crate::gate::default_policy_manifest_id()?;
    put_policy_manifest_bytes(&vault, default_manifest_id, &encode_policy_manifest(vec![]))?;
    let policy = resolve(&vault)?;

    let mut effect = external_effect_gate_input("sender", "send", "line");
    effect.has_opted_in = false;
    effect.standing_grant_ref = Some(format!("grant:{}", default_manifest_id.to_hex()));
    let (_decision_id, decision, _effector_charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &effect, &policy, true)
    })?;

    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&decision),
        vec![
            "gate.pending.consent.irreversible_effect",
            "gate.pending.external_effect_authority",
        ]
    );
    let decisions = vault.store.gate_decisions(10)?;
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].grant_ref, None);
    Ok(())
}

#[test]
fn scoped_mcp_grant_is_payload_aware_at_external_effect_gate() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xD8), &encode_policy_manifest(vec![]))?;
    let grant_id = test_id(0xD9);
    vault.mint_scoped_mcp_outbound_grant(
        &grant_id,
        &crate::outbound_grant::ScopedMcpGrantMintIntent {
            principal_ref: test_id(0xE0).to_hex(),
            origin_component_id: "ask-mcp".to_owned(),
            origin_action_id: "grant-scoped-mcp".to_owned(),
            origin_receipt_ref: Some("gate:ask-mcp".to_owned()),
            server: "files".to_owned(),
            tool: "read_file".to_owned(),
            data_class_ceiling: crate::outbound_consent::DataClass::Personal,
            endpoint_allowlist: vec!["https://files.internal.example".to_owned()],
        },
        10,
    )?;
    vault.register_connector_key(
        &test_id(0xDA),
        crate::connector_key::ConnectorKeyRecord::active(
            scoped_capability_connector("files", &grant_id),
            None,
            Vec::new(),
            10,
        ),
    )?;
    let policy = resolve(&vault)?;
    let in_scope_call = || crate::outbound_consent::ScopedMcpCallContext {
        server: "files".to_owned(),
        tool: "read_file".to_owned(),
        payload_data_class: crate::outbound_consent::DataClass::Personal,
        resolved_endpoint: "https://files.internal.example".to_owned(),
    };

    let mut in_scope = external_effect_gate_input(&test_id(0xE0).to_hex(), "send", "mcp:calendar");
    in_scope.has_opted_in = false;
    in_scope.scoped_mcp_call = Some(in_scope_call());
    let (_, decision, _) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &in_scope, &policy, true)
    })?;
    assert_eq!(decision.outcome(), GateOutcome::Allow);

    let exceeds = [
        crate::outbound_consent::ScopedMcpCallContext {
            server: "calendar".to_owned(),
            ..in_scope_call()
        },
        crate::outbound_consent::ScopedMcpCallContext {
            tool: "write_file".to_owned(),
            ..in_scope_call()
        },
        crate::outbound_consent::ScopedMcpCallContext {
            payload_data_class: crate::outbound_consent::DataClass::Secret,
            ..in_scope_call()
        },
        crate::outbound_consent::ScopedMcpCallContext {
            resolved_endpoint: "https://exfil.example".to_owned(),
            ..in_scope_call()
        },
    ];
    let mut escalations = 0_usize;
    for call in exceeds {
        let mut effect =
            external_effect_gate_input(&test_id(0xE0).to_hex(), "send", "mcp:calendar");
        effect.has_opted_in = false;
        effect.scoped_mcp_call = Some(call);
        let (_, decision, _) = vault.with_write_txn(|wtxn| {
            check_external_effect_policy(&vault.store, wtxn, &effect, &policy, true)
        })?;
        assert_eq!(decision.outcome(), GateOutcome::Pending);
        escalations = escalations.saturating_add(1);
    }
    // Discriminating: presence-only authorization makes at least one of the
    // four scope-exceeds Allow instead of recording all four escalations.
    assert_eq!(escalations, 4);
    Ok(())
}

#[test]
fn scoped_mcp_grant_without_registered_connector_key_stays_pending() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xDC), &encode_policy_manifest(vec![]))?;
    let grant_id = test_id(0xDD);
    vault.mint_scoped_mcp_outbound_grant(
        &grant_id,
        &crate::outbound_grant::ScopedMcpGrantMintIntent {
            principal_ref: test_id(0xE0).to_hex(),
            origin_component_id: "ask-mcp".to_owned(),
            origin_action_id: "grant-scoped-mcp".to_owned(),
            origin_receipt_ref: Some("gate:ask-mcp".to_owned()),
            server: "files".to_owned(),
            tool: "read_file".to_owned(),
            data_class_ceiling: crate::outbound_consent::DataClass::Personal,
            endpoint_allowlist: vec!["https://files.internal.example".to_owned()],
        },
        10,
    )?;
    let policy = resolve(&vault)?;
    let mut effect = external_effect_gate_input(&test_id(0xE0).to_hex(), "send", "mcp:calendar");
    effect.has_opted_in = false;
    effect.scoped_mcp_call = Some(crate::outbound_consent::ScopedMcpCallContext {
        server: "files".to_owned(),
        tool: "read_file".to_owned(),
        payload_data_class: crate::outbound_consent::DataClass::Personal,
        resolved_endpoint: "https://files.internal.example".to_owned(),
    });

    let (_, decision, _) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &effect, &policy, true)
    })?;
    // Discriminating: this exact-principal, in-scope call used to Allow when
    // its synthetic scoped-MCP connector key was not registered.
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.pending.connector_key_unregistered"]
    );
    assert_eq!(decision.receipt_reasons(), &["connector_key_unregistered"]);
    Ok(())
}

#[test]
fn scoped_mcp_grant_budget_matches_its_synthetic_governing_key() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xC0), &encode_policy_manifest(vec![]))?;
    let principal_ref = test_id(0xE0).to_hex();
    let grant_id = test_id(0xC1);
    vault.mint_scoped_mcp_outbound_grant(
        &grant_id,
        &crate::outbound_grant::ScopedMcpGrantMintIntent {
            principal_ref: principal_ref.clone(),
            origin_component_id: "ask-mcp".to_owned(),
            origin_action_id: "grant-scoped-mcp".to_owned(),
            origin_receipt_ref: Some("gate:ask-mcp".to_owned()),
            server: "files".to_owned(),
            tool: "read_file".to_owned(),
            data_class_ceiling: crate::outbound_consent::DataClass::Personal,
            endpoint_allowlist: vec!["https://files.internal.example".to_owned()],
        },
        10,
    )?;
    let governing_connector = scoped_capability_connector("files", &grant_id);
    let key_id = test_id(0xC2);
    vault.register_connector_key(
        &key_id,
        crate::connector_key::ConnectorKeyRecord::active(
            governing_connector,
            None,
            vec![crate::connector_key::EffectorBudget::rate(1, 3_600)],
            10,
        ),
    )?;

    let policy = resolve(&vault)?;
    let mut effect = external_effect_gate_input(&principal_ref, "send", "mcp:calendar");
    effect.has_opted_in = false;
    effect.send_ref = Some("intent:scoped".to_owned());
    effect.scoped_mcp_call = Some(crate::outbound_consent::ScopedMcpCallContext {
        server: "files".to_owned(),
        tool: "read_file".to_owned(),
        payload_data_class: crate::outbound_consent::DataClass::Personal,
        resolved_endpoint: "https://files.internal.example".to_owned(),
    });

    // The first in-scope scoped call charges the rate-1 budget on the
    // synthetic per-grant key.
    let (_, decision, charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy_with_budget(&vault.store, wtxn, &effect, &policy, true)
    })?;
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    assert!(charge.is_some(), "the synthetic governing row was enforced");

    // Discriminating: the rate-1 cap lives on the synthetic per-grant key.
    // Comparing against the raw mcp:calendar channel would miss the cap and
    // let this second in-scope scoped call auto-fire instead of exhausting.
    let (_, decision, _) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy_with_budget(&vault.store, wtxn, &effect, &policy, true)
    })?;
    assert_eq!(decision.outcome(), GateOutcome::Deny);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.deny.effector_budget_exhausted"]
    );
    Ok(())
}

#[test]
fn scoped_mcp_grant_dissolves_only_its_proposed_external_effect_fork() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let herald_id = test_id(0xB7);
    vault.put_agent_definition(
        &herald_id,
        &agent_def_fixture("test.proposed.scoped_mcp", AgentCeiling::Proposed),
        test_time(1),
        1,
    )?;
    put_policy_manifest_bytes(&vault, test_id(0xB8), &encode_policy_manifest(vec![]))?;
    let grant_id = test_id(0xB9);
    vault.mint_scoped_mcp_outbound_grant(
        &grant_id,
        &crate::outbound_grant::ScopedMcpGrantMintIntent {
            principal_ref: herald_id.to_hex(),
            origin_component_id: "ask-mcp".to_owned(),
            origin_action_id: "grant-scoped-mcp".to_owned(),
            origin_receipt_ref: Some("gate:ask-mcp".to_owned()),
            server: "files".to_owned(),
            tool: "read_file".to_owned(),
            data_class_ceiling: crate::outbound_consent::DataClass::Personal,
            endpoint_allowlist: vec!["https://files.internal.example".to_owned()],
        },
        10,
    )?;
    vault.register_connector_key(
        &test_id(0xBA),
        crate::connector_key::ConnectorKeyRecord::active(
            scoped_capability_connector("files", &grant_id),
            None,
            Vec::new(),
            10,
        ),
    )?;
    let policy = resolve(&vault)?;
    let mut effect = external_effect_gate_input(&herald_id.to_hex(), "send", "mcp:calendar");
    effect.actor.actor_class = "agent".to_owned();
    effect.provenance.actor_entity_ref = Some(herald_id);
    effect.has_opted_in = false;
    effect.scoped_mcp_call = Some(crate::outbound_consent::ScopedMcpCallContext {
        server: "files".to_owned(),
        tool: "read_file".to_owned(),
        payload_data_class: crate::outbound_consent::DataClass::Personal,
        resolved_endpoint: "https://files.internal.example".to_owned(),
    });

    let (_, decision, _) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &effect, &policy, true)
    })?;
    // Discriminating: leaving the earlier actor-ceiling branch unchanged
    // adds PendingActorCeiling despite the verified scoped grant.
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    Ok(())
}

#[test]
fn scoped_mcp_grant_does_not_cross_an_unverified_identity_pair() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xBB), &encode_policy_manifest(vec![]))?;
    let caller_id = test_id(0xBC);
    let grant_owner_id = test_id(0xBD);
    let grant_id = test_id(0xBE);
    vault.mint_scoped_mcp_outbound_grant(
        &grant_id,
        &crate::outbound_grant::ScopedMcpGrantMintIntent {
            principal_ref: grant_owner_id.to_hex(),
            origin_component_id: "ask-mcp".to_owned(),
            origin_action_id: "grant-scoped-mcp".to_owned(),
            origin_receipt_ref: Some("gate:ask-mcp".to_owned()),
            server: "files".to_owned(),
            tool: "read_file".to_owned(),
            data_class_ceiling: crate::outbound_consent::DataClass::Personal,
            endpoint_allowlist: vec!["https://files.internal.example".to_owned()],
        },
        10,
    )?;
    vault.register_connector_key(
        &test_id(0xBF),
        crate::connector_key::ConnectorKeyRecord::active(
            scoped_capability_connector("files", &grant_id),
            None,
            Vec::new(),
            10,
        ),
    )?;
    let policy = resolve(&vault)?;
    let mut effect = external_effect_gate_input(&caller_id.to_hex(), "send", "mcp:calendar");
    effect.actor.actor_class = "agent".to_owned();
    effect.provenance.actor_entity_ref = Some(grant_owner_id);
    effect.has_opted_in = false;
    effect.scoped_mcp_call = Some(crate::outbound_consent::ScopedMcpCallContext {
        server: "files".to_owned(),
        tool: "read_file".to_owned(),
        payload_data_class: crate::outbound_consent::DataClass::Personal,
        resolved_endpoint: "https://files.internal.example".to_owned(),
    });

    let (_, decision, _) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &effect, &policy, true)
    })?;
    // Discriminating: the caller's own actor_ref is paired with a different
    // entity that owns this in-scope grant; matching either identity would
    // dissolve the Proposed clamp and make this call Allow.
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    Ok(())
}

#[test]
fn standing_outbound_grant_reasks_out_of_scope_stale_and_revoked_sends() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xDA), &encode_policy_manifest(vec![]))?;

    let grant_id = test_id(0xDB);
    let intent = GrantMintIntent {
        principal_ref: "sender".to_owned(),
        origin_component_id: "ask-1".to_owned(),
        origin_action_id: "escalate_always_this_channel".to_owned(),
        origin_receipt_ref: Some("gate:ask-1".to_owned()),
        scope: GrantMintIntentScope::Channel {
            channel: "line".to_owned(),
        },
    };
    vault.mint_standing_outbound_grant(&grant_id, &intent, 10)?;
    let policy = resolve(&vault)?;

    let mut out_of_scope = external_effect_gate_input("sender", "send", "email");
    out_of_scope.has_opted_in = false;
    let (_decision_id, decision, _effector_charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &out_of_scope, &policy, true)
    })?;
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&decision),
        vec![
            "gate.pending.consent.irreversible_effect",
            "gate.pending.external_effect_authority",
        ]
    );

    let mut lifecycle_effect = external_effect_gate_input("sender", "provision", "line");
    lifecycle_effect.has_opted_in = false;
    let (_decision_id, decision, _effector_charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &lifecycle_effect, &policy, true)
    })?;
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&decision),
        vec![
            "gate.pending.consent.irreversible_effect",
            "gate.pending.external_effect_authority",
        ]
    );

    put_policy_manifest_bytes(&vault, test_id(0xDC), &encode_policy_manifest(vec![]))?;
    let stale_policy = resolve(&vault)?;
    let mut in_scope_stale = external_effect_gate_input("sender", "send", "line");
    in_scope_stale.has_opted_in = false;
    let (_decision_id, decision, _effector_charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &in_scope_stale, &stale_policy, true)
    })?;
    assert_eq!(decision.outcome(), GateOutcome::Pending);

    vault.revoke_standing_outbound_grant(&grant_id, 20)?;
    let mut in_scope_revoked = external_effect_gate_input("sender", "send", "line");
    in_scope_revoked.has_opted_in = false;
    let (_decision_id, decision, _effector_charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &in_scope_revoked, &stale_policy, true)
    })?;
    assert_eq!(decision.outcome(), GateOutcome::Pending);

    let lens = vault.standing_outbound_grants_lens(StandingOutboundGrantsLensQuery::new(10, 10))?;
    assert_eq!(lens.grants.len(), 1);
    assert_eq!(lens.grants[0].status, "revoked");
    assert_eq!(lens.grants[0].revoked_at, Some(20));
    assert_eq!(lens.grants[0].scope_dial, "always_this_channel");
    assert_eq!(
        lens.grants[0].origin_receipt_ref.as_deref(),
        Some("gate:ask-1")
    );
    Ok(())
}

#[test]
fn counterparty_contact_records_are_visible_and_revocable_by_identity() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let identity = test_id(0xC7);
    let intro_id = test_id(0xC8);
    let inbound_id = test_id(0xC9);
    let intro = CounterpartyContactRecord::user_introduction(identity, " kenji@example.com ", 10)?;
    let inbound = CounterpartyContactRecord::inbound_first(identity, "+15551234567", 11)?;

    vault.create_counterparty_contact(&intro_id, &intro)?;
    vault.create_counterparty_contact(&inbound_id, &inbound)?;

    let found = vault
        .find_counterparty_contact(&identity, "kenji@example.com")?
        .expect("intro contact visible by target");
    assert_eq!(found.0, intro_id);
    assert_eq!(
        found.1.first_touch,
        CounterpartyFirstTouch::UserIntroduction
    );
    assert_eq!(found.1.counterparty, "kenji@example.com");

    let contacts = vault.counterparty_contacts_for_identity(&identity)?;
    assert_eq!(contacts.len(), 2);

    let revoked = vault.revoke_counterparty_contact(&intro_id, 20)?;
    assert_eq!(revoked.status, CounterpartyContactStatus::Revoked);
    assert!(revoked.revoked_at.is_some());

    let stored = vault
        .get_counterparty_contact(&intro_id)?
        .expect("revoked stored");
    assert_eq!(stored.identity_ref, identity);
    assert_eq!(stored.counterparty, "kenji@example.com");
    assert_eq!(stored.status, CounterpartyContactStatus::Revoked);
    assert!(stored.revoked_at.is_some());
    Ok(())
}

#[test]
fn counterparty_contact_lookup_uses_dedicated_index_before_scan() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let identity = test_id(0xC7);
    let contact_id = test_id(0xC8);
    let contact = CounterpartyContactRecord::user_introduction(identity, "kenji@example.com", 10)?;
    vault.create_counterparty_contact(&contact_id, &contact)?;

    // Persist an incomplete-index integrity fixture: the contact and its
    // identity-counterparty association remain stored without a type-index row.
    // Visibility and normalized assignment uniqueness must survive this state.
    vault.with_write_txn(|wtxn| {
        let type_key = Store::encode_type_key(ENTITY_TYPE_COUNTERPARTY_CONTACT, &contact_id);
        vault.store.type_index.delete(wtxn, &type_key)?;
        Ok(())
    })?;

    let found = vault
        .find_counterparty_contact(&identity, "kenji@example.com")?
        .expect("stored contact remains visible with an incomplete index");
    assert_eq!(found.0, contact_id);
    assert_eq!(found.1.counterparty, "kenji@example.com");

    let duplicate_id = test_id(0xC9);
    let duplicate = CounterpartyContactRecord::inbound_first(identity, " kenji@example.com ", 20)?;
    let err = vault
        .create_counterparty_contact(&duplicate_id, &duplicate)
        .expect_err("incomplete index must not permit a duplicate counterparty assignment");
    assert!(matches!(
        err.kind(),
        ErrorKind::CounterpartyContactAlreadyExists,
    ));
    Ok(())
}

/// ONE-1752: the grant is irrelevant to the opt-out consequence, exactly as
/// before — only the consequence itself moved from a deny to a held owner
/// decision.
#[test]
fn external_effect_holds_opted_out_counterparty_regardless_of_grant() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let data = encode_policy_manifest(vec![external_effect_scoped_grant_entry(
        "sender",
        "send",
        Value::Map(vec![(
            Value::from(EXTERNAL_EFFECT_SCOPE_CHANNEL_KEY),
            Value::from("line"),
        )]),
        None,
    )]);
    put_policy_manifest_bytes(&vault, test_id(0xD5), &data)?;
    let policy = resolve(&vault)?;

    let identity = test_id(0xCA);
    let contact_id = test_id(0xCB);
    let contact = CounterpartyContactRecord::user_introduction(identity, "kenji@example.com", 10)?;
    vault.create_counterparty_contact(&contact_id, &contact)?;
    let opted_out = vault.opt_out_counterparty_contact(
        &contact_id,
        CounterpartyOptOutReason::Unsubscribe,
        20,
    )?;
    assert!(opted_out.is_opted_out());

    let mut effect = external_effect_gate_input("sender", "send", "line");
    effect.channel_identity_ref = Some(identity);
    effect.counterparty = Some("kenji@example.com".to_owned());

    let (_decision_id, decision, _effector_charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &effect, &policy, true)
    })?;

    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.pending.counterparty_opt_out"]
    );
    assert_eq!(
        decision.receipt_reasons(),
        &[
            "counterparty_opt_out_unsubscribe",
            "counterparty_first_touch_user_introduction"
        ]
    );

    let decisions = vault.store.gate_decisions(10)?;
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].outcome, "pending");
    assert_eq!(
        decisions[0].reason_codes,
        vec!["gate.pending.counterparty_opt_out"]
    );
    assert_eq!(
        decisions[0].receipt_reasons,
        vec![
            "counterparty_opt_out_unsubscribe",
            "counterparty_first_touch_user_introduction"
        ]
    );

    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))?;
    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipts[0].policy_trace,
        vec![
            "gate.pending.counterparty_opt_out",
            "counterparty_opt_out_unsubscribe",
            "counterparty_first_touch_user_introduction"
        ]
    );
    assert_eq!(
        receipts[0].fields.get("receipt_reason").map(String::as_str),
        Some("counterparty_opt_out_unsubscribe")
    );
    assert_eq!(
        receipts[0]
            .fields
            .get("receipt_reasons")
            .map(String::as_str),
        Some("counterparty_opt_out_unsubscribe,counterparty_first_touch_user_introduction")
    );
    Ok(())
}
