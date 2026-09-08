//! Definition ceiling and charter never-key and never-channel enforcement.

use super::*;

#[test]
fn definition_ceiling_clamps_manifest_auto() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut data = encode_policy_manifest(vec![]);
    append_actor_ceiling(&mut data, actor_ceiling_row("agent", "auto"));
    put_policy_manifest_bytes(&vault, test_id(0xC1), &data)?;
    let policy = resolve(&vault)?;

    let mut input = gate_evaluator_input(
        "agent",
        Some("dispatched-agent"),
        ClaimSource::UserStated,
        PolicyCriticality::Normal,
    );
    assert_eq!(
        policy.evaluate_gate(&input).outcome(),
        GateOutcome::Allow,
        "no definition bound keeps the manifest grant"
    );

    input.agent_definition_ceiling = Some(PolicyApprovalCeiling::Auto);
    assert_eq!(
        policy.evaluate_gate(&input).outcome(),
        GateOutcome::Allow,
        "an Auto definition ceiling does not restrict the grant"
    );

    input.agent_definition_ceiling = Some(PolicyApprovalCeiling::Proposed);
    let decision = policy.evaluate_gate(&input);
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        decision.reason_codes(),
        &[GateReasonCode::PendingActorCeiling]
    );
    Ok(())
}

#[test]
fn charter_enforcement_requires_the_human_stamp() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xD0), &connector_key_line_send_manifest())?;
    let key_id = test_id(0x7B);
    vault.register_connector_key(
        &key_id,
        crate::connector_key::ConnectorKeyRecord::active("line", None, Vec::new(), 1_000),
    )?;
    let policy = resolve(&vault)?;
    let mut effect = external_effect_gate_input("sender", "send", "line");
    effect.send_ref = Some("intent:one".to_owned());

    // (a) After propose alone, enforcement is unchanged: the matching
    // never-line does not bind.
    let pending = vault.propose_connector_charter(&key_id, "never send on line", 1_001)?;
    let (decision, _) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(decision.outcome(), GateOutcome::Allow);

    // (b) A wrong re-presented hash is rejected and enforcement stays
    // unchanged.
    assert!(matches!(
        vault.approve_connector_charter(&key_id, [0xEE; 32], "owner", 1_002),
        Err(Error::ConnectorCharterApprovalMismatch)
    ));
    let (decision, _) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(decision.outcome(), GateOutcome::Allow);

    // (c) The stamped charter binds: the same dispatch now denies on the
    // never-list and consumes no budget (charge None).
    vault.approve_connector_charter(&key_id, pending.compiled_hash, "owner", 1_003)?;
    let deny_before =
        gate_metrics_snapshot().count(GateOutcome::Deny, GateMetricReasonClass::CharterPolicy);
    let (decision, charge) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(decision.outcome(), GateOutcome::Deny);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.deny.charter_never_list"]
    );
    assert!(decision.receipt_reasons().contains(&"charter_never_list"));
    assert!(charge.is_none(), "a never-list deny never reaches budgets");
    let deny_after =
        gate_metrics_snapshot().count(GateOutcome::Deny, GateMetricReasonClass::CharterPolicy);
    assert!(deny_after > deny_before, "CharterPolicy deny metric counts");

    Ok(())
}

/// The real engine-produced per-grant capability connector. Tests may only
/// obtain a capability spelling through the engine producer (ONE-1885).
pub(super) fn scoped_capability_connector(server: &str, grant_id: &EntityId) -> String {
    crate::connector_key::ScopedCapabilityProvenance::mint(server, grant_id)
        .expect("safe canonical scoped server")
        .connector()
        .to_owned()
}

fn scoped_mcp_grant_intent(
    principal_ref: &str,
    server: &str,
) -> crate::outbound_grant::ScopedMcpGrantMintIntent {
    crate::outbound_grant::ScopedMcpGrantMintIntent {
        principal_ref: principal_ref.to_owned(),
        origin_component_id: "ask-mcp".to_owned(),
        origin_action_id: "grant-scoped-mcp".to_owned(),
        origin_receipt_ref: Some("gate:ask-mcp".to_owned()),
        server: server.to_owned(),
        tool: "read_file".to_owned(),
        data_class_ceiling: crate::outbound_consent::DataClass::Personal,
        endpoint_allowlist: vec!["https://files.internal.example".to_owned()],
    }
}

fn scoped_mcp_effect(principal: EntityId, server: &str) -> ExternalEffectGateInput {
    let mut effect = external_effect_gate_input(&principal.to_hex(), "send", "mcp:calendar");
    effect.provenance.actor_entity_ref = Some(principal);
    effect.has_opted_in = false;
    effect.scoped_mcp_call = Some(crate::outbound_consent::ScopedMcpCallContext {
        server: server.to_owned(),
        tool: "read_file".to_owned(),
        payload_data_class: crate::outbound_consent::DataClass::Personal,
        resolved_endpoint: "https://files.internal.example".to_owned(),
    });
    effect
}

#[test]
fn charter_never_key_denies_one_scoped_grant_without_widening() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xC6), &encode_policy_manifest(vec![]))?;
    let denied_principal = test_id(0xE0);
    let neighbour_principal = test_id(0xE3);
    let denied_grant = test_id(0xC7);
    let neighbour_grant = test_id(0xC8);
    let hyphen_grant = test_id(0xC9);
    vault.mint_scoped_mcp_outbound_grant(
        &denied_grant,
        &scoped_mcp_grant_intent(&denied_principal.to_hex(), "files"),
        10,
    )?;
    vault.mint_scoped_mcp_outbound_grant(
        &neighbour_grant,
        &scoped_mcp_grant_intent(&neighbour_principal.to_hex(), "files"),
        10,
    )?;
    vault.mint_scoped_mcp_outbound_grant(
        &hyphen_grant,
        &scoped_mcp_grant_intent(&denied_principal.to_hex(), "my-server"),
        10,
    )?;
    let denied_key = test_id(0xCA);
    let neighbour_key = test_id(0xCB);
    let hyphen_key = test_id(0xCC);
    for (key_id, grant_id, server) in [
        (denied_key, denied_grant, "files"),
        (neighbour_key, neighbour_grant, "files"),
        (hyphen_key, hyphen_grant, "my-server"),
    ] {
        vault.register_connector_key(
            &key_id,
            crate::connector_key::ConnectorKeyRecord::active(
                scoped_capability_connector(server, &grant_id),
                None,
                Vec::new(),
                10,
            ),
        )?;
    }
    let policy = resolve(&vault)?;
    let denied_effect = scoped_mcp_effect(denied_principal, "files");
    let neighbour_effect = scoped_mcp_effect(neighbour_principal, "files");
    let hyphen_effect = scoped_mcp_effect(denied_principal, "my-server");

    // Every in-scope scoped call auto-fires before any charter is stamped.
    for effect in [&denied_effect, &neighbour_effect, &hyphen_effect] {
        let (decision, _) = check_effect(&vault, effect, &policy)?;
        assert_eq!(decision.outcome(), GateOutcome::Allow);
    }

    // The owner stamps a deny naming ONE exact per-grant capability key. Before
    // ONE-1885 this charter could not even be stored: the entry carries three
    // colons, so the record validator rejected it and the prohibition was
    // inexpressible.
    let denied_capability = scoped_capability_connector("files", &denied_grant);
    let text = format!("never key {denied_capability}");
    let pending = vault.propose_connector_charter(&denied_key, &text, 1_001)?;
    vault.approve_connector_charter(&denied_key, pending.compiled_hash, "owner", 1_002)?;
    // The neighbour key carries the SAME stamped text, naming the other grant.
    let pending = vault.propose_connector_charter(&neighbour_key, &text, 1_001)?;
    vault.approve_connector_charter(&neighbour_key, pending.compiled_hash, "owner", 1_002)?;

    let (decision, charge) = check_effect(&vault, &denied_effect, &policy)?;
    assert_eq!(decision.outcome(), GateOutcome::Deny);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.deny.charter_never_list"]
    );
    assert!(decision.receipt_reasons().contains(&"charter_never_list"));
    assert!(charge.is_none(), "a never-list deny never reaches budgets");

    // Discriminating: the deny binds that grant's identity, not the server, the
    // channel, or the tool. A second grant on the SAME server, with the same
    // tool and channel and the SAME stamped text, keeps its prior outcome — a
    // first-segment or prefix reading of the entry would deny it too.
    let (decision, _) = check_effect(&vault, &neighbour_effect, &policy)?;
    assert_eq!(decision.outcome(), GateOutcome::Allow);

    // A canonical hyphenated server stays hyphenated through grant, key,
    // charter compilation, and gate matching.
    let hyphen_hex = hyphen_grant.to_hex();
    let hyphen_text = format!("never key mcp:my-server:grant:{hyphen_hex}");
    let pending = vault.propose_connector_charter(&hyphen_key, &hyphen_text, 1_003)?;
    vault.approve_connector_charter(&hyphen_key, pending.compiled_hash, "owner", 1_004)?;
    let (decision, _) = check_effect(&vault, &hyphen_effect, &policy)?;
    assert_eq!(decision.outcome(), GateOutcome::Deny);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.deny.charter_never_list"]
    );
    Ok(())
}

#[test]
fn charter_never_channel_preserves_hyphen_and_underscore_for_scoped_calls() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xD5), &encode_policy_manifest(vec![]))?;
    let principal = test_id(0xD0);
    let hyphen_grant = test_id(0xD1);
    let underscore_grant = test_id(0xD2);
    vault.mint_scoped_mcp_outbound_grant(
        &hyphen_grant,
        &scoped_mcp_grant_intent(&principal.to_hex(), "foo-bar"),
        10,
    )?;
    vault.mint_scoped_mcp_outbound_grant(
        &underscore_grant,
        &scoped_mcp_grant_intent(&principal.to_hex(), "foo_bar"),
        10,
    )?;
    let hyphen_key = test_id(0xD3);
    let underscore_key = test_id(0xD4);
    vault.register_connector_key(
        &hyphen_key,
        crate::connector_key::ConnectorKeyRecord::active(
            scoped_capability_connector("foo-bar", &hyphen_grant),
            None,
            Vec::new(),
            10,
        ),
    )?;
    vault.register_connector_key(
        &underscore_key,
        crate::connector_key::ConnectorKeyRecord::active(
            scoped_capability_connector("foo_bar", &underscore_grant),
            None,
            Vec::new(),
            10,
        ),
    )?;
    let policy = resolve(&vault)?;
    let hyphen_effect = scoped_mcp_effect(principal, "foo-bar");
    let underscore_effect = scoped_mcp_effect(principal, "foo_bar");
    assert_eq!(
        check_effect(&vault, &hyphen_effect, &policy)?.0.outcome(),
        GateOutcome::Allow
    );
    assert_eq!(
        check_effect(&vault, &underscore_effect, &policy)?
            .0
            .outcome(),
        GateOutcome::Allow
    );

    // The ordinary-channel wildcard preserves the complete scoped server
    // connector. It denies the hyphenated server and never aliases `_` to `-`.
    for key_id in [hyphen_key, underscore_key] {
        let pending = vault.propose_connector_charter(&key_id, "never * on mcp:foo-bar", 1_001)?;
        vault.approve_connector_charter(&key_id, pending.compiled_hash, "owner", 1_002)?;
    }
    let (decision, charge) = check_effect(&vault, &hyphen_effect, &policy)?;
    assert_eq!(decision.outcome(), GateOutcome::Deny);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.deny.charter_never_list"]
    );
    assert!(charge.is_none());
    let (decision, _) = check_effect(&vault, &underscore_effect, &policy)?;
    assert_eq!(decision.outcome(), GateOutcome::Allow);

    // A named ordinary rule spelled the OTHER way never reaches the typed call:
    // the normalized ordinary entry (`mcp:foo_bar:*` for either spelling) is not
    // an axis a typed dispatch reads, so no aliasing can occur in either
    // direction.
    let alias_key = test_id(0xD6);
    let alias_grant = test_id(0xD8);
    let alias_principal = test_id(0xD9);
    vault.mint_scoped_mcp_outbound_grant(
        &alias_grant,
        &scoped_mcp_grant_intent(&alias_principal.to_hex(), "foo-bar"),
        10,
    )?;
    vault.register_connector_key(
        &alias_key,
        crate::connector_key::ConnectorKeyRecord::active(
            scoped_capability_connector("foo-bar", &alias_grant),
            None,
            Vec::new(),
            10,
        ),
    )?;
    let policy = resolve(&vault)?;
    let alias_effect = scoped_mcp_effect(alias_principal, "foo-bar");
    let pending = vault.propose_connector_charter(&alias_key, "never * on mcp:foo_bar", 1_003)?;
    vault.approve_connector_charter(&alias_key, pending.compiled_hash, "owner", 1_004)?;
    let (decision, _) = check_effect(&vault, &alias_effect, &policy)?;
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    Ok(())
}

#[test]
fn charter_wildcard_channel_still_binds_typed_scoped_calls() -> Result<()> {
    // `never <verb>` names NO channel spelling, so it cannot alias `foo-bar`
    // onto `foo_bar` and must keep binding every dispatch — a typed scoped-MCP
    // call included. The private exact-scoped entry deliberately never carries a
    // wildcard channel, so this whole-fleet form is the one ordinary rule a
    // typed call reads.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xE5), &encode_policy_manifest(vec![]))?;
    let principal = test_id(0xE6);
    let grant_id = test_id(0xE7);
    vault.mint_scoped_mcp_outbound_grant(
        &grant_id,
        &scoped_mcp_grant_intent(&principal.to_hex(), "foo-bar"),
        10,
    )?;
    let key_id = test_id(0xE8);
    vault.register_connector_key(
        &key_id,
        crate::connector_key::ConnectorKeyRecord::active(
            scoped_capability_connector("foo-bar", &grant_id),
            None,
            Vec::new(),
            10,
        ),
    )?;
    let policy = resolve(&vault)?;
    let effect = scoped_mcp_effect(principal, "foo-bar");
    assert_eq!(
        check_effect(&vault, &effect, &policy)?.0.outcome(),
        GateOutcome::Allow
    );

    let pending = vault.propose_connector_charter(&key_id, "never read_file", 1_001)?;
    vault.approve_connector_charter(&key_id, pending.compiled_hash, "owner", 1_002)?;
    let (decision, charge) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(decision.outcome(), GateOutcome::Deny);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.deny.charter_never_list"]
    );
    assert!(charge.is_none(), "a never-list deny never reaches budgets");

    // Discriminating: the wildcard binds only the VERB it names. A second
    // capability whose owner prohibited a DIFFERENT verb fleet-wide keeps its
    // prior outcome, so this is not a blanket scoped deny.
    let other_principal = test_id(0xE9);
    let other_grant = test_id(0xEA);
    let other_key = test_id(0xEB);
    vault.mint_scoped_mcp_outbound_grant(
        &other_grant,
        &scoped_mcp_grant_intent(&other_principal.to_hex(), "foo-bar"),
        10,
    )?;
    vault.register_connector_key(
        &other_key,
        crate::connector_key::ConnectorKeyRecord::active(
            scoped_capability_connector("foo-bar", &other_grant),
            None,
            Vec::new(),
            10,
        ),
    )?;
    let policy = resolve(&vault)?;
    let pending = vault.propose_connector_charter(&other_key, "never send", 1_003)?;
    vault.approve_connector_charter(&other_key, pending.compiled_hash, "owner", 1_004)?;
    let other_effect = scoped_mcp_effect(other_principal, "foo-bar");
    let (decision, _) = check_effect(&vault, &other_effect, &policy)?;
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    Ok(())
}

/// One manifest granting `external:send` on each ordinary colon-bearing
/// channel, so an ordinary dispatch on it reaches the connector-key stage.
fn ordinary_channels_send_manifest(channels: &[&str]) -> Vec<u8> {
    let grant_row = |channel: &str| {
        Value::Map(vec![
            (Value::from(ACTOR_REF_KEY), Value::from("sender")),
            (
                Value::from(GRANT_EFFECTOR_KEY),
                Value::from("external:send"),
            ),
            (
                Value::from(GRANT_SCOPE_KEY),
                Value::Map(vec![(
                    Value::from(EXTERNAL_EFFECT_SCOPE_CHANNEL_KEY),
                    Value::from(channel),
                )]),
            ),
        ])
    };
    encode_policy_manifest(vec![(
        Value::from(POLICY_SCOPED_GRANTS_KEY),
        Value::Array(channels.iter().copied().map(grant_row).collect()),
    )])
}

#[test]
fn charter_never_key_never_reaches_an_ordinary_connector() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // An ordinary connector spelled EXACTLY like a real per-grant capability
    // key. It is ordinary because of how it was constructed — an ordinary
    // registration, with no typed provenance — not because its text fails a
    // heuristic.
    let lookalike = scoped_capability_connector("calendar", &test_id(0xB1));
    let channels = ["mcp:calendar", "mcp:calendar:grant:foo", lookalike.as_str()];
    put_policy_manifest_bytes(
        &vault,
        test_id(0xD2),
        &ordinary_channels_send_manifest(&channels),
    )?;
    let key_ids = [test_id(0xB2), test_id(0xB3), test_id(0xB4)];
    for (key_id, channel) in key_ids.iter().zip(channels) {
        vault.register_connector_key(
            key_id,
            crate::connector_key::ConnectorKeyRecord::active(channel, None, Vec::new(), 10),
        )?;
    }
    let policy = resolve(&vault)?;
    let ordinary_effect = |channel: &str| {
        let mut effect = external_effect_gate_input("sender", "send", channel);
        effect.send_ref = Some("intent:ordinary".to_owned());
        effect
    };

    // A capability-only rule naming the lookalike spelling is stamped on every
    // ordinary key. None of them may be denied by it: `never key` is consulted
    // only against a typed capability identity, which no ordinary row has.
    let capability_text = format!("never key {lookalike}");
    for key_id in &key_ids {
        let pending = vault.propose_connector_charter(key_id, &capability_text, 1_001)?;
        vault.approve_connector_charter(key_id, pending.compiled_hash, "owner", 1_002)?;
    }
    for channel in channels {
        let (decision, _) = check_effect(&vault, &ordinary_effect(channel), &policy)?;
        assert_eq!(
            decision.outcome(),
            GateOutcome::Allow,
            "ordinary connector {channel} must stay ordinary under a never-key rule"
        );
    }

    // The ordinary channel/verb form matches the COMPLETE connector string.
    let pending =
        vault.propose_connector_charter(&key_ids[0], "never send on mcp:calendar", 1_003)?;
    vault.approve_connector_charter(&key_ids[0], pending.compiled_hash, "owner", 1_004)?;
    let (decision, charge) = check_effect(&vault, &ordinary_effect("mcp:calendar"), &policy)?;
    assert_eq!(decision.outcome(), GateOutcome::Deny);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.deny.charter_never_list"]
    );
    assert!(charge.is_none(), "a never-list deny never reaches budgets");
    // A DIFFERENT whole connector is untouched: a first-colon reading of the
    // same rule would deny every `mcp:*` channel.
    let pending = vault.propose_connector_charter(
        &key_ids[1],
        "never send on mcp:calendar:grant:foo",
        1_003,
    )?;
    vault.approve_connector_charter(&key_ids[1], pending.compiled_hash, "owner", 1_004)?;
    let (decision, _) = check_effect(&vault, &ordinary_effect("mcp:calendar:grant:foo"), &policy)?;
    assert_eq!(decision.outcome(), GateOutcome::Deny);
    let (decision, _) = check_effect(&vault, &ordinary_effect(&lookalike), &policy)?;
    assert_eq!(
        decision.outcome(),
        GateOutcome::Allow,
        "an ordinary rule on another connector must not widen"
    );
    Ok(())
}

#[test]
fn charter_compiled_caps_enforce_like_key_budgets() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xD0), &connector_key_line_send_manifest())?;
    let key_id = test_id(0x7C);
    vault.register_connector_key(
        &key_id,
        crate::connector_key::ConnectorKeyRecord::active("line", None, Vec::new(), 1_000),
    )?;
    let pending = vault.propose_connector_charter(&key_id, "cap 2 sends per day on line", 1_001)?;
    vault.approve_connector_charter(&key_id, pending.compiled_hash, "owner", 1_002)?;
    let policy = resolve(&vault)?;
    let mut effect = external_effect_gate_input("sender", "send", "line");
    effect.send_ref = Some("intent:one".to_owned());

    // Sends 1-2 admit and debit the compiled row at index 0x8000; the ladder
    // fires on compiled rows exactly like key rows (Silent50 at 50%, then
    // Plan80 + Land95 at 100%).
    let (decision, charge) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    let charge = charge.expect("charged");
    assert_eq!(charge.matched_rows, vec![0x8000]);
    assert_eq!(charge.read.rows.len(), 1);
    assert_eq!(charge.read.rows[0].row_index, 0x8000);
    assert_eq!(charge.read.rows[0].used, 1);
    assert_eq!(
        charge
            .ladder_events
            .iter()
            .map(|event| event.threshold)
            .collect::<Vec<_>>(),
        vec![crate::llm::BudgetThreshold::Silent50]
    );
    let (decision, charge) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    let plan80_fired = charge
        .expect("charged")
        .ladder_events
        .iter()
        .any(|event| event.threshold == crate::llm::BudgetThreshold::Plan80);
    assert!(plan80_fired, "ladder fires on compiled rows too");

    // The compiled-cap usage row exists at index 0x8000.
    let usage_key = crate::connector_key::connector_key_usage_row_key(&key_id, 0x8000);
    let usage_row_exists = {
        let rtxn = vault.store.env.read_txn()?;
        vault.store.vault_meta.get(&rtxn, &usage_key)?.is_some()
    };
    assert!(usage_row_exists, "compiled-cap usage row at 0x8000");
    // The self.* meter read includes the compiled-cap row (echo property
    // holds post-GOV-10).
    let read = vault
        .effector_budget_read("line", None)?
        .expect("governing key");
    assert_eq!(read.rows.len(), 1);
    assert_eq!(read.rows[0].row_index, 0x8000);
    assert_eq!(read.rows[0].used, 2);

    // The third send exhausts the compiled row: suspend-the-key with the
    // charter-local index in the reason.
    let (decision, _) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.deny.effector_budget_exhausted"]
    );
    let record = vault.get_connector_key(&key_id)?.expect("record");
    assert_eq!(
        record.status,
        crate::connector_key::ConnectorKeyStatus::Suspended
    );
    assert_eq!(
        record.suspended_reason.as_deref(),
        Some("budget_exhausted:charter_row:0")
    );

    // Approving a REPLACEMENT charter clears the positional 0x8000 usage
    // rows in the same txn.
    let replacement =
        vault.propose_connector_charter(&key_id, "cap 3 sends per day on line", 1_010)?;
    vault.approve_connector_charter(&key_id, replacement.compiled_hash, "owner", 1_011)?;
    let usage_row_exists = {
        let rtxn = vault.store.env.read_txn()?;
        vault.store.vault_meta.get(&rtxn, &usage_key)?.is_some()
    };
    assert!(!usage_row_exists, "re-stamp cleared compiled-cap usage");
    Ok(())
}

#[test]
fn charter_and_key_rows_debit_as_one_atomic_union() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xD0), &connector_key_line_send_manifest())?;
    let key_id = test_id(0x7D);
    vault.register_connector_key(
        &key_id,
        crate::connector_key::ConnectorKeyRecord::active(
            "line",
            None,
            vec![crate::connector_key::EffectorBudget::sends(
                10,
                day_window(),
                crate::connector_key::EffectorBudgetOnExhaust::Suspend,
            )],
            1_000,
        ),
    )?;
    let pending = vault.propose_connector_charter(&key_id, "cap 1 sends per day on line", 1_001)?;
    vault.approve_connector_charter(&key_id, pending.compiled_hash, "owner", 1_002)?;
    let policy = resolve(&vault)?;
    let mut effect = external_effect_gate_input("sender", "send", "line");
    effect.send_ref = Some("intent:one".to_owned());

    // The first send debits BOTH rows of the union in one evaluation.
    let (decision, charge) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    let charge = charge.expect("charged");
    assert_eq!(charge.matched_rows, vec![0, 0x8000]);
    assert_eq!(charge.read.rows[0].used, 1, "key row debited");
    assert_eq!(charge.read.rows[1].used, 1, "charter row debited");

    // The second send is refused by the charter row and the key row's usage
    // stays at 1 — no partial debit leaks from the refused evaluation.
    let (decision, charge) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.deny.effector_budget_exhausted"]
    );
    let charge = charge.expect("exhaustion charge");
    assert_eq!(charge.read.rows[0].used, 1, "key row NOT debited");
    assert_eq!(charge.read.rows[1].used, 1);
    assert_eq!(
        vault
            .get_connector_key(&key_id)?
            .expect("record")
            .suspended_reason
            .as_deref(),
        Some("budget_exhausted:charter_row:0")
    );
    Ok(())
}

#[test]
fn definition_ceiling_blocks_edge_provenance_exception() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // No agent-class rows: the manifest has only first_party rows.
    put_policy_manifest_bytes(&vault, test_id(0xC2), &encode_policy_manifest(vec![]))?;
    let policy = resolve(&vault)?;

    let mut input = gate_evaluator_input(
        "agent",
        Some("dispatched-agent"),
        ClaimSource::UserStated,
        PolicyCriticality::Normal,
    );
    input.content_kind = GateContentKind::EdgeProvenanceClaim;

    assert_eq!(
        policy.evaluate_gate(&input).outcome(),
        GateOutcome::Allow,
        "a non-definition agent actor keeps today's no-row exception"
    );

    input.agent_definition_ceiling = Some(PolicyApprovalCeiling::Proposed);
    let decision = policy.evaluate_gate(&input);
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        decision.reason_codes(),
        &[GateReasonCode::PendingActorCeiling]
    );

    // Auto means "does not self-limit", not "inherits the no-row exception":
    // with no owner row the definition-bound actor still holds to proposal.
    input.agent_definition_ceiling = Some(PolicyApprovalCeiling::Auto);
    let decision = policy.evaluate_gate(&input);
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        decision.reason_codes(),
        &[GateReasonCode::PendingActorCeiling]
    );
    Ok(())
}

#[test]
fn definition_ceiling_blocks_external_effect_auto() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut data = encode_policy_manifest(vec![]);
    append_actor_ceiling(&mut data, actor_ceiling_row("agent", "auto"));
    put_policy_manifest_bytes(&vault, test_id(0xC3), &data)?;
    let policy = resolve(&vault)?;

    let mut effect = external_effect_gate_input("dispatched-agent", "send", "line");
    effect.actor.actor_class = "agent".to_owned();
    effect.standing_grant_ref = Some("grant:test".to_owned());

    assert_eq!(
        policy
            .evaluate_gate(&effect.gate_input(None, None))
            .outcome(),
        GateOutcome::Allow,
        "the effect is auto-eligible without a definition bound"
    );

    let decision =
        policy.evaluate_gate(&effect.gate_input(Some(PolicyApprovalCeiling::Proposed), None));
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert!(
        decision
            .reason_codes()
            .contains(&GateReasonCode::PendingExternalEffectAuthority),
        "a Proposed-ceiling agent can never auto-fire an external effect, got {:?}",
        decision.reason_codes()
    );
    Ok(())
}
