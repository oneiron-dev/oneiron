use super::*;
use crate::genui::GrantMintIntentScope;

fn intent(scope: GrantMintIntentScope) -> GrantMintIntent {
    GrantMintIntent {
        principal_ref: "owner".to_owned(),
        origin_component_id: "ask-1".to_owned(),
        origin_action_id: "escalate_always_this_verb_class".to_owned(),
        origin_receipt_ref: Some("gate:ask".to_owned()),
        scope,
    }
}

#[test]
fn standing_outbound_grant_codec_round_trips_active_grant() -> Result<()> {
    let grant = StandingOutboundGrant::from_grant_mint_intent(
        &intent(GrantMintIntentScope::VerbClass {
            verb_class: "send".to_owned(),
        }),
        10,
        vec![0xA5; 32],
        [0xB6; 32],
    )?;

    let encoded = encode_standing_outbound_grant_body(&grant)?;
    validate_standing_outbound_grant_body_bytes(&encoded)?;
    let decoded = decode_standing_outbound_grant_body(&encoded)?;

    assert_eq!(decoded, grant);
    assert_eq!(decoded.scope.dial_label(), "always_this_verb_class");
    assert!(decoded.revoked_at.is_none());
    assert!(decoded.last_used_at.is_none());
    Ok(())
}

#[test]
fn scoped_mcp_grant_codec_round_trips_all_payload_axes() -> Result<()> {
    assert_eq!(OUTBOUND_GRANT_BODY_KEYS[5], "scope");
    assert_eq!(OUTBOUND_GRANT_BODY_KEYS[11], "read_frontier_hash");
    assert_eq!(
        &OUTBOUND_GRANT_BODY_KEYS[12..],
        &["server", "tool", "data_class_ceiling", "endpoint_allowlist"]
    );
    let grant = StandingOutboundGrant {
        principal_ref: "owner".to_owned(),
        origin_component_id: "ask-mcp".to_owned(),
        origin_action_id: "grant-scoped-mcp".to_owned(),
        origin_receipt_ref: Some("gate:mcp".to_owned()),
        scope: StandingOutboundGrantScope::ScopedMcp {
            server: "files".to_owned(),
            tool: "read_file".to_owned(),
            data_class_ceiling: DataClass::Personal,
            endpoint_allowlist: vec!["https://files.internal.example".to_owned()],
        },
        status: StandingOutboundGrantStatus::Active,
        created_at: 10,
        revoked_at: None,
        last_used_at: None,
        binding_diff_handle: vec![0xA5; 32],
        read_frontier_hash: [0xB6; 32],
    };

    let encoded = encode_standing_outbound_grant_body(&grant)?;
    let decoded = decode_standing_outbound_grant_body(&encoded)?;
    // Discriminating: omitting any new pinned scope key breaks equality.
    assert_eq!(decoded, grant);
    assert_eq!(decoded.scope.dial_label(), "scoped_mcp");
    Ok(())
}

#[test]
fn schema_v1_contact_grant_with_legacy_five_key_scope_decodes() -> Result<()> {
    let grant = StandingOutboundGrant::from_grant_mint_intent(
        &intent(GrantMintIntentScope::Contact {
            contact_ref: "contact:legacy".to_owned(),
        }),
        10,
        vec![0xA5; 32],
        [0xB6; 32],
    )?;
    let legacy_value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(OUTBOUND_GRANT_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_PRINCIPAL_REF),
            Value::from(grant.principal_ref.clone()),
        ),
        (
            Value::from(KEY_ORIGIN_COMPONENT_ID),
            Value::from(grant.origin_component_id.clone()),
        ),
        (
            Value::from(KEY_ORIGIN_ACTION_ID),
            Value::from(grant.origin_action_id.clone()),
        ),
        (
            Value::from(KEY_ORIGIN_RECEIPT_REF),
            option_string_value(grant.origin_receipt_ref.as_deref()),
        ),
        (
            Value::from(KEY_SCOPE),
            Value::Map(vec![
                (Value::from(SCOPE_KEYS[0]), Value::from(SCOPE_KIND_CONTACT)),
                (Value::from(SCOPE_KEYS[1]), Value::from("contact:legacy")),
                (Value::from(SCOPE_KEYS[2]), Value::Nil),
                (Value::from(SCOPE_KEYS[3]), Value::Nil),
                (Value::from(SCOPE_KEYS[4]), Value::Nil),
            ]),
        ),
        (Value::from(KEY_STATUS), Value::from(grant.status.as_str())),
        (Value::from(KEY_CREATED_AT), Value::from(grant.created_at)),
        (Value::from(KEY_REVOKED_AT), Value::Nil),
        (Value::from(KEY_LAST_USED_AT), Value::Nil),
        (
            Value::from(KEY_BINDING_DIFF_HANDLE),
            Value::Binary(grant.binding_diff_handle.clone()),
        ),
        (
            Value::from(KEY_READ_FRONTIER_HASH),
            Value::Binary(grant.read_frontier_hash.to_vec()),
        ),
    ]);
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &legacy_value)
        .expect("encode legacy schema-v1 grant fixture");

    // Discriminating: strict nine-key scope validation rejects this legacy
    // on-disk row because it contains only the original five scope keys.
    assert_eq!(decode_standing_outbound_grant_body(&encoded)?, grant);
    Ok(())
}

#[test]
fn contact_grant_decode_rejects_non_nil_scoped_mcp_field() -> Result<()> {
    let grant = StandingOutboundGrant::from_grant_mint_intent(
        &intent(GrantMintIntentScope::Contact {
            contact_ref: "contact:injected".to_owned(),
        }),
        10,
        vec![0xA5; 32],
        [0xB6; 32],
    )?;
    let encoded = encode_standing_outbound_grant_body(&grant)?;
    let mut body = rmpv::decode::read_value(&mut std::io::Cursor::new(encoded))
        .expect("decode contact grant fixture");
    let Value::Map(body_entries) = &mut body else {
        panic!("grant body must be a map");
    };
    let scope = &mut body_entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some(KEY_SCOPE))
        .expect("scope field")
        .1;
    let Value::Map(scope_entries) = scope else {
        panic!("scope must be a map");
    };
    let server = &mut scope_entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some(SCOPE_KEYS[5]))
        .expect("server field")
        .1;
    *server = Value::from("files");
    let mut injected = Vec::new();
    rmpv::encode::write_value(&mut injected, &body).expect("encode injected contact grant fixture");

    let error = decode_standing_outbound_grant_body(&injected)
        .expect_err("non-applicable scoped MCP field must fail closed");
    // Discriminating: without the applicability check, this decodes as a
    // clean blind contact grant while silently ignoring `server`.
    assert_eq!(error.kind(), crate::ErrorKind::InvalidOutboundGrantBody);
    Ok(())
}

#[test]
fn scoped_mcp_grant_decode_rejects_every_non_nil_legacy_scope_field() -> Result<()> {
    let grant = StandingOutboundGrant {
        principal_ref: "owner".to_owned(),
        origin_component_id: "ask-mcp".to_owned(),
        origin_action_id: "grant-scoped-mcp".to_owned(),
        origin_receipt_ref: Some("gate:mcp".to_owned()),
        scope: StandingOutboundGrantScope::ScopedMcp {
            server: "files".to_owned(),
            tool: "read_file".to_owned(),
            data_class_ceiling: DataClass::Personal,
            endpoint_allowlist: vec!["https://files.internal.example".to_owned()],
        },
        status: StandingOutboundGrantStatus::Active,
        created_at: 10,
        revoked_at: None,
        last_used_at: None,
        binding_diff_handle: vec![0xA5; 32],
        read_frontier_hash: [0xB6; 32],
    };
    let encoded = encode_standing_outbound_grant_body(&grant)?;

    for (scope_key, injected_value) in [
        (SCOPE_KEYS[1], Value::from("contact:injected")),
        (SCOPE_KEYS[2], Value::from("send")),
        (SCOPE_KEYS[3], Value::from("channel:injected")),
        (SCOPE_KEYS[4], Value::from("brief:injected")),
    ] {
        let mut body = rmpv::decode::read_value(&mut std::io::Cursor::new(&encoded))
            .expect("decode scoped MCP grant fixture");
        let Value::Map(body_entries) = &mut body else {
            panic!("grant body must be a map");
        };
        let scope = &mut body_entries
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some(KEY_SCOPE))
            .expect("scope field")
            .1;
        let Value::Map(scope_entries) = scope else {
            panic!("scope must be a map");
        };
        let legacy_field = &mut scope_entries
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some(scope_key))
            .expect("legacy scope field")
            .1;
        *legacy_field = injected_value;
        let mut injected = Vec::new();
        rmpv::encode::write_value(&mut injected, &body)
            .expect("encode injected scoped MCP grant fixture");

        let error = decode_standing_outbound_grant_body(&injected)
            .expect_err("non-applicable legacy scope field must fail closed");
        assert_eq!(error.kind(), crate::ErrorKind::InvalidOutboundGrantBody);
    }
    Ok(())
}

#[test]
fn scoped_mcp_grant_decode_rejects_noncanonical_endpoint() {
    let body = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(OUTBOUND_GRANT_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_PRINCIPAL_REF),
            Value::from("principal:scope"),
        ),
        (
            Value::from(KEY_ORIGIN_COMPONENT_ID),
            Value::from("consent:scope"),
        ),
        (
            Value::from(KEY_ORIGIN_ACTION_ID),
            Value::from("grant:scoped_tool"),
        ),
        (Value::from(KEY_ORIGIN_RECEIPT_REF), Value::Nil),
        (
            Value::from(KEY_SCOPE),
            Value::Map(vec![
                (
                    Value::from(SCOPE_KEYS[0]),
                    Value::from(SCOPE_KIND_SCOPED_MCP),
                ),
                (Value::from(SCOPE_KEYS[1]), Value::Nil),
                (Value::from(SCOPE_KEYS[2]), Value::Nil),
                (Value::from(SCOPE_KEYS[3]), Value::Nil),
                (Value::from(SCOPE_KEYS[4]), Value::Nil),
                (Value::from(SCOPE_KEYS[5]), Value::from("files")),
                (Value::from(SCOPE_KEYS[6]), Value::from("read_file")),
                (
                    Value::from(SCOPE_KEYS[7]),
                    Value::from(DataClass::Personal.as_str()),
                ),
                (
                    Value::from(SCOPE_KEYS[8]),
                    Value::Array(vec![Value::from("https://files.internal.example ")]),
                ),
            ]),
        ),
        (
            Value::from(KEY_STATUS),
            Value::from(StandingOutboundGrantStatus::Active.as_str()),
        ),
        (Value::from(KEY_CREATED_AT), Value::from(10_u64)),
        (Value::from(KEY_REVOKED_AT), Value::Nil),
        (Value::from(KEY_LAST_USED_AT), Value::Nil),
        (
            Value::from(KEY_BINDING_DIFF_HANDLE),
            Value::Binary(vec![0xA5; 32]),
        ),
        (
            Value::from(KEY_READ_FRONTIER_HASH),
            Value::Binary(vec![0xB6; 32]),
        ),
    ]);
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &body).expect("encode scoped MCP grant fixture");

    let error = decode_standing_outbound_grant_body(&encoded)
        .expect_err("noncanonical scoped MCP endpoint must fail closed");
    // Discriminating: silent-trim decode would turn this row into a clean
    // endpoint that can auto-authorize instead of rejecting the grant.
    assert_eq!(error.kind(), crate::ErrorKind::InvalidOutboundGrantBody);
}

#[test]
fn standing_outbound_grant_revoke_and_touch_validate_lifecycle() -> Result<()> {
    let grant = StandingOutboundGrant::from_grant_mint_intent(
        &intent(GrantMintIntentScope::Channel {
            channel: "line".to_owned(),
        }),
        10,
        vec![0xA5],
        [0xB6; 32],
    )?;

    let touched = grant.clone().touched(12)?;
    assert_eq!(touched.last_used_at, Some(12));
    let revoked = grant.revoked(20)?;
    assert_eq!(revoked.status, StandingOutboundGrantStatus::Revoked);
    assert_eq!(revoked.revoked_at, Some(20));
    assert!(!revoked.is_active_under_policy(&[0xB6; 32]));
    Ok(())
}

#[test]
fn standing_outbound_grant_scope_matching_is_narrow() {
    let contact = StandingOutboundGrantScope::Contact {
        contact_ref: "contact:yuki".to_owned(),
    };
    assert!(contact.matches_effect("send", "line", Some("contact:yuki"), None));
    assert!(!contact.matches_effect("send", "line", Some("ren"), None));
    assert!(!contact.matches_effect("send", "line", Some("slack:yuki"), None));

    let channel = StandingOutboundGrantScope::Channel {
        channel: "line".to_owned(),
    };
    assert!(channel.matches_effect("send", "line", None, None));
    assert!(!channel.matches_effect("provision", "line", None, None));
    assert!(!channel.matches_effect("send", "email", None, None));

    let contact = StandingOutboundGrantScope::Contact {
        contact_ref: "contact:yuki".to_owned(),
    };
    let verb = StandingOutboundGrantScope::VerbClass {
        verb_class: "send".to_owned(),
    };
    // Discriminating: any blind scope returning true here reopens the
    // argument-blind MCP auto-fire path.
    assert!(!contact.matches_effect("send", "mcp:calendar", Some("contact:yuki"), None));
    assert!(!verb.matches_effect("send", "mcp:calendar", None, None));

    let brief = StandingOutboundGrantScope::BriefVerbClass {
        brief_ref: "brief:party".to_owned(),
        verb_class: "send".to_owned(),
    };
    assert!(brief.matches_effect("send", "line", None, Some("brief:party")));
    assert!(!brief.matches_effect("react", "line", None, Some("brief:party")));
    assert!(!brief.matches_effect("send", "line", None, Some("party")));
    assert!(!brief.matches_effect("send", "line", None, Some("brief:other")));
}

#[test]
fn standing_outbound_grant_rejects_non_standing_intent_scopes() {
    let just_once = StandingOutboundGrant::from_grant_mint_intent(
        &intent(GrantMintIntentScope::JustOnce {
            effect_ref: Some("effect:send-1".to_owned()),
        }),
        10,
        vec![0xA5],
        [0xB6; 32],
    )
    .expect_err("one-shot consent is not a standing grant scope");
    assert_eq!(just_once.kind(), crate::ErrorKind::InvalidOutboundGrantBody);

    let exact_bundle = StandingOutboundGrant::from_grant_mint_intent(
        &intent(GrantMintIntentScope::BundleExactSends {
            send_refs: vec!["send-1".to_owned()],
        }),
        10,
        vec![0xA5],
        [0xB6; 32],
    )
    .expect_err("exact send bundles are not standing grant scopes");
    assert_eq!(
        exact_bundle.kind(),
        crate::ErrorKind::InvalidOutboundGrantBody
    );
}

#[test]
fn standing_outbound_grant_decode_fails_closed_for_malformed_bodies() {
    let err = decode_standing_outbound_grant_body(b"not-msgpack")
        .expect_err("malformed body must fail closed");
    assert_eq!(err.kind(), crate::ErrorKind::InvalidOutboundGrantBody);
}

#[test]
fn standing_outbound_grant_schema_has_no_auto_expiry_field() {
    assert!(!OUTBOUND_GRANT_BODY_KEYS.contains(&"expires_at"));
    assert!(!OUTBOUND_GRANT_BODY_KEYS.contains(&"ttl"));
}

// --- ONE-1885 one safe canonical scoped-server segment -----------------------

fn scoped_intent(server: &str) -> ScopedMcpGrantMintIntent {
    ScopedMcpGrantMintIntent {
        principal_ref: "owner".to_owned(),
        origin_component_id: "ask-mcp".to_owned(),
        origin_action_id: "grant-scoped-mcp".to_owned(),
        origin_receipt_ref: Some("gate:mcp".to_owned()),
        server: server.to_owned(),
        tool: "read_file".to_owned(),
        data_class_ceiling: DataClass::Personal,
        endpoint_allowlist: vec!["https://files.internal.example".to_owned()],
    }
}

fn scoped_mcp_scope_value(server: &str) -> Value {
    Value::Map(vec![
        (
            Value::from(SCOPE_KEYS[0]),
            Value::from(SCOPE_KIND_SCOPED_MCP),
        ),
        (Value::from(SCOPE_KEYS[1]), Value::Nil),
        (Value::from(SCOPE_KEYS[2]), Value::Nil),
        (Value::from(SCOPE_KEYS[3]), Value::Nil),
        (Value::from(SCOPE_KEYS[4]), Value::Nil),
        (Value::from(SCOPE_KEYS[5]), Value::from(server)),
        (Value::from(SCOPE_KEYS[6]), Value::from("read_file")),
        (
            Value::from(SCOPE_KEYS[7]),
            Value::from(DataClass::Personal.as_str()),
        ),
        (
            Value::from(SCOPE_KEYS[8]),
            Value::Array(vec![Value::from("https://files.internal.example")]),
        ),
    ])
}

fn scoped_server_of(grant: &StandingOutboundGrant) -> String {
    grant
        .scope
        .scoped_mcp_grant()
        .expect("scoped grant")
        .server
        .to_owned()
}

#[test]
fn scoped_mcp_grant_creation_pins_one_safe_canonical_server() -> Result<()> {
    let grant_id = EntityId::from_bytes([0x5C; 16]).expect("grant id");

    // An accepted spelling maps to the canonical segment ONCE, at mint, so the
    // stored grant and the per-grant capability key producer name the same
    // authority byte-for-byte.
    for spelling in ["files", "FILES"] {
        let grant = StandingOutboundGrant::from_scoped_mcp_grant_mint_intent(
            &scoped_intent(spelling),
            10,
            vec![0xA5; 32],
            [0xB6; 32],
        )?;
        assert_eq!(scoped_server_of(&grant), "files", "{spelling}");
    }
    let hyphen = StandingOutboundGrant::from_scoped_mcp_grant_mint_intent(
        &scoped_intent("my-server"),
        10,
        vec![0xA5; 32],
        [0xB6; 32],
    )?;
    assert_eq!(scoped_server_of(&hyphen), "my_server");
    let capability = crate::connector_key::ScopedCapabilityProvenance::mint("my-server", &grant_id)
        .expect("safe canonical server");
    assert_eq!(capability.server(), scoped_server_of(&hyphen));
    assert_eq!(
        capability.connector(),
        format!(
            "mcp:{}:grant:{}",
            scoped_server_of(&hyphen),
            grant_id.to_hex()
        )
    );
    // The stored grant round-trips through the persisted codec unchanged.
    let encoded = encode_standing_outbound_grant_body(&hyphen)?;
    assert_eq!(decode_standing_outbound_grant_body(&encoded)?, hyphen);

    // Every unsafe spelling fails closed at the constructor: a colon (which
    // would forge extra capability-key segments), ASCII or Unicode whitespace
    // anywhere, a wildcard/glob spelling, and the empty segment.
    for unsafe_server in [
        "files:extra",
        ":",
        " files",
        "files ",
        "fi les",
        "fi\tles",
        "fi\u{00a0}les",
        "*",
        "fi*",
        "files?",
        "files[1]",
        "",
        "   ",
    ] {
        assert!(
            StandingOutboundGrant::from_scoped_mcp_grant_mint_intent(
                &scoped_intent(unsafe_server),
                10,
                vec![0xA5; 32],
                [0xB6; 32],
            )
            .is_err(),
            "unsafe scoped server {unsafe_server:?} must not mint a grant"
        );
        // The same rule guards the persisted scope: a forged row never decodes.
        assert!(
            decode_scope(&scoped_mcp_scope_value(unsafe_server)).is_err(),
            "unsafe stored scoped server {unsafe_server:?} must fail closed"
        );
    }

    // Stored-form == authority-form: a merely well-shaped non-canonical server
    // would govern under one spelling and enforce under another.
    for non_canonical in ["Files", "my-server"] {
        assert!(
            decode_scope(&scoped_mcp_scope_value(non_canonical)).is_err(),
            "non-canonical stored scoped server {non_canonical:?} must fail closed"
        );
    }
    assert_eq!(
        decode_scope(&scoped_mcp_scope_value("my_server"))?,
        hyphen.scope
    );

    // An in-memory grant carrying an unsafe server can never be persisted.
    let forged = StandingOutboundGrant {
        scope: StandingOutboundGrantScope::ScopedMcp {
            server: "files:extra".to_owned(),
            tool: "read_file".to_owned(),
            data_class_ceiling: DataClass::Personal,
            endpoint_allowlist: vec!["https://files.internal.example".to_owned()],
        },
        ..hyphen
    };
    assert!(encode_standing_outbound_grant_body(&forged).is_err());
    Ok(())
}

#[test]
fn scoped_mcp_admission_shares_the_safe_server_rule() {
    fn call(server: &str) -> crate::outbound_consent::ScopedMcpCall<'_> {
        crate::outbound_consent::ScopedMcpCall {
            server,
            tool: "read_file",
            payload_data_class: DataClass::Personal,
            resolved_endpoint: "https://files.internal.example",
        }
    }

    let grant = StandingOutboundGrant::from_scoped_mcp_grant_mint_intent(
        &scoped_intent("my-server"),
        10,
        vec![0xA5; 32],
        [0xB6; 32],
    )
    .expect("safe canonical server");
    let scope = grant.scope.scoped_mcp_grant().expect("scoped grant");

    // Admission canonicalizes the call's server through the SAME authority, so
    // an accepted spelling of the granted server still auto-fires.
    for spelling in ["my-server", "my_server", "MY-SERVER"] {
        assert_eq!(
            crate::outbound_consent::evaluate_scoped_mcp_call(scope, call(spelling)),
            crate::outbound_consent::ScopedMcpConsentDecision::AutoFire,
            "{spelling}"
        );
    }
    // An unsafe call server has no safe canonical segment at all: it escalates
    // rather than being trimmed or normalized into some other authority.
    for unsafe_server in ["my_server:extra", " my_server", "my server", "my_*", ""] {
        assert_eq!(
            crate::outbound_consent::evaluate_scoped_mcp_call(scope, call(unsafe_server)),
            crate::outbound_consent::ScopedMcpConsentDecision::Escalate(
                crate::outbound_consent::ScopedMcpEscalationReason::WrongServer
            ),
            "{unsafe_server}"
        );
    }
    // A different safe server is still the wrong server.
    assert_eq!(
        crate::outbound_consent::evaluate_scoped_mcp_call(scope, call("other")),
        crate::outbound_consent::ScopedMcpConsentDecision::Escalate(
            crate::outbound_consent::ScopedMcpEscalationReason::WrongServer
        )
    );

    // A grant whose own server is not a safe segment authorizes nothing, even
    // when the call spells the same bytes.
    let endpoints = vec!["https://files.internal.example".to_owned()];
    for unsafe_server in ["my_server:extra", "my server", "my_*", ""] {
        let unsafe_scope = ScopedMcpGrantRef {
            server: unsafe_server,
            tool: "read_file",
            data_class_ceiling: DataClass::Personal,
            endpoint_allowlist: &endpoints,
        };
        assert_eq!(
            crate::outbound_consent::evaluate_scoped_mcp_call(unsafe_scope, call(unsafe_server)),
            crate::outbound_consent::ScopedMcpConsentDecision::Escalate(
                crate::outbound_consent::ScopedMcpEscalationReason::InvalidGrant
            ),
            "{unsafe_server}"
        );
    }
}
