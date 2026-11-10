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
fn artifact_publish_grant_codec_round_trips_without_broad_send_authority() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
    let grant = vault.mint_standing_outbound_grant(
        &crate::test_util::embedded_owner_proof(&vault),
        EntityId::now(),
        &intent(GrantMintIntentScope::ArtifactPublish {
            artifact: "site".to_owned(),
        }),
    )?;
    let row = vault.consent_grant(&grant.grant_ref())?.expect("grant row");
    let encoded = crate::consent::encode_consent_grant_row(&row)?;
    let decoded = StandingOutboundGrant::from_row(&crate::consent::decode_consent_grant_row(&encoded)?)
        .expect("outbound grant row");
    assert_eq!(decoded, grant);
    assert!(
        decoded
            .scope
            .matches_effect("publish", "artifact", Some("site"), None)
    );
    assert!(
        !decoded
            .scope
            .matches_effect("publish", "artifact", Some("other"), None)
    );
    assert!(
        !decoded
            .scope
            .matches_effect("send", "email", Some("site"), None)
    );
    for broad in [
        StandingOutboundGrantScope::VerbClass {
            verb_class: "publish".to_owned(),
        },
        StandingOutboundGrantScope::Contact {
            contact_ref: "site".to_owned(),
        },
        StandingOutboundGrantScope::BriefVerbClass {
            brief_ref: "site".to_owned(),
            verb_class: "publish".to_owned(),
        },
    ] {
        assert!(!broad.matches_effect("publish", "artifact", Some("site"), Some("site")));
    }
    Ok(())
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
    let just_once = StandingOutboundGrantScope::from_grant_mint_scope(
        &intent(GrantMintIntentScope::JustOnce {
            effect_ref: Some("effect:send-1".to_owned()),
        })
        .scope,
    )
    .expect_err("one-shot consent is not a standing grant scope");
    assert_eq!(just_once.kind(), crate::ErrorKind::InvalidOutboundGrantBody);

    let exact_bundle = StandingOutboundGrantScope::from_grant_mint_scope(
        &intent(GrantMintIntentScope::BundleExactSends {
            send_refs: vec!["send-1".to_owned()],
        })
        .scope,
    )
    .expect_err("exact send bundles are not standing grant scopes");
    assert_eq!(
        exact_bundle.kind(),
        crate::ErrorKind::InvalidOutboundGrantBody
    );
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
        tool_data_classes: vec![crate::outbound_consent::tool_call::ToolGrantDataClass::Arguments],
        endpoint_allowlist: vec!["https://files.internal.example".to_owned()],
    }
}

fn scoped_mcp_scope_value(server: &str) -> Value {
    Value::Map(vec![
        (
            Value::from("tool_data_classes"),
            Value::Array(vec![Value::from("arguments")]),
        ),
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

    let files = StandingOutboundGrant::from_scoped_mcp_grant_mint_intent(
        &scoped_intent("files"),
        10,
        vec![0xA5; 32],
        [0xB6; 32],
    )?;
    assert_eq!(scoped_server_of(&files), "files");

    // Hyphen and underscore remain separate canonical capability identities.
    let hyphen = StandingOutboundGrant::from_scoped_mcp_grant_mint_intent(
        &scoped_intent("my-server"),
        10,
        vec![0xA5; 32],
        [0xB6; 32],
    )?;
    let underscore = StandingOutboundGrant::from_scoped_mcp_grant_mint_intent(
        &scoped_intent("my_server"),
        10,
        vec![0xA5; 32],
        [0xB6; 32],
    )?;
    assert_eq!(scoped_server_of(&hyphen), "my-server");
    assert_eq!(scoped_server_of(&underscore), "my_server");
    assert_ne!(scoped_server_of(&hyphen), scoped_server_of(&underscore));
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

    let encoded = encode_standing_outbound_grant_body(&hyphen)?;
    let decoded = decode_standing_outbound_grant_body(&encoded)?;
    assert_eq!(decoded.principal_ref, hyphen.principal_ref);
    assert_eq!(decoded.origin_component_id, hyphen.origin_component_id);
    assert_eq!(decoded.origin_action_id, hyphen.origin_action_id);
    assert_eq!(decoded.origin_receipt_ref, hyphen.origin_receipt_ref);
    assert_eq!(decoded.scope, hyphen.scope);
    assert_eq!(decoded.status, hyphen.status);
    assert_eq!(decoded.binding_diff_handle, hyphen.binding_diff_handle);
    assert_eq!(decoded.read_frontier_hash, hyphen.read_frontier_hash);

    let value = rmpv::decode::read_value(&mut Cursor::new(&encoded)).unwrap();
    let Value::Map(entries) = value else {
        panic!("grant map");
    };

    // Exercise unsafe scope payloads inside complete persisted grant bodies.
    for unsafe_server in [
        "Files",
        "FILES",
        "MY-SERVER",
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
        let mut invalid = entries.clone();
        invalid
            .iter_mut()
            .find(|(key, _)| key == &Value::from(KEY_SCOPE))
            .expect("scope key")
            .1 = scoped_mcp_scope_value(unsafe_server);
        let mut invalid_bytes = Vec::new();
        rmpv::encode::write_value(&mut invalid_bytes, &Value::Map(invalid)).unwrap();
        assert_eq!(
            decode_standing_outbound_grant_body(&invalid_bytes)
                .unwrap_err()
                .kind(),
            crate::ErrorKind::InvalidOutboundGrantBody
        );
    }

    for (server, expected) in [("my-server", &hyphen), ("my_server", &underscore)] {
        let mut persisted = entries.clone();
        persisted
            .iter_mut()
            .find(|(key, _)| key == &Value::from(KEY_SCOPE))
            .expect("scope key")
            .1 = scoped_mcp_scope_value(server);
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &Value::Map(persisted)).unwrap();
        let decoded = decode_standing_outbound_grant_body(&bytes)?;
        assert_eq!(decoded.scope, expected.scope);
        assert_eq!(scoped_server_of(&decoded), server);
    }

    // An in-memory grant carrying an unsafe server can never be persisted.
    let forged = StandingOutboundGrant {
        scope: StandingOutboundGrantScope::ScopedMcp {
            server: "files:extra".to_owned(),
            tool: "read_file".to_owned(),
            data_class_ceiling: DataClass::Personal,
            tool_data_classes: vec![
                crate::outbound_consent::tool_call::ToolGrantDataClass::Arguments,
            ],
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

    let scope = StandingOutboundGrantScope::ScopedMcp {
        server: "my-server".to_owned(),
        tool: "read_file".to_owned(),
        data_class_ceiling: DataClass::Personal,
        tool_data_classes: vec![crate::outbound_consent::tool_call::ToolGrantDataClass::Arguments],
        endpoint_allowlist: vec!["https://files.internal.example".to_owned()],
    };
    scope.validate().expect("safe canonical server");
    let scope = scope.scoped_mcp_grant().expect("scoped grant");

    assert_eq!(
        crate::outbound_consent::evaluate_scoped_mcp_call(scope, call("my-server")),
        crate::outbound_consent::ScopedMcpConsentDecision::AutoFire
    );
    // Admission is exact: underscore, mixed case, whitespace, and unsafe
    // spellings cannot alias the granted hyphenated server.
    for wrong_server in [
        "my_server",
        "MY-SERVER",
        "My-Server",
        "my-server:extra",
        " my-server",
        "my-server ",
        "my server",
        "my-*",
        "",
        "other",
    ] {
        assert_eq!(
            crate::outbound_consent::evaluate_scoped_mcp_call(scope, call(wrong_server)),
            crate::outbound_consent::ScopedMcpConsentDecision::Escalate(
                crate::outbound_consent::ScopedMcpEscalationReason::WrongServer
            ),
            "{wrong_server}"
        );
    }

    // A grant whose own server is non-canonical or unsafe authorizes nothing,
    // even when the call repeats the same bytes.
    let endpoints = vec!["https://files.internal.example".to_owned()];
    for unsafe_server in [
        "My-Server",
        "MY-SERVER",
        "my_server:extra",
        "my server",
        "my-*",
        "",
    ] {
        let unsafe_scope = ScopedMcpGrantRef {
            server: unsafe_server,
            tool: "read_file",
            data_class_ceiling: DataClass::Personal,
            tool_data_classes: &[crate::outbound_consent::tool_call::ToolGrantDataClass::Arguments],
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

mod header_classes;

/// SOL-9A-2-R2 F3: each use stamps the grant it ran under, and is no reason
/// to refuse a restore over the vault; a revocation since the backup is.
#[test]
fn a_restore_goes_ahead_past_a_grant_use_and_refuses_a_revocation() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
    let id = EntityId::now();
    let owner = crate::test_util::embedded_owner_proof(&vault);
    let grant = vault.mint_standing_outbound_grant(
        &owner,
        id,
        &intent(GrantMintIntentScope::Channel {
            channel: "line".to_owned(),
        }),
    )?;
    let backups = crate::test_support::restore_tempdir();
    let image = backups.path().join("backup");
    vault.snapshot_checkpoint(&image, 100)?;
    let key = vault.checkpoint_key()?;
    let restore = |destination: &std::path::Path| {
        crate::Vault::restore_checkpoint_keeping_authority(
            &image,
            &key,
            destination,
            crate::VaultConfig::device(),
            &vault,
            200,
        )
        .map(|(restored, _)| restored)
    };

    vault.record_standing_grant_use(&grant.grant_ref(), grant.bound().digest())?;
    drop(restore(&backups.path().join("first"))?);

    vault.revoke_consent_grant(&owner, &grant.grant_ref())?;
    let destination = backups.path().join("second");
    let error = restore(&destination)
        .err()
        .expect("the restore must be refused");
    assert!(error.to_string().contains("outbound grants"), "{error}");
    assert!(!destination.exists());
    Ok(())
}
