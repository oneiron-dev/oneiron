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

fn mint_outbound_grant_row(
    vault: &crate::Vault,
    scope: StandingOutboundGrantScope,
) -> Result<(StandingOutboundGrant, crate::consent::ConsentGrantRow)> {
    let owner = crate::test_util::embedded_owner_proof(vault);
    let grant = vault.with_write_txn(|wtxn| {
        vault.mint_standing_outbound_grant_in_txn(wtxn, &owner, EntityId::now(), "owner", scope)
    })?;
    let row = vault.consent_grant(&grant.grant_ref())?.expect("grant row");
    Ok((grant, row))
}

fn consent_row_with_selectors(
    row: &crate::consent::ConsentGrantRow,
    change: impl FnOnce(&mut Vec<String>),
) -> Result<crate::consent::ConsentGrantRow> {
    let mut bound = row.grant.bound().clone();
    let crate::consent::BoundEnvelope::Action(envelope) = &mut bound.envelope else {
        panic!("outbound grant must have an action envelope");
    };
    // Preserve hostile bytes: ActionEnvelope::new would trim padded selectors.
    change(&mut envelope.selectors);
    envelope.selectors.sort();
    let mut changed = row.clone();
    changed.grant = crate::consent::StandingConsentGrant::from_bound(bound)?;
    Ok(changed)
}

fn consent_row_with_version(encoded: &[u8], version: Value) -> Vec<u8> {
    let Value::Map(mut fields) =
        rmpv::decode::read_value(&mut Cursor::new(encoded)).expect("decode consent grant fixture")
    else {
        panic!("consent grant row must be a map");
    };
    fields
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("schema_version"))
        .expect("schema version field")
        .1 = version;
    let mut changed = Vec::new();
    rmpv::encode::write_value(&mut changed, &Value::Map(fields))
        .expect("encode consent grant fixture");
    changed
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
    let decoded =
        StandingOutboundGrant::from_row(&crate::consent::decode_consent_grant_row(&encoded)?)
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
fn schema_v1_contact_grant_with_five_key_scope_is_rejected() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
    let (grant, row) = mint_outbound_grant_row(
        &vault,
        StandingOutboundGrantScope::Contact {
            contact_ref: "contact:legacy".to_owned(),
        },
    )?;
    let encoded = crate::consent::encode_consent_grant_row(&row)?;
    let decoded = crate::consent::decode_consent_grant_row(&encoded)?;
    assert_eq!(decoded, row);
    assert_eq!(StandingOutboundGrant::from_row(&decoded), Some(grant));

    let wrong_version = consent_row_with_version(
        &encoded,
        Value::from(crate::consent::CONSENT_GRANT_SCHEMA_VERSION + 1),
    );
    assert!(crate::consent::decode_consent_grant_row(&wrong_version).is_err());
    Ok(())
}

#[test]
fn contact_grant_decode_rejects_non_nil_scoped_mcp_field() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
    let (grant, row) = mint_outbound_grant_row(
        &vault,
        StandingOutboundGrantScope::Contact {
            contact_ref: "contact:injected".to_owned(),
        },
    )?;
    assert_eq!(StandingOutboundGrant::from_row(&row), Some(grant));
    let injected = consent_row_with_selectors(&row, |selectors| {
        selectors.push("server:files".to_owned());
    })?;
    assert!(StandingOutboundGrant::from_row(&injected).is_none());
    Ok(())
}

#[test]
fn scoped_mcp_grant_decode_rejects_every_non_nil_legacy_scope_field() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
    let (grant, row) = mint_outbound_grant_row(&vault, scoped_mcp_scope("files"))?;
    assert_eq!(StandingOutboundGrant::from_row(&row), Some(grant));
    for selector in [
        "contact:contact:injected",
        "verb_class:send",
        "channel:channel:injected",
        "brief:brief:injected",
        "artifact:site",
        "page:91919191919191919191919191919191",
    ] {
        let injected = consent_row_with_selectors(&row, |selectors| {
            selectors.push(selector.to_owned());
        })?;
        assert!(
            StandingOutboundGrant::from_row(&injected).is_none(),
            "other-family selector {selector:?} must not read as a scoped MCP grant"
        );
    }
    Ok(())
}

#[test]
fn scoped_mcp_persisted_endpoint_padding_refuses_otherwise_valid_authority() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
    let (grant, row) = mint_outbound_grant_row(&vault, scoped_mcp_scope("files"))?;
    assert_eq!(StandingOutboundGrant::from_row(&row), Some(grant));
    let padded = consent_row_with_selectors(&row, |selectors| {
        *selectors
            .iter_mut()
            .find(|selector| selector.starts_with("endpoint:"))
            .expect("endpoint selector") = "endpoint:https://files.internal.example ".to_owned();
    })?;
    assert!(StandingOutboundGrant::from_row(&padded).is_none());
    Ok(())
}

#[test]
fn standing_outbound_grant_revoke_and_touch_validate_lifecycle() -> Result<()> {
    let clock = crate::ports::ManualClock::new(10);
    let mut config = crate::VaultConfig::device();
    config.store_clock = clock.bundle();
    let (_dir, vault) = crate::test_util::open_test_vault_with(config);
    let owner = crate::test_util::embedded_owner_proof(&vault);
    let grant = vault.mint_standing_outbound_grant(
        &owner,
        EntityId::now(),
        &intent(GrantMintIntentScope::Channel {
            channel: "line".to_owned(),
        }),
    )?;

    clock.set(12);
    vault.record_standing_grant_use(&grant.grant_ref(), grant.bound().digest())?;
    let touched = vault.standing_outbound_grants_lens(
        crate::receipt::StandingOutboundGrantsLensQuery::new(1, 10),
    )?;
    assert_eq!(touched.grants[0].last_used_at, Some(12));
    clock.set(20);
    vault.revoke_consent_grant(&owner, &grant.grant_ref())?;
    let revoked = vault
        .get_standing_outbound_grant(&grant.id)?
        .expect("grant");
    let history = vault.standing_outbound_grants_lens(
        crate::receipt::StandingOutboundGrantsLensQuery::new(1, 10),
    )?;
    assert_eq!(revoked.status, StandingOutboundGrantStatus::Revoked);
    assert_eq!(history.grants[0].revoked_at, Some(20));
    assert!(!revoked.is_active_under_policy(&grant.policy_frontier));
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

fn scoped_mcp_scope(server: &str) -> StandingOutboundGrantScope {
    StandingOutboundGrantScope::ScopedMcp {
        server: server.to_owned(),
        tool: "read_file".to_owned(),
        data_class_ceiling: DataClass::Personal,
        tool_data_classes: vec![crate::outbound_consent::tool_call::ToolGrantDataClass::Arguments],
        endpoint_allowlist: vec!["https://files.internal.example".to_owned()],
    }
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
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
    let owner = crate::test_util::embedded_owner_proof(&vault);
    let policy_frontier = {
        let rtxn = vault.store.env.read_txn()?;
        crate::gate::resolve_policy_manifest(&vault.store, &rtxn)?.read_frontier_hash()?
    };
    let mint = |server: &str| {
        vault.with_write_txn(|wtxn| {
            vault.mint_standing_outbound_grant_in_txn(
                wtxn,
                &owner,
                EntityId::now(),
                "owner",
                scoped_mcp_scope(server),
            )
        })
    };
    let grant_id = EntityId::from_bytes([0x5C; 16]).expect("grant id");

    let files = mint("files")?;
    assert_eq!(scoped_server_of(&files), "files");

    // Hyphen and underscore remain separate canonical capability identities.
    let hyphen = mint("my-server")?;
    let underscore = mint("my_server")?;
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

    let hyphen_row = vault
        .consent_grant(&hyphen.grant_ref())?
        .expect("grant row");
    let encoded = crate::consent::encode_consent_grant_row(&hyphen_row)?;
    let decoded =
        StandingOutboundGrant::from_row(&crate::consent::decode_consent_grant_row(&encoded)?)
            .expect("outbound grant row");
    assert_eq!(decoded.principal_ref, hyphen.principal_ref);
    assert_eq!(decoded.scope, hyphen.scope);
    assert_eq!(decoded.status, hyphen.status);
    assert_eq!(decoded.policy_frontier, policy_frontier);

    let files_row = vault.consent_grant(&files.grant_ref())?.expect("grant row");
    assert_eq!(
        StandingOutboundGrant::from_row(&files_row),
        Some(files.clone())
    );

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
            mint(unsafe_server).is_err(),
            "unsafe scoped server {unsafe_server:?} must not mint a grant"
        );
        let unsafe_row = consent_row_with_selectors(&files_row, |selectors| {
            *selectors
                .iter_mut()
                .find(|selector| selector.starts_with("server:"))
                .expect("server selector") = format!("server:{unsafe_server}");
        })?;
        assert!(
            StandingOutboundGrant::from_row(&unsafe_row).is_none(),
            "unsafe persisted scoped server {unsafe_server:?} must not read as a grant"
        );
    }
    for (server, expected) in [("my-server", &hyphen), ("my_server", &underscore)] {
        let row = vault
            .consent_grant(&expected.grant_ref())?
            .expect("grant row");
        let encoded = crate::consent::encode_consent_grant_row(&row)?;
        let decoded =
            StandingOutboundGrant::from_row(&crate::consent::decode_consent_grant_row(&encoded)?)
                .expect("outbound grant row");
        assert_eq!(
            decoded.scope,
            StandingOutboundGrantScope::ScopedMcp {
                server: server.to_owned(),
                tool: "read_file".to_owned(),
                data_class_ceiling: DataClass::Personal,
                tool_data_classes: vec![
                    crate::outbound_consent::tool_call::ToolGrantDataClass::Arguments,
                ],
                endpoint_allowlist: vec!["https://files.internal.example".to_owned()],
            }
        );
    }
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

#[test]
fn schema_v3_carries_every_outbound_scope_and_rejects_other_versions() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
    let scopes = [
        StandingOutboundGrantScope::Contact {
            contact_ref: "contact:1".to_owned(),
        },
        StandingOutboundGrantScope::VerbClass {
            verb_class: "send".to_owned(),
        },
        StandingOutboundGrantScope::Channel {
            channel: "email".to_owned(),
        },
        StandingOutboundGrantScope::BriefVerbClass {
            brief_ref: "brief:1".to_owned(),
            verb_class: "send".to_owned(),
        },
        StandingOutboundGrantScope::ArtifactPublish {
            artifact: "site".to_owned(),
        },
        StandingOutboundGrantScope::BookingPageInvites {
            page_ref: EntityId::from_bytes([0x91; 16]).expect("page id"),
        },
        StandingOutboundGrantScope::ScopedMcp {
            server: "files".to_owned(),
            tool: "read_file".to_owned(),
            data_class_ceiling: DataClass::Personal,
            tool_data_classes: vec![
                crate::outbound_consent::tool_call::ToolGrantDataClass::Arguments,
            ],
            endpoint_allowlist: vec!["https://files.example.test".to_owned()],
        },
    ];
    for scope in scopes {
        let expected_scope = scope.clone();
        let (grant, row) = mint_outbound_grant_row(&vault, scope)?;
        assert_eq!(grant.scope, expected_scope);
        let encoded = crate::consent::encode_consent_grant_row(&row)?;
        let decoded = crate::consent::decode_consent_grant_row(&encoded)?;
        assert_eq!(decoded, row);
        assert_eq!(StandingOutboundGrant::from_row(&decoded), Some(grant));

        for version in [
            Value::from(0_u64),
            Value::from(2_u64),
            Value::from(3_u64),
            Value::from(4_u64),
            Value::from(-1),
            Value::from("2"),
            Value::from(2.0),
            Value::Nil,
        ] {
            let invalid = consent_row_with_version(&encoded, version);
            assert!(crate::consent::decode_consent_grant_row(&invalid).is_err());
        }
    }
    Ok(())
}

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
