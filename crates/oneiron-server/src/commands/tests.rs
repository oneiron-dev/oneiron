use super::*;
use crate::auth::mint_core_token_v2;

#[test]
fn empty_cors_origin_list_stays_restrictive() {
    let config = SyncServerConfig::default();

    let parsed = parse_allowed_origins(&config.allowed_origins).unwrap();

    assert!(parsed.is_empty());
    assert!(build_cors_layer(&config).is_ok());
}

#[test]
fn configured_cors_origin_is_parsed() {
    let config = SyncServerConfig {
        allowed_origins: vec!["https://app.oneiron.dev".to_owned(), "  ".to_owned()],
        ..Default::default()
    };

    assert_eq!(
        parse_allowed_origins(&config.allowed_origins).unwrap(),
        vec![HeaderValue::from_static("https://app.oneiron.dev")]
    );
    assert!(build_cors_layer(&config).is_ok());
}

#[test]
fn wildcard_cors_origin_is_rejected() {
    let origins = vec!["*".to_owned()];

    let error = parse_allowed_origins(&origins).unwrap_err().to_string();

    assert!(error.contains("wildcard CORS origin is not allowed"));
}

#[test]
fn provenance_claim_json_omits_payload_by_default() {
    let body = oneiron::ClaimBody::new(
        oneiron::REPO_PROVENANCE_PREDICATE,
        oneiron::ClaimSubject::Edge {
            source: oneiron::EntityId::now(),
            kind: oneiron::EdgeKind::Mentions,
            target: oneiron::EntityId::now(),
        },
        MsgpackValue::from("private payload"),
        1.0,
        oneiron::ClaimApprovalStatus::Auto,
        oneiron::ClaimLifecycleStatus::Active,
    );

    let redacted = claim_body_json(&body, false);
    assert!(redacted.get("value").is_none());
    assert!(redacted.get("scope").is_none());
    assert!(redacted.get("evidence").is_none());

    let included = claim_body_json(&body, true);
    assert_eq!(included["value"], "private payload");
}

#[test]
fn msgpack_json_conversion_truncates_deep_arrays() {
    let value = MsgpackValue::Array(vec![MsgpackValue::Array(vec![MsgpackValue::from(
        "private payload",
    )])]);

    let rendered = msgpack_value_json_with_depth(&value, 1);

    assert_eq!(rendered, json!([{ "truncated": "max_depth" }]));
}

#[test]
fn init_creates_vault_and_doctor_reports() {
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("vault");
    let args = VaultArgs {
        path: vault_path.clone(),
        dimensions: 32,
        map_size: 64 * 1024 * 1024,
        dict_search_paths: Some(Vec::new()),
    };

    init(args.clone()).unwrap();
    assert!(vault_path.join("data.mdb").is_file());

    let vault = open_vault_for_command(&args).unwrap();
    let report = vault.doctor().unwrap();
    assert!(report.storage_abi_version.is_some());
    assert!(report.db_manifest.missing_names.is_empty());
}

#[test]
fn doctor_opens_existing_vault() {
    let dir = tempfile::tempdir().unwrap();
    let args = VaultArgs {
        path: dir.path().join("vault"),
        dimensions: 32,
        map_size: 64 * 1024 * 1024,
        dict_search_paths: Some(Vec::new()),
    };

    init(args.clone()).unwrap();
    doctor(args).unwrap();
}

#[tokio::test]
async fn revoke_command_refuses_missing_vault_path_without_creating_storage() {
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("missing-vault");

    let err = revoke(RevokeArgs {
        client: "0123456789abcdef".to_string(),
        serve: ServeArgs {
            vault_path: Some(vault_path.clone()),
            dimensions: Some(32),
            map_size: Some(64 * 1024 * 1024),
            dict_search_paths: Some(Vec::new()),
            ..Default::default()
        },
    })
    .await
    .unwrap_err();

    assert!(
        err.to_string()
            .contains("refusing to create a new vault for revoke")
    );
    assert!(
        !vault_path.join("data.mdb").exists(),
        "bad revoke path must not create LMDB storage"
    );
}

#[tokio::test]
async fn revoke_command_flips_existing_binding_and_preserves_pubkey_floor() {
    use ed25519_dalek::{Signer, SigningKey};
    use oneiron::sync::lease::{
        self, LEASE_DURATION_SECS, LeaseRecord, LeaseStatus, ROOT_LEASES_MAP,
    };

    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("vault");
    let mut vault_config = oneiron::VaultConfig::server();
    vault_config.dimensions = 32;
    vault_config.map_size = 64 * 1024 * 1024;
    let vault = Arc::new(oneiron::Vault::open(&vault_path, vault_config.clone()).unwrap());
    let server = SyncServer::new(vault.clone(), SyncServerConfig::default()).unwrap();

    let client_id = 0x0123_4567_89ab_cdefu64;
    let signer = SigningKey::from_bytes(&[77u8; 32]);
    let pubkey = signer.verifying_key().to_bytes();
    let record = LeaseRecord {
        vault_id: 0,
        status: LeaseStatus::Active,
        pubkey,
        granted_at: 1_000,
        renewed_at: 1_000,
        expires_at: 1_000 + LEASE_DURATION_SECS,
    };
    server
        .root_doc
        .get_map(ROOT_LEASES_MAP)
        .insert(
            lease::client_id_hex(client_id).as_str(),
            lease::encode_lease_record(&record).as_slice(),
        )
        .unwrap();
    server.root_doc.commit();
    oneiron::sync::server_state::persist_root_snapshot(&vault, &server.root_doc).unwrap();
    lease::mirror_leases_from_root(&vault, &server.root_doc).unwrap();
    drop(server);
    drop(vault);

    revoke(RevokeArgs {
        client: lease::client_id_hex(client_id),
        serve: ServeArgs {
            vault_path: Some(vault_path.clone()),
            dimensions: Some(32),
            map_size: Some(64 * 1024 * 1024),
            dict_search_paths: Some(Vec::new()),
            ..Default::default()
        },
    })
    .await
    .unwrap();

    let vault = Arc::new(oneiron::Vault::open(&vault_path, vault_config).unwrap());
    let revoked = vault
        .sync_state_get(&lease::lease_key(0, client_id))
        .unwrap()
        .unwrap();
    assert_eq!(revoked[1], 0x03, "CLI revoke flips status to revoked");

    let server = SyncServer::new(vault.clone(), SyncServerConfig::default()).unwrap();
    let other_client = 0x1111_2222_3333_4444u64;
    let pop = signer
        .sign(&lease::lease_pop_transcript(other_client, &pubkey))
        .to_bytes();
    let decision = server
        .register_lease(other_client, &pubkey, &pop)
        .await
        .unwrap();
    assert!(
        !decision.granted,
        "revoked pubkey remains terminal across fresh client ids"
    );
    assert!(
        vault
            .sync_state_get(&lease::lease_key(0, other_client))
            .unwrap()
            .is_none(),
        "pubkey floor writes no fresh active row"
    );
}

#[test]
fn missing_dicts_returns_loud_startup_warning() {
    let resolution = resolve_dict_search_paths_from_candidates(&[], Vec::new());

    assert!(resolution.paths.is_empty());
    assert_eq!(resolution.warning, Some(NO_CJK_DICT_WARNING));
    assert!(NO_CJK_DICT_WARNING.contains("NO CJK DICTIONARY FOUND"));
}

#[test]
fn auto_discovers_candidate_with_cjk_dict_marker() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("dicts");
    std::fs::create_dir_all(root.join("zh")).unwrap();
    std::fs::write(root.join("zh").join("jieba.dict.utf8"), "token 1 n\n").unwrap();

    let resolution = resolve_dict_search_paths_from_candidates(&[], vec![root.clone()]);

    assert_eq!(resolution.paths, vec![root]);
    assert_eq!(resolution.warning, None);
}

/// The CLI mint surface must produce exactly the pinned wire format, so a
/// token minted by ops verifies against a server running the same secret.
#[test]
fn token_mint_claims_reproduce_the_golden_vectors() {
    const VECTOR_SECRET: &str = "correct horse battery staple";

    let owner = build_token_claims(None, None);
    assert_eq!(owner, "");
    assert_eq!(
        mint_core_token_v2(VECTOR_SECRET, &owner),
        "v2..326ad3492c855a6d722398f75f006241ce8808250d79f38ffd4af64470118743"
    );

    let scoped = build_token_claims(Some(&["core:read".to_owned()]), None);
    assert_eq!(scoped, "scope=core:read");
    assert_eq!(
        mint_core_token_v2(VECTOR_SECRET, &scoped),
        "v2.scope=core:read.1f166e678c06858ee6dca47da42e5bf257db95cadc993fa1f5db90f52370eda4"
    );

    let bound = build_token_claims(
        Some(&["companion:profile:read".to_owned()]),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
    );
    assert_eq!(
        bound,
        "scope=companion:profile:read;principal_ref=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(
        mint_core_token_v2(VECTOR_SECRET, &bound),
        "v2.scope=companion:profile:read;principal_ref=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.547000c78580b12473a643b569d46d4078fa9df6eab25a69cac5d72a80afc102"
    );
}

/// F3 — the secret is the MAC key for every minted token and BLAKE3 is fast,
/// so a recipient can test guesses offline against the claims/MAC pair they
/// were handed. The mint door warns on the same threshold `serve` does: an
/// operator who only ever mints never sees the startup warning.
#[test]
fn mint_path_warns_on_a_weak_secret_and_stays_quiet_otherwise() {
    let short = "x".repeat(MIN_RECOMMENDED_AUTH_SECRET_BYTES - 1);
    let warning = prepare_token_mint(&short, None, None)
        .expect("mint succeeds")
        .warning
        .expect("the mint path must carry the warning, not just compute it");
    assert!(warning.contains("MAC key for every minted bearer token"));
    assert!(warning.contains(&MIN_RECOMMENDED_AUTH_SECRET_BYTES.to_string()));
    assert!(
        !warning.contains(&short),
        "the warning must never quote the secret"
    );

    // Same threshold as the serve door, so an operator who only ever mints
    // gets the same nudge. The boundary is a floor: exactly-at-length is fine.
    for secret in [
        "x".repeat(MIN_RECOMMENDED_AUTH_SECRET_BYTES),
        "x".repeat(64),
    ] {
        assert!(
            prepare_token_mint(&secret, Some(&["core:read".to_owned()]), None)
                .expect("mint succeeds")
                .warning
                .is_none(),
            "an adequate secret must stay quiet"
        );
    }

    // A warning is a nudge, not a wall: the token is still minted and valid.
    let weak = prepare_token_mint(&short, None, None).expect("mint succeeds");
    assert!(weak.token.starts_with("v2."));
    assert!(weak.token.contains(&format!("jti={}", weak.jti)));
}

/// F2 — the explicit revocation act, end to end through the CLI's storage.
/// Idempotent, and the row it writes is exactly the one the verify path reads.
#[test]
fn token_revoke_records_the_id_the_verify_path_consults() {
    use crate::auth::RevokedTokenJtis;

    let dir = tempfile::tempdir().unwrap();
    let mut vault_config = oneiron::VaultConfig::server();
    vault_config.dimensions = 32;
    vault_config.map_size = 64 * 1024 * 1024;
    let vault = oneiron::Vault::open(dir.path().join("vault"), vault_config).unwrap();

    let (_token, jti) = mint_identified_core_token_v2("secret", "scope=core:read");
    let sibling = mint_identified_core_token_v2("secret", "scope=core:read").1;

    assert!(!vault.is_revoked(&jti).unwrap(), "nothing starts revoked");

    assert!(
        revoke_token_jti(&vault, &jti).unwrap(),
        "first call revokes"
    );
    assert!(
        !revoke_token_jti(&vault, &jti).unwrap(),
        "revoking twice is idempotent and reports no change"
    );

    assert!(vault.is_revoked(&jti).unwrap());
    assert!(
        !vault.is_revoked(&sibling).unwrap(),
        "revocation names one identity, not a claims class"
    );
}

/// A typo'd id would write a row no token can ever present, which would look
/// like a successful revocation while the token stayed live.
#[test]
fn token_revoke_refuses_a_malformed_id() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault_config = oneiron::VaultConfig::server();
    vault_config.dimensions = 32;
    vault_config.map_size = 64 * 1024 * 1024;
    let vault = oneiron::Vault::open(dir.path().join("vault"), vault_config).unwrap();

    for bad in ["", "0123456789abcdef", &"0".repeat(33), &"A".repeat(32)] {
        let error = revoke_token_jti(&vault, bad)
            .expect_err(&format!("{bad:?} must not be accepted"))
            .to_string();
        assert!(error.contains("lowercase hex"), "{error}");
    }
    assert!(
        vault
            .sync_state_keys_with_prefix("auth:revoked-token-jti:")
            .unwrap()
            .is_empty(),
        "a refused revocation must write nothing"
    );
}

/// The revoke command refuses to create storage: a fresh vault holds no
/// tokens, so it would report success against state the server never reads.
#[tokio::test]
async fn token_revoke_refuses_missing_vault_path_without_creating_storage() {
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("missing-vault");

    let err = token_revoke(TokenRevokeArgs {
        jti: "0".repeat(32),
        serve: ServeArgs {
            vault_path: Some(vault_path.clone()),
            dimensions: Some(32),
            map_size: Some(64 * 1024 * 1024),
            dict_search_paths: Some(Vec::new()),
            ..Default::default()
        },
    })
    .unwrap_err();

    assert!(
        err.to_string()
            .contains("refusing to create a new vault for revoke")
    );
    assert!(!vault_path.join("data.mdb").exists());
}

/// Every issued token carries an identity, and identical claims mint distinct
/// tokens — the property that makes per-token revocation meaningful at all.
#[test]
fn identified_mint_attaches_a_fresh_id_to_every_token() {
    for claims in ["", "scope=core:read"] {
        let (first, first_jti) = mint_identified_core_token_v2("secret", claims);
        let (second, second_jti) = mint_identified_core_token_v2("secret", claims);

        assert_ne!(first_jti, second_jti);
        assert_ne!(first, second);
        assert!(first.contains(&format!("jti={first_jti}")));
        assert!(
            validate_bearer_claims(&format!(
                "{}jti={first_jti}",
                if claims.is_empty() {
                    String::new()
                } else {
                    format!("{claims};")
                }
            ))
            .is_ok(),
            "the identified claims must satisfy the server's grammar"
        );
    }
}

/// Reject-before-mint: claims the server would 401 never leave the CLI.
#[test]
fn token_mint_rejects_claims_the_server_would_refuse() {
    let multi = build_token_claims(
        Some(&["core:read".to_owned(), "core:write".to_owned()]),
        None,
    );
    assert_eq!(multi, "scope=core:read,core:write");
    assert!(validate_bearer_claims(&multi).is_ok());

    for claims in [
        build_token_claims(Some(&["core:admin".to_owned()]), None),
        build_token_claims(Some(&["core:read".to_owned()]), Some("not-an-entity")),
    ] {
        assert!(
            validate_bearer_claims(&claims).is_err(),
            "{claims:?} must be refused before minting"
        );
    }

    // The refusal is on the mint path itself, not merely available to it.
    for (scope, principal_ref) in [
        (vec!["core:admin".to_owned()], None),
        (vec!["core:read".to_owned()], Some("not-an-entity")),
    ] {
        assert!(
            prepare_token_mint("secret", Some(&scope), principal_ref).is_err(),
            "{scope:?}/{principal_ref:?} must never be minted"
        );
    }
}

#[test]
fn loopback_host_detection_distinguishes_public_bind_addresses() {
    for host in ["localhost", "127.0.0.1", "::1"] {
        assert!(is_loopback(host), "{host} should be loopback");
    }
    for host in ["0.0.0.0", "::", "192.0.2.10", "example.test"] {
        assert!(!is_loopback(host), "{host} should be treated as public");
    }
}

#[test]
fn public_bind_without_auth_refusal_emits_warning_predicate() {
    assert!(should_warn_public_bind_without_auth(None, false, "0.0.0.0"));
    assert!(should_warn_public_bind_without_auth(None, false, "::"));
    assert!(!should_warn_public_bind_without_auth(
        None,
        false,
        "127.0.0.1"
    ));
    assert!(!should_warn_public_bind_without_auth(
        Some("secret"),
        false,
        "0.0.0.0"
    ));
    assert!(!should_warn_public_bind_without_auth(None, true, "0.0.0.0"));
}
