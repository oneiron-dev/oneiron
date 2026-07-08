use super::*;

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
