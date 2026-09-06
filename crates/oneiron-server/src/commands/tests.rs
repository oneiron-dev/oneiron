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

/// The CORS rows above stop at "the config parsed" and "a layer was built" —
/// neither says what a browser is told. A layer built over the right origin
/// list but attached to the wrong axum stage, or an allowlist that answered
/// every origin, would keep them green while the deployed server handed a
/// foreign page an `Access-Control-Allow-Origin` for the vault's own API.
///
/// So this row drives the response itself: `build_cors_layer` over a probe
/// router, one real preflight per origin. The allowed origin is echoed back,
/// the foreign one gets no grant, and the default (empty allowlist) config
/// grants nothing to anybody — the restrictive shape the empty list claims to
/// mean, asserted at the response instead of at the parse.
#[tokio::test]
async fn configured_cors_origin_controls_actual_preflight_response() {
    use axum::Router;
    use axum::body::Body;
    use axum::http::header::{ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_REQUEST_METHOD, ORIGIN};
    use axum::http::{Method, Request, StatusCode};
    use axum::routing::get;
    use tower::ServiceExt;

    const ALLOWED: &str = "https://app.oneiron.dev";
    const FOREIGN: &str = "https://foreign.invalid";

    fn probe_router(config: &SyncServerConfig) -> Router {
        Router::new()
            .route("/probe", get(|| async { StatusCode::NO_CONTENT }))
            .layer(build_cors_layer(config).unwrap())
    }

    fn preflight(origin: &str) -> Request<Body> {
        Request::builder()
            .method(Method::OPTIONS)
            .uri("/probe")
            .header(ORIGIN, origin)
            .header(ACCESS_CONTROL_REQUEST_METHOD, "GET")
            .body(Body::empty())
            .unwrap()
    }

    let configured = probe_router(&SyncServerConfig {
        allowed_origins: vec![ALLOWED.to_owned()],
        ..Default::default()
    });

    let allowed = configured
        .clone()
        .oneshot(preflight(ALLOWED))
        .await
        .unwrap();
    assert_eq!(allowed.status(), StatusCode::OK);
    assert_eq!(
        allowed.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN),
        Some(&HeaderValue::from_static(ALLOWED)),
        "a configured origin must be granted by name"
    );

    let foreign = configured.oneshot(preflight(FOREIGN)).await.unwrap();
    assert!(
        foreign.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN).is_none(),
        "an unlisted origin must receive no cross-origin grant"
    );

    // The default config's empty list is restrictive, not permissive: no
    // origin — not even one another config would allow — is granted.
    let unconfigured = probe_router(&SyncServerConfig::default());
    for origin in [ALLOWED, FOREIGN] {
        let response = unconfigured
            .clone()
            .oneshot(preflight(origin))
            .await
            .unwrap();
        assert!(
            response
                .headers()
                .get(ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none(),
            "an empty allowlist must grant nothing to {origin}"
        );
    }
}

#[test]
fn provenance_claim_json_omits_payload_by_default() {
    let body = oneiron::ClaimBody::new(
        oneiron::repo_mutation::REPO_PROVENANCE_PREDICATE,
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

    let owner = build_token_claims(None, None, None);
    assert_eq!(owner, "");
    assert_eq!(
        mint_core_token_v2(VECTOR_SECRET, &owner),
        "v2..326ad3492c855a6d722398f75f006241ce8808250d79f38ffd4af64470118743"
    );

    let scoped = build_token_claims(Some(&["core:read".to_owned()]), None, None);
    assert_eq!(scoped, "scope=core:read");
    assert_eq!(
        mint_core_token_v2(VECTOR_SECRET, &scoped),
        "v2.scope=core:read.1f166e678c06858ee6dca47da42e5bf257db95cadc993fa1f5db90f52370eda4"
    );

    let bound = build_token_claims(
        Some(&["companion:profile:read".to_owned()]),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        None,
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
    let warning = prepare_token_mint(&short, None, None, None)
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
            prepare_token_mint(&secret, Some(&["core:read".to_owned()]), None, None)
                .expect("mint succeeds")
                .warning
                .is_none(),
            "an adequate secret must stay quiet"
        );
    }

    // A warning is a nudge, not a wall: the token is still minted and valid.
    let weak = prepare_token_mint(&short, None, None, None).expect("mint succeeds");
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
        None,
    );
    assert_eq!(multi, "scope=core:read,core:write");
    assert!(validate_bearer_claims(&multi).is_ok());

    for claims in [
        build_token_claims(Some(&["core:admin".to_owned()]), None, None),
        build_token_claims(Some(&["core:read".to_owned()]), Some("not-an-entity"), None),
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
            prepare_token_mint("secret", Some(&scope), principal_ref, None).is_err(),
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

// ══════════════════════════════════════════════════════════════════════════
// ONE-1705 — `oneiron api …`, the curl-backed lane.
//
// The rows below are about the FAÇADE, not about HTTP: which existing route a
// short command resolves to, what a caller's text can and cannot do to that
// URL, and what the child process is handed. The credential channel and the
// byte-for-byte passthrough are driven through a fake `curl` so the assertions
// read what a real one would have received.
// ══════════════════════════════════════════════════════════════════════════

use crate::cli::ApiCommand;

/// An obvious non-credential. Nothing in this file, in a snapshot, or in a
/// captured argv may ever carry a real one.
#[cfg(unix)]
const PLACEHOLDER_SECRET: &str = "placeholder-secret-not-a-credential";

/// Stage an executable stand-in for `curl` under a temporary directory.
#[cfg(unix)]
fn write_fake_curl(dir: &std::path::Path, script: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let path = dir.join("fake-curl");
    std::fs::write(&path, script).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// A fake curl that records what it was given, replays a fixed response body,
/// writes a diagnostic to stderr, and exits with the requested status.
#[cfg(unix)]
fn fake_curl_script(dir: &std::path::Path, exit_code: i32) -> String {
    let dir = dir.display();
    format!(
        "#!/bin/sh\n\
         cat > \"{dir}/stdin.bin\"\n\
         : > \"{dir}/argv.txt\"\n\
         for arg in \"$@\"; do\n\
         printf '%s\\n' \"$arg\" >> \"{dir}/argv.txt\"\n\
         case \"$arg\" in @*) cp \"${{arg#@}}\" \"{dir}/body.bin\" ;; esac\n\
         done\n\
         cat \"{dir}/response.bin\"\n\
         printf 'curl: diagnostic on stderr\\n' >&2\n\
         exit {exit_code}\n"
    )
}

#[test]
fn api_short_commands_resolve_to_existing_routes() {
    let base = "http://127.0.0.1:3000";

    let discover = api::request_for_command(base, ApiCommand::Discover).unwrap();
    assert_eq!(discover.method, "GET");
    assert_eq!(discover.url, "http://127.0.0.1:3000/api/core/discover");
    assert_eq!(discover.body, None);

    let search = api::request_for_command(
        base,
        ApiCommand::Search {
            query: "kickoff notes".to_owned(),
            limit: Some(5),
        },
    )
    .unwrap();
    assert_eq!(
        search.url,
        "http://127.0.0.1:3000/api/search/text?query=kickoff%20notes&limit=5"
    );

    let unlimited = api::request_for_command(
        base,
        ApiCommand::Search {
            query: "kickoff".to_owned(),
            limit: None,
        },
    )
    .unwrap();
    assert_eq!(
        unlimited.url, "http://127.0.0.1:3000/api/search/text?query=kickoff",
        "an omitted limit must leave the server's own default in force"
    );

    let entity = api::request_for_command(
        base,
        ApiCommand::Get {
            entity_id: "entity-42".to_owned(),
        },
    )
    .unwrap();
    assert_eq!(entity.url, "http://127.0.0.1:3000/api/entity/entity-42");

    let call = api::request_for_command(
        base,
        ApiCommand::Call {
            verb: "board.append".to_owned(),
            data: "{\"ok\":true}".to_owned(),
        },
    )
    .unwrap();
    assert_eq!(call.method, "POST");
    assert_eq!(
        call.url,
        "http://127.0.0.1:3000/v1/core/memory/verbs/board.append"
    );
    assert_eq!(call.body.as_deref(), Some(b"{\"ok\":true}".as_slice()));
    assert_eq!(call.content_type.as_deref(), Some("application/json"));

    let raw = api::request_for_command(
        base,
        ApiCommand::Raw {
            method: "get".to_owned(),
            path: "/api/health".to_owned(),
            data: None,
            content_type: None,
        },
    )
    .unwrap();
    assert_eq!(
        raw.method, "GET",
        "the method is normalized, not re-spelled"
    );
    assert_eq!(raw.url, "http://127.0.0.1:3000/api/health");
    assert_eq!(raw.body, None);
    assert_eq!(raw.content_type, None);

    // A trailing slash on the configured origin must not double up.
    let trailing =
        api::request_for_command("http://127.0.0.1:3000/", ApiCommand::Discover).unwrap();
    assert_eq!(trailing.url, "http://127.0.0.1:3000/api/core/discover");
}

/// Caller text is DATA. A query, an entity id, or a verb that looks like URL
/// structure must arrive percent-encoded rather than adding a path segment,
/// another query parameter, or a host.
#[test]
fn api_percent_encodes_caller_text_into_the_url() {
    let base = "https://vault.example";

    let search = api::request_for_command(
        base,
        ApiCommand::Search {
            query: "a b&limit=999#frag/../etc".to_owned(),
            limit: Some(1),
        },
    )
    .unwrap();
    assert_eq!(
        search.url,
        "https://vault.example/api/search/text?query=a%20b%26limit%3D999%23frag%2F..%2Fetc&limit=1"
    );

    let entity = api::request_for_command(
        base,
        ApiCommand::Get {
            entity_id: "../../v1/core/batch".to_owned(),
        },
    )
    .unwrap();
    assert_eq!(
        entity.url, "https://vault.example/api/entity/..%2F..%2Fv1%2Fcore%2Fbatch",
        "an entity id must not climb into another route"
    );

    let call = api::request_for_command(
        base,
        ApiCommand::Call {
            verb: "verb/../../etc".to_owned(),
            data: "{}".to_owned(),
        },
    )
    .unwrap();
    assert_eq!(
        call.url,
        "https://vault.example/v1/core/memory/verbs/verb%2F..%2F..%2Fetc"
    );
}

/// `raw` is the escape hatch, not an open redirect: every way of leaving the
/// configured origin is refused before a request exists.
#[test]
fn api_raw_refuses_requests_that_leave_the_configured_origin() {
    for path in [
        "//evil.example/api/health",
        "https://evil.example/api/health",
        "api/health",
        "/api/../../etc/passwd",
        "/api/health\\..",
        "/api/ health",
    ] {
        let error = api::request_for_command(
            "http://127.0.0.1:3000",
            ApiCommand::Raw {
                method: "GET".to_owned(),
                path: path.to_owned(),
                data: None,
                content_type: None,
            },
        )
        .unwrap_err();
        assert!(
            !error.to_string().is_empty(),
            "{path} must be refused with a reason"
        );
    }

    for method in ["--upload-file", "GET POST", "", "G3T"] {
        assert!(
            api::request_for_command(
                "http://127.0.0.1:3000",
                ApiCommand::Raw {
                    method: method.to_owned(),
                    path: "/api/health".to_owned(),
                    data: None,
                    content_type: None,
                },
            )
            .is_err(),
            "method {method:?} must be refused before it can reach curl's argv"
        );
    }

    for base in [
        "127.0.0.1:3000",
        "file:///etc/passwd",
        "http://127.0.0.1:3000/?next=",
        "http://",
    ] {
        assert!(
            api::request_for_command(base, ApiCommand::Discover).is_err(),
            "base URL {base:?} must be refused"
        );
    }
}

/// A base URL carrying a PATH is refused rather than quietly honoured. Every
/// shaped command appends a literal route to the configured origin, so a base
/// of `http://host/prefix` would send `GET /prefix/api/core/discover` — a
/// route this server does not serve — and the caller would read a 404 about a
/// request they never wrote. Rejecting is the only reading that cannot be
/// wrong: stripping the prefix would discard something the caller typed on
/// purpose, and honouring it would send the request somewhere else.
#[test]
fn api_refuses_a_base_url_that_carries_a_path() {
    for base in [
        "http://127.0.0.1:3000/prefix",
        "https://vault.example/a/b/",
        "http://vault.example/api",
    ] {
        let error = api::request_for_command(base, ApiCommand::Discover)
            .expect_err(&format!("base URL {base:?} must be refused"))
            .to_string();
        assert!(
            error.contains("plain origin without a path"),
            "the refusal must name the reason: {error}"
        );
    }

    // The origins that always worked still do, trailing slash and all.
    for (base, expected) in [
        ("http://127.0.0.1:3000", "http://127.0.0.1:3000"),
        ("http://127.0.0.1:3000/", "http://127.0.0.1:3000"),
        ("https://vault.example", "https://vault.example"),
        ("https://vault.example///", "https://vault.example"),
    ] {
        let request = api::request_for_command(base, ApiCommand::Discover)
            .unwrap_or_else(|error| panic!("base URL {base:?} must be accepted: {error}"));
        assert_eq!(request.url, format!("{expected}/api/core/discover"));
    }
}

/// `raw` is the only command whose body is not this server's own JSON, so the
/// media type is a caller decision there and nowhere else. The DEFAULT does
/// not move — a body with no declared type is still `application/json`, which
/// is what every registered route reads — and a declared type replaces it, so
/// a wire protocol like Git smart-HTTP is expressible without a second
/// command or a second authority model.
#[test]
fn api_raw_content_type_defaults_to_json_and_only_a_valid_type_replaces_it() {
    let base = "http://127.0.0.1:3000";
    let raw = |data: Option<&str>, content_type: Option<&str>| {
        api::request_for_command(
            base,
            ApiCommand::Raw {
                method: "POST".to_owned(),
                path: "/api/health".to_owned(),
                data: data.map(str::to_owned),
                content_type: content_type.map(str::to_owned),
            },
        )
    };

    assert_eq!(
        raw(Some("{}"), None).unwrap().content_type.as_deref(),
        Some("application/json"),
        "a body with no declared type keeps the pinned default"
    );
    assert_eq!(
        raw(None, None).unwrap().content_type,
        None,
        "a request with no body declares no media type"
    );

    let git = raw(Some("0000"), Some("application/x-git-upload-pack-request")).unwrap();
    assert_eq!(
        git.content_type.as_deref(),
        Some("application/x-git-upload-pack-request"),
        "a declared type passes through verbatim, in place of JSON"
    );
    assert_eq!(git.body.as_deref(), Some(b"0000".as_slice()));

    for rejected in [
        "",
        "application/json; charset=utf-8",
        "application/json\nheader = \"x: y\"",
        "application/ json",
        "application/js\u{00f8}n",
        "applicationjson",
        "application/x/y",
    ] {
        assert!(
            raw(Some("{}"), Some(rejected)).is_err(),
            "content type {rejected:?} must be refused before it can become a header"
        );
    }
}

/// `@FILE` and a literal body are different forms, and neither is shell text:
/// a body full of shell metacharacters is bytes, not a command.
#[test]
fn api_body_forms_are_distinct_and_never_shell_evaluated() {
    let dir = tempfile::tempdir().unwrap();
    let body_path = dir.path().join("request.json");
    std::fs::write(&body_path, b"{\"from\":\"file\"}").unwrap();

    let from_file = api::request_for_command(
        "http://127.0.0.1:3000",
        ApiCommand::Call {
            verb: "board.append".to_owned(),
            data: format!("@{}", body_path.display()),
        },
    )
    .unwrap();
    assert_eq!(
        from_file.body.as_deref(),
        Some(b"{\"from\":\"file\"}".as_slice())
    );

    let literal = "{\"shell\":\"$(id); rm -rf / `whoami`\"}";
    let verbatim = api::request_for_command(
        "http://127.0.0.1:3000",
        ApiCommand::Call {
            verb: "board.append".to_owned(),
            data: literal.to_owned(),
        },
    )
    .unwrap();
    assert_eq!(
        verbatim.body.as_deref(),
        Some(literal.as_bytes()),
        "a literal body is sent verbatim, never expanded"
    );

    assert!(
        api::request_for_command(
            "http://127.0.0.1:3000",
            ApiCommand::Call {
                verb: "board.append".to_owned(),
                data: format!("@{}", dir.path().join("absent.json").display()),
            },
        )
        .is_err(),
        "a missing @FILE is an error here, not an empty request"
    );
}

/// The credential travels in curl's config channel on stdin. It is in no
/// argument, no captured stdout, and no captured stderr.
#[test]
#[cfg(unix)]
fn api_credential_reaches_curl_only_through_the_config_channel() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("response.bin"), b"{\"ok\":true}").unwrap();
    let program = write_fake_curl(dir.path(), &fake_curl_script(dir.path(), 0));

    let request = api::request_for_command(
        "http://127.0.0.1:3000",
        ApiCommand::Call {
            verb: "board.append".to_owned(),
            data: "{\"claim\":\"placeholder\"}".to_owned(),
        },
    )
    .unwrap();

    let output = api::run_curl_output(
        program.as_os_str(),
        &request,
        Some(PLACEHOLDER_SECRET),
        std::process::Stdio::piped(),
        std::process::Stdio::piped(),
    )
    .unwrap();

    let argv = std::fs::read_to_string(dir.path().join("argv.txt")).unwrap();
    let config = std::fs::read_to_string(dir.path().join("stdin.bin")).unwrap();
    let staged_body = std::fs::read(dir.path().join("body.bin")).unwrap();

    assert!(
        !argv.contains(PLACEHOLDER_SECRET),
        "the credential must never appear in the child's argument list"
    );
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains(PLACEHOLDER_SECRET)
            && !String::from_utf8_lossy(&output.stderr).contains(PLACEHOLDER_SECRET),
        "the credential must never be printed"
    );
    assert_eq!(
        config,
        format!("header = \"Authorization: Bearer {PLACEHOLDER_SECRET}\"\n"),
        "the credential rides the config channel as a bearer header"
    );
    assert!(
        !config.contains("x-oneiron-secret"),
        "the deleted legacy header must never be sent"
    );
    assert_eq!(
        staged_body, b"{\"claim\":\"placeholder\"}",
        "the request body reaches curl exactly as read"
    );
    for flag in api::CURL_FLAGS {
        assert!(argv.contains(flag), "curl must be invoked with {flag}");
    }
    assert!(
        argv.contains("--config\n-\n"),
        "the config channel must be curl's stdin: {argv}"
    );

    // The body is staged privately for the length of the call and no longer.
    let staged_path = argv
        .lines()
        .find_map(|line| line.strip_prefix('@'))
        .expect("curl must be handed the staged body file");
    assert!(
        !std::path::Path::new(staged_path).exists(),
        "the staged request body must not outlive the call"
    );
}

/// A success body is the server's bytes, not a re-encoding of them: binary,
/// invalid UTF-8, and embedded NULs all arrive unchanged.
#[test]
#[cfg(unix)]
fn api_success_body_passes_through_byte_for_byte() {
    let dir = tempfile::tempdir().unwrap();
    let response: Vec<u8> = vec![0x00, 0xff, b'{', b'"', b'a', b'"', b'}', 0x0a, 0xc3, 0x28];
    std::fs::write(dir.path().join("response.bin"), &response).unwrap();
    let program = write_fake_curl(dir.path(), &fake_curl_script(dir.path(), 0));

    let request = api::request_for_command("http://127.0.0.1:3000", ApiCommand::Discover).unwrap();
    let output = api::run_curl_output(
        program.as_os_str(),
        &request,
        Some(PLACEHOLDER_SECRET),
        std::process::Stdio::piped(),
        std::process::Stdio::piped(),
    )
    .unwrap();

    assert_eq!(
        output.stdout, response,
        "the response body must arrive byte-identical, binary included"
    );
    assert!(api::exit_status_result(&output.status).is_ok());
}

/// A non-2xx keeps its body and its diagnostic, and still fails. `curl`'s
/// `--fail-with-body` is what makes both true at once.
#[test]
#[cfg(unix)]
fn api_failure_keeps_the_body_and_exits_non_zero() {
    let dir = tempfile::tempdir().unwrap();
    let body = b"{\"code\":\"UNAUTHORIZED\",\"message\":\"request is not authorized\"}";
    std::fs::write(dir.path().join("response.bin"), body).unwrap();
    let program = write_fake_curl(dir.path(), &fake_curl_script(dir.path(), 22));

    let request = api::request_for_command("http://127.0.0.1:3000", ApiCommand::Discover).unwrap();
    let output = api::run_curl_output(
        program.as_os_str(),
        &request,
        Some(PLACEHOLDER_SECRET),
        std::process::Stdio::piped(),
        std::process::Stdio::piped(),
    )
    .unwrap();

    assert_eq!(
        output.stdout,
        body.as_slice(),
        "the server's error envelope must stay visible"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("curl: diagnostic on stderr"),
        "curl diagnostics must stay on stderr"
    );
    let error = api::exit_status_result(&output.status).unwrap_err();
    assert!(
        error.to_string().contains("22"),
        "the failing status must survive as a non-zero exit: {error}"
    );
}

/// The config channel is a grammar, so a credential that could smuggle a
/// second option into it is refused instead of quoted into one.
#[test]
fn api_config_channel_refuses_a_credential_it_cannot_carry_safely() {
    assert_eq!(
        api::curl_config("abc\"def\\gh").unwrap(),
        "header = \"Authorization: Bearer abc\\\"def\\\\gh\"\n"
    );
    assert!(api::curl_config("").is_err());
    assert!(api::curl_config("line\nheader = \"x: y\"").is_err());
}

/// curl reads the HOST's own config file before any flag on its command line,
/// and it reads it EVEN when `--config` is given. A line there that added a
/// transfer would be handed the credential this process puts on the config
/// channel — a leak to a host nobody named. `-q` refuses that file, and curl
/// honours it only as the FIRST argument, which is what this row pins.
#[test]
#[cfg(unix)]
fn api_refuses_the_hosts_curl_config_before_any_other_argument() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("response.bin"), b"{}").unwrap();
    let program = write_fake_curl(dir.path(), &fake_curl_script(dir.path(), 0));

    let request = api::request_for_command("http://127.0.0.1:3000", ApiCommand::Discover).unwrap();
    api::run_curl_output(
        program.as_os_str(),
        &request,
        Some(PLACEHOLDER_SECRET),
        std::process::Stdio::piped(),
        std::process::Stdio::piped(),
    )
    .unwrap();

    let argv = std::fs::read_to_string(dir.path().join("argv.txt")).unwrap();
    assert_eq!(
        argv.lines().next(),
        Some(api::CURL_DISABLE_HOST_CONFIG),
        "the host-config refusal must be curl's first argument, or curl ignores it: {argv}"
    );
    for flag in api::CURL_FLAGS {
        assert!(
            argv.contains(flag),
            "curl must still be invoked with {flag}"
        );
    }
}

/// The property above is curl's own, so this row proves it with the REAL
/// binary: a populated `CURL_HOME/.curlrc` that sends the transfer's body to a
/// file of its own choosing. Loaded, that config captures the body; through
/// this module it is refused and the bytes arrive here instead. A host with no
/// curl, or with a curl that cannot read the `file://` fixture, has nothing to
/// demonstrate and this row stands down rather than failing on the host.
#[test]
#[cfg(unix)]
fn api_keeps_a_host_curlrc_from_capturing_the_transfer() {
    const PAYLOAD: &[u8] = b"served-bytes";

    let dir = tempfile::tempdir().unwrap();
    let payload = dir.path().join("payload.bin");
    std::fs::write(&payload, PAYLOAD).unwrap();
    let url = format!("file://{}", payload.display());

    let Ok(probe) = std::process::Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--fail-with-body",
            "--url",
            &url,
        ])
        .output()
    else {
        return;
    };
    if !probe.status.success() || probe.stdout != PAYLOAD {
        return;
    }

    let captured = dir.path().join("captured-by-curlrc.bin");
    std::fs::write(
        dir.path().join(".curlrc"),
        format!("output = \"{}\"\n", captured.display()),
    )
    .unwrap();

    // The fixture is real: with the host config loaded, the body goes where
    // that file said instead of to the caller.
    let control = std::process::Command::new("curl")
        .env("CURL_HOME", dir.path())
        .args([
            "--silent",
            "--show-error",
            "--fail-with-body",
            "--url",
            &url,
        ])
        .output()
        .unwrap();
    assert!(
        control.status.success() && control.stdout.is_empty() && captured.is_file(),
        "fixture check: a loaded curlrc must capture the body"
    );
    std::fs::remove_file(&captured).unwrap();

    // The same curlrc, in force for this module's own invocation.
    let program = write_fake_curl(
        dir.path(),
        &format!(
            "#!/bin/sh\nCURL_HOME=\"{}\" exec curl \"$@\"\n",
            dir.path().display()
        ),
    );
    let request = api::CurlRequest {
        method: "GET".to_owned(),
        url: url.clone(),
        body: None,
        content_type: None,
    };
    let output = api::run_curl_output(
        program.as_os_str(),
        &request,
        Some(PLACEHOLDER_SECRET),
        std::process::Stdio::piped(),
        std::process::Stdio::piped(),
    )
    .unwrap();

    assert_eq!(
        output.stdout,
        PAYLOAD,
        "the body must reach this process, not the curlrc's file: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !captured.exists(),
        "the host curlrc must not be loaded at all"
    );
}

/// The server serves public routes and can be configured to allow
/// unauthenticated access, so an ABSENT credential is a request without one
/// rather than an error. Nothing stands in for it: no config channel, no empty
/// header, no placeholder bearer — a bogus credential is an authentication
/// ATTEMPT the server refuses, which is not the anonymous call that works.
#[test]
#[cfg(unix)]
fn api_without_a_configured_secret_sends_no_authorization_at_all() {
    let dir = tempfile::tempdir().unwrap();
    let served = b"{\"status\":\"ok\"}";
    std::fs::write(dir.path().join("response.bin"), served).unwrap();
    let program = write_fake_curl(dir.path(), &fake_curl_script(dir.path(), 0));

    let request = api::request_for_command(
        "http://127.0.0.1:3000",
        ApiCommand::Raw {
            method: "GET".to_owned(),
            path: "/api/health".to_owned(),
            data: None,
            content_type: None,
        },
    )
    .unwrap();

    let anonymous = api::run_curl_output(
        program.as_os_str(),
        &request,
        None,
        std::process::Stdio::piped(),
        std::process::Stdio::piped(),
    )
    .unwrap();

    let argv = std::fs::read_to_string(dir.path().join("argv.txt")).unwrap();
    let stdin = std::fs::read(dir.path().join("stdin.bin")).unwrap();

    assert_eq!(anonymous.stdout, served, "a public route still answers");
    assert!(
        !argv.contains("--config"),
        "no credential means no config channel at all: {argv}"
    );
    assert!(
        !argv.to_ascii_lowercase().contains("authorization"),
        "no credential means no Authorization header: {argv}"
    );
    assert!(
        stdin.is_empty(),
        "nothing is handed to curl's stdin when there is nothing to carry"
    );
    assert_eq!(
        argv.lines().next(),
        Some(api::CURL_DISABLE_HOST_CONFIG),
        "the host-config refusal stays first on the anonymous path too"
    );

    // The credentialled path is unchanged: the header still rides stdin only.
    api::run_curl_output(
        program.as_os_str(),
        &request,
        Some(PLACEHOLDER_SECRET),
        std::process::Stdio::piped(),
        std::process::Stdio::piped(),
    )
    .unwrap();
    let argv = std::fs::read_to_string(dir.path().join("argv.txt")).unwrap();
    let config = std::fs::read_to_string(dir.path().join("stdin.bin")).unwrap();
    assert!(argv.contains("--config\n-\n"), "{argv}");
    assert!(!argv.contains(PLACEHOLDER_SECRET));
    assert_eq!(
        config,
        format!("header = \"Authorization: Bearer {PLACEHOLDER_SECRET}\"\n")
    );

    // A credential that IS configured is still checked: an empty one is a
    // misconfiguration, not an anonymous request.
    assert!(
        api::run_curl_output(
            program.as_os_str(),
            &request,
            Some(""),
            std::process::Stdio::piped(),
            std::process::Stdio::piped(),
        )
        .is_err(),
        "an empty configured credential must be refused rather than sent"
    );
}

/// Staging a body that fails PART-WAY through must leave nothing on disk. The
/// file exists from the moment it is opened, so the guard that removes it has
/// to own the path BEFORE the first write: otherwise a write error returns
/// past the guard's construction and the partial body — request bytes, maybe
/// private ones — stays in the temp directory for the rest of the boot.
#[test]
fn api_a_failed_body_staging_leaves_nothing_behind() {
    struct RefusingSink;

    impl std::io::Write for RefusingSink {
        fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("no space left on device"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let failed = dir.path().join("failed.body");
    std::fs::write(&failed, b"partial").unwrap();

    let error = api::TempBody::write_staged(
        failed.clone(),
        &mut RefusingSink,
        b"{\"claim\":\"placeholder\"}",
    )
    .expect_err("a sink that refuses every write must fail the staging");
    assert!(error.to_string().contains("stage the request body"));
    assert!(
        !failed.exists(),
        "a failed staging must not leave request bytes in the temp directory"
    );

    // The success path is unchanged: a live file for the length of the call,
    // and no longer.
    let staged_path = dir.path().join("staged.body");
    let mut file = std::fs::File::create(&staged_path).unwrap();
    let staged = api::TempBody::write_staged(staged_path.clone(), &mut file, b"body").unwrap();
    assert!(staged_path.is_file());
    drop(staged);
    assert!(
        !staged_path.exists(),
        "a staged body must not outlive the call"
    );
}
