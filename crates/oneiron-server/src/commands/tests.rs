use super::*;

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
    )
    .unwrap();

    let redacted = claim_body_json(&body, false);
    assert!(redacted.get("value").is_none());
    assert!(redacted.get("scope").is_none());
    assert!(redacted.get("evidence").is_none());

    let included = claim_body_json(&body, true);
    assert_eq!(included["value"], "private payload");
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

/// The CLI's 64-hex door writes signed withdrawal authority, not a legacy
/// tombstone. Revoking the named parent also kills its logged descendants.
#[test]
fn token_revoke_with_slip_id_revokes_subtree_and_preserves_sibling() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault");
    let mut cfg = oneiron::VaultConfig::server();
    cfg.dimensions = 32;
    cfg.map_size = 64 * 1024 * 1024;
    let vault = oneiron::Vault::open(&path, cfg.clone()).unwrap();
    let issuer = oneiron::authority::HostSlipIssuer::from_secret(b"cli-revoke").unwrap();
    let root = vault.ensure_host_root_slip(&issuer).unwrap();
    for (id, parent) in [
        ([71; 32], root.claims.slip_id),
        ([72; 32], root.claims.slip_id),
        ([73; 32], [71; 32]),
    ] {
        let mut claims = root.claims.clone();
        claims.slip_id = id;
        claims.parent_id = Some(parent);
        vault.mint_capability_slip(&issuer, claims).unwrap();
        assert!(vault.capability_slip_id_is_live(&id).unwrap());
    }
    drop(vault);
    let id: String = [71u8; 32].iter().map(|b| format!("{b:02x}")).collect();
    token_revoke(TokenRevokeArgs {
        jti: id,
        serve: ServeArgs {
            vault_path: Some(path.clone()),
            dimensions: Some(32),
            map_size: Some(64 * 1024 * 1024),
            dict_search_paths: Some(Vec::new()),
            auth_secret: Some("cli-revoke".into()),
            ..Default::default()
        },
    })
    .unwrap();
    let vault = oneiron::Vault::open(path, cfg).unwrap();
    assert!(!vault.capability_slip_id_is_live(&[71; 32]).unwrap());
    assert!(!vault.capability_slip_id_is_live(&[73; 32]).unwrap());
    assert!(vault.capability_slip_id_is_live(&[72; 32]).unwrap());
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

/// Stage a stand-in for `curl` without executing a freshly written inode.
#[cfg(unix)]
fn write_fake_curl(dir: &std::path::Path, script: &str) -> std::path::PathBuf {
    let path = dir.join("fake-curl");
    std::fs::write(path.with_extension("sh"), script).unwrap();
    // A concurrent fork can briefly inherit the script writer despite CLOEXEC.
    // Execute an immutable launcher and read the per-test script as data instead.
    let launcher = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/commands/tests/curl-launcher.sh");
    std::os::unix::fs::symlink(launcher, &path).unwrap();
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

#[test]
fn cli_binding_proof_authenticates_only_its_logged_holder() {
    let dir = tempfile::tempdir().unwrap();
    let vault = std::sync::Arc::new(
        oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap(),
    );
    let server = crate::server::SyncServer::new(
        vault,
        crate::config::SyncServerConfig {
            auth_secret: Some("cli-slip-issuer".into()),
            ..Default::default()
        },
    )
    .unwrap();
    let (slip, key) = crate::test_credentials::credential(&server, "jti=cli-holder-proof");
    assert!(slip.caveats.is_empty(), "this pins the uncaveated control");
    let token = slip.to_token().unwrap();
    let seed: String = key.to_bytes().iter().map(|b| format!("{b:02x}")).collect();
    let json = api::signed_binding_for_seed(&token, &seed).unwrap();
    let proof: crate::auth::BindingProof = serde_json::from_str(&json).unwrap();
    let auth =
        crate::auth::CoreAuth::from_slip_token(&token, &proof, server.vault().as_ref()).unwrap();
    assert!(auth.is_owner_grade());
    assert!(api::signed_binding_for_seed(&token, &"00".repeat(32)).is_err());
}

#[test]
fn cli_binding_proof_accepts_the_transferred_current_holder() {
    let dir = tempfile::tempdir().unwrap();
    let vault = std::sync::Arc::new(
        oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap(),
    );
    let server = crate::server::SyncServer::new(
        vault,
        crate::config::SyncServerConfig {
            auth_secret: Some("cli-transferred-slip-issuer".into()),
            ..Default::default()
        },
    )
    .unwrap();
    let (mut slip, old_holder) =
        crate::test_credentials::credential(&server, "jti=cli-transferred-holder");
    let recipient = ed25519_dalek::SigningKey::from_bytes(&[0xA5; 32]);
    slip.attenuate_to(
        oneiron::authority::SlipCaveat {
            ttl_secs: Some(60),
            ..Default::default()
        },
        &old_holder,
        recipient.verifying_key().to_bytes(),
    )
    .unwrap();
    let token = slip.to_token().unwrap();
    let old_seed: String = old_holder
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert!(api::signed_binding_for_seed(&token, &old_seed).is_err());

    let recipient_seed: String = recipient
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let json = api::signed_binding_for_seed(&token, &recipient_seed).unwrap();
    let proof: crate::auth::BindingProof = serde_json::from_str(&json).unwrap();
    let auth =
        crate::auth::CoreAuth::from_slip_token(&token, &proof, server.vault().as_ref()).unwrap();
    assert!(!auth.is_owner_grade());
}

#[test]
fn pairing_config_sends_slip_and_holder_proof_without_an_injected_option() {
    let binding = r#"{"timestamp":42,"nonce":"fresh","signature":"abcd"}"#;
    let config = api::curl_config_with_binding("v2.slip.logged", Some(binding)).unwrap();
    assert_eq!(config.lines().count(), 2);
    assert!(config.contains("Authorization: Bearer v2.slip.logged"));
    assert!(config.contains(r#"x-oneiron-binding: {\"timestamp\":42"#));
    assert!(
        api::curl_config_with_binding("v2.slip.logged", Some("ok\nurl = \"https://bad\"")).is_err()
    );
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
        url,
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
    .err()
    .expect("a sink that refuses every write must fail the staging");
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
