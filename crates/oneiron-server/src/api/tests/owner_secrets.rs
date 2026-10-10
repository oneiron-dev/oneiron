//! `/v1/owner/secrets/register`: the owner puts a secret into custody
//! (ARCH-0069 S1–S3), with the repo manifest's entry when a repository
//! declares the name (S2), and can then rotate it (S6).
use std::path::Path;

use super::owner_routes::{call, owner_recipe, refused_recipes};
use super::*;
use oneiron::git_wire::{GitOid, GitRefName, GitWire};
use oneiron::origin::publication::{OriginPublicationRequest, origin_publication_intent_claim};
use oneiron::origin::secret_manifest::SECRET_MANIFEST_PATH;

const MANIFEST: &str = r#"schema_version = 1

[[secrets]]
name = "deploy-token"
class = "custody-portable"
declared_paths = [".env.deploy"]

[[secrets.bindings]]
effector = "deploy"
tier_ceiling = 1
scopes = ["read"]
"#;

fn git(dir: &Path, args: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .current_dir(dir)
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .expect("git runs");
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// Serves `repo` from the vault with one commit holding the manifest, and
/// publishes `refs/heads/main` at it, as a landed push would. Returns the
/// commit.
fn publish_manifest(vault: &oneiron::Vault, repo: &str) -> String {
    let source = tempfile::tempdir().expect("source");
    git(source.path(), &["init", "--initial-branch=main"]);
    let file = source.path().join(SECRET_MANIFEST_PATH);
    std::fs::create_dir_all(file.parent().expect("manifest dir")).expect("mkdir");
    std::fs::write(&file, MANIFEST).expect("manifest");
    git(source.path(), &["add", "."]);
    git(
        source.path(),
        &[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-m",
            "declare secrets",
        ],
    );
    let commit = git(source.path(), &["rev-parse", "HEAD"]);
    let root = oneiron::origin::smart_http::origin_serving_root(vault).expect("serving root");
    let bare = format!("{repo}.git");
    let source_path = source.path().to_str().expect("utf-8");
    git(&root, &["clone", "--bare", source_path, &bare]);
    let dir = root.join(&bare).canonicalize().expect("repo dir");
    // A raw ref is not publication authority; the journal is.
    git(&dir, &["update-ref", "-d", "refs/heads/main"]);
    let wire = GitWire::new(vault).expect("wire");
    let repo_ref = oneiron::codebase::RepoRef::parse(&format!("local:{}#{commit}", dir.display()))
        .expect("repo ref");
    let handle = wire.open_repo(repo_ref, &dir).expect("open repo");
    let request = OriginPublicationRequest {
        repo_id: oneiron::origin::lfs::lfs_repo_id(&handle.identity().as_hex()).expect("repo id"),
        repo: handle,
        ref_name: GitRefName::parse_full("refs/heads/main").expect("ref name"),
        expected_old_oid: None,
        new_oid: GitOid::parse_hex(commit.as_str()).expect("oid"),
        required_objects: Vec::new(),
        required_lfs_oids: Vec::new(),
        provenance_claim_id: oneiron::EntityId::now(),
        actor_id: oneiron::EntityId::now(),
        occurred: oneiron::TimeRange { start: 1, end: 1 },
        learned_at: 1,
    };
    let intent = origin_publication_intent_claim(&request).expect("intent");
    vault
        .put_claim(
            &request.provenance_claim_id,
            &intent,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
        )
        .expect("provenance");
    vault.publish_origin_ref(&wire, request).expect("published");
    commit
}

/// One request with exactly these bytes, so the wipe hook can name them.
async fn post_raw(server: &Arc<SyncServer>, path: &str, body: &[u8]) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("POST")
        .uri(path)
        .header(AUTHORIZATION, owner_recipe(server))
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_vec()))
        .unwrap();
    route_json(server.clone(), request).await
}

#[tokio::test]
async fn owner_registers_a_secret_then_rotates_it_and_nobody_else_can() {
    let (_dir, server) = auth_test_server();
    let first = "Zmlyc3Qgc3ludGhldGlj"; // "first synthetic"
    let body = json!({
        "name": "deploy-token",
        "class": "custody-portable",
        "rung": 1,
        "bindings": [{ "effector": "deploy", "scopes": ["read"] }],
        "value_base64": first,
    });
    for recipe in refused_recipes(&server) {
        let (status, _) = call(
            &server,
            "POST",
            "/v1/owner/secrets/register",
            recipe,
            Some(&body),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    assert_eq!(
        server.vault().resolve_secret_ref("deploy-token").unwrap(),
        None
    );

    let owner = owner_recipe(&server);
    let (status, registered) = call(
        &server,
        "POST",
        "/v1/owner/secrets/register",
        owner.clone(),
        Some(&body),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{registered}");
    assert_eq!(registered["name"], "deploy-token");
    assert_eq!(registered["class"], "custody-portable");
    assert_eq!(registered["rotation_generation"], 0);
    assert_eq!(
        registered["bindings"],
        json!([{ "effector": "deploy", "tier_ceiling": 1, "scopes": ["read"] }])
    );
    assert_eq!(registered["manifest_ref"], "");
    let reply = registered.to_string();
    assert!(!reply.contains(first) && !reply.contains("first synthetic"));
    // The refused callers' bodies were never read; the owner's frame and the
    // buffer it was copied into were both wiped.
    assert_eq!(
        crate::owner::secrets::wiped::count(body.to_string().as_bytes()),
        2
    );
    let id = server
        .vault()
        .resolve_secret_ref("deploy-token")
        .unwrap()
        .expect("in custody");
    let generation = |server: &SyncServer| {
        server
            .vault()
            .get_secret_metadata(&id)
            .unwrap()
            .unwrap()
            .rotation_generation
    };
    assert_eq!(generation(&server), 0);

    // #1339's route rotates what the registration stored.
    let second = "c2Vjb25kIHN5bnRoZXRpYw=="; // "second synthetic"
    let (status, rotated) = call(
        &server,
        "POST",
        "/v1/owner/secrets/rotate",
        owner.clone(),
        Some(&json!({ "name": "deploy-token", "value_base64": second })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{rotated}");
    assert_eq!(rotated["from_generation"], 0);
    assert_eq!(rotated["to_generation"], 1);
    let reply = rotated.to_string();
    assert!(!reply.contains(second) && !reply.contains("second synthetic"));
    assert_eq!(generation(&server), 1);

    // Each refusal is the caller's error, typed.
    let refusals = [
        (body.clone(), StatusCode::CONFLICT, "secret_name_in_use"),
        (
            // Longer than a name-index key holds (Sol on #1372: a 500 before).
            json!({ "name": "n".repeat(300), "class": "cross-vault", "rung": 0, "value_base64": first }),
            StatusCode::BAD_REQUEST,
            "name must be 1 to 255 bytes",
        ),
        (
            json!({ "name": "t", "class": "custody-cloud", "rung": 0, "value_base64": first }),
            StatusCode::BAD_REQUEST,
            "class must be",
        ),
        (
            json!({ "name": "t", "class": "cross-vault", "rung": 3, "value_base64": first }),
            StatusCode::BAD_REQUEST,
            "a rung is",
        ),
        (
            // The default floor holds a cross-vault value at the door.
            json!({ "name": "t", "class": "cross-vault", "rung": 1, "value_base64": first }),
            StatusCode::CONFLICT,
            "secret_wider_than_floor",
        ),
        (
            json!({
                "name": "t", "class": "custody-portable", "rung": 0,
                "bindings": [{ "effector": "deploy", "tier_ceiling": 2 }],
                "value_base64": first,
            }),
            StatusCode::BAD_REQUEST,
            "above the secret's rung",
        ),
        (
            json!({
                "name": "t", "class": "custody-portable", "rung": 0,
                "manifest": { "repo": "absent" }, "value_base64": first,
            }),
            StatusCode::NOT_FOUND,
            "repo",
        ),
        (
            // A tag can name a tag object, which holds no tree (Sol on #1372:
            // a published annotated tag answered 500).
            json!({
                "name": "t", "class": "custody-portable", "rung": 0,
                "manifest": { "repo": "app", "ref": "refs/tags/v1" }, "value_base64": first,
            }),
            StatusCode::BAD_REQUEST,
            "manifest.ref must be a branch",
        ),
    ];
    for (body, expected, says) in refusals {
        let (status, reply) = call(
            &server,
            "POST",
            "/v1/owner/secrets/register",
            owner.clone(),
            Some(&body),
        )
        .await;
        assert_eq!(status, expected, "{body} -> {reply}");
        assert!(reply.to_string().contains(says), "{body} -> {reply}");
        assert!(!reply.to_string().contains(first), "{reply}");
    }
    assert_eq!(server.vault().resolve_secret_ref("t").unwrap(), None);
    assert_eq!(generation(&server), 1);
}

/// A registration refused inside its value, as #1339's rotation check does:
/// the frame and the one buffer it was copied into are both wiped.
#[tokio::test]
async fn a_registration_refused_inside_the_value_wipes_the_body_that_carried_it() {
    let (_dir, server) = auth_test_server();
    let body: &[u8] = br#"{"name":"deploy-token","class":"custody-portable","rung":0,"value_base64":"c3ludGhldGlj\uZZZZ"}"#;
    let (status, reply) = post_raw(&server, "/v1/owner/secrets/register", body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{reply}");
    assert!(!reply.to_string().contains("c3ludGhldGlj"), "{reply}");
    assert_eq!(crate::owner::secrets::wiped::count(body), 2);
    assert_eq!(
        server.vault().resolve_secret_ref("deploy-token").unwrap(),
        None
    );
}

/// ARCH-0069 S2 through the route: the repo's manifest declares the name, so
/// its entry lands on the record; an ask wider than the entry is refused, and
/// the body that carried it is wiped.
#[tokio::test]
async fn the_repo_manifest_entry_lands_on_the_record_and_a_wider_ask_is_refused() {
    let (_dir, server) = auth_test_server();
    let commit = publish_manifest(server.vault(), "app");

    let wider: &[u8] = br#"{"name":"deploy-token","class":"custody-portable","rung":2,"bindings":[{"effector":"deploy","scopes":["read"]}],"manifest":{"repo":"app"},"value_base64":"c3ludGhldGlj"}"#;
    let (status, reply) = post_raw(&server, "/v1/owner/secrets/register", wider).await;
    assert_eq!(status, StatusCode::CONFLICT, "{reply}");
    assert!(
        reply.to_string().contains("secret_wider_than_manifest"),
        "{reply}"
    );
    assert_eq!(crate::owner::secrets::wiped::count(wider), 2);
    assert_eq!(
        server.vault().resolve_secret_ref("deploy-token").unwrap(),
        None
    );

    let (status, registered) = call(
        &server,
        "POST",
        "/v1/owner/secrets/register",
        owner_recipe(&server),
        Some(&json!({
            "name": "deploy-token",
            "class": "custody-portable",
            "rung": 2,
            "manifest": { "repo": "app", "ref": "refs/heads/main" },
            "value_base64": "c3ludGhldGlj",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{registered}");
    assert_eq!(
        registered["manifest_ref"],
        format!("app:refs/heads/main@{commit}:{SECRET_MANIFEST_PATH}")
    );
    assert_eq!(registered["declared_paths"], json!([".env.deploy"]));
    // The manifest's binding, at its own tier 1 below the asked rung 2.
    assert_eq!(
        registered["bindings"],
        json!([{ "effector": "deploy", "tier_ceiling": 1, "scopes": ["read"] }])
    );
    let id = server
        .vault()
        .resolve_secret_ref("deploy-token")
        .unwrap()
        .expect("in custody");
    let stored = server.vault().get_secret_metadata(&id).unwrap().unwrap();
    assert_eq!(stored.bindings.len(), 1);
    assert_eq!(
        stored.bindings[0].tier_ceiling,
        oneiron::secret_custody::CustodyTier::T1Leased
    );
}
