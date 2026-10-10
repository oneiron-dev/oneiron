//! ARCH-0069 S2 at register time: a name the repo manifest declares carries
//! the manifest's entry on its custody record, and an ask wider than that entry
//! stores nothing.

use std::path::Path;
use std::process::Command;

use super::*;
use crate::codebase::RepoRef;
use crate::git_wire::{GitOid, GitRefName, GitWire};
use crate::origin::lfs::lfs_repo_id;
use crate::origin::publication::{OriginPublicationRequest, origin_publication_intent_claim};
use crate::origin::secret_manifest::SECRET_MANIFEST_PATH;
use crate::origin::smart_http::origin_serving_root;
use crate::secret_custody::doors::read_secret_custody_in_txn;
use crate::store::GateDecisionId;
use crate::temporal::TimeRange;

const MANIFEST: &str = r#"schema_version = 1

[[secrets]]
name = "deploy-token"
class = "custody-portable"
declared_paths = [".env.deploy"]

[[secrets.bindings]]
effector = "deploy"
tier_ceiling = 1
scopes = ["read"]

[[secrets]]
name = "signing-key"
class = "custody-device-bound"
declared_paths = ["keys/signing.pem"]

[[secrets.bindings]]
effector = "release"
tier_ceiling = 0
scopes = ["read"]
"#;

fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
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
fn publish_manifest(vault: &Vault, repo: &str, manifest: &str) -> String {
    let source = tempfile::tempdir().expect("source");
    git(source.path(), &["init", "--initial-branch=main"]);
    let file = source.path().join(SECRET_MANIFEST_PATH);
    std::fs::create_dir_all(file.parent().expect("manifest dir")).expect("mkdir");
    std::fs::write(&file, manifest).expect("manifest");
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
    let root = origin_serving_root(vault).expect("serving root");
    let bare = format!("{repo}.git");
    git(
        &root,
        &[
            "clone",
            "--bare",
            source.path().to_str().expect("utf-8"),
            &bare,
        ],
    );
    let dir = root.join(&bare).canonicalize().expect("repo dir");
    // A raw ref is not publication authority; the journal is.
    git(&dir, &["update-ref", "-d", "refs/heads/main"]);
    let wire = GitWire::new(vault).expect("wire");
    let oid = GitOid::parse_hex(commit.as_str()).expect("oid");
    let repo_ref = RepoRef::parse(&format!("local:{}#{commit}", dir.display())).expect("ref");
    let handle = wire.open_repo(repo_ref, &dir).expect("open repo");
    let request = OriginPublicationRequest {
        repo_id: lfs_repo_id(&handle.identity().as_hex()).expect("repo id"),
        repo: handle,
        ref_name: GitRefName::parse_full("refs/heads/main").expect("ref name"),
        expected_old_oid: None,
        new_oid: oid,
        required_objects: Vec::new(),
        required_lfs_oids: Vec::new(),
        provenance_claim_id: EntityId::now(),
        actor_id: EntityId::now(),
        occurred: TimeRange { start: 1, end: 1 },
        learned_at: 1,
    };
    let intent = origin_publication_intent_claim(&request).expect("intent");
    vault
        .put_claim(
            &request.provenance_claim_id,
            &intent,
            TimeRange { start: 1, end: 1 },
            1,
        )
        .expect("provenance");
    vault.publish_origin_ref(&wire, request).expect("published");
    commit
}

fn owner(vault: &Vault) -> AuthenticatedOwner {
    let actor = vault.ensure_embedded_owner_actor().expect("owner actor");
    vault
        .authenticate_owner(actor, &actor.to_hex(), true, GateDecisionId::now())
        .expect("owner")
}

fn ask<'a>(name: &'a str, class: CustodyClass, rung: CustodyTier) -> OwnerSecretRegistration<'a> {
    OwnerSecretRegistration {
        name,
        class,
        device_only: false,
        rung,
        bindings: Vec::new(),
        manifest: Some(ManifestSource {
            repo: "app".to_owned(),
            git_ref: "refs/heads/main".to_owned(),
        }),
        value: b"synthetic-placeholder",
    }
}

fn binding(effector: &str, tier: Option<CustodyTier>, scopes: &[&str]) -> RequestedBinding {
    RequestedBinding {
        effector: effector.to_owned(),
        tier_ceiling: tier,
        scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
    }
}

#[test]
fn a_declared_name_carries_its_manifest_entry_and_a_wider_ask_stores_nothing() {
    let dir = tempfile::tempdir().expect("vault dir");
    let vault = Vault::open(dir.path(), crate::config::VaultConfig::default()).expect("vault");
    let commit = publish_manifest(&vault, "app", MANIFEST);
    let owner = owner(&vault);

    // The owner asks for rung 2 and names no binding: the manifest's binding
    // is taken, at the manifest's tier 1.
    let registered = vault
        .register_secret_as_owner(
            &owner,
            &ask(
                "deploy-token",
                CustodyClass::CustodyPortable,
                CustodyTier::T2LocalRegistered,
            ),
            7,
        )
        .expect("registered");
    let manifest_ref = format!("app:refs/heads/main@{commit}:{SECRET_MANIFEST_PATH}");
    let txn = vault.store.env.read_txn().expect("txn");
    let stored = read_secret_custody_in_txn(&vault.store, &txn, &registered.secret_id)
        .expect("read")
        .expect("stored");
    drop(txn);
    assert_eq!(stored.manifest_ref(), manifest_ref);
    assert_eq!(stored.declared_paths, [".env.deploy"]);
    assert_eq!(
        stored.bindings,
        [SecretBinding {
            effector: "deploy".to_owned(),
            tier_ceiling: CustodyTier::T1Leased,
            scopes: vec!["read".to_owned()],
        }]
    );
    assert_eq!(stored.rotation_generation, 0);
    assert_eq!(stored.registered_at, 7);
    assert_eq!(stored.policy_floor_snapshot, SecretCustodyFloor::default());
    assert_eq!(registered.manifest_ref, manifest_ref);
    assert_eq!(registered.declared_paths, stored.declared_paths);

    // Each ask reaches past the entry in one way, and stores nothing.
    let wider: [(&str, OwnerSecretRegistration<'_>); 5] = [
        (
            "a tier above the manifest's",
            OwnerSecretRegistration {
                bindings: vec![binding("deploy", None, &["read"])],
                ..ask(
                    "deploy-token-2",
                    CustodyClass::CustodyPortable,
                    CustodyTier::T2LocalRegistered,
                )
            },
        ),
        (
            "an effector the manifest does not declare",
            OwnerSecretRegistration {
                bindings: vec![binding("ci", None, &["read"])],
                ..ask(
                    "deploy-token-2",
                    CustodyClass::CustodyPortable,
                    CustodyTier::T1Leased,
                )
            },
        ),
        (
            "a scope the manifest does not declare",
            OwnerSecretRegistration {
                bindings: vec![binding("deploy", None, &["read", "write"])],
                ..ask(
                    "deploy-token-2",
                    CustodyClass::CustodyPortable,
                    CustodyTier::T1Leased,
                )
            },
        ),
        (
            "a class that travels further",
            ask(
                "signing-key",
                CustodyClass::CustodyPortable,
                CustodyTier::T0Doored,
            ),
        ),
        (
            "a name the manifest does not declare",
            ask(
                "undeclared",
                CustodyClass::CrossVault,
                CustodyTier::T0Doored,
            ),
        ),
    ];
    for (why, request) in wider {
        let error = vault
            .register_secret_as_owner(&owner, &request, 8)
            .expect_err(why);
        assert!(
            matches!(
                error,
                Error::Secret(SecretError::SecretWiderThanManifest { .. })
            ),
            "{why}: {error:?}"
        );
        assert_eq!(
            vault.resolve_secret_ref(request.name).expect("index"),
            None,
            "{why}"
        );
    }

    // Narrower than the entry is the owner's call: the device-bound key may
    // be cross-vault.
    let narrower = vault
        .register_secret_as_owner(
            &owner,
            &ask(
                "signing-key",
                CustodyClass::CrossVault,
                CustodyTier::T0Doored,
            ),
            9,
        )
        .expect("narrower registers");
    assert_eq!(narrower.declared_paths, ["keys/signing.pem"]);
    assert_eq!(narrower.bindings[0].tier_ceiling, CustodyTier::T0Doored);
}

/// Sol on #1372: a `refs/replace/<commit>` entry in the served repository
/// made every object read return the replacement, so a registration took a
/// wider manifest than the published commit declares, under that commit's
/// name.
#[test]
fn a_replacement_ref_never_decides_which_manifest_is_read() {
    let dir = tempfile::tempdir().expect("vault dir");
    let vault = Vault::open(dir.path(), crate::config::VaultConfig::default()).expect("vault");
    let narrow = MANIFEST.replace("tier_ceiling = 1", "tier_ceiling = 0");
    let published = publish_manifest(&vault, "app", &narrow);

    // A commit declaring tier 2, planted as the published commit's replacement.
    let wide = tempfile::tempdir().expect("wide");
    git(wide.path(), &["init", "--initial-branch=main"]);
    let file = wide.path().join(SECRET_MANIFEST_PATH);
    std::fs::create_dir_all(file.parent().expect("manifest dir")).expect("mkdir");
    std::fs::write(
        &file,
        MANIFEST.replace("tier_ceiling = 1", "tier_ceiling = 2"),
    )
    .expect("manifest");
    git(wide.path(), &["add", "."]);
    git(
        wide.path(),
        &[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-m",
            "wider",
        ],
    );
    let replacement = git(wide.path(), &["rev-parse", "HEAD"]);
    let bare = origin_serving_root(&vault).expect("root").join("app.git");
    let wide_path = wide.path().to_str().expect("utf-8");
    git(&bare, &["fetch", wide_path, "main:refs/planted/wide"]);
    git(&bare, &["replace", &published, &replacement]);
    git(&bare, &["update-ref", "-d", "refs/planted/wide"]);

    let registered = vault
        .register_secret_as_owner(
            &owner(&vault),
            &ask(
                "deploy-token",
                CustodyClass::CustodyPortable,
                CustodyTier::T2LocalRegistered,
            ),
            7,
        )
        .expect("registered");
    assert_eq!(
        registered.manifest_ref,
        format!("app:refs/heads/main@{published}:{SECRET_MANIFEST_PATH}")
    );
    assert_eq!(registered.bindings[0].tier_ceiling, CustodyTier::T0Doored);
}
