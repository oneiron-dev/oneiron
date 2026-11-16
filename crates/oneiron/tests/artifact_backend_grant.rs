//! A published app's backend holds verbs only under Grant rows the owner
//! mints as their own act, default none (canon ARCH-0050:347 and
//! CROSS-ARCH-0019 #public-backend, PUBLIC-BACKEND = A; Engine RULING
//! APP-BACKEND-LINK-GRANT = A, 15 Nov 20:30; FIX
//! [ARTIFACT-BACKEND-LINK-MINTS-DEFAULT-READ-GRANT]).
//!
//! Red at main: a second owner link that names verbs for the backend's
//! principal issues and mints a default read Grant, and one that names no
//! verb mints that Grant too; an owner link that leaves its holder open and
//! names verbs is redeemed as the backend; the serve-start backfill mints a
//! default read Grant for a backend that holds a read slip from a host link.
//! Guards (they pass there too): the backend's first link mints none and it
//! redeems that link; a backend the owner granted takes a verb link and gains
//! no second Grant; an ordinary named agent's link still mints its default
//! read Grant, it redeems an open verb link, and the backfill still mints its
//! default read Grant.
//!
//! FIX [APP-BACKEND-LINK-EXPIRED-GRANT-COUNTS]: a Grant whose `expires_at`
//! the authority clock has reached names no backend. Red at the merge of
//! #8713: once the backend's only Grant expired, the owner's link that names
//! verbs still issues, and a link issued while it stood still redeems.
//! Guards: the same link issues before the expiry, and a backend whose Grant
//! stands redeems it.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --test artifact_backend_grant`.
#![cfg(oneiron_test_support)]
#![allow(
    clippy::disallowed_methods,
    reason = "the fixture commits an app bundle with the git binary"
)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::agent_dispatch::CommReach;
use oneiron::authority::{
    ActSurface, CapabilitySlip, HostSlipIssuer, MachineRole, PairingLink, PairingPrincipal,
};
use oneiron::consent::{AuthenticatedOwner, ConsentRegistryQuery, ConsentRegistryRow};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_contracts::entity_id::derived_domains::AGENT_PRINCIPAL;
use serde_json::json;

const APP: &str = "backend-grant-app";
/// How long an expiring Grant of these tests stands after its mint: well
/// inside the one-hour pairing code a link issued at the mint keeps.
const GRANT_LIFETIME_SECS: u64 = 120;

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    issuer: HostSlipIssuer,
    owner_proof: AuthenticatedOwner,
    /// The app backend's principal, as its first link names it.
    backend: EntityId,
    /// The backend's first, zero-verb link, not yet redeemed.
    first_link: PairingLink,
}

fn git(repo: &std::path::Path, args: &[&str]) {
    let status = std::process::Command::new("git")
        .args(args)
        .current_dir(repo)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("git starts");
    assert!(status.success(), "git {args:?} failed");
}

/// Commits a one-page app to a fresh repository and stores it as the
/// hostable code bundle `APP`; returns its fork hash.
fn ingest_app(vault: &Vault) -> [u8; 32] {
    let repo = tempfile::tempdir().expect("app repo");
    std::fs::write(repo.path().join("index.html"), "<h1>an app</h1>\n").expect("write app page");
    git(repo.path(), &["init"]);
    git(
        repo.path(),
        &["config", "user.email", "oneiron@example.test"],
    );
    git(repo.path(), &["config", "user.name", "Oneiron Test"]);
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-m", "app"]);
    let ingest = oneiron::codebase::RepoIngestConfig::new(repo.path(), ["index.html"])
        .expect("ingest config");
    let result = vault
        .ingest_local_repo_at_commit(APP, &ingest, "HEAD", TimeRange { start: 10, end: 10 }, 10)
        .expect("ingest the app bundle");
    let body = vault
        .get_code_artifact(&result.code_artifact_id)
        .expect("read code artifact")
        .expect("code artifact exists")
        .with_class(oneiron::code_artifact::CodeArtifactClass::Artifact);
    vault
        .put_code_artifact(
            &result.code_artifact_id,
            &body,
            TimeRange { start: 10, end: 10 },
            10,
        )
        .expect("mark the bundle hostable");
    result.snapshot.fork_hash
}

/// A rooted vault whose owner created `APP`'s backend pairing: its principal
/// and its first, zero-verb link.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    // The app lands before the vault is rooted, as the browser rows do.
    let fork_hash = ingest_app(&vault);
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    // The owner's Grant act is carried by this install's live machine
    // profile, as a serving start or `init` enrols it (FIX 4648).
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let (_owner, owner_proof) = embedded_owner(&vault).expect("authenticated embedded owner");
    let pairing = vault
        .create_artifact_backend_pairing(
            &owner_proof,
            &issuer,
            APP,
            &fork_hash,
            3_600,
            CommReach::Parent,
        )
        .expect("owner creates the app backend's pairing");
    let backend = EntityId::from_hex(&pairing.principal_ref).expect("backend principal id");
    Fixture {
        vault,
        _dir: dir,
        issuer,
        owner_proof,
        backend,
        first_link: pairing.link,
    }
}

/// The pairing Scope `oneiron token read` gives: every world, `core:read`.
fn read_slip_scope() -> Scope {
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from(["core:read".to_owned()]));
    scope
}

/// A Scope that names no verb, as the backend's own first link has.
fn no_verb_scope() -> Scope {
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::new());
    scope
}

/// The owner's link for `holder` as class `agent`, made from this install
/// (POST /v1/core/pairing/links's engine door).
fn owner_link(fixture: &Fixture, holder: EntityId, scope: Scope) -> oneiron::Result<PairingLink> {
    fixture.vault.issue_owner_pairing_link_from_surface(
        &fixture.issuer,
        &fixture.owner_proof,
        ActSurface::ThisInstall,
        scope,
        3_600,
        PairingPrincipal {
            holder_ref: Some(holder.to_hex()),
            actor_class: Some("agent".to_owned()),
            ..PairingPrincipal::default()
        },
    )
}

/// The owner's link as class `agent` that names no holder: whoever redeems
/// it names itself (POST /v1/core/pairing/links with no holder_ref).
fn open_owner_link(fixture: &Fixture, scope: Scope) -> PairingLink {
    fixture
        .vault
        .issue_owner_pairing_link_from_surface(
            &fixture.issuer,
            &fixture.owner_proof,
            ActSurface::ThisInstall,
            scope,
            3_600,
            PairingPrincipal {
                holder_ref: None,
                actor_class: Some("agent".to_owned()),
                ..PairingPrincipal::default()
            },
        )
        .expect("owner issues an open-holder agent link")
}

/// The host's link as class `agent` for `holder` with no owner proof, as
/// every agent paired before Grants was linked; it mints no Grant.
fn host_link(fixture: &Fixture, holder: EntityId, scope: Scope) -> PairingLink {
    fixture
        .vault
        .issue_pairing_link_for_principal(
            &fixture.issuer,
            scope,
            3_600,
            PairingPrincipal {
                holder_ref: Some(holder.to_hex()),
                actor_class: Some("agent".to_owned()),
                ..PairingPrincipal::default()
            },
        )
        .expect("host issues the agent link with no owner proof")
}

/// `holder` redeems `link` with the connection key `binding_seed` derives.
fn redeem(
    fixture: &Fixture,
    link: &PairingLink,
    holder: EntityId,
    binding_seed: u8,
) -> oneiron::Result<CapabilitySlip> {
    let holder_ref = holder.to_hex();
    let signing_key = SigningKey::from_bytes(&[binding_seed; 32]);
    let binding_key = signing_key.verifying_key().to_bytes();
    let transcript = oneiron::authority::pairing_binding_transcript_pinned(
        &link.code,
        &binding_key,
        &holder_ref,
        link.pin.as_ref(),
    )
    .expect("pairing binding transcript");
    fixture.vault.redeem_pairing_link(
        &fixture.issuer,
        &link.code,
        &holder_ref,
        binding_key,
        &signing_key.sign(&transcript).to_bytes(),
    )
}

/// The recording clock's reading now (Unix seconds), which a Grant's
/// `expires_at` must pass at its mint.
fn wall_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock reads after the epoch")
        .as_secs()
}

/// The owner mints the backend a read Grant as their own act, ending at
/// `expires_at` (`None`: no expiry).
fn mint_backend_read_grant(fixture: &Fixture, expires_at: Option<u64>) {
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    mint_agent_grant_as(
        &fixture.vault,
        &fixture.owner_proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent: fixture.backend,
            authority_scope,
            expires_at,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
        },
    )
    .expect("owner mints the app backend a read Grant");
}

/// The wire name of `result`'s error kind, `None` when it succeeded.
fn error_kind<T>(result: &oneiron::Result<T>) -> Option<serde_json::Value> {
    result
        .as_ref()
        .err()
        .map(|error| serde_json::to_value(error.kind()).expect("error kind wire name"))
}

/// The live owner-agent Grants of the registry that name `holder`.
fn grants_naming(vault: &Vault, holder: EntityId) -> Vec<ConsentRegistryRow> {
    vault
        .consent_registry(ConsentRegistryQuery::new(1_000, false))
        .expect("owner's consent registry")
        .rows
        .into_iter()
        .filter(|row| {
            row.agent_grant
                .as_ref()
                .is_some_and(|grant| grant.agent == holder)
        })
        .collect()
}

/// APP-BACKEND-LINK-GRANT = A: a link that names a verb for a backend no
/// Grant row names is refused with a typed error that names the door making
/// that row, and nothing is minted.
#[test]
fn verb_bearing_link_for_ungranted_backend_principal_is_refused() {
    let fixture = fixture();
    let backend = fixture.backend;
    let first = grants_naming(&fixture.vault, backend);
    assert!(
        first.is_empty(),
        "actor=app backend {backend:?}; expected its first, zero-verb link to mint no Grant; seen grants={first:?}"
    );

    let refused = owner_link(&fixture, backend, read_slip_scope());
    let error = refused.as_ref().err();
    let kind = error.map(|error| serde_json::to_value(error.kind()).expect("error kind wire name"));
    assert_eq!(
        kind,
        Some(json!("app_backend_grant_required")),
        "actor=app backend {backend:?}; expected the owner's core:read link refused as app_backend_grant_required; seen issued={}, error={error:?}",
        refused.is_ok()
    );
    let message = error.map(ToString::to_string).unwrap_or_default();
    assert!(
        message.contains("vault.agents.grants.mint"),
        "actor=app backend {backend:?}; expected the refusal to name vault.agents.grants.mint; seen message={message:?}"
    );
    let after = grants_naming(&fixture.vault, backend);
    assert!(
        after.is_empty(),
        "actor=app backend {backend:?}; expected no Grant after the refused link; seen grants={after:?}"
    );
}

/// Default none: a second owner link that names no verb issues, as the first
/// does, and mints no read Grant for the backend.
#[test]
fn zero_verb_owner_link_for_backend_principal_mints_no_grant() {
    let fixture = fixture();
    let backend = fixture.backend;
    let issued = owner_link(&fixture, backend, no_verb_scope());
    assert!(
        issued.is_ok(),
        "actor=app backend {backend:?}; expected the owner's zero-verb link to issue; seen error={:?}",
        issued.as_ref().err()
    );
    let grants = grants_naming(&fixture.vault, backend);
    assert!(
        grants.is_empty(),
        "actor=app backend {backend:?}; expected the zero-verb link to mint no Grant; seen grants={grants:?}"
    );
}

/// Once the owner mints the backend's Grant row as its own act, a link that
/// names verbs issues, and the link mints no second Grant.
#[test]
fn granted_backend_principal_takes_a_verb_bearing_link() {
    let fixture = fixture();
    let backend = fixture.backend;
    mint_backend_read_grant(&fixture, None);
    let issued = owner_link(&fixture, backend, read_slip_scope());
    assert!(
        issued.is_ok(),
        "actor=app backend {backend:?}; expected the owner's core:read link to issue once a Grant row names it; seen error={:?}",
        issued.as_ref().err()
    );
    let grants = grants_naming(&fixture.vault, backend);
    assert_eq!(
        grants.len(),
        1,
        "actor=app backend {backend:?}; expected the owner's one Grant and no default Grant beside it; seen grants={grants:?}"
    );
}

/// FIX [APP-BACKEND-LINK-EXPIRED-GRANT-COUNTS]: a Grant whose expiry the
/// authority clock has reached names no backend, so a link that names verbs
/// for a backend whose only Grant expired is refused as for one never
/// granted. Before the expiry the same link issues.
#[test]
fn verb_bearing_link_for_backend_whose_grant_expired_is_refused() {
    let fixture = fixture();
    let backend = fixture.backend;
    let expires_at = wall_secs() + GRANT_LIFETIME_SECS;
    mint_backend_read_grant(&fixture, Some(expires_at));
    let before = owner_link(&fixture, backend, read_slip_scope());
    assert!(
        before.is_ok(),
        "actor=app backend {backend:?}; expected the owner's core:read link to issue while its Grant stands (expires_at={expires_at}); seen error={:?}",
        before.as_ref().err()
    );

    fixture
        .vault
        .advance_authority_clock_for_test(expires_at)
        .expect("the authority clock reaches the Grant's expiry");
    let after = owner_link(&fixture, backend, read_slip_scope());
    assert_eq!(
        error_kind(&after),
        Some(json!("app_backend_grant_required")),
        "actor=app backend {backend:?}; expected the owner's core:read link refused as app_backend_grant_required once its only Grant expired (expires_at={expires_at}); seen issued={}, error={:?}",
        after.is_ok(),
        after.as_ref().err()
    );
}

/// The expiry is judged again at redemption: a link that names verbs, issued
/// while the backend's Grant stood, is refused when the backend redeems it
/// after that Grant expired.
#[test]
fn verb_link_issued_under_a_grant_is_refused_at_redemption_after_it_expired() {
    let fixture = fixture();
    let backend = fixture.backend;
    let expires_at = wall_secs() + GRANT_LIFETIME_SECS;
    mint_backend_read_grant(&fixture, Some(expires_at));
    let link = owner_link(&fixture, backend, read_slip_scope())
        .expect("owner issues the backend's core:read link while its Grant stands");

    fixture
        .vault
        .advance_authority_clock_for_test(expires_at)
        .expect("the authority clock reaches the Grant's expiry");
    let redeemed = redeem(&fixture, &link, backend, 0x56);
    assert_eq!(
        error_kind(&redeemed),
        Some(json!("app_backend_grant_required")),
        "actor=app backend {backend:?}; expected its redemption of the owner's core:read link refused as app_backend_grant_required once its only Grant expired (expires_at={expires_at}); seen redeemed={}, error={:?}",
        redeemed.is_ok(),
        redeemed.as_ref().err()
    );
}

/// The redemption refusal waits on the expiry: a backend whose Grant still
/// stands redeems the owner's link that names verbs.
#[test]
fn granted_backend_redeems_a_verb_link_while_its_grant_stands() {
    let fixture = fixture();
    let backend = fixture.backend;
    let expires_at = wall_secs() + GRANT_LIFETIME_SECS;
    mint_backend_read_grant(&fixture, Some(expires_at));
    let link = owner_link(&fixture, backend, read_slip_scope())
        .expect("owner issues the backend's core:read link while its Grant stands");
    let redeemed = redeem(&fixture, &link, backend, 0x57);
    assert!(
        redeemed.is_ok(),
        "actor=app backend {backend:?}; expected it to redeem the owner's core:read link while its Grant stands (expires_at={expires_at}); seen error={:?}",
        redeemed.as_ref().err()
    );
}

/// The refusal is the backend's alone: an ordinary named agent's link that
/// names verbs still mints its default read Grant (PAIR-GRANT-DESIGN Q3/Q4).
#[test]
fn named_agent_verb_link_still_mints_its_default_grant() {
    let fixture = fixture();
    let agent = fixture
        .vault
        .ensure_agent_principal("backend_grant_control_agent")
        .expect("named agent principal");
    let issued = owner_link(&fixture, agent, read_slip_scope());
    assert!(
        issued.is_ok(),
        "actor=named agent {agent:?}; expected the owner's core:read link to issue; seen error={:?}",
        issued.as_ref().err()
    );
    let grants = grants_naming(&fixture.vault, agent);
    assert_eq!(
        grants.len(),
        1,
        "actor=named agent {agent:?}; expected the link to mint its default read Grant; seen grants={grants:?}"
    );
}

/// APP-BACKEND-LINK-GRANT = A at redemption: an owner link that names verbs
/// and leaves its holder open is refused when the backend redeems it, so
/// the backend gains no verb-bearing slip without a Grant row. The
/// backend's own zero-verb first link still redeems.
#[test]
fn open_holder_verb_link_redeemed_as_ungranted_backend_is_refused() {
    let fixture = fixture();
    let backend = fixture.backend;
    let first = redeem(&fixture, &fixture.first_link, backend, 0x51);
    assert!(
        first.is_ok(),
        "actor=app backend {backend:?}; expected it to redeem its own zero-verb first link; seen error={:?}",
        first.as_ref().err()
    );

    let link = open_owner_link(&fixture, read_slip_scope());
    let redeemed = redeem(&fixture, &link, backend, 0x52);
    let error = redeemed.as_ref().err();
    let kind = error.map(|error| serde_json::to_value(error.kind()).expect("error kind wire name"));
    assert_eq!(
        kind,
        Some(json!("app_backend_grant_required")),
        "actor=app backend {backend:?}; expected its redemption of the owner's open core:read link refused as app_backend_grant_required; seen redeemed={}, error={error:?}",
        redeemed.is_ok()
    );
    let grants = grants_naming(&fixture.vault, backend);
    assert!(
        grants.is_empty(),
        "actor=app backend {backend:?}; expected no Grant after the refused redemption; seen grants={grants:?}"
    );
}

/// The redemption refusal is the backend's alone: an ordinary named agent
/// redeems the owner's open link that names verbs.
#[test]
fn open_holder_verb_link_redeemed_by_named_agent_still_pairs() {
    let fixture = fixture();
    let agent = fixture
        .vault
        .ensure_agent_principal("backend_grant_open_link_agent")
        .expect("named agent principal");
    let link = open_owner_link(&fixture, read_slip_scope());
    let redeemed = redeem(&fixture, &link, agent, 0x53);
    assert!(
        redeemed.is_ok(),
        "actor=named agent {agent:?}; expected it to redeem the owner's open core:read link; seen error={:?}",
        redeemed.as_ref().err()
    );
}

/// Default none at the serve start: a backend holding a live read slip from
/// a host link (the state a backend paired that way before this change is
/// in) gets no default read Grant from the backfill, while an ordinary
/// named agent in the same state still gets its one (GRANTLESS-SHAPE Q1).
/// The backend's PERSON is written after its slip, with the backend name
/// form, because a link that names verbs for a recognized backend is now
/// refused at issue and at redemption.
#[test]
fn serve_start_backfill_mints_no_grant_for_a_backend_principal() {
    let fixture = fixture();
    let backend_name = "artifact-backend:backfill-probe";
    let backend = EntityId::derive(AGENT_PRINCIPAL, &[backend_name.as_bytes()])
        .expect("derive the backend principal id");
    let backend_link = host_link(&fixture, backend, read_slip_scope());
    redeem(&fixture, &backend_link, backend, 0x54).expect("backend redeems its host link");
    let person = fixture
        .vault
        .ensure_agent_principal(backend_name)
        .expect("backend principal PERSON");
    assert_eq!(person, backend, "the backend name derives its principal id");

    let agent = fixture
        .vault
        .ensure_agent_principal("backend_grant_backfill_agent")
        .expect("named agent principal");
    let agent_link = host_link(&fixture, agent, read_slip_scope());
    redeem(&fixture, &agent_link, agent, 0x55).expect("named agent redeems its host link");

    fixture
        .vault
        .backfill_default_agent_grants(&fixture.owner_proof)
        .expect("the serve-start backfill runs");
    let backend_grants = grants_naming(&fixture.vault, backend);
    assert!(
        backend_grants.is_empty(),
        "actor=app backend {backend:?}; expected the backfill to mint it no Grant; seen grants={backend_grants:?}"
    );
    let agent_grants = grants_naming(&fixture.vault, agent);
    assert_eq!(
        agent_grants.len(),
        1,
        "actor=named agent {agent:?}; expected the backfill to mint its default read Grant; seen grants={agent_grants:?}"
    );
}
