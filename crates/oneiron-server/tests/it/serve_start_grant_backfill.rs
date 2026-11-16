//! The shipped `oneiron serve` mints the default read Grant of each named
//! agent paired before Grants, once per self-hosted vault (FIX
//! GRANTLESS-SERVE-START-SERVER-CASE). The start calls
//! `owner::agent_grants::backfill_default_grants_at_start` right after
//! `build_server` (`commands/serve.rs`), once this install's profile carries
//! the owner's acts; `crates/oneiron/tests/agent_grant_backfill.rs` holds the
//! core cases. Here the agent pairs on the stopped vault through the host's
//! link alone, as every agent paired before Grants did, and the vault is read
//! back stopped after each start.

use std::collections::BTreeSet;
use std::path::Path;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{HostSlipIssuer, PairingPrincipal, pairing_binding_transcript_pinned};
use oneiron::consent::{ConsentRegistryQuery, ConsentRegistryRow};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::{EntityId, HostingPrivacyPosture, Vault};
use oneiron_server::config::ServeArgs;
use oneiron_server::config::merge::resolve_serve_config;

use super::reopen_after_restart::{oneiron, serve, sigterm, stdout};

const SLIP_LIFETIME_SECS: u64 = 3_600;

/// The stopped vault `config` names, opened as `oneiron token read` opens
/// it, with this install's keystore installed, so the host issuer `oneiron
/// token bootstrap` rooted the vault with loads.
fn open_stopped(config: &Path) -> (Vault, HostSlipIssuer) {
    let config = resolve_serve_config(&ServeArgs {
        config: Some(config.to_path_buf()),
        ..ServeArgs::default()
    })
    .expect("the serve config `oneiron init` wrote");
    let vault =
        Vault::open_owned(&config.vault_path, config.vault_config()).expect("the stopped vault");
    assert!(
        config.keystore.install_on(&vault, &config.vault_path),
        "this install's keystore, as `oneiron serve` installs it"
    );
    let issuer = vault
        .load_host_slip_issuer()
        .expect("the host issuer `oneiron token bootstrap` rooted the vault with");
    vault
        .ensure_host_root_slip(&issuer)
        .expect("the vault's host root slip, as `oneiron token read` ensures it");
    (vault, issuer)
}

/// The pairing Scope `oneiron token read` gives: every world, `core:read`.
fn read_slip_scope() -> Scope {
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from(["core:read".to_owned()]));
    scope
}

/// The Scope of the default read Grant for a [`read_slip_scope`] slip: verbs
/// `read`, the slip's other axes.
fn default_grant_scope() -> Scope {
    let mut scope = read_slip_scope();
    scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    scope
}

/// `name`'s named-agent principal pairs as class `agent` on a link the host
/// issues with no owner proof, as every agent paired before Grants did, and
/// redeems it with the key `binding_seed` derives. No Grant is minted.
fn pair_before_grants(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    name: &str,
    binding_seed: u8,
) -> EntityId {
    let holder = vault
        .ensure_agent_principal(name)
        .expect("named agent principal");
    let holder_ref = holder.to_hex();
    let link = vault
        .issue_pairing_link_for_principal(
            issuer,
            read_slip_scope(),
            SLIP_LIFETIME_SECS,
            PairingPrincipal {
                holder_ref: Some(holder_ref.clone()),
                actor_class: Some("agent".to_owned()),
                ..PairingPrincipal::default()
            },
        )
        .expect("the host issues the agent's pairing link with no owner proof");
    let signing_key = SigningKey::from_bytes(&[binding_seed; 32]);
    let binding_key = signing_key.verifying_key().to_bytes();
    let transcript =
        pairing_binding_transcript_pinned(&link.code, &binding_key, &holder_ref, link.pin.as_ref())
            .expect("agent pairing transcript");
    vault
        .redeem_pairing_link(
            issuer,
            &link.code,
            &holder_ref,
            binding_key,
            &signing_key.sign(&transcript).to_bytes(),
        )
        .expect("the agent redeems its pairing link");
    holder
}

/// The owner-agent Grants of the registry that name `holder`.
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

fn grant_refs(rows: &[ConsentRegistryRow]) -> BTreeSet<String> {
    rows.iter().map(|row| row.grant_ref.clone()).collect()
}

fn read_log(log: &Path) -> String {
    std::fs::read_to_string(log).unwrap_or_default()
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("a free loopback port")
        .local_addr()
        .expect("bound loopback address")
        .port()
}

/// owen pairs on the host's link before the vault is first served: no Grant
/// names him. The first `oneiron serve` mints his one default read Grant
/// (verbs `read`, the slip's other axes). yuki then pairs the same way on the
/// stopped vault, and the second start mints nothing: the first start set the
/// vault's completion marker, so yuki stays grantless and owen keeps the one
/// Grant he had.
#[test]
fn serve_start_mints_the_default_grant_of_an_agent_paired_before_grants_once() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let vault_path = dir.path().join("vault");
    let config = dir.path().join("oneiron.toml");
    stdout(oneiron(
        &[
            "init",
            vault_path.to_str().expect("UTF-8 vault path"),
            "--embedder",
            "none",
        ],
        &config,
    ));
    let port = free_port();
    let origin = format!("http://127.0.0.1:{port}");
    stdout(oneiron(&["token", "bootstrap", "--url", &origin], &config));
    let owen = {
        let (vault, issuer) = open_stopped(&config);
        let owen = pair_before_grants(&vault, &issuer, "owen", 0x71);
        let before = grants_naming(&vault, owen);
        assert!(
            before.is_empty(),
            "actor=named agent {owen:?}; expected no Grant before the first serve start (paired on the host's link); seen grants={before:?}"
        );
        owen
    };

    let first_log = dir.path().join("serve-1.log");
    sigterm(serve(&config, port, &first_log));
    let (first_grants, yuki) = {
        let (vault, issuer) = open_stopped(&config);
        let rows = grants_naming(&vault, owen);
        assert_eq!(
            rows.len(),
            1,
            "actor=named agent {owen:?}; expected the first serve start to mint one default Grant naming him; seen grants={rows:?}; serve log:\n{}",
            read_log(&first_log)
        );
        assert_eq!(
            rows[0].scope.as_ref(),
            Some(&default_grant_scope()),
            "actor=named agent {owen:?}; expected the default Grant at the slip's axes with verbs [read]; seen row={:?}",
            rows[0]
        );
        let yuki = pair_before_grants(&vault, &issuer, "yuki", 0x72);
        (grant_refs(&rows), yuki)
    };

    let second_log = dir.path().join("serve-2.log");
    sigterm(serve(&config, port, &second_log));
    let (vault, _issuer) = open_stopped(&config);
    let owen_rows = grants_naming(&vault, owen);
    assert_eq!(
        grant_refs(&owen_rows),
        first_grants,
        "actor=named agent {owen:?}; expected the second serve start to leave his one Grant as the first minted it; seen grants={owen_rows:?}"
    );
    let yuki_rows = grants_naming(&vault, yuki);
    assert!(
        yuki_rows.is_empty(),
        "actor=named agent {yuki:?}; expected the second serve start to mint nothing (the first set the completion marker); seen grants={yuki_rows:?}; serve log:\n{}",
        read_log(&second_log)
    );
}

/// A managed vault (an operator hosts it and can read it) runs no backfill at
/// its serve start: owen pairs on the host's link as above, and the start
/// mints him nothing. A guard case: the server's posture check, `host_owner`
/// and the engine's own backfill each refuse a vault that is not self-hosted.
#[test]
fn serve_start_of_a_managed_vault_mints_no_default_grant() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let vault_path = dir.path().join("vault");
    let config = dir.path().join("oneiron.toml");
    // `oneiron init` keeps the keys a config file already holds.
    std::fs::write(
        &config,
        "privacy_posture = \"managed\"\nhosted_kms_key_ref = \"kms://example/serve-start-backfill\"\n",
    )
    .expect("managed posture in the config file");
    stdout(oneiron(
        &[
            "init",
            vault_path.to_str().expect("UTF-8 vault path"),
            "--embedder",
            "none",
        ],
        &config,
    ));
    let port = free_port();
    let origin = format!("http://127.0.0.1:{port}");
    stdout(oneiron(&["token", "bootstrap", "--url", &origin], &config));
    let owen = {
        let (vault, issuer) = open_stopped(&config);
        assert_eq!(
            vault.privacy_posture(),
            HostingPrivacyPosture::Hosted,
            "expected the vault to open managed, as its config file says"
        );
        let owen = pair_before_grants(&vault, &issuer, "owen", 0x73);
        let before = grants_naming(&vault, owen);
        assert!(
            before.is_empty(),
            "actor=named agent {owen:?}; expected no Grant before the serve start (paired on the host's link); seen grants={before:?}"
        );
        owen
    };

    let log = dir.path().join("serve-managed.log");
    sigterm(serve(&config, port, &log));
    let (vault, _issuer) = open_stopped(&config);
    let rows = grants_naming(&vault, owen);
    assert!(
        rows.is_empty(),
        "actor=named agent {owen:?}; expected the serve start of a managed vault to mint nothing; seen grants={rows:?}; serve log:\n{}",
        read_log(&log)
    );
}
