//! An enrolled device vault for the L7-47 mesh peer path tests.
//!
//! The macOS app starts device sync over a vault this install already holds a
//! machine identity in, with an enrolment that dials its home. This door builds
//! that pair under a directory the test owns: a rooted device vault with this
//! install profiled in it, an enrolment record and credential beside a
//! test-only key directory, and the serve config that resolves them.

use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use ed25519_dalek::Signer;

/// Builds the vault and config the macOS app holds when it starts device sync (L7-47).
///
/// The vault opens under `dir`, roots under the test host, and profiles this install as an
/// unanswered serving machine. The enrolment names a fresh home machine, a home node id that is
/// not this machine's own sync node id, and a home URL on a loopback port no one listens on, with
/// no mesh address and no checkpoint pin. The paired credential is minted by this vault's own host
/// root through the pairing doors; the link never presents it, since the home is dead, and its
/// client configuration only parses it. The serve config carries the vault path and a keystore
/// directory under `dir`, and no `[device_sync]` section, so the dial resolves the enrolled home.
///
/// # Errors
///
/// What opening, rooting, profiling, pairing, or writing the enrolment returns.
pub fn enrolled_device(
    dir: &Path,
) -> anyhow::Result<(Arc<oneiron::Vault>, crate::config::ServeConfig)> {
    let vault_dir = dir.join("vault");
    let vault = oneiron::Vault::open(&vault_dir, oneiron::VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault.ensure_serving_install_profile(&issuer, oneiron::authority::MachineRole::Unanswered)?;
    let local = vault
        .local_machine()?
        .ok_or_else(|| anyhow::anyhow!("the profiled vault names no local machine"))?
        .id;
    let mut home = oneiron::EntityId::now();
    while home == local {
        home = oneiron::EntityId::now();
    }
    let own = oneiron::DreamerRunnerStore::new(&vault)
        .local_home_node_candidate(true, true, false)?
        .node_id;
    let mut home_node = own.wrapping_add(1);
    if home_node == 0 {
        home_node = 1;
    }
    let port = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    let home_url = format!("ws://127.0.0.1:{port}/ws");
    let (token, seed) = paired_credential(&vault, &issuer)?;
    let slip = token.strip_prefix("v2.slip.").unwrap_or(&token);
    let credential = format!("v2.cred.{slip}.{seed}");
    let mut config = crate::config::ServeConfig {
        vault_path: vault_dir,
        ..crate::config::ServeConfig::default()
    };
    config.keystore.dir = Some(dir.join("keys"));
    let files = crate::device_sync::EnrolmentFiles::for_vault(&config.keystore, &vault)?;
    if let Some(parent) = files.record.parent() {
        create_private_dir(parent)?;
    }
    write_new(&files.credential, credential.as_bytes())?;
    let record = serde_json::json!({
        "home_machine": home.to_hex(),
        "home_node_id": home_node,
        "home_url": home_url,
    });
    if let Err(error) = write_new(&files.record, &serde_json::to_vec_pretty(&record)?) {
        let _ = std::fs::remove_file(&files.credential);
        return Err(error);
    }
    Ok((Arc::new(vault), config))
}

/// Mints the paired owner-grade credential the enrolment stores (L7-47).
///
/// The holder is a fresh person, paired through this vault's own host root with the top scope.
/// Returns the slip token and the hex seed of the binding key it was redeemed to.
fn paired_credential(
    vault: &oneiron::Vault,
    issuer: &oneiron::authority::HostSlipIssuer,
) -> anyhow::Result<(String, String)> {
    let holder = oneiron::EntityId::now();
    vault.put_entity(
        &holder,
        oneiron::registry::ENTITY_TYPE_PERSON,
        oneiron::TimeRange { start: 1, end: 1 },
        1,
        b"l7-47 device holder",
    )?;
    let holder = holder.to_hex();
    let link = vault.issue_pairing_link_for_principal(
        issuer,
        oneiron::federation::Scope::top(),
        3600,
        oneiron::authority::PairingPrincipal {
            holder_ref: Some(holder.clone()),
            actor_class: Some(oneiron::EdgeActorClass::Human.gate_actor_class().to_owned()),
            org_ref: None,
            write_facet: None,
            comm: None,
        },
    )?;
    let key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let binding = key.verifying_key().to_bytes();
    let transcript = oneiron::authority::pairing_binding_transcript(&link.code, &binding, &holder)?;
    let signature = key.sign(&transcript);
    let slip =
        vault.redeem_pairing_link(issuer, &link.code, &holder, binding, &signature.to_bytes())?;
    Ok((slip.to_token()?, hex(key.as_bytes())))
}

/// Creates `dir` and its parents; a new `dir` only its owner may enter (L7-47).
fn create_private_dir(dir: &Path) -> anyhow::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder
        .create(dir)
        .map_err(|error| anyhow::anyhow!("create {}: {error}", dir.display()))
}

/// Writes `bytes` and a newline to a new owner-only file, synced to disk (L7-47).
fn write_new(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut file = crate::commands::credential_file::create(path)?;
    let mut owned = bytes.to_vec();
    owned.push(b'\n');
    if let Err(error) = file.write_all(&owned).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(path);
        anyhow::bail!("write {}: {error}", path.display());
    }
    Ok(())
}

/// Lowercase hex of `bytes` (L7-47).
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
