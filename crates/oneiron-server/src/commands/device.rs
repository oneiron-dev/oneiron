//! `device enrol`: enrols this stopped vault's machine with its home, from
//! the owner's machine pairing link ([`crate::device_sync::enrol`]). Output
//! is JSON on stdout, never the credential: with the request code this
//! machine shows and the enrolment request it sent, which the owner's kit
//! anchoring takes (FIX 4956).
//!
//! A vault with no authority root joins its home from empty (FIX 3375): the
//! pin the owner's link keeps is read from the home and verified
//! ([`crate::device_sync::join`]), the empty store is set aside beside the
//! vault, and a fresh one is created under the home's storage id before the
//! machine enrols for the home's genesis.

use base64::Engine as _;
use serde::Serialize;

use crate::cli::DeviceEnrolArgs;
use crate::config::{ServeArgs, resolve_serve_config};

/// What `device enrol` stored.
#[derive(Serialize)]
struct Enrolled {
    home_machine: String,
    home_node_id: u64,
    home_url: String,
    /// Whether the link pinned an authority checkpoint, which the first
    /// connection adopts.
    checkpoint_pinned: bool,
    /// Whether the home paired again a machine it already held, credential
    /// only (FIX 8636): its identity and class stand as they were.
    re_paired: bool,
    /// Whether the home named its mesh address (FIX 3374): serve dials it
    /// there first, and at `home_url` when that fails.
    home_mesh: bool,
    /// The home's receipt of this machine's mesh binding: the binding it
    /// made, or why it made none.
    #[serde(skip_serializing_if = "Option::is_none")]
    mesh_bind: Option<serde_json::Value>,
    /// Where the empty store this vault joined from was set aside (FIX 3375).
    #[serde(skip_serializing_if = "Option::is_none")]
    empty_store_set_aside: Option<String>,
    record: String,
    credential_file: String,
    /// The code this machine shows the owner, 26 characters: he types it
    /// where his kit anchors this machine (`oneiron recovery-kit anchor
    /// --code`).
    request_code: String,
    /// The enrolment request it sent, as that anchoring takes it
    /// (`--enrolment`).
    enrolment: serde_json::Value,
}

/// Opens the stopped vault, reads the link from stdin and enrols.
pub fn device_enrol(args: DeviceEnrolArgs) -> anyhow::Result<()> {
    let config = resolve_serve_config(&ServeArgs {
        config: args.config,
        vault_path: Some(args.path),
        ..ServeArgs::default()
    })?;
    let vault = super::owner::open_stopped_vault_with(
        &config,
        super::owner::vault_config(&config),
        "then enrol again",
    )?;
    let mut link = String::new();
    std::io::stdin().read_line(&mut link)?;
    anyhow::ensure!(
        !link.trim().is_empty(),
        "pass the pairing link on stdin: `oneiron token pair --machine yours` prints it on the \
         home"
    );
    // A vault with no authority root and no rows of its own joins from
    // empty; any other enrols as the copy of its home's vault it is.
    if vault.authority_fold()?.vault_id.is_some() {
        let (files, shown, enrolled) = enrol_into(&config, &vault, &link, None)?;
        return emit(files, shown, enrolled, None);
    }
    crate::device_sync::join::ensure_joinable(&vault)?;
    let join = crate::device_sync::join::fetch_join_pin(&link)?;
    let path = config.vault_path.clone();
    let set_aside = set_aside_path(&path)?;
    drop(vault);
    std::fs::rename(&path, &set_aside).map_err(|error| {
        anyhow::anyhow!(
            "set the empty vault {} aside as {}: {error}",
            path.display(),
            set_aside.display()
        )
    })?;
    // Any failure from here on puts the empty store back where it was: a
    // join that does not finish leaves the vault as `device enrol` found it.
    // The fresh store's handle closes with the closure, before any restore.
    let joined = open_joining_store(&config, &join)
        .and_then(|vault| enrol_into(&config, &vault, &link, Some(&join)));
    match joined {
        Ok((files, shown, enrolled)) => emit(files, shown, enrolled, Some(&set_aside)),
        Err(error) => match restore_empty_store(&path, &set_aside) {
            Ok(()) => Err(error),
            Err(restore) => Err(error.context(format!(
                "and the empty vault set aside as {} could not be put back at {}: {restore:#}",
                set_aside.display(),
                path.display()
            ))),
        },
    }
}

/// What one enrolment wrote and showed: its files, the request code and
/// enrolment request it showed, and the enrolment.
type EnrolledInto = (
    crate::device_sync::EnrolmentFiles,
    (String, serde_json::Value),
    crate::device_sync::Enrolled,
);

/// Enrols `vault`'s machine from `link`, as the copy of its home's vault, or
/// as a vault joining from empty under `join`.
fn enrol_into(
    config: &crate::config::ServeConfig,
    vault: &oneiron::Vault,
    link: &str,
    join: Option<&crate::device_sync::join::JoinPin>,
) -> anyhow::Result<EnrolledInto> {
    let files = crate::device_sync::EnrolmentFiles::for_vault(&config.keystore, vault)?;
    // Read before the enrolment, as it reads it: nothing that can fail runs
    // after the link is spent.
    let shown = shown_request(vault, join)?;
    let enrolled = crate::device_sync::enrol(vault, &files, link, join)?;
    Ok((files, shown, enrolled))
}

/// Prints what an enrolment stored.
fn emit(
    files: crate::device_sync::EnrolmentFiles,
    (request_code, enrolment): (String, serde_json::Value),
    enrolled: crate::device_sync::Enrolled,
    set_aside: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    let record = enrolled.record;
    super::owner::emit(&Enrolled {
        home_machine: record.home_machine,
        home_node_id: record.home_node_id,
        home_url: record.home_url,
        checkpoint_pinned: record.authority_checkpoint_pin.is_some(),
        re_paired: enrolled.re_paired,
        home_mesh: record.home_mesh.is_some(),
        mesh_bind: enrolled.mesh_bind,
        empty_store_set_aside: set_aside.map(|path| path.display().to_string()),
        record: files.record.display().to_string(),
        credential_file: files.credential.display().to_string(),
        request_code,
        enrolment,
    })
}

/// Where the empty store at `path` is set aside: beside it, named for when.
fn set_aside_path(path: &std::path::Path) -> anyhow::Result<std::path::PathBuf> {
    let name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("vault path {} names no directory", path.display()))?;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let set_aside = path.with_file_name(format!("{}.empty-{stamp}", name.to_string_lossy()));
    anyhow::ensure!(
        !set_aside.exists(),
        "{} already exists; move it and enrol again",
        set_aside.display()
    );
    Ok(set_aside)
}

/// Creates the fresh store at the vault path under the home's storage id the
/// verified `join` pin names (`OpenOptions::adopt_storage_id`, L01 04:55).
fn open_joining_store(
    config: &crate::config::ServeConfig,
    join: &crate::device_sync::join::JoinPin,
) -> anyhow::Result<oneiron::Vault> {
    use crate::device_sync::join::JoinRefusal;

    let path = &config.vault_path;
    let storage_id = oneiron::VaultStorageId::from_verified_pin(&join.pin);
    let vault = oneiron::Vault::open_owned_with(
        path,
        super::owner::vault_config(config),
        oneiron::OpenOptions::default().adopt_storage_id(storage_id),
    )
    .map_err(|error| anyhow::anyhow!("create vault {}: {error}", path.display()))?;
    config.keystore.install_on(&vault, path);
    vault.ensure_serving_install_profile_at_start(
        super::owner::configured_host_issuer(config, &vault, false).as_ref(),
        "device enrol",
    );
    if vault.vault_key_vault_id() != *storage_id.as_bytes() {
        return Err(JoinRefusal::StorageId.into());
    }
    Ok(vault)
}

/// Puts the empty store set aside back at `path` after a join that did not
/// finish. What a failed join left at `path` is only the fresh store this
/// run created, and goes first.
fn restore_empty_store(path: &std::path::Path, set_aside: &std::path::Path) -> anyhow::Result<()> {
    if path.exists() {
        std::fs::remove_dir_all(path)
            .map_err(|error| anyhow::anyhow!("remove {}: {error}", path.display()))?;
    }
    std::fs::rename(set_aside, path).map_err(|error| {
        anyhow::anyhow!("move {} back to {}: {error}", set_aside.display(), path.display())
    })
}

/// This machine's enrolment request for its vault, the one `enrol` sends
/// (the same request: its proof is a deterministic signature), and the code
/// it shows for it (`RequestCode::to_text`).
fn shown_request(
    vault: &oneiron::Vault,
    join: Option<&crate::device_sync::join::JoinPin>,
) -> anyhow::Result<(String, serde_json::Value)> {
    use crate::owner::vault_key::hex;
    let vault_id = crate::device_sync::enrolment_vault_id(vault, join)?;
    let request =
        vault.machine_enrolment_request(vault_id, vault.machine_encryption_key(vault_id)?)?;
    let enrolment = serde_json::json!({
        "vault_id": hex(&request.vault_id),
        "machine": request.machine.to_hex(),
        "machine_key": hex(&request.machine_key),
        "device_class": request.device_class,
        "encryption_suite": request.encryption_key.suite,
        "encryption_key": base64::engine::general_purpose::STANDARD
            .encode(&request.encryption_key.key),
        "machine_proof": hex(&request.machine_proof),
    });
    Ok((request.code().to_text(), enrolment))
}
