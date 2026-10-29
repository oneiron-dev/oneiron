//! `device enrol`: enrols this stopped vault's machine with its home, from
//! the owner's machine pairing link ([`crate::device_sync::enrol`]). Output
//! is JSON on stdout, never the credential: with the request code this
//! machine shows and the enrolment request it sent, which the owner's kit
//! anchoring takes (FIX 4956).

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
    let files = crate::device_sync::EnrolmentFiles::for_vault(&config.keystore, &vault)?;
    let mut link = String::new();
    std::io::stdin().read_line(&mut link)?;
    anyhow::ensure!(
        !link.trim().is_empty(),
        "pass the pairing link on stdin: `oneiron token pair --machine yours` prints it on the \
         home"
    );
    let record = crate::device_sync::enrol(&vault, &files, &link)?;
    let (request_code, enrolment) = shown_request(&vault)?;
    super::owner::emit(&Enrolled {
        home_machine: record.home_machine,
        home_node_id: record.home_node_id,
        home_url: record.home_url,
        checkpoint_pinned: record.authority_checkpoint_pin.is_some(),
        record: files.record.display().to_string(),
        credential_file: files.credential.display().to_string(),
        request_code,
        enrolment,
    })
}

/// This machine's enrolment request for its vault, the one `enrol` sent, and
/// the code it shows for it (`RequestCode::to_text`).
fn shown_request(vault: &oneiron::Vault) -> anyhow::Result<(String, serde_json::Value)> {
    use crate::owner::vault_key::hex;
    let vault_id = vault
        .authority_fold()?
        .vault_id
        .ok_or_else(|| anyhow::anyhow!("this vault has no authority root yet"))?;
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
