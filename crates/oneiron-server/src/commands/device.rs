//! `device enrol`: enrols this stopped vault's machine with its home, from
//! the owner's machine pairing link ([`crate::device_sync::enrol`]). Output
//! is JSON on stdout, never the credential.

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
    super::owner::emit(&Enrolled {
        home_machine: record.home_machine,
        home_node_id: record.home_node_id,
        home_url: record.home_url,
        checkpoint_pinned: record.authority_checkpoint_pin.is_some(),
        record: files.record.display().to_string(),
        credential_file: files.credential.display().to_string(),
    })
}
