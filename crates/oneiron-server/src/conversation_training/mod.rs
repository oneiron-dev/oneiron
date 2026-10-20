//! The publisher training outbox (OF-420 A1, "Learn from my conversations"):
//! the worker that writes this vault's training offers and withdrawals into
//! `--publisher-training-outbox-dir` and reads the intake's receipts back
//! (`oneiron_vault_contract::conversation_training`).
//!
//! The flag is argv only in both serve paths, with no default: plain serve
//! takes it from the operator, managed serve from the supervisor (which
//! gives `<vault>/training-outbox`), and a managed settings file that names
//! it is refused as the supervisor's. Without it no worker runs, and no
//! conversation text goes toward training.
//!
//! The engine decides everything: which words count, the release, the
//! reconciliation, the seal and the signature. This module only supplies
//! the in-vault filter, the directory, and the hooks that decide whether
//! offers may be written at all: the intake's sealing key (CALLS-5) and its
//! receipt key. Without them no offer is written; withdrawals still are.
//!
//! A self-hosted vault's offers leave through the anonymous training window
//! (TL-6), which takes no account, so they are written only while its
//! self-host shipper is on (`--publisher-training-self-host-shipper`, off by
//! default, plain serve only). The shipper fetches the intake's public
//! descriptor (`descriptor`) and installs the same two key files a managed
//! vault's supervisor pushes, so one reader serves both. Its own loop
//! (`shipper`) then carries the released offers and the withdrawals to the
//! intake and applies its signed receipts. Managed serve never starts it.

mod descriptor;
mod http;
mod outbox;
mod retry;
mod shipper;
mod worker;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use oneiron::feedback::{IntakeReceiptKey, IntakeRecipient, TrainingUnavailable};
use oneiron_vault_contract::conversation_training::{
    INTAKE_RECEIPT_KEY_FILE, INTAKE_RECIPIENT_FILE,
};

use self::descriptor::Descriptor;
use self::http::Intake;
use crate::config::ServeConfig;
use crate::server::{HousekeepingAdmission, SyncServer};

/// The intake the self-host shipper reaches without
/// `--publisher-training-intake-origin` (CALLS TL6_DESCRIPTOR_TRUST).
pub(crate) const DEFAULT_INTAKE_ORIGIN: &str = "https://oneiron.dev";

/// How often the outbox applies receipts, reconciles and writes controls: a
/// pace, so a withdrawal reaches `controls/` within one.
const POLL: Duration = Duration::from_secs(30);
/// How often an offer pass runs, and how long a conversation must have been
/// still before it is offered: a pace. A conversation still moving waits
/// for a later pass and then goes whole; nothing is dropped.
const OFFER_POLL: Duration = Duration::from_secs(15 * 60);

/// Which serve path runs the outbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Placement {
    /// Plain serve: a self-hosted vault, whose offers leave through the
    /// anonymous training window (TL-6), so they wait for its self-host
    /// shipper.
    SelfHost,
    /// Managed serve: the supervisor binds the registry vault id and the
    /// node's bearer outside the engine's offer.
    Managed,
}

/// Refuses a relative outbox directory, the flag's one shape rule.
///
/// # Errors
/// A directory given that is not absolute.
pub(crate) fn validate_outbox_dir(dir: Option<&Path>) -> anyhow::Result<()> {
    if dir.is_some_and(Path::is_relative) {
        anyhow::bail!("--publisher-training-outbox-dir must be an absolute path");
    }
    Ok(())
}

/// Refuses an intake origin the self-host shipper may not reach, by the
/// feedback transport's rule: HTTPS, or HTTP on loopback only, with no
/// credentials, query or fragment.
///
/// # Errors
/// An origin that breaks it.
pub(crate) fn validate_intake_origin(origin: &str) -> anyhow::Result<()> {
    crate::feedback_delivery::check_endpoint(origin).map_err(|_| {
        anyhow::anyhow!(
            "--publisher-training-intake-origin must be an HTTPS origin (HTTP only on loopback) \
             with no credentials, query or fragment"
        )
    })
}

/// Starts the outbox on `dir` with no self-host shipper: managed serve's,
/// whose supervisor pushes the intake's keys and ships.
pub(crate) fn spawn(
    server: Arc<SyncServer>,
    admit: HousekeepingAdmission,
    dir: PathBuf,
    placement: Placement,
) -> tokio::task::JoinHandle<()> {
    worker::spawn(server, admit, dir, placement, None)
}

/// Starts plain serve's outbox on `--publisher-training-outbox-dir`, and
/// with it, while `--publisher-training-self-host-shipper` is on (TL-6),
/// the self-host shipper: its descriptor fetch in the outbox's tick, and its
/// own loop. Their handles, for serve to stop; none with no outbox. The
/// shipper flag without an outbox warns once and stays inactive: nothing is
/// fetched or shipped.
pub(crate) fn spawn_self_host(
    server: &Arc<SyncServer>,
    config: &ServeConfig,
) -> Vec<tokio::task::JoinHandle<()>> {
    let shipper = config.publisher_training_self_host_shipper;
    let Some(dir) = config.publisher_training_outbox_dir.clone() else {
        if shipper {
            tracing::warn!(
                "--publisher-training-self-host-shipper needs --publisher-training-outbox-dir; \
                 the self-host training shipper stays inactive"
            );
        }
        return Vec::new();
    };
    let intake = shipper.then(|| {
        tracing::info!(
            "the self-host training shipper is on: the intake's descriptor is fetched at start \
             and hourly, and released offers and withdrawals go to the intake every 30 s"
        );
        Arc::new(Intake::new(&config.publisher_training_intake_origin))
    });
    let descriptor = intake
        .as_ref()
        .map(|intake| Arc::new(Descriptor::new(Arc::clone(intake))));
    let mut handles = vec![worker::spawn(
        Arc::clone(server),
        crate::server::admit_every_pass(),
        dir.clone(),
        Placement::SelfHost,
        descriptor.clone(),
    )];
    if let (Some(intake), Some(descriptor)) = (intake, descriptor) {
        handles.push(shipper::spawn(
            Arc::clone(server),
            crate::server::admit_every_pass(),
            dir,
            intake,
            descriptor,
        ));
    }
    handles
}

/// CALLS-5: the intake's sealing key, read from the one fixed file the
/// supervisor, or a self-hosted vault's shipper from the intake's
/// descriptor, publishes in the outbox directory,
/// [`INTAKE_RECIPIENT_FILE`]. Every chunk is sealed to it with the envelope
/// escrow seals to its recipients with. No file, or one that holds no
/// hybrid public key, refuses offers with a typed unavailable naming it;
/// controls still flow. Never the escrow key, never a key the vault mints
/// or shares.
fn intake_recipient_key(outbox_dir: &Path) -> Result<IntakeRecipient, TrainingUnavailable> {
    let bytes = read_key_file(&outbox_dir.join(INTAKE_RECIPIENT_FILE))
        .ok_or(TrainingUnavailable::MissingIntakeKey)?;
    IntakeRecipient::from_key_file(&bytes)
}

/// The intake's receipt key ring, from its fixed file
/// ([`INTAKE_RECEIPT_KEY_FILE`]): what authenticates a receipt, by the
/// current key or the one before it (FIX 6156). Without it no receipt is
/// applied, so nothing retires.
fn intake_receipt_key(outbox_dir: &Path) -> Result<IntakeReceiptKey, TrainingUnavailable> {
    let bytes = read_key_file(&outbox_dir.join(INTAKE_RECEIPT_KEY_FILE))
        .ok_or(TrainingUnavailable::MissingReceiptKey)?;
    IntakeReceiptKey::from_key_file(&bytes)
}

/// Whether offers may be written from this vault now, and the key they are
/// sealed to. A self-hosted vault's offers wait for its self-host shipper
/// (`shipper`, TL-6); past that both placements read the one installed
/// recipient.
fn offer_gate(
    outbox_dir: &Path,
    placement: Placement,
    shipper: bool,
) -> Result<IntakeRecipient, TrainingUnavailable> {
    if placement == Placement::SelfHost && !shipper {
        return Err(TrainingUnavailable::ShipperOff);
    }
    intake_recipient_key(outbox_dir)
}

/// A key file's bytes: a regular file, never a link the directory's other
/// writers could aim elsewhere; `None` when there is none to read.
fn read_key_file(path: &Path) -> Option<Vec<u8>> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_file() {
        return None;
    }
    std::fs::read(path).ok()
}
