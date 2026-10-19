//! The publisher training outbox (OF-420 A1, "Learn from my conversations"):
//! the worker that writes this vault's training offers and withdrawals into
//! `--publisher-training-outbox-dir` and reads the intake's receipts back
//! (`oneiron_vault_contract::conversation_training`).
//!
//! The flag is argv only in both serve paths, with no default: plain serve
//! takes it from the operator, managed serve from the supervisor (which
//! gives `<vault>/training-outbox`), and a managed settings file that names
//! it is refused as the supervisor's. Without it no worker runs, and
//! `oneiron::feedback::share_for_publisher_training` keeps refusing with
//! `NO_PUBLISHER_TRAINING_INTAKE`, as before.
//!
//! The engine decides everything: which words count, the release, the
//! reconciliation, the seal and the signature. This module only supplies
//! the in-vault filter, the directory, and the hooks that decide whether
//! offers may be written at all: the intake's sealing key (CALLS-5), its
//! receipt key, and a self-hosted vault's account binding (C1, `account`).
//! Without them no offer is written; withdrawals still are.

mod account;
mod outbox;
mod worker;

use std::path::Path;
use std::time::Duration;

use oneiron::feedback::{IntakeReceiptKey, IntakeRecipient, TrainingUnavailable};
use oneiron_vault_contract::conversation_training::{
    INTAKE_RECEIPT_KEY_FILE, INTAKE_RECIPIENT_FILE,
};

pub(crate) use self::worker::spawn;

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
    /// Plain serve: a self-hosted vault, whose offers need its account
    /// binding to the intake (C1).
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

/// CALLS-5: the intake's sealing key, read from the one fixed file the
/// supervisor (or a self-host operator) publishes in the outbox directory,
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

/// The intake's receipt key, from its fixed file
/// ([`INTAKE_RECEIPT_KEY_FILE`]): what authenticates a receipt. Without it
/// no receipt is applied, so nothing retires.
fn intake_receipt_key(outbox_dir: &Path) -> Result<IntakeReceiptKey, TrainingUnavailable> {
    let bytes = read_key_file(&outbox_dir.join(INTAKE_RECEIPT_KEY_FILE))
        .ok_or(TrainingUnavailable::MissingReceiptKey)?;
    IntakeReceiptKey::from_key_file(&bytes)
}

/// Whether offers may be written from this vault now, and the key they are
/// sealed to: a self-hosted vault first needs its account binding (C1).
fn offer_gate(
    outbox_dir: &Path,
    placement: Placement,
) -> Result<IntakeRecipient, TrainingUnavailable> {
    if placement == Placement::SelfHost {
        account::intake_account_binding()?;
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
