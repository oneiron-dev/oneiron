//! The size a drafted reply with files from an IMAP mailbox may have (fix
//! list row 17645): what its own submission server takes, asked before the
//! reply is asked for and again before each press, and judged once more by
//! the send's own session before `MAIL` (`smtp_client`).
//!
//! - **The limit.** A positive number after `SIZE` in the server's `EHLO`
//!   over TLS (RFC 1870) is the most octets it takes. `SIZE` absent, with no
//!   number or with 0 names none, and the host operator's setting
//!   `mail.smtp.max_message_octets_unadvertised` stands instead
//!   ([`MailHostSettings`], [`DEFAULT_SMTP_MAX_MESSAGE_OCTETS_UNADVERTISED`]
//!   unless the host sets it). A limit the server names always wins over the
//!   setting. The exact frozen message is counted: its CRLF MIME octets, not
//!   its dot-stuffed data, nor the final `.<CRLF>`.
//! - **The check.** Through the mailbox's own submission credential, at its
//!   door: TLS, `EHLO`, `AUTH` as its send authenticates, the limit read,
//!   `QUIT`. Never `MAIL`, `RCPT` or `DATA`. A check that cannot be made
//!   refuses the draft, or the press; nothing is asked for or pressed on a
//!   limit nobody read. The draft keeps the limit and when it was read for
//!   its reviewer, never as a lasting permission: each press asks again.
//! - **What it binds to.** A check records what it was read from: the
//!   mailbox source, the custody record its credential is held under and
//!   that record's value generation, the submission server (host and port)
//!   that value names, and, for a server that named no limit, the setting it
//!   applied. The writer that publishes the draft and the writer that
//!   presses it each read the source and its credential record as they
//!   stand there and take the check only while it is still bound to them,
//!   and to the setting the host applies now; then the exact frozen message
//!   is judged against it. A reconnect to another credential, a rotated
//!   credential or a changed setting refuses that write, and the next call
//!   asks the server again outside it.
//! - **Where it runs.** The check waits on the network inside the drafter's
//!   own call, with the drafter's own handle and the mailbox's own
//!   credential. It runs on the blocking runner its host installs
//!   ([`MailBlockingRunner`]), so no async runtime worker is held while it
//!   waits; where the host installs none, the call is a blocking one already
//!   and the check runs in place.

use std::sync::{Arc, PoisonError, RwLock};

use serde::{Deserialize, Serialize};

use super::credential::WireReads;
use super::reply_send::{SMTP_SUBMISSION_CONNECTOR_EFFECTOR, open_submission};
use super::source::{MailProvider, MailSourceRow};
use super::wire::MailSyncSource;
use crate::memory::{MemoryError, MemoryResult};
use crate::secret_record::read_secret_custody_admission_in_txn;
use crate::store::secret_name_index::resolve_secret_ref_in_txn;
use crate::{EntityId, Result, Vault};

/// The default of the host operator's setting
/// `mail.smtp.max_message_octets_unadvertised` (fix list row 17645):
/// 36,700,160 octets (35 MiB) of the exact message, the most one message
/// submitted over SMTP may have when its server's `EHLO` names no `SIZE`
/// limit. A host policy, not an SMTP or a provider limit.
pub const DEFAULT_SMTP_MAX_MESSAGE_OCTETS_UNADVERTISED: u64 = 36_700_160;

/// The host operator's mail settings (fix list row 17645), as the host
/// installs them on a vault ([`Vault::install_mail_host`]); the defaults
/// where it installs none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailHostSettings {
    /// `mail.smtp.max_message_octets_unadvertised`: the most octets one
    /// message submitted over SMTP may have when its server's `EHLO` names
    /// no `SIZE` limit. A limit the server names always wins over it.
    pub smtp_max_message_octets_unadvertised: u64,
}

impl Default for MailHostSettings {
    fn default() -> Self {
        Self {
            smtp_max_message_octets_unadvertised: DEFAULT_SMTP_MAX_MESSAGE_OCTETS_UNADVERTISED,
        }
    }
}

/// Where a host runs the mail pack's blocking network work that a caller's
/// own call waits on (fix list row 17645): the size check of an IMAP
/// mailbox's submission server for a drafted reply with files.
pub trait MailBlockingRunner: Send + Sync {
    /// Runs `work` once, to its end, before it returns: on the calling
    /// thread or on one the host lends it, never holding an async runtime
    /// worker while it waits.
    fn run(&self, work: &mut (dyn FnMut() + Send));
}

/// What a host installed for the mail pack on one vault: its settings and
/// the runner its blocking mail work runs on. Never persisted.
#[derive(Default)]
pub(crate) struct MailHostSlot(RwLock<MailHost>);

#[derive(Default)]
struct MailHost {
    settings: MailHostSettings,
    runner: Option<Arc<dyn MailBlockingRunner>>,
}

impl Vault {
    /// Installs the host operator's mail settings on this vault, and the
    /// runner its blocking mail work runs on, in place of any before them
    /// (fix list row 17645). With no runner, that work runs in place, on the
    /// calling thread.
    pub fn install_mail_host(
        &self,
        settings: MailHostSettings,
        runner: Option<Arc<dyn MailBlockingRunner>>,
    ) {
        *self
            .store
            .mail_host
            .0
            .write()
            .unwrap_or_else(PoisonError::into_inner) = MailHost { settings, runner };
    }

    /// The host operator's mail settings on this vault.
    pub(super) fn mail_host_settings(&self) -> MailHostSettings {
        self.store
            .mail_host
            .0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .settings
    }

    /// Runs `work` on the runner the host installed, else in place.
    fn run_mail_blocking(&self, work: &mut (dyn FnMut() + Send)) {
        let runner = self
            .store
            .mail_host
            .0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .runner
            .clone();
        match runner {
            Some(runner) => runner.run(work),
            None => work(),
        }
    }
}

/// What an IMAP mailbox's submission server named of the size it takes,
/// when it was last asked for one revision of a drafted reply with files
/// (fix list row 17645), and what it was read from. The draft keeps it for
/// its reviewer; it is never a lasting permission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct SmtpSizeCheck {
    /// The most octets the exact message may have: the server's own `SIZE`,
    /// else the host's setting.
    pub(super) limit: u64,
    /// Whether the server named it.
    pub(super) advertised: bool,
    /// When it was read, unix seconds.
    pub(super) read_at: u64,
    /// What it was read from. A check that names none, one kept before
    /// checks named it, stands in no writer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) bound: Option<SmtpSizeBinding>,
}

/// What one size check of an IMAP mailbox's submission server was read
/// from (fix list row 17645): the writer that relies on it takes it only
/// while each of these still stands as it was.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct SmtpSizeBinding {
    /// The mailbox source it was read for.
    pub(super) source: EntityId,
    /// The custody record that source named for its credential at the door;
    /// a reconnect to another credential names another.
    pub(super) custody_ref: String,
    /// That record's value generation at the door; a rotation of the
    /// credential under the same record raises it.
    pub(super) credential_generation: u32,
    /// The submission server the credential's value at that generation
    /// names.
    pub(super) endpoint: SmtpEndpoint,
    /// The host's setting `mail.smtp.max_message_octets_unadvertised` it
    /// applied, when the server named no limit; `None` when it named one.
    pub(super) unadvertised_setting: Option<u64>,
}

/// The submission server an IMAP mailbox's credential names: its host and
/// port (fix list row 17645).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct SmtpEndpoint {
    /// The server name, lower case.
    pub(super) host: String,
    /// Its submission port.
    pub(super) port: u16,
}

impl SmtpSizeCheck {
    /// Whether this check still binds in `txn`, the writer that would rely
    /// on it, for the mailbox source `source_ref` as `source` stands there
    /// (fix list row 17645): it was read for that IMAP source, through the
    /// custody record the source names in `txn`, at the value generation
    /// that record holds in `txn` (so from the submission server that value
    /// names: the endpoint is read from the credential's value alone), and,
    /// when the server named no limit, under the setting this host applies
    /// now. A check that does not bind is not taken: the caller asks the
    /// server again outside the writer.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub(super) fn binds_in(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        source_ref: EntityId,
        source: &MailSourceRow,
    ) -> Result<bool> {
        let Some(bound) = &self.bound else {
            return Ok(false);
        };
        if bound.source != source_ref
            || source.provider != MailProvider::Imap
            || bound.custody_ref != source.custody_ref
        {
            return Ok(false);
        }
        let generation = match resolve_secret_ref_in_txn(&vault.store, txn, &source.custody_ref)? {
            Some(id) => read_secret_custody_admission_in_txn(&vault.store, txn, &id)?
                .map(|record| record.rotation_generation),
            None => None,
        };
        if generation != Some(bound.credential_generation) {
            return Ok(false);
        }
        let setting = (!self.advertised).then(|| {
            vault
                .mail_host_settings()
                .smtp_max_message_octets_unadvertised
        });
        Ok(bound.unadvertised_setting == setting && setting.is_none_or(|set| set == self.limit))
    }

    /// Why a message of `octets` octets is too large for this limit; `None`
    /// while it fits.
    pub(super) fn refusal(&self, octets: u64) -> Option<String> {
        let limit = self.limit;
        (octets > limit).then(|| {
            let named = if self.advertised {
                "its mailbox's submission server takes"
            } else {
                "this host submits to a server that names no limit"
            };
            format!("the reply with its files is {octets} octets; {named} at most {limit}")
        })
    }
}

/// Asks the submission server of the IMAP mailbox `source` the size it
/// takes now (fix list row 17645), through the mailbox's own credential at
/// its door: TLS, `EHLO` naming the domain of `from`, the mailbox's address,
/// `AUTH` as its send authenticates, the limit read, `QUIT`; never `MAIL`,
/// `RCPT` or `DATA`. It runs on the host's blocking runner, within the
/// caller's own call. The check names what it was read from: the source,
/// the custody record its credential is held under and the value generation
/// the door read, the server that value names and the setting it applied
/// ([`SmtpSizeBinding`]).
///
/// # Errors
///
/// A check that could not be made: the mailbox's credential, its server or
/// its session refused it or did not answer. Nothing may be asked for or
/// pressed on it.
pub(super) fn check_smtp_size(
    vault: &Vault,
    source: &MailSyncSource,
    from: &str,
) -> MemoryResult<SmtpSizeCheck> {
    let unadvertised = vault
        .mail_host_settings()
        .smtp_max_message_octets_unadvertised;
    let mut outcome = None;
    vault.run_mail_blocking(&mut || {
        let mut read = None;
        let door = vault.with_source_token_at_door(
            source,
            WireReads::Mailbox,
            SMTP_SUBMISSION_CONNECTOR_EFFECTOR,
            &mut |secret: &[u8]| {
                let (session, endpoint) = open_submission(source, secret, from)?;
                read = Some((session.advertised_size(), endpoint));
                session.quit();
                Ok(())
            },
        );
        outcome = Some(match (read, door) {
            (Some((advertised, endpoint)), Ok(receipt)) => {
                Ok((advertised, endpoint, receipt.value_generation))
            }
            (_, Err(error)) => Err(error.to_string()),
            (None, Ok(_)) => Err("smtp_credential_door_refused".to_owned()),
        });
    });
    let refused = |reason: &str| {
        MemoryError::bad_request(format!(
            "the mailbox's submission server could not be asked the size it takes \
             ({reason}); a reply with files waits until it can"
        ))
    };
    let (advertised, endpoint, credential_generation) = match outcome {
        Some(Ok(read)) => read,
        Some(Err(reason)) => return Err(refused(&reason)),
        None => return Err(refused("smtp_size_check_not_run")),
    };
    let unadvertised_setting = advertised.is_none().then_some(unadvertised);
    Ok(SmtpSizeCheck {
        limit: advertised.unwrap_or(unadvertised),
        advertised: advertised.is_some(),
        read_at: crate::unix_seconds_now(),
        bound: Some(SmtpSizeBinding {
            source: source.source_ref,
            custody_ref: source.custody_ref.clone(),
            credential_generation,
            endpoint,
            unadvertised_setting,
        }),
    })
}
