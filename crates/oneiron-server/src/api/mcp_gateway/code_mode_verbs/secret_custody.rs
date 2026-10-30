//! A run's secret custody for its browser and desktop (FIX 8028, OF-560;
//! ARCH-0069): a secret field the run's guest finds becomes a custody record
//! bound to the run where it is found (`Vault::mint_run_secret`), and the
//! guest's own type and expect take its bytes back through the one trusted
//! consumer (`Vault::with_run_secret`), never as an answer.
//!
//! The custody holds the call's verified caller (the connector's credential,
//! the public call's credential, or the pumped run's agent), the run and
//! the seat, never any guest input. Its records go with the seat that
//! found them: the seat's end hard-erases them (server/desktop_seats.rs).
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::secret_custody::{RunSecretHolder, RunSecretSeat};
use oneiron_browser::{BrowserError, SecretCustody, SecretKind, SecretUse};

use super::VerdictAsker;

/// The use a run-bound secret's Gate record names where the session names
/// no operation: the guest's own type or expect.
const BROWSER_SECRET_USE: &str = "browser.secret";

/// The use a Gate record names for the session's own operation (FIX 8342):
/// a type's send or an expect's comparison.
const fn browser_secret_use(operation: SecretUse) -> &'static str {
    match operation {
        SecretUse::Type => "browser.secret.type",
        SecretUse::Expect => "browser.secret.expect",
    }
}

/// One call's custody of its run's secrets, on one seat of the run.
pub(super) struct RunSecretCustody {
    vault: Arc<oneiron::Vault>,
    holder: RunSecretHolder,
}

impl RunSecretCustody {
    /// The custody of run `run`'s `seat` for the call `caller` makes.
    pub(super) fn new(
        vault: &Arc<oneiron::Vault>,
        caller: &VerdictAsker,
        run: EntityId,
        seat: RunSecretSeat,
    ) -> Self {
        let (actor, actor_class) = match caller {
            VerdictAsker::Connector(actor) => (actor.actor_ref, actor.actor_class),
            VerdictAsker::Credential(_, actor) | VerdictAsker::Agent(actor, _) => {
                (actor.entity_ref(), actor.actor_class())
            }
        };
        Self {
            vault: Arc::clone(vault),
            holder: RunSecretHolder {
                run,
                seat,
                actor,
                actor_class,
            },
        }
    }
}

/// The kind's word in its record and receipts.
const fn kind_word(kind: SecretKind) -> &'static str {
    match kind {
        SecretKind::Card => "card",
        SecretKind::Cvv => "cvv",
        SecretKind::Otp => "otp",
        SecretKind::Password => "password",
    }
}

impl SecretCustody for RunSecretCustody {
    fn acquire(&self, kind: SecretKind, value: &str, origin: &str) -> Result<String, BrowserError> {
        self.vault
            .mint_run_secret(&self.holder, kind_word(kind), value.as_bytes(), origin)
            .map(|(_, handle)| handle)
            .map_err(|error| BrowserError::SecretRefused(error.to_string()))
    }

    fn with_value(
        &self,
        handle: &str,
        use_: &mut dyn FnMut(&str) -> Result<(), BrowserError>,
    ) -> Result<(), BrowserError> {
        self.lend(handle, BROWSER_SECRET_USE, use_)
    }

    fn with_value_as(
        &self,
        handle: &str,
        operation: SecretUse,
        use_: &mut dyn FnMut(&str) -> Result<(), BrowserError>,
    ) -> Result<(), BrowserError> {
        self.lend(handle, browser_secret_use(operation), use_)
    }

    /// The custody's admission of `handle` for this run's seat, its bytes
    /// unread and no use recorded (FIX 10424).
    fn holds(&self, handle: &str) -> Result<bool, BrowserError> {
        self.vault
            .holds_run_secret(&self.holder, handle)
            .map_err(|error| BrowserError::SecretRefused(error.to_string()))
    }
}

impl RunSecretCustody {
    /// Lends `handle`'s bytes to `use_` once, its Gate record naming
    /// `operation`.
    fn lend(
        &self,
        handle: &str,
        operation: &str,
        use_: &mut dyn FnMut(&str) -> Result<(), BrowserError>,
    ) -> Result<(), BrowserError> {
        // The guest's own error, kept apart from the custody's, so a send
        // that failed answers as it failed.
        let mut failed = None;
        let lent =
            self.vault
                .with_run_secret(&self.holder, handle, operation, &mut |bytes: &[u8]| {
                    let text = std::str::from_utf8(bytes).map_err(|_| {
                        oneiron::Error::InvariantViolation("a run-bound secret is not text")
                    })?;
                    use_(text).map_err(|error| {
                        failed = Some(error);
                        oneiron::Error::InvariantViolation(
                            "the guest's use of a run-bound secret failed",
                        )
                    })
                });
        match (lent, failed) {
            (_, Some(error)) => Err(error),
            (Ok(()), None) => Ok(()),
            (Err(error), None) => Err(BrowserError::SecretRefused(error.to_string())),
        }
    }
}
