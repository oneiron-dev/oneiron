//! The owner presence check: "Confirm it's you" before an owner act (row
//! OWNER-CONFIRM-SHEET).
//!
//! An owner door calls [`Vault::owner_presence`] before it opens its write
//! transaction and says how much its act moves. The check answers a witness
//! when the act may go on, or a typed refusal, and writes nothing either way.
//!
//! An ordinary act is not asked. For an important act the device is read in
//! this order: a device PIN that is set asks for the PIN, and its open window
//! is the confirm; else the device's own unlock prompt asks, through the
//! process's presence gate, and one confirm serves the acts of the gate's
//! window; a device with neither lets the act stand.

use std::sync::{Arc, PoisonError};

use oneiron_keystore::{PresenceConfirmation, PresenceError, PresenceGate};

use super::device_pin::{device_pin_is_set, no_device_pin_here, pin_refused, presence_refused};
use crate::authority::Direction;
use crate::error::{DevicePinRefusal, OwnerPresenceRefusal, RecordError, Result};
use crate::vault::Vault;

/// How much an owner act moves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerActImportance {
    /// An act that narrows authority or moves no authority.
    Ordinary,
    /// An identity act, a widening, or an act whose direction the door cannot tell.
    Important,
}

impl OwnerActImportance {
    /// An act is important when it widens or when its comparator cannot call it a narrowing.
    #[must_use]
    pub fn of_direction(direction: Direction) -> Self {
        match direction {
            Direction::Widens => Self::Important,
            Direction::Narrows | Direction::Neutral => Self::Ordinary,
        }
    }
}

/// Why an owner act may go on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerPresenceBasis {
    /// The act is ordinary, so no prompt was needed.
    NotAsked,
    /// The person answered this device's prompt for this act.
    Prompted,
    /// An earlier prompt confirmation or right device PIN still holds.
    WithinWindow,
    /// This device has no prompt or device PIN, so the act stands under the interim rule.
    DeviceCannotAsk,
}

/// The value a door holds to show the presence check was made for one act.
/// Only [`Vault::owner_presence`] makes one.
#[derive(Debug)]
#[must_use]
pub struct OwnerPresenceWitness {
    importance: OwnerActImportance,
    basis: OwnerPresenceBasis,
}

impl OwnerPresenceWitness {
    /// The importance of the act that was checked.
    pub fn importance(&self) -> OwnerActImportance {
        self.importance
    }

    /// Why the checked act may go on.
    pub fn basis(&self) -> OwnerPresenceBasis {
        self.basis
    }
}

impl Vault {
    /// Installs the gate for this device's own unlock prompt. The host makes
    /// one gate for the process and installs that same gate on every vault
    /// handle. A handle without a gate cannot ask through a platform prompt.
    /// [`Self::install_process_presence_gate`] does both for the platform's
    /// own prompt.
    pub fn install_presence_gate(&self, gate: Arc<PresenceGate>) {
        *self
            .world_keys
            .presence_gate
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(gate);
    }

    /// Installs this process's one gate over the platform's own prompt
    /// ([`PresenceGate::process_wide`]) on a handle that holds no gate. A
    /// gate installed before stays ([`Self::install_presence_gate`]): a host
    /// with a prompt of its own keeps it.
    ///
    /// The call of a host whose caller is at this device: a program that
    /// opens the vault in its own process, or a command a person runs here.
    /// From then on an important owner act on this handle asks through the
    /// device's unlock prompt. On a platform with no prompt the gate answers
    /// as a device that cannot ask, so the act stands as on a handle with no
    /// gate. A process that serves callers on other devices does not call
    /// it: its screen is not theirs.
    pub fn install_process_presence_gate(&self) {
        let mut installed = self
            .world_keys
            .presence_gate
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if installed.is_none() {
            *installed = Some(PresenceGate::process_wide());
        }
    }

    /// Returns a shared reference to the platform presence gate installed on this handle.
    #[must_use]
    pub fn presence_gate(&self) -> Option<Arc<PresenceGate>> {
        self.world_keys
            .presence_gate
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Checks presence for an owner act. `reason` is the one line shown in
    /// the device's prompt. A door calls this before opening its write
    /// transaction, while holding no lock other work waits on: the prompt
    /// can block for [`oneiron_keystore::PRESENCE_PROMPT_SECS`]. This check
    /// opens no transaction and writes nothing.
    ///
    /// # Errors
    /// A refused platform prompt answers [`RecordError::OwnerPresenceRequired`].
    /// A set device PIN needs an installed PIN gate and an open PIN window;
    /// PIN refusals answer [`crate::error::SecretError::DevicePin`]: a closed
    /// window answers [`DevicePinRefusal::Required`], and a handle whose host
    /// installed no device PIN answers [`DevicePinRefusal::Unavailable`],
    /// because no call on that handle could take the PIN. A failed PIN-home
    /// read answers the keystore's error.
    pub fn owner_presence(
        &self,
        importance: OwnerActImportance,
        reason: &str,
    ) -> Result<OwnerPresenceWitness> {
        if importance == OwnerActImportance::Ordinary {
            return Ok(OwnerPresenceWitness {
                importance,
                basis: OwnerPresenceBasis::NotAsked,
            });
        }

        if let Ok(keystore) = self.device_keystore()
            && device_pin_is_set(keystore.as_ref()).map_err(super::keystore_error)?
        {
            let pin = self.device_pin().ok_or_else(no_device_pin_here)?;
            if !pin.window_is_open() {
                return Err(pin_refused(DevicePinRefusal::Required));
            }
            return Ok(OwnerPresenceWitness {
                importance,
                basis: OwnerPresenceBasis::WithinWindow,
            });
        }

        let Some(gate) = self.presence_gate() else {
            return Ok(device_cannot_ask(importance));
        };
        let basis = match gate.confirm(reason) {
            Ok(PresenceConfirmation::Prompted) => OwnerPresenceBasis::Prompted,
            Ok(PresenceConfirmation::WithinWindow) => OwnerPresenceBasis::WithinWindow,
            // A backend answers `NoPrompt` only where it can never show its
            // prompt. A session that is off the screen answers `ScreenLocked`.
            Err(PresenceError::NoPrompt(_)) => return Ok(device_cannot_ask(importance)),
            Err(PresenceError::Declined) => {
                return Err(owner_presence_refused(OwnerPresenceRefusal::Declined));
            }
            Err(PresenceError::NoAnswer) => {
                return Err(owner_presence_refused(OwnerPresenceRefusal::NoAnswer));
            }
            Err(PresenceError::ScreenLocked) => {
                return Err(owner_presence_refused(OwnerPresenceRefusal::ScreenLocked));
            }
            Err(PresenceError::Platform(name, code)) => {
                tracing::warn!(name, code, "The device's presence prompt failed.");
                return Err(owner_presence_refused(OwnerPresenceRefusal::PromptFailed));
            }
            Err(
                error @ (PresenceError::PinRequired
                | PresenceError::WrongPin
                | PresenceError::TooManyTries { .. }),
            ) => {
                return Err(presence_refused(error));
            }
        };
        Ok(OwnerPresenceWitness { importance, basis })
    }
}

fn owner_presence_refused(here: OwnerPresenceRefusal) -> crate::error::Error {
    RecordError::OwnerPresenceRequired { here }.into()
}

/// The answer of a device that cannot ask: it has no unlock prompt and no
/// device PIN. An important act stands on it, as it did before the confirm
/// sheet, because a device knows only its own capability and nothing lists
/// the owner's other devices that could confirm. The hand-over (row
/// OWNER-CONFIRM-SHEET, PR 5) lists them, and its typed refusal goes in this
/// one function. No shown prompt, locked screen, set PIN, or platform
/// failure reaches this function.
fn device_cannot_ask(importance: OwnerActImportance) -> OwnerPresenceWitness {
    OwnerPresenceWitness {
        importance,
        basis: OwnerPresenceBasis::DeviceCannotAsk,
    }
}
