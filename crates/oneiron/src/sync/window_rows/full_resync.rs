//! The value of a window's full-resync marker (`fr:w:{key}`, FIX 20202).
//!
//! Every writer but one puts the plain form, the single byte `[1]`: the
//! window's sync state is no faithful delta source, and only a full resync
//! takes the marker away (an all-windows device's re-bootstrap, or explicit
//! sync-all recovery on an opened-item device). The actor erase's rewrite of
//! a stored window ([`crate::sync::source_audiences::erase_carriers_in_txn`])
//! puts the policy-wake form instead. The redaction it wrote, and the queued
//! sends of the window it dropped, reach the home through the window's own
//! exchange once the policy wake the erase left persisted the window again
//! and readied it ([`crate::sync::WindowManager::mark_window_ready`]), so the
//! form carries the ready generation that wake raises the window to. An
//! opened-item device's connect leaves each such marker to its window's
//! promoted exchange, which takes it away once the home holds everything this
//! device holds of the window at that generation or a later one.
//!
//! Plain beats wake: a plain writer puts `[1]` over a wake form, and a wake
//! form never takes a plain marker's place. Of two wake forms, the newer
//! generation stays. Bytes that spell no wake form read as plain, so a value
//! no wake writer wrote keeps its full resync.

use heed::{RoTxn, RwTxn};

use crate::Vault;
use crate::error::Result;
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};

/// The plain form's single byte, what every writer but the actor erase's
/// rewrite puts.
const PLAIN_MARKER: u8 = 1;
/// The policy-wake form's first byte; the ready generation follows it, eight
/// bytes big-endian.
const POLICY_WAKE_MARKER: u8 = 2;

/// What a window's full-resync marker holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FullResyncForm {
    /// `[1]`: only a full resync takes it away.
    Plain,
    /// `[2]` and the generation: the actor erase's rewrite, which the policy
    /// wake it left delivers once it raises the window's ready generation to
    /// `generation`.
    PolicyWake { generation: u64 },
}

impl FullResyncForm {
    /// The form `bytes` hold: the policy-wake form when they spell one,
    /// plain otherwise.
    fn read(bytes: &[u8]) -> Self {
        match bytes.split_first() {
            Some((&POLICY_WAKE_MARKER, generation)) => {
                <[u8; 8]>::try_from(generation).map_or(Self::Plain, |generation| Self::PolicyWake {
                    generation: u64::from_be_bytes(generation),
                })
            }
            _ => Self::Plain,
        }
    }

    /// The bytes the form is stored as.
    fn bytes(self) -> Vec<u8> {
        match self {
            Self::Plain => vec![PLAIN_MARKER],
            Self::PolicyWake { generation } => {
                let mut bytes = vec![POLICY_WAKE_MARKER];
                bytes.extend_from_slice(&generation.to_be_bytes());
                bytes
            }
        }
    }
}

impl RawValue for FullResyncForm {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(self.bytes())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(Self::read(bytes))
    }
}

/// The full-resync marker rows read and written as their form. The plain
/// writers keep `WINDOW_FULL_RESYNC_MARKER`'s `[1]`, the same rows.
const FULL_RESYNC_FORM: SideTable<String, FullResyncForm, Raw> =
    SideTable::new(&side_table::WINDOW_FULL_RESYNC_MARKER);

/// The form of window `window`'s full-resync marker, read in `txn`; `None`
/// when it holds none.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn full_resync_form_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    window: &str,
) -> Result<Option<FullResyncForm>> {
    FULL_RESYNC_FORM.get(&vault.store, txn, &window.to_owned())
}

/// Marks window `window` for its policy wake's exchange in `wtxn`, at ready
/// generation `generation`: a plain marker stays plain, and a wake form at
/// `generation` or a newer one stays as it is.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn put_policy_wake_marker_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    window: &str,
    generation: u64,
) -> Result<()> {
    let window = window.to_owned();
    let held = FULL_RESYNC_FORM.get(&vault.store, wtxn, &window)?;
    match held {
        Some(FullResyncForm::Plain) => Ok(()),
        Some(FullResyncForm::PolicyWake { generation: held }) if held >= generation => Ok(()),
        Some(FullResyncForm::PolicyWake { .. }) | None => FULL_RESYNC_FORM.put(
            &vault.store,
            wtxn,
            &window,
            &FullResyncForm::PolicyWake { generation },
        ),
    }
}

/// Takes window `window`'s policy-wake marker away in `wtxn` once an exchange
/// proved the home holds everything this device holds of the window while its
/// ready generation is `ready`: a wake form at `ready` or an older generation
/// goes. A plain marker, a wake form past `ready` and no marker stay as they
/// are. Whether a marker went.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn clear_covered_policy_wake_marker_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    window: &str,
    ready: u64,
) -> Result<bool> {
    let window = window.to_owned();
    let held = FULL_RESYNC_FORM.get(&vault.store, wtxn, &window)?;
    match held {
        Some(FullResyncForm::PolicyWake { generation }) if generation <= ready => {
            FULL_RESYNC_FORM.delete(&vault.store, wtxn, &window)
        }
        Some(FullResyncForm::Plain | FullResyncForm::PolicyWake { .. }) | None => Ok(false),
    }
}
