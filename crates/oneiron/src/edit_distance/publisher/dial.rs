//! Publisher share dial: explicit, install-profile, and compiled-default resolution.

use crate::Vault;
use crate::error::Error;
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};

use super::PublisherResult;

/// The publisher share dial. House pattern is a per-feature table in the
/// owning module (`INBOX_REVIEW_DIAL_KEY`, `inbox.rs:73`). `settings.rs` is
/// UI-customization only and is not touched.
const ENABLED: SideTable<(), DialToken, Raw> =
    SideTable::new(&side_table::EDIT_DISTANCE_PUBLISHER_ENABLED);

/// The install profile's default for [`ENABLED`], written at provisioning.
/// This is where the cloud posture's default-ON (ARCH-0056 §9 rung 1, owner
/// ruling r6) lands; a self-host install writes its own answer, and a build
/// that never provisioned falls through to
/// [`PUBLISHER_ENABLED_COMPILED_DEFAULT`].
const INSTALL_DEFAULT: SideTable<(), DialToken, Raw> =
    SideTable::new(&side_table::EDIT_DISTANCE_PUBLISHER_INSTALL_DEFAULT);

/// The compiled fallback: disabled.
///
/// The engine cannot know its own posture, and it is the OSS/self-hostable
/// artifact — "self-host picks posture at install" (§9) means a build that
/// never picked must not send to a publisher nobody chose. This is posture
/// resolution, not a wall: one write to either key above flips it.
pub const PUBLISHER_ENABLED_COMPILED_DEFAULT: bool = false;

const DIAL_ENABLED: &str = "enabled";

const DIAL_DISABLED: &str = "disabled";

/// The dial's on-disk token, one leading-byte-free `enabled`/`disabled`
/// string.
struct DialToken(bool);

impl RawValue for DialToken {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let token = if self.0 { DIAL_ENABLED } else { DIAL_DISABLED };
        Ok(token.as_bytes().to_vec())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        match std::str::from_utf8(bytes) {
            Ok(DIAL_ENABLED) => Ok(Self(true)),
            Ok(DIAL_DISABLED) => Ok(Self(false)),
            _ => Err(CodecError::Value(Error::CorruptedIndex("publisher dial"))),
        }
    }
}

/// Resolves the effective publisher dial.
///
/// Order: the owner's explicit dial, then the install profile, then the
/// compiled default. The explicit dial sits on top deliberately — an install
/// profile that overrode a dial the owner set would make it a wall, and this
/// is ratified as a dial (worklog D4).
///
/// # Errors
///
/// Storage errors, and [`Error::CorruptedIndex`] on a dial token this engine
/// never wrote.
pub fn publisher_enabled(vault: &Vault) -> PublisherResult<bool> {
    let rtxn = vault.store.env.read_txn().map_err(Error::from)?;
    if let Some(explicit) = ENABLED.get(&vault.store, &rtxn, &())? {
        return Ok(explicit.0);
    }
    if let Some(profile) = INSTALL_DEFAULT.get(&vault.store, &rtxn, &())? {
        return Ok(profile.0);
    }
    Ok(PUBLISHER_ENABLED_COMPILED_DEFAULT)
}

/// Sets the owner's explicit dial position.
///
/// # Errors
///
/// Storage errors.
pub fn set_publisher_enabled(vault: &Vault, enabled: bool) -> PublisherResult<()> {
    vault.with_write_txn(|wtxn| ENABLED.put(&vault.store, wtxn, &(), &DialToken(enabled)))?;
    Ok(())
}

/// Writes the install profile's default. Provisioning-time door; it never
/// overrides an explicit dial.
///
/// # Errors
///
/// Storage errors.
pub fn set_publisher_install_default(vault: &Vault, enabled: bool) -> PublisherResult<()> {
    vault
        .with_write_txn(|wtxn| INSTALL_DEFAULT.put(&vault.store, wtxn, &(), &DialToken(enabled)))?;
    Ok(())
}
