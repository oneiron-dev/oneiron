//! Publisher share dial: explicit, install-profile, and compiled-default resolution.

use super::{PublisherResult, put_meta};
use crate::Vault;
use crate::error::{Error, Result};

/// The publisher share dial, over `vault_meta` — house pattern is a per-feature
/// byte-key const in the owning module (`INBOX_REVIEW_DIAL_KEY`, `inbox.rs:73`).
/// `settings.rs` is UI-customization only and is not touched.
pub const PUBLISHER_ENABLED_KEY: &[u8] = b"settings:publisher:v1:enabled";

/// The install profile's default for [`PUBLISHER_ENABLED_KEY`], written at
/// provisioning. This is where the cloud posture's default-ON (ARCH-0056 §9
/// rung 1, owner ruling r6) lands; a self-host install writes its own answer,
/// and a build that never provisioned falls through to
/// [`PUBLISHER_ENABLED_COMPILED_DEFAULT`].
pub const PUBLISHER_INSTALL_DEFAULT_KEY: &[u8] = b"settings:publisher:v1:install_default";

/// The compiled fallback: disabled.
///
/// The engine cannot know its own posture, and it is the OSS/self-hostable
/// artifact — "self-host picks posture at install" (§9) means a build that
/// never picked must not send to a publisher nobody chose. This is posture
/// resolution, not a wall: one write to either key above flips it.
pub const PUBLISHER_ENABLED_COMPILED_DEFAULT: bool = false;

const DIAL_ENABLED: &str = "enabled";

const DIAL_DISABLED: &str = "disabled";

fn read_dial_key(vault: &Vault, key: &[u8]) -> Result<Option<bool>> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault.store.vault_meta.get(&rtxn, key)? else {
        return Ok(None);
    };
    match std::str::from_utf8(&raw) {
        Ok(DIAL_ENABLED) => Ok(Some(true)),
        Ok(DIAL_DISABLED) => Ok(Some(false)),
        _ => Err(Error::CorruptedIndex("publisher dial")),
    }
}

fn write_dial_key(vault: &Vault, key: &[u8], enabled: bool) -> Result<()> {
    let token = if enabled { DIAL_ENABLED } else { DIAL_DISABLED };
    put_meta(vault, key, token.as_bytes())
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
    if let Some(explicit) = read_dial_key(vault, PUBLISHER_ENABLED_KEY)? {
        return Ok(explicit);
    }
    if let Some(profile) = read_dial_key(vault, PUBLISHER_INSTALL_DEFAULT_KEY)? {
        return Ok(profile);
    }
    Ok(PUBLISHER_ENABLED_COMPILED_DEFAULT)
}

/// Sets the owner's explicit dial position.
///
/// # Errors
///
/// Storage errors.
pub fn set_publisher_enabled(vault: &Vault, enabled: bool) -> PublisherResult<()> {
    write_dial_key(vault, PUBLISHER_ENABLED_KEY, enabled)?;
    Ok(())
}

/// Writes the install profile's default. Provisioning-time door; it never
/// overrides an explicit dial.
///
/// # Errors
///
/// Storage errors.
pub fn set_publisher_install_default(vault: &Vault, enabled: bool) -> PublisherResult<()> {
    write_dial_key(vault, PUBLISHER_INSTALL_DEFAULT_KEY, enabled)?;
    Ok(())
}
