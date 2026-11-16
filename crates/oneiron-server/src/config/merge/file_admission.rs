//! A config file's text, read once the file is admitted by who else can
//! reach it (FIX CONFIG-VALIDATION-PORT).
//!
//! The config file decides what this server serves and whom it trusts, so
//! one that any user can write is refused. One that sets `auth_secret` holds
//! the issuer key itself, so it is held to the rule of every credential
//! file (`credential_file::admit`): its owner's alone, by its mode and, on
//! macOS, by any ACL entry.
//!
//! A file the config refers to (a prompt, a wording or recipe file, a JSON
//! settings file, the wake config, the registration pins) decides what a
//! model is told, what runs or whom this server trusts, so it is held to the
//! first rule: one any user can write is refused (FIX
//! CONFIG-SIDE-FILES-MODE-UNCHECKED). None holds the issuer key.
//!
//! Both are read from the open handle the text is then read from, so the
//! file checked is the file read. A link is followed: its target is that
//! file. Only a regular file is checked, because a pipe or a device keeps no
//! mode an operator could change. The mode bits are Unix's; elsewhere
//! nothing is refused here, as for a credential file.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::Context;

use super::super::diagnostics::locate_toml_root_key;
use crate::commands::credential_file;

/// The config key that holds the issuer key itself. Every other credential
/// a config names is a vault secret's name or an environment variable's.
const ISSUER_KEY_SETTING: &str = "auth_secret";

/// The mode bit that lets any user write a file.
#[cfg(unix)]
const WRITE_BY_ANY_USER: u32 = 0o002;

/// The text of the config file at `path`, from one open handle, once that
/// handle's file is admitted: not writable by any user, and its owner's
/// alone when the text sets the issuer key. A refusal names the file, its
/// mode and the command that mends it, and for the issuer key the line that
/// sets it; it never repeats a value.
pub(crate) fn read_config_file(path: &Path) -> anyhow::Result<String> {
    let Admitted {
        file,
        stored,
        text: raw,
    } = read_admitted(path, Role::Config)?;
    if stored && sets_issuer_key(&raw) {
        credential_file::admit(path, &file).with_context(|| {
            let place = match locate_toml_root_key(&raw, ISSUER_KEY_SETTING) {
                Some(line) => format!(" at line {line}"),
                None => String::new(),
            };
            format!(
                "config file {} sets {ISSUER_KEY_SETTING}{place}, the issuer key, so only the \
                 file's owner may read it (ONEIRON_AUTH_SECRET keeps the key out of the file)",
                path.display()
            )
        })?;
    }
    Ok(raw)
}

/// The text of the file at `path` that a config refers to, from one open
/// handle, once that handle's file is not writable by any user. A refusal
/// names the file, its mode and the command that mends it; it never repeats
/// a line of the file.
pub(crate) fn read_referenced_file(path: &Path) -> anyhow::Result<String> {
    read_admitted(path, Role::Referenced).map(|admitted| admitted.text)
}

/// What a file is to this server, as a refusal names it.
#[derive(Clone, Copy)]
enum Role {
    /// The config file itself: `--config`, `ONEIRON_CONFIG`, the default
    /// path, `--settings-file`, the config `model-workers` reads.
    Config,
    /// A file a config refers to.
    Referenced,
}

impl Role {
    /// The file, as a refusal names it before its path.
    fn noun(self) -> &'static str {
        match self {
            Self::Config => "config file",
            Self::Referenced => "file",
        }
    }

    /// Why a file any user can write is refused.
    #[cfg_attr(not(unix), allow(dead_code))]
    fn stake(self) -> &'static str {
        match self {
            Self::Config => "it decides what this server serves and whom it trusts",
            Self::Referenced => {
                "the config refers to it for what a model is told, what runs or whom this \
                 server trusts"
            }
        }
    }
}

/// A file read to its end from the handle its admission checked.
struct Admitted {
    file: File,
    /// Whether the handle's file is a regular file, whose mode was checked.
    stored: bool,
    text: String,
}

/// The file at `path`, opened once and read from that handle when the
/// handle's file is not writable by any user.
fn read_admitted(path: &Path, role: Role) -> anyhow::Result<Admitted> {
    let mut file = File::open(path).with_context(|| unread(path, role))?;
    let metadata = file.metadata().with_context(|| unread(path, role))?;
    let stored = metadata.is_file();
    #[cfg(unix)]
    if stored {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        anyhow::ensure!(
            mode & WRITE_BY_ANY_USER == 0,
            "{} {} can be written by any user (mode {:o}), and {}; run `chmod o-w` on it",
            role.noun(),
            path.display(),
            mode & 0o777,
            role.stake()
        );
    }
    let mut text = String::new();
    file.read_to_string(&mut text)
        .with_context(|| unread(path, role))?;
    Ok(Admitted { file, stored, text })
}

/// Whether `raw` reads as a TOML table that sets the issuer key. A text
/// that does not read as one starts no server, and its reader names where
/// it fails.
fn sets_issuer_key(raw: &str) -> bool {
    toml::from_str::<toml::Table>(raw).is_ok_and(|table| table.contains_key(ISSUER_KEY_SETTING))
}

/// What a file that could not be opened or read is named as.
fn unread(path: &Path, role: Role) -> String {
    format!("read {} {}", role.noun(), path.display())
}
