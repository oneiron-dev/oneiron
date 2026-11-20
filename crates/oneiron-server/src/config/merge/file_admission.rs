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
//! A config file a host places for the process it starts is held to the
//! first rule alone (FIX MANAGED-SETTINGS-FILE-MODE-UNCHECKED): a managed
//! vault's settings file, which Hypnos writes root's at mode 0640 for the
//! vault's group, and a relay room's file, which the room's installer writes
//! root's at 0440 for the room's group. Neither holds the issuer key: the
//! managed reader refuses `auth_secret` as the supervisor's leaf, and a
//! room's schema has no such field.
//!
//! A credential its host shares with one group cannot be its owner's alone:
//! a relay room's locker token is root's, at 0440, and the room reads it
//! through its own private group. So it is refused when any user outside its
//! owner and its group can read or write it (FIX
//! RELAY-ACCESS-TOKEN-FILE-NOT-ADMITTED), and when it carries an access
//! control list: a list's entries let in users its mode does not show, and
//! on Linux its group bits then show the list's mask, not the group's reach
//! (REVIEW-9811). An owner-alone credential needs no such check off macOS,
//! because its group bits of zero mask every entry.
//!
//! Each is read from the open handle the text is then read from, so the
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

/// What a refused mode lets users outside a file's owner and group do, and
/// the command that shuts them out.
#[cfg(unix)]
#[derive(Clone, Copy)]
struct Reach {
    /// The mode bits that refuse the file.
    bits: u32,
    /// What those bits let any user do, as a refusal says it.
    acts: &'static str,
    /// The command that clears those bits.
    mend: &'static str,
}

/// The mode bit that lets any user write a file.
#[cfg(unix)]
const WRITE_BY_ANY_USER: Reach = Reach {
    bits: 0o002,
    acts: "written",
    mend: "chmod o-w",
};

/// The mode bits that let any user read or write a file.
#[cfg(unix)]
const READ_OR_WRITE_BY_ANY_USER: Reach = Reach {
    bits: 0o006,
    acts: "read or written",
    mend: "chmod o-rw",
};

/// The command that removes a file's access control list.
#[cfg(target_os = "macos")]
const ACCESS_CONTROL_LIST_MEND: &str = "chmod -N";
/// The command that removes a file's access control list.
#[cfg(all(unix, not(target_os = "macos")))]
const ACCESS_CONTROL_LIST_MEND: &str = "setfacl -b";

/// The extended attribute a Linux file system keeps a file's POSIX access
/// ACL in. A list the mode alone can say is not kept, so a file that has
/// this attribute carries an entry its mode does not show.
#[cfg(any(target_os = "linux", target_os = "android"))]
const POSIX_ACCESS_ACL_ATTRIBUTE: &str = "system.posix_acl_access";

/// A file this server will not read because of who else can reach it. Its
/// text names the file, its mode and the command that mends it, and never
/// repeats a line of the file, so a caller may show it to the owner as it
/// is: the owner route's first-run model setup does (FIX
/// INIT-ADOPTS-UNADMITTED-CONFIG).
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub(crate) struct FileRefused(String);

impl FileRefused {
    /// The refusal `error` carries, under any context a caller added.
    pub(crate) fn of(error: &anyhow::Error) -> Option<&Self> {
        error.downcast_ref()
    }
}

/// The text of the config file at `path`, from one open handle, once that
/// handle's file is admitted: not writable by any user, and its owner's
/// alone when the text sets the issuer key. A refusal ([`FileRefused`])
/// names the file, its mode and the command that mends it, and for the
/// issuer key the line that sets it; it never repeats a value.
pub(crate) fn read_config_file(path: &Path) -> anyhow::Result<String> {
    let Admitted {
        file,
        stored,
        text: raw,
    } = read_admitted(path, Role::Config)?;
    if stored && sets_issuer_key(&raw) {
        credential_file::admit(path, &file).map_err(|refusal| {
            let place = match locate_toml_root_key(&raw, ISSUER_KEY_SETTING) {
                Some(line) => format!(" at line {line}"),
                None => String::new(),
            };
            FileRefused(format!(
                "config file {} sets {ISSUER_KEY_SETTING}{place}, the issuer key, so only the \
                 file's owner may read it (ONEIRON_AUTH_SECRET keeps the key out of the file): \
                 {refusal}",
                path.display()
            ))
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

/// The text of the config file at `path` that a host places for the process
/// it starts (a managed vault's settings file, a relay room's file), from one
/// open handle, once that handle's file is not writable by any user. Such a
/// file never holds the issuer key, so the owner-alone rule of
/// [`read_config_file`] is not asked of it: its host shares it with the
/// process's group. A refusal names the file, its mode and the command that
/// mends it; it never repeats a line of the file.
pub(crate) fn read_host_placed_config_file(path: &Path) -> anyhow::Result<String> {
    read_admitted(path, Role::Config).map(|admitted| admitted.text)
}

/// The text of the credential file at `path` that its host shares with one
/// group (a relay room's locker token), from one open handle, once no user
/// outside that handle's file's owner and group can read or write it, by its
/// mode and with no access control list. A refusal names the file, its mode
/// and the command that mends it; it never repeats the file's text.
pub(crate) fn read_group_shared_credential_file(path: &Path) -> anyhow::Result<String> {
    read_admitted(path, Role::GroupSharedCredential).map(|admitted| admitted.text)
}

/// What a file is to this server, as a refusal names it.
#[derive(Clone, Copy)]
enum Role {
    /// The config file itself: `--config`, `ONEIRON_CONFIG`, the default
    /// path, `--settings-file`, the config `model-workers` reads, a relay
    /// room's file.
    Config,
    /// A file a config refers to.
    Referenced,
    /// A credential its host shares with one group: a relay room's locker
    /// token.
    GroupSharedCredential,
}

impl Role {
    /// The file, as a refusal names it before its path.
    fn noun(self) -> &'static str {
        match self {
            Self::Config => "config file",
            Self::Referenced => "file",
            Self::GroupSharedCredential => "credential file",
        }
    }

    /// Why a file outside users can reach is refused.
    #[cfg_attr(not(unix), allow(dead_code))]
    fn stake(self) -> &'static str {
        match self {
            Self::Config => "it decides what this server serves and whom it trusts",
            Self::Referenced => {
                "the config refers to it for what a model is told, what runs or whom this \
                 server trusts"
            }
            Self::GroupSharedCredential => {
                "it holds a credential its host shares with one group alone"
            }
        }
    }

    /// What users outside the file's owner and group may not do to it.
    #[cfg(unix)]
    fn refused_reach(self) -> Reach {
        match self {
            Self::Config | Self::Referenced => WRITE_BY_ANY_USER,
            Self::GroupSharedCredential => READ_OR_WRITE_BY_ANY_USER,
        }
    }

    /// Whether a file that carries an access control list is refused: one
    /// whose mode shuts out every user outside its owner and group says who
    /// may reach it only without a list. A file any user may read is not
    /// made safer by one, and a list that shares write is its owner's grant,
    /// as a group's write is.
    #[cfg(unix)]
    fn refuses_access_control_list(self) -> bool {
        matches!(self, Self::GroupSharedCredential)
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
/// handle's file keeps out what `role` refuses: any user's write, and for a
/// group-shared credential any user's read too, and any access control list.
fn read_admitted(path: &Path, role: Role) -> anyhow::Result<Admitted> {
    let mut file = File::open(path).with_context(|| unread(path, role))?;
    let metadata = file.metadata().with_context(|| unread(path, role))?;
    let stored = metadata.is_file();
    #[cfg(unix)]
    if stored {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        let reach = role.refused_reach();
        if mode & reach.bits != 0 {
            return Err(FileRefused(format!(
                "{} {} can be {} by any user (mode {:o}), and {}; run `{}` on it",
                role.noun(),
                path.display(),
                reach.acts,
                mode & 0o777,
                role.stake(),
                reach.mend
            ))
            .into());
        }
        if role.refuses_access_control_list()
            && carries_access_control_list(&file)
                .with_context(|| format!("check who can read {} {}", role.noun(), path.display()))?
        {
            return Err(FileRefused(format!(
                "{} {} has an access control list, whose entries can let in users its mode \
                 ({:o}) does not show, and {}; run `{}` on it",
                role.noun(),
                path.display(),
                mode & 0o777,
                role.stake(),
                ACCESS_CONTROL_LIST_MEND
            ))
            .into());
        }
    }
    let mut text = String::new();
    file.read_to_string(&mut text)
        .with_context(|| unread(path, role))?;
    Ok(Admitted { file, stored, text })
}

/// Whether the open `file` carries a POSIX access ACL. A file system that
/// keeps no extended attributes keeps no such list.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn carries_access_control_list(file: &File) -> std::io::Result<bool> {
    use rustix::io::Errno;
    match rustix::fs::fgetxattr(file, POSIX_ACCESS_ACL_ATTRIBUTE, &mut [0u8; 0]) {
        Ok(_) => Ok(true),
        Err(error) if error == Errno::NODATA || error == Errno::NOTSUP => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// Whether the open `file` carries an ACL entry, which macOS never masks by
/// the mode. A list that cannot be read counts as one.
#[cfg(target_os = "macos")]
fn carries_access_control_list(file: &File) -> std::io::Result<bool> {
    Ok(credential_file::has_extended_acl(file))
}

/// Whether the open `file` carries an access control list: none is read on
/// this system, as for a credential file.
#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android", target_os = "macos"))
))]
fn carries_access_control_list(_: &File) -> std::io::Result<bool> {
    Ok(false)
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
