//! The owner paths of a managed vault's settings file (`--settings-file`):
//! the leaves that name a file or directory the server reads or writes, and
//! the one rule each must pass. The vault checks it at boot, and a supervisor
//! checks the same rule when it takes the file in (FIX 5187), so a file it
//! took in never fails the boot on a path.
//!
//! An owner path is absolute, holds no `..` part and no part that begins
//! with `~`, exists, and once its links are resolved lies under one of the
//! allowed roots: the vault's data directory or the settings file's own
//! directory ([`owner_roots`]). A link that resolves inside a root counts as
//! inside. The bindings a supervisor sets on the file after the check (a
//! guest's container CLI) are not owner paths, and may lie outside.
//!
//! A supervisor adds its own containment on top: on a vault it hosts, the
//! resolved path [`check_owner_path`] returns must also lie in that vault's
//! own storage. For a vault VM it checks the guest path as written first
//! ([`check_owner_path_lexical`]), then maps it onto the vault's storage by
//! its [`VM_GUEST_CONFIG_DIR`](crate::vm::VM_GUEST_CONFIG_DIR) or
//! [`VM_GUEST_DATA_DIR`](crate::vm::VM_GUEST_DATA_DIR) parts, never by a
//! string prefix, before it resolves anything.
//!
//! [`SETTINGS_PATHS_REVISION`] names this list and rule. A vault reports it
//! on `Ping` (`settings_paths_revision`); one built before it reports none,
//! which a supervisor reads as unknown.

use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::settings_policy::matches_any;

/// The revision of the owner-path list and rule here, which a vault built
/// with them reports on `Ping` (`settings_paths_revision`).
pub const SETTINGS_PATHS_REVISION: u32 = 1;

/// The leaves that name a file or directory the server reads or writes, as
/// dotted fields (`*` is any one key). An array's items are its own leaf's.
pub const OWNER_PATHS: &[&str] = &[
    "dict_search_paths",
    "embedder.model_dir",
    "embedder.models_dir",
    "oneironer.model_dir",
    "oneironer.tiers.*.model_dir",
    "backup.dir",
    "import.queue_dir",
    "import.claude_code_root",
    "import.codex_root",
    "import.hook_transcript_roots",
    "failure_signals.candidates.*.instructions_file",
    "device_sync.credential_file",
    "browser.runtime",
    "desktop.runtime",
    "models.prompt_file",
    "models.roles.*.prompt_file",
    "models.roles.*.rungs.prompt_file",
    "models.dreamer.summary_prompt_file",
    "models.dreamer.resident_prompt_file",
    "models.dreamer.task_prompt_file",
    "models.dreamer.person_about_prompt_file",
    "models.code_mode.prompt_package",
    "models.code_mode.check.microsoft_tsc",
    "models.decision_read.recipe",
    "models.voice.extraction_prompt_file",
];

/// The import queue's source roots, as leaves of `[import]`. A queue that is
/// on reads each source the settings give no root at its default root, the
/// session-log folders under HOME, outside the vault
/// ([`queue_reads_default_root`]).
pub const IMPORT_SOURCE_ROOTS: &[&str] = &["claude_code_root", "codex_root"];

/// The code of a supervisor's typed answer refusing one owner path at
/// intake, carried with a [`SettingsPathRefused`].
pub const SETTINGS_PATH_REFUSED: &str = "settings_path_refused";

/// Why an owner path is refused, in closed names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettingsPathReason {
    /// The path is not absolute.
    NotAbsolute,
    /// It holds a `..` part.
    ParentComponent,
    /// It holds a part that begins with `~`.
    TildeComponent,
    /// Nothing is there.
    Missing,
    /// It did not resolve for another reason than a missing part: a
    /// permission, a link loop or another I/O failure.
    Unreadable,
    /// It resolves outside every allowed root.
    OutsideVault,
}

impl SettingsPathReason {
    /// The wire spelling, for a log field.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotAbsolute => "not_absolute",
            Self::ParentComponent => "parent_component",
            Self::TildeComponent => "tilde_component",
            Self::Missing => "missing",
            Self::Unreadable => "unreadable",
            Self::OutsideVault => "outside_vault",
        }
    }
}

/// One owner path a supervisor refused at intake, as its typed answer
/// ([`SETTINGS_PATH_REFUSED`]) names it: the dotted field, the path as the
/// settings file wrote it, and why. Never the file's bytes or another
/// setting's value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingsPathRefused {
    /// The dotted field, as `models.roles.writer.prompt_file`.
    pub field: String,
    /// The path as the settings file wrote it.
    pub path: String,
    /// Why it was refused.
    pub reason: SettingsPathReason,
}

/// Whether `field`, a dotted field given one key per part, is one of the
/// [`OWNER_PATHS`].
#[must_use]
pub fn is_owner_path<S: AsRef<str>>(field: &[S]) -> bool {
    matches_any(field, OWNER_PATHS)
}

/// Whether an import queue would read a source's default root: the queue is
/// on (`import.queue = true`), and `[import]` sets one of the
/// [`IMPORT_SOURCE_ROOTS`] not (`names(leaf)` is false). A managed vault
/// refuses that queue as `import.queue`, outside the vault.
#[must_use]
pub fn queue_reads_default_root(queue: bool, names: impl Fn(&str) -> bool) -> bool {
    queue && !IMPORT_SOURCE_ROOTS.iter().all(|&leaf| names(leaf))
}

/// The roots an owner path may lie under: the vault's data directory and the
/// settings file's own directory, links resolved. One that does not exist
/// yet, or is the filesystem root, holds no owner path.
#[must_use]
pub fn owner_roots(data_dir: &Path, settings_dir: Option<&Path>) -> Vec<PathBuf> {
    [Some(data_dir), settings_dir]
        .into_iter()
        .flatten()
        .filter_map(|dir| dir.canonicalize().ok())
        .filter(|dir| dir.parent().is_some())
        .collect()
}

/// The part of the rule that reads the path as written: absolute, with no
/// `..` part and no part that begins with `~`. It touches no filesystem.
pub fn check_owner_path_lexical(path: &Path) -> Result<(), SettingsPathReason> {
    if !path.is_absolute() {
        return Err(SettingsPathReason::NotAbsolute);
    }
    for part in path.components() {
        match part {
            Component::ParentDir => return Err(SettingsPathReason::ParentComponent),
            Component::Normal(name) if name.as_encoded_bytes().starts_with(b"~") => {
                return Err(SettingsPathReason::TildeComponent);
            }
            _ => {}
        }
    }
    Ok(())
}

/// The whole rule for one owner path: [`check_owner_path_lexical`], then the
/// path resolved, links and all, under one of `roots` ([`owner_roots`]).
/// Returns the resolved path, for a supervisor to check its own containment
/// on part by part ([`Path::starts_with`]).
pub fn check_owner_path(path: &Path, roots: &[PathBuf]) -> Result<PathBuf, SettingsPathReason> {
    check_owner_path_lexical(path)?;
    let real = path.canonicalize().map_err(|error| match error.kind() {
        ErrorKind::NotFound | ErrorKind::NotADirectory => SettingsPathReason::Missing,
        _ => SettingsPathReason::Unreadable,
    })?;
    if roots.iter().any(|root| real.starts_with(root)) {
        Ok(real)
    } else {
        Err(SettingsPathReason::OutsideVault)
    }
}
