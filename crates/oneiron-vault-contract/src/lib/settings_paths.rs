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
//! A model directory that lies outside both may lie in the shared model root
//! the supervisor declared instead ([`SharedModelRoot`],
//! `--shared-model-root`): one read-only store per node that no vault's UID
//! can write, so a node keeps one copy of a bundle, not one per vault. It
//! holds each bundle at `<root>/<class>/<stack_sha16>/` and admits only that
//! exact directory, for a [`SHARED_MODEL_PATHS`] field whose settings pin
//! the same stack beside it ([`SHARED_MODEL_STACK`]). From the root down,
//! every part of it is owned by uid 0, writable by no group or other, and a
//! directory or a plain file, never a link. The vault's own roots are
//! checked first, as before, and the shared root admits no other owner path.
//!
//! A supervisor adds its own containment on top: on a vault it hosts, the
//! resolved path [`check_owner_path`] returns with an
//! [`OwnerPathOrigin::Vault`] origin must also lie in that vault's own
//! storage; one with an [`OwnerPathOrigin::SharedModel`] origin lies in the
//! node's store. For a vault VM it checks the guest path as written first
//! ([`check_owner_path_lexical`]), then maps it onto the vault's storage by
//! its [`VM_GUEST_CONFIG_DIR`](crate::vm::VM_GUEST_CONFIG_DIR) or
//! [`VM_GUEST_DATA_DIR`](crate::vm::VM_GUEST_DATA_DIR) parts, never by a
//! string prefix, before it resolves anything.
//!
//! [`SETTINGS_PATHS_REVISION`] names this list and rule. A vault reports it
//! on `Ping` (`settings_paths_revision`); one built before it reports none,
//! which a supervisor reads as unknown.

use std::fs::Metadata;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::settings_policy::matches_any;

/// The revision of the owner-path list and rule here, which a vault built
/// with them reports on `Ping` (`settings_paths_revision`). Revision 2 adds
/// the shared model root ([`SharedModelRoot`], FIX 6828).
pub const SETTINGS_PATHS_REVISION: u32 = 2;

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

/// The owner paths a shared model root may hold, as dotted fields, each with
/// the class directory its bundles lie in under that root. Only the
/// Oneironer's are enabled; `embedder`, `reranker` and `llm` are reserved
/// class names, each to be enabled with its own class's identity check.
pub const SHARED_MODEL_PATHS: &[(&str, &str)] = &[
    ("oneironer.model_dir", "oneironer"),
    ("oneironer.tiers.*.model_dir", "oneironer"),
];

/// The key beside a [`SHARED_MODEL_PATHS`] field, in the same table, that
/// pins the stack its bundle serves: under a shared model root, the bundle
/// directory's name.
pub const SHARED_MODEL_STACK: &str = "stack_sha16";

/// The reason token of the notice a vault logs when it ignores the shared
/// model root its supervisor declared, with the cause
/// ([`SharedModelRootIgnored`]).
pub const SHARED_MODEL_ROOT_IGNORED: &str = "shared_model_root_ignored";

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
    /// It lies in the shared model root, but is not, as written, its field's
    /// bundle directory `<root>/<class>/<stack_sha16>`.
    SharedModelLayout,
    /// It is a bundle directory in the shared model root, but the settings
    /// pin no stack beside it, or another stack than its name.
    SharedModelStack,
    /// It is reached through a link into the shared model root, or a part of
    /// that store from the root down through the bundle is not owned by uid
    /// 0, is writable by its group or others, or is neither a directory nor
    /// a plain file.
    SharedModelUnsafe,
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
            Self::SharedModelLayout => "shared_model_layout",
            Self::SharedModelStack => "shared_model_stack",
            Self::SharedModelUnsafe => "shared_model_unsafe",
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

/// Why a vault ignores the shared model root its supervisor declared, in
/// closed names. An ignored root admits nothing, and the vault starts
/// without it: a model directory only it would admit is refused as before.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SharedModelRootIgnored {
    /// The path is not absolute.
    NotAbsolute,
    /// It holds a `..` part.
    ParentComponent,
    /// It holds a part that begins with `~`.
    TildeComponent,
    /// Nothing is there.
    Missing,
    /// It, or a directory above it, did not resolve or read for another
    /// reason than a missing part.
    Unreadable,
    /// It is the filesystem root.
    FilesystemRoot,
    /// It passes through a link: the path as written is not its resolved
    /// path.
    Symlink,
    /// It is not a directory.
    NotDirectory,
    /// It, or a directory above it, is not owned by uid 0.
    NotRootOwned,
    /// It, or a directory above it, is writable by its group or others.
    Writable,
    /// This platform has no owner and mode bits to check.
    Unsupported,
}

impl SharedModelRootIgnored {
    /// The wire spelling, for a log field.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotAbsolute => "not_absolute",
            Self::ParentComponent => "parent_component",
            Self::TildeComponent => "tilde_component",
            Self::Missing => "missing",
            Self::Unreadable => "unreadable",
            Self::FilesystemRoot => "filesystem_root",
            Self::Symlink => "symlink",
            Self::NotDirectory => "not_directory",
            Self::NotRootOwned => "not_root_owned",
            Self::Writable => "writable",
            Self::Unsupported => "unsupported",
        }
    }
}

/// A shared model root a supervisor declared and [`SharedModelRoot::validate`]
/// accepted: an absolute directory that is its own resolved path, owned by
/// uid 0 and writable by no group or other, as is every directory above it,
/// so no vault's UID can write in it or rename a part of its path. The
/// supervisor itself may still write it. It holds model bundles at
/// `<root>/<class>/<stack_sha16>/` ([`SHARED_MODEL_PATHS`]), each checked
/// when a settings file names it, never written by a vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedModelRoot(PathBuf);

impl SharedModelRoot {
    /// Checks a declared root. One that fails is ignored for the cause
    /// returned, never a refused start.
    pub fn validate(declared: &Path) -> Result<Self, SharedModelRootIgnored> {
        check_owner_path_lexical(declared).map_err(|reason| match reason {
            SettingsPathReason::ParentComponent => SharedModelRootIgnored::ParentComponent,
            SettingsPathReason::TildeComponent => SharedModelRootIgnored::TildeComponent,
            _ => SharedModelRootIgnored::NotAbsolute,
        })?;
        let real = declared
            .canonicalize()
            .map_err(|error| match error.kind() {
                ErrorKind::NotFound | ErrorKind::NotADirectory => SharedModelRootIgnored::Missing,
                _ => SharedModelRootIgnored::Unreadable,
            })?;
        if real.parent().is_none() {
            return Err(SharedModelRootIgnored::FilesystemRoot);
        }
        if real.as_path() != declared {
            return Err(SharedModelRootIgnored::Symlink);
        }
        for dir in real.ancestors() {
            let meta =
                std::fs::symlink_metadata(dir).map_err(|_| SharedModelRootIgnored::Unreadable)?;
            if !meta.is_dir() {
                return Err(SharedModelRootIgnored::NotDirectory);
            }
            guarded(&meta)?;
        }
        Ok(Self(real))
    }

    /// The root, resolved.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0
    }

    /// Admits `path`, whose links resolve outside the vault's own roots, as
    /// a bundle directory of `class` in this root: as written, exactly
    /// `<root>/<class>/<stack_sha16>` with no link on the way, named by the
    /// stack the settings pin beside it (`stack`), and guarded from the root
    /// down through every entry of the bundle. One that neither is written
    /// nor resolves under this root is outside, as before.
    fn admit(
        &self,
        class: &str,
        path: &Path,
        stack: Option<&str>,
    ) -> Result<PathBuf, SettingsPathReason> {
        let real = resolve(path)?;
        if !real.starts_with(&self.0) && !path.starts_with(&self.0) {
            return Err(SettingsPathReason::OutsideVault);
        }
        if real.as_path() != path {
            return Err(SettingsPathReason::SharedModelUnsafe);
        }
        let class_dir = self.0.join(class);
        let name = real.file_name().and_then(std::ffi::OsStr::to_str);
        if real.parent() != Some(class_dir.as_path()) || !name.is_some_and(is_sha16) {
            return Err(SettingsPathReason::SharedModelLayout);
        }
        if stack != name {
            return Err(SettingsPathReason::SharedModelStack);
        }
        for dir in [self.0.as_path(), class_dir.as_path()] {
            let meta =
                std::fs::symlink_metadata(dir).map_err(|_| SettingsPathReason::Unreadable)?;
            guarded_part(&meta, false)?;
        }
        guarded_tree(&real)?;
        Ok(real)
    }
}

/// The roots an owner path may lie under ([`owner_roots`]): the vault's own
/// data and configuration directories, and the shared model root its
/// supervisor declared, when one was accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerRoots {
    vault: Vec<PathBuf>,
    shared_model: Option<SharedModelRoot>,
}

/// The roots an owner path may lie under: the vault's data directory and the
/// settings file's own directory, links resolved, and for the
/// [`SHARED_MODEL_PATHS`] alone the shared model root `shared_model`, when
/// [`SharedModelRoot::validate`] accepted one. A directory that does not
/// exist yet, or is the filesystem root, holds no owner path.
#[must_use]
pub fn owner_roots(
    data_dir: &Path,
    settings_dir: Option<&Path>,
    shared_model: Option<SharedModelRoot>,
) -> OwnerRoots {
    let vault = [Some(data_dir), settings_dir]
        .into_iter()
        .flatten()
        .filter_map(|dir| dir.canonicalize().ok())
        .filter(|dir| dir.parent().is_some())
        .collect();
    OwnerRoots {
        vault,
        shared_model,
    }
}

/// Which root admitted an owner path ([`check_owner_path`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerPathOrigin {
    /// The vault's data directory or the settings file's own directory.
    Vault,
    /// The shared model root: a bundle directory in the node's read-only
    /// store, outside the vault's own storage.
    SharedModel,
}

/// An owner path the rule admitted: where it resolves, and which root
/// admitted it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerPath {
    /// The path resolved, links and all.
    pub path: PathBuf,
    /// The root it lies under.
    pub origin: OwnerPathOrigin,
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

/// The whole rule for one owner path, which the dotted `field` names one key
/// per part: [`check_owner_path_lexical`], then the path resolved, links and
/// all, under the vault's data or configuration directory. Only a path that
/// resolves outside them, for a [`SHARED_MODEL_PATHS`] field, is tried in
/// the shared model root, with `stack` the value the settings pin beside it
/// ([`SHARED_MODEL_STACK`]). Returns the resolved path and the root that
/// admitted it, for a supervisor to check its own containment on a
/// [`OwnerPathOrigin::Vault`] path part by part ([`Path::starts_with`]).
pub fn check_owner_path<S: AsRef<str>>(
    field: &[S],
    path: &Path,
    stack: Option<&str>,
    roots: &OwnerRoots,
) -> Result<OwnerPath, SettingsPathReason> {
    match check_vault_path(path, &roots.vault) {
        Ok(path) => Ok(OwnerPath {
            path,
            origin: OwnerPathOrigin::Vault,
        }),
        Err(SettingsPathReason::OutsideVault) => {
            let class = SHARED_MODEL_PATHS
                .iter()
                .find(|(pattern, _)| matches_any(field, &[*pattern]))
                .map(|&(_, class)| class);
            match (class, &roots.shared_model) {
                (Some(class), Some(root)) => root.admit(class, path, stack).map(|path| OwnerPath {
                    path,
                    origin: OwnerPathOrigin::SharedModel,
                }),
                _ => Err(SettingsPathReason::OutsideVault),
            }
        }
        Err(reason) => Err(reason),
    }
}

/// The rule's first part, unchanged by the shared model root: the path as
/// written, then resolved, links and all, under one of the vault's own
/// `roots`.
fn check_vault_path(path: &Path, roots: &[PathBuf]) -> Result<PathBuf, SettingsPathReason> {
    check_owner_path_lexical(path)?;
    let real = resolve(path)?;
    if roots.iter().any(|root| real.starts_with(root)) {
        Ok(real)
    } else {
        Err(SettingsPathReason::OutsideVault)
    }
}

/// `path` with its links resolved, or why it does not resolve.
fn resolve(path: &Path) -> Result<PathBuf, SettingsPathReason> {
    path.canonicalize().map_err(|error| match error.kind() {
        ErrorKind::NotFound | ErrorKind::NotADirectory => SettingsPathReason::Missing,
        _ => SettingsPathReason::Unreadable,
    })
}

/// Whether `name` is a stack: 16 lowercase hex digits.
fn is_sha16(name: &str) -> bool {
    name.len() == 16
        && name
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Every entry of the bundle at `bundle`, itself included, read without
/// following a link: [`guarded_part`], a directory or a plain file. No
/// depth or count bounds the walk; the store's owner writes the bundle.
fn guarded_tree(bundle: &Path) -> Result<(), SettingsPathReason> {
    let meta = std::fs::symlink_metadata(bundle).map_err(|_| SettingsPathReason::Unreadable)?;
    guarded_part(&meta, false)?;
    let mut pending = vec![bundle.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).map_err(|_| SettingsPathReason::Unreadable)? {
            let entry = entry.map_err(|_| SettingsPathReason::Unreadable)?;
            // An entry's metadata is the entry's own: a link is not followed.
            let meta = entry
                .metadata()
                .map_err(|_| SettingsPathReason::Unreadable)?;
            guarded_part(&meta, true)?;
            if meta.is_dir() {
                pending.push(entry.path());
            }
        }
    }
    Ok(())
}

/// One part of a shared model store, as its own metadata reads: a directory,
/// or a plain file where `file` allows one, never a link or another kind,
/// and [`guarded`].
fn guarded_part(meta: &Metadata, file: bool) -> Result<(), SettingsPathReason> {
    let kind = meta.file_type();
    if !(kind.is_dir() || (file && kind.is_file())) {
        return Err(SettingsPathReason::SharedModelUnsafe);
    }
    guarded(meta).map_err(|_| SettingsPathReason::SharedModelUnsafe)
}

/// Owned by uid 0 and writable by no group or other, so no vault's UID can
/// write it. On Linux a POSIX ACL's mask stands in the group bits, so the
/// mode caps every named entry of the ACL too.
#[cfg(unix)]
fn guarded(meta: &Metadata) -> Result<(), SharedModelRootIgnored> {
    use std::os::unix::fs::MetadataExt as _;
    if meta.uid() != 0 {
        Err(SharedModelRootIgnored::NotRootOwned)
    } else if meta.mode() & 0o022 != 0 {
        Err(SharedModelRootIgnored::Writable)
    } else {
        Ok(())
    }
}

/// No owner and mode bits to check here, so nothing is guarded.
#[cfg(not(unix))]
fn guarded(_meta: &Metadata) -> Result<(), SharedModelRootIgnored> {
    Err(SharedModelRootIgnored::Unsupported)
}
