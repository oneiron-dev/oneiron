//! The hosted vault this user's sign-in selected (H41, ARCH-0028
//! `#plugin-first-run` step 3), as `oneiron hook` reads it and
//! `oneiron hosted` publishes it.
//!
//! One file, `hosted.json` in the per-user oneiron folder beside `hook.toml`,
//! holds every hosted vault this user signed in to here and which one is
//! selected. Each names its origin, its vault id, how a client authenticates
//! there and the file holding that credential, never a credential value. It
//! is written only through [`publish`] (`oneiron hosted login | select |
//! logout`, which the surface the owner signed in on runs to export his
//! selection), whole and owner-only, in one rename. A hook only reads it:
//! a vault that does not answer, a timeout or a failed read never signs
//! anyone out or drops the selection.

use std::io::Read as _;
use std::os::unix::fs::DirBuilderExt as _;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::recall::RecallAuth;
use crate::commands::{credential_file, local_servers};

/// The selection, in the per-user oneiron folder.
const SELECTION_FILE: &str = "hosted.json";
/// A selection is a few hundred bytes a vault; a larger file is not one.
const MAX_READ_BYTES: u64 = 1 << 20;

/// How a client authenticates at a hosted vault, as `oneiron mcp
/// --auth-mode` names it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum HostedAuthMode {
    /// A paired slip, from the file `token agent --out` wrote.
    Slip,
    /// The vault's owner, by the upgrade headers the surface he signed in
    /// on wrote for this vault.
    Owner,
}

/// One hosted vault this user signed in to here: where it answers, which
/// vault it is, and the credential that reaches it, which goes to that
/// origin alone.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct HostedVault {
    /// The origin `oneiron mcp --url` reaches it at.
    pub(super) origin: String,
    /// Its authority vault id, in lowercase hex.
    pub(super) vault_id: String,
    pub(super) auth_mode: HostedAuthMode,
    /// The absolute path of the file `oneiron mcp` reads the credential
    /// from: a paired credential (slip), or the owner's upgrade headers.
    pub(super) credential_file: PathBuf,
    /// When `oneiron hosted login` last saw the origin admit that
    /// credential, in ms since the Unix epoch. A record, never an expiry.
    pub(super) verified_at_ms: u64,
}

impl HostedVault {
    /// Whom a recall from this vault runs as: its own credential, in its
    /// own mode.
    pub(super) fn recall_auth(&self) -> RecallAuth<'_> {
        match self.auth_mode {
            HostedAuthMode::Slip => RecallAuth::Slip(&self.credential_file),
            HostedAuthMode::Owner => RecallAuth::Owner(&self.credential_file),
        }
    }

    /// The vault id's first 12 characters, as a session line names a vault.
    pub(super) fn short_id(&self) -> String {
        self.vault_id.chars().take(12).collect()
    }
}

/// The selection file's body.
#[derive(Debug, Default, Serialize, Deserialize)]
pub(super) struct Selection {
    /// Every hosted vault signed in to here, one per vault id.
    #[serde(default)]
    pub(super) vaults: Vec<HostedVault>,
    /// The vault id of the one selected, if any.
    #[serde(default)]
    pub(super) selected: Option<String>,
}

impl Selection {
    /// The selected vault, when the selection names one signed in to here.
    pub(super) fn selected_vault(&self) -> Option<&HostedVault> {
        let id = self.selected.as_deref()?;
        self.vaults.iter().find(|vault| vault.vault_id == id)
    }

    /// Where this selection stands.
    pub(super) fn discovery(&self) -> HostedDiscovery {
        if self.vaults.is_empty() {
            return HostedDiscovery::NotLoggedIn;
        }
        self.selected_vault()
            .cloned()
            .map_or(HostedDiscovery::NoSelection, HostedDiscovery::Selected)
    }
}

/// What step 3 found (H41).
pub(super) enum HostedDiscovery {
    /// No hosted vault is signed in to here.
    NotLoggedIn,
    /// Hosted vaults are signed in to here, and none is selected.
    NoSelection,
    /// The selected hosted vault.
    Selected(HostedVault),
    /// The selection could not be read, and why. Not proof of no sign-in;
    /// the selection is left as it is.
    Unavailable(String),
}

impl HostedDiscovery {
    /// The state's name, as `oneiron hosted status` prints it.
    pub(super) const fn state(&self) -> &'static str {
        match self {
            Self::NotLoggedIn => "not_logged_in",
            Self::NoSelection => "no_selection",
            Self::Selected(_) => "selected",
            Self::Unavailable(_) => "unavailable",
        }
    }
}

/// The selection file's path.
fn selection_file() -> Option<PathBuf> {
    local_servers::user_dir().map(|dir| dir.join(SELECTION_FILE))
}

/// The selection the file holds, an empty one when there is no file, or
/// why it could not be read. Only a file no one else can write counts, as
/// for the pin: a recall sends the credential it names where it says.
pub(super) fn read() -> Result<Selection, String> {
    let path = selection_file()
        .ok_or_else(|| "there is no per-user oneiron folder (HOME is not set)".to_owned())?;
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Selection::default());
        }
        Err(error) => return Err(format!("{}: {error}", path.display())),
        Ok(_) => {}
    }
    let file = local_servers::open_own(&path)
        .ok_or_else(|| format!("{} is not a file only you can write", path.display()))?;
    let mut body = Vec::new();
    file.take(MAX_READ_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    if body.len() as u64 > MAX_READ_BYTES {
        return Err(format!("{} is too large to be a selection", path.display()));
    }
    // Only where it failed: serde's own message can quote the text.
    serde_json::from_slice(&body).map_err(|error| {
        format!(
            "{} is not a hosted selection (line {}, column {})",
            path.display(),
            error.line(),
            error.column()
        )
    })
}

/// Step 3's answer, as both a session and a prompt ask it.
pub(super) fn discover() -> HostedDiscovery {
    match read() {
        Ok(selection) => selection.discovery(),
        Err(why) => HostedDiscovery::Unavailable(why),
    }
}

/// Writes `selection` whole, owner-only and in one rename: the one helper
/// every sign-in, selection and sign-out goes through. A selection with no
/// vault left removes the file.
pub(super) fn publish(selection: &Selection) -> anyhow::Result<()> {
    let path = selection_file()
        .ok_or_else(|| anyhow::anyhow!("there is no per-user oneiron folder (HOME is not set)"))?;
    if selection.vaults.is_empty() {
        return match std::fs::remove_file(&path) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                Err(anyhow::anyhow!("remove {}: {error}", path.display()))
            }
            _ => Ok(()),
        };
    }
    if let Some(dir) = path.parent() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|error| anyhow::anyhow!("create {}: {error}", dir.display()))?;
    }
    credential_file::replace(&path, &serde_json::to_vec_pretty(selection)?)
}
