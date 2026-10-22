//! `oneiron files`: the Files world on a stopped vault (FIX 6942), the
//! folders this install keeps searchable on this install only. A running
//! server answers the same at `vault.files.sources.*`.

use std::path::PathBuf;

use clap::{Args, Subcommand};

use crate::config::ServeArgs;

#[derive(Subcommand, Clone, Debug)]
pub enum FilesCommand {
    /// Attach a folder to this install's Files world, opting in on the first
    /// one, and read it; `oneiron serve` rescans it every few minutes from
    /// then on. The world stays on this install: no sealed copy, never synced.
    Attach(Box<FilesAttachArgs>),
    /// Rescan one Files folder now, or every one.
    Rescan(Box<FilesRescanArgs>),
    /// Detach a Files folder: no rescan reads it again. Its notes stay.
    Detach(Box<FilesPathArgs>),
    /// This install's Files world and every Files folder, with its ledger's
    /// counts.
    List(Box<FilesListArgs>),
    /// Every file one Files folder's ledger holds: its readiness, revision
    /// and dates.
    Files(Box<FilesPathArgs>),
}

#[derive(Args, Clone, Debug)]
pub struct FilesAttachArgs {
    /// The folder. Only this path is read: symbolic links under it are never
    /// followed, and nothing is written to it.
    pub path: PathBuf,

    /// Only files whose path under the folder matches (`*` within a name,
    /// `**` across folders, `?` one character). Repeatable; none is every
    /// file.
    #[arg(long)]
    pub include: Vec<String>,

    /// Also never open what matches, by an entry's name or its path under
    /// the folder. Repeatable; added to the default exclusions (hidden
    /// entries, version control, dependency and build folders, credential
    /// stores and key files).
    #[arg(long)]
    pub exclude: Vec<String>,

    /// Drop the default exclusions: only `--exclude` is passed over.
    #[arg(long)]
    pub no_default_exclude: bool,

    /// The note kind of a file whose frontmatter `type` names no kind the
    /// vault knows; `observation` when absent.
    #[arg(long)]
    pub kind: Option<String>,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct FilesRescanArgs {
    /// The Files folder; none rescans every one.
    pub path: Option<PathBuf>,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct FilesPathArgs {
    /// The Files folder.
    pub path: PathBuf,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct FilesListArgs {
    #[command(flatten)]
    pub serve: ServeArgs,
}
