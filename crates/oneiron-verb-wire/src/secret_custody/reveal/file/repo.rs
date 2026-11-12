//! Moved from `crates/oneiron/src/secret_custody/reveal/file/repo.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The reach of the owner's grant on a repo file read: the scope the
/// owner's standing answer to one repo file reveal picks (FIX 9236).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RepoFileRevealScope {
    /// This file, until revoked.
    File,
    /// This file, for this task (run) only.
    FileTask,
    /// Every marked file of this repo, until revoked.
    Repo,
    /// Every marked file of this repo, for this task (run) only.
    RepoTask,
}

impl RepoFileRevealScope {
    /// Every scope, the narrowest first: the order a read's bound is tried.
    pub const ALL: [Self; 4] = [Self::FileTask, Self::File, Self::RepoTask, Self::Repo];

    /// The pinned scope word.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::FileTask => "file_task",
            Self::Repo => "repo",
            Self::RepoTask => "repo_task",
        }
    }

    const fn names_file(self) -> bool {
        matches!(self, Self::File | Self::FileTask)
    }

    const fn names_task(self) -> bool {
        matches!(self, Self::FileTask | Self::RepoTask)
    }
}
