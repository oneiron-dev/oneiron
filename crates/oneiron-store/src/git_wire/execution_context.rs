//! Typed Git invocation context: repository selector and operation policy travel together.

use std::ffi::OsString;
use std::path::Path;

use crate::git_wire::bridge::bridged_verb_index;
use crate::git_wire::failure::invalid;
use crate::git_wire::ids::GitOid;
use crate::git_wire::operation::GitWireOperation;
use oneiron_base::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitExecutionEffect {
    Initialization,
    ContextOnly,
    PersistentConfig,
    AttributeRead,
    AttributeWrite,
    WorktreeAdd,
}

impl GitExecutionEffect {
    pub const fn needs_profile(self) -> bool {
        matches!(
            self,
            Self::AttributeRead | Self::AttributeWrite | Self::WorktreeAdd
        )
    }

    pub const fn creates_worktree(self) -> bool {
        matches!(self, Self::WorktreeAdd)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum GitExecutionContext<'a> {
    /// A local repository root, proven by the GitWire handle before effects;
    /// discovery reads can establish that proof without an effect profile.
    Repository(&'a Path),
    /// The hub's validated private bare scratch repository. Its remote
    /// configuration must persist between fixed config/fetch/read calls.
    HubBare {
        root: &'a Path,
        selector: &'a [OsString],
    },
}

impl GitExecutionContext<'_> {
    pub const fn root(&self) -> &Path {
        match self {
            Self::Repository(root) | Self::HubBare { root, .. } => root,
        }
    }
}

/// `rm -q -f -- <path>` or `rm -q --cached -- <path>`: one quiet removal of
/// one path, from the checkout and index or from the index alone.
pub fn fixed_rm_form(tail: &[String]) -> bool {
    matches!(
        tail,
        [quiet, mode, separator, path]
            if quiet == "-q"
                && (mode == "-f" || mode == "--cached")
                && separator == "--"
                && !path.is_empty()
    )
}
