//! Typed Git invocation context: repository selector and operation policy travel together.

use std::ffi::OsString;
use std::path::Path;

use super::argv::FrozenGitArgv;
use super::bridge::bridged_verb_index;
use super::failure::invalid;
use super::{GitOid, GitWireOperation};
use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GitExecutionEffect {
    Initialization,
    ContextOnly,
    PersistentConfig,
    AttributeRead,
    AttributeWrite,
    WorktreeAdd,
}

impl GitExecutionEffect {
    pub(super) const fn needs_profile(self) -> bool {
        matches!(
            self,
            Self::AttributeRead | Self::AttributeWrite | Self::WorktreeAdd
        )
    }

    pub(super) const fn creates_worktree(self) -> bool {
        matches!(self, Self::WorktreeAdd)
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) enum GitExecutionContext<'a> {
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
    pub(super) const fn root(&self) -> &Path {
        match self {
            Self::Repository(root) | Self::HubBare { root, .. } => root,
        }
    }
}

pub(super) struct GitCommandSpec<'a> {
    context: GitExecutionContext<'a>,
    args: &'a [OsString],
    stdin: Option<&'a [u8]>,
    prefix: &'a [OsString],
    effect: GitExecutionEffect,
    worktree_target: Option<&'a Path>,
    expected_commit: Option<&'a GitOid>,
}

impl<'a> GitCommandSpec<'a> {
    pub(super) fn wire(root: &'a Path, argv: &'a FrozenGitArgv) -> Self {
        let effect = match argv.operation() {
            GitWireOperation::StatusPorcelain => GitExecutionEffect::AttributeRead,
            GitWireOperation::WorktreeAdd => GitExecutionEffect::WorktreeAdd,
            GitWireOperation::ConfigureCheckout => GitExecutionEffect::PersistentConfig,
            _ => GitExecutionEffect::ContextOnly,
        };
        let (worktree_target, expected_commit) = argv
            .worktree_target()
            .map_or((None, None), |(path, commit)| (Some(path), Some(commit)));
        Self {
            context: GitExecutionContext::Repository(root),
            args: argv.args(),
            stdin: argv.stdin(),
            prefix: &[],
            effect,
            worktree_target,
            expected_commit,
        }
    }

    /// `bridged_argv` has already validated the sole accepted global `-c`
    /// identity pairs and every token. The verb list is closed here, not
    /// rediscovered by the generic process launcher.
    pub(super) fn bridge(
        root: &'a Path,
        raw_args: &[String],
        argv: &'a [OsString],
    ) -> Result<Self> {
        let index = bridged_verb_index(raw_args)?;
        let verb = raw_args[index].as_str();
        let effect = match verb {
            "init" => GitExecutionEffect::Initialization,
            "config" | "remote" => GitExecutionEffect::PersistentConfig,
            "worktree" if raw_args.get(index + 1).is_some_and(|arg| arg == "add") => {
                GitExecutionEffect::WorktreeAdd
            }
            "cat-file"
                if raw_args[index + 1..].iter().any(|arg| {
                    matches!(arg.as_str(), "--filters" | "--textconv" | "--batch-command")
                }) =>
            {
                GitExecutionEffect::AttributeRead
            }
            "hash-object"
                if raw_args[index + 1..]
                    .iter()
                    .any(|arg| arg.starts_with("--path")) =>
            {
                GitExecutionEffect::AttributeWrite
            }
            "worktree" | "rev-parse" | "for-each-ref" | "show-ref" | "cat-file" | "hash-object"
            | "mktree" | "commit-tree" | "update-ref" | "notes" | "rev-list" | "merge-base"
            | "merge-tree" | "ls-tree" | "ls-files" | "check-ref-format" | "symbolic-ref"
            | "fsck" | "count-objects" | "pack-refs" | "prune" | "gc" | "branch" => {
                GitExecutionEffect::ContextOnly
            }
            "status" | "diff" | "show" | "log" => GitExecutionEffect::AttributeRead,
            "add" | "commit" | "checkout" | "checkout-index" | "reset" | "restore" | "switch"
            | "merge" | "rebase" | "cherry-pick" | "am" | "apply" | "read-tree"
            | "update-index" => GitExecutionEffect::AttributeWrite,
            _ => return Err(invalid("unsupported bridged Git verb")),
        };
        let worktree_target = if effect.creates_worktree() {
            argv.iter()
                .position(|arg| arg.as_os_str() == std::ffi::OsStr::new("--"))
                .and_then(|position| argv.get(position + 1))
                .map(Path::new)
        } else {
            None
        };
        if effect.creates_worktree() && worktree_target.is_none() {
            return Err(invalid("worktree add path is missing"));
        }
        Ok(Self {
            context: GitExecutionContext::Repository(root),
            args: argv,
            stdin: None,
            prefix: &argv[..index],
            effect,
            worktree_target,
            expected_commit: None,
        })
    }

    /// `hub_read` validates every allowed argv shape before constructing this
    /// typed bare context; no mutable local repository is checked out here.
    pub(super) fn hub(root: &'a Path, args: &'a [OsString], verb: &str) -> Result<Self> {
        let effect = match verb {
            "init" => GitExecutionEffect::Initialization,
            "config" => GitExecutionEffect::PersistentConfig,
            "fetch" | "rev-parse" | "ls-tree" | "cat-file" => GitExecutionEffect::ContextOnly,
            _ => return Err(invalid("unsupported hub Git verb")),
        };
        let prefix = if verb == "init" { &[][..] } else { &args[..1] };
        Ok(Self {
            context: GitExecutionContext::HubBare {
                root,
                selector: prefix,
            },
            args,
            stdin: None,
            prefix,
            effect,
            worktree_target: None,
            expected_commit: None,
        })
    }

    #[cfg(test)]
    pub(super) fn test_raw(
        root: &'a Path,
        args: &'a [OsString],
        effect: GitExecutionEffect,
    ) -> Self {
        Self {
            context: GitExecutionContext::Repository(root),
            args,
            stdin: None,
            prefix: &[],
            effect,
            worktree_target: None,
            expected_commit: None,
        }
    }

    pub(super) const fn context(&self) -> GitExecutionContext<'a> {
        self.context
    }

    pub(super) const fn args(&self) -> &'a [OsString] {
        self.args
    }

    pub(super) const fn stdin(&self) -> Option<&'a [u8]> {
        self.stdin
    }

    pub(super) const fn prefix(&self) -> &'a [OsString] {
        match self.context {
            GitExecutionContext::Repository(_) => self.prefix,
            GitExecutionContext::HubBare { selector, .. } => selector,
        }
    }

    pub(super) const fn effect(&self) -> GitExecutionEffect {
        self.effect
    }

    pub(super) const fn worktree_target(&self) -> Option<&'a Path> {
        self.worktree_target
    }

    pub(super) const fn expected_commit(&self) -> Option<&'a GitOid> {
        self.expected_commit
    }
}
