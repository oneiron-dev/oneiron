//! The fixed process profile of an outside import's Git legs (FIX 6871).
//!
//! Two shapes, each built only by its validated constructor: the SOURCE
//! profile fetches over https alone, with at most one `Authorization`
//! header the custody door handed this call; the RELAY profile pushes over
//! plain http to the invocation's own loopback door relay and carries no
//! credential at all. Both pin their scratch root, follow no redirect, use
//! no proxy, read no ambient home or credential, and keep tags, signing,
//! submodules, hooks and LFS transfer off, appended to the closed GitWire
//! policy and never replacing it. They add no bound of their own and lift
//! the captured wall-clock bound (Rule 5); the output bound still applies.

use std::path::{Path, PathBuf};
use std::process::Command;

use super::super::failure::invalid;
use crate::error::Result;

/// Which leg a profile serves.
#[derive(Clone, PartialEq, Eq)]
enum ImportLeg {
    /// The https fetch, with the full header line when a binding gave one.
    Source {
        header: Option<zeroize::Zeroizing<String>>,
    },
    /// The push to the loopback door relay.
    Relay,
}

/// One import leg's fixed profile. Its `Debug` names the leg only: never
/// the credential, never the scratch path.
#[derive(Clone, PartialEq, Eq)]
pub(in crate::git_wire) struct ImportProcessProfile {
    root: PathBuf,
    leg: ImportLeg,
}

impl std::fmt::Debug for ImportProcessProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.leg {
            ImportLeg::Source { .. } => "ImportProcessProfile::Source(..)",
            ImportLeg::Relay => "ImportProcessProfile::Relay(..)",
        })
    }
}

impl ImportProcessProfile {
    /// The https fetch's profile under the scratch `root`, carrying
    /// `authorization` (the complete header value) when given.
    ///
    /// # Errors
    /// A root that is not absolute, or a credential that is empty or holds
    /// a control byte.
    pub(in crate::git_wire) fn source(root: &Path, authorization: Option<&str>) -> Result<Self> {
        let header = match authorization {
            None => None,
            Some(value) => {
                if value.trim().is_empty() || value.bytes().any(|byte| byte.is_ascii_control()) {
                    return Err(invalid(
                        "an import binding must be one Authorization header value",
                    ));
                }
                Some(zeroize::Zeroizing::new(format!("Authorization: {value}")))
            }
        };
        Ok(Self {
            root: pinned_root(root)?,
            leg: ImportLeg::Source { header },
        })
    }

    /// The door relay push's profile under the scratch `root`, to the
    /// loopback `door_url` only.
    ///
    /// # Errors
    /// A root that is not absolute, or a URL that is not the loopback relay.
    pub(in crate::git_wire) fn relay(root: &Path, door_url: &str) -> Result<Self> {
        let Some(rest) = door_url.strip_prefix("http://127.0.0.1:") else {
            return Err(invalid("an import push goes to its loopback door relay only"));
        };
        if rest.is_empty()
            || rest.contains(['@', '?', '#'])
            || rest
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b' ' || byte == b'\\')
        {
            return Err(invalid("an import door relay URL is malformed"));
        }
        Ok(Self {
            root: pinned_root(root)?,
            leg: ImportLeg::Relay,
        })
    }

    /// Whether this leg's child runs without the captured wall-clock bound.
    /// Always: a bound that kills a big fetch or push refuses work by its
    /// size (Rule 5; CALLS "G7 PR1 import child bound"). The caller's own
    /// cancel and the process teardown still apply, and no stall guard is
    /// added.
    pub(in crate::git_wire) const fn lifts_child_bound(&self) -> bool {
        true
    }

    /// Appends this leg's profile to `command`, run at `repo_root`, which
    /// must lie inside the pinned scratch root.
    ///
    /// # Errors
    /// A child root outside the scratch, or a platform without process
    /// groups.
    pub(in crate::git_wire) fn configure(
        &self,
        command: &mut Command,
        repo_root: &Path,
    ) -> Result<()> {
        if !repo_root.starts_with(&self.root) {
            return Err(invalid("an import leg runs inside its own scratch store only"));
        }
        let mut policy: Vec<(&str, &str)> = vec![
            ("http.followRedirects", "false"),
            ("http.proxy", ""),
            ("http.sslVerify", "true"),
            // An empty value clears every header a config names; the one
            // credential, when there is one, is the header left.
            ("http.extraHeader", ""),
            ("credential.helper", ""),
            ("submodule.recurse", "false"),
            ("fetch.recurseSubmodules", "false"),
            ("fetch.writeCommitGraph", "false"),
            ("push.gpgSign", "false"),
            ("push.followTags", "false"),
            ("push.recurseSubmodules", "no"),
            ("tag.gpgSign", "false"),
        ];
        let protocol = match &self.leg {
            ImportLeg::Source { header } => {
                policy.push(("protocol.https.allow", "always"));
                if let Some(header) = header {
                    policy.push(("http.extraHeader", header.as_str()));
                }
                "https"
            }
            ImportLeg::Relay => {
                policy.push(("protocol.http.allow", "always"));
                "http"
            }
        };
        command
            .env("HOME", &self.root)
            .env("XDG_CONFIG_HOME", &self.root)
            .env("GIT_ALLOW_PROTOCOL", protocol)
            .env("GIT_PROTOCOL_FROM_USER", "0")
            .env("GIT_LFS_SKIP_SMUDGE", "1")
            .env("GIT_LFS_SKIP_PUSH", "1");
        let offset = super::super::GIT_WIRE_CONFIG_POLICY.len();
        command.env("GIT_CONFIG_COUNT", (offset + policy.len()).to_string());
        for (i, (key, value)) in policy.iter().enumerate() {
            command
                .env(format!("GIT_CONFIG_KEY_{}", offset + i), key)
                .env(format!("GIT_CONFIG_VALUE_{}", offset + i), value);
        }
        own_process_group(command)
    }
}

/// The canonical scratch root a profile pins.
fn pinned_root(root: &Path) -> Result<PathBuf> {
    if !root.is_absolute() {
        return Err(invalid("an import scratch root must be absolute"));
    }
    root.canonicalize()
        .map_err(|_| invalid("an import scratch root does not resolve"))
}

#[cfg(unix)]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the unsupported-platform implementation fails closed through this same signature"
)]
fn own_process_group(command: &mut Command) -> Result<()> {
    use std::os::unix::process::CommandExt;
    // The leg's transport helper and pack children die with it.
    command.process_group(0);
    Ok(())
}

#[cfg(not(unix))]
fn own_process_group(_: &mut Command) -> Result<()> {
    Err(invalid("an import leg needs a host with process groups"))
}
