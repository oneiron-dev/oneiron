//! The fixed process profile of an outside import's Git legs (FIX 6871).
//!
//! Three shapes, each built only by its validated constructor: the SOURCE
//! profile fetches an anonymous source over https alone; the SOURCE RELAY
//! profile fetches a bound source over plain http from the invocation's own
//! loopback source relay, which sends each exchange through the credential
//! broker (OSH-3); the RELAY profile pushes over plain http to the
//! invocation's own loopback door relay. None carries a credential: a bound
//! source's stays with the broker. Each pins its scratch root, follows no
//! redirect, uses
//! no proxy, read no ambient home or credential, and keep tags, signing,
//! submodules, hooks and LFS transfer off, appended to the closed GitWire
//! policy and never replacing it. They add no bound of their own and lift
//! the captured wall-clock bound (Rule 5); the output bound still applies.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::git_wire::failure::invalid;
use oneiron_base::error::Result;

/// Which leg a profile serves.
#[derive(Clone, PartialEq, Eq)]
enum ImportLeg {
    /// The anonymous https fetch.
    Source,
    /// The fetch from the loopback source relay: no credential, only the
    /// relay's ticket header line, which the environment carries and the
    /// argv never does.
    SourceRelay { ticket: zeroize::Zeroizing<String> },
    /// The push to the loopback door relay.
    Relay,
}

/// One import leg's fixed profile. Its `Debug` names the leg only: never
/// the credential, never the scratch path.
#[derive(Clone, PartialEq, Eq)]
pub struct ImportProcessProfile {
    root: PathBuf,
    leg: ImportLeg,
}

impl std::fmt::Debug for ImportProcessProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.leg {
            ImportLeg::Source => "ImportProcessProfile::Source(..)",
            ImportLeg::SourceRelay { .. } => "ImportProcessProfile::SourceRelay(..)",
            ImportLeg::Relay => "ImportProcessProfile::Relay(..)",
        })
    }
}

impl ImportProcessProfile {
    /// The anonymous https fetch's profile under the scratch `root`.
    ///
    /// # Errors
    /// A root that is not absolute.
    pub fn source(root: &Path) -> Result<Self> {
        Ok(Self {
            root: pinned_root(root)?,
            leg: ImportLeg::Source,
        })
    }

    /// The door relay push's profile under the scratch `root`, to the
    /// loopback `door_url` only.
    ///
    /// # Errors
    /// A root that is not absolute, or a URL that is not the loopback relay.
    pub fn relay(root: &Path, door_url: &str) -> Result<Self> {
        if door_url.strip_prefix(LOOPBACK).is_none() {
            return Err(invalid(
                "an import push goes to its loopback door relay only",
            ));
        }
        loopback_relay(door_url)?;
        Ok(Self {
            root: pinned_root(root)?,
            leg: ImportLeg::Relay,
        })
    }

    /// The source relay fetch's profile under the scratch `root`, from the
    /// loopback `relay_url` only, each request carrying the relay's
    /// `ticket` in the [`SOURCE_RELAY_TICKET_HEADER`] header. The URL rides
    /// the child's argv, which other local users can read; the ticket rides
    /// its environment only. The child carries no credential: the relay's
    /// broker installs it.
    ///
    /// # Errors
    /// A root that is not absolute, a URL that is not a loopback relay, or
    /// a ticket that is not one token of visible ASCII.
    pub fn source_relay(root: &Path, relay_url: &str, ticket: &str) -> Result<Self> {
        if relay_url.strip_prefix(LOOPBACK).is_none() {
            return Err(invalid(
                "an import fetch through the broker reads its loopback source relay only",
            ));
        }
        loopback_relay(relay_url)?;
        if ticket.is_empty() || !ticket.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
            return Err(invalid("an import source relay ticket is malformed"));
        }
        Ok(Self {
            root: pinned_root(root)?,
            leg: ImportLeg::SourceRelay {
                ticket: zeroize::Zeroizing::new(format!("{SOURCE_RELAY_TICKET_HEADER}: {ticket}")),
            },
        })
    }

    /// Whether this leg's child runs without the captured wall-clock bound.
    /// Always: a bound that kills a big fetch or push refuses work by its
    /// size (Rule 5; CALLS "G7 PR1 import child bound"). The caller's own
    /// cancel and the process teardown still apply, and no stall guard is
    /// added.
    pub const fn lifts_child_bound(&self) -> bool {
        true
    }

    /// Appends this leg's profile to `command`, run at `repo_root`, which
    /// must lie inside the pinned scratch root.
    ///
    /// # Errors
    /// A child root outside the scratch, or a platform without process
    /// groups.
    pub fn configure(&self, command: &mut Command, repo_root: &Path) -> Result<()> {
        if !repo_root.starts_with(&self.root) {
            return Err(invalid(
                "an import leg runs inside its own scratch store only",
            ));
        }
        let mut policy: Vec<(&str, &str)> = vec![
            ("http.followRedirects", "false"),
            ("http.proxy", ""),
            ("http.sslVerify", "true"),
            // An empty value clears every header a config names; a source
            // relay's ticket, when there is one, is the header left.
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
            ImportLeg::Source => {
                policy.push(("protocol.https.allow", "always"));
                "https"
            }
            ImportLeg::SourceRelay { ticket } => {
                policy.push(("protocol.http.allow", "always"));
                policy.push(("http.extraHeader", ticket.as_str()));
                "http"
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
        let offset = crate::git_wire::config::GIT_WIRE_CONFIG_POLICY.len();
        command.env("GIT_CONFIG_COUNT", (offset + policy.len()).to_string());
        for (i, (key, value)) in policy.iter().enumerate() {
            command
                .env(format!("GIT_CONFIG_KEY_{}", offset + i), key)
                .env(format!("GIT_CONFIG_VALUE_{}", offset + i), value);
        }
        own_process_group(command)
    }
}

/// The request header that carries an import source relay's ticket.
pub const SOURCE_RELAY_TICKET_HEADER: &str = "x-oneiron-relay-ticket";

/// The loopback origin an invocation's own relays listen on.
const LOOPBACK: &str = "http://127.0.0.1:";

/// Whether `url` is one plain loopback relay URL: a port and a path, no
/// userinfo, query, fragment, space, backslash or control byte.
fn loopback_relay(url: &str) -> Result<()> {
    let rest = url.strip_prefix(LOOPBACK).unwrap_or_default();
    if rest.is_empty()
        || rest.contains(['@', '?', '#'])
        || rest
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ' || byte == b'\\')
    {
        return Err(invalid("an import relay URL is malformed"));
    }
    Ok(())
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
