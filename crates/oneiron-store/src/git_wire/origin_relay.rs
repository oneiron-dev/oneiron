//! The fixed process profile of an exact publish's Git legs on a served host
//! (ARCH-0069 OSH-3, FIX 19083).
//!
//! Two shapes, each built only by its validated constructor: the READ leg
//! lists one branch, and the PUSH leg pushes one exact commit, each over
//! plain http to the served host's own loopback mirror relay, which sends
//! every exchange through the credential broker. The child carries no
//! credential: the broker alone installs the mirror's. Its one header is the
//! relay's ticket, which the environment carries and the argv never does.
//! It follows no redirect, uses no proxy or credential helper, and keeps
//! signing, tags, submodules and LFS transfer off, appended to the closed
//! GitWire policy (which already keeps hooks off) and never replacing it.
//! The push leg lifts the captured wall-clock bound, as the import legs do
//! (Rule 5): the relay and the broker end a send that makes no progress, and
//! the caller's mirror hold and the process teardown still apply. The read
//! leg keeps its bound. The output bound applies to both.

use std::process::Command;

use crate::git_wire::failure::invalid;
use crate::git_wire::import_fetch::profile::{LOOPBACK, loopback_relay, relay_ticket_header};
use oneiron_base::error::Result;

/// Which leg a profile serves.
#[derive(Clone, Copy, PartialEq, Eq)]
enum OriginRelayLeg {
    /// The read of one branch at the mirror.
    Read,
    /// The one exact push.
    Push,
}

/// One exact publish leg's fixed relay profile. Its `Debug` names the leg
/// only, never the ticket.
#[derive(Clone, PartialEq, Eq)]
pub struct OriginRelayEgress {
    leg: OriginRelayLeg,
    /// The relay ticket's header line.
    ticket: zeroize::Zeroizing<String>,
}

impl std::fmt::Debug for OriginRelayEgress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.leg {
            OriginRelayLeg::Read => "OriginRelayEgress::Read(..)",
            OriginRelayLeg::Push => "OriginRelayEgress::Push(..)",
        })
    }
}

impl OriginRelayEgress {
    /// The read leg's profile, to the loopback `relay_url` only, each request
    /// carrying the relay's `ticket` in the relay ticket header.
    ///
    /// # Errors
    /// A URL that is not a loopback relay, or a ticket that is not one token
    /// of visible ASCII.
    pub fn read(relay_url: &str, ticket: &str) -> Result<Self> {
        Self::new(OriginRelayLeg::Read, relay_url, ticket)
    }

    /// The push leg's profile, to the loopback `relay_url` only, each request
    /// carrying the relay's `ticket` in the relay ticket header.
    ///
    /// # Errors
    /// A URL that is not a loopback relay, or a ticket that is not one token
    /// of visible ASCII.
    pub fn push(relay_url: &str, ticket: &str) -> Result<Self> {
        Self::new(OriginRelayLeg::Push, relay_url, ticket)
    }

    fn new(leg: OriginRelayLeg, relay_url: &str, ticket: &str) -> Result<Self> {
        if relay_url.strip_prefix(LOOPBACK).is_none() {
            return Err(invalid(
                "an exact publish through the broker reaches its loopback mirror relay only",
            ));
        }
        loopback_relay(relay_url)?;
        Ok(Self {
            leg,
            ticket: relay_ticket_header(ticket)?,
        })
    }

    /// Whether this leg's child runs without the captured wall-clock bound:
    /// the push leg's does, so no big push is refused by its size (Rule 5).
    pub const fn lifts_child_bound(&self) -> bool {
        matches!(self.leg, OriginRelayLeg::Push)
    }

    /// Appends this leg's profile to the closed GitWire policy `command`
    /// already carries.
    pub fn configure(&self, command: &mut Command) {
        let policy: [(&str, &str); 11] = [
            ("protocol.http.allow", "always"),
            ("http.followRedirects", "false"),
            ("http.proxy", ""),
            ("credential.helper", ""),
            // An empty value clears every header the repository names; the
            // relay's ticket is the one header left.
            ("http.extraHeader", ""),
            ("http.extraHeader", self.ticket.as_str()),
            ("push.gpgSign", "false"),
            ("push.followTags", "false"),
            ("push.recurseSubmodules", "no"),
            ("submodule.recurse", "false"),
            ("tag.gpgSign", "false"),
        ];
        command
            .env("GIT_ALLOW_PROTOCOL", "http")
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
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            // The leg's transport helper and pack children die with it.
            command.process_group(0);
        }
    }
}
