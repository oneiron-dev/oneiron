//! Fixed outbound push profile for an origin's mirror (ARCH-0068 RA8).
//! https only, no redirects, no proxy, no hooks and no stored credential: the
//! one credential is an `Authorization` header the caller hands this child
//! through its own environment, inside the custody door, and never to config
//! or disk.
use std::process::Command;
use std::time::Duration;

use crate::git_wire::failure::invalid;
use crate::git_wire::failure::uncertain;
use crate::git_wire::ids::GitOid;
use crate::git_wire::ids::GitRefName;
use crate::git_wire::operation::GitWireOperation;
use crate::git_wire::repo::GitWireRepo;
use oneiron_base::error::Result;

/// How long one mirror push may run.
pub const MIRROR_PUSH_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// Captured output bound of one mirror push: porcelain lines, one per ref.
pub const MIRROR_PUSH_MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

/// Refspecs one push child carries; more refs go in further pushes.
pub const MIRROR_PUSH_REFSPECS: usize = 256;

/// Rejected refs named in a failure.
const MIRROR_PUSH_NAMED_REJECTIONS: usize = 8;

/// The credential one mirror push carries. Its `Debug` names nothing.
#[derive(Clone, PartialEq, Eq)]
pub struct MirrorEgress {
    pub authorization: zeroize::Zeroizing<String>,
}

impl MirrorEgress {
    /// The egress of one outbound call carrying `authorization`, the full
    /// header value: an exact publish (FIX 6866) rides this same profile.
    pub fn with_authorization(authorization: &str) -> Self {
        Self {
            authorization: zeroize::Zeroizing::new(format!("Authorization: {authorization}")),
        }
    }
}

impl std::fmt::Debug for MirrorEgress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MirrorEgress(..)")
    }
}

/// The refs a `push --porcelain` run names as rejected (`!` lines), up to
/// [`MIRROR_PUSH_NAMED_REJECTIONS`].
pub fn rejected_refs(stdout: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(stdout)
        .lines()
        .filter_map(|line| line.strip_prefix("!\t"))
        .filter_map(|rest| rest.split('\t').next())
        .filter_map(|spec| spec.rsplit(':').next())
        .take(MIRROR_PUSH_NAMED_REJECTIONS)
        .map(str::to_owned)
        .collect()
}

/// Appends the outbound profile to the closed GitWire policy, never replacing
/// its hook and credential rules.
pub fn configure(command: &mut Command, egress: &MirrorEgress) {
    let policy: [(&str, &str); 12] = [
        ("protocol.https.allow", "always"),
        ("http.followRedirects", "false"),
        ("http.proxy", ""),
        ("http.sslVerify", "true"),
        ("http.lowSpeedLimit", "1024"),
        ("http.lowSpeedTime", "30"),
        // An empty value clears every header the repository names; the
        // credential is the one header left.
        ("http.extraHeader", ""),
        ("http.extraHeader", egress.authorization.as_str()),
        ("push.gpgSign", "false"),
        ("push.followTags", "false"),
        ("push.recurseSubmodules", "no"),
        ("submodule.recurse", "false"),
    ];
    // Git-LFS objects go to the mirror from the vault's own store through
    // the engine's batch client once the refs are out (FIX 919), never
    // through a git-lfs hook.
    command
        .env("GIT_ALLOW_PROTOCOL", "https")
        .env("GIT_PROTOCOL_FROM_USER", "0")
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
        // The push's transport helper and pack-objects die with it.
        command.process_group(0);
    }
}
