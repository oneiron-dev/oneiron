//! Fixed outbound push profile for an origin's mirror (ARCH-0068 RA8).
//! https only, no redirects, no proxy, no hooks and no stored credential: the
//! one credential is an `Authorization` header the caller hands this child
//! through its own environment, inside the custody door, and never to config
//! or disk.
use std::process::Command;
use std::time::Duration;

use super::argv::FrozenGitArgv;
use super::execution_context::GitCommandSpec;
use super::failure::{classify_failure, invalid, uncertain};
use super::process::spawn_git;
use super::{GitOid, GitRefName, GitWire, GitWireOperation, GitWireRepo};
use crate::error::Result;

/// How long one mirror push may run.
pub(super) const MIRROR_PUSH_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// Captured output bound of one mirror push: porcelain lines, one per ref.
pub(super) const MIRROR_PUSH_MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

/// Refspecs one push child carries; more refs go in further pushes.
pub(crate) const MIRROR_PUSH_REFSPECS: usize = 256;

/// Rejected refs named in a failure.
const MIRROR_PUSH_NAMED_REJECTIONS: usize = 8;

/// The credential one mirror push carries. Its `Debug` names nothing.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct MirrorEgress {
    authorization: zeroize::Zeroizing<String>,
}

impl MirrorEgress {
    /// The egress of one outbound call carrying `authorization`, the full
    /// header value: an exact publish (FIX 6866) rides this same profile.
    pub(super) fn with_authorization(authorization: &str) -> Self {
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

impl GitWire<'_> {
    /// Pushes exactly `refs`, forced, to the https mirror at `url` and deletes
    /// exactly `deletions` there. `authorization` is the full header value
    /// (`Basic ...` or `Bearer ...`). A failure carries the class, exit code
    /// and the refs the mirror rejected, never git's diagnostics.
    pub fn push_mirror(
        &self,
        repo: &GitWireRepo,
        url: &str,
        refs: &[(GitRefName, GitOid)],
        deletions: &[GitRefName],
        authorization: &str,
    ) -> Result<()> {
        if !url.starts_with("https://") {
            return Err(invalid("mirror push needs an https URL"));
        }
        if authorization.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(invalid("mirror push authorization holds a control byte"));
        }
        if self.canonical_common_dir(&repo.repo_root)? != repo.common_dir {
            return Err(invalid("git wire repository binding changed"));
        }
        let mut env = self
            .process_env
            .clone()
            .with_limits(MIRROR_PUSH_TIMEOUT, MIRROR_PUSH_MAX_OUTPUT_BYTES)?;
        env.mirror_egress = Some(MirrorEgress {
            authorization: zeroize::Zeroizing::new(format!("Authorization: {authorization}")),
        });
        let batches = refs
            .chunks(MIRROR_PUSH_REFSPECS)
            .map(|chunk| (chunk, &[][..]))
            .chain(
                deletions
                    .chunks(MIRROR_PUSH_REFSPECS)
                    .map(|chunk| (&[][..], chunk)),
            );
        for (pairs, gone) in batches {
            let argv = FrozenGitArgv::mirror_push(url, pairs, gone)?;
            let output = spawn_git(&env, &GitCommandSpec::wire(&repo.repo_root, &argv))?;
            if output.success {
                continue;
            }
            let failure = classify_failure(&output).message(GitWireOperation::MirrorPush);
            let rejected = rejected_refs(&output.stdout);
            return Err(uncertain(if rejected.is_empty() {
                failure
            } else {
                format!("{failure} rejected={}", rejected.join(","))
            }));
        }
        Ok(())
    }
}

/// The refs a `push --porcelain` run names as rejected (`!` lines), up to
/// [`MIRROR_PUSH_NAMED_REJECTIONS`].
fn rejected_refs(stdout: &[u8]) -> Vec<String> {
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
pub(super) fn configure(command: &mut Command, egress: &MirrorEgress) {
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
    let offset = super::GIT_WIRE_CONFIG_POLICY.len();
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
