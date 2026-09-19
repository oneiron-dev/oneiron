//! Lease-bound worktree remotes. No upstream URL, credential, or helper is copied.

use super::argv::{FrozenGitArgv, os_args};
use super::failure::invalid;
use super::{GitWire, GitWireOperation, GitWireRepo, GitWireResult, lock_repository};
use crate::checkout::lease::CheckoutLeaseAct;
use std::path::Path;

impl GitWire<'_> {
    /// Configures checkout materialization at an origin base such as
    /// `https://host.example/git`. The lease id/epoch becomes part of its URL.
    /// HTTP is permitted only on loopback; userinfo and query fragments are refused.
    pub fn with_checkout_door(mut self, endpoint: &str) -> GitWireResult<Self> {
        let authority = endpoint
            .strip_prefix("https://")
            .or_else(|| endpoint.strip_prefix("http://"))
            .ok_or_else(|| invalid("door endpoint must be HTTP(S)"))?;
        let (host, path) = authority
            .split_once('/')
            .ok_or_else(|| invalid("door endpoint path missing"))?;
        if path != "git"
            || host.is_empty()
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".:-[]".contains(&b))
            || endpoint.starts_with("http://")
                && !(host == "localhost"
                    || host.starts_with("localhost:")
                    || host == "127.0.0.1"
                    || host.starts_with("127.0.0.1:")
                    || host == "[::1]"
                    || host.starts_with("[::1]:"))
        {
            return Err(invalid("door endpoint has unsafe authority or path"));
        }
        self.checkout_door = Some(endpoint.to_owned());
        Ok(self)
    }

    pub(super) fn preflight_checkout_remote(&self, repo: &GitWireRepo) -> GitWireResult<()> {
        if self.checkout_door.is_none() {
            return Ok(());
        }
        let serving_root = crate::origin::smart_http::origin_serving_root(self.vault)?;
        if repo.common_dir().parent() != Some(serving_root.as_path()) {
            return Err(invalid(
                "door checkout requires this vault's origin repository",
            ));
        }
        // A linked worktree inherits common config. Refuse a source carrying
        // remote/credential/include/rewrite config instead of shadowing it:
        // inherited multi-valued pushurl or extraHeader would survive shadowing.
        let config = self.run_read(
            repo,
            &FrozenGitArgv::frozen(
                GitWireOperation::ReadConfig,
                os_args(&["config", "--local", "--null", "--list"]),
            ),
        )?;
        for row in config
            .stdout
            .split(|b| *b == 0)
            .filter(|row| !row.is_empty())
        {
            let key = row.split(|b| *b == b'\n').next().unwrap_or_default();
            let key = String::from_utf8_lossy(key).to_ascii_lowercase();
            if [
                "remote.",
                "credential.",
                "http.",
                "url.",
                "include.",
                "includeif.",
            ]
            .iter()
            .any(|prefix| key.starts_with(prefix))
            {
                return Err(invalid(
                    "door checkout refuses inherited remote or credential configuration",
                ));
            }
        }
        Ok(())
    }

    pub(super) fn configure_checkout_remote(
        &self,
        repo: &GitWireRepo,
        tree: &Path,
        lease: &CheckoutLeaseAct,
    ) -> GitWireResult<()> {
        let Some(base) = &self.checkout_door else {
            return Ok(());
        };
        let _guard = lock_repository(repo.common_dir())?;
        self.preflight_checkout_remote(repo)?;
        let repo_name = repo
            .common_dir()
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_suffix(".git"))
            .ok_or_else(|| invalid("door checkout requires a served bare repository"))?;
        crate::origin::smart_http::validate_repo_name(repo_name)?;
        let url = format!(
            "{base}/lease/{}.{}/{repo_name}.git",
            lease.checkout_id, lease.epoch
        );
        let worktree = self.open_repo(repo.repo_ref().clone(), tree)?;
        self.run_mutation(
            repo,
            &FrozenGitArgv::frozen(
                GitWireOperation::ConfigureCheckout,
                os_args(&["config", "--local", "extensions.worktreeConfig", "true"]),
            ),
        )?;
        for (key, value) in [
            ("core.bare", "false"),
            ("remote.origin.url", url.as_str()),
            ("remote.origin.pushurl", url.as_str()),
            ("credential.helper", ""),
        ] {
            self.run_mutation(
                &worktree,
                &FrozenGitArgv::frozen(
                    GitWireOperation::ConfigureCheckout,
                    os_args(&["config", "--worktree", "--replace-all", key, value]),
                ),
            )?;
        }
        Ok(())
    }
}
