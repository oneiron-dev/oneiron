//! The frozen `git http-backend` invocation: typed request, closed argv/env
//! command, and the running child handle.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use super::paths::{SERVE_QUARANTINE_PREFIX, SERVE_REAP_TIMEOUT, serve_failed};
use crate::error::Result;
use crate::git_wire::GitWireProcessEnv;

/// One CGI request, as typed fields. Every environment value the child sees
/// beyond the closed baseline is built from exactly these. Host authority is
/// deliberately not a request field: trusted hosts use [`super::serve_with_authority`]
/// with a separately obtained lease; neither `remote_user` nor headers mint one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeRequest {
    /// `GET` or `POST`.
    pub method: String,
    /// The path under `GIT_PROJECT_ROOT`, e.g. `/demo.git/info/refs`.
    pub path_info: String,
    /// The raw query string, without the leading `?`.
    pub query_string: String,
    /// The request's content type, when it carries a body.
    pub content_type: Option<String>,
    /// The request's declared length. `None` streams to EOF (chunked upload).
    pub content_length: Option<u64>,
    /// The body's content encoding. A stock client gzips its RPC bodies, and
    /// the backend inflates them only when it is told they are gzipped.
    pub content_encoding: Option<String>,
    /// The negotiated wire protocol version, when the client sent one.
    pub git_protocol: Option<String>,
    /// The registered principal this request authenticated as. It becomes the
    /// reflog identity of anything the push lands.
    pub remote_user: Option<String>,
    /// The peer address, when the transport knows it. Never an authorization
    /// input.
    pub remote_addr: Option<String>,
}

impl ServeRequest {
    /// Whether this request drives `git-receive-pack` — the only shape that
    /// opens a door window and lands refs.
    #[must_use]
    pub fn is_receive_pack(&self) -> bool {
        self.path_info.ends_with("/git-receive-pack")
    }

    /// Whether this request is part of a push: the receive-pack exchange or
    /// the advertisement a push starts with.
    #[must_use]
    pub fn is_push(&self) -> bool {
        self.is_receive_pack()
            || (self.is_ref_advertisement()
                && self.advertised_service() == Some("git-receive-pack"))
    }

    /// Whether this request is the smart-HTTP ref advertisement.
    ///
    /// This is the ONE response that carries a ref list, and therefore the one
    /// response [`Vault::published_origin_refs`](crate::Vault::published_origin_refs) gates.
    #[must_use]
    pub fn is_ref_advertisement(&self) -> bool {
        self.method.eq_ignore_ascii_case("GET")
            && self.path_info.ends_with("/info/refs")
            && self.advertised_service().is_some()
    }

    /// The service a smart advertisement names, if this request is one.
    ///
    /// A `GET /info/refs` with no `service=` is the DUMB protocol: it serves a
    /// file, not a pkt-line ref list, and nothing here touches it.
    fn advertised_service(&self) -> Option<&'static str> {
        self.query_string.split('&').find_map(|pair| match pair {
            "service=git-upload-pack" => Some("git-upload-pack"),
            "service=git-receive-pack" => Some("git-receive-pack"),
            _ => None,
        })
    }

    pub(super) fn env_pairs(&self) -> Vec<(String, String)> {
        let mut pairs = vec![
            ("REQUEST_METHOD".to_owned(), self.method.clone()),
            ("PATH_INFO".to_owned(), self.path_info.clone()),
            ("QUERY_STRING".to_owned(), self.query_string.clone()),
        ];
        if let Some(content_type) = &self.content_type {
            pairs.push(("CONTENT_TYPE".to_owned(), content_type.clone()));
        }
        if let Some(length) = self.content_length {
            pairs.push(("CONTENT_LENGTH".to_owned(), length.to_string()));
        }
        if let Some(encoding) = &self.content_encoding {
            pairs.push(("HTTP_CONTENT_ENCODING".to_owned(), encoding.clone()));
        }
        // `HTTP_GIT_PROTOCOL` is deliberately NOT forwarded, so every served
        // exchange speaks the v0/v1 wire.
        //
        // Protocol v2 moves the ref list out of this response and into an
        // `ls-refs` command inside the RPC body, where it is interleaved with
        // negotiation and cannot be projected through
        // [`Vault::published_origin_refs`]. Advertising v2 and then gating
        // nothing would publish heads this vault has not proved; advertising
        // v2 and gating the GET would leave the client asking `ls-refs` for a
        // list nobody filtered. Declining the version is the only answer that
        // keeps "every advertised ref is a published ref" true, and a stock
        // client that asked for v2 falls back to v0 on its own.
        if let Some(user) = &self.remote_user {
            pairs.push(("REMOTE_USER".to_owned(), user.clone()));
        }
        if let Some(addr) = &self.remote_addr {
            pairs.push(("REMOTE_ADDR".to_owned(), addr.clone()));
        }
        pairs
    }
}

/// The frozen serve invocation: one argv and one closed environment baseline,
/// both fixed at build time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeCommand {
    argv: Vec<String>,
    env: BTreeMap<String, String>,
}

impl ServeCommand {
    /// Builds the one serve invocation: `git -c core.hooksPath=<door dir>
    /// http-backend`, with the pinned git executable as `argv[0]`.
    ///
    /// `core.hooksPath` travels in argv rather than the environment because it
    /// is a git config key; `git -c` gives it command-line precedence and
    /// carries it to every git child the backend spawns, so no repository-local
    /// `hooksPath` and no repository-supplied hook can displace the door's.
    ///
    /// Automatic maintenance, the fsmonitor daemon and the signature
    /// verifiers are pinned off the same way, as GitWire pins them for its
    /// own commands: a push would otherwise start a repack, a daemon or a
    /// signer's agent that detaches and outlives the exchange that started
    /// it, and with it the exchange's permit.
    pub fn http_backend(
        repo_dir: &Path,
        project_root: &Path,
        door_hooks_dir: &Path,
    ) -> Result<Self> {
        let process_env = GitWireProcessEnv::capture()?;
        let hooks = door_hooks_dir
            .to_str()
            .ok_or_else(|| serve_failed("door hooks path must be UTF-8"))?;
        let mut argv = vec![
            path_arg(process_env.git_binary())?,
            "-c".to_owned(),
            format!("core.hooksPath={hooks}"),
        ];
        for pinned in [
            "receive.autogc=false",
            "gc.auto=0",
            "maintenance.auto=false",
            "core.fsmonitor=false",
            "gpg.program=false",
            "gpg.ssh.program=false",
            "gpg.x509.program=false",
        ] {
            argv.extend(["-c".to_owned(), pinned.to_owned()]);
        }
        argv.push("http-backend".to_owned());
        let mut env = BTreeMap::new();
        env.insert("GIT_DIR".to_owned(), path_arg(repo_dir)?);
        env.insert("GIT_PROJECT_ROOT".to_owned(), path_arg(project_root)?);
        env.insert("GIT_HTTP_EXPORT_ALL".to_owned(), "1".to_owned());
        // Reaches receive-pack, the door hook, and every git either of them
        // spawns: the whole serve path reads true object bytes, never a
        // replacement's.
        env.insert("GIT_NO_REPLACE_OBJECTS".to_owned(), "1".to_owned());
        env.insert("PATH".to_owned(), inherited_path());
        Ok(Self { argv, env })
    }

    /// The read-only invocation over a masked copy's bare store (FIX 7608
    /// slice 2b-i): the same pinned git and pinned-off maintenance, fsmonitor
    /// and signers as [`Self::http_backend`], but `http.receivepack=false`
    /// and no door hook, so only `git-upload-pack` answers and nothing is
    /// ever received into a copy. `GIT_NO_REPLACE_OBJECTS` keeps every byte
    /// served the copy's own. No caller yet; the canonical command is
    /// unchanged.
    ///
    /// # Errors
    /// A git executable that cannot be pinned, or a non-UTF-8 path.
    pub(crate) fn http_backend_read_only(copy_dir: &Path, project_root: &Path) -> Result<Self> {
        let process_env = GitWireProcessEnv::capture()?;
        let mut argv = vec![path_arg(process_env.git_binary())?];
        for pinned in [
            "http.receivepack=false",
            "http.uploadpack=true",
            "core.hooksPath=/dev/null",
            "receive.autogc=false",
            "gc.auto=0",
            "maintenance.auto=false",
            "core.fsmonitor=false",
            "gpg.program=false",
            "gpg.ssh.program=false",
            "gpg.x509.program=false",
        ] {
            argv.extend(["-c".to_owned(), pinned.to_owned()]);
        }
        argv.push("http-backend".to_owned());
        let mut env = BTreeMap::new();
        env.insert("GIT_DIR".to_owned(), path_arg(copy_dir)?);
        env.insert("GIT_PROJECT_ROOT".to_owned(), path_arg(project_root)?);
        env.insert("GIT_HTTP_EXPORT_ALL".to_owned(), "1".to_owned());
        env.insert("GIT_NO_REPLACE_OBJECTS".to_owned(), "1".to_owned());
        env.insert("PATH".to_owned(), inherited_path());
        Ok(Self { argv, env })
    }

    /// The frozen argv.
    #[must_use]
    pub fn argv(&self) -> &[String] {
        &self.argv
    }

    /// The closed environment baseline.
    #[must_use]
    pub const fn env(&self) -> &BTreeMap<String, String> {
        &self.env
    }

    /// The exact environment one child receives: the closed baseline plus the
    /// typed CGI request keys. Nothing else reaches the child, because the
    /// spawn clears the ambient environment first.
    #[must_use]
    pub fn child_env(&self, request: &ServeRequest) -> BTreeMap<String, String> {
        let mut env = self.env.clone();
        env.extend(request.env_pairs());
        env
    }

    /// Spawns the backend with piped stdio and a cleared environment, as the
    /// leader of its own process group: `git http-backend` runs the service as
    /// its own child, which holds the same pipes, so ending the exchange ends
    /// the group.
    pub fn spawn(&self, request: &ServeRequest) -> Result<ServeChild> {
        let mut command = oneiron_spawn::command(&self.argv[0]);
        command
            .args(&self.argv[1..])
            .env_clear()
            .envs(self.child_env(request))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let mut child = command.spawn()?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| serve_failed("git http-backend stdin was not piped"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| serve_failed("git http-backend stdout was not piped"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| serve_failed("git http-backend stderr was not piped"))?;
        Ok(ServeChild {
            child,
            stdin: Some(stdin),
            stdout: Some(stdout),
            stderr: Some(stderr),
            ended: None,
            #[cfg(not(unix))]
            killed: false,
        })
    }
}

pub(super) fn path_arg(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| serve_failed("serve path must be UTF-8"))
}

/// `PATH` is the one inherited value, matching the GitWire baseline. Every
/// other environment key the child sees is assigned, never inherited.
fn inherited_path() -> String {
    std::env::var_os("PATH")
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned()
}

/// One running `git http-backend`.
#[derive(Debug)]
pub struct ServeChild {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
    /// How the reaped child ended.
    ended: Option<ExitStatus>,
    /// Whether [`Self::end`] found the child still running. Off Unix a
    /// killed child reports an exit code like any other, so its status
    /// cannot say who ended it.
    #[cfg(not(unix))]
    killed: bool,
}

impl ServeChild {
    /// Takes the request-body sink.
    pub fn take_stdin(&mut self) -> Result<ChildStdin> {
        self.stdin
            .take()
            .ok_or_else(|| serve_failed("git http-backend stdin was already taken"))
    }

    /// Takes the response source.
    pub fn take_stdout(&mut self) -> Result<ChildStdout> {
        self.stdout
            .take()
            .ok_or_else(|| serve_failed("git http-backend stdout was already taken"))
    }

    /// Takes the diagnostic stream.
    pub fn take_stderr(&mut self) -> Result<ChildStderr> {
        self.stderr
            .take()
            .ok_or_else(|| serve_failed("git http-backend stderr was already taken"))
    }

    /// Reaps the child and reports whether it exited cleanly. A child whose
    /// output has ended has `SERVE_REAP_TIMEOUT` to exit; past it, it is
    /// killed and reaped, and the exchange fails.
    pub fn wait(&mut self) -> Result<bool> {
        let deadline = Instant::now() + SERVE_REAP_TIMEOUT;
        let mut pause = Duration::from_millis(1);
        loop {
            if let Some(status) = self.child.try_wait()? {
                self.ended = Some(status);
                return Ok(status.success());
            }
            if Instant::now() >= deadline {
                self.kill();
                return Err(serve_failed(
                    "git http-backend did not exit after its output ended",
                ));
            }
            std::thread::sleep(pause);
            pause = (pause * 2).min(Duration::from_millis(50));
        }
    }

    /// Ends a child whose request could not be completed.
    pub fn kill(&mut self) {
        self.end();
        self.ended = self.child.wait().ok();
    }

    /// Whether the reaped child exited by itself rather than by a signal,
    /// such as the kill an exchange sends. One that had already exited when
    /// it was killed exited by itself.
    pub(super) fn exited_by_itself(&self) -> bool {
        #[cfg(unix)]
        {
            self.ended.is_some_and(|status| status.code().is_some())
        }
        #[cfg(not(unix))]
        {
            self.ended.is_some() && !self.killed
        }
    }

    /// Kills the child and the service it runs without reaping it, from
    /// beside an exchange that is still reading their pipes; [`Self::kill`] or
    /// [`Self::wait`] reaps it.
    pub(super) fn end(&mut self) {
        #[cfg(unix)]
        if let Ok(group) = libc::pid_t::try_from(self.child.id()) {
            // SAFETY: `spawn` started the child as leader of its own process
            // group, and it is not reaped yet, so the group id is still its.
            unsafe {
                libc::kill(-group, libc::SIGKILL);
            }
        }
        // A child that exits by itself between this check and the kill is
        // counted as killed, so its exchange sweeps: the safe side.
        #[cfg(not(unix))]
        if matches!(self.child.try_wait(), Ok(None)) {
            self.killed = true;
        }
        let _ = self.child.kill();
    }
}

impl Drop for ServeChild {
    /// A child its exchange never reaped, because the exchange unwound, is
    /// ended and reaped here: no backend outlives the permit that owns it.
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            self.kill();
        }
    }
}

/// The quarantines a receive-pack's backend makes in the repository's objects
/// directory. Git removes its own as it exits, but not when it is killed:
/// dropping this removes every one that appeared since [`Self::note`], unless
/// the backend exited by itself. Drop it once the backend is reaped and before
/// the repository coordinator is let go, so none of them can belong to
/// another push this process admitted.
pub(super) struct IncomingQuarantines {
    objects: PathBuf,
    before: BTreeSet<OsString>,
    sweep: bool,
}

impl IncomingQuarantines {
    pub(super) fn note(objects: PathBuf) -> Self {
        let before = Self::present(&objects);
        Self {
            objects,
            before,
            sweep: true,
        }
    }

    /// Settles the sweep on how the reaped `backend` ended. One that exited
    /// by itself removed its own quarantine, so anything new beside it is not
    /// this exchange's to remove.
    pub(super) fn settle(&mut self, backend: &ServeChild) {
        self.sweep = !backend.exited_by_itself();
    }

    fn present(objects: &Path) -> BTreeSet<OsString> {
        fs::read_dir(objects)
            .into_iter()
            .flatten()
            .flatten()
            .map(|entry| entry.file_name())
            .filter(|name| {
                name.as_encoded_bytes()
                    .starts_with(SERVE_QUARANTINE_PREFIX.as_bytes())
            })
            .collect()
    }
}

impl Drop for IncomingQuarantines {
    fn drop(&mut self) {
        if !self.sweep {
            return;
        }
        for name in Self::present(&self.objects) {
            if self.before.contains(&name) {
                continue;
            }
            let path = self.objects.join(&name);
            if fs::symlink_metadata(&path).is_ok_and(|meta| meta.is_dir()) {
                let _ = fs::remove_dir_all(&path);
            }
        }
    }
}
