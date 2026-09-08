//! The frozen `git http-backend` invocation: typed request, closed argv/env
//! command, and the running child handle.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};

use super::paths::serve_failed;
use crate::error::Result;
use crate::git_wire::GitWireProcessEnv;

/// One CGI request, as typed fields. Every environment value the child sees
/// beyond the closed baseline is built from exactly these.
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
    pub fn http_backend(
        repo_dir: &Path,
        project_root: &Path,
        door_hooks_dir: &Path,
    ) -> Result<Self> {
        let process_env = GitWireProcessEnv::capture()?;
        let hooks = door_hooks_dir
            .to_str()
            .ok_or_else(|| serve_failed("door hooks path must be UTF-8"))?;
        let argv = vec![
            path_arg(process_env.git_binary())?,
            "-c".to_owned(),
            format!("core.hooksPath={hooks}"),
            "http-backend".to_owned(),
        ];
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

    /// Spawns the backend with piped stdio and a cleared environment.
    pub fn spawn(&self, request: &ServeRequest) -> Result<ServeChild> {
        let mut command = Command::new(&self.argv[0]);
        command
            .args(&self.argv[1..])
            .env_clear()
            .envs(self.child_env(request))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
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

    /// Reaps the child and reports whether it exited cleanly.
    pub fn wait(&mut self) -> Result<bool> {
        Ok(self.child.wait()?.success())
    }

    /// Ends a child whose request could not be completed.
    pub fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
