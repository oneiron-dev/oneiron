//! The frozen `git http-backend` invocation: typed request, closed argv/env
//! command, and the running child handle.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use oneiron_base::error::Result;

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
    pub fn advertised_service(&self) -> Option<&'static str> {
        self.query_string.split('&').find_map(|pair| match pair {
            "service=git-upload-pack" => Some("git-upload-pack"),
            "service=git-receive-pack" => Some("git-receive-pack"),
            _ => None,
        })
    }

    pub fn env_pairs(&self) -> Vec<(String, String)> {
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

/// `PATH` is the one inherited value, matching the GitWire baseline. Every
/// other environment key the child sees is assigned, never inherited.
pub fn inherited_path() -> String {
    std::env::var_os("PATH")
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned()
}
