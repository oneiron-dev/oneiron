//! `oneiron api …` — the bash/curl lane of the packaging ladder.
//!
//! This module is a façade, deliberately: it maps five short commands onto
//! routes the server already serves, hands the request to the host's `curl`
//! (7.76 or newer, the release that added `--fail-with-body`), and gets out of
//! the way. It adds no endpoint, no authority model, no response parsing, no
//! retry, and no cache, so what a caller reads on stdout is what the server
//! sent — a wire error stays a wire error.
//!
//! Two properties are load-bearing and are pinned by tests rather than left to
//! reviewer memory:
//!
//! * The credential travels through curl's config channel on the child's
//!   stdin. It is never an argument, so it cannot leak through `ps`, a shell
//!   history, or a process-listing log line, and it is never written to disk.
//!   A request BODY goes the other way — into a 0600 temporary file that is
//!   removed when the call ends. This process reads that body into memory
//!   first, so a body is bounded by the memory this process has; the RESPONSE
//!   is what streams, and it never passes through this process at all.
//! * Nothing here is evaluated as shell text. `@FILE` is opened by this
//!   process, `-` is this process reading stdin, and any other `--data` value
//!   is sent verbatim. No shell is spawned at any point.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::cli::{ApiArgs, ApiCommand};

/// `--silent` drops the progress meter, `--show-error` keeps the diagnostic,
/// and `--fail-with-body` is what makes a 4xx or 5xx both VISIBLE and
/// non-zero: the server's error body still reaches stdout, and the process
/// still fails. It says nothing about a 3xx — no `--location` is passed here,
/// so a redirect arrives as its own response and exits zero — and it needs
/// curl 7.76 or newer, the release that added the flag.
pub(crate) const CURL_FLAGS: [&str; 3] = ["--silent", "--show-error", "--fail-with-body"];

/// curl reads the host's own config (`$CURL_HOME/.curlrc`, the XDG location,
/// or `~/.curlrc`) BEFORE the flags above, and it reads it EVEN WHEN
/// `--config` is given. A line in that file can add a second transfer, to any
/// host, which would then be handed the credential this process puts on the
/// config channel. `-q` refuses that file, and curl honours it only as the
/// FIRST argument — which is why it is a separate constant applied before
/// [`CURL_FLAGS`] rather than a fourth entry inside it.
pub(crate) const CURL_DISABLE_HOST_CONFIG: &str = "-q";

/// The host's curl. There is no HTTP client dependency in this crate's CLI on
/// purpose: a second HTTP stack would be a second set of defaults to explain.
const CURL_PROGRAM: &str = "curl";

const JSON_CONTENT_TYPE: &str = "application/json";

/// One resolved request. `method`/`url` are already validated against the
/// configured origin; `body` is already read from wherever the caller named;
/// `content_type` is either this module's own JSON default or a media type the
/// caller named and this module validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CurlRequest {
    pub(crate) method: String,
    pub(crate) url: String,
    pub(crate) body: Option<Vec<u8>>,
    pub(crate) content_type: Option<String>,
}

pub async fn api(args: ApiArgs) -> anyhow::Result<()> {
    let secret_env = &args.secret_env;
    // An ABSENT credential is a request without one, not an error: the server
    // serves public routes (`/api/health`) and can be configured to allow
    // unauthenticated access, and a placeholder bearer would be an auth
    // ATTEMPT the server refuses rather than the anonymous call that works.
    let secret = match std::env::var(secret_env) {
        Ok(secret) => Some(secret),
        Err(std::env::VarError::NotPresent) => None,
        // A set-but-unreadable credential is a misconfiguration, not an
        // anonymous request. The error's own Display would quote the value, so
        // this names the variable instead.
        Err(std::env::VarError::NotUnicode(_)) => {
            anyhow::bail!("{secret_env} is not valid UTF-8; nothing was sent")
        }
    };
    let request = request_for_command(&args.base_url, args.command)?;
    run_curl(&request, secret.as_deref())
}

/// Map a short command onto an EXISTING route. Every URL is built from the
/// configured origin plus a literal path this function owns, with caller text
/// percent-encoded into it — a caller value can therefore not add a path
/// segment, a query parameter, or a host.
pub(crate) fn request_for_command(
    base_url: &str,
    command: ApiCommand,
) -> anyhow::Result<CurlRequest> {
    let base = normalized_base(base_url)?;

    match command {
        ApiCommand::Discover => Ok(CurlRequest {
            method: "GET".to_owned(),
            url: format!("{base}/api/core/discover"),
            body: None,
            content_type: None,
        }),
        ApiCommand::Search { query, limit } => {
            let mut url = format!("{base}/api/search/text?query={}", percent_encoded(&query));
            if let Some(limit) = limit {
                url.push_str(&format!("&limit={limit}"));
            }
            Ok(CurlRequest {
                method: "GET".to_owned(),
                url,
                body: None,
                content_type: None,
            })
        }
        ApiCommand::Get { entity_id } => Ok(CurlRequest {
            method: "GET".to_owned(),
            url: format!("{base}/api/entity/{}", percent_encoded(&entity_id)),
            body: None,
            content_type: None,
        }),
        // A shaped verb call is JSON by definition: the route it names accepts
        // nothing else, so the media type is this module's, not the caller's.
        ApiCommand::Call { verb, data } => Ok(CurlRequest {
            method: "POST".to_owned(),
            url: format!("{base}/v1/core/memory/verbs/{}", percent_encoded(&verb)),
            body: Some(read_body(&data)?),
            content_type: Some(JSON_CONTENT_TYPE.to_owned()),
        }),
        // The escape hatch. It exists so this family never becomes a second,
        // hand-maintained copy of the route catalog: an unshaped route is one
        // `raw METHOD PATH` away, still on the same origin and credential.
        ApiCommand::Raw {
            method,
            path,
            data,
            content_type,
        } => {
            let method = validated_method(&method)?;
            let path = validated_path(&path)?;
            let body = match data.as_deref() {
                Some(data) => Some(read_body(data)?),
                None => None,
            };
            // The DEFAULT is unchanged — a body with no declared type is JSON,
            // which is what every route this server registers reads. Naming a
            // type REPLACES that default, so an unshaped wire protocol (Git
            // smart-HTTP, say) is expressible without a second command.
            let content_type = match content_type.as_deref() {
                Some(declared) => Some(validated_content_type(declared)?),
                None => body.is_some().then(|| JSON_CONTENT_TYPE.to_owned()),
            };
            Ok(CurlRequest {
                method,
                url: format!("{base}{path}"),
                body,
                content_type,
            })
        }
    }
}

/// Run one request through the host's curl, streaming the response body to
/// this process's own stdout untouched.
pub(crate) fn run_curl(request: &CurlRequest, secret: Option<&str>) -> anyhow::Result<()> {
    let output = run_curl_output(
        OsStr::new(CURL_PROGRAM),
        request,
        secret,
        Stdio::inherit(),
        Stdio::inherit(),
    )?;
    exit_status_result(&output.status)
}

/// The one execution path, parameterized only by where the child's streams go.
///
/// Production INHERITS both, which is what makes a success body byte-identical:
/// the bytes never pass through this process at all, so there is nothing here
/// that could re-encode, buffer, or truncate them. Tests capture instead, to
/// read exactly what a fake curl was handed.
///
/// `secret` is `None` when the environment names no credential. That sends the
/// request WITHOUT an `Authorization` header — no config channel, no empty
/// header, no placeholder — because a public route answers an anonymous call
/// and refuses a bogus one.
pub(crate) fn run_curl_output(
    program: &OsStr,
    request: &CurlRequest,
    secret: Option<&str>,
    stdout: Stdio,
    stderr: Stdio,
) -> anyhow::Result<Output> {
    let config = match secret {
        Some(secret) => Some(curl_config(secret)?),
        None => None,
    };
    let body = match request.body.as_deref() {
        Some(bytes) => Some(TempBody::create(bytes)?),
        None => None,
    };

    let mut command = Command::new(program);
    // FIRST, before anything else: curl only honours the refusal there.
    command.arg(CURL_DISABLE_HOST_CONFIG);
    command.args(CURL_FLAGS);
    command.arg("--request").arg(&request.method);
    if let Some(content_type) = request.content_type.as_deref() {
        command
            .arg("--header")
            .arg(format!("Content-Type: {content_type}"));
    }
    if let Some(body) = &body {
        command.arg("--data-binary").arg(body.curl_value());
    }
    // The credential rides this channel and only this channel, and the channel
    // exists only when there is a credential to carry.
    if config.is_some() {
        command.arg("--config").arg("-");
    }
    command.arg("--url").arg(&request.url);
    command
        .stdin(if config.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(stdout)
        .stderr(stderr);

    let mut child = command
        .spawn()
        .map_err(|error| anyhow::anyhow!("run {}: {error}", program.to_string_lossy()))?;
    if let Some(config) = &config {
        let mut child_stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("curl stdin channel was not opened"))?;
        // A curl that already refused the request has already closed this
        // channel and already said why on stderr; let its own diagnostic and
        // exit status be the answer rather than replacing them with ours.
        if let Err(error) = child_stdin.write_all(config.as_bytes())
            && error.kind() != io::ErrorKind::BrokenPipe
        {
            return Err(anyhow::anyhow!("hand curl its request config: {error}"));
        }
    }

    child
        .wait_with_output()
        .map_err(|error| anyhow::anyhow!("wait for curl: {error}"))
}

/// curl already reported the failure on stderr and already printed the body;
/// this only decides that the process exits non-zero, and it rewrites neither.
pub(crate) fn exit_status_result(status: &ExitStatus) -> anyhow::Result<()> {
    match status.code() {
        Some(0) => Ok(()),
        Some(code) => anyhow::bail!("curl exited with status {code}"),
        None => anyhow::bail!("curl was terminated by a signal"),
    }
}

/// curl's config-file grammar: one long option per line, value double-quoted
/// with backslash escapes. Refusing a control character keeps a credential
/// from smuggling a second option onto a following line.
pub(crate) fn curl_config(secret: &str) -> anyhow::Result<String> {
    anyhow::ensure!(
        !secret.is_empty(),
        "the configured credential is empty; nothing was sent"
    );
    anyhow::ensure!(
        !secret.chars().any(char::is_control),
        "the configured credential contains a control character; nothing was sent"
    );

    let escaped = secret.replace('\\', "\\\\").replace('"', "\\\"");
    Ok(format!("header = \"Authorization: Bearer {escaped}\"\n"))
}

/// Percent-encode one path segment or query value: everything outside the
/// unreserved set is escaped, so `/`, `?`, `&`, `#`, and `..` in caller text
/// are data rather than structure.
fn percent_encoded(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(char::from(*byte));
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

/// The configured origin, trailing slash removed. A base carrying a query, a
/// fragment, or a PATH is refused because `{base}/api/…` would then mean
/// something other than "this path on that origin": a base of
/// `http://host/prefix` would silently send every shaped command to
/// `/prefix/api/…`, a route this server does not serve. The refusal is the
/// answer rather than stripping the prefix, because a caller who typed one
/// meant something, and quietly sending the request somewhere else is the
/// failure mode this whole module exists to avoid.
fn normalized_base(base_url: &str) -> anyhow::Result<String> {
    let base = base_url.trim_end_matches('/');
    anyhow::ensure!(
        base.starts_with("http://") || base.starts_with("https://"),
        "base URL must be an http(s) origin: {base_url:?}"
    );
    anyhow::ensure!(
        !base.contains(['?', '#', '\\']) && !base.chars().any(char::is_whitespace),
        "base URL must be a plain origin without a query, fragment, or whitespace: {base_url:?}"
    );
    let after_scheme = base.split_once("://").map_or("", |(_, rest)| rest);
    let authority = after_scheme.split('/').next().unwrap_or_default();
    anyhow::ensure!(!authority.is_empty(), "base URL has no host: {base_url:?}");
    anyhow::ensure!(
        authority.len() == after_scheme.len(),
        "base URL must be a plain origin without a path: {base_url:?}"
    );

    Ok(base.to_owned())
}

/// A `raw` path is caller-authored and sent unencoded, so it is checked
/// instead: it must stay on the configured origin. A scheme, a
/// protocol-relative `//host`, a backslash, or a `..` segment would each be a
/// way to leave it.
fn validated_path(path: &str) -> anyhow::Result<&str> {
    anyhow::ensure!(
        path.starts_with('/'),
        "path must start with `/` and stay on the configured origin: {path:?}"
    );
    anyhow::ensure!(
        !path.starts_with("//"),
        "path must not start with `//`: that addresses another host: {path:?}"
    );
    anyhow::ensure!(
        !path.contains("://") && !path.contains('\\'),
        "path must not carry a scheme or a backslash: {path:?}"
    );
    anyhow::ensure!(
        !path.chars().any(|c| c.is_whitespace() || c.is_control()),
        "path must not contain whitespace or control characters: {path:?}"
    );
    anyhow::ensure!(
        !path
            .split(['/', '?', '&', '=', '#'])
            .any(|segment| segment == ".."),
        "path must not climb out of the configured origin with `..`: {path:?}"
    );

    Ok(path)
}

/// A caller-named media type becomes a header VALUE on curl's command line, so
/// it is checked the way every other caller string here is: one printable
/// ASCII `type/subtype` token, with no whitespace or control character to end
/// the line early and no `;` to hang a second directive off the end.
fn validated_content_type(content_type: &str) -> anyhow::Result<String> {
    anyhow::ensure!(
        !content_type.is_empty(),
        "content type must not be empty: {content_type:?}"
    );
    anyhow::ensure!(
        content_type.chars().all(|c| c.is_ascii_graphic()) && !content_type.contains(';'),
        "content type must be one printable ASCII token without whitespace, control characters, or `;` parameters: {content_type:?}"
    );
    anyhow::ensure!(
        content_type.matches('/').count() == 1
            && !content_type.starts_with('/')
            && !content_type.ends_with('/'),
        "content type must be spelled type/subtype: {content_type:?}"
    );

    Ok(content_type.to_owned())
}

/// An alphabetic method cannot be read by curl as an option, however the
/// caller spelled it.
fn validated_method(method: &str) -> anyhow::Result<String> {
    anyhow::ensure!(
        !method.is_empty() && method.chars().all(|c| c.is_ascii_alphabetic()),
        "method must be alphabetic, e.g. GET or POST: {method:?}"
    );

    Ok(method.to_ascii_uppercase())
}

/// `@FILE`, `-`, and literal bytes are three distinct forms, resolved here and
/// never handed to a shell to interpret.
fn read_body(data: &str) -> anyhow::Result<Vec<u8>> {
    if data == "-" {
        let mut buffer = Vec::new();
        io::stdin()
            .lock()
            .read_to_end(&mut buffer)
            .map_err(|error| anyhow::anyhow!("read request body from stdin: {error}"))?;
        return Ok(buffer);
    }

    if let Some(file) = data.strip_prefix('@') {
        anyhow::ensure!(!file.is_empty(), "`--data @FILE` needs a file name");
        return fs::read(file)
            .map_err(|error| anyhow::anyhow!("read request body from {file}: {error}"));
    }

    Ok(data.as_bytes().to_vec())
}

/// A request body reaches curl through a private temporary file rather than
/// the config channel, because the config channel is the credential's and a
/// body may be arbitrary bytes. The file is owner-only and removed on drop.
pub(crate) struct TempBody {
    path: PathBuf,
}

impl TempBody {
    fn create(bytes: &[u8]) -> anyhow::Result<Self> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "oneiron-api-{}-{nanos:x}-{sequence:x}.body",
            std::process::id()
        ));

        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&path)
            .map_err(|error| anyhow::anyhow!("stage the request body: {error}"))?;

        Self::write_staged(path, &mut file, bytes)
    }

    /// The file EXISTS from the moment it is opened, so ownership of the path
    /// moves into `Self` before the first byte is written: a write that fails
    /// part-way then unlinks the partial body through `Drop` instead of
    /// leaving request bytes behind in the temp directory. Writing through a
    /// generic sink is what lets a test take the failing branch on any host.
    pub(crate) fn write_staged<W: Write>(
        path: PathBuf,
        sink: &mut W,
        bytes: &[u8],
    ) -> anyhow::Result<Self> {
        let staged = Self { path };
        sink.write_all(bytes)
            .map_err(|error| anyhow::anyhow!("stage the request body: {error}"))?;

        Ok(staged)
    }

    fn curl_value(&self) -> OsString {
        let mut value = OsString::from("@");
        value.push(&self.path);
        value
    }
}

impl Drop for TempBody {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
