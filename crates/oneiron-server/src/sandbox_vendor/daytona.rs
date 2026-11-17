//! Daytona's sandbox API as a [`VendorSandboxClient`] (L8-43): one sandbox
//! per batch run, made from the Daytona snapshot of the step's pinned guest
//! image, driven through Daytona's toolbox proxy, and deleted at the run's
//! end.
//!
//! The owner's key is read at the custody door, bound to `sandbox:daytona`,
//! at the run's first call, and held for the run in memory that is wiped
//! when the client drops. It goes as a bearer token only to the two Daytona
//! bases this client was built with, never to a URL an answer names, and it
//! is scrubbed from every error text.
//!
//! A snapshot fixes a sandbox's resources: the guest holds its program to
//! the budget's processes and to its own memory limit, and the sandbox may
//! have more memory than the budget (FIX [VENDOR-MEM-BUDGET]). The guest
//! image's snapshot is the owner's, named after the image's digest; Daytona
//! cannot show that it holds that image. The sandbox has no network
//! (`networkBlockAll`): a vendor run has no egress (module doc of
//! `VendorBatchBackend`). A sandbox a lost run leaves behind stops after
//! [`AUTO_STOP_MINUTES`] idle minutes and is then deleted by Daytona.

use std::io::{self, Read, Write};
use std::sync::{Mutex, Weak};
use std::time::{Duration, Instant};

use oneiron::Vault;
use oneiron::code_sandbox::microvm::backend_error;
use oneiron::code_sandbox::{SandboxProposalBody, SandboxVendor};
use oneiron::engine_executor::StepCancellation;
use oneiron_agent_runtime::code_sandbox::microvm::{
    VendorCallBound, VendorSandboxClient, VendorSandboxId, VendorSandboxSpec,
};
use reqwest::blocking::{Client, RequestBuilder, Response, multipart};
use serde::Deserialize;
use serde_json::json;
use zeroize::Zeroizing;

/// The one vendor this client reaches.
const VENDOR: SandboxVendor = SandboxVendor::Daytona;
/// The toolbox session every command of a run goes through.
const SESSION: &str = "oneiron-batch";
/// The longest wait for a connection to either base.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// A delete's own bound: it runs after the step's deadline or cancellation
/// too, so it never takes theirs.
const DELETE_TIMEOUT: Duration = Duration::from_secs(60);
/// The first and the longest pause between two polls of a sandbox's state or
/// a command's exit.
const FIRST_POLL: Duration = Duration::from_millis(100);
const LONGEST_POLL: Duration = Duration::from_secs(1);
/// The most characters of an answer's body an error text quotes.
const ERROR_BODY_CHARS: usize = 300;
/// Idle minutes after which Daytona stops a sandbox a lost run left, and
/// then deletes it (`autoDeleteInterval` 0).
const AUTO_STOP_MINUTES: u32 = 15;
/// The bytes one read of a download takes.
const DOWNLOAD_CHUNK: usize = 64 * 1024;

/// Where Daytona's API answers.
#[derive(Debug, Clone)]
pub(crate) struct DaytonaEndpoints {
    /// The control API: `{api}/sandbox`.
    pub(crate) api: String,
    /// The toolbox proxy: `{toolbox}/{sandbox}/files/...` and `/process/...`.
    pub(crate) toolbox: String,
}

impl Default for DaytonaEndpoints {
    fn default() -> Self {
        Self {
            api: "https://app.daytona.io/api".into(),
            toolbox: "https://proxy.app.daytona.io/toolbox".into(),
        }
    }
}

/// One run's client of Daytona, on the owner's key the switch names.
pub(super) struct DaytonaClient {
    vault: Weak<Vault>,
    key_name: String,
    endpoints: DaytonaEndpoints,
    key: Mutex<Option<Zeroizing<String>>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SandboxAnswer {
    id: String,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    error_reason: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CommandStarted {
    cmd_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CommandStatus {
    #[serde(default)]
    exit_code: Option<i32>,
}

fn failed(detail: impl Into<String>) -> oneiron::Error {
    backend_error(VENDOR.backend_name(), detail)
}

/// The time left before `deadline`.
fn remaining(deadline: Instant) -> oneiron::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or_else(|| failed("the step's deadline passed"))
}

/// A path segment from an id an answer named: Daytona's ids are UUIDs, so
/// anything else could reshape the URL it goes into.
fn segment(id: &str) -> oneiron::Result<&str> {
    let plain = !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
    if plain {
        Ok(id)
    } else {
        Err(failed("daytona answered an id that is not a plain name"))
    }
}

/// The command line of `argv` for the session's shell: every argument is a
/// plain word, so nothing in it is shell syntax.
fn command_line(argv: &[&str]) -> oneiron::Result<String> {
    let plain = |arg: &&str| {
        !arg.is_empty()
            && arg
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_./-".contains(&byte))
    };
    if argv.is_empty() || !argv.iter().all(plain) {
        return Err(failed("a vendor command argument is not a plain word"));
    }
    Ok(argv.join(" "))
}

/// The Daytona snapshot of a digest-pinned guest image: built once from the
/// image (`oneiron-guest-<first 12 hex of its digest>`).
fn snapshot_name(guest_image: &str) -> oneiron::Result<String> {
    let digest = guest_image
        .rsplit_once("@sha256:")
        .map(|(_, digest)| digest)
        .filter(|digest| digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| failed("a vendor run needs a digest-pinned guest image"))?;
    Ok(format!("oneiron-guest-{}", &digest[..12]))
}

/// The step's pause before the next poll: at most `wait`, never past the
/// deadline, and refused once the step is cancelled.
fn pause(wait: Duration, bound: VendorCallBound<'_>) -> oneiron::Result<()> {
    std::thread::sleep(wait.min(remaining(bound.deadline)?));
    bound.cancel.check()
}

/// A body reader that stops at the step's cancellation, so an upload ends
/// soon after it.
struct CancellableReader<R> {
    inner: R,
    cancel: StepCancellation,
}

impl<R: Read> Read for CancellableReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.cancel.is_cancelled() {
            return Err(io::Error::other("the step was cancelled"));
        }
        self.inner.read(buf)
    }
}

impl DaytonaClient {
    pub(super) fn new(vault: Weak<Vault>, key_name: String, endpoints: DaytonaEndpoints) -> Self {
        Self {
            vault,
            key_name,
            endpoints,
            key: Mutex::new(None),
        }
    }

    /// The owner's key, read at the custody door at the run's first call.
    fn key(&self) -> oneiron::Result<Zeroizing<String>> {
        let mut held = self
            .key
            .lock()
            .map_err(|_| failed("the daytona key state is poisoned"))?;
        if let Some(key) = held.as_ref() {
            return Ok(Zeroizing::new(key.as_str().to_owned()));
        }
        let vault = self
            .vault
            .upgrade()
            .ok_or_else(|| failed("the vault closed before its vendor run"))?;
        let mut bytes = Zeroizing::new(Vec::new());
        vault
            .inject_secret_at_door(&self.key_name, VENDOR.effector(), &mut |value: &[u8]| {
                // Sized once, so no reallocation leaves an unwiped copy.
                bytes.reserve_exact(value.len());
                bytes.extend_from_slice(value);
                Ok(())
            })
            .map_err(|error| {
                tracing::warn!(%error, secret = %self.key_name, "daytona key not read at the custody door");
                failed(format!(
                    "the owner's Daytona key is not readable at the custody door: {error}"
                ))
            })?;
        let key = std::str::from_utf8(&bytes)
            .map_err(|_| failed("the owner's Daytona key is not text"))?
            .trim();
        if key.is_empty() {
            return Err(failed("the owner's Daytona key is empty"));
        }
        let key = Zeroizing::new(key.to_owned());
        *held = Some(Zeroizing::new(key.as_str().to_owned()));
        Ok(key)
    }

    /// An HTTP client for one call: no redirect, no proxy, so the key goes
    /// to the base it was sent to and nowhere else.
    fn http() -> oneiron::Result<Client> {
        Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .map_err(|_| failed("the daytona HTTP client could not be built"))
    }

    fn sandbox_url(&self, sandbox: &str) -> oneiron::Result<String> {
        Ok(format!(
            "{}/sandbox/{}",
            self.endpoints.api,
            segment(sandbox)?
        ))
    }

    fn toolbox_url(&self, sandbox: &str, rest: &str) -> oneiron::Result<String> {
        Ok(format!(
            "{}/{}/{rest}",
            self.endpoints.toolbox,
            segment(sandbox)?
        ))
    }

    /// Sends one request on the owner's key inside the step's bound, and
    /// keeps only an answer of success.
    fn send(
        request: RequestBuilder,
        key: &str,
        bound: VendorCallBound<'_>,
    ) -> oneiron::Result<Response> {
        bound.cancel.check()?;
        let response = request
            .bearer_auth(key)
            .timeout(remaining(bound.deadline)?)
            .send()
            .map_err(|error| http_failed(error, key))?;
        checked(response, key)
    }

    /// Polls the sandbox until it runs, and opens the run's command session.
    fn start(
        &self,
        http: &Client,
        key: &str,
        sandbox: &str,
        made: SandboxAnswer,
        bound: VendorCallBound<'_>,
    ) -> oneiron::Result<()> {
        let (mut state, mut reason) = (made.state, made.error_reason);
        let mut wait = FIRST_POLL;
        loop {
            match state.as_deref() {
                Some("started") => break,
                Some(failure @ ("error" | "build_failed")) => {
                    let reason = reason
                        .as_deref()
                        .map_or_else(String::new, |reason| scrubbed(reason, key));
                    return Err(failed(format!(
                        "the daytona sandbox ended in {failure}: {reason}"
                    )));
                }
                _ => {}
            }
            pause(wait, bound)?;
            wait = (wait * 2).min(LONGEST_POLL);
            let answer: SandboxAnswer =
                Self::send(http.get(self.sandbox_url(sandbox)?), key, bound)?
                    .json()
                    .map_err(|error| http_failed(error, key))?;
            (state, reason) = (answer.state, answer.error_reason);
        }
        Self::send(
            http.post(self.toolbox_url(sandbox, "process/session")?)
                .json(&json!({ "sessionId": SESSION })),
            key,
            bound,
        )?;
        Ok(())
    }

    fn delete_on(&self, http: &Client, key: &str, sandbox: &str) -> oneiron::Result<()> {
        let response = http
            .delete(self.sandbox_url(sandbox)?)
            .bearer_auth(key)
            .timeout(DELETE_TIMEOUT)
            .send()
            .map_err(|error| http_failed(error, key))?;
        checked(response, key).map(drop)
    }
}

impl VendorSandboxClient for DaytonaClient {
    fn vendor(&self) -> SandboxVendor {
        VENDOR
    }

    fn create(
        &self,
        spec: &VendorSandboxSpec<'_>,
        bound: VendorCallBound<'_>,
    ) -> oneiron::Result<VendorSandboxId> {
        let key = self.key()?;
        let http = Self::http()?;
        let made: SandboxAnswer = Self::send(
            http.post(format!("{}/sandbox", self.endpoints.api))
                .json(&json!({
                    "snapshot": snapshot_name(spec.guest_image)?,
                    "labels": { "oneiron": "batch-run" },
                    "autoStopInterval": AUTO_STOP_MINUTES,
                    "autoDeleteInterval": 0,
                    "networkBlockAll": true,
                })),
            &key,
            bound,
        )?
        .json()
        .map_err(|error| http_failed(error, &key))?;
        let id = VendorSandboxId::new(segment(&made.id)?)?;
        // From here the sandbox is this run's to delete, on any failure.
        if let Err(error) = self.start(&http, &key, id.as_str(), made, bound) {
            if let Err(cleanup) = self.delete_on(&http, &key, id.as_str()) {
                tracing::warn!(error = %cleanup, sandbox = %id.as_str(), "daytona sandbox delete failed");
            }
            return Err(error);
        }
        Ok(id)
    }

    fn upload(
        &self,
        sandbox: &VendorSandboxId,
        path: &str,
        body: &SandboxProposalBody,
        bound: VendorCallBound<'_>,
    ) -> oneiron::Result<()> {
        let key = self.key()?;
        let http = Self::http()?;
        let reader = CancellableReader {
            inner: body.reader(),
            cancel: bound.cancel.clone(),
        };
        // The daemon reads the part named `file`, and only as a file.
        let part = multipart::Part::reader_with_length(reader, body.len()).file_name("upload");
        Self::send(
            http.post(self.toolbox_url(sandbox.as_str(), "files/upload")?)
                .query(&[("path", path)])
                .multipart(multipart::Form::new().part("file", part)),
            &key,
            bound,
        )?;
        Ok(())
    }

    fn execute(
        &self,
        sandbox: &VendorSandboxId,
        argv: &[&str],
        bound: VendorCallBound<'_>,
    ) -> oneiron::Result<i32> {
        let command = command_line(argv)?;
        let key = self.key()?;
        let http = Self::http()?;
        let started: CommandStarted = Self::send(
            http.post(
                self.toolbox_url(sandbox.as_str(), &format!("process/session/{SESSION}/exec"))?,
            )
            .json(&json!({ "command": command, "runAsync": true })),
            &key,
            bound,
        )?
        .json()
        .map_err(|error| http_failed(error, &key))?;
        let status_url = self.toolbox_url(
            sandbox.as_str(),
            &format!(
                "process/session/{SESSION}/command/{}",
                segment(&started.cmd_id)?
            ),
        )?;
        let mut wait = FIRST_POLL;
        loop {
            let status: CommandStatus = Self::send(http.get(&status_url), &key, bound)?
                .json()
                .map_err(|error| http_failed(error, &key))?;
            if let Some(code) = status.exit_code {
                return Ok(code);
            }
            pause(wait, bound)?;
            wait = (wait * 2).min(LONGEST_POLL);
        }
    }

    fn download(
        &self,
        sandbox: &VendorSandboxId,
        path: &str,
        sink: &mut dyn Write,
        bound: VendorCallBound<'_>,
    ) -> oneiron::Result<()> {
        let key = self.key()?;
        let http = Self::http()?;
        let mut response = Self::send(
            http.get(self.toolbox_url(sandbox.as_str(), "files/download")?)
                .query(&[("path", path)]),
            &key,
            bound,
        )?;
        let mut chunk = vec![0; DOWNLOAD_CHUNK];
        loop {
            bound.cancel.check()?;
            let read = response.read(&mut chunk).map_err(|error| {
                failed(format!(
                    "daytona download failed: {}",
                    scrubbed(&error.to_string(), &key)
                ))
            })?;
            if read == 0 {
                return Ok(());
            }
            sink.write_all(&chunk[..read])?;
        }
    }

    fn delete(&self, sandbox: &VendorSandboxId) -> oneiron::Result<()> {
        let key = self.key()?;
        self.delete_on(&Self::http()?, &key, sandbox.as_str())
    }
}

/// `text` with every copy of the key replaced.
fn scrubbed(text: &str, key: &str) -> String {
    text.replace(key, "<key>")
}

/// A failed call, without its URL and without the key.
fn http_failed(error: reqwest::Error, key: &str) -> oneiron::Error {
    failed(format!(
        "daytona call failed: {}",
        scrubbed(&error.without_url().to_string(), key)
    ))
}

/// The answer, when it is a success; else an error quoting the start of its
/// body, without the key.
fn checked(response: Response, key: &str) -> oneiron::Result<Response> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    let mut body = Vec::new();
    let _ = response.take(4096).read_to_end(&mut body);
    let quoted: String = scrubbed(&String::from_utf8_lossy(&body), key)
        .chars()
        .filter(|c| !c.is_control())
        .take(ERROR_BODY_CHARS)
        .collect();
    Err(failed(format!(
        "daytona answered {}: {quoted}",
        status.as_u16()
    )))
}
