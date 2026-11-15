//! InstaBox's sandbox API as a [`VendorSandboxClient`] (L8-43): one InstaBox
//! machine per batch run, made from the owner's saved InstaBox snapshot of
//! the step's pinned guest image, driven through InstaBox's v1 API, and
//! deleted at the run's end.
//!
//! The owner's key, read at the custody door bound to `sandbox:instabox` at
//! the run's first call, goes as `X-API-Key` only to the API base this
//! client was built with, and is scrubbed from every error text. The
//! machine gets none of the account's Secrets: no proxy Secret, no env
//! Secret and no Vault delivery. Every create and delete carries an
//! `Idempotency-Key` of its own, as InstaBox requires, and a delete confirms
//! its machine's id.
//!
//! InstaBox boots no OCI image. So the guest image reaches it as a snapshot
//! the owner makes once from the image (`instabox snapshot import`), named
//! `oneiron-guest-<first 12 hex of its digest>` as Daytona's and boat's
//! snapshots and E2B's template are.
//!
//! InstaBox has no egress setting, and every command and file write of its
//! API runs as the machine's own user, who keeps the network. So each
//! command of a run is confined ([`confined`]): as root, it starts in a
//! network namespace of its own, which holds only a loopback device, and
//! then runs as [`GUEST_ID`], a user and group no account of the machine
//! has, with no supplementary group and no way to gain a privilege. The
//! machine user's passwordless sudo, any setuid program, the docker socket,
//! and that user's own processes, home and sessions are then out of its
//! reach, so the guest can neither leave the namespace nor change it, nor
//! leave code for a later command of the machine's user: a vendor run has
//! no egress (module doc of `VendorBatchBackend`). The confinement is made
//! before the command starts, so on a machine where it cannot be made
//! nothing runs and the run fails. A Unix socket a system daemon serves at a
//! path stays reachable, as on boat: FIX [BOAT-GUEST-DAEMON-SOCKETS].
//!
//! A file InstaBox writes belongs to the machine's user, and the guest's own
//! directory refuses that user. So an upload lands first in a file of the
//! client's own, which only the machine's user reads, and root then copies
//! it into place as the guest's file.
//!
//! InstaBox ends a waited command after 10 minutes. So each command starts
//! detached, writes its exit status to a file of its own when it ends, and
//! the client polls that file through the file route, which runs no command
//! on the machine. InstaBox deletes the machine by itself at the step's own
//! time left plus [`LIFETIME_MARGIN`], so a lost run leaves nothing running.

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::sync::Weak;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use oneiron::Vault;
use oneiron::code_sandbox::{SandboxProposalBody, SandboxVendor};
use oneiron_agent_runtime::code_sandbox::microvm::{
    VendorCallBound, VendorSandboxClient, VendorSandboxId, VendorSandboxSpec,
};
use rand_core::{OsRng, RngCore as _};
use reqwest::StatusCode;
use reqwest::blocking::{Body, Client, RequestBuilder, Response};
use serde::Deserialize;
use serde_json::json;

use super::vendor_http::{CancellableReader, DELETE_TIMEOUT, OwnerVendorKey, VendorHttp, quoted};

/// The one vendor this client reaches.
const VENDOR: SandboxVendor = SandboxVendor::Instabox;
const HTTP: VendorHttp = VendorHttp(VENDOR);
/// What a machine lives past the step's own time left, so InstaBox deletes
/// one a lost run left soon after the run would have ended.
const LIFETIME_MARGIN: Duration = Duration::from_secs(60);
/// The shortest and the longest life InstaBox gives a machine it deletes by
/// itself.
const SHORTEST_LIFETIME_SECONDS: u64 = 60;
const LONGEST_LIFETIME_SECONDS: u64 = 86_400;
/// The longest a waited command may take: one that starts a detached
/// command, or one that copies an upload into place.
const WAITED_COMMAND_SECONDS: u64 = 60;
/// The first and the longest pause between two polls of an operation or of
/// a command's exit status.
const FIRST_POLL: Duration = Duration::from_millis(100);
const LONGEST_POLL: Duration = Duration::from_secs(1);
/// The user and group every command of a run runs as: an id no account of a
/// machine has (Debian allocates none from 65536 to 99999, and subordinate
/// ids start at 100000).
const GUEST_ID: &str = "70000";
/// The program a detached command's shell runs: it closes its output, runs
/// the command (its arguments, which it never parses), and then writes the
/// command's exit status to the file `$0` names, whole or not at all.
const DETACHED: &str =
    r#"exec </dev/null >/dev/null 2>&1; "$@"; echo "$?" >"$0.part" && mv -f "$0.part" "$0""#;
/// The start of the path of each command's exit status file and of each
/// staged upload.
const CLIENT_FILE_PREFIX: &str = "/tmp/oneiron-instabox";
/// The most bytes of an exit status file the client reads.
const EXIT_STATUS_BYTES: u64 = 16;

/// Where InstaBox's API answers.
#[derive(Debug, Clone)]
pub(crate) struct InstaboxEndpoints {
    /// The v1 API: `{api}/machines` makes a machine.
    pub(crate) api: String,
}

impl Default for InstaboxEndpoints {
    fn default() -> Self {
        Self {
            api: "https://api.instabox.sh/v1".into(),
        }
    }
}

/// One run's client of InstaBox, on the owner's key the switch names.
pub(super) struct InstaboxClient {
    key: OwnerVendorKey,
    endpoints: InstaboxEndpoints,
    /// The client's files made so far on its machines.
    files: AtomicU64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Operation {
    id: String,
    machine_id: String,
    state: String,
    #[serde(default)]
    error: Option<OperationError>,
}

#[derive(Deserialize)]
struct OperationError {
    #[serde(default)]
    code: String,
    #[serde(default)]
    message: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExecResult {
    exit_code: i32,
    #[serde(default)]
    timed_out: bool,
}

/// A fresh `Idempotency-Key`: InstaBox replays the first answer to a key, so
/// each create and delete takes its own.
fn idempotency_key() -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    let mut key = String::from("oneiron-");
    for byte in bytes {
        let _ = write!(key, "{byte:02x}");
    }
    key
}

/// `argv`, confined and started detached, with its exit status written to
/// `status_file` when it ends.
fn confined(status_file: &str, argv: &[&str]) -> Vec<String> {
    let reuid = format!("--reuid={GUEST_ID}");
    let regid = format!("--regid={GUEST_ID}");
    [
        "sudo",
        "-n",
        "unshare",
        "--net",
        "--",
        "setpriv",
        reuid.as_str(),
        regid.as_str(),
        "--clear-groups",
        "--no-new-privs",
        "--",
        "setsid",
        "-f",
        "sh",
        "-c",
        DETACHED,
        status_file,
    ]
    .into_iter()
    .chain(argv.iter().copied())
    .map(str::to_owned)
    .collect()
}

impl InstaboxClient {
    pub(super) fn new(vault: Weak<Vault>, key_name: String, endpoints: InstaboxEndpoints) -> Self {
        Self {
            key: OwnerVendorKey::new(vault, VENDOR, key_name),
            endpoints,
            files: AtomicU64::new(0),
        }
    }

    /// `{api}/machines/{machine}{rest}`.
    fn machine_url(&self, machine: &str, rest: &str) -> oneiron::Result<String> {
        Ok(format!(
            "{}/machines/{}{rest}",
            self.endpoints.api,
            HTTP.segment(machine)?
        ))
    }

    /// A path of the client's own on a machine, named `kind`, that no other
    /// file of this client has.
    fn client_file(&self, kind: &str) -> String {
        let number = self.files.fetch_add(1, Ordering::Relaxed);
        format!("{CLIENT_FILE_PREFIX}-{kind}-{number}")
    }

    /// Sends one request on the owner's key inside the step's bound, and
    /// answers what came back.
    fn sent(
        request: RequestBuilder,
        key: &str,
        bound: VendorCallBound<'_>,
    ) -> oneiron::Result<Response> {
        bound.cancel.check()?;
        request
            .header("X-API-Key", key)
            .timeout(HTTP.remaining(bound.deadline)?)
            .send()
            .map_err(|error| HTTP.http_failed(error, &[key]))
    }

    /// [`Self::sent`], keeping only an answer of success.
    fn send(
        request: RequestBuilder,
        key: &str,
        bound: VendorCallBound<'_>,
    ) -> oneiron::Result<Response> {
        HTTP.checked(Self::sent(request, key, bound)?, &[key])
    }

    /// Polls the create `operation` until the machine runs.
    fn started(
        &self,
        http: &Client,
        key: &str,
        mut operation: Operation,
        bound: VendorCallBound<'_>,
    ) -> oneiron::Result<()> {
        let url = format!(
            "{}/operations/{}",
            self.endpoints.api,
            HTTP.segment(&operation.id)?
        );
        let mut wait = FIRST_POLL;
        loop {
            match operation.state.as_str() {
                "succeeded" => return Ok(()),
                "failed" => {
                    let reason = operation.error.map_or_else(String::new, |error| {
                        quoted(&format!("{}: {}", error.code, error.message), &[key])
                    });
                    return Err(
                        HTTP.failed(format!("the InstaBox machine did not start: {reason}"))
                    );
                }
                _ => {}
            }
            HTTP.pause(wait, bound)?;
            wait = (wait * 2).min(LONGEST_POLL);
            operation = Self::send(http.get(&url), key, bound)?
                .json()
                .map_err(|error| HTTP.http_failed(error, &[key]))?;
        }
    }

    /// Runs `argv` on `machine` as the machine's user and waits for its exit
    /// status, which comes within [`WAITED_COMMAND_SECONDS`].
    fn waited(
        &self,
        http: &Client,
        key: &str,
        machine: &str,
        argv: &[String],
        bound: VendorCallBound<'_>,
    ) -> oneiron::Result<i32> {
        let seconds = HTTP
            .remaining(bound.deadline)?
            .as_secs()
            .clamp(1, WAITED_COMMAND_SECONDS);
        let result: ExecResult = Self::send(
            http.post(self.machine_url(machine, "/exec")?)
                .json(&json!({ "argv": argv, "timeoutSeconds": seconds })),
            key,
            bound,
        )?
        .json()
        .map_err(|error| HTTP.http_failed(error, &[key]))?;
        if result.timed_out {
            return Err(HTTP.failed("an InstaBox command ran past its time"));
        }
        Ok(result.exit_code)
    }

    /// The exit status in `status_file` on `machine`, or none while the
    /// command runs.
    fn exit_status(
        &self,
        http: &Client,
        key: &str,
        machine: &str,
        status_file: &str,
        bound: VendorCallBound<'_>,
    ) -> oneiron::Result<Option<i32>> {
        let response = Self::sent(
            http.get(self.machine_url(machine, "/files/content")?)
                .query(&[("path", status_file)]),
            key,
            bound,
        )?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let mut status = Vec::new();
        HTTP.checked(response, &[key])?
            .take(EXIT_STATUS_BYTES)
            .read_to_end(&mut status)
            .map_err(|_| HTTP.failed("an InstaBox exit status could not be read"))?;
        std::str::from_utf8(&status)
            .ok()
            .and_then(|status| status.trim().parse().ok())
            .map(Some)
            .ok_or_else(|| HTTP.failed("an InstaBox command left an unreadable exit status"))
    }

    fn delete_on(&self, http: &Client, key: &str, machine: &str) -> oneiron::Result<()> {
        let response = http
            .delete(self.machine_url(machine, "")?)
            .header("X-API-Key", key)
            .header("Idempotency-Key", idempotency_key())
            .header("X-Confirm-Delete", HTTP.segment(machine)?)
            .timeout(DELETE_TIMEOUT)
            .send()
            .map_err(|error| HTTP.http_failed(error, &[key]))?;
        HTTP.checked(response, &[key]).map(drop)
    }
}

impl VendorSandboxClient for InstaboxClient {
    fn vendor(&self) -> SandboxVendor {
        VENDOR
    }

    fn create(
        &self,
        spec: &VendorSandboxSpec<'_>,
        bound: VendorCallBound<'_>,
    ) -> oneiron::Result<VendorSandboxId> {
        let key = self.key.read()?;
        let http = HTTP.client()?;
        let lifetime = (HTTP.remaining(bound.deadline)? + LIFETIME_MARGIN)
            .as_secs()
            .clamp(SHORTEST_LIFETIME_SECONDS, LONGEST_LIFETIME_SECONDS);
        let accepted: Operation = Self::send(
            http.post(format!("{}/machines", self.endpoints.api))
                .header("Idempotency-Key", idempotency_key())
                .json(&json!({
                    "snapshotId": HTTP.guest_image_name(spec.guest_image)?,
                    "deleteAfterSeconds": lifetime,
                    "secrets": [],
                    "envSecrets": [],
                    "vault": false,
                    "metadata": { "oneiron": "batch-run" },
                })),
            &key,
            bound,
        )?
        .json()
        .map_err(|error| HTTP.http_failed(error, &[key.as_str()]))?;
        let id = VendorSandboxId::new(HTTP.segment(&accepted.machine_id)?)?;
        // From here the machine is this run's to delete, on any failure.
        if let Err(error) = self.started(&http, &key, accepted, bound) {
            if let Err(cleanup) = self.delete_on(&http, &key, id.as_str()) {
                tracing::warn!(error = %cleanup, sandbox = %id.as_str(), "InstaBox machine delete failed");
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
        HTTP.plain_words(&[path])?;
        let key = self.key.read()?;
        let http = HTTP.client()?;
        let staged = self.client_file("upload");
        let reader = CancellableReader {
            inner: body.reader(),
            cancel: bound.cancel.clone(),
        };
        Self::send(
            http.put(self.machine_url(sandbox.as_str(), "/files")?)
                .query(&[("path", staged.as_str()), ("mode", "0600")])
                .header("Content-Type", "application/octet-stream")
                .body(Body::sized(reader, body.len())),
            &key,
            bound,
        )?;
        let install = [
            "sudo",
            "-n",
            "install",
            "-o",
            GUEST_ID,
            "-g",
            GUEST_ID,
            "-m",
            "0600",
            "-T",
            "--",
            staged.as_str(),
            path,
        ]
        .map(str::to_owned);
        let placed = self.waited(&http, &key, sandbox.as_str(), &install, bound)?;
        if placed != 0 {
            return Err(HTTP.failed(format!(
                "an InstaBox upload could not be placed as the guest's file (exit {placed})"
            )));
        }
        Ok(())
    }

    fn execute(
        &self,
        sandbox: &VendorSandboxId,
        argv: &[&str],
        bound: VendorCallBound<'_>,
    ) -> oneiron::Result<i32> {
        HTTP.plain_words(argv)?;
        let key = self.key.read()?;
        let http = HTTP.client()?;
        let status_file = self.client_file("status");
        let started = self.waited(
            &http,
            &key,
            sandbox.as_str(),
            &confined(&status_file, argv),
            bound,
        )?;
        if started != 0 {
            return Err(HTTP.failed(format!(
                "an InstaBox command could not start in its confinement (exit {started})"
            )));
        }
        let mut wait = FIRST_POLL;
        loop {
            HTTP.pause(wait, bound)?;
            wait = (wait * 2).min(LONGEST_POLL);
            if let Some(code) =
                self.exit_status(&http, &key, sandbox.as_str(), &status_file, bound)?
            {
                return Ok(code);
            }
        }
    }

    fn download(
        &self,
        sandbox: &VendorSandboxId,
        path: &str,
        sink: &mut dyn Write,
        bound: VendorCallBound<'_>,
    ) -> oneiron::Result<()> {
        let key = self.key.read()?;
        let http = HTTP.client()?;
        let response = Self::send(
            http.get(self.machine_url(sandbox.as_str(), "/files/content")?)
                .query(&[("path", path)]),
            &key,
            bound,
        )?;
        HTTP.copy_body(response, sink, &[key.as_str()], bound)
    }

    fn delete(&self, sandbox: &VendorSandboxId) -> oneiron::Result<()> {
        let key = self.key.read()?;
        self.delete_on(&HTTP.client()?, &key, sandbox.as_str())
    }
}
