//! boat's sandbox API as a [`VendorSandboxClient`] (L8-43): one boat VM per
//! batch run, made from the owner's saved boat snapshot of the step's pinned
//! guest image, driven through boat's v1 API, and deleted at the run's end.
//!
//! The owner's key, read at the custody door bound to `sandbox:boat` at the
//! run's first call, goes as a bearer token only to the API base this
//! client was built with, and is scrubbed from every error text. A file
//! moves through a signed URL the VM serves itself: boat names it, so the
//! client sends it no header of ours, keeps only one on the API base's
//! scheme (a file never goes in clear text when the API is reached over
//! TLS), and scrubs it from every error text, as it scrubs the key.
//!
//! boat boots every VM from its own Ubuntu image, never from an OCI image.
//! So the guest image reaches boat as a saved snapshot the owner makes once,
//! of a VM holding the guest image's files at their paths, named
//! `oneiron-guest-<first 12 hex of its digest>` as Daytona's snapshot and
//! E2B's template are; boat cannot show that it holds that image. The VM
//! gets none of the account's secrets and is confined to itself (`noEnv`).
//!
//! boat has no egress setting, and the VM's own user `user` must keep its
//! network, since boat's tunnel to the VM runs as that user. So every
//! command of a run is confined (`vendor_http::confined`): as root, it
//! starts in a network namespace of its own, which holds only a loopback
//! device, and then runs as a user and group no account of the VM has, with
//! no supplementary group and no way to gain a privilege. Neither `user`'s
//! passwordless sudo, nor its docker socket, nor the user manager and
//! session bus of the desktop boat streams as `user` are in the guest's
//! reach, so it can neither leave the namespace nor change it, nor leave
//! code for a later command of `user`: a vendor run has no egress (module
//! doc of `VendorBatchBackend`). The confinement is made before the command
//! starts, so on a VM where it cannot be made nothing runs and the run
//! fails. A Unix socket a system daemon serves at a path stays reachable, as
//! it does under boat's own pattern for untrusted code (a second user and
//! an iptables rule on its uid): FIX [BOAT-GUEST-DAEMON-SOCKETS].
//!
//! boat's file API reads and writes as `user`, and the guest's own directory
//! refuses that user. So the client's files sit in a directory `user` makes
//! at the run's start, which the guest cannot enter: an upload lands there
//! and the guest's own user then writes it into place from a redirection
//! `user` opens; a download is first copied there by the guest's own user
//! into a redirection `user` opens. Neither root nor `user` opens a path the
//! guest can reach, so a link the guest leaves in place of a file yields
//! nothing the guest could not read or write itself.
//!
//! A command runs detached and the client polls its status, so a guest may
//! run past boat's cap on a waited command. The VM keeps no disk snapshot,
//! and boat stops it at the step's own time left plus [`LIFETIME_MARGIN`],
//! which erases its disk: a lost run leaves nothing running and no data.

use std::io::Write;
use std::sync::Weak;
use std::time::Duration;

use oneiron::Vault;
use oneiron::code_sandbox::{SandboxProposalBody, SandboxVendor};
use oneiron_agent_runtime::code_sandbox::microvm::{
    VendorCallBound, VendorSandboxClient, VendorSandboxId, VendorSandboxSpec,
};
use reqwest::blocking::{Body, Client, RequestBuilder};
use serde::Deserialize;
use serde_json::json;
use zeroize::Zeroizing;

use super::vendor_http::{
    Answer, CancellableReader, ClientFiles, MAKE_CLIENT_DIR, OwnerVendorKey, VendorHttp, confined,
    quoted, read_as_guest, write_as_guest,
};

/// The one vendor this client reaches.
const VENDOR: SandboxVendor = SandboxVendor::Boat;
const HTTP: VendorHttp = VendorHttp(VENDOR);
/// boat's smallest VM (2 vCPU, 4 GB): a snapshot does not fix a VM's size.
/// The guest holds its program to the budget's processes and to its own
/// memory limit; the VM may have more memory than the budget (FIX
/// [VENDOR-MEM-BUDGET]).
const MACHINE_TYPE: &str = "small";
/// What a VM lives past the step's own time left, so boat stops one a lost
/// run left soon after the run would have ended.
const LIFETIME_MARGIN: Duration = Duration::from_secs(60);
/// The longest a signed file URL may stay valid at boat.
const LONGEST_URL_SECONDS: u64 = 3600;
/// The first and the longest pause between two polls of a VM's state or a
/// command's status.
const FIRST_POLL: Duration = Duration::from_millis(100);
const LONGEST_POLL: Duration = Duration::from_secs(1);

/// Where boat's API answers.
#[derive(Debug, Clone)]
pub(crate) struct BoatEndpoints {
    /// The v1 API: `{api}/sandboxes` makes a VM.
    pub(crate) api: String,
}

impl Default for BoatEndpoints {
    fn default() -> Self {
        Self {
            api: "https://boat.dev/api/v1".into(),
        }
    }
}

/// One run's client of boat, on the owner's key the switch names.
pub(super) struct BoatClient {
    key: OwnerVendorKey,
    endpoints: BoatEndpoints,
    files: ClientFiles,
}

#[derive(Deserialize)]
struct SandboxAnswer {
    sandbox: Sandbox,
}

#[derive(Deserialize)]
struct Sandbox {
    id: String,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CommandStarted {
    process_id: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CommandStatus {
    status: String,
    #[serde(default)]
    exit_code: Option<i32>,
    #[serde(default)]
    signal: Option<String>,
}

#[derive(Deserialize)]
struct SignedUrl {
    url: String,
}

/// Where a command's standard streams go besides boat's log: each is a
/// file of the client's, which `user`'s shell opens.
#[derive(Clone, Copy)]
enum Streams<'a> {
    Log,
    OutputTo(&'a str),
    /// Input from the file, and the output discarded.
    InputFrom(&'a str),
}

/// The scheme of `url`, in lower case.
fn scheme(url: &str) -> Option<String> {
    url.split_once("://")
        .map(|(scheme, _)| scheme.to_ascii_lowercase())
}

impl BoatClient {
    pub(super) fn new(vault: Weak<Vault>, key_name: String, endpoints: BoatEndpoints) -> Self {
        Self {
            key: OwnerVendorKey::new(vault, VENDOR, key_name),
            endpoints,
            files: ClientFiles::default(),
        }
    }

    /// `{api}/sandboxes/{sandbox}{rest}`.
    fn sandbox_url(&self, sandbox: &str, rest: &str) -> oneiron::Result<String> {
        Ok(format!(
            "{}/sandboxes/{}{rest}",
            self.endpoints.api,
            HTTP.segment(sandbox)?
        ))
    }

    /// Sends one request on the owner's key inside the step's bound, and
    /// keeps only an answer of success.
    fn send(
        request: RequestBuilder,
        key: &str,
        bound: VendorCallBound<'_>,
    ) -> oneiron::Result<Answer> {
        HTTP.send(request.bearer_auth(key), &[key], bound)
    }

    /// Polls the VM until it runs.
    fn start(
        &self,
        http: &Client,
        key: &str,
        made: Sandbox,
        bound: VendorCallBound<'_>,
    ) -> oneiron::Result<()> {
        let url = self.sandbox_url(&made.id, "")?;
        let (mut state, mut reason) = (made.state, made.error);
        let mut wait = FIRST_POLL;
        loop {
            match state.as_deref() {
                Some("ready" | "idle" | "running") => return Ok(()),
                Some(ended @ ("error" | "cancelled" | "archiving" | "archived")) => {
                    let reason = reason
                        .as_deref()
                        .map_or_else(String::new, |reason| quoted(reason, &[key]));
                    return Err(HTTP.failed(format!("the boat VM ended in {ended}: {reason}")));
                }
                _ => {}
            }
            HTTP.pause(wait, bound)?;
            wait = (wait * 2).min(LONGEST_POLL);
            let answer: SandboxAnswer = Self::send(http.get(&url), key, bound)?.json()?;
            (state, reason) = (answer.sandbox.state, answer.sandbox.error);
        }
    }

    /// The signed URL (`upload-url` or `download-url`) for the file `path`
    /// on `sandbox`, valid for the step's time left. One off the API base's
    /// scheme is refused unused.
    fn signed_url(
        &self,
        http: &Client,
        key: &str,
        sandbox: &VendorSandboxId,
        kind: &str,
        path: &str,
        bound: VendorCallBound<'_>,
    ) -> oneiron::Result<Zeroizing<String>> {
        let seconds = HTTP
            .remaining(bound.deadline)?
            .as_secs()
            .clamp(1, LONGEST_URL_SECONDS);
        let signed: SignedUrl = Self::send(
            http.post(self.sandbox_url(sandbox.as_str(), &format!("/files/{kind}"))?)
                .json(&json!({ "path": path, "ttlSeconds": seconds })),
            key,
            bound,
        )?
        .json()?;
        let url = Zeroizing::new(signed.url);
        let answered = scheme(&url);
        if answered.is_none() || answered != scheme(&self.endpoints.api) {
            return Err(HTTP.failed(format!(
                "boat answered a signed file URL off its API's scheme ({kind})"
            )));
        }
        Ok(url)
    }

    /// Runs `argv` on `sandbox` through `user`'s shell, detached, with its
    /// standard streams as `streams` says, and polls it to its exit code.
    fn command(
        &self,
        http: &Client,
        key: &str,
        sandbox: &str,
        argv: &[&str],
        streams: Streams<'_>,
        bound: VendorCallBound<'_>,
    ) -> oneiron::Result<i32> {
        let line = HTTP.command_line(argv)?;
        let command = match streams {
            Streams::Log => line,
            Streams::OutputTo(file) => format!("{line} >{file}"),
            Streams::InputFrom(file) => format!("{line} <{file} >/dev/null"),
        };
        let started: CommandStarted = Self::send(
            http.post(self.sandbox_url(sandbox, "/commands")?)
                .json(&json!({ "command": command, "detached": true })),
            key,
            bound,
        )?
        .json()?;
        let status_url = self.sandbox_url(sandbox, &format!("/commands/{}", started.process_id))?;
        let mut wait = FIRST_POLL;
        loop {
            HTTP.pause(wait, bound)?;
            wait = (wait * 2).min(LONGEST_POLL);
            // One byte of each log: the run reads the guest's frames from
            // its file, never from its output.
            let status: CommandStatus = Self::send(
                http.get(&status_url).query(&[("tailBytes", "1")]),
                key,
                bound,
            )?
            .json()?;
            match (status.status.as_str(), status.exit_code) {
                ("exited", Some(code)) => return Ok(code),
                ("exited", None) => {
                    let signal = status.signal.as_deref().unwrap_or_default();
                    return Err(HTTP.failed(format!(
                        "the boat command ended without an exit code: {}",
                        quoted(signal, &[key])
                    )));
                }
                ("lost", _) => return Err(HTTP.failed("boat lost the command it was running")),
                _ => {}
            }
        }
    }

    /// Makes the client's directory on the VM, as `user`.
    fn make_client_dir(
        &self,
        http: &Client,
        key: &str,
        sandbox: &str,
        bound: VendorCallBound<'_>,
    ) -> oneiron::Result<()> {
        let made = self.command(http, key, sandbox, &MAKE_CLIENT_DIR, Streams::Log, bound)?;
        if made != 0 {
            return Err(HTTP.failed(format!(
                "the boat VM could not make the client's directory (exit {made})"
            )));
        }
        Ok(())
    }

    fn delete_on(&self, http: &Client, key: &str, sandbox: &str) -> oneiron::Result<()> {
        HTTP.send_delete(
            http.delete(self.sandbox_url(sandbox, "")?)
                .bearer_auth(key)
                .header("X-Ascii-Confirm-Delete", HTTP.segment(sandbox)?),
            &[key],
        )
        .map(drop)
    }
}

impl VendorSandboxClient for BoatClient {
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
        let lifetime = HTTP.remaining(bound.deadline)? + LIFETIME_MARGIN;
        let made: SandboxAnswer = Self::send(
            http.post(format!("{}/sandboxes", self.endpoints.api))
                .json(&json!({
                    "from": HTTP.guest_image_name(spec.guest_image)?,
                    "type": MACHINE_TYPE,
                    "ttlSeconds": lifetime.as_secs(),
                    "noEnv": true,
                    "snapshots": false,
                    "visibility": "private",
                    "labels": { "oneiron": "batch-run" },
                })),
            &key,
            bound,
        )?
        .json()
        .map_err(|error| HTTP.http_failed(error, &[key.as_str()]))?;
        let id = VendorSandboxId::new(HTTP.segment(&made.sandbox.id)?)?;
        // From here the VM is this run's to delete, on any failure.
        let ready = self
            .start(&http, &key, made.sandbox, bound)
            .and_then(|()| self.make_client_dir(&http, &key, id.as_str(), bound));
        if let Err(error) = ready {
            if let Err(cleanup) = self.delete_on(&http, &key, id.as_str()) {
                tracing::warn!(error = %cleanup, sandbox = %id.as_str(), "boat VM delete failed");
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
        let key = self.key.read()?;
        let http = HTTP.client()?;
        let staged = self.files.next("upload");
        let url = self.signed_url(&http, &key, sandbox, "upload-url", &staged, bound)?;
        let secrets = [key.as_str(), url.as_str()];
        let reader = CancellableReader {
            inner: body.reader(),
            cancel: bound.cancel.clone(),
        };
        HTTP.send(
            http.put(url.as_str())
                .header("Content-Type", "application/octet-stream")
                .body(Body::sized(reader, body.len())),
            &secrets,
            bound,
        )?;
        let placed = self.command(
            &http,
            &key,
            sandbox.as_str(),
            &write_as_guest(path),
            Streams::InputFrom(&staged),
            bound,
        )?;
        if placed != 0 {
            return Err(HTTP.failed(format!(
                "a boat upload could not be placed as the guest's file (exit {placed})"
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
        let key = self.key.read()?;
        let http = HTTP.client()?;
        self.command(
            &http,
            &key,
            sandbox.as_str(),
            &confined(argv),
            Streams::Log,
            bound,
        )
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
        let staged = self.files.next("download");
        let copy = read_as_guest(path);
        let copied = self.command(
            &http,
            &key,
            sandbox.as_str(),
            &copy,
            Streams::OutputTo(&staged),
            bound,
        )?;
        if copied != 0 {
            return Err(HTTP.failed(format!(
                "a boat download could not be copied out as the guest (exit {copied})"
            )));
        }
        let url = self.signed_url(&http, &key, sandbox, "download-url", &staged, bound)?;
        let secrets = [key.as_str(), url.as_str()];
        HTTP.send(http.get(url.as_str()), &secrets, bound)?
            .copy_to(sink)
    }

    fn delete(&self, sandbox: &VendorSandboxId) -> oneiron::Result<()> {
        let key = self.key.read()?;
        self.delete_on(&HTTP.client()?, &key, sandbox.as_str())
    }
}
