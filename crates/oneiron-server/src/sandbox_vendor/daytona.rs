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

use std::io::Write;
use std::sync::Weak;
use std::time::Duration;

use oneiron::Vault;
use oneiron::code_sandbox::{SandboxProposalBody, SandboxVendor};
use oneiron_agent_runtime::code_sandbox::microvm::{
    VendorCallBound, VendorSandboxClient, VendorSandboxId, VendorSandboxSpec,
};
use reqwest::blocking::{Client, RequestBuilder, multipart};
use serde::Deserialize;
use serde_json::json;

use super::vendor_http::{Answer, CancellableReader, OwnerVendorKey, VendorHttp, quoted};

/// The one vendor this client reaches.
const VENDOR: SandboxVendor = SandboxVendor::Daytona;
const HTTP: VendorHttp = VendorHttp(VENDOR);
/// The toolbox session every command of a run goes through.
const SESSION: &str = "oneiron-batch";
/// The first and the longest pause between two polls of a sandbox's state or
/// a command's exit.
const FIRST_POLL: Duration = Duration::from_millis(100);
const LONGEST_POLL: Duration = Duration::from_secs(1);
/// Idle minutes after which Daytona stops a sandbox a lost run left, and
/// then deletes it (`autoDeleteInterval` 0).
const AUTO_STOP_MINUTES: u32 = 15;

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
    key: OwnerVendorKey,
    endpoints: DaytonaEndpoints,
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
        return Err(HTTP.failed("a vendor command argument is not a plain word"));
    }
    Ok(argv.join(" "))
}

impl DaytonaClient {
    pub(super) fn new(vault: Weak<Vault>, key_name: String, endpoints: DaytonaEndpoints) -> Self {
        Self {
            key: OwnerVendorKey::new(vault, VENDOR, key_name),
            endpoints,
        }
    }

    fn sandbox_url(&self, sandbox: &str) -> oneiron::Result<String> {
        Ok(format!(
            "{}/sandbox/{}",
            self.endpoints.api,
            HTTP.segment(sandbox)?
        ))
    }

    fn toolbox_url(&self, sandbox: &str, rest: &str) -> oneiron::Result<String> {
        Ok(format!(
            "{}/{}/{rest}",
            self.endpoints.toolbox,
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
                        .map_or_else(String::new, |reason| quoted(reason, &[key]));
                    return Err(
                        HTTP.failed(format!("the daytona sandbox ended in {failure}: {reason}"))
                    );
                }
                _ => {}
            }
            HTTP.pause(wait, bound)?;
            wait = (wait * 2).min(LONGEST_POLL);
            let answer: SandboxAnswer =
                Self::send(http.get(self.sandbox_url(sandbox)?), key, bound)?.json()?;
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
        HTTP.send_delete(
            http.delete(self.sandbox_url(sandbox)?).bearer_auth(key),
            &[key],
        )
        .map(drop)
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
        let key = self.key.read()?;
        let http = HTTP.client()?;
        let made: SandboxAnswer = Self::send(
            http.post(format!("{}/sandbox", self.endpoints.api))
                .json(&json!({
                    "snapshot": HTTP.guest_image_name(spec.guest_image)?,
                    "labels": { "oneiron": "batch-run" },
                    "autoStopInterval": AUTO_STOP_MINUTES,
                    "autoDeleteInterval": 0,
                    "networkBlockAll": true,
                })),
            &key,
            bound,
        )?
        .json()?;
        let id = VendorSandboxId::new(HTTP.segment(&made.id)?)?;
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
        let key = self.key.read()?;
        let http = HTTP.client()?;
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
        let key = self.key.read()?;
        let http = HTTP.client()?;
        let started: CommandStarted = Self::send(
            http.post(
                self.toolbox_url(sandbox.as_str(), &format!("process/session/{SESSION}/exec"))?,
            )
            .json(&json!({ "command": command, "runAsync": true })),
            &key,
            bound,
        )?
        .json()?;
        let status_url = self.toolbox_url(
            sandbox.as_str(),
            &format!(
                "process/session/{SESSION}/command/{}",
                HTTP.segment(&started.cmd_id)?
            ),
        )?;
        let mut wait = FIRST_POLL;
        loop {
            let status: CommandStatus = Self::send(http.get(&status_url), &key, bound)?.json()?;
            if let Some(code) = status.exit_code {
                return Ok(code);
            }
            HTTP.pause(wait, bound)?;
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
        let key = self.key.read()?;
        let http = HTTP.client()?;
        Self::send(
            http.get(self.toolbox_url(sandbox.as_str(), "files/download")?)
                .query(&[("path", path)]),
            &key,
            bound,
        )?
        .copy_to(sink)
    }

    fn delete(&self, sandbox: &VendorSandboxId) -> oneiron::Result<()> {
        let key = self.key.read()?;
        self.delete_on(&HTTP.client()?, &key, sandbox.as_str())
    }
}
