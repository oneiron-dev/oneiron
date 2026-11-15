//! E2B's sandbox API as a [`VendorSandboxClient`] (L8-43): one sandbox per
//! batch run, made from the E2B template of the step's pinned guest image,
//! driven through the sandbox's own daemon (envd), and killed at the run's
//! end.
//!
//! Two secrets reach E2B, each only at its own base. The owner's key, read
//! at the custody door bound to `sandbox:e2b` at the run's first call, goes
//! as `X-API-Key` to the control API this client was built with. The access
//! token E2B answers for the one sandbox it made goes as `X-Access-Token` to
//! that sandbox's daemon, at the address this client derives from the
//! sandbox's id, never at a domain an answer names. Both are held in memory
//! that is wiped when the client drops, and both are scrubbed from every
//! error text.
//!
//! E2B secures every sandbox (its daemon refuses a call without the token),
//! and this client refuses a sandbox answered without one. The sandbox has
//! no internet access, so a vendor run has no egress (module doc of
//! `VendorBatchBackend`), and no public traffic: no port of it answers
//! without its traffic token. A template fixes a sandbox's resources: the
//! guest holds its program to the budget's processes and to its own memory
//! limit, and the sandbox may have more memory than the budget (FIX
//! [VENDOR-MEM-BUDGET]). The template is the owner's, named after the guest
//! image's digest; E2B cannot show that it holds that image. E2B
//! kills a sandbox at its timeout, which is the step's own time left plus
//! [`LIFETIME_MARGIN`], so a lost run leaves nothing running.
//!
//! A command runs through the daemon's `process.Process/Start` Connect RPC,
//! a server stream in Connect's JSON envelope framing: the client reads its
//! events up to the process's end.

use std::io::{Read, Write};
use std::sync::{Mutex, Weak};
use std::time::Duration;

use base64::Engine as _;
use oneiron::Vault;
use oneiron::code_sandbox::{SandboxProposalBody, SandboxVendor};
use oneiron_agent_runtime::code_sandbox::microvm::{
    VendorCallBound, VendorSandboxClient, VendorSandboxId, VendorSandboxSpec,
};
use reqwest::blocking::{Body, Client, RequestBuilder};
use serde::Deserialize;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::vendor_http::{Answer, CancellableReader, OwnerVendorKey, VendorHttp, quoted, scrubbed};

/// The one vendor this client reaches.
const VENDOR: SandboxVendor = SandboxVendor::E2b;
const HTTP: VendorHttp = VendorHttp(VENDOR);
/// The sandbox user every file and command of a run belongs to: the
/// template's own unprivileged user.
const USER: &str = "user";
/// The port of a sandbox's daemon, which E2B's proxy routes to.
const ENVD_PORT: &str = "49983";
/// What a sandbox lives past the step's own time left, so E2B kills one a
/// lost run left soon after the run would have ended.
const LIFETIME_MARGIN: Duration = Duration::from_secs(60);
/// The longest event of a command's stream this client reads: a command's
/// output comes in chunks well under it.
const MAX_EVENT_BYTES: usize = 4 * 1024 * 1024;
/// Seconds between the keepalive events the daemon sends on a quiet
/// command stream, so the client sees a cancellation inside one of them.
const KEEPALIVE_SECONDS: &str = "1";
/// A Connect envelope's flags: compressed, and the end of the stream.
const ENVELOPE_COMPRESSED: u8 = 0x01;
const ENVELOPE_END_STREAM: u8 = 0x02;

/// Where E2B's API answers.
#[derive(Debug, Clone)]
pub(crate) struct E2bEndpoints {
    /// The control API: `{api}/v2/sandboxes` makes a sandbox,
    /// `{api}/sandboxes/{id}` kills it.
    pub(crate) api: String,
    /// The daemon of one sandbox, with `{sandbox}` standing for its id.
    pub(crate) envd: String,
}

impl Default for E2bEndpoints {
    fn default() -> Self {
        Self {
            api: "https://api.e2b.app".into(),
            envd: format!("https://{ENVD_PORT}-{{sandbox}}.e2b.app"),
        }
    }
}

/// The sandbox this run made, and its daemon's access token.
struct MadeSandbox {
    id: String,
    token: Zeroizing<String>,
}

/// One run's client of E2B, on the owner's key the switch names.
pub(super) struct E2bClient {
    key: OwnerVendorKey,
    endpoints: E2bEndpoints,
    made: Mutex<Option<MadeSandbox>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SandboxAnswer {
    #[serde(rename = "sandboxID")]
    sandbox_id: String,
    #[serde(default)]
    envd_access_token: Option<String>,
}

/// One message of the command stream.
#[derive(Deserialize)]
struct StartAnswer {
    #[serde(default)]
    event: Option<ProcessEvent>,
}

/// The one event this client acts on is the process's end; its start, its
/// output and the keepalives are read and dropped.
#[derive(Deserialize)]
struct ProcessEvent {
    #[serde(default)]
    end: Option<ProcessEnd>,
}

/// A JSON message leaves out a field at its zero value: an exit code of 0
/// and a false `exited` are absent.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProcessEnd {
    #[serde(default)]
    exit_code: i32,
    #[serde(default)]
    exited: bool,
    #[serde(default)]
    status: String,
    #[serde(default)]
    error: Option<String>,
}

/// The stream's last message: an error, or nothing.
#[derive(Deserialize)]
struct EndOfStream {
    #[serde(default)]
    error: Option<ConnectError>,
}

#[derive(Deserialize)]
struct ConnectError {
    #[serde(default)]
    code: String,
    #[serde(default)]
    message: String,
}

/// `message` in one Connect envelope: no flags, its length, its JSON.
fn envelope(message: &Value) -> oneiron::Result<Vec<u8>> {
    let body = serde_json::to_vec(message)
        .map_err(|_| HTTP.failed("an e2b command message could not be encoded"))?;
    let length =
        u32::try_from(body.len()).map_err(|_| HTTP.failed("an e2b command message is too long"))?;
    let mut framed = Vec::with_capacity(5 + body.len());
    framed.push(0);
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(&body);
    Ok(framed)
}

/// The next envelope of `stream`: its flags and its message, or none at the
/// stream's clean end.
fn next_envelope(
    stream: &mut impl Read,
    secrets: &[&str],
) -> oneiron::Result<Option<(u8, Vec<u8>)>> {
    let mut head = [0; 5];
    let mut filled = 0;
    while filled < head.len() {
        let read = stream.read(&mut head[filled..]).map_err(|error| {
            HTTP.failed(format!(
                "e2b command stream failed: {}",
                scrubbed(&error.to_string(), secrets)
            ))
        })?;
        if read == 0 {
            return if filled == 0 {
                Ok(None)
            } else {
                Err(HTTP.failed("e2b command stream ended inside an envelope"))
            };
        }
        filled += read;
    }
    let flags = head[0];
    if flags & ENVELOPE_COMPRESSED != 0 {
        return Err(HTTP.failed("e2b sent a compressed envelope it was not asked for"));
    }
    let length = usize::try_from(u32::from_be_bytes([head[1], head[2], head[3], head[4]]))
        .map_err(|_| HTTP.failed("an e2b envelope length does not fit"))?;
    if length > MAX_EVENT_BYTES {
        return Err(HTTP.failed(format!(
            "an e2b command event of {length} bytes is over {MAX_EVENT_BYTES}"
        )));
    }
    let mut message = vec![0; length];
    stream.read_exact(&mut message).map_err(|error| {
        HTTP.failed(format!(
            "e2b command stream failed: {}",
            scrubbed(&error.to_string(), secrets)
        ))
    })?;
    Ok(Some((flags, message)))
}

/// The exit status of a command whose stream is `stream`: the process's end
/// event, before the stream's end. A process ended by a signal, an error at
/// the stream's end, or a stream with no end event fails.
fn exit_status(
    stream: &mut impl Read,
    secrets: &[&str],
    bound: VendorCallBound<'_>,
) -> oneiron::Result<i32> {
    let mut exit = None;
    loop {
        bound.cancel.check()?;
        let next = next_envelope(stream, secrets);
        // A wait the step's cancellation ended reads as a broken stream.
        bound.cancel.check()?;
        let Some((flags, message)) = next? else {
            break;
        };
        if flags & ENVELOPE_END_STREAM != 0 {
            let end: EndOfStream = serde_json::from_slice(&message).map_err(|_| {
                HTTP.failed("e2b ended its command stream with an unreadable message")
            })?;
            if let Some(error) = end.error {
                return Err(HTTP.failed(format!(
                    "e2b ended the command with {}: {}",
                    quoted(&error.code, secrets),
                    quoted(&error.message, secrets)
                )));
            }
            break;
        }
        let answer: StartAnswer = serde_json::from_slice(&message)
            .map_err(|_| HTTP.failed("e2b sent an unreadable command event"))?;
        if let Some(end) = answer.event.and_then(|event| event.end) {
            if !end.exited {
                let error = end.error.as_deref().unwrap_or_default();
                return Err(HTTP.failed(format!(
                    "the e2b command ended without exiting: {} {}",
                    quoted(&end.status, secrets),
                    quoted(error, secrets)
                )));
            }
            exit = Some(end.exit_code);
        }
    }
    exit.ok_or_else(|| HTTP.failed("e2b's command stream ended before the command did"))
}

impl E2bClient {
    pub(super) fn new(vault: Weak<Vault>, key_name: String, endpoints: E2bEndpoints) -> Self {
        Self {
            key: OwnerVendorKey::new(vault, VENDOR, key_name),
            endpoints,
            made: Mutex::new(None),
        }
    }

    fn sandbox_url(&self, sandbox: &str) -> oneiron::Result<String> {
        Ok(format!(
            "{}/sandboxes/{}",
            self.endpoints.api,
            HTTP.segment(sandbox)?
        ))
    }

    /// `rest` at the daemon of `sandbox`, the one this run made, with its
    /// access token.
    fn daemon(
        &self,
        sandbox: &VendorSandboxId,
        rest: &str,
    ) -> oneiron::Result<(String, Zeroizing<String>)> {
        let made = self
            .made
            .lock()
            .map_err(|_| HTTP.failed("the e2b sandbox state is poisoned"))?;
        let made = made
            .as_ref()
            .filter(|made| made.id == sandbox.as_str())
            .ok_or_else(|| HTTP.failed("an e2b call named a sandbox this run did not make"))?;
        let base = self
            .endpoints
            .envd
            .replace("{sandbox}", HTTP.segment(&made.id)?);
        Ok((
            format!("{base}/{rest}"),
            Zeroizing::new(made.token.as_str().to_owned()),
        ))
    }

    /// Sends one control call on the owner's key inside the step's bound,
    /// and keeps only an answer of success.
    fn control(
        request: RequestBuilder,
        key: &str,
        bound: VendorCallBound<'_>,
    ) -> oneiron::Result<Answer> {
        HTTP.send(request.header("X-API-Key", key), &[key], bound)
    }

    /// Sends one call to the daemon of `sandbox` on its access token inside
    /// the step's bound, and keeps only an answer of success. The routing
    /// headers name the sandbox and the daemon's port, as E2B's own clients
    /// send them.
    fn to_daemon(
        request: RequestBuilder,
        sandbox: &VendorSandboxId,
        token: &str,
        bound: VendorCallBound<'_>,
    ) -> oneiron::Result<Answer> {
        HTTP.send(
            request
                .header("X-Access-Token", token)
                .header("E2b-Sandbox-Id", sandbox.as_str())
                .header("E2b-Sandbox-Port", ENVD_PORT),
            &[token],
            bound,
        )
    }

    fn kill_on(&self, http: &Client, key: &str, sandbox: &str) -> oneiron::Result<()> {
        HTTP.send_delete(
            http.delete(self.sandbox_url(sandbox)?).header("X-API-Key", key),
            &[key],
        )
        .map(drop)
    }
}

impl VendorSandboxClient for E2bClient {
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
        let made: SandboxAnswer = Self::control(
            http.post(format!("{}/v2/sandboxes", self.endpoints.api))
                .json(&json!({
                    "templateID": HTTP.guest_image_name(spec.guest_image)?,
                    "timeout": lifetime.as_secs(),
                    "allow_internet_access": false,
                    // No port of the sandbox answers the internet without
                    // its traffic token; the daemon keeps its own check.
                    "network": { "allowPublicTraffic": false },
                    "autoPause": false,
                    "metadata": { "oneiron": "batch-run" },
                })),
            &key,
            bound,
        )?
        .json()?;
        let id = VendorSandboxId::new(HTTP.segment(&made.sandbox_id)?)?;
        // From here the sandbox is this run's to kill, on any failure.
        let token = made
            .envd_access_token
            .filter(|token| !token.is_empty())
            .map(Zeroizing::new);
        let held = match (token, self.made.lock()) {
            (Some(token), Ok(mut made)) => {
                *made = Some(MadeSandbox {
                    id: id.as_str().to_owned(),
                    token,
                });
                Ok(())
            }
            (None, _) => Err(HTTP.failed("e2b made a sandbox with no access token")),
            (Some(_), Err(_)) => Err(HTTP.failed("the e2b sandbox state is poisoned")),
        };
        if let Err(error) = held {
            if let Err(cleanup) = self.kill_on(&http, &key, id.as_str()) {
                tracing::warn!(error = %cleanup, sandbox = %id.as_str(), "e2b sandbox kill failed");
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
        let (url, token) = self.daemon(sandbox, "files")?;
        let http = HTTP.client()?;
        let reader = CancellableReader {
            inner: body.reader(),
            cancel: bound.cancel.clone(),
        };
        // A raw body names its file in the query alone.
        Self::to_daemon(
            http.post(url)
                .query(&[("path", path), ("username", USER)])
                .header("Content-Type", "application/octet-stream")
                .body(Body::sized(reader, body.len())),
            sandbox,
            &token,
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
        let (program, args) = argv
            .split_first()
            .ok_or_else(|| HTTP.failed("an e2b command has no program"))?;
        let (url, token) = self.daemon(sandbox, "process.Process/Start")?;
        let http = HTTP.client()?;
        let user = base64::engine::general_purpose::STANDARD.encode(format!("{USER}:"));
        // The daemon kills the process at the call's own timeout, so a
        // command a lost run left ends at the step's deadline.
        let left = HTTP.remaining(bound.deadline)?.as_millis().max(1);
        let mut stream = Self::to_daemon(
            http.post(url)
                .header("Content-Type", "application/connect+json")
                .header("Connect-Protocol-Version", "1")
                .header("Connect-Timeout-Ms", left.to_string())
                .header("Keepalive-Ping-Interval", KEEPALIVE_SECONDS)
                .header("Authorization", format!("Basic {user}"))
                .body(envelope(&json!({
                    "process": { "cmd": program, "args": args, "envs": {} },
                    "stdin": false,
                }))?),
            sandbox,
            &token,
            bound,
        )?;
        exit_status(&mut stream, &[token.as_str()], bound)
    }

    fn download(
        &self,
        sandbox: &VendorSandboxId,
        path: &str,
        sink: &mut dyn Write,
        bound: VendorCallBound<'_>,
    ) -> oneiron::Result<()> {
        let (url, token) = self.daemon(sandbox, "files")?;
        let http = HTTP.client()?;
        Self::to_daemon(
            http.get(url).query(&[("path", path), ("username", USER)]),
            sandbox,
            &token,
            bound,
        )?
        .copy_to(sink)
    }

    fn delete(&self, sandbox: &VendorSandboxId) -> oneiron::Result<()> {
        let key = self.key.read()?;
        self.kill_on(&HTTP.client()?, &key, sandbox.as_str())
    }
}
