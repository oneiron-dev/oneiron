//! `oneiron recovery-kit pad-access | upkeep | roots | pin | anchor`: the kit
//! and root calls of a running server (FIX 4564, 4953, 4955, 4956), with the
//! credential `oneiron api` reads. The other subcommands open a stopped vault;
//! these ask the server that holds one.
//!
//! A kit call reads the pieces from their owner-only files and the
//! passphrase from `--secret-file` or stdin, never from an argument, and
//! sends them in that call's body alone: to `https://`, or to `http://` on
//! this machine, so a kit never crosses a network in the clear. Its `target`
//! is the server's own machine unless `--target` names one; the server proves
//! it is that install before it reads the kit. Nothing here prints, logs or
//! keeps kit material. Each answer is the server's JSON, printed as it came.

use std::path::Path;

use oneiron::authority::RequestCode;
use oneiron::recovery::RecoveryCode;
use reqwest::Method;
use serde::Serialize;
use serde_json::Value;
use zeroize::Zeroizing;

use super::{emit, read_piece, read_secret};
use crate::cli::{
    KitPieceArgs, RecoveryKitAnchorArgs, RecoveryKitPadAccessArgs, RecoveryKitPinArgs,
    RecoveryKitRootsArgs, RunningServerArgs, SecretSourceArgs,
};
use crate::commands::api::{normalized_base, signed_binding};
use crate::owner::vault_key::hex;

/// The running server one command asks, and its credential.
struct Server {
    base: String,
    /// The owner's credential; `None` asks with none.
    secret: Option<Zeroizing<String>>,
    binding_key_env: String,
}

impl Server {
    fn of(args: &RunningServerArgs) -> anyhow::Result<Self> {
        let secret = match std::env::var(&args.secret_env) {
            Ok(secret) => Some(Zeroizing::new(secret)),
            Err(std::env::VarError::NotPresent) => None,
            Err(std::env::VarError::NotUnicode(_)) => {
                anyhow::bail!("{} is not valid UTF-8; nothing was sent", args.secret_env)
            }
        };
        Ok(Self {
            base: normalized_base(&args.url)?,
            secret,
            binding_key_env: args.binding_key_env.clone(),
        })
    }

    /// Refuses an origin a kit would cross a network to in the clear: kit
    /// material goes to `https://`, or to `http://` on this machine named as
    /// itself (localhost or a loopback address).
    fn admits_kit(&self) -> anyhow::Result<()> {
        let url = reqwest::Url::parse(&self.base)?;
        let loopback = url.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
        anyhow::ensure!(
            matches!((url.scheme(), loopback), ("https", _) | ("http", true)),
            "kit material goes only to an https:// server, or to http:// on this machine: \
             over http:// to {} the kit would cross in cleartext",
            self.base
        );
        Ok(())
    }

    /// One call: `path` on the server, with `body` as JSON. A refusal's body
    /// goes to stderr as the server sent it, and the command fails.
    fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<Zeroizing<Vec<u8>>>,
    ) -> anyhow::Result<Value> {
        let binding = self
            .secret
            .as_deref()
            .filter(|token| token.starts_with("v2.slip."))
            .map(|token| signed_binding(token, &self.binding_key_env))
            .transpose()?;
        let url = format!("{}{path}", self.base);
        let secret = self.secret.clone();
        // The command runs on the CLI's runtime, so the blocking call gets a
        // thread of its own.
        std::thread::scope(|scope| {
            scope
                .spawn(move || -> anyhow::Result<Value> {
                    let client = reqwest::blocking::Client::builder()
                        .redirect(reqwest::redirect::Policy::none())
                        .timeout(None::<std::time::Duration>)
                        .build()?;
                    let mut request = client.request(method, &url);
                    if let Some(secret) = &secret {
                        request = request.bearer_auth(secret.as_str());
                    }
                    if let Some(binding) = &binding {
                        request = request.header("x-oneiron-binding", binding.as_str());
                    }
                    if let Some(body) = body {
                        request = request
                            .header(reqwest::header::CONTENT_TYPE, "application/json")
                            .body(body.to_vec());
                    }
                    let response = request
                        .send()
                        .map_err(|error| anyhow::anyhow!("{url}: {error}"))?;
                    let status = response.status();
                    let text = response.text().unwrap_or_default();
                    if !status.is_success() {
                        eprintln!("{text}");
                        anyhow::bail!("{url} answered {status}");
                    }
                    serde_json::from_str(&text)
                        .map_err(|_| anyhow::anyhow!("{url} answered {status} with no JSON"))
                })
                .join()
                .map_err(|_| anyhow::anyhow!("the call to {path} stopped"))?
        })
    }

    /// `named`, or else the server's own machine, as `GET /v1/owner/roots`
    /// names it.
    fn target(&self, named: Option<&str>) -> anyhow::Result<String> {
        if let Some(named) = named {
            return Ok(named.to_owned());
        }
        self.call(Method::GET, "/v1/owner/roots", None)?
            .get("machine")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| {
                anyhow::anyhow!("the server's install is no machine yet, so it takes no kit")
            })
    }
}

/// A kit as the server's kit calls take it: each piece's recovery code, and
/// the passphrase. Wiped on drop.
struct KitText {
    codes: Vec<RecoveryCode>,
    passphrase: Option<Zeroizing<String>>,
}

impl KitText {
    /// The pieces in their files, and the passphrase from `--secret-file`
    /// when one is named, else from stdin when only one piece is given.
    fn read(args: &KitPieceArgs) -> anyhow::Result<Self> {
        let codes = args
            .pieces
            .iter()
            .map(|file| read_piece(file).map(|piece| piece.recovery_code()))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let passphrase = if args.secret_file.is_some() || codes.len() == 1 {
            Some(read_passphrase_text(args.secret_file.as_deref())?)
        } else {
            None
        };
        Ok(Self { codes, passphrase })
    }

    fn pieces(&self) -> Vec<&str> {
        self.codes.iter().map(RecoveryCode::reveal).collect()
    }

    fn passphrase(&self) -> Option<&str> {
        self.passphrase.as_deref().map(String::as_str)
    }
}

fn read_passphrase_text(secret_file: Option<&Path>) -> anyhow::Result<Zeroizing<String>> {
    let source = SecretSourceArgs {
        secret_file: secret_file.map(Path::to_path_buf),
        ..SecretSourceArgs::default()
    };
    let bytes = read_secret(&source, "the kit passphrase")?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| anyhow::anyhow!("the kit passphrase is UTF-8 text"))?;
    Ok(Zeroizing::new(text.to_owned()))
}

/// A body as JSON bytes, wiped on drop.
fn json_body(body: &impl Serialize) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    Ok(Zeroizing::new(serde_json::to_vec(body)?))
}

#[derive(Serialize)]
struct PadAccessBody<'a> {
    target: &'a str,
    pieces: Vec<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    passphrase: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    machine: Option<&'a str>,
}

/// `pad-access`: `POST /v1/owner/recovery-kit/pad-access`.
pub(super) fn pad_access(args: RecoveryKitPadAccessArgs) -> anyhow::Result<()> {
    let server = Server::of(&args.server)?;
    server.admits_kit()?;
    let kit = KitText::read(&args.kit)?;
    let target = server.target(args.target.as_deref())?;
    let body = json_body(&PadAccessBody {
        target: &target,
        pieces: kit.pieces(),
        passphrase: kit.passphrase(),
        machine: args.machine.as_deref(),
    })?;
    emit(&server.call(
        Method::POST,
        "/v1/owner/recovery-kit/pad-access",
        Some(body),
    )?)
}

/// `upkeep`: `GET /v1/owner/recovery-kit/upkeep`.
pub(super) fn upkeep(args: &RunningServerArgs) -> anyhow::Result<()> {
    let server = Server::of(args)?;
    emit(&server.call(Method::GET, "/v1/owner/recovery-kit/upkeep", None)?)
}

/// `roots`: `GET /v1/owner/roots`, one page.
pub(super) fn roots(args: RecoveryKitRootsArgs) -> anyhow::Result<()> {
    let server = Server::of(&args.server)?;
    let mut query = Vec::new();
    if let Some(after) = args.after {
        query.push(format!("after={}", hex(&after)));
    }
    if let Some(limit) = args.limit {
        query.push(format!("limit={limit}"));
    }
    let path = if query.is_empty() {
        "/v1/owner/roots".to_owned()
    } else {
        format!("/v1/owner/roots?{}", query.join("&"))
    };
    emit(&server.call(Method::GET, &path, None)?)
}

/// `pin`: `POST /v1/owner/roots/pin`.
pub(super) fn pin(args: RecoveryKitPinArgs) -> anyhow::Result<()> {
    let server = Server::of(&args.server)?;
    let body = json_body(&serde_json::json!({ "root": hex(&args.root) }))?;
    emit(&server.call(Method::POST, "/v1/owner/roots/pin", Some(body))?)
}

#[derive(Serialize)]
struct AnchorBody<'a> {
    target: &'a str,
    pieces: Vec<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    passphrase: Option<&'a str>,
    enrolment: &'a Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    confirm_root: Option<String>,
}

/// `anchor`: `POST /v1/owner/roots/anchor`. The code is read as the machine
/// shows it and sent in its one text form.
pub(super) fn anchor(args: RecoveryKitAnchorArgs) -> anyhow::Result<()> {
    let code = args
        .code
        .as_deref()
        .map(RequestCode::from_text)
        .transpose()
        .map_err(|why| anyhow::anyhow!("--code: {why}"))?;
    let enrolment: Value = serde_json::from_str(
        &std::fs::read_to_string(&args.enrolment)
            .map_err(|error| anyhow::anyhow!("read {}: {error}", args.enrolment.display()))?,
    )
    .map_err(|error| anyhow::anyhow!("{}: {error}", args.enrolment.display()))?;
    let server = Server::of(&args.server)?;
    server.admits_kit()?;
    let kit = KitText::read(&args.kit)?;
    let target = server.target(args.target.as_deref())?;
    let body = json_body(&AnchorBody {
        target: &target,
        pieces: kit.pieces(),
        passphrase: kit.passphrase(),
        enrolment: &enrolment,
        code: code.map(|code| code.to_text()),
        fingerprint: args.fingerprint.map(|root| hex(&root)),
        confirm_root: args.confirm_root.map(|root| hex(&root)),
    })?;
    emit(&server.call(Method::POST, "/v1/owner/roots/anchor", Some(body))?)
}
