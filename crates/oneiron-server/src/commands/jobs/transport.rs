//! One verb call of the booker: the verb's facade row over `oneiron api`'s curl path, its answer
//! read back. The credential goes on curl's config channel only, with a fresh holder proof for
//! each call (`commands/api.rs`); no shell runs and no argument carries it.

use std::ffi::OsStr;
use std::process::Stdio;

use serde_json::Value;

use super::super::api::{
    CURL_PROGRAM, CurlCredential, CurlTransport, curl_transport, request_for_command,
    run_curl_output_inner, signed_binding_for_seed,
};
use super::super::credential_file::PairedCredentialFile;
use crate::cli::{ApiCommand, JobsConnectArgs};

/// curl's exit when `--fail-with-body` met an HTTP error: the body is the server's refusal.
const CURL_HTTP_ERROR: i32 = 22;

/// Why a call gave no answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum CallError {
    /// The server refused: its body as it sent it (a JSON `{"error": {...}}` envelope, or any
    /// other text a proxy answered).
    Refused { body: String },
    /// No answer came: curl could not reach the server, or the transfer ended before one.
    Unreached { why: String },
}

impl CallError {
    /// The refusal's `error.code`, when the body is the server's envelope.
    pub(super) fn code(&self) -> Option<String> {
        self.envelope()
            .and_then(|error| error.get("code")?.as_str().map(str::to_owned))
    }

    /// The refusal's `error.reason_codes`, empty when it names none.
    pub(super) fn reason_codes(&self) -> Vec<String> {
        self.envelope()
            .and_then(|error| error.get("reason_codes")?.as_array().cloned())
            .unwrap_or_default()
            .iter()
            .filter_map(|code| code.as_str().map(str::to_owned))
            .collect()
    }

    fn envelope(&self) -> Option<Value> {
        match self {
            Self::Refused { body } => serde_json::from_str::<Value>(body)
                .ok()?
                .get("error")
                .cloned(),
            Self::Unreached { .. } => None,
        }
    }

    /// What to print: the body as the server sent it, or why nothing came.
    pub(super) fn text(&self) -> &str {
        match self {
            Self::Refused { body } => body,
            Self::Unreached { why } => why,
        }
    }
}

/// The calls the booker makes, one verb at a time.
pub(super) trait VerbCall {
    /// `verb` with `input`: its answer, or why there is none.
    fn call(&mut self, verb: &str, input: &Value) -> Result<Value, CallError>;
}

/// The bearer and its binding seed, read once.
struct Credential {
    token: zeroize::Zeroizing<String>,
    /// Set for a slip, which signs a holder proof for each request.
    seed: Option<zeroize::Zeroizing<String>>,
}

/// [`VerbCall`] over the host's curl.
pub(super) struct CurlVerbCall {
    base_url: String,
    credential: Credential,
    /// The variables the credential came from: no curl child inherits them.
    env: Vec<String>,
    transport: CurlTransport,
}

impl CurlVerbCall {
    /// The calls `connect` names: its origin, its deadline and pin, and the booker's credential
    /// from its file, else from its two variables.
    ///
    /// # Errors
    ///
    /// A bad deadline or pin, an unreadable credential file, or no credential at all: the
    /// booker never calls as nobody.
    pub(super) fn new(connect: &JobsConnectArgs) -> anyhow::Result<Self> {
        let transport = curl_transport(
            &connect.base_url,
            &connect.resolve_address,
            Some(connect.max_time),
        )?;
        let credential = match &connect.credential_file {
            Some(path) => {
                let file = PairedCredentialFile::read(path)?;
                Credential {
                    token: zeroize::Zeroizing::new(file.token.clone()),
                    seed: Some(zeroize::Zeroizing::new(file.seed.clone())),
                }
            }
            None => {
                let token = std::env::var(&connect.secret_env).map_err(|_| {
                    anyhow::anyhow!(
                        "{} holds no credential and no --credential-file was given: the booker \
                         calls as its agent; nothing was sent",
                        connect.secret_env
                    )
                })?;
                let seed = if token.starts_with("v2.slip.") {
                    Some(zeroize::Zeroizing::new(
                        std::env::var(&connect.binding_key_env).map_err(|_| {
                            anyhow::anyhow!("{} holds no binding seed", connect.binding_key_env)
                        })?,
                    ))
                } else {
                    None
                };
                Credential {
                    token: zeroize::Zeroizing::new(token),
                    seed,
                }
            }
        };
        Ok(Self {
            base_url: connect.base_url.clone(),
            credential,
            env: vec![connect.secret_env.clone(), connect.binding_key_env.clone()],
            transport,
        })
    }
}

impl VerbCall for CurlVerbCall {
    fn call(&mut self, verb: &str, input: &Value) -> Result<Value, CallError> {
        let unreached = |why: String| CallError::Unreached { why };
        let request = request_for_command(
            &self.base_url,
            ApiCommand::Call {
                verb: verb.to_owned(),
                // A JSON object's text starts with `{`, so `oneiron api`'s `@FILE` and `-`
                // forms never read it.
                data: input.to_string(),
            },
        )
        .map_err(|error| unreached(error.to_string()))?;
        let binding = match &self.credential.seed {
            Some(seed) => Some(
                signed_binding_for_seed(&self.credential.token, seed)
                    .map_err(|error| unreached(error.to_string()))?,
            ),
            None => None,
        };
        let output = run_curl_output_inner(
            OsStr::new(CURL_PROGRAM),
            &request,
            CurlCredential {
                secret: Some(self.credential.token.as_str()),
                binding: binding.as_deref(),
                env: &self.env,
            },
            &self.transport,
            Stdio::piped(),
            Stdio::piped(),
        )
        .map_err(|error| unreached(error.to_string()))?;
        let body = String::from_utf8_lossy(&output.stdout).into_owned();
        match output.status.code() {
            Some(0) => answer_of(body),
            Some(CURL_HTTP_ERROR) => Err(CallError::Refused { body }),
            _ => Err(unreached(format!(
                "{verb}: no answer ({})",
                String::from_utf8_lossy(&output.stderr).trim()
            ))),
        }
    }
}

/// A 2xx body: the verb's answer, or a refusal the server sent with a 2xx status (a pending
/// check-in answers 202 with the error envelope).
pub(super) fn answer_of(body: String) -> Result<Value, CallError> {
    match serde_json::from_str::<Value>(&body) {
        Ok(value) if value.get("error").is_some_and(Value::is_object) => {
            Err(CallError::Refused { body })
        }
        Ok(value) => Ok(value),
        Err(_) => Err(CallError::Refused { body }),
    }
}
