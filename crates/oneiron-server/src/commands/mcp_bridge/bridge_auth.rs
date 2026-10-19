//! Whom `oneiron mcp`'s requests run as (FIX 5540): a paired slip, or the
//! vault's owner himself by the sign-in an authenticated surface issued.
//!
//! Owner mode reads that sign-in from an owner-only file: one JSON object of
//! header names to text values, which the socket's upgrade carries in place
//! of a slip and its holder proof. For a managed vault it is the sign-in the
//! vault's proxy honours, which then attests the owner to his vault itself;
//! nothing here mints or refreshes it. The file is read again, and who can
//! read it checked again, for every new socket, so the surface that wrote it
//! can replace an expired sign-in in place; an open socket keeps the identity
//! it opened with. It may not set the upgrade's own HTTP or WebSocket
//! framing, a slip or its holder proof, an MCP connector's credential, or an
//! attestation only a vault's supervisor makes: such a file is refused
//! whole, naming the header. No value it holds is printed, logged or handed
//! to a process the bridge starts.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use tokio_tungstenite::tungstenite::http::{HeaderMap, HeaderName, HeaderValue};

use crate::cli::{McpArgs, McpAuthMode, McpTransport};
use crate::commands::{api, credential_file};

/// Whom the bridge's requests run as.
pub(super) enum Auth {
    /// A paired slip, and the hex seed of the key it is bound to: every
    /// request carries the slip and a holder proof signed for it alone.
    Slip { token: String, seed: String },
    /// The vault's owner, by the upgrade headers this file holds.
    Owner { headers_file: PathBuf },
}

impl Auth {
    /// The credential `args` name. One that cannot work fails here, at
    /// spawn, on the stderr the operator reads: a slip that is not one or
    /// does not match its seed, or an owner mode mixed with a slip, asked to
    /// go over HTTP, or given a headers file that is not admitted.
    pub(super) fn from_args(args: &McpArgs) -> anyhow::Result<Self> {
        match args.auth_mode {
            McpAuthMode::Slip => Self::slip(args),
            McpAuthMode::Owner => Self::owner(args),
        }
    }

    fn slip(args: &McpArgs) -> anyhow::Result<Self> {
        anyhow::ensure!(
            args.owner_upgrade_headers_file.is_none(),
            "--owner-upgrade-headers-file is the owner's sign-in, which slip mode does not \
             read; pass --auth-mode owner with it"
        );
        let (token, seed) = match &args.credential_file {
            Some(path) => {
                let held = credential_file::PairedCredentialFile::read(path)?;
                (held.token, held.seed)
            }
            None => (
                credential_env(&args.secret_env)?,
                credential_env(&args.binding_key_env)?,
            ),
        };
        anyhow::ensure!(
            token.starts_with("v2.slip."),
            "the credential is not a paired slip; mint one with `oneiron token agent`"
        );
        // Sign once now, so a slip and seed that do not belong together fail
        // at spawn, on the stderr the operator reads, and not on every call.
        api::signed_binding_for_seed(&token, &seed)?;
        Ok(Self::Slip { token, seed })
    }

    fn owner(args: &McpArgs) -> anyhow::Result<Self> {
        // His socket stands on his sign-in alone: beside a slip, the server
        // would take the slip's caller, not him.
        anyhow::ensure!(
            args.credential_file.is_none(),
            "--credential-file names a paired slip, and owner mode runs as the vault's owner \
             with no slip; drop it, or pass --auth-mode slip"
        );
        for name in [&args.secret_env, &args.binding_key_env] {
            anyhow::ensure!(
                std::env::var_os(name)
                    .is_none_or(|value| value.to_string_lossy().trim().is_empty()),
                "{name} holds a slip's credential, and owner mode runs as the vault's owner \
                 with no slip; unset it (or set it empty) for this process, or pass \
                 --auth-mode slip"
            );
        }
        anyhow::ensure!(
            args.transport == McpTransport::Socket,
            "owner mode rides the server's socket alone: his sign-in is attested for the \
             socket's upgrade, never for an HTTP request; drop --transport http"
        );
        let headers_file = args.owner_upgrade_headers_file.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "owner mode needs --owner-upgrade-headers-file: the file of upgrade headers \
                 the surface the owner signed in on wrote for this vault"
            )
        })?;
        // Read once now, so a file that is not admitted fails at spawn.
        UpgradeHeaders::read(&headers_file)?;
        Ok(Self::Owner { headers_file })
    }

    /// What to do when the server refuses this credential.
    pub(super) fn refused_advice(&self) -> &'static str {
        match self {
            Self::Slip { .. } => {
                "the server refused this credential before MCP; check --url names the vault that minted it. If revoked or expired, stop that vault, re-mint with `oneiron token agent --name <name> --tier <tier> --out <new-file> --config <vault-config>`, restart `oneiron serve --config <vault-config>`, and update --credential-file"
            }
            Self::Owner { .. } => {
                "the server refused the owner's sign-in before MCP; check --url names the vault it was issued for. If it expired or was signed out, sign in again on the surface that wrote --owner-upgrade-headers-file, so it rewrites that file (owner-only); a later request opens a fresh socket with it"
            }
        }
    }
}

fn credential_env(name: &str) -> anyhow::Result<String> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => Ok(value.trim().to_owned()),
        Ok(_) | Err(std::env::VarError::NotPresent) => anyhow::bail!(
            "{name} is not set; pass --credential-file or set {name} (`oneiron token agent` mints both)"
        ),
        // The error's own Display would quote the value.
        Err(std::env::VarError::NotUnicode(_)) => anyhow::bail!("{name} is not valid UTF-8"),
    }
}

/// The upgrade's own HTTP and WebSocket framing and its hop-by-hop headers,
/// which are the bridge's to set; every `sec-websocket-*` header is the
/// framing's too.
const FRAMING_HEADERS: [&str; 11] = [
    "host",
    "connection",
    "upgrade",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "content-length",
];

/// A slip's holder proof and an MCP connector's credential: either makes the
/// socket someone else's, never the owner's own.
const SLIP_HEADERS: [&str; 2] = ["x-oneiron-binding", "x-oneiron-mcp-credential"];

/// The attestations only a vault's supervisor makes, after it checks the
/// sign-in itself, and strips when a caller brings one.
const SUPERVISOR_HEADERS: [&str; 2] = [
    oneiron_vault_contract::MANAGED_OWNER_ACTION_HEADER,
    "x-oneiron-managed-widen-action",
];

/// The framing of a capability slip and of the paired one-string form: a
/// value holding either carries a slip, whatever header names it.
const SLIP_MARKS: [&str; 2] = ["v2.slip.", "v2.cred."];

/// Why an owner upgrade never takes header `name` from the file, if it
/// does not.
fn refused(name: &str) -> Option<&'static str> {
    if FRAMING_HEADERS.contains(&name) || name.starts_with("sec-websocket-") {
        Some("the upgrade's HTTP and WebSocket framing and hop-by-hop headers are the bridge's")
    } else if SLIP_HEADERS.contains(&name) {
        Some("a holder proof or an MCP connector credential makes the socket a slip's")
    } else if SUPERVISOR_HEADERS.contains(&name) {
        Some("only a vault's supervisor makes that attestation, after it checks the sign-in")
    } else {
        None
    }
}

/// An owner upgrade's headers, as the file holds them. Each value is marked
/// sensitive, so no `Debug` of one shows it.
pub(super) struct UpgradeHeaders(Vec<(HeaderName, HeaderValue)>);

impl UpgradeHeaders {
    /// Reads `path`: a file only its owner may read, by its mode and by any
    /// ACL, holding one JSON object of header names to text values, none of
    /// them one an owner upgrade never takes. Every refusal names the file
    /// and the header, never a value.
    pub(super) fn read(path: &Path) -> anyhow::Result<Self> {
        let mut file = File::open(path).map_err(|error| {
            anyhow::anyhow!(
                "open {}: {error}; pass the file of upgrade headers the surface the owner \
                 signed in on wrote for this vault",
                path.display()
            )
        })?;
        credential_file::admit(path, &file)?;
        let mut text = String::new();
        file.read_to_string(&mut text)
            .map_err(|error| anyhow::anyhow!("read {}: {error}", path.display()))?;
        // Only where it failed: serde's own message can quote the text.
        let entries: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&text)
            .map_err(|error| {
                anyhow::anyhow!(
                    "{} is not one JSON object of header names to text values (line {}, \
                     column {})",
                    path.display(),
                    error.line(),
                    error.column()
                )
            })?;
        let mut headers: Vec<(HeaderName, HeaderValue)> = Vec::with_capacity(entries.len());
        for (name, value) in entries {
            let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
                anyhow::bail!(
                    "{} names a header that is not a valid HTTP header name",
                    path.display()
                );
            };
            if let Some(why) = refused(name.as_str()) {
                anyhow::bail!(
                    "{} names {name}, which an owner upgrade never takes from it: {why}",
                    path.display()
                );
            }
            anyhow::ensure!(
                !headers.iter().any(|(held, _)| *held == name),
                "{} names {name} twice",
                path.display()
            );
            let Some(value) = value.as_str() else {
                anyhow::bail!("{}'s {name} is not a text value", path.display());
            };
            anyhow::ensure!(
                !SLIP_MARKS.iter().any(|mark| value.contains(mark)),
                "{}'s {name} carries a capability slip, and owner mode runs as the vault's \
                 owner with no slip; pass a slip with --auth-mode slip instead",
                path.display()
            );
            let Ok(mut value) = HeaderValue::from_str(value) else {
                anyhow::bail!(
                    "{}'s {name} is not a valid HTTP header value",
                    path.display()
                );
            };
            value.set_sensitive(true);
            headers.push((name, value));
        }
        anyhow::ensure!(
            !headers.is_empty(),
            "{} names no header; the surface the owner signed in on writes his sign-in there",
            path.display()
        );
        Ok(Self(headers))
    }

    /// Sets each header on an upgrade's request.
    pub(super) fn apply(self, headers: &mut HeaderMap) {
        for (name, value) in self.0 {
            headers.insert(name, value);
        }
    }
}
