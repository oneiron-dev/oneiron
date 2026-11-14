//! `oneiron hosted login --origin <url>` with no credential: this user signs
//! in to the hosted vault through the vault's own OAuth 2.1 server, as a
//! native app (RFC 8252; ruling L1-14-HOSTED-LOGIN = B, Engine Sat 14 Nov
//! 03:02).
//!
//! The command reads the vault's protected-resource document for the
//! resource and its issuer, listens on a loopback port, registers a public
//! client with that loopback redirect, and prints the authorize URL (PKCE
//! S256, a fresh `state`, the `read` scope, the `resource`) and opens it in a
//! browser. The vault's page shows a match code, and the owner allows the
//! request in his inbox, where the same code shows; the browser then comes
//! back to the loopback with the code. The command checks `state` and `iss`,
//! exchanges the code with its verifier, and writes the tokens to one
//! owner-only file ([`crate::commands::oauth_sign_in`]). Nothing here mints
//! authority: the hook then reaches the vault as an ordinary OAuth agent in
//! the owner's consent registry, at the tier he allowed.

use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::Path;
use std::time::{Duration, Instant};

use base64::Engine as _;
use rand_core::{OsRng, RngCore as _};
use serde::Deserialize;
use sha2::Digest as _;

use crate::api::{
    AUTHORIZE_PATH, PROTECTED_RESOURCE_MCP_METADATA_PATH, REGISTER_PATH, REVOKE_PATH, TOKEN_PATH,
};
use crate::commands::oauth_sign_in::{self, MAX_ANSWER_BYTES, OAuthSignIn, SignInParty};

/// Where the browser comes back to on the loopback.
const CALLBACK_PATH: &str = "/oauth/callback";
/// The tier asked for: a hook recalls, and writes nothing.
const REQUESTED_SCOPE: &str = "read";
/// The name the owner's ask and consent registry show for the client.
const CLIENT_NAME: &str = "oneiron hosted login";
/// The most of a callback request read: its request line and headers.
const MAX_REQUEST_HEAD_BYTES: usize = 8 * 1024;
/// How long one loopback connection may take to send its request.
const CALLBACK_READ_TIMEOUT: Duration = Duration::from_secs(5);
/// How often the loopback is checked for the browser's return.
const CALLBACK_POLL: Duration = Duration::from_millis(100);

/// The vault's protected-resource document (RFC 9728).
#[derive(Deserialize)]
struct ProtectedResource {
    resource: String,
    #[serde(default)]
    authorization_servers: Vec<String>,
}

/// A registration's answer (RFC 7591 §3.2.1): the one field read.
#[derive(Deserialize)]
struct Registered {
    client_id: String,
}

/// Signs this user in at the vault at `origin` and writes the sign-in to
/// `token_file`, within `timeout` from the start to the browser's return.
/// Runs on the blocking pool of the command's runtime.
pub(super) fn sign_in(origin: &str, token_file: &Path, timeout: Duration) -> anyhow::Result<()> {
    let runtime = tokio::runtime::Handle::try_current()
        .map_err(|_| anyhow::anyhow!("hosted login signs in on the command's runtime"))?;
    let deadline = Instant::now() + timeout;
    let client = oauth_sign_in::endpoint_client()?;
    let document: ProtectedResource = runtime.block_on(get_json(
        &client,
        &format!("{origin}{PROTECTED_RESOURCE_MCP_METADATA_PATH}"),
    ))?;
    let issuer = document
        .authorization_servers
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("{origin} names no authorization server for its MCP"))?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .map_err(|error| anyhow::anyhow!("listen on the loopback: {error}"))?;
    let redirect_uri = format!(
        "http://127.0.0.1:{}{CALLBACK_PATH}",
        listener.local_addr()?.port()
    );
    let client_id = runtime.block_on(register(&client, origin, &redirect_uri))?;
    let verifier = random_text(32);
    let state = random_text(16);
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(sha2::Sha256::digest(verifier.as_bytes()));
    let mut authorize = reqwest::Url::parse(&format!("{origin}{AUTHORIZE_PATH}"))?;
    authorize
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &client_id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", &state)
        .append_pair("scope", REQUESTED_SCOPE)
        .append_pair("resource", &document.resource);
    let _ = writeln!(
        std::io::stderr().lock(),
        "To sign in to {origin}, open this page in a browser on this machine:\n  {authorize}\n\
         It shows a match code. Allow the request in your Oneiron inbox when its match code is \
         the same; this command waits up to {}s.",
        timeout.as_secs()
    );
    open_in_browser(authorize.as_str());
    let code = wait_for_code(&listener, &state, &issuer, deadline)?;
    let token_endpoint = format!("{origin}{TOKEN_PATH}");
    let answer = runtime.block_on(oauth_sign_in::token_call(
        &client,
        &token_endpoint,
        &[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("client_id", client_id.as_str()),
            ("code_verifier", verifier.as_str()),
            ("resource", document.resource.as_str()),
        ],
    ))?;
    let party = SignInParty {
        token_endpoint,
        revocation_endpoint: format!("{origin}{REVOKE_PATH}"),
        client_id,
        resource: document.resource,
    };
    OAuthSignIn::from_answer(party, answer, oauth_sign_in::now_ms())?.write(token_file)
}

/// Revokes the sign-in in `token_file` at its vault, best effort, and
/// removes the file, which `hosted login` wrote. A vault that does not
/// answer is named on stderr; the file goes all the same.
pub(super) fn sign_out(token_file: &Path) -> anyhow::Result<()> {
    if let Ok(sign_in) = OAuthSignIn::read(token_file) {
        let revoked = tokio::runtime::Handle::try_current()
            .map_err(|_| anyhow::anyhow!("no runtime"))
            .and_then(|runtime| {
                let client = oauth_sign_in::endpoint_client()?;
                runtime.block_on(oauth_sign_in::revoke(&client, &sign_in))
            });
        if let Err(error) = revoked {
            let _ = writeln!(
                std::io::stderr().lock(),
                "the vault did not confirm the sign-out ({error}); the owner can revoke it in his \
                 consent registry"
            );
        }
    }
    let mut lock = token_file.as_os_str().to_owned();
    lock.push(".lock");
    for path in [token_file, Path::new(&lock)] {
        if let Err(error) = std::fs::remove_file(path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            anyhow::bail!("remove {}: {error}", path.display());
        }
    }
    Ok(())
}

/// GETs `url` and reads its JSON answer.
async fn get_json<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
) -> anyhow::Result<T> {
    let response = client
        .get(url)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|error| anyhow::anyhow!("could not reach {url}: {}", error.without_url()))?;
    let status = response.status();
    anyhow::ensure!(
        status != reqwest::StatusCode::NOT_FOUND,
        "{url} is not served: this origin offers no OAuth sign-in. Sign in on the console or the \
         app instead, and pass the credential it wrote with --credential-file or \
         --owner-upgrade-headers-file"
    );
    anyhow::ensure!(
        status.is_success(),
        "{url} answered HTTP {}",
        status.as_u16()
    );
    let body = response
        .bytes()
        .await
        .map_err(|error| anyhow::anyhow!("{url}'s answer broke off: {}", error.without_url()))?;
    anyhow::ensure!(
        body.len() <= MAX_ANSWER_BYTES,
        "{url}'s answer is too large"
    );
    serde_json::from_slice(&body).map_err(|_| anyhow::anyhow!("{url} answered no such document"))
}

/// Registers a public client at the vault (RFC 7591) whose one redirect is
/// `redirect_uri`, and answers its id.
async fn register(
    client: &reqwest::Client,
    origin: &str,
    redirect_uri: &str,
) -> anyhow::Result<String> {
    let endpoint = format!("{origin}{REGISTER_PATH}");
    let response = client
        .post(&endpoint)
        .json(&serde_json::json!({
            "redirect_uris": [redirect_uri],
            "client_name": CLIENT_NAME,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        }))
        .send()
        .await
        .map_err(|error| anyhow::anyhow!("could not reach {endpoint}: {}", error.without_url()))?;
    let status = response.status();
    let body = response.bytes().await.map_err(|error| {
        anyhow::anyhow!("{endpoint}'s answer broke off: {}", error.without_url())
    })?;
    anyhow::ensure!(
        status.is_success() && body.len() <= MAX_ANSWER_BYTES,
        "{endpoint} did not register this client (HTTP {})",
        status.as_u16()
    );
    let registered: Registered = serde_json::from_slice(&body)
        .map_err(|_| anyhow::anyhow!("{endpoint} answered no client id"))?;
    Ok(registered.client_id)
}

/// `bytes` fresh random bytes, as unpadded base64url text.
fn random_text(bytes: usize) -> String {
    let mut held = vec![0_u8; bytes];
    OsRng.fill_bytes(&mut held);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(held)
}

/// Opens `url` in the person's browser, best effort: the URL is printed
/// whether or not this works.
fn open_in_browser(url: &str) {
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    if let Ok(mut child) = std::process::Command::new(opener)
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        std::thread::spawn(move || {
            let _ = child.wait();
        });
    }
}

/// Waits on `listener` until `deadline` for the browser's return to the
/// callback with this sign-in's `state`, and answers its code. A request
/// for another path or with another `state` is answered and ignored.
fn wait_for_code(
    listener: &TcpListener,
    state: &str,
    issuer: &str,
    deadline: Instant,
) -> anyhow::Result<String> {
    listener.set_nonblocking(true)?;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                if let Some(outcome) = callback(stream, state, issuer) {
                    return outcome;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                anyhow::ensure!(
                    Instant::now() < deadline,
                    "the browser did not come back from the sign-in in time; nothing was \
                     recorded. Run `oneiron hosted login --origin <url>` again"
                );
                std::thread::sleep(CALLBACK_POLL);
            }
            Err(error) => anyhow::bail!("the loopback listener failed: {error}"),
        }
    }
}

/// One loopback request: `None` when it is not this sign-in's return, which
/// is answered and ignored; else the code, or why the sign-in ended.
fn callback(mut stream: TcpStream, state: &str, issuer: &str) -> Option<anyhow::Result<String>> {
    stream.set_nonblocking(false).ok()?;
    stream.set_read_timeout(Some(CALLBACK_READ_TIMEOUT)).ok()?;
    let target = request_target(&mut stream)?;
    let url = reqwest::Url::parse(&format!("http://127.0.0.1{target}")).ok()?;
    if url.path() != CALLBACK_PATH {
        respond(&mut stream, "404 Not Found", "Not found.");
        return None;
    }
    let param = |name: &str| {
        url.query_pairs()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
    };
    if param("state").as_deref() != Some(state) {
        respond(
            &mut stream,
            "400 Bad Request",
            "This is not the sign-in this command is waiting for.",
        );
        return None;
    }
    if param("iss").is_some_and(|iss| iss != issuer) {
        respond(
            &mut stream,
            "400 Bad Request",
            "The sign-in came from another vault.",
        );
        return Some(Err(anyhow::anyhow!(
            "the sign-in came back from an issuer other than {issuer}; nothing was recorded"
        )));
    }
    if let Some(error) = param("error") {
        respond(
            &mut stream,
            "200 OK",
            "The sign-in did not complete. You can close this tab.",
        );
        let error: String = error
            .chars()
            .filter(char::is_ascii_graphic)
            .take(64)
            .collect();
        return Some(Err(anyhow::anyhow!(
            "the vault ended the sign-in ({error}); nothing was recorded"
        )));
    }
    let Some(code) = param("code") else {
        respond(
            &mut stream,
            "400 Bad Request",
            "The sign-in brought no code.",
        );
        return None;
    };
    respond(
        &mut stream,
        "200 OK",
        "Signed in. You can close this tab and go back to the terminal.",
    );
    Some(Ok(code))
}

/// The request target of a GET on `stream`, from its request line.
fn request_target(stream: &mut TcpStream) -> Option<String> {
    let mut head = Vec::new();
    let mut chunk = [0_u8; 1024];
    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            break;
        }
        head.extend_from_slice(&chunk[..read]);
        if head.len() > MAX_REQUEST_HEAD_BYTES {
            return None;
        }
    }
    let line = std::str::from_utf8(&head).ok()?.lines().next()?.to_owned();
    let mut words = line.split(' ');
    let (Some("GET"), Some(target)) = (words.next(), words.next()) else {
        return None;
    };
    target.starts_with('/').then(|| target.to_owned())
}

/// Answers `stream` with `status` and a one-line page of `text`.
fn respond(stream: &mut TcpStream, status: &str, text: &str) {
    let body = format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Oneiron sign-in</title><p>{text}</p>"
    );
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.flush();
}
