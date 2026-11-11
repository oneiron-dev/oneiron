//! The broker's side of an LFS exchange, from its header on (see the parent
//! module's steps): spool and check the body, admit an action's host,
//! acknowledge, take the credential segment, send once, and relay the reply
//! as it came, but for a batch reply's exact echoes of the credential in
//! its action headers. The spool, the send and the relay are the spooled
//! exchanges' shared ones (`crate::exchange`); the target, the admission,
//! the request and the batch reply's rewrite are LFS's own.

use std::io;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use oneiron_sandbox_contract::network::global_address;
use reqwest::header::{
    ACCEPT, ACCEPT_ENCODING, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING,
};
use reqwest::{Body, Client, Method, Url};
use serde_json::Value;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use zeroize::Zeroizing;

use super::{
    BatchRewrites, LFS_CREDENTIAL_PLACEHOLDER, LfsCallHeader, LfsRequestDigest,
    is_credential_placeholder,
};
use crate::deadline::FAR_FUTURE;
use crate::exchange::credential::{Credential, read_authorization};
use crate::exchange::idle_bound;
use crate::exchange::relay::{answer, read_whole, relay, relay_whole, reply_header};
use crate::exchange::send::{Sent, send};
use crate::exchange::spool::{Spool, acknowledge, drain, spool, spool_body};
use crate::frame::{read_segment, write_segment, write_stream_end, write_stream_header};
use crate::send::{Sender, encoded, git_echo_forms, git_reply_headers};
use crate::{Failure, MAX_SECRET, Outcome, Refusal};

/// Serves one LFS exchange whose header the frame opened with. The
/// connection is closed at the end; a broken one ends the exchange where it
/// broke, and nothing is sent once the daemon is gone.
pub(crate) async fn serve_lfs(mut stream: UnixStream, header: LfsCallHeader, sender: &Sender) {
    let _ = exchange(&mut stream, &header, sender).await;
}

async fn exchange(
    stream: &mut UnixStream,
    header: &LfsCallHeader,
    sender: &Sender,
) -> io::Result<()> {
    let idle = header.idle();
    let (call, digest) = (header.call.as_str(), header.digest.as_str());
    let (url, spooled, pinned) = match admit(stream, header, sender).await? {
        Ok(admitted) => admitted,
        Err(reason) => return acknowledge(stream, call, digest, Some(reason), idle).await,
    };
    acknowledge(stream, call, digest, None, idle).await?;
    let secret = idle_bound(idle, read_segment(stream, MAX_SECRET)).await?;
    let credential = match lfs_credential(header, &secret) {
        Ok(credential) => credential,
        Err(reason) => {
            return answer(stream, call, digest, Outcome::Refused { reason }, idle).await;
        }
    };
    drop(secret);
    let client = match &pinned {
        Some(pinned) => pinned,
        None => sender.exchange_client(),
    };
    let progress = Arc::new(AtomicU64::new(0));
    let body = header
        .target
        .carries_body()
        .then(|| (spooled.len, spool_body(spooled, Arc::clone(&progress))));
    let request = match request(client, header, url, body, credential.as_ref()) {
        Ok(request) => request,
        Err(reason) => {
            return answer(stream, call, digest, Outcome::Refused { reason }, idle).await;
        }
    };
    let response = match send(client, request, stream, &progress, idle).await {
        Sent::Response(response) => response,
        Sent::Outcome(outcome) => return answer(stream, call, digest, outcome, idle).await,
        Sent::Cancelled => return Ok(()),
    };
    if encoded(response.headers()) {
        let outcome = Outcome::Failed {
            reason: Failure::ReplyEncoded,
        };
        return answer(stream, call, digest, outcome, idle).await;
    }
    relay_reply(stream, header, response, credential.as_ref()).await
}

/// Relays the far end's reply: its header, then an action's body as it
/// streams, or a batch's rewrite count and its body read whole and
/// rewritten ([`batch_reply`]); then its end, clean or cut. Each is watched
/// for the forms of the credential the exchange carried
/// ([`lfs_echo_forms`]): on a batch, or on an action in place of the
/// placeholder. An action that carried none has its reply go byte for
/// byte.
async fn relay_reply(
    stream: &mut UnixStream,
    header: &LfsCallHeader,
    mut response: reqwest::Response,
    credential: Option<&Credential>,
) -> io::Result<()> {
    let idle = header.idle();
    let (call, digest) = (header.call.as_str(), header.digest.as_str());
    let forms = credential.map_or_else(Vec::new, lfs_echo_forms);
    let status = response.status().as_u16();
    let mut headers = git_reply_headers(response.headers(), &forms);
    let Some(limit) = header.batch_reply_limit() else {
        let answered = Outcome::Answered { status, headers };
        idle_bound(
            idle,
            write_stream_header(stream, &reply_header(call, digest, answered)),
        )
        .await?;
        let cut = relay(&mut response, stream, forms, idle).await?;
        return idle_bound(idle, write_stream_end(stream, cut)).await;
    };
    // A batch's reply is read whole, so its rewrites are made and counted
    // before its header goes.
    let read = batch_reply(&mut response, limit, idle, credential).await?;
    let credential_rewrites = read.as_ref().map_or(0, |(_, rewrites)| *rewrites);
    if credential_rewrites > 0 {
        // The rewritten body is not the length the far end sent.
        headers.retain(|(name, _)| name != CONTENT_LENGTH.as_str());
    }
    let answered = Outcome::Answered { status, headers };
    idle_bound(
        idle,
        write_stream_header(stream, &reply_header(call, digest, answered)),
    )
    .await?;
    write_rewrites(stream, credential_rewrites, idle).await?;
    let cut = match read {
        Ok((body, _)) => relay_whole(stream, &body, &forms, idle).await?,
        Err(failure) => Some(failure),
    };
    idle_bound(idle, write_stream_end(stream, cut)).await
}

/// A batch's reply body, read whole within `limit` bytes, with
/// `credential`'s exact echoes in its action headers rewritten
/// ([`rewrite_batch_reply`]), and how many were; or the failure that ended
/// the read.
async fn batch_reply(
    response: &mut reqwest::Response,
    limit: u64,
    idle: Duration,
    credential: Option<&Credential>,
) -> io::Result<Result<(Zeroizing<Vec<u8>>, u64), Failure>> {
    let body = match read_whole(response, limit, idle).await? {
        Ok(body) => body,
        Err(failure) => return Ok(Err(failure)),
    };
    let rewritten =
        credential.and_then(|credential| rewrite_batch_reply(&body, credential.header.as_bytes()));
    Ok(Ok(rewritten.unwrap_or((body, 0))))
}

/// The batch reply `body` with each action header value that is
/// `installed`, the complete `Authorization` value the broker sent, byte
/// for byte, rewritten to [`LFS_CREDENTIAL_PLACEHOLDER`]: in
/// `objects[*].actions.<name>.header` of an object with no `error` (none,
/// or `null`), and nowhere else. Returns the reply as JSON writes it again
/// and how many values it rewrote; or `None`, and the reply goes as it
/// came, when it is not JSON or nothing in it was rewritten. Each value
/// taken out is wiped as it drops.
fn rewrite_batch_reply(body: &[u8], installed: &[u8]) -> Option<(Zeroizing<Vec<u8>>, u64)> {
    let mut reply: Value = serde_json::from_slice(body).ok()?;
    let values = reply
        .get_mut("objects")
        .and_then(Value::as_array_mut)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object_mut)
        .filter(|object| object.get("error").is_none_or(Value::is_null))
        .filter_map(|object| object.get_mut("actions").and_then(Value::as_object_mut))
        .flat_map(|actions| actions.values_mut())
        .filter_map(|action| action.get_mut("header").and_then(Value::as_object_mut))
        .flat_map(|header| header.values_mut());
    let mut rewrites = 0_u64;
    for value in values {
        if value
            .as_str()
            .is_some_and(|text| text.as_bytes() == installed)
        {
            let echoed =
                std::mem::replace(value, Value::String(LFS_CREDENTIAL_PLACEHOLDER.to_owned()));
            if let Value::String(echoed) = echoed {
                drop(Zeroizing::new(echoed));
            }
            rewrites += 1;
        }
    }
    if rewrites == 0 {
        return None;
    }
    serde_json::to_vec(&reply)
        .ok()
        .map(|rewritten| (Zeroizing::new(rewritten), rewrites))
}

/// Writes an answered batch reply's rewrite count, the LFS frame between
/// its header and its body ([`BatchRewrites`]).
async fn write_rewrites(
    stream: &mut UnixStream,
    credential_rewrites: u64,
    idle: Duration,
) -> io::Result<()> {
    let frame = serde_json::to_vec(&BatchRewrites {
        credential_rewrites,
    })
    .map_err(io::Error::other)?;
    idle_bound(idle, async {
        write_segment(stream, &frame).await?;
        stream.flush().await
    })
    .await
}

/// The forms the reply of an exchange that carries `credential` is watched
/// for: the token's literal forms ([`git_echo_forms`]), and the complete
/// `Authorization` value the broker installed, raw and as JSON spells it,
/// whatever its length, so a reply that hands the whole value back is cut
/// wherever the batch reply's rewrite did not take it out.
fn lfs_echo_forms(credential: &Credential) -> Vec<Zeroizing<Vec<u8>>> {
    let installed = credential.header.as_bytes();
    let mut forms = git_echo_forms(&credential.watched);
    // The whole installed value, and the credentials after its scheme on
    // their own: an auth scheme reads the same in any case and after any
    // run of spaces (`basic dXNl…` authenticates as `Basic dXNl…`), so the
    // payload alone is watched too, with no short-token filter, raw and in
    // its JSON spelling.
    let payload = installed
        .iter()
        .position(|byte| *byte == b' ')
        .map(|space| installed[space..].trim_ascii())
        .filter(|payload| !payload.is_empty());
    for form in std::iter::once(installed).chain(payload) {
        forms.push(Zeroizing::new(form.to_vec()));
        if let Ok(text) = std::str::from_utf8(form)
            && let Ok(quoted) = serde_json::to_string(text).map(Zeroizing::new)
        {
            forms.push(Zeroizing::new(
                quoted.as_bytes()[1..quoted.len() - 1].to_vec(),
            ));
        }
    }
    forms
}

/// Checks the header, spools the body, and for an action admits its host.
/// Returns the URL, the spool and, for an action, the client pinned to its
/// host's admitted addresses; or the refusal, the body read to its end
/// either way.
async fn admit(
    stream: &mut UnixStream,
    header: &LfsCallHeader,
    sender: &Sender,
) -> io::Result<Result<(Url, Spool, Option<Client>), Refusal>> {
    let idle = header.idle();
    let url = match header.check() {
        Ok(url) => url,
        Err(reason) => {
            drain(stream, idle).await?;
            return Ok(Err(reason));
        }
    };
    let body = LfsRequestDigest::new(&header.target, &header.headers, header.body_len).into_body();
    let spooled = match spool(stream, header.body_len, body, &header.digest, idle).await? {
        Ok(spooled) => spooled,
        Err(reason) => return Ok(Err(reason)),
    };
    if header.target.is_batch() {
        return Ok(Ok((url, spooled, None)));
    }
    let pinned = match pinned_action_client(sender, &url, idle).await {
        Ok(pinned) => pinned,
        Err(reason) => return Ok(Err(reason)),
    };
    Ok(Ok((url, spooled, Some(pinned))))
}

/// An action's client: its host resolved now, within `idle`, every address
/// it resolves to a global one, and the client reaching those addresses
/// alone, so the name is never resolved again after its admission. A batch
/// goes to its repository's own host through the shared client, as it
/// always has.
async fn pinned_action_client(
    sender: &Sender,
    url: &Url,
    idle: Duration,
) -> Result<Client, Refusal> {
    let host = url.host_str().ok_or(Refusal::Origin)?.to_owned();
    let lookup = url.clone();
    // An `https` URL always has a port: its own, or the scheme's.
    let resolved = tokio::time::timeout(
        idle,
        tokio::task::spawn_blocking(move || lookup.socket_addrs(|| None)),
    )
    .await;
    let Ok(Ok(Ok(addresses))) = resolved else {
        return Err(Refusal::Connect);
    };
    if addresses.is_empty()
        || addresses
            .iter()
            .any(|address| !global_address(address.ip()))
    {
        return Err(Refusal::Origin);
    }
    sender
        .pinned_exchange_client(&host, &addresses)
        .map_err(|_| Refusal::Connect)
}

/// The credential the exchange carries, from its credential segment
/// `secret`: none when it is empty (an anonymous batch, or an action with
/// its own headers alone); the `Authorization` value it holds for a batch,
/// or for an action that names the placeholder
/// ([`LfsCallHeader::names_credential_placeholder`]), whose URL's origin its
/// check found to be the repository's. A segment that holds anything for
/// any other action is refused, since that action never carries the
/// repository credential.
fn lfs_credential(header: &LfsCallHeader, secret: &[u8]) -> Result<Option<Credential>, Refusal> {
    if secret.is_empty() {
        Ok(None)
    } else if header.target.is_batch() || header.names_credential_placeholder() {
        read_authorization(secret).map(Some)
    } else {
        Err(Refusal::Secret)
    }
}

/// The exchange's request: its target's method and URL, identity coding,
/// an action's own headers as given (but for the credential in place of
/// each header's placeholder, under that header's own name, when the
/// action carries it), the
/// media types its target derives where an action names none of its own,
/// and for a batch the credential as the one auth header. A body goes at
/// the spool's exact length, unless an action names its own
/// `Content-Length` (of that length) or `Transfer-Encoding` (chunked). No
/// total timeout: the send's idle bound and the daemon's hang-up end it
/// ([`send`]).
fn request(
    client: &Client,
    header: &LfsCallHeader,
    url: Url,
    body: Option<(u64, Body)>,
    credential: Option<&Credential>,
) -> Result<reqwest::Request, Refusal> {
    let target = &header.target;
    let method = Method::from_bytes(target.method().as_bytes()).map_err(|_| Refusal::Method)?;
    let named = |wanted: &str| {
        header
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case(wanted))
    };
    let mut builder = client
        .request(method, url)
        .timeout(FAR_FUTURE)
        .header(ACCEPT_ENCODING, "identity");
    for (name, value) in &header.headers {
        builder = match credential {
            // The credential again, under the header's own name, where the
            // batch reply's rewrite put the placeholder for it.
            Some(credential) if is_credential_placeholder(value) => {
                builder.header(name.as_str(), credential.header.clone())
            }
            _ => builder.header(name.as_str(), value.as_str()),
        };
    }
    if let Some(accept) = target.accept()
        && !named(ACCEPT.as_str())
    {
        builder = builder.header(ACCEPT, accept);
    }
    if target.is_batch()
        && let Some(credential) = credential
    {
        builder = builder.header(AUTHORIZATION, credential.header.clone());
    }
    if let Some((len, body)) = body {
        if let Some(content_type) = target.content_type()
            && !named(CONTENT_TYPE.as_str())
        {
            builder = builder.header(CONTENT_TYPE, content_type);
        }
        if !named(CONTENT_LENGTH.as_str()) && !named(TRANSFER_ENCODING.as_str()) {
            builder = builder.header(CONTENT_LENGTH, len);
        }
        builder = builder.body(body);
    }
    builder.build().map_err(|_| Refusal::Header)
}
