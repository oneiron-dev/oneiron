//! The broker's side of a git exchange, from its header on (see the parent
//! module's steps): spool and check the body, acknowledge, take the
//! credential, send once, and relay the reply exactly as it came. The
//! spool, the send and the relay are the spooled exchanges' shared ones
//! (`crate::exchange`); the request is git's own.

use std::io;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use reqwest::header::{
    ACCEPT, ACCEPT_ENCODING, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, USER_AGENT,
};
use reqwest::{Body, Client, Method, Url};
use tokio::net::UnixStream;

use super::{GitCallHeader, GitExchange, GitRequestDigest};
use crate::deadline::FAR_FUTURE;
use crate::exchange::credential::{Credential, read_authorization};
use crate::exchange::idle_bound;
use crate::exchange::relay::{answer, relay, reply_header};
use crate::exchange::send::{Sent, send};
use crate::exchange::spool::{acknowledge, drain, spool, spool_body};
use crate::frame::{read_segment, write_stream_end, write_stream_header};
use crate::send::{Sender, encoded, git_echo_forms, git_reply_headers};
use crate::{Failure, MAX_SECRET, Outcome, Refusal};

/// The user agent of a git exchange: a smart-HTTP server serves its smart
/// protocol to a `git/` agent.
const GIT_USER_AGENT: &str = "git/oneiron-broker";

/// Serves one git exchange whose header the frame opened with. The
/// connection is closed at the end; a broken one ends the exchange where it
/// broke, and nothing is sent once the daemon is gone.
pub(crate) async fn serve_git(mut stream: UnixStream, header: GitCallHeader, sender: &Sender) {
    let _ = exchange(&mut stream, &header, sender).await;
}

async fn exchange(
    stream: &mut UnixStream,
    header: &GitCallHeader,
    sender: &Sender,
) -> io::Result<()> {
    let client = sender.exchange_client();
    let idle = header.idle();
    let (call, digest) = (header.call.as_str(), header.digest.as_str());
    let prepared = match header.check() {
        Ok(url) => {
            let body =
                GitRequestDigest::new(&header.target, &header.headers, header.body_len).into_body();
            spool(stream, header.body_len, body, digest, idle)
                .await?
                .map(|spool| (url, spool))
        }
        Err(reason) => {
            drain(stream, idle).await?;
            Err(reason)
        }
    };
    let (url, spool) = match prepared {
        Ok(prepared) => prepared,
        Err(reason) => return acknowledge(stream, call, digest, Some(reason), idle).await,
    };
    acknowledge(stream, call, digest, None, idle).await?;
    let secret = idle_bound(idle, read_segment(stream, MAX_SECRET)).await?;
    let credential = match read_authorization(&secret) {
        Ok(credential) => credential,
        Err(reason) => {
            return answer(stream, call, digest, Outcome::Refused { reason }, idle).await;
        }
    };
    drop(secret);
    let progress = Arc::new(AtomicU64::new(0));
    let body = (header.target.exchange == GitExchange::Rpc)
        .then(|| (spool.len, spool_body(spool, Arc::clone(&progress))));
    let request = match request(client, header, url, body, &credential) {
        Ok(request) => request,
        Err(reason) => {
            return answer(stream, call, digest, Outcome::Refused { reason }, idle).await;
        }
    };
    let mut response = match send(client, request, stream, &progress, idle).await {
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
    let forms = git_echo_forms(&credential.watched);
    let answered = Outcome::Answered {
        status: response.status().as_u16(),
        headers: git_reply_headers(response.headers(), &forms),
    };
    idle_bound(
        idle,
        write_stream_header(stream, &reply_header(call, digest, answered)),
    )
    .await?;
    let cut = relay(&mut response, stream, forms, idle).await?;
    idle_bound(idle, write_stream_end(stream, cut)).await
}

/// The exchange's request: its target's method, URL, content types and
/// agent, identity coding, the one `git-protocol` header the call may
/// carry, and the credential as the one auth header. An RPC carries its
/// spooled body at its exact length. No total timeout: the send's idle
/// bound and the daemon's hang-up end it ([`send`]).
fn request(
    client: &Client,
    header: &GitCallHeader,
    url: Url,
    body: Option<(u64, Body)>,
    credential: &Credential,
) -> Result<reqwest::Request, Refusal> {
    let method =
        Method::from_bytes(header.target.method().as_bytes()).map_err(|_| Refusal::Method)?;
    let mut builder = client
        .request(method, url)
        .timeout(FAR_FUTURE)
        .header(ACCEPT_ENCODING, "identity")
        .header(ACCEPT, header.target.reply_content_type())
        .header(USER_AGENT, GIT_USER_AGENT)
        .header(AUTHORIZATION, credential.header.clone());
    for (name, value) in &header.headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    if let (Some(content_type), Some((len, body))) = (header.target.request_content_type(), body) {
        builder = builder
            .header(CONTENT_TYPE, content_type)
            .header(CONTENT_LENGTH, len)
            .body(body);
    }
    builder.build().map_err(|_| Refusal::Header)
}
