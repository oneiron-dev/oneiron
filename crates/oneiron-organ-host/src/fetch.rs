//! The granted fetch, `net.fetch`: the engine fetches for an organ that has
//! no network of its own, inside the allowlist its install grant names.
//!
//! Every hop's origin (scheme, host, port) must be on the allowlist. DNS is
//! resolved once per hop; an address that is not global is dropped unless a
//! granted CIDR names it, and the connection goes only to the addresses
//! checked, so a name cannot rebind between the check and the connect. At
//! most three redirects, each checked afresh. No proxy, no cookies, no
//! credentials, no compression. The body is capped, and the whole fetch,
//! every hop's send and its whole body, runs inside the call's time left.
//! These are the rules the seal crate's own guarded fetcher keeps
//! (ARCH-0064a, SGN-00). A POST redirected by 301, 302 or 303 goes on as a
//! GET without its body; by 307 or 308 it keeps both (RFC 9110 §15.4).
//!
//! The handler blocks, as a host call does: run it off any async runtime.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

use oneiron_organ_protocol::{
    AskCode, AskRefusal, ByteBuf, FetchAnswer, FetchAsk, FetchMethod, Hash32,
};
use reqwest::Url;

use crate::handlers::{Answered, AskHandler, AskRequest};
use crate::receipt::{FetchTarget, bound_text};
use crate::spec::FetchGrant;

const MAX_REDIRECTS: u8 = 3;
const MAX_PURPOSE_BYTES: usize = 32;
const MAX_CONTENT_TYPE_BYTES: usize = 256;

/// The host's guarded HTTP fetch, the handler for `net.fetch`.
#[derive(Debug, Clone, Copy, Default)]
pub struct GuardedFetch;

fn refused(code: AskCode, detail: impl Into<String>) -> AskRefusal {
    AskRefusal::new(code, detail)
}

fn failed(detail: impl Into<String>) -> AskRefusal {
    AskRefusal::new(AskCode::Failed, detail).retryable()
}

/// Reads a fetch ask as the wire carries it: named fields, enums by name.
fn parse(value: &rmpv::Value) -> Result<(FetchAsk, Url), AskRefusal> {
    let not_a_fetch =
        |err: &dyn std::fmt::Display| refused(AskCode::BadRequest, format!("not a fetch: {err}"));
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).map_err(|err| not_a_fetch(&err))?;
    let ask: FetchAsk = rmp_serde::from_slice(&bytes).map_err(|err| not_a_fetch(&err))?;
    if ask.purpose.len() > MAX_PURPOSE_BYTES {
        return Err(refused(AskCode::BadRequest, "the purpose is over 32 bytes"));
    }
    let url = Url::parse(&ask.url)
        .map_err(|err| refused(AskCode::BadRequest, format!("the url: {err}")))?;
    Ok((ask, url))
}

fn origin(url: &Url) -> String {
    format!(
        "{}://{}:{}",
        url.scheme(),
        url.host_str().unwrap_or_default(),
        url.port_or_known_default().unwrap_or(0)
    )
}

/// Whether `url` may be fetched under `grant`: an exact origin on the
/// allowlist, and no credentials.
fn allowed(url: &Url, grant: &FetchGrant) -> Result<(), AskRefusal> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err(refused(AskCode::NotGranted, "only http and https"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(refused(AskCode::NotGranted, "credentials in the url"));
    }
    let port = url.port_or_known_default();
    let host = url.host_str();
    let named = grant.origins.iter().any(|granted| {
        granted.scheme == url.scheme()
            && Some(granted.host.as_str()) == host
            && Some(granted.port) == port
    });
    if named {
        Ok(())
    } else {
        Err(refused(
            AskCode::NotGranted,
            format!("{} is not on the allowlist", origin(url)),
        ))
    }
}

/// The host's own check of a fetch's first hop, before any handler runs.
/// Returns what the receipt records of the target either way.
pub(crate) fn first_hop(
    value: &rmpv::Value,
    grant: &FetchGrant,
) -> (Option<FetchTarget>, Result<(), AskRefusal>) {
    let (_, url) = match parse(value) {
        Ok(parsed) => parsed,
        Err(refusal) => return (None, Err(refusal)),
    };
    let target = FetchTarget {
        origin: bound_text(&origin(&url), MAX_CONTENT_TYPE_BYTES),
        url_digest: Hash32::of(url.as_str().as_bytes()),
        status: 0,
    };
    (Some(target), allowed(&url, grant))
}

/// Resolves `url`'s host once, inside the time left, and keeps only the
/// addresses the grant lets a fetch reach.
fn resolve(
    url: &Url,
    grant: &FetchGrant,
    deadline: Instant,
) -> Result<Vec<SocketAddr>, AskRefusal> {
    let host = url
        .host_str()
        .ok_or_else(|| refused(AskCode::BadRequest, "no host"))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| refused(AskCode::BadRequest, "no port"))?;
    let (found, looked_up) = mpsc::sync_channel(1);
    // A stalled resolver holds only this thread, never the call.
    thread::Builder::new()
        .name("organ-fetch-dns".into())
        .spawn(move || {
            let addrs = (host.as_str(), port)
                .to_socket_addrs()
                .map(Iterator::collect::<Vec<_>>);
            let _ = found.send(addrs);
        })
        .map_err(|err| failed(format!("resolve: {err}")))?;
    let left = deadline.saturating_duration_since(Instant::now());
    let addrs = looked_up
        .recv_timeout(left)
        .map_err(|_| failed("resolve: out of time"))?
        .map_err(|err| failed(format!("resolve: {err}")))?;
    let reachable: Vec<SocketAddr> = addrs
        .into_iter()
        .filter(|addr| address_allowed(addr.ip(), &grant.private_cidrs))
        .collect();
    if reachable.is_empty() {
        return Err(refused(
            AskCode::NotGranted,
            "no address the grant lets a fetch reach",
        ));
    }
    Ok(reachable)
}

impl AskHandler for GuardedFetch {
    fn answer(&self, ask: &AskRequest<'_>) -> Result<Answered, AskRefusal> {
        let (request, first) = parse(ask.value)?;
        let cap = ask.fetch.max_bytes.min(ask.max_bytes);
        let deadline = ask.deadline;
        // One deadline over the whole fetch, every hop's send and all of its
        // body: at the deadline the fetch is dropped, and its connection
        // with it. (reqwest's blocking timeout starts afresh at every read,
        // so a server that drips its body would outlast it.)
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|err| failed(format!("fetch: {err}")))?;
        runtime.block_on(async {
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                fetch(&request, first, ask.fetch, cap, deadline),
            )
            .await
            .unwrap_or_else(|_| Err(failed("out of time")))
        })
    }
}

/// The fetch itself, hop by hop. DNS is bounded by `deadline` here; the
/// caller bounds the rest.
async fn fetch(
    request: &FetchAsk,
    first: Url,
    grant: &FetchGrant,
    cap: u64,
    deadline: Instant,
) -> Result<Answered, AskRefusal> {
    let mut target = FetchTarget {
        origin: bound_text(&origin(&first), MAX_CONTENT_TYPE_BYTES),
        url_digest: Hash32::of(first.as_str().as_bytes()),
        status: 0,
    };
    let mut url = first;
    let mut method = request.method;
    let mut hops = 0u8;
    loop {
        allowed(&url, grant)?;
        let addrs = resolve(&url, grant, deadline)?;
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(failed("out of time"));
        }
        let host = url.host_str().unwrap_or_default().to_owned();
        let client = reqwest::Client::builder()
            .no_proxy()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(&host, &addrs)
            .build()
            .map_err(|err| failed(format!("client: {err}")))?;
        let builder = match method {
            FetchMethod::Get => client.get(url.clone()),
            FetchMethod::Post => {
                let builder = client.post(url.clone());
                let builder = match &request.content_type {
                    Some(content_type) => {
                        builder.header(reqwest::header::CONTENT_TYPE, content_type.as_str())
                    }
                    None => builder,
                };
                builder.body(
                    request
                        .body
                        .clone()
                        .map_or_else(Vec::new, ByteBuf::into_vec),
                )
            }
        };
        let mut response = builder
            .send()
            .await
            .map_err(|err| failed(format!("fetch: {err}")))?;
        let status = response.status();
        target.status = status.as_u16();
        if status.is_redirection() {
            if hops >= MAX_REDIRECTS {
                return Err(refused(AskCode::Failed, "more than 3 redirects"));
            }
            url = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|location| location.to_str().ok())
                .and_then(|location| url.join(location).ok())
                .ok_or_else(|| refused(AskCode::Failed, "a redirect with no location"))?;
            if matches!(status.as_u16(), 301..=303) {
                method = FetchMethod::Get;
            }
            hops += 1;
            continue;
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|value| bound_text(value, MAX_CONTENT_TYPE_BYTES));
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|err| failed(format!("body: {err}")))?
        {
            body.extend_from_slice(&chunk);
            if body.len() as u64 > cap {
                return Err(refused(
                    AskCode::TooLarge,
                    format!("the body is over {cap} bytes"),
                ));
            }
        }
        let answer = FetchAnswer {
            status: status.as_u16(),
            content_type,
            final_url: url.to_string(),
        };
        let encoded = rmp_serde::to_vec_named(&answer)
            .map_err(|err| refused(AskCode::Failed, format!("answer: {err}")))?;
        let value = rmpv::decode::read_value(&mut encoded.as_slice())
            .map_err(|err| refused(AskCode::Failed, format!("answer: {err}")))?;
        return Ok(Answered {
            value,
            data: Some(body),
            fetch: Some(target),
        });
    }
}

/// Whether a fetch may reach `ip`: any global address, or one a granted
/// CIDR names. A v4-mapped or NAT64 (64:ff9b::/96) address is judged as
/// the v4 address it carries.
fn address_allowed(ip: IpAddr, private_cidrs: &[ipnet::IpNet]) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => {
            let o = v6.octets();
            let embedded = v6.to_ipv4_mapped().or_else(|| {
                (v6.segments()[..6] == [0x64, 0xff9b, 0, 0, 0, 0])
                    .then(|| Ipv4Addr::new(o[12], o[13], o[14], o[15]))
            });
            embedded.map_or(IpAddr::V6(v6), IpAddr::V4)
        }
        v4 => v4,
    };
    private_cidrs.iter().any(|cidr| cidr.contains(&ip))
        || oneiron_sandbox_contract::network::global_address(ip)
}
