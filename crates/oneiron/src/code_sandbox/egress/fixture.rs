//! Host-declared fixture origin. No loopback socket is opened on the host.
//!
//! The origin serves in one mode the host set: a directory's files, or a
//! forward to one operator-configured upstream (FIX 8061), reached by
//! nothing but this exact origin. With neither set, no request is taken.
use super::*;
use std::io::Read;
use std::path::{Component, Path};

/// The one upstream a fixture origin forwards to (FIX 8061), as checked by
/// [`FixtureForward::new`]: a numeric IPv4 address that is not loopback,
/// unspecified, multicast or broadcast, with a nonzero port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixtureForward(SocketAddrV4);

/// Why a fixture forward was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FixtureForwardError {
    #[error("a loopback address (127.0.0.0/8) is never a fixture forward target")]
    Loopback,
    #[error("the unspecified address is never a fixture forward target")]
    Unspecified,
    #[error("a multicast address is never a fixture forward target")]
    Multicast,
    #[error("the broadcast address is never a fixture forward target")]
    Broadcast,
    #[error("a fixture forward target needs a nonzero port")]
    ZeroPort,
    #[error("a fixture origin serves a directory or a forward, never both")]
    WithDirectory,
}

impl FixtureForward {
    /// The bench forward target rule (CALLS, FIX 8061): one numeric unicast
    /// IPv4 address off the host's loopback, with a nonzero port. The host's
    /// own loopback services, a fixture's private one among them, stay out
    /// of reach.
    ///
    /// # Errors
    /// Names the rule `target` breaks.
    pub fn new(target: SocketAddrV4) -> Result<Self, FixtureForwardError> {
        let address = target.ip();
        if address.is_loopback() {
            return Err(FixtureForwardError::Loopback);
        }
        if address.is_unspecified() {
            return Err(FixtureForwardError::Unspecified);
        }
        if address.is_multicast() {
            return Err(FixtureForwardError::Multicast);
        }
        if address.is_broadcast() {
            return Err(FixtureForwardError::Broadcast);
        }
        if target.port() == 0 {
            return Err(FixtureForwardError::ZeroPort);
        }
        Ok(Self(target))
    }

    /// The upstream's address and port.
    #[must_use]
    pub const fn target(self) -> SocketAddrV4 {
        self.0
    }
}

pub(super) fn fetch(
    proxy: &OpenEgressProxy,
    request: &HttpRequest,
) -> Option<io::Result<HttpResponse>> {
    if proxy.fixture.is_none() && proxy.fixture_forward.is_none() {
        return None;
    }
    let url = match reqwest::Url::parse(&request.url) {
        Ok(url) => url,
        Err(_) => return None,
    };
    if url.scheme() != "http"
        || url.host_str() != Some("127.0.0.1")
        || url.port_or_known_default() != Some(8080)
    {
        return None;
    }
    Some((|| {
        if !url.username().is_empty() || url.password().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "fixture URL credentials",
            ));
        }
        let root = match (&proxy.fixture, proxy.fixture_forward) {
            (Some(root), None) => root,
            (None, Some(forward)) => {
                return super::http::forward(proxy, forward.target(), &url, request);
            }
            // Both set: the origin picks neither.
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    FixtureForwardError::WithDirectory,
                ));
            }
        };
        let relative = if url.path() == "/" {
            "index.html"
        } else {
            url.path().trim_start_matches('/')
        };
        let mut path = root.clone();
        for part in Path::new(relative).components() {
            match part {
                Component::Normal(name) => path.push(name),
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "fixture path",
                    ));
                }
            }
            if std::fs::symlink_metadata(&path)?.is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "fixture symlink",
                ));
            }
        }
        let mut bytes = Vec::new();
        std::fs::File::open(&path)?
            .take(proxy.config.max_response_bytes as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > proxy.config.max_response_bytes {
            return Err(io::Error::other("fixture byte bound"));
        }
        let mime = match path.extension().and_then(|e| e.to_str()) {
            Some("html" | "htm") => "text/html",
            Some("js") => "text/javascript",
            Some("css") => "text/css",
            Some("json") => "application/json",
            Some("svg") => "image/svg+xml",
            Some("png") => "image/png",
            Some("jpg" | "jpeg") => "image/jpeg",
            _ => "application/octet-stream",
        };
        proxy.record(
            "fixture",
            url.as_str(),
            &bytes,
            PolicyClassifyDecision::Allow,
            PolicyVerdictCategory::None,
            None,
        )?;
        Ok(HttpResponse {
            url: url.to_string(),
            status: 200,
            headers: vec![("content-type".into(), mime.into())],
            body: bytes,
        })
    })())
}
