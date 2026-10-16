//! Host-declared fixture origin. No loopback socket is opened on the host.
use super::*;
use std::io::Read;
use std::path::{Component, Path};

pub(super) fn fetch(
    proxy: &OpenEgressProxy,
    request: &HttpRequest,
) -> Option<io::Result<HttpResponse>> {
    let root = proxy.fixture.as_ref()?;
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
