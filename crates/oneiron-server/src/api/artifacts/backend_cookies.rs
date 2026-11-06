//! Server-side app cookies on the shared artifact listener, never host credentials.

use axum::http::header::{COOKIE, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue};

const COOKIE_NAMESPACE: &str = "oneiron_app_";

pub(super) struct AppCookies<'a> {
    root: &'a str,
    namespace: String,
}

impl<'a> AppCookies<'a> {
    pub(super) fn new(authority: &str, root: &'a str) -> Self {
        let mut digest = blake3::Hasher::new_derive_key("oneiron artifact backend cookies v1");
        digest.update(authority.as_bytes());
        digest.update(&[0]);
        digest.update(root.as_bytes());
        Self {
            root,
            namespace: format!("{COOKIE_NAMESPACE}{}_", digest.finalize().to_hex()),
        }
    }

    pub(super) fn request_header(&self, headers: &HeaderMap) -> Option<HeaderValue> {
        let mut pairs = Vec::new();
        for header in headers.get_all(COOKIE).iter() {
            let Ok(header) = header.to_str() else {
                continue;
            };
            for pair in header.split(';') {
                let Some((name, value)) = pair.trim().split_once('=') else {
                    continue;
                };
                let Some(name) = name.trim().strip_prefix(self.namespace.as_str()) else {
                    continue;
                };
                let value = value.trim();
                if valid_pair(name, value) {
                    pairs.push(format!("{name}={value}"));
                }
            }
        }
        if pairs.is_empty() {
            None
        } else {
            HeaderValue::from_str(&pairs.join("; ")).ok()
        }
    }

    pub(super) fn rewrite_response(&self, headers: &mut HeaderMap, target: &str) {
        let values: Vec<_> = headers.get_all(SET_COOKIE).iter().cloned().collect();
        headers.remove(SET_COOKIE);
        for value in values {
            if let Some(value) = value
                .to_str()
                .ok()
                .and_then(|value| self.rewrite(value, target))
            {
                headers.append(SET_COOKIE, value);
            }
        }
    }

    fn rewrite(&self, header: &str, target: &str) -> Option<HeaderValue> {
        let mut parts = header.split(';');
        let (name, value) = parts.next()?.split_once('=')?;
        let (name, value) = (name.trim(), value.trim());
        if !valid_pair(name, value) {
            return None;
        }
        let mut attributes = Vec::new();
        let mut path = None;
        let mut domain = false;
        let mut secure = false;
        let mut http_only = false;
        for attribute in parts.map(str::trim).filter(|part| !part.is_empty()) {
            let (key, value) = attribute.split_once('=').unwrap_or((attribute, ""));
            let key = key.trim();
            if key.eq_ignore_ascii_case("domain") {
                domain = true;
            } else if key.eq_ignore_ascii_case("path") {
                path = Some(value.trim());
            } else {
                secure |= key.eq_ignore_ascii_case("secure");
                http_only |= key.eq_ignore_ascii_case("httponly");
                attributes.push(attribute);
            }
        }
        // Wrapping the name hides browser-reserved prefixes. Enforce their
        // original requirements before mapping valid app-root cookies.
        if ((name.starts_with("__Secure-") || name.starts_with("__Host-")) && !secure)
            || (name.starts_with("__Host-") && (domain || path != Some("/")))
            || ((name.starts_with("__Http-") || name.starts_with("__Host-Http-"))
                && (!secure || !http_only))
        {
            return None;
        }
        let default_path = target.split_once('?').map_or(target, |(path, _)| path);
        let default_path =
            default_path.rsplit_once('/').map_or(
                "/",
                |(parent, _)| if parent.is_empty() { "/" } else { parent },
            );
        let path = path
            .filter(|path| path.starts_with('/'))
            .unwrap_or(default_path);
        let mut result = format!(
            "{}{name}={value}; Path={}{}",
            self.namespace,
            self.root,
            path.strip_prefix('/')?,
        );
        for attribute in attributes {
            result.push_str("; ");
            result.push_str(attribute);
        }
        HeaderValue::from_str(&result).ok()
    }
}

fn valid_pair(name: &str, value: &str) -> bool {
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
    {
        return false;
    }
    let value = if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
        &value[1..value.len() - 1]
    } else {
        value
    };
    value
        .bytes()
        .all(|byte| matches!(byte, 0x21 | 0x23..=0x2b | 0x2d..=0x3a | 0x3c..=0x5b | 0x5d..=0x7e))
}
