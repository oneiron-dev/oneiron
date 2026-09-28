//! One typed codec for artifact bundle entry and canonical file URLs.
//! Control occupies fixed segments; encoded file data never gets reparsed.

use super::{ApiError, ArtifactServeQuery, EnvelopedApiError};
use axum::http::Uri;
use oneiron::{ArtifactPointerChannel, ArtifactSnapshotSelector};

#[derive(Debug)]
pub(super) enum AddressForm {
    Entry,
    Canonical { needs_slash: bool },
}

#[derive(Debug)]
pub(super) struct BundlePath {
    encoded: String,
    decoded: String,
}

impl BundlePath {
    fn parse(encoded: &str) -> Result<Self, EnvelopedApiError> {
        let mut segments = Vec::new();
        for segment in encoded.split('/') {
            segments.push(decode_component(segment)?);
        }
        let path = segments.join("/");
        let decoded = if path.is_empty() {
            "index.html".to_owned()
        } else if path.ends_with('/') {
            format!("{path}index.html")
        } else {
            path
        };
        Ok(Self {
            encoded: encoded.to_owned(),
            decoded,
        })
    }
}

/// An artifact, credential, selection and file are parsed once from fixed
/// URI positions. The same value renders redirects without decoding again.
pub(super) struct ArtifactRoute {
    pub(super) artifact: String,
    pub(super) token: Option<String>,
    pub(super) selector: ArtifactSnapshotSelector,
    pub(super) file: BundlePath,
    form: AddressForm,
    raw_artifact: String,
}

impl ArtifactRoute {
    pub(super) fn parse(
        uri: &Uri,
        claimed_artifact: &str,
        query: &ArtifactServeQuery,
    ) -> Result<Self, EnvelopedApiError> {
        let raw_path = uri.path().strip_prefix("/a/").ok_or_else(missing)?;
        let (raw_artifact, tail) = raw_path.split_once('/').unwrap_or((raw_path, ""));
        let artifact = decode_component(raw_artifact)?;
        if artifact != claimed_artifact || artifact.is_empty() {
            return Err(missing());
        }
        let (token, rest) = if let Some(after) = tail.strip_prefix("_t/") {
            let (raw_token, rest) = after.split_once('/').unwrap_or((after, ""));
            if raw_token.len() != 64 || !raw_token.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(missing());
            }
            (Some(raw_token.to_owned()), rest)
        } else {
            (None, tail)
        };
        let (selector, encoded_file, form) = if let Some(after) = rest.strip_prefix("_s/") {
            if query.explicit_selector() {
                return Err(missing());
            }
            let (kind, after_kind) = after.split_once('/').ok_or_else(missing)?;
            let (value, file) = after_kind.split_once('/').unwrap_or((after_kind, ""));
            let selector = match kind {
                "c" => ArtifactSnapshotSelector::Channel(
                    ArtifactPointerChannel::parse(value).map_err(|_| missing())?,
                ),
                "f" => ArtifactSnapshotSelector::ForkHash(
                    oneiron::parse_codebase_fork_hash_hex(value).map_err(|_| missing())?,
                ),
                "b" => ArtifactSnapshotSelector::BlobVersion(
                    value
                        .parse::<u64>()
                        .ok()
                        .filter(|n| *n > 0)
                        .ok_or_else(missing)?,
                ),
                _ => return Err(missing()),
            };
            (
                selector,
                file,
                AddressForm::Canonical {
                    needs_slash: file.is_empty() && !uri.path().ends_with('/'),
                },
            )
        } else {
            (query.selector()?, rest, AddressForm::Entry)
        };
        Ok(Self {
            artifact,
            token,
            selector,
            file: BundlePath::parse(encoded_file)?,
            form,
            raw_artifact: raw_artifact.to_owned(),
        })
    }

    pub(super) fn path(&self) -> &str {
        &self.file.decoded
    }

    pub(super) fn redirect(&self) -> Option<String> {
        match self.form {
            AddressForm::Canonical { needs_slash: false } => return None,
            AddressForm::Entry | AddressForm::Canonical { needs_slash: true } => {}
        }
        let selector = match self.selector {
            ArtifactSnapshotSelector::Channel(channel) => format!("c/{}", channel.as_str()),
            ArtifactSnapshotSelector::ForkHash(hash) => {
                format!("f/{}", oneiron::artifact_hex(&hash))
            }
            ArtifactSnapshotSelector::BlobVersion(version) => format!("b/{version}"),
            _ => return None,
        };
        let token = self
            .token
            .as_deref()
            .map_or(String::new(), |v| format!("/_t/{v}"));
        Some(format!(
            "/a/{}{token}/_s/{selector}/{}",
            self.raw_artifact, self.file.encoded
        ))
    }
}

impl ArtifactServeQuery {
    fn explicit_selector(&self) -> bool {
        self.channel.is_some() || self.fork_hash.is_some() || self.blob_version.is_some()
    }

    fn selector(&self) -> Result<ArtifactSnapshotSelector, EnvelopedApiError> {
        if let Some(version) = self.blob_version {
            if version == 0 || self.channel.is_some() || self.fork_hash.is_some() {
                return Err(ApiError::bad_request(
                    "blobVersion must be positive and exclusive",
                    Some("blobVersion"),
                )
                .into());
            }
            return Ok(ArtifactSnapshotSelector::BlobVersion(version));
        }
        if self.channel.is_some() && self.fork_hash.is_some() {
            return Err(ApiError::bad_request(
                "channel and forkHash cannot be combined",
                Some("forkHash"),
            )
            .into());
        }
        if let Some(fork) = &self.fork_hash {
            return Ok(ArtifactSnapshotSelector::ForkHash(
                oneiron::parse_codebase_fork_hash_hex(fork)
                    .map_err(|error| ApiError::bad_request(error.to_string(), Some("forkHash")))?,
            ));
        }
        let channel =
            self.channel
                .as_deref()
                .map_or(Ok(ArtifactPointerChannel::Published), |v| {
                    ArtifactPointerChannel::parse(v)
                        .map_err(|error| ApiError::bad_request(error.to_string(), Some("channel")))
                })?;
        Ok(ArtifactSnapshotSelector::Channel(channel))
    }
}

fn missing() -> EnvelopedApiError {
    ApiError::not_found("artifact", None).into()
}

fn decode_component(raw: &str) -> Result<String, EnvelopedApiError> {
    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut pos = 0;
    while pos < bytes.len() {
        if bytes[pos] == b'%' {
            if pos + 2 >= bytes.len() {
                return Err(missing());
            }
            let a = hex(bytes[pos + 1]).ok_or_else(missing)?;
            let b = hex(bytes[pos + 2]).ok_or_else(missing)?;
            decoded.push((a << 4) | b);
            pos += 3;
        } else {
            decoded.push(bytes[pos]);
            pos += 1;
        }
    }
    String::from_utf8(decoded).map_err(|_| missing())
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_render_round_trips_data_and_selector_without_marker_search() {
        let token = "ab".repeat(32);
        for (artifact, suffix, query, selected) in [
            ("site", "", "", "c/published".to_owned()),
            ("_t", "c/app.js", "?channel=preview", "c/preview".to_owned()),
            (
                "_t",
                "nested%23a%3Fb%2520.js",
                "?channel=preview",
                "c/preview".to_owned(),
            ),
            (
                "site",
                "f/nested%23a.js",
                "?forkHash=",
                format!("f/{}", "00".repeat(32)),
            ),
        ] {
            let full_query = if query == "?forkHash=" {
                format!("{query}{}", "00".repeat(32))
            } else {
                query.to_owned()
            };
            let uri: Uri = format!("/a/{artifact}/_t/{token}/{suffix}{full_query}")
                .parse()
                .unwrap();
            let query = match full_query.as_str() {
                "?channel=preview" => ArtifactServeQuery {
                    channel: Some("preview".into()),
                    ..Default::default()
                },
                q if q.starts_with("?forkHash=") => ArtifactServeQuery {
                    fork_hash: Some("00".repeat(32)),
                    ..Default::default()
                },
                _ => ArtifactServeQuery::default(),
            };
            let entry = ArtifactRoute::parse(&uri, artifact, &query).unwrap();
            let canonical = entry.redirect().unwrap();
            assert!(canonical.contains(&format!("/_t/{token}/_s/{selected}/")));
            let followed: Uri = canonical.parse().unwrap();
            let parsed =
                ArtifactRoute::parse(&followed, artifact, &ArtifactServeQuery::default()).unwrap();
            assert_eq!(parsed.artifact, entry.artifact);
            assert_eq!(parsed.token, entry.token);
            assert_eq!(parsed.selector, entry.selector);
            assert_eq!(parsed.path(), entry.path());
            assert!(parsed.redirect().is_none());
        }
        // A public/member URL uses the same selector codec without a token;
        // _s and _t below its complete prefix are ordinary file data.
        let uri: Uri = "/a/_t/_s/c/published/_s/_t/nested%23a%3Fb%2520.js"
            .parse()
            .unwrap();
        let parsed = ArtifactRoute::parse(&uri, "_t", &ArtifactServeQuery::default()).unwrap();
        assert!(parsed.token.is_none());
        assert_eq!(parsed.path(), "_s/_t/nested#a?b%20.js");
        assert!(parsed.redirect().is_none());
        let encoded_artifact: Uri = "/a/a%2Fb/".parse().unwrap();
        let entry =
            ArtifactRoute::parse(&encoded_artifact, "a/b", &ArtifactServeQuery::default()).unwrap();
        assert_eq!(entry.redirect().unwrap(), "/a/a%2Fb/_s/c/published/");
        let slash: Uri = "/a/_t/_s/c/published/nested%2Ffile%23.js".parse().unwrap();
        let path = ArtifactRoute::parse(&slash, "_t", &ArtifactServeQuery::default()).unwrap();
        assert_eq!(path.path(), "nested/file#.js");
        assert!(path.redirect().is_none());
    }
}
