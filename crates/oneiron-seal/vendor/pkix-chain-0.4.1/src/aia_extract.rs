//! Private AIA `caIssuers` URI extraction for chain-build integration.
//!
//! Walks the `AuthorityInfoAccess` extension (RFC 5280 §4.2.2.1) on a
//! certificate, filters to `accessMethod = id-ad-caIssuers`
//! (1.3.6.1.5.5.7.48.2), and pulls out HTTP/HTTPS `UniformResourceIdentifier`
//! `GeneralName` values. Non-HTTP schemes (LDAP, FTP, file) and non-URI
//! `GeneralName` variants are silently dropped — only URIs an
//! [`AiaFetcher`](pkix_aia::AiaFetcher) might successfully resolve are
//! returned to the caller.
//!
//! This helper is intentionally narrower than
//! `pkix_revocation_http::extract_aia_http_urls`: it returns only the
//! `ca_issuers` partition (no OCSP responder URIs) and lives in this crate
//! rather than `pkix-revocation-http` so `pkix-chain` does not pull in a
//! transitive dependency on `pkix-revocation-http`'s HTTP transport. The
//! parsing logic is identical in shape; if a future refactor migrates the
//! shared helper into `pkix-aia` itself, this module dissolves into a
//! single-line re-export.

use der::{asn1::ObjectIdentifier, Decode};
use x509_cert::{
    ext::pkix::{name::GeneralName, AuthorityInfoAccessSyntax},
    Certificate,
};

/// `id-pe-authorityInfoAccess` — RFC 5280 §4.2.2.1.
const OID_AUTHORITY_INFO_ACCESS: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.1");

/// `id-ad-caIssuers` — RFC 5280 §4.2.2.1, the access method we care about
/// for chain reassembly. `id-ad-ocsp` (1.3.6.1.5.5.7.48.1) is owned by the
/// OCSP machinery and is silently skipped here.
const OID_AD_CA_ISSUERS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.2");

/// Return the `caIssuers` HTTP/HTTPS URIs present on `cert`'s
/// `AuthorityInfoAccess` extension, in the order they appear.
///
/// Returns an empty `Vec` when the extension is absent, contains no
/// caIssuers access descriptions, or every caIssuers `GeneralName` has a
/// non-HTTP scheme. Malformed AIA extension values yield an empty result
/// rather than an error — a malformed AIA on the orphan cert is not itself
/// a chain-validation failure; the caller treats "no URIs to try" the same
/// way it treats "every fetch returned `FetchingDisabled`".
pub(crate) fn ca_issuers_http_uris(cert: &Certificate) -> impl Iterator<Item = String> {
    find_extension_value(cert, &OID_AUTHORITY_INFO_ACCESS)
        .and_then(|v| AuthorityInfoAccessSyntax::from_der(v).ok())
        .into_iter()
        .flat_map(|aia| {
            aia.0.into_iter().filter_map(|ad| {
                if ad.access_method != OID_AD_CA_ISSUERS {
                    return None;
                }
                if let GeneralName::UniformResourceIdentifier(uri) = ad.access_location {
                    let uri_str = uri.as_str();
                    if is_http_scheme(uri_str) {
                        return Some(uri_str.to_owned());
                    }
                }
                None
            })
        })
}

fn find_extension_value<'a>(cert: &'a Certificate, oid: &ObjectIdentifier) -> Option<&'a [u8]> {
    cert.tbs_certificate
        .extensions
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .find(|e| &e.extn_id == oid)
        .map(|e| e.extn_value.as_bytes())
}

fn is_http_scheme(uri: &str) -> bool {
    // Cheap ASCII scheme check matching pkix-revocation-http's
    // `push_if_http_uri`. Treats only `http:` and `https:` as fetchable —
    // anything else (ldap:, ftp:, file:, …) is dropped on the floor before
    // we'd hand it to a fetcher.
    let lower_prefix = |p: &str| {
        uri.len() > p.len()
            && uri.as_bytes()[..p.len()]
                .iter()
                .map(|b| b.to_ascii_lowercase())
                .eq(p.bytes())
    };
    lower_prefix("http://") || lower_prefix("https://")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_scheme_accepts_http_and_https_case_insensitively() {
        assert!(is_http_scheme("http://ca.example/i.der"));
        assert!(is_http_scheme("HTTP://ca.example/i.der"));
        assert!(is_http_scheme("https://ca.example/i.der"));
        assert!(is_http_scheme("HTTPS://ca.example/i.der"));
        assert!(is_http_scheme("HtTpS://ca.example/i.der"));
    }

    #[test]
    fn http_scheme_rejects_non_http_schemes_and_garbage() {
        assert!(!is_http_scheme("ldap://ca.example/i.der"));
        assert!(!is_http_scheme("ftp://ca.example/i.der"));
        assert!(!is_http_scheme("file:///tmp/i.der"));
        assert!(!is_http_scheme(""));
        assert!(!is_http_scheme("http:")); // empty path
        assert!(!is_http_scheme("http:/x")); // single slash
        assert!(!is_http_scheme("notascheme"));
    }
}
