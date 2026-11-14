//! First-party HTML on the API's origin (ARCH-0050 #artifact-origin-open):
//! the signing ceremony (`GET /sign`), the owner's field editor
//! (`GET /sign/editor`), the certificate's QR page (`GET /esign/verify`) and
//! the booking instructions fragment. Each stays on the API's origin, whose
//! routes its page calls; the artifact origin is where agent code runs, so a
//! first-party page never moves there. Every reply carries its own content
//! security policy beside one isolation set, so no other document on the
//! origin, an `/a/` code bundle included, frames it, keeps a window handle on
//! it, embeds it or runs a script in it that the page did not pin.

use axum::http::header::{self, HeaderName};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use sha2::{Digest, Sha256};

/// A document that opened this one, or that this one opens, keeps no handle
/// on it unless it is same-origin and sends the same policy.
const CROSS_ORIGIN_OPENER_POLICY: HeaderName =
    HeaderName::from_static("cross-origin-opener-policy");
/// No other origin loads the reply as a subresource.
const CROSS_ORIGIN_RESOURCE_POLICY: HeaderName =
    HeaderName::from_static("cross-origin-resource-policy");

/// The content type of every first-party page and fragment.
const FIRST_PARTY_HTML_CONTENT_TYPE: &str = "text/html; charset=utf-8";

/// The booking fragment is one JSON data block: opened as a document it is
/// an opaque origin that runs, loads and submits nothing.
pub(super) const DATA_FRAGMENT_CONTENT_SECURITY_POLICY: &str =
    "sandbox; default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// The `script-src` source that admits exactly `script` as an inline script.
pub(super) fn inline_script_source(script: &str) -> String {
    let digest =
        base64::engine::general_purpose::STANDARD.encode(Sha256::digest(script.as_bytes()));
    format!("'sha256-{digest}'")
}

/// `html` as a first-party reply: `csp`, the isolation set, no-store and
/// no-referrer.
pub(super) fn isolated_html(csp: String, html: String) -> Response {
    (
        [
            (
                header::CONTENT_TYPE,
                FIRST_PARTY_HTML_CONTENT_TYPE.to_owned(),
            ),
            (header::CONTENT_SECURITY_POLICY, csp),
            (CROSS_ORIGIN_OPENER_POLICY, "same-origin".to_owned()),
            (CROSS_ORIGIN_RESOURCE_POLICY, "same-origin".to_owned()),
            (header::X_FRAME_OPTIONS, "DENY".to_owned()),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_owned()),
            (header::REFERRER_POLICY, "no-referrer".to_owned()),
            (header::CACHE_CONTROL, "no-store".to_owned()),
        ],
        html,
    )
        .into_response()
}
