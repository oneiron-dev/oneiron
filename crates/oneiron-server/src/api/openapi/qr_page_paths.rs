//! The public QR page a sealed certificate names (`/esign/verify`,
//! ARCH-0064a section 6, [SGN-05]). The certificate prints
//! `/esign/verify#<capability>`; the page scrubs the fragment and sends the
//! capability only in the `x-oneiron-esign-qr-capability` header of its
//! report POST. Keyless: the capability is checked in the vault on each
//! report, and an unusable one gets one refusal.

use serde_json::{Value, json};

pub(super) fn merge_qr_page_paths(spec: &mut Value) {
    let Some(paths) = spec.get_mut("paths").and_then(Value::as_object_mut) else {
        return;
    };
    paths.insert(
        "/esign/verify".to_owned(),
        json!({"get": {
            "tags": ["signing"],
            "operationId": "esign_qr_page",
            "summary": "The QR page shell a sealed certificate names as /esign/verify#<capability>. The page scrubs the fragment and sends the capability only in the x-oneiron-esign-qr-capability header of its report POST.",
            "security": [],
            "responses": {
                "200": {
                    "description": "The QR page, served no-store, no-referrer and noindex with a hash-pinned script.",
                    "content": {"text/html": {"schema": {"type": "string"}}}
                }
            }
        }}),
    );
    paths.insert(
        "/esign/verify/report".to_owned(),
        json!({"post": {
            "tags": ["signing"],
            "operationId": "esign_qr_report",
            "summary": "What the seal the QR was printed in proved: the document's title and outcome, the seal time, the audit chain head, who signed and when (names and roles only), and each item's sealed version, SHA-256 file identifier, seal profile evidence and seal-time self-verification. Never the PDF, an email, an IP or a user agent.",
            "security": [],
            "parameters": [{
                "name": "x-oneiron-esign-qr-capability",
                "in": "header",
                "required": true,
                "description": "The QR capability from the certificate URL's fragment: 64 lower-hex characters.",
                "schema": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
            }],
            "responses": {
                "200": {
                    "description": "The QR page projection, served no-store, no-referrer and noindex.",
                    "content": {"application/json": {"schema": {"type": "object"}}}
                },
                "404": {
                    "description": "One refusal for an unknown, revoked, expired or erased capability. No call is refused for its rate."
                }
            }
        }}),
    );
}
