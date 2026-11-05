# OCSP validation material for seals

A B-LT/B-LTA seal gathers revocation material for each non-anchor signer and
timestamp-chain certificate. It first tries the certificate's existing CRL
distribution points. Only a certificate without a working CRL tries its HTTP(S)
OCSP access locations from Authority Information Access (AIA). An unavailable,
denied, malformed, stale, unbound, unauthorized, unknown or revoked response
provides no usable material; incomplete coverage keeps the existing lower-profile
degradation. A typed memory-floor, resource-deadline or cancellation refusal is
still the seal's resource error, not missing evidence.

## Configuration and request path

The existing `--seal-ocsp-origins` / `ONEIRON_SEAL_OCSP_ORIGINS` setting supplies
the origin allowlist. Configuring an origin does not replace the responder path
advertised by the certificate. Fetches retain the existing grant, origin/address
checks and call/fetch deadlines. Unrelated AIA certificate fetching remains
disabled in the organ.

OCSP requests are unsigned, nonce-free SHA-256 CertID POSTs with content type
`application/ocsp-request`. No new retry, nonce, cache or redirect policy is
introduced. The host measures each reply against `limits.seal_ocsp_bytes`, whose
default is 1,048,576 bytes, matching the already-declared OCSP value. Crossing the
row asks whether everything is okay and reads the reply whole; it is not a body
cap. An operator can override the row through the ordinary `[limits]` setting.

## Validation and ownership

Gathering reuses the native DSS verifier's successful-response, exact CertID,
GOOD status, responder authorization/signature, freshness and producedAt checks.
Its certificate context is the requested certificate and its actual key-bound
issuer. A delegated responder embedded in the response is admitted and checked by
the same verifier. A responder available only in another configured certificate,
and unrelated extra SingleResponses that cannot bind to that pair, do not count
as coverage in this gather slice.

The request uses admitted certificate values rather than decoding fresh copies.
Subject DER, CertID heap fields, the one request-list slot and the exact encoded
body reserve from the existing operation ledger before allocation. The body and
explicit fetch metadata keep their holds through the fetch. AIA descriptions are
read in place. Successful response bodies retain their existing fetch admission
as shared bytes through DSS serialization; gathering does not copy or re-encode
them.

This is not a whole-seal memory bound. URL normalization and transport/wire
internals, including the native POST per-hop body clone, remain shared-path
accounting follow-ups. The original grant and resource services remain in force.
No new dependency, format migration or storage ABI change is required. Deploy a
matching engine/server and rebuilt seal organ to use the added fetch purpose.
