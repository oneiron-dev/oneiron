//! The partition a keyed non-core route keeps its caller's replays in on a
//! vault no supervisor manages (FIX 5404; CALLS "FIX 5404 self-hosted
//! principal", Engine 10-21 02:4x).
//!
//! The route's own owner gate (`require_owner_auth`) verified the request's
//! credential already; this reads that verdict and verifies nothing again.
//! A verified individual credential, a log-backed slip with its holder
//! proof, keys under its own principal, as a core route's caller does, so
//! two callers never replay each other's response. Every other caller the
//! gate passes keeps the shared label it had: the explicit dev mode with no
//! credential, and a dev token whose MAC goes unverified, whose claims are
//! never taken for an identity. A request that presents an individual
//! credential the gate did not verify keeps that shared label too, and the
//! server logs a typed warning naming the credential. Nothing here admits or
//! refuses a request: the gate and the route judge it as before.

use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;

use crate::auth::CoreAuth;

/// Whether a verified individual caller of a non-core keyed route keys its
/// replays under its own principal rather than the shared label (CALLS
/// "FIX 5404 self-hosted principal").
const NON_CORE_INDIVIDUAL_PRINCIPAL: bool = true;

/// Framing prefix of a capability slip.
const SLIP_PREFIX: &str = "v2.slip.";

/// The header an MCP connector names its credential in.
const MCP_CREDENTIAL_HEADER: &str = "x-oneiron-mcp-credential";

/// An individual credential a request presents that its route's gate did
/// not verify: the request keeps the shared label, and the warning says
/// which credential it was.
#[derive(Clone, Copy, Debug)]
enum UnverifiedIndividual {
    /// A capability slip as the request's bearer.
    BearerSlip,
    /// A capability slip as its MCP connector credential, which a non-core
    /// route's gate does not read.
    ConnectorSlip,
}

impl UnverifiedIndividual {
    /// The first individual credential `headers` present, with its token.
    fn presented(headers: &HeaderMap) -> Option<(Self, &str)> {
        let bearer = headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim_start().split_once(char::is_whitespace))
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
            .map(|(_, token)| token.trim())
            .filter(|token| token.starts_with(SLIP_PREFIX))
            .map(|token| (Self::BearerSlip, token));
        bearer.or_else(|| {
            headers
                .get(MCP_CREDENTIAL_HEADER)
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
                .filter(|token| token.starts_with(SLIP_PREFIX))
                .map(|token| (Self::ConnectorSlip, token))
        })
    }

    /// The warning's stable reason.
    const fn reason(self) -> &'static str {
        match self {
            Self::BearerSlip => "idempotency_bearer_slip_unverified",
            Self::ConnectorSlip => "idempotency_connector_slip_unverified",
        }
    }
}

/// The partition of a non-core keyed request whose route's owner gate
/// admitted `auth`: that caller's own [`CoreAuth::idempotency_principal`]
/// when the gate verified an individual credential, else `None`, and the
/// request keeps the shared label it has today.
pub(super) fn individual_principal(auth: &CoreAuth, headers: &HeaderMap) -> Option<String> {
    if !NON_CORE_INDIVIDUAL_PRINCIPAL {
        return None;
    }
    if auth.verified_slip().is_some() {
        return Some(auth.idempotency_principal());
    }
    if let Some((credential, token)) = UnverifiedIndividual::presented(headers) {
        tracing::warn!(
            reason = credential.reason(),
            instrument = %blake3::hash(token.as_bytes()).to_hex(),
            "a keyed request presented an individual credential its route did not verify; \
             it keeps the shared idempotency partition"
        );
    }
    None
}
