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
//!
//! A verified individual's entries are stamped with its entity, as a core
//! route's caller's are (KS-2B2), so the erase of that person reaches them:
//! the erase drops each, and the person's replays end with the erase, not at
//! the TTL (FIX 7357; CALLS "FIX 7357 erase reach", Engine 10-21 18:4x).
//! Every other entry is stamped as it was.

use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;

use crate::auth::CoreAuth;

/// Whether a verified individual caller of a non-core keyed route keys its
/// replays under its own principal rather than the shared label (CALLS
/// "FIX 5404 self-hosted principal").
const NON_CORE_INDIVIDUAL_PRINCIPAL: bool = true;

/// Whether the erase of a verified individual drops the non-core keyed
/// entries stamped as theirs, rather than leaving the erased form a core
/// route's entry keeps and answers "response erased" with (CALLS "FIX 7357
/// erased replay form").
const ERASE_DROPS_INDIVIDUAL_REPLAY: bool = true;

/// Who owns a keyed entry's response, as it is written: the caller its
/// credential names, and whether that caller's erase drops the entry.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct EntryStamp {
    pub(super) caller: Option<oneiron::EntityId>,
    pub(super) erase_drops: bool,
}

impl EntryStamp {
    /// A core route's caller, or a managed vault's legacy route's, as
    /// KS-2B2 stamps it: its principal's entity, when its credential names
    /// one. Its erase leaves the entry's erased form.
    pub(super) fn core(auth: &CoreAuth) -> Self {
        Self {
            caller: auth.principal_entity(),
            erase_drops: false,
        }
    }

    /// A verified individual caller whose entries key under its own
    /// partition ([`individual_principal`]), stamped as a core route's
    /// caller is, its erase dropping them (FIX 7357). A credential that names
    /// no entity, a host-held slip, stamps no one, as on a core route; one
    /// whose principal ref names no entity stamps no one either, the entry
    /// kept and replayed as today, and the server logs a typed warning.
    fn individual(auth: &CoreAuth) -> Self {
        let caller = auth.principal_entity();
        if caller.is_none() && auth.principal_ref().is_some() {
            tracing::warn!(
                reason = "idempotency_individual_stamp_unnamed",
                "a verified individual's principal ref names no entity; \
                 its keyed entry is kept unstamped"
            );
        }
        Self {
            caller,
            erase_drops: ERASE_DROPS_INDIVIDUAL_REPLAY && caller.is_some(),
        }
    }
}

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

/// [`individual_principal`], with the stamp the verified individual's entry
/// is written under (FIX 7357); `None` exactly where it is `None`.
pub(super) fn individual_partition(
    auth: &CoreAuth,
    headers: &HeaderMap,
) -> Option<(String, EntryStamp)> {
    individual_principal(auth, headers).map(|principal| (principal, EntryStamp::individual(auth)))
}
