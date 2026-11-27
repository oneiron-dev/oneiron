//! One held scope exceed's signal, kept as the call driver keeps it, for
//! `tests/connector_revision_offers_listed_rows.rs`: the evidence and keep
//! doors are crate-private, and no public read names a signal. The grant
//! comes from the public connector consent door; this door only keeps the
//! signal a held call under it would have kept, and names its ref and ask.

use crate::connector_key::{
    ScopeExceedCall, connector_scope_evidence, keep_connector_scope_signal, scope_signals_for_test,
};
use crate::error::{Error, Result};
use crate::outbound_consent::{DataClass, ScopedMcpCallContext, ScopedMcpEscalationReason};
use crate::{EntityId, Vault};

/// Keeps the `seq`-th held call's scope signal for `connector` under `key`
/// and the scoped grant `grant`: an endpoint exceed naming
/// `requested_endpoint`, which must be outside the grant's allowlist. Each
/// `seq` keeps its own signal on the one scope, so repeated rulings fold
/// into one streak. Returns the signal ref (32 hex, as the verbs take it)
/// and the held ask's digest, for `record_connector_scope_outcome`.
///
/// # Errors
/// An unknown grant, a grant that is no scoped grant, evidence the call
/// leaves none of, and storage failures.
#[doc(hidden)]
pub fn keep_scope_signal(
    vault: &Vault,
    key: &EntityId,
    grant: &EntityId,
    connector: &str,
    requested_endpoint: &str,
    seq: u64,
) -> Result<(String, String)> {
    let held = vault
        .get_standing_outbound_grant(grant)?
        .ok_or(Error::EntityNotFound)?;
    let scope = held.scope.scoped_mcp_grant().ok_or(Error::EntityNotFound)?;
    let call = ScopedMcpCallContext {
        server: scope.server.to_owned(),
        tool: scope.tool.to_owned(),
        payload_data_class: DataClass::Personal,
        resolved_endpoint: requested_endpoint.to_owned(),
    };
    let attempt = format!("revision-offers-listed-rows attempt {seq}");
    let evidence = connector_scope_evidence(
        ScopedMcpEscalationReason::EndpointNotAllowed,
        &held,
        *grant,
        *key,
        ScopeExceedCall {
            connector,
            principal_ref: &held.principal_ref,
            attempt: attempt.as_bytes(),
            call_seq: seq,
            call: &call,
        },
    )
    .ok_or(Error::InvariantViolation(
        "the fixture's scoped grant leaves endpoint evidence",
    ))?;
    let ask = format!("revision-offers-listed-rows ask {seq}");
    let call_ref = EntityId::now();
    keep_connector_scope_signal(vault, evidence, call_ref, None, Some(&ask));
    let signal = scope_signals_for_test(vault)?
        .into_iter()
        .find(|signal| signal.call_ref == call_ref)
        .ok_or(Error::InvariantViolation(
            "the kept scope signal reads back",
        ))?;
    Ok((signal.signal_id.to_hex(), ask))
}
