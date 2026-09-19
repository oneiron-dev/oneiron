//! Paired MCP fixture credentials. Labels are local lookup recipes, never tokens.
use super::*;
use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, PairingPrincipal, pairing_binding_transcript,
};
use oneiron::federation::{Scope, ScopeAxis, ScopeId};

fn cache_key(label: &str) -> String {
    format!(
        "test:mcp:paired:{}",
        blake3::hash(label.as_bytes()).to_hex()
    )
}
fn holder_key(label: &str) -> SigningKey {
    SigningKey::from_bytes(&blake3::derive_key(
        "oneiron/test/mcp-paired-holder/v2",
        label.as_bytes(),
    ))
}

pub(super) fn pair_mcp_credential(
    server: &SyncServer,
    label: &str,
    actor: oneiron::EntityId,
    class: oneiron::EdgeActorClass,
    scope: &crate::mcp::McpConnectorScope,
) -> String {
    let issuer =
        HostSlipIssuer::from_secret(server.config.auth_secret.as_ref().unwrap().as_bytes())
            .unwrap();
    let mut authority = Scope::top();
    if let Some(world) = scope.world_ref {
        authority.worlds = ScopeAxis::Some(std::collections::BTreeSet::from([ScopeId(world)]));
    }
    if let Some(facet) = scope.facet_ref {
        authority.facets = ScopeAxis::Some(std::collections::BTreeSet::from([ScopeId(facet)]));
    }
    let holder = actor.to_hex();
    let link = server
        .vault()
        .issue_pairing_link_for_principal(
            &issuer,
            authority,
            3600,
            PairingPrincipal {
                holder_ref: Some(holder.clone()),
                actor_class: Some(class.gate_actor_class().to_owned()),
                org_ref: None,
            },
        )
        .unwrap();
    let key = holder_key(label);
    let binding = key.verifying_key().to_bytes();
    let signature = key.sign(&pairing_binding_transcript(&link.ticket, &binding, &holder).unwrap());
    let slip = server
        .vault()
        .redeem_pairing_link(
            &issuer,
            &link.ticket,
            &holder,
            binding,
            &signature.to_bytes(),
        )
        .unwrap();
    let token = slip.to_token().unwrap();
    server
        .vault()
        .sync_state_put(&cache_key(label), token.as_bytes())
        .unwrap();
    token
}

pub(super) fn mcp_registered_credential(server: &SyncServer, label: &str) -> String {
    server
        .vault()
        .sync_state_get(&cache_key(label))
        .unwrap()
        .map_or_else(
            || label.to_owned(),
            |bytes| String::from_utf8(bytes).unwrap(),
        )
}

pub(super) fn bind_mcp_request(server: &SyncServer, request: Request<Body>) -> Request<Body> {
    let Some(label) = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return request;
    };
    let Some(token) = server.vault().sync_state_get(&cache_key(label)).unwrap() else {
        return request;
    };
    let key = holder_key(label);
    let slip = CapabilitySlip::from_token(std::str::from_utf8(&token).unwrap()).unwrap();
    crate::test_credentials::bind_slip_request(&slip, &key, request)
}
