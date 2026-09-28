//! Paired MCP fixture credentials and the host-signed owner binding. Labels are
//! local lookup recipes, never tokens.
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
    let signature = key.sign(&pairing_binding_transcript(&link.code, &binding, &holder).unwrap());
    let slip = server
        .vault()
        .redeem_pairing_link(&issuer, &link.code, &holder, binding, &signature.to_bytes())
        .unwrap();
    let token = slip.to_token().unwrap();
    server
        .vault()
        .sync_state_put(&cache_key(label), token.as_bytes())
        .unwrap();
    token
}

/// The holder attenuates its own paired credential; the label then presents
/// the narrowed token. Register the returned token, not the paired one.
pub(super) fn attenuate_mcp_credential(
    server: &SyncServer,
    label: &str,
    caveat: oneiron::authority::SlipCaveat,
) -> String {
    let mut slip = CapabilitySlip::from_token(&mcp_registered_credential(server, label)).unwrap();
    slip.attenuate(caveat, &holder_key(label)).unwrap();
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
    crate::test_credentials::bind_slip_request(server, &slip, &key, request)
}

/// Fixture: a logged, host-signed human binding plus a holder-bound top slip.
/// A bare host secret has no authenticated PERSON identity to exclude.
pub(super) fn bind_room_owner(server: &SyncServer, owner: oneiron::EntityId) {
    use oneiron::authority::{
        AUTHORITY_LOG_SCHEMA_VERSION, AuthorityLogEntry, AuthorityOp, AuthoritySignature,
        HostSlipIssuer, actor_binding_is_active, authority_entry_hash, authority_transcript,
    };
    use std::collections::BTreeSet;

    let issuer = HostSlipIssuer::from_secret(b"secret").unwrap();
    let host_key = issuer.public_key();
    let seed = blake3::derive_key("oneiron/host-authority-signing/v2", b"secret");
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    assert_eq!(signing.verifying_key().to_bytes(), issuer.binding_key());
    let fold = server.vault.authority_fold().unwrap();
    let mut heads: BTreeSet<_> = fold.valid_entries.clone();
    let mut seq = 0;
    for row in server
        .vault
        .entities_by_type(oneiron::registry::ENTITY_TYPE_AUTHORITY_LOG)
        .unwrap()
    {
        let entry = server.vault.get_authority_log_entry(&row).unwrap().unwrap();
        let hash = authority_entry_hash(&entry).unwrap();
        if fold.valid_entries.contains(&hash) {
            for parent in &entry.parent_hashes {
                heads.remove(parent);
            }
            if entry.signer.public_key == host_key {
                seq = seq.max(entry.seq.saturating_add(1));
            }
        }
    }
    let now = server.vault.now_recorded_at();
    let mut entry = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: fold.vault_id,
        seq,
        parent_hashes: heads.into_iter().collect(),
        op: AuthorityOp::BindActor {
            authority_key: host_key.clone(),
            actor_ref: owner,
            actor_class: "human".into(),
            epoch: 1,
        },
        signer: AuthoritySignature {
            suite: host_key.suite(),
            public_key: host_key,
            signature: vec![0; 64],
        },
        cosigns: vec![],
        ts: now,
    };
    entry.signer.signature = signing
        .sign(&authority_transcript(&entry).unwrap())
        .to_bytes()
        .to_vec();
    server
        .vault
        .put_authority_log_entry(
            &entry,
            oneiron::TimeRange {
                start: now,
                end: now,
            },
            now,
        )
        .unwrap();
    assert!(actor_binding_is_active(
        &server.vault.authority_fold().unwrap(),
        &owner,
        "human"
    ));
}

/// Fixture: the owner-signed depth birth an owner-rooted vault requires before
/// it takes a new PROJECT, signed with the host key `bind_room_owner` binds.
pub(super) fn create_owned_project(
    server: &SyncServer,
    owner: oneiron::EntityId,
    project: oneiron::EntityId,
    record: &oneiron::workspace_roster::ProjectRecord,
) {
    let signing = SigningKey::from_bytes(&blake3::derive_key(
        "oneiron/host-authority-signing/v2",
        b"secret",
    ));
    server
        .vault
        .create_project_with_owner(
            project,
            record,
            &oneiron::write_envelope::WriteActor::new(owner, oneiron::EdgeActorClass::Human),
            1,
            oneiron::authority::AuthorityKey::Ed25519(signing.verifying_key().to_bytes()),
            |message| Ok(signing.sign(message).to_bytes().to_vec()),
        )
        .expect("owner-signed project birth");
}
