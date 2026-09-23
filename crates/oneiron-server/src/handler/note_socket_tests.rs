//! Document socket writes recheck the live grant, not the cached subscription.
use crate::config::SyncServerConfig;
use crate::server::SyncServer;
use oneiron::sync::transport::{self, document_sub_tags};
use oneiron::sync::{SyncSelector, SyncSelectorWorld};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use std::sync::Arc;
const SECRET: &str = "note-socket-fixture-root";

#[tokio::test]
async fn document_socket_update_cannot_use_a_downgraded_subscription() {
    use super::{conn_state::ConnState, documents::handle_document};
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
    let id = EntityId::now();
    let facet = EntityId::now();
    vault
        .put_entity(
            &id,
            oneiron::registry::ENTITY_TYPE_TURN,
            TimeRange { start: 1, end: 1 },
            1,
            b"turn",
        )
        .unwrap();
    vault
        .put_entity(
            &facet,
            oneiron::registry::ENTITY_TYPE_FACET,
            TimeRange { start: 1, end: 1 },
            1,
            b"turn facet",
        )
        .unwrap();
    vault
        .put_edge(&id, oneiron::EdgeKind::FacetOf, &facet, 1.0)
        .unwrap();
    let member = EntityId::now();
    let grant_id = EntityId::now();
    let mut grant = oneiron::federation::FederationGrant::new(
        oneiron::FederationGrantScope::vault(7),
        member,
        oneiron::federation::FederationGrantRole::Member,
        oneiron::federation::FederationGrantPreset::Member,
    );
    oneiron::sync::put_selector_test_federation_grant(&vault, &grant_id, &grant, 1).unwrap();
    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![facet],
        vec![oneiron::federation::SelectorRange::Core],
    );
    let server = SyncServer::new(
        vault.clone(),
        SyncServerConfig {
            auth_secret: Some(SECRET.into()),
            ..Default::default()
        },
    )
    .unwrap();
    let mut state = ConnState::new(transport::PROTOCOL_VERSION);
    state.bound_auth = Some(crate::test_credentials::authenticate(
        &server,
        &format!(
            "scope=core:read,core:write;principal_ref={}",
            member.to_hex()
        ),
    ));
    let (direct, _responses) = tokio::sync::mpsc::unbounded_channel();
    let request =
        oneiron::sync::encode_selector_vv_request(&selector, &loro::VersionVector::new().encode())
            .unwrap();
    handle_document(
        &server,
        1,
        id,
        document_sub_tags::REQUEST,
        &request,
        &direct,
        &mut state,
    )
    .unwrap();
    let remote = loro::LoroDoc::new();
    remote.get_text("body").insert(0, "first").unwrap();
    remote.commit();
    let update = remote.export(loro::ExportMode::all_updates()).unwrap();
    handle_document(
        &server,
        1,
        id,
        document_sub_tags::UPDATE,
        &update,
        &direct,
        &mut state,
    )
    .unwrap();
    let before = remote.oplog_vv();
    remote.get_text("body").insert(5, " forbidden").unwrap();
    remote.commit();
    let update = remote.export(loro::ExportMode::updates(&before)).unwrap();
    grant.role = oneiron::federation::FederationGrantRole::Viewer;
    oneiron::sync::put_selector_test_federation_grant(&vault, &grant_id, &grant, 2).unwrap();
    assert!(
        handle_document(
            &server,
            1,
            id,
            document_sub_tags::UPDATE,
            &update,
            &direct,
            &mut state
        )
        .is_err()
    );
    assert_eq!(
        server
            .reassert_manager
            .documents()
            .open(id)
            .unwrap()
            .text()
            .unwrap(),
        "first"
    );
}
