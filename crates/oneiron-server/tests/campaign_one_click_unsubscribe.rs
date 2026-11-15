// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
// The member's link is minted through a test door, which only the test
// command's `--cfg oneiron_test_support` compiles.
#![cfg(oneiron_test_support)]
//! The one-click unsubscribe link a bulk campaign email carries (ARCH-0059
//! #opt-out, RFC 8058; FIX [CAMPAIGN-BULK-SEND-MODE] PR 2), redeemed at the
//! host's public door: a POST of `List-Unsubscribe=One-Click` to the link
//! suppresses the member on email before it answers, a GET writes nothing,
//! and a link this vault did not mint answers 404.

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use oneiron::campaign::claims::{
    CampaignMemberChannel, CampaignMemberState, CampaignMemberValue, PREDICATE_CAMPAIGN_MEMBER,
    PREDICATE_COMM_DO_NOT_CONTACT, decode_campaign_member_value, encode_campaign_member_value,
};
use oneiron::test_doors::campaign_opt_out_line::one_click_unsubscribe_uri;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId, TimeRange, Vault,
    VaultConfig,
};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use tower::ServiceExt;

const ORIGIN: &str = "https://oneiron.test";
const MEMBER_ADDRESS: &str = "yuki@example.com";
const ONE_CLICK_BODY: &str = "List-Unsubscribe=One-Click";

fn test_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 32 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    config
}

/// Every live claim on `subject` carrying `predicate`.
fn live_claims(vault: &Vault, subject: EntityId, predicate: &str) -> Vec<ClaimBody> {
    vault
        .claims_for_subject(&subject)
        .unwrap()
        .into_iter()
        .filter_map(|id| vault.get_claim(&id).unwrap())
        .filter(|body| {
            body.predicate == predicate && body.lifecycle == ClaimLifecycleStatus::Active
        })
        .collect()
}

/// The states of `person`'s live membership heads.
fn member_states(vault: &Vault, person: EntityId) -> Vec<CampaignMemberState> {
    live_claims(vault, person, PREDICATE_CAMPAIGN_MEMBER)
        .iter()
        .map(|body| decode_campaign_member_value(&body.value).unwrap().state)
        .collect()
}

async fn call(app: &axum::Router, method: &str, path: &str, body: &str) -> (StatusCode, String) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// A member enrolled in a campaign on email, on a vault whose host
/// installed its public origin, redeems the link a bulk send to them
/// freezes. The GET and a link with a changed mac write nothing; the POST
/// writes the email suppression and the suppressed membership before it
/// answers; a repeat answers 200 again; a POST without the one-click body is
/// refused.
#[tokio::test]
async fn one_click_post_suppresses_member_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open_unseeded_for_test(dir.path(), test_config()).unwrap();
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let person = oneiron::comm::resolve_or_create_comm_party(&vault, MEMBER_ADDRESS).unwrap();
    let campaign = EntityId::now();
    let member = CampaignMemberValue {
        campaign,
        state: CampaignMemberState::Enrolled,
        channels: vec![CampaignMemberChannel {
            channel: "email".to_owned(),
            basis_evidence: EntityId::now(),
            sender_ref: EntityId::now(),
        }],
        derivation: None,
    };
    vault
        .put_claim(
            &EntityId::now(),
            &ClaimBody::new(
                PREDICATE_CAMPAIGN_MEMBER,
                ClaimSubject::Entity(person),
                encode_campaign_member_value(&member),
                1.0,
                ClaimApprovalStatus::Approved,
                ClaimLifecycleStatus::Active,
            )
            .unwrap(),
            TimeRange { start: 1, end: 1 },
            1,
        )
        .unwrap();

    assert_eq!(
        one_click_unsubscribe_uri(&vault, campaign, person).unwrap(),
        None,
        "a vault with no origin installed mints no link"
    );
    vault.install_one_click_unsubscribe_origin(ORIGIN).unwrap();
    let uri = one_click_unsubscribe_uri(&vault, campaign, person)
        .unwrap()
        .expect("the member's link");
    let prefix = format!(
        "{ORIGIN}/unsubscribe/one-click/{}/{}/",
        campaign.to_hex(),
        person.to_hex()
    );
    assert!(uri.starts_with(&prefix), "the link's shape: {uri}");
    assert_eq!(
        one_click_unsubscribe_uri(&vault, campaign, person)
            .unwrap()
            .as_deref(),
        Some(uri.as_str()),
        "the same member's link is the same bytes on every mint"
    );
    let path = uri.strip_prefix(ORIGIN).unwrap().to_owned();

    let vault = Arc::new(vault);
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                lease_vault_id: 1,
                auth_secret: Some("one-click-owner-issuer".into()),
                oauth_resource_indicator: Some(ORIGIN.to_owned()),
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let app = build_app(server);

    let (status, page) = call(&app, "GET", &path, "").await;
    assert_eq!(status, StatusCode::OK, "the link's page: {page}");
    assert!(
        page.contains("List-Unsubscribe"),
        "the page's button posts the one-click body: {page}"
    );
    assert_eq!(
        member_states(&vault, person),
        vec![CampaignMemberState::Enrolled],
        "a GET writes nothing"
    );

    let mut forged = path.clone();
    let last = forged.pop().unwrap();
    forged.push(if last == '0' { '1' } else { '0' });
    let (status, _) = call(&app, "POST", &forged, ONE_CLICK_BODY).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "a changed mac is not known");
    assert_eq!(
        member_states(&vault, person),
        vec![CampaignMemberState::Enrolled],
        "a link that does not verify writes nothing"
    );

    let (status, reply) = call(&app, "POST", &path, "").await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a POST without the one-click body: {reply}"
    );

    let (status, reply) = call(&app, "POST", &path, ONE_CLICK_BODY).await;
    assert_eq!(status, StatusCode::OK, "the one-click POST: {reply}");
    assert_eq!(
        member_states(&vault, person),
        vec![CampaignMemberState::Suppressed],
        "the membership is suppressed before the POST answers"
    );
    assert_eq!(
        live_claims(&vault, person, PREDICATE_COMM_DO_NOT_CONTACT).len(),
        1,
        "the email suppression the gate reads is written at once"
    );

    let (status, reply) = call(&app, "POST", &path, ONE_CLICK_BODY).await;
    assert_eq!(status, StatusCode::OK, "a repeat POST: {reply}");
    assert_eq!(
        live_claims(&vault, person, PREDICATE_COMM_DO_NOT_CONTACT).len(),
        1,
        "a repeat writes no second suppression"
    );
}
