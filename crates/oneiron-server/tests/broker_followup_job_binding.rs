//! Census L8-46: provider follow-up URLs stay bound to the admitted
//! destination and job, including the video poll and cancel paths.
//! Ruling: Engine 07:49 Sat 14 Nov, L8-46-ALREADY-BOUND = A.
//! FIX 9923 binds each follow-up to the submitting lease, model and job.
//! The caller receives a server-minted ticket, never the provider job id.
//! This pin test is intended green on main: the behaviour already exists,
//! so there is no red phase or production change.
//! Public media doors reach a TLS fake through the real credential broker.
#![cfg(unix)]

use std::sync::Arc;

use oneiron::llm::BrokerIsolation;
use oneiron::llm::media::{AiOperation, MediaJobState, MediaPart, MediaRequest};
use oneiron::secret_custody::{CustodyTier, SECRET_SCOPE_READ, SecretBinding};
use oneiron::{
    CallClass, CallEnvelope, CallPurpose, ModelId, ModelLocality, ModelTierRef, ResponseFormat,
    TierPrecedence, Vault, VaultConfig,
};
use oneiron_broker::testing::{FakeProvider, FakeReply};
use oneiron_server::config::models::ModelsConfig;
use oneiron_server::models::{BROKER_EFFECTOR, KeyDoor, ModelRuntime, VaultKeyDoor};
use serde_json::json;

const KEY_HANDLE: &str = "video-provider-key";
const PROVIDER_JOB_ID: &str = "video_admitted_1";

#[tokio::test(flavor = "multi_thread")]
async fn video_job_follow_ups_reach_the_provider_only_for_the_admitted_job() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let key = format!("video-provider-sentinel-{nanos:x}-{:x}", std::process::id());
    let expected_authorization = format!("Bearer {key}");
    let fake = FakeProvider::start(FakeReply::json(401, &json!({})));
    let responder_authorization = expected_authorization.clone();
    fake.respond_with(move |request| {
        if request.header("authorization") != Some(responder_authorization.as_str()) {
            return FakeReply::json(401, &json!({"error": {"message": "no key"}}));
        }
        match (request.method.as_str(), request.path.as_str()) {
            ("POST", "/v1/videos") => {
                FakeReply::json(200, &json!({"id": PROVIDER_JOB_ID, "status": "queued"}))
            }
            ("GET", "/v1/videos/video_admitted_1") => FakeReply::json(
                200,
                &json!({"id": PROVIDER_JOB_ID, "status": "in_progress", "progress": 10}),
            ),
            ("DELETE", "/v1/videos/video_admitted_1") => FakeReply::json(200, &json!({})),
            _ => FakeReply::json(404, &json!({})),
        }
    });

    let files = tempfile::tempdir().expect("fixture dir");
    let ca = files.path().join("ca.pem");
    std::fs::write(&ca, fake.ca_pem()).expect("ca");
    let vault_dir = tempfile::tempdir().expect("vault dir");
    let vault = Arc::new(Vault::open(vault_dir.path(), VaultConfig::default()).expect("vault"));
    vault
        .register_test_secret(
            KEY_HANDLE,
            key.as_bytes(),
            vec![SecretBinding {
                effector: BROKER_EFFECTOR.to_owned(),
                tier_ceiling: CustodyTier::T0Doored,
                scopes: vec![SECRET_SCOPE_READ.to_owned()],
            }],
            1_700_000_000,
        )
        .expect("register the key");
    let door: Arc<dyn KeyDoor> = Arc::new(VaultKeyDoor::new(vault.clone()));
    let config = ModelsConfig::from_toml(
        &format!(
            r#"
[providers.paid]
kind = "openai-compat"
base_url = "{origin}"
key_secret = "{KEY_HANDLE}"
revision = "v1"
timeout_secs = 20

[media.video]
rungs = ["paid:video-small"]

[broker]
program = "{program}"
extra_roots = ["{ca}"]
"#,
            origin = fake.origin(),
            program = env!("CARGO_BIN_EXE_oneiron-broker"),
            ca = ca.display(),
        ),
        None,
    )
    .expect("models config");
    let runtime = ModelRuntime::build_with_keys(
        Some(&config),
        Some(door),
        oneiron::HostingPrivacyPosture::SelfHostLocal,
    )
    .with_media_vault(vault);
    assert_eq!(
        runtime.status().providers[0].broker_isolation,
        Some(BrokerIsolation::SameUser),
        "the key_secret provider uses the same-user broker child"
    );

    let purpose = CallPurpose::Other {
        name: "video-job-follow-up".to_owned(),
    };
    let request = MediaRequest {
        model: ModelId::new("paid/video-small@v1").expect("model id"),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Default::default(),
            tier: TierPrecedence::for_purpose(&purpose, ModelTierRef("video".into())),
            purpose,
            class: CallClass::BestEffort,
            response_format: ResponseFormat::Text,
            locality: ModelLocality::ThirdParty,
            host_keyless: false,
            host_paid: false,
        },
        operation: AiOperation::Video,
        parts: vec![MediaPart::Text {
            text: "A harbour at dawn".to_owned(),
        }],
        references: Vec::new(),
        mask: None,
        params: [
            ("seconds".to_owned(), json!(4)),
            ("size".to_owned(), json!("1280x720")),
        ]
        .into_iter()
        .collect(),
        voice: None,
    };
    let media = runtime.media();
    let ticket = media
        .submit(request, None, None, None)
        .await
        .expect("the admitted video job is submitted");
    assert_ne!(ticket.job, PROVIDER_JOB_ID, "the server mints the ticket");
    let state = media
        .poll(&ticket.job)
        .await
        .expect("the admitted job polls");
    assert!(
        matches!(state, MediaJobState::Running { .. } | MediaJobState::Queued),
        "the first poll keeps the admitted job running: {state:?}"
    );
    media
        .cancel(&ticket.job)
        .await
        .expect("the admitted job cancels");

    let seen = fake.seen();
    let requests: Vec<_> = seen
        .iter()
        .map(|request| (request.method.as_str(), request.path.as_str()))
        .collect();
    assert_eq!(
        requests,
        vec![
            ("POST", "/v1/videos"),
            ("GET", "/v1/videos/video_admitted_1"),
            ("DELETE", "/v1/videos/video_admitted_1"),
        ],
        "only submit, poll and cancel of the admitted provider job reach the provider, in order"
    );
    assert!(
        seen.iter().all(|request| {
            request.header("authorization") == Some(expected_authorization.as_str())
        }),
        "every request carries the sentinel key added by the broker"
    );

    assert!(
        media.poll("ticket-never-minted").await.is_err(),
        "a ticket no submit minted is refused"
    );
    assert_eq!(
        fake.seen().len(),
        seen.len(),
        "the refused poll sends no request to the provider"
    );
}
