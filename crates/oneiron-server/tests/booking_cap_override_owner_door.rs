//! BK-MEETING-CAPS PR B: only the vault's owner books past a meeting cap
//! (RULING BK-CAP-OVERRIDE-WHO = B, from the lead's OWNER-GRADE ruling, 15
//! Nov: "a full slip is a scope, not a Grant").
//!
//! `cap_override_reason` on a hold passes when the owner door
//! (`owner_routes::owner`) verifies the caller: here the host root. An agent
//! on an owner-grade slip (verified, unattenuated, top scope, vault reach)
//! is not the owner: naming a reason gets a 400, and the full day answers it
//! `slot_taken` like anyone else.
//!
//! The fixture is `tests/it/booking_agent_api.rs`'s (one page, one all-day
//! event type, an elected local writer, the host root); the agent slip is
//! minted as `tests/image_organ_route.rs` mints one. Run: `cargo test -p
//! oneiron-server --test booking_cap_override_owner_door`.
#![allow(clippy::unwrap_used)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use oneiron::agent_dispatch::DEFAULT_BASE_LOGICAL_ID;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, holder_proof_challenge};
use oneiron::booking::EventTypeKey;
use oneiron::booking::config::{
    BOOKING_EVENT_TYPE_PREDICATE, BOOKING_EVENT_TYPE_SCHEMA_VERSION, BookingEventTypeClaimValue,
    EventTypeConfig, HostAvailabilityConfig, RoutingMode, WeeklyWallWindow,
    encode_event_type_claim_value,
};
use oneiron::federation::Scope;
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_PERSON};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, DreamerHomeNodeCandidate,
    DreamerRunnerStore, EntityId, TimeRange, Vault, VaultConfig,
};
use oneiron_server::build_app;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::server::SyncServer;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SECRET: &str = "booking-cap-override-owner-door";
const EVENT_TYPE: &str = "intro-call";
const HOME_NODE_ID: u64 = 7;
const PAGE_TOKEN_DOMAIN: &[u8] = b"oneiron.booking.agent_api.page_token.v1\0";
const REASON: &str = "Board review moved; owen asked for this slot himself.";

fn seeded_id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).unwrap()
}

fn at(value: u64) -> TimeRange {
    TimeRange {
        start: value,
        end: value,
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn page_token(page_ref: EntityId) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PAGE_TOKEN_DOMAIN);
    hasher.update(page_ref.as_bytes());
    let digest = *hasher.finalize().as_bytes();
    format!("bkp_{}", hex_lower(&digest[..16]))
}

/// All day, every day, UTC, 30-minute slots, one booking a day.
fn capped_config(host: EntityId, calendar: EntityId) -> EventTypeConfig {
    EventTypeConfig {
        key: EventTypeKey(EVENT_TYPE.to_owned()),
        duration_min: 30,
        slot_step_min: 30,
        pre_buffer_min: 0,
        post_buffer_min: 0,
        min_notice_secs: 0,
        booking_window_secs: 30 * 86_400,
        daily_cap: Some(1),
        weekly_cap: None,
        routing: RoutingMode::Either,
        hosts: vec![HostAvailabilityConfig {
            host_ref: host,
            calendar_refs: vec![calendar],
            host_tz: "UTC".to_owned(),
            working_hours: (0..7)
                .map(|weekday| WeeklyWallWindow {
                    weekday,
                    start_minute: 0,
                    end_minute: 1440,
                })
                .collect(),
            preferred_hours: Vec::new(),
        }],
        flex_windows: Vec::new(),
    }
}

/// A vault with one booking page whose event type takes one booking a day,
/// and an elected local writer.
fn seeded_vault() -> (tempfile::TempDir, Arc<Vault>, EntityId) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.max_readers = 32;
    let vault = Vault::open(dir.path(), config).unwrap();
    let page = seeded_id(0xB0);
    vault
        .put_entity(&page, ENTITY_TYPE_ASSET, at(1), 1, b"booking page")
        .unwrap();
    vault
        .put_entity(&seeded_id(0xB1), ENTITY_TYPE_PERSON, at(1), 1, b"host")
        .unwrap();
    vault
        .put_entity(&seeded_id(0xB2), ENTITY_TYPE_ASSET, at(1), 1, b"calendar")
        .unwrap();
    DreamerRunnerStore::new(&vault)
        .elect_home_node(
            &[DreamerHomeNodeCandidate::always_on_local(HOME_NODE_ID)],
            1,
        )
        .unwrap();
    let value = BookingEventTypeClaimValue {
        schema_version: BOOKING_EVENT_TYPE_SCHEMA_VERSION,
        page_ref: page,
        config: capped_config(seeded_id(0xB1), seeded_id(0xB2)),
    };
    let mut body = ClaimBody::new(
        BOOKING_EVENT_TYPE_PREDICATE,
        ClaimSubject::Entity(page),
        encode_event_type_claim_value(&value).unwrap(),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("fixture");
    body.scope_facet = vault.default_facet().unwrap();
    vault.put_claim(&seeded_id(0xB3), &body, at(1), 1).unwrap();
    (dir, Arc::new(vault), page)
}

async fn spawn(vault: Arc<Vault>) -> (SocketAddr, Arc<SyncServer>, tokio::task::JoinHandle<()>) {
    let config = SyncServerConfig {
        auth_secret: Some(SECRET.to_owned()),
        ..Default::default()
    };
    let server = Arc::new(SyncServer::new(vault, config).unwrap());
    let app = build_app(server.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    (addr, server, handle)
}

/// Who signs a request's holder proof.
enum Holder {
    Issuer(HostSlipIssuer),
    Key(SigningKey),
}

/// One bearer credential and the key its holder proof is signed with.
struct Credential {
    slip: CapabilitySlip,
    holder: Holder,
}

impl Credential {
    /// The host root: the owner door passes it as the owner it acts as.
    fn host_root(vault: &Vault) -> Self {
        let issuer = HostSlipIssuer::from_secret(SECRET.as_bytes()).unwrap();
        let slip = vault.ensure_host_root_slip(&issuer).unwrap();
        Self {
            slip,
            holder: Holder::Issuer(issuer),
        }
    }

    /// An owner-grade agent slip: the root's top scope and vault reach, held
    /// by the seeded base agent under its own key.
    fn owner_grade_agent(vault: &Vault) -> Self {
        let issuer = HostSlipIssuer::from_secret(SECRET.as_bytes()).unwrap();
        let root = vault.ensure_host_root_slip(&issuer).unwrap();
        let (agent, _) = vault
            .get_seeded_agent_definition_by_logical_id(DEFAULT_BASE_LOGICAL_ID)
            .unwrap()
            .expect("the base agent is seeded");
        let key = SigningKey::from_bytes(&[0x72; 32]);
        let mut claims = root.claims.clone();
        claims.parent_id = None;
        claims.holder_ref = agent.to_hex();
        claims.binding_key = key.verifying_key().to_bytes();
        claims.actor_class = Some("agent".to_owned());
        claims.scope = Scope::top();
        claims.slip_id = [0x72; 32];
        Self {
            slip: vault.mint_capability_slip(&issuer, claims).unwrap(),
            holder: Holder::Key(key),
        }
    }

    /// The bearer and holder-proof headers for one request.
    fn headers(&self, vault: &Vault) -> String {
        let timestamp = vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let signature = match &self.holder {
            Holder::Issuer(issuer) => issuer.binding_proof(&self.slip, &challenge).unwrap(),
            Holder::Key(key) => key
                .sign(&self.slip.binding_transcript(&challenge).unwrap())
                .to_bytes()
                .to_vec(),
        };
        let binding = json!({
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": hex_lower(&signature),
        });
        format!(
            "Authorization: Bearer {}\r\nx-oneiron-binding: {binding}\r\n",
            self.slip.to_token().unwrap()
        )
    }
}

struct Booking {
    addr: SocketAddr,
    vault: Arc<Vault>,
    token: String,
}

impl Booking {
    async fn post(&self, credential: &Credential, op: &str, body: &Value) -> (u16, Value) {
        let body = body.to_string();
        let path = format!("/api/booking/{}/{op}", self.token);
        let mut stream = tokio::net::TcpStream::connect(self.addr).await.unwrap();
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{}\r\n{body}",
            self.addr,
            body.len(),
            credential.headers(&self.vault),
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(20), stream.read_to_end(&mut response))
            .await
            .expect("timed out waiting for HTTP response")
            .expect("failed reading HTTP response");
        let response = String::from_utf8(response).unwrap();
        let status = response
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse().ok())
            .unwrap_or_else(|| panic!("no HTTP status in {response:?}"));
        let body = response.split_once("\r\n\r\n").unwrap().1;
        let json = serde_json::from_str(body)
            .unwrap_or_else(|error| panic!("response body should be JSON ({error}): {body}"));
        (status, json)
    }

    /// Two open slots on one UTC day, before anything is booked.
    async fn two_slots_on_one_day(&self, credential: &Credential) -> (Value, Value) {
        let now = now_secs();
        let (status, answer) = self
            .post(
                credential,
                "availability",
                &json!({
                    "event_type": EVENT_TYPE,
                    "window": { "start": now, "end": now + 30 * 3_600 },
                    "visitor_tz": "UTC",
                    "constraint": null,
                    "session_ref": "sess-availability",
                }),
            )
            .await;
        assert_eq!(status, 200, "{answer}");
        let slots = answer["result"]["slots"].as_array().unwrap().clone();
        let day = |slot: &Value| slot["start_utc"].as_u64().unwrap() / 86_400;
        for (index, first) in slots.iter().enumerate() {
            if let Some(second) = slots[index + 1..]
                .iter()
                .find(|slot| day(slot) == day(first))
            {
                return (first.clone(), second.clone());
            }
        }
        panic!("thirty hours hold two slots on one day: {slots:?}");
    }

    /// Holds `slot` for `session`, with `reason` when given.
    async fn hold(
        &self,
        credential: &Credential,
        slot: &Value,
        session: &str,
        reason: Option<&str>,
    ) -> (u16, Value) {
        let mut input = json!({
            "event_type": EVENT_TYPE,
            "selected_slot": { "start_utc": slot["start_utc"], "end_utc": slot["end_utc"] },
            "visitor_tz": "UTC",
            "constraint": null,
            "session_ref": session,
            "checkout_lease_token": null,
            "idempotency_key": format!("hold-{session}"),
        });
        if let Some(reason) = reason {
            input["cap_override_reason"] = json!(reason);
        }
        self.post(
            credential,
            "book",
            &json!({ "stage": "hold", "input": input }),
        )
        .await
    }

    /// Confirms the hold `held` answered for `session`.
    async fn confirm(&self, credential: &Credential, held: &Value, session: &str) -> (u16, Value) {
        let hold_token = held["result"]["result"]["hold_token"].as_str().unwrap();
        self.post(
            credential,
            "book",
            &json!({
                "stage": "confirm",
                "input": {
                    "hold_token": hold_token,
                    "booker_email": "owen@example.com",
                    "intake": [],
                    "session_ref": session,
                    "idempotency_key": format!("confirm-{session}"),
                },
            }),
        )
        .await
    }

    /// Books `slot` as the host root, so its day is full.
    async fn fill_the_day(&self, root: &Credential, slot: &Value) {
        let (status, held) = self.hold(root, slot, "sess-first", None).await;
        assert_eq!(status, 200, "{held}");
        assert_eq!(held["result"]["stage"], "held", "{held}");
        let (status, confirmed) = self.confirm(root, &held, "sess-first").await;
        assert_eq!(status, 200, "{confirmed}");
        assert_eq!(confirmed["result"]["stage"], "confirmed", "{confirmed}");
    }
}

/// The host root passes the owner door: on a day the cap filled, a hold with
/// no reason is answered `slot_taken`, and a hold with one is held and
/// confirmed past the cap.
#[tokio::test]
async fn the_owner_holds_and_confirms_past_a_full_day_with_a_reason() {
    let (_dir, vault, page) = seeded_vault();
    let (addr, _server, handle) = spawn(vault.clone()).await;
    let booking = Booking {
        addr,
        vault: vault.clone(),
        token: page_token(page),
    };
    let root = Credential::host_root(&vault);
    let (first, second) = booking.two_slots_on_one_day(&root).await;
    booking.fill_the_day(&root, &first).await;

    let (status, taken) = booking.hold(&root, &second, "sess-plain", None).await;
    assert_eq!(status, 200, "{taken}");
    assert_eq!(
        taken["result"]["stage"], "slot_taken",
        "the cap filled the day: {taken}"
    );

    let (status, held) = booking
        .hold(&root, &second, "sess-owner", Some(REASON))
        .await;
    assert_eq!(status, 200, "{held}");
    assert_eq!(
        held["result"]["stage"], "held",
        "the owner holds past the cap: {held}"
    );
    let (status, confirmed) = booking.confirm(&root, &held, "sess-owner").await;
    assert_eq!(status, 200, "{confirmed}");
    assert_eq!(
        confirmed["result"]["stage"], "confirmed",
        "the owner books past the cap: {confirmed}"
    );
    handle.abort();
}

/// An owner-grade agent slip is not the owner: naming a reason gets a 400
/// that says so, and without one the full day answers `slot_taken`.
#[tokio::test]
async fn an_owner_grade_agent_slip_cannot_book_past_a_full_day() {
    let (_dir, vault, page) = seeded_vault();
    let (addr, _server, handle) = spawn(vault.clone()).await;
    let booking = Booking {
        addr,
        vault: vault.clone(),
        token: page_token(page),
    };
    let root = Credential::host_root(&vault);
    let agent = Credential::owner_grade_agent(&vault);
    let (first, second) = booking.two_slots_on_one_day(&root).await;
    booking.fill_the_day(&root, &first).await;

    let (status, refused) = booking
        .hold(&agent, &second, "sess-agent-reason", Some(REASON))
        .await;
    assert_eq!(status, 400, "an agent may not name a reason: {refused}");
    assert!(
        refused.to_string().contains("past a meeting cap"),
        "the refusal is the owner door's, not a parse error: {refused}"
    );

    let (status, taken) = booking
        .hold(&agent, &second, "sess-agent-plain", None)
        .await;
    assert_eq!(status, 200, "{taken}");
    assert_eq!(
        taken["result"]["stage"], "slot_taken",
        "the full day is full for the agent too: {taken}"
    );
    handle.abort();
}
