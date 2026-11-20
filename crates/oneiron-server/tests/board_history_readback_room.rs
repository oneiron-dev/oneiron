//! A board read back in the room it read in (BOARD-HISTORY-READBACK-ROOM).
//!
//! GET /v1/core/context-board/turns/{turn} rebuilt the caller's authority
//! with no room. An outside reader that is not owner grade and not one of
//! the vault's own agents, homed in ConversationHome::UNNAMED with no room,
//! could not read back a board it made in a room it stands in when that
//! board showed a claim stamped sensitivity "private": the read-back
//! answered 409 board_document_unreadable. The fix keeps the board's room
//! on the turn anchor and reads back with that room.
//!
//! Deterministic: in-process vault and router (`oneshot`, no TCP ports, no
//! sleeps, no models, no embedder). Fixture pattern copied from
//! `context_pack_conversation_home.rs` (stamped claims, the outside reader,
//! the precleared contact) and `board_replay_conversation_home.rs` (the
//! owner's slip, put_turn, the room pin, the board body).
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support
//! --test board_history_readback_room`.

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::on_engine_stack;
use oneiron::authority::{CapabilitySlip, MachineRole, holder_proof_challenge};
use oneiron::conversation::{ConversationBody, ConversationKind};
use oneiron::counterparty_contact::CounterpartyContactRecord;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::workspace_roster::{RoomLeaveRequest, RoomPinRequest};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor,
};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const BOARD: &str = "/v1/core/context-board";
const BOARD_TURNS: &str = "/v1/core/context-board/turns";
/// When the seeded claim and its subject were learned and hold.
const LEARNED_AT: u64 = 1_780_000_000;
/// The word every seeded claim holds, which no other row holds.
const SHARED_WORD: &str = "lanternwick";
/// The one word the private stamped claim alone holds.
const PRIVATE_WORD: &str = "wren";
/// The seeded claim's predicate, which is not Tier A.
const PREDICATE: &str = "profile.note";

struct Host {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    owner: EntityId,
    owner_slip: CapabilitySlip,
    owner_token: String,
    owner_key: SigningKey,
    outside_slip: CapabilitySlip,
    outside_token: String,
    outside_key: SigningKey,
    outside_person: EntityId,
    private_stamped: EntityId,
    room: EntityId,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// One seeded claim about `subject`, holding `text`, stamped `sensitivity`
/// when named, and indexed for text retrieval.
fn seed_claim(
    vault: &Vault,
    id: &EntityId,
    subject: EntityId,
    text: &str,
    sensitivity: Option<&str>,
) -> TestResult {
    let mut body = ClaimBody::new(
        PREDICATE,
        ClaimSubject::Entity(subject),
        rmpv::Value::from(text),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::UserStated);
    if let Some(band) = sensitivity {
        body.scope = Some(rmpv::Value::Map(vec![(
            rmpv::Value::from("sensitivity"),
            rmpv::Value::from(band),
        )]));
    }
    vault.put_claim(
        id,
        &body,
        TimeRange {
            start: LEARNED_AT,
            end: LEARNED_AT,
        },
        LEARNED_AT,
    )?;
    vault.batch().text(id, &[("body", text)]).commit()?;
    Ok(())
}

impl Host {
    fn new() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let mut config = VaultConfig::device();
        config.embedding_model = None;
        config.dimensions = 4;
        let vault = Arc::new(Vault::open_owned(dir.path(), config)?);
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        let owner = vault.ensure_embedded_owner_actor()?;
        // One PERSON the claim hangs off, and one PERSON the outside
        // reader's identity links to. The room seats both as PERSONs: a
        // conversation's member_ids must be PERSONs, so the reader stands
        // in the room as this PERSON, not as its contact id.
        let subject = EntityId::now();
        vault.put_entity(
            &subject,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: LEARNED_AT,
                end: LEARNED_AT,
            },
            LEARNED_AT,
            b"home clearance subject",
        )?;
        let outside_person = EntityId::now();
        vault.put_entity(
            &outside_person,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: LEARNED_AT,
                end: LEARNED_AT,
            },
            LEARNED_AT,
            b"outside person",
        )?;
        // The one claim this row turns on: stamped sensitivity "private".
        let private_stamped = EntityId::from_bytes([0x53; 16])?;
        seed_claim(
            &vault,
            &private_stamped,
            subject,
            &format!("{SHARED_WORD} {PRIVATE_WORD}"),
            Some("private"),
        )?;
        let server = Arc::new(SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("board-history-readback-room".into()),
                ..Default::default()
            },
        )?);
        let issuer = vault.load_host_slip_issuer()?;
        let root = vault.ensure_host_root_slip(&issuer)?;
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let proof = vault
            .memory(owner, EdgeActorClass::Human)
            .embedded_owner("vault.disclosure.home.set")?;
        // A room of this vault seating the owner and the outside reader's
        // PERSON, so the reader stands in the room it posts its board in.
        let room = EntityId::now();
        vault.create_conversation(
            room,
            &ConversationBody {
                kind: ConversationKind::Group,
                member_ids: vec![owner, outside_person],
                ..Default::default()
            },
            WriteActor::new(owner, EdgeActorClass::Human),
            vault.now_recorded_at(),
        )?;
        // The outside reader's contact, cleared for the vault's full scope.
        // The contact is About the reader's PERSON alone, so the room meet
        // classes that member as this contact and lets Scope::top() admit
        // the private stamped claim.
        let contact = EntityId::now();
        vault.create_counterparty_contact(
            &contact,
            &CounterpartyContactRecord::public(
                outside_person,
                "outside@example.com",
                vault.now_recorded_at(),
            )?,
        )?;
        let _ = vault.preclear_contact_disclosure(
            &proof,
            "outside-reader",
            &[contact],
            Scope::top(),
        )?;
        // The owner's credential: the root slip's top scope bound to the
        // embedded owner as a human, so it is owner-grade (Scope::top()
        // and unattenuated) and its principal owns its own TURN's board.
        // Keep Scope::top(): attenuating it would remove owner-grade
        // standing.
        let owner_key = SigningKey::from_bytes(&[0x67; 32]);
        let mut claims = root.claims.clone();
        claims.parent_id = None;
        claims.holder_ref = owner.to_hex();
        claims.binding_key = owner_key.verifying_key().to_bytes();
        claims.actor_class = Some("human".to_owned());
        claims.scope = Scope::top();
        claims.slip_id = [0x67; 32];
        let owner_slip = vault.mint_capability_slip(&issuer, claims)?;
        let owner_token = owner_slip.to_token()?;
        // The outside reader's delegated credential: verbs read and write
        // (board recording needs CoreScope::Write), holder the reader's
        // PERSON. The narrowed verbs make it not owner-grade, and a human
        // holder who is no vault agent makes it not one of the vault's own
        // agents.
        let outside_key = SigningKey::from_bytes(&[0x66; 32]);
        let mut scope = Scope::top();
        scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
        let mut claims = owner_slip.claims.clone();
        claims.parent_id = None;
        claims.holder_ref = outside_person.to_hex();
        claims.binding_key = outside_key.verifying_key().to_bytes();
        claims.actor_class = Some("human".to_owned());
        claims.scope = scope;
        claims.slip_id = [0x66; 32];
        let outside_slip = vault.mint_capability_slip(&issuer, claims)?;
        let outside_token = outside_slip.to_token()?;
        let app = build_app(server);
        Ok(Self {
            _dir: dir,
            vault,
            app,
            owner,
            owner_slip,
            owner_token,
            owner_key,
            outside_slip,
            outside_token,
            outside_key,
            outside_person,
            private_stamped,
            room,
        })
    }

    fn owner_binding(&self) -> TestResult<String> {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let transcript = self.owner_slip.binding_transcript(&challenge)?;
        let signature = self.owner_key.sign(&transcript).to_bytes();
        Ok(
            json!({"timestamp": timestamp, "nonce": nonce, "signature": hex(&signature)})
                .to_string(),
        )
    }

    fn outside_binding(&self) -> TestResult<String> {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let transcript = self.outside_slip.binding_transcript(&challenge)?;
        let signature = self.outside_key.sign(&transcript).to_bytes();
        Ok(
            json!({"timestamp": timestamp, "nonce": nonce, "signature": hex(&signature)})
                .to_string(),
        )
    }

    async fn send(&self, request: Request<Body>) -> TestResult<(StatusCode, Value)> {
        let response = self.app.clone().oneshot(request).await?;
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX).await?;
        let answer: Value = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
            panic!(
                "the request answered no JSON: {}",
                String::from_utf8_lossy(&bytes)
            )
        });
        Ok((status, answer))
    }

    async fn post_as_owner(&self, path: &str, body: Value) -> TestResult<(StatusCode, Value)> {
        let request = Request::post(path)
            .header("authorization", format!("Bearer {}", self.owner_token))
            .header("x-oneiron-binding", self.owner_binding()?)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))?;
        self.send(request).await
    }

    async fn post_as_outside(&self, path: &str, body: Value) -> TestResult<(StatusCode, Value)> {
        let request = Request::post(path)
            .header("authorization", format!("Bearer {}", self.outside_token))
            .header("x-oneiron-binding", self.outside_binding()?)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))?;
        self.send(request).await
    }

    async fn get_as_owner(&self, path: &str) -> TestResult<(StatusCode, Value)> {
        let request = Request::get(path)
            .header("authorization", format!("Bearer {}", self.owner_token))
            .header("x-oneiron-binding", self.owner_binding()?)
            .body(Body::empty())?;
        self.send(request).await
    }

    async fn get_as_outside(&self, path: &str) -> TestResult<(StatusCode, Value)> {
        let request = Request::get(path)
            .header("authorization", format!("Bearer {}", self.outside_token))
            .header("x-oneiron-binding", self.outside_binding()?)
            .body(Body::empty())?;
        self.send(request).await
    }

    /// A TURN whose body carries `author` as the author its door stamps.
    fn put_turn(&self, author: EntityId) -> TestResult<EntityId> {
        let turn = EntityId::now();
        let body = rmp_serde::to_vec_named(&json!({ "actor": author.to_hex() }))?;
        self.vault.put_entity(
            &turn,
            ENTITY_TYPE_TURN,
            TimeRange {
                start: LEARNED_AT,
                end: LEARNED_AT,
            },
            LEARNED_AT,
            &body,
        )?;
        Ok(turn)
    }

    /// The board request: no retrieval, for `author`'s TURN, in the room.
    fn board_body(&self, turn: EntityId, author: EntityId) -> Value {
        json!({
            "session": {"session_id": author.to_hex()},
            "turn": {"id": turn.to_hex()},
            "room": {"conversation_id": self.room.to_hex()}
        })
    }

    /// The owner pins the private stamped claim in the room.
    fn pin_private(&self) -> TestResult {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .rooms_pins_pin(&RoomPinRequest {
                room: self.room,
                target: self.private_stamped,
            })?;
        Ok(())
    }

    /// The owner removes the outside reader from the room: `rooms.leave`,
    /// the vault owner's removal door.
    fn remove_outside(&self) -> TestResult {
        let outcome = self
            .vault
            .memory(self.owner, EdgeActorClass::Human)
            .rooms_leave(&RoomLeaveRequest {
                room: self.room,
                person: self.outside_person,
            })?;
        assert!(
            !outcome.member_ids.contains(&self.outside_person),
            "the owner removed the outside reader from the room: {outcome:?}"
        );
        Ok(())
    }
}

fn pinned_row(board: &Value, claim: EntityId) -> &Value {
    board["memories"]["rows"]
        .as_array()
        .expect("the board carries MEMORIES rows")
        .iter()
        .find(|row| row["id"] == claim.to_hex())
        .unwrap_or_else(|| panic!("the room admits the private stamped claim: {board}"))
}

fn pinned_contains(history: &Value, claim: EntityId) -> bool {
    history["selection"]["pinned"]
        .as_array()
        .is_some_and(|rows| rows.iter().any(|row| row == &json!(claim.to_hex())))
}

#[test]
fn an_outside_reader_reads_back_its_board_in_a_room() -> TestResult {
    on_engine_stack(|| async {
        let host = Host::new()?;
        host.pin_private()?;
        let turn = host.put_turn(host.outside_person)?;

        let (status, board) = host
            .post_as_outside(BOARD, host.board_body(turn, host.outside_person))
            .await?;
        assert_eq!(status, StatusCode::OK, "{board}");
        assert_eq!(board["board_turn"]["turn"], turn.to_hex(), "{board}");
        let pin = pinned_row(&board, host.private_stamped);
        assert_eq!(pin["tier"], "pinned", "{board}");
        assert_eq!(pin["room_pin"]["target"], host.private_stamped.to_hex());
        assert_eq!(pin["room_pin"]["pinned_by"], host.owner.to_hex());

        // On main this GET answers 409 board_document_unreadable: that is
        // the red, because the read-back rebuilt authority with no room.
        let path = format!("{BOARD_TURNS}/{}", turn.to_hex());
        let (status, history) = host.get_as_outside(&path).await?;
        assert_eq!(status, StatusCode::OK, "{history}");
        assert_eq!(history["kind"], json!("board"), "{history}");
        assert!(
            pinned_contains(&history, host.private_stamped),
            "the read-back keeps the room pin: {history}"
        );
        assert!(
            history["documents"]
                .get(host.private_stamped.to_hex())
                .is_some(),
            "the read-back carries the pinned claim's document: {history}"
        );
        Ok(())
    })
}

#[test]
fn an_outside_reader_who_left_the_room_reads_none_of_its_board_back() -> TestResult {
    on_engine_stack(|| async {
        let host = Host::new()?;
        host.pin_private()?;
        let turn = host.put_turn(host.outside_person)?;

        let (status, board) = host
            .post_as_outside(BOARD, host.board_body(turn, host.outside_person))
            .await?;
        assert_eq!(status, StatusCode::OK, "{board}");
        assert_eq!(board["board_turn"]["turn"], turn.to_hex(), "{board}");

        host.remove_outside()?;
        let path = format!("{BOARD_TURNS}/{}", turn.to_hex());
        let (status, history) = host.get_as_outside(&path).await?;
        assert_ne!(
            status,
            StatusCode::OK,
            "a reader who left the room reads none of its board back: {history}"
        );
        assert!(
            !history.to_string().contains(&host.private_stamped.to_hex()),
            "the refusal names no pinned claim: {history}"
        );
        Ok(())
    })
}

#[test]
fn the_owner_reads_back_its_board_in_a_room() -> TestResult {
    on_engine_stack(|| async {
        let host = Host::new()?;
        host.pin_private()?;
        let turn = host.put_turn(host.owner)?;

        let (status, board) = host
            .post_as_owner(BOARD, host.board_body(turn, host.owner))
            .await?;
        assert_eq!(status, StatusCode::OK, "{board}");
        assert_eq!(board["board_turn"]["turn"], turn.to_hex(), "{board}");
        let pin = pinned_row(&board, host.private_stamped);
        assert_eq!(pin["tier"], "pinned", "{board}");

        let path = format!("{BOARD_TURNS}/{}", turn.to_hex());
        let (status, history) = host.get_as_owner(&path).await?;
        assert_eq!(status, StatusCode::OK, "{history}");
        assert_eq!(history["kind"], json!("board"), "{history}");
        assert!(
            pinned_contains(&history, host.private_stamped),
            "the owner reads back its room pin: {history}"
        );
        assert!(
            history["documents"]
                .get(host.private_stamped.to_hex())
                .is_some(),
            "the owner reads back the pinned claim's document: {history}"
        );
        Ok(())
    })
}
