//! A keyed board replay meets the home its kept retrieval named
//! ([BOARD-REPLAY-CONVERSATION-HOME], DEC-0006 `#home-clearance`).
//!
//! A board whose retrieval runs homed in another vault is kept under its
//! `Idempotency-Key` while that home is cleared for sensitive stamped
//! claims, so its pack carries one. A retry under the key replays the board
//! only under the caller's authority as it stands then: once the owner
//! revokes the home clearance, the replay is refused as a board naming an
//! unreadable document is, and a fresh pack homed there leaves the stamped
//! claims out. While the clearance stands, the retry replays the first
//! board exactly.
//!
//! Deterministic: in-process vault and router (`oneshot`, no TCP ports, no
//! sleeps, no models, no embedder). Fixture pattern copied from
//! `context_pack_conversation_home.rs` (stamped claims, the owner's home
//! doors) and `room_pins_boards.rs` (an owner slip bound to the embedded
//! owner driving the board route).
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --test board_replay_conversation_home`.

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::on_engine_stack;
use oneiron::authority::{CapabilitySlip, MachineRole, holder_proof_challenge};
use oneiron::consent::AuthenticatedOwner;
use oneiron::disclosure::DisclosureBand;
use oneiron::federation::Scope;
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EntityId, HomeClearanceRequest, HomeClearanceSet, TimeRange, Vault,
    VaultConfig,
};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const BOARD: &str = "/v1/core/context-board";
const CONTEXT_PACK: &str = "/v1/core/context-pack";
const KEY: &str = "board-home-replay";
/// Another vault's authority id, as the home rule names it.
const OTHER: [u8; 32] = [0x42; 32];
/// When the seeded claims and their subject were learned and hold.
const LEARNED_AT: u64 = 1_780_000_000;
/// The word every seeded claim holds, which no other row holds.
const SHARED_WORD: &str = "lanternwick";
/// The one word each seeded claim alone holds.
const UNSTAMPED_WORD: &str = "juniper";
const PRIVATE_WORD: &str = "wren";
const SENSITIVE_WORD: &str = "lark";
/// The seeded claims' predicate, which is not Tier A.
const PREDICATE: &str = "profile.note";

struct Host {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    proof: AuthenticatedOwner,
    owner: EntityId,
    slip: CapabilitySlip,
    token: String,
    key: SigningKey,
    unstamped: EntityId,
    private_stamped: EntityId,
    sensitive_stamped: EntityId,
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
        // One PERSON the three claims hang off.
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
        let unstamped = EntityId::from_bytes([0x51; 16])?;
        seed_claim(
            &vault,
            &unstamped,
            subject,
            &format!("{SHARED_WORD} {UNSTAMPED_WORD}"),
            None,
        )?;
        let private_stamped = EntityId::from_bytes([0x53; 16])?;
        seed_claim(
            &vault,
            &private_stamped,
            subject,
            &format!("{SHARED_WORD} {PRIVATE_WORD}"),
            Some("private"),
        )?;
        let sensitive_stamped = EntityId::from_bytes([0x54; 16])?;
        seed_claim(
            &vault,
            &sensitive_stamped,
            subject,
            &format!("{SHARED_WORD} {SENSITIVE_WORD}"),
            Some("sensitive"),
        )?;
        let server = Arc::new(SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("board-replay-conversation-home".into()),
                ..Default::default()
            },
        )?);
        let issuer = vault.load_host_slip_issuer()?;
        let root = vault.ensure_host_root_slip(&issuer)?;
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let proof = vault
            .memory(owner, EdgeActorClass::Human)
            .embedded_owner("vault.disclosure.home.set")?;
        // The board caller's credential: the root slip's top scope bound to
        // the embedded owner as a human, so it is owner-grade (it may name a
        // foreign home) and its principal owns the TURN's board. Keep
        // Scope::top(): attenuating it would remove owner-grade standing.
        let key = SigningKey::from_bytes(&[0x67; 32]);
        let mut claims = root.claims.clone();
        claims.parent_id = None;
        claims.holder_ref = owner.to_hex();
        claims.binding_key = key.verifying_key().to_bytes();
        claims.actor_class = Some("human".to_owned());
        claims.scope = Scope::top();
        claims.slip_id = [0x67; 32];
        let slip = vault.mint_capability_slip(&issuer, claims)?;
        let token = slip.to_token()?;
        let app = build_app(server);
        Ok(Self {
            _dir: dir,
            vault,
            app,
            proof,
            owner,
            slip,
            token,
            key,
            unstamped,
            private_stamped,
            sensitive_stamped,
        })
    }

    /// The owner clears the other vault's home for sensitive stamped claims.
    fn set_home(&self) -> TestResult {
        let view = self.vault.set_home_disclosure_clearance(
            &self.proof,
            HomeClearanceSet {
                home_vault_id: hex(&OTHER),
                band: DisclosureBand::Sensitive,
            },
        )?;
        assert_eq!(view.band, Some(DisclosureBand::Sensitive));
        Ok(())
    }

    /// The owner revokes that home clearance.
    fn clear_home(&self) -> TestResult {
        let view = self.vault.clear_home_disclosure_clearance(
            &self.proof,
            HomeClearanceRequest {
                home_vault_id: hex(&OTHER),
            },
        )?;
        assert_eq!(view.band, None);
        Ok(())
    }

    /// A TURN whose body carries the owner as the author its door stamps.
    fn put_turn(&self) -> TestResult<EntityId> {
        let turn = EntityId::now();
        let body = rmp_serde::to_vec_named(&json!({ "actor": self.owner.to_hex() }))?;
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

    /// The keyed board request: a retrieval homed in the other vault, for
    /// the owner's TURN.
    fn board_body(&self, turn: EntityId) -> Value {
        json!({
            "retrieval": {
                "query": SHARED_WORD,
                "limit": 10,
                "conversation_home": hex(&OTHER),
            },
            "session": {"session_id": self.owner.to_hex()},
            "turn": {"id": turn.to_hex()}
        })
    }

    async fn post(
        &self,
        path: &str,
        body: &Value,
        idempotency_key: Option<&str>,
    ) -> TestResult<(StatusCode, Value)> {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let transcript = self.slip.binding_transcript(&challenge)?;
        let signature = self.key.sign(&transcript).to_bytes();
        let mut request = Request::post(path)
            .header("authorization", format!("Bearer {}", self.token))
            .header(
                "x-oneiron-binding",
                json!({"timestamp": timestamp, "nonce": nonce, "signature": hex(&signature)})
                    .to_string(),
            )
            .header("content-type", "application/json");
        if let Some(key) = idempotency_key {
            request = request.header("Idempotency-Key", key);
        }
        let request = request.body(Body::from(body.to_string()))?;
        let response = self.app.clone().oneshot(request).await?;
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX).await?;
        let answer: Value = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
            panic!(
                "{path} answered no JSON: {}",
                String::from_utf8_lossy(&bytes)
            )
        });
        Ok((status, answer))
    }
}

/// The result ids of a board's pack.
fn board_pack_ids(board: &Value) -> Vec<String> {
    board["pack"]["results"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter_map(|row| row["id"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// The result ids of a context pack on its own route.
fn pack_ids(pack: &Value) -> Vec<String> {
    pack["results"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter_map(|row| row["id"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn a_keyed_board_replay_honours_a_revoked_home_clearance() -> TestResult {
    on_engine_stack(|| async {
        let host = Host::new()?;
        host.set_home()?;
        let turn = host.put_turn()?;
        let body = host.board_body(turn);

        let (status, first) = host.post(BOARD, &body, Some(KEY)).await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "a board homed in the cleared vault answers 200: {first}"
        );
        assert_eq!(first["board_turn"]["turn"], turn.to_hex(), "{first}");
        let ids = board_pack_ids(&first);
        assert!(
            ids.contains(&host.sensitive_stamped.to_hex()),
            "the cleared home's board carries the sensitive stamped claim: {first}"
        );
        assert!(
            ids.contains(&host.private_stamped.to_hex()),
            "the cleared home's board carries the private stamped claim: {first}"
        );
        // While the clearance stands, the retry replays the first board.
        let (status, retried) = host.post(BOARD, &body, Some(KEY)).await?;
        assert_eq!(status, StatusCode::OK, "{retried}");
        assert_eq!(retried, first);

        // The owner revokes the home clearance between the first request and
        // the retry: the replay is refused, and names no stamped claim.
        host.clear_home()?;
        let (status, refused) = host.post(BOARD, &body, Some(KEY)).await?;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "a replay after the home clearance is revoked is refused: {refused}"
        );
        assert!(
            refused.to_string().contains("board_document_unreadable"),
            "{refused}"
        );
        assert!(
            !refused
                .to_string()
                .contains(&host.sensitive_stamped.to_hex()),
            "{refused}"
        );

        // A fresh pack homed there agrees: the stamped claims stay out.
        let (status, pack) = host
            .post(
                CONTEXT_PACK,
                &json!({"query": SHARED_WORD, "limit": 10, "conversation_home": hex(&OTHER)}),
                None,
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "{pack}");
        let ids = pack_ids(&pack);
        assert!(
            ids.contains(&host.unstamped.to_hex()),
            "a fresh pack homed in the revoked vault reads the unstamped claim: {pack}"
        );
        assert!(
            !ids.contains(&host.private_stamped.to_hex()),
            "a fresh pack homed in the revoked vault leaves the private claim out: {pack}"
        );
        assert!(
            !ids.contains(&host.sensitive_stamped.to_hex()),
            "a fresh pack homed in the revoked vault leaves the sensitive claim out: {pack}"
        );

        // Granting the clearance again lets the same key replay its board.
        host.set_home()?;
        let (status, retried) = host.post(BOARD, &body, Some(KEY)).await?;
        assert_eq!(status, StatusCode::OK, "{retried}");
        assert_eq!(retried, first);
        Ok(())
    })
}

#[test]
fn a_keyed_board_replay_with_its_home_clearance_standing_replays_its_first_board() -> TestResult {
    on_engine_stack(|| async {
        let host = Host::new()?;
        host.set_home()?;
        let turn = host.put_turn()?;
        let body = host.board_body(turn);

        let (status, first) = host.post(BOARD, &body, Some(KEY)).await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "a board homed in the cleared vault answers 200: {first}"
        );
        assert!(
            board_pack_ids(&first).contains(&host.sensitive_stamped.to_hex()),
            "the cleared home's board carries the sensitive stamped claim: {first}"
        );
        for _ in 0..2 {
            let (status, retried) = host.post(BOARD, &body, Some(KEY)).await?;
            assert_eq!(
                status,
                StatusCode::OK,
                "an unchanged home clearance replays its board: {retried}"
            );
            assert_eq!(retried, first);
        }
        Ok(())
    })
}
