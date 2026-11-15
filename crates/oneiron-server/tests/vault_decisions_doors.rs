//! The `vault.decisions.*` rows at the public door: each test proves one canon
//! promise of a decision ask or a decision band through the server's real router.
//!
//! All six rows are host doors (`host_only(...)` in-process), so these tests
//! drive `build_app` at `POST /v1/core/facade/<verb>`. The self-hosted root
//! credential (`HostSlipIssuer::from_secret`) acts as the vault's embedded owner
//! (the band rows and `confirm_grant` take the owner's own credential); a person
//! who holds an ask's role calls `answer` and `climb` with a slip this host mints
//! them. Asks are queued model-free with the engine's own `Vault` calls; the acts
//! under test are always the facade's. Every body runs on the engine's stack.
//!
//! Canon:
//! - `an_ask_climbs_under_its_ceiling_and_ends_at_the_owner`:
//!   oneiron-arch-0076-typed-judgments-v1.md:24 "It climbs under the caller's
//!   ceiling and ends at the vault owner role".
//! - `an_ask_closes_as_one_settlement`: oneiron-dec-0006-unified-consent-mode.md:45
//!   "Every ask is one PROPOSAL, and it closes as one SETTLEMENT".
//! - `a_drafted_grant_settles_on_the_owners_confirm`: dec-0006:37 "A default policy
//!   row says who settles it": the owner's reason drafts the standing grant and
//!   his confirm alone makes it live.
//! - `a_learned_band_shadows_until_the_owner_enforces_it`: arch-0076:275 "A learned
//!   decision-band mode and its version", within one host: a band is learned in
//!   shadow at a version that only advances, and enforces only once learned.
//! - `a_malformed_unsigned_or_roleless_decisions_act_is_refused`: each of the six rows.
//!
//! Seeded faults (each makes its test fail and leaves the crates compiling):
//! - red1: `oneiron/src/llm/decision/asks.rs:706`, the climb's next role asked
//!   `after: None`, so a climb restarts its chain at the responsible person (the
//!   climb test);
//!   `asks.rs:498` `return if held.answer == answer {` made `!=`, so the same
//!   answer again is refused (the settlement test). Green there: the grant, band
//!   and refusal tests, which never climb and answer no ask twice.
//! - red2: `oneiron/src/llm/decision/asks/grant_draft.rs:32` `*role != AskRole::Owner`
//!   made `==`, so the owner's reason drafts nothing (the grant test);
//!   `oneiron-store/src/model_decision/policy.rs:259` `row.version >= version` made
//!   `>`, so a band relearns at its own version (the band test);
//!   `oneiron-verb-wire/src/receipt/decision_asks.rs:39` `deny_unknown_fields`
//!   deleted on `DecisionAskClimbRequest` (the refusal table). Green there: the
//!   climb and settlement tests, which send well-formed bodies only.
//!
//! Not proven here: dec-0006:38 "Anything that exceeds the bound is a fresh ask"
//! (no row of this family carries a bound; the gate's evaluator judges it), and
//! promise-dura-10 "stay in effect after a restart" (a band row lives in the
//! host's memory, `DecisionBandPolicy`, so a new host reads the seed: FIX-LIST).
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --test vault_decisions_doors`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use engine_stack::run_on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, holder_proof};
use oneiron::consent::{
    ActionClass, ActionEnvelope, ActorBound, ComposedEffect, EffectFacts, GrantBound,
};
use oneiron::federation::ScopeAxis;
use oneiron::llm::decision::{
    AnswerActor, AnswerContract, AskAct, AskConsent, AskGrantDraft, AskRole, AskTo, DecisionAnswer,
    DecisionClass, DecisionQuestion, DecisionRung, HumanAskReason, HumanDecisionRequest,
    ProviderPin, RoleRank,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

const SECRET: &str = "vault-decisions-doors-secret";

/// A distinct slip id for each credential a test mints.
fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// The key every minted credential binds; its holder proves it per request.
fn holder_key() -> SigningKey {
    SigningKey::from_bytes(&[0x5B; 32])
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A yes-or-no question under a fresh id: an open ask for the same question,
/// principal, evidence, route and correlation is that same ask.
fn question(text: &str) -> DecisionQuestion {
    DecisionQuestion {
        id: EntityId::now(),
        version: 1,
        text: text.to_owned(),
        class: DecisionClass::Judgment,
        contract: AnswerContract::Noul,
        accept_type: false,
    }
}

/// `question` as the band rows take it.
fn question_json(question: &DecisionQuestion) -> Value {
    json!({
        "id": question.id.to_hex(),
        "version": question.version,
        "text": question.text,
        "class": "judgment",
        "contract": {"kind": "noul"},
        "accept_type": false,
    })
}

/// An ask for `principal`'s judgment at `to`, with no evidence and no prior.
fn request(principal: EntityId, to: AskTo, text: &str) -> HumanDecisionRequest {
    HumanDecisionRequest {
        question: question(text),
        principal,
        evidence: Vec::new(),
        reason: HumanAskReason::Uncertain,
        prior: None,
        prior_provider: None,
        queue_pin: ProviderPin {
            rung: DecisionRung::Human,
            model: "test.decisions.door".to_owned(),
            version: "1".to_owned(),
        },
        to,
        correlation: None,
    }
}

/// The person `who` is responsible, up to `ceiling`.
fn responsible(who: EntityId, ceiling: RoleRank) -> AskTo {
    AskTo {
        role: AskRole::Responsible {
            actor: AnswerActor::Actor(who),
            project: None,
        },
        ceiling,
        act: AskAct::Judgment,
    }
}

/// A refusal's (status, code, message): what a caller tells apart.
fn refusal(status: StatusCode, body: &Value) -> (StatusCode, Value, Value) {
    (
        status,
        body["error"]["code"].clone(),
        body["error"]["message"].clone(),
    )
}

/// One rooted vault, its server's router and the self-hosted root credential.
struct Door {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    root: CapabilitySlip,
    owner: EntityId,
}

impl Door {
    fn open() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
        let server = Arc::new(
            SyncServer::new(
                Arc::clone(&vault),
                SyncServerConfig {
                    auth_secret: Some(SECRET.to_owned()),
                    ..Default::default()
                },
            )
            .unwrap(),
        );
        let issuer = HostSlipIssuer::from_secret(SECRET.as_bytes()).unwrap();
        let root = vault.ensure_host_root_slip(&issuer).unwrap();
        let owner = vault.ensure_embedded_owner_actor().unwrap();
        Self {
            _dir: dir,
            app: build_app(server),
            vault,
            issuer,
            root,
            owner,
        }
    }

    /// A live person.
    fn person(&self) -> EntityId {
        let id = EntityId::now();
        self.vault
            .put_entity(
                &id,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"human",
            )
            .unwrap();
        id
    }

    async fn send(&self, request: Request<Body>) -> (StatusCode, Value) {
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1_048_576).await.unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// `POST /v1/core/facade/<verb>` with `body` as sent, under the
    /// `(token, binding)` credential, or with none.
    async fn post_raw(
        &self,
        verb: &str,
        body: String,
        credential: Option<(String, String)>,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .method("POST")
            .uri(format!("/v1/core/facade/{verb}"))
            .header("content-type", "application/json");
        if let Some((token, binding)) = credential {
            request = request
                .header("authorization", format!("Bearer {token}"))
                .header("x-oneiron-binding", binding);
        }
        self.send(request.body(Body::from(body)).unwrap()).await
    }

    /// The root credential with a fresh proof: the owner's own.
    fn owner_credential(&self) -> (String, String) {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let signature = self
            .issuer
            .binding_proof(&self.root, challenge.as_bytes())
            .unwrap();
        let binding = json!({"timestamp": timestamp, "nonce": nonce, "signature": hex(&signature)});
        (self.root.to_token().unwrap(), binding.to_string())
    }

    /// A slip this host mints the person `who`, holding `read` and `write`, with
    /// a fresh holder proof: not owner-grade and not the host's own.
    fn person_credential(&self, who: EntityId) -> (String, String) {
        let mut claims = self.root.claims.clone();
        claims.slip_id = next_slip_id();
        claims.parent_id = None;
        claims.holder_ref = who.to_hex();
        claims.actor_class = Some("human".to_owned());
        claims.binding_key = holder_key().verifying_key().to_bytes();
        claims.scope.verbs =
            ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
        let slip = self
            .vault
            .mint_capability_slip(&self.issuer, claims)
            .unwrap();
        let binding = holder_proof(&slip, &holder_key(), self.vault.now_recorded_at()).unwrap();
        (slip.to_token().unwrap(), binding.to_string())
    }

    async fn post_owner(&self, verb: &str, body: &Value) -> (StatusCode, Value) {
        let credential = self.owner_credential();
        self.post_raw(verb, body.to_string(), Some(credential))
            .await
    }

    async fn post_person(&self, who: EntityId, verb: &str, body: &Value) -> (StatusCode, Value) {
        let credential = self.person_credential(who);
        self.post_raw(verb, body.to_string(), Some(credential))
            .await
    }
}

/// arch-0076:24 "It climbs under the caller's ceiling and ends at the vault owner
/// role": an ask at its responsible person climbs one step to the owner role,
/// held by the vault's owner; under a Responsible ceiling it climbs nowhere and
/// stays its person's to answer.
#[test]
fn an_ask_climbs_under_its_ceiling_and_ends_at_the_owner() {
    run_on_engine_stack("decisions-climb", || async {
        let door = Door::open();
        let person = door.person();

        let seq = door
            .vault
            .queue_decision_ask(&request(
                person,
                responsible(person, RoleRank::Owner),
                "climbs",
            ))
            .unwrap();
        let (status, climbed) = door
            .post_person(person, "vault.decisions.asks.climb", &json!({"seq": seq}))
            .await;
        assert_eq!(status, StatusCode::OK, "{climbed}");
        assert_eq!(climbed["role"]["role"], "owner", "{climbed}");
        let holders = climbed["holders"].as_array().unwrap();
        assert!(
            holders
                .iter()
                .any(|holder| holder["actor"] == door.owner.to_hex()),
            "the owner role is the vault owner's: {climbed}"
        );

        let capped = door
            .vault
            .queue_decision_ask(&request(
                person,
                responsible(person, RoleRank::Responsible),
                "stays",
            ))
            .unwrap();
        let (status, stayed) = door
            .post_person(
                person,
                "vault.decisions.asks.climb",
                &json!({"seq": capped}),
            )
            .await;
        assert_eq!(
            (status, &stayed),
            (StatusCode::OK, &Value::Null),
            "{stayed}"
        );
        let (status, answered) = door
            .post_person(
                person,
                "vault.decisions.asks.answer",
                &json!({"seq": capped, "answer": {"kind": "noul", "value": true}}),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the capped ask is still its person's: {answered}"
        );
    });
}

/// dec-0006:45 "Every ask is one PROPOSAL, and it closes as one SETTLEMENT": the
/// same answer again answers the ask as it stands, and a different answer is
/// refused.
#[test]
fn an_ask_closes_as_one_settlement() {
    run_on_engine_stack("decisions-settlement", || async {
        let door = Door::open();
        let person = door.person();
        let seq = door
            .vault
            .queue_decision_ask(&request(
                person,
                responsible(person, RoleRank::Owner),
                "settles",
            ))
            .unwrap();

        let yes = json!({"seq": seq, "answer": {"kind": "noul", "value": true}});
        let (status, first) = door
            .post_person(person, "vault.decisions.asks.answer", &yes)
            .await;
        assert_eq!(status, StatusCode::OK, "{first}");
        assert_eq!(first["seq"], seq, "{first}");
        assert_eq!(
            first["answer"]["answer"],
            json!({"kind": "noul", "value": true}),
            "{first}"
        );
        assert_eq!(first["answer"]["by"], person.to_hex(), "{first}");

        let (status, again) = door
            .post_person(person, "vault.decisions.asks.answer", &yes)
            .await;
        assert_eq!(status, StatusCode::OK, "the same answer again: {again}");
        assert_eq!(
            again["answer"], first["answer"],
            "the settlement stands as it was"
        );

        let (status, refused) = door
            .post_person(
                person,
                "vault.decisions.asks.answer",
                &json!({"seq": seq, "answer": {"kind": "noul", "value": false}}),
            )
            .await;
        assert_eq!(
            refusal(status, &refused),
            (
                StatusCode::BAD_REQUEST,
                json!("BAD_REQUEST"),
                json!("decision ask already answered")
            ),
            "{refused}"
        );
    });
}

/// dec-0006:37 "A default policy row says who settles it": the owner's yes with
/// a reason drafts a standing grant, his confirm at the door makes it live, and
/// no one else's confirm settles it.
#[test]
fn a_drafted_grant_settles_on_the_owners_confirm() {
    run_on_engine_stack("decisions-grant", || async {
        let door = Door::open();
        let owner = door
            .vault
            .authenticate_owner(door.owner, "principal:owner", true, GateDecisionId::now())
            .unwrap();
        let bound = GrantBound::action(
            ActorBound::new("agent-a").unwrap(),
            ActionClass::new("send").unwrap(),
            ActionEnvelope::new(["channel:team".to_owned()]).unwrap(),
        )
        .unwrap();
        let effect = ComposedEffect::new(
            EffectFacts::new("channel.send")
                .unwrap()
                .with_external_observers(true),
        )
        .with_action_requirement(bound.clone())
        .unwrap();
        let consent = AskConsent::of(&effect, &bound).unwrap();
        let seq = door
            .vault
            .queue_decision_ask_with_consent(
                &request(door.owner, AskTo::owner(), "remember team sends"),
                None,
                &consent,
            )
            .unwrap();
        let answered = door
            .vault
            .answer_decision_ask_with_reason(
                &owner,
                seq,
                DecisionAnswer::Noul(true),
                Some("team only"),
            )
            .unwrap();
        let grant_ref = match &answered.answer.as_ref().unwrap().grant {
            Some(AskGrantDraft::Proposed { grant_ref }) => grant_ref.clone(),
            other => panic!("the owner's reason drafts a grant: {other:?}"),
        };
        assert!(
            !door
                .vault
                .consent_grant(&grant_ref)
                .ok()
                .flatten()
                .is_some_and(|row| row.is_active()),
            "a draft grants nothing"
        );

        let confirm = json!({"seq": seq, "notice": "Remembered for team sends"});
        let stranger = door.person();
        let (status, refused) = door
            .post_person(stranger, "vault.decisions.asks.confirm_grant", &confirm)
            .await;
        assert_eq!(
            refusal(status, &refused),
            (
                StatusCode::FORBIDDEN,
                json!("FORBIDDEN"),
                json!("vault.decisions.asks.confirm_grant is the vault owner's")
            ),
            "{refused}"
        );

        let (status, settled) = door
            .post_owner("vault.decisions.asks.confirm_grant", &confirm)
            .await;
        assert_eq!(status, StatusCode::OK, "{settled}");
        assert_eq!(
            settled["answer"]["grant"]["state"], "confirmed",
            "{settled}"
        );
        assert_eq!(
            settled["answer"]["grant"]["grant_ref"], grant_ref,
            "{settled}"
        );
        assert!(
            door.vault
                .consent_grant(&grant_ref)
                .unwrap()
                .is_some_and(|row| row.is_active()),
            "the confirmed grant is live"
        );
    });
}

/// arch-0076:275 "A learned decision-band mode and its version", within one host:
/// an unlearned band reads as its seed in shadow at version 0; a learned one
/// reads in shadow at its version until the owner enforces it; its version only
/// advances; and no band enforces before it is learned.
#[test]
fn a_learned_band_shadows_until_the_owner_enforces_it() {
    run_on_engine_stack("decisions-bands", || async {
        let door = Door::open();
        let asked = question_json(&question("band question"));
        let seed = json!({"low": 0.35, "high": 0.65});
        let band = json!({"low": 0.3, "high": 0.7});
        let read = json!({"question": asked, "reversibility": "reversible_read", "seed": seed});

        let (status, unlearned) = door.post_owner("vault.decisions.bands.read", &read).await;
        assert_eq!(status, StatusCode::OK, "{unlearned}");
        assert_eq!(
            unlearned,
            json!({"band": seed, "version": 0, "mode": "shadow"}),
            "{unlearned}"
        );

        let (status, refused) = door
            .post_owner(
                "vault.decisions.bands.enforce",
                &json!({"question": asked, "reversibility": "reversible_read"}),
            )
            .await;
        assert_eq!(
            refusal(status, &refused),
            (
                StatusCode::BAD_REQUEST,
                json!("BAD_REQUEST"),
                json!("band must be learned before enforcement")
            ),
            "{refused}"
        );

        let learn = json!({"question": asked, "reversibility": "reversible_read", "band": band, "version": 3});
        let (status, learned) = door.post_owner("vault.decisions.bands.learn", &learn).await;
        assert_eq!(status, StatusCode::OK, "{learned}");
        assert_eq!(
            learned,
            json!({"band": band, "version": 3, "mode": "shadow"}),
            "{learned}"
        );
        let (status, shadow) = door.post_owner("vault.decisions.bands.read", &read).await;
        assert_eq!((status, &shadow), (StatusCode::OK, &learned), "{shadow}");

        let (status, refused) = door.post_owner("vault.decisions.bands.learn", &learn).await;
        assert_eq!(
            refusal(status, &refused),
            (
                StatusCode::BAD_REQUEST,
                json!("BAD_REQUEST"),
                json!("learned band version must advance")
            ),
            "{refused}"
        );

        let (status, enforced) = door
            .post_owner(
                "vault.decisions.bands.enforce",
                &json!({"question": asked, "reversibility": "reversible_read"}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{enforced}");
        assert_eq!(
            enforced,
            json!({"band": band, "version": 3, "mode": "enforce"}),
            "{enforced}"
        );
        let (status, now) = door.post_owner("vault.decisions.bands.read", &read).await;
        assert_eq!((status, &now), (StatusCode::OK, &enforced), "{now}");
    });
}

/// Each of the six rows refuses a body with a field it does not know and a body
/// missing its fields, refuses any body with no credential, and refuses a
/// credential that is not its caller: the owner's root on the holder rows (it
/// names no person who holds a role), a person's slip on the owner's rows.
#[test]
fn a_malformed_unsigned_or_roleless_decisions_act_is_refused() {
    run_on_engine_stack("decisions-refusals", || async {
        let door = Door::open();
        let person = door.person();
        let stranger = door.person();
        let seq = door
            .vault
            .queue_decision_ask(&request(
                person,
                responsible(person, RoleRank::Owner),
                "refused",
            ))
            .unwrap();
        let asked = question_json(&question("refused band question"));
        let answer = json!({"seq": seq, "answer": {"kind": "noul", "value": true}});
        // (verb, a well-formed body, whether a role holder calls it.)
        let rows: [(&str, Value, bool); 6] = [
            ("vault.decisions.asks.answer", answer.clone(), true),
            ("vault.decisions.asks.climb", json!({"seq": seq}), true),
            (
                "vault.decisions.asks.confirm_grant",
                json!({"seq": seq, "notice": "Remembered"}),
                false,
            ),
            (
                "vault.decisions.bands.learn",
                json!({"question": asked, "reversibility": "reversible_read", "band": {"low": 0.3, "high": 0.7}, "version": 1}),
                false,
            ),
            (
                "vault.decisions.bands.enforce",
                json!({"question": asked, "reversibility": "reversible_read"}),
                false,
            ),
            (
                "vault.decisions.bands.read",
                json!({"question": asked, "reversibility": "reversible_read", "seed": {"low": 0.35, "high": 0.65}}),
                false,
            ),
        ];
        for (verb, body, holder_row) in &rows {
            let mut extra = body.clone();
            extra["unexpected"] = json!(1);
            for malformed in [extra, json!({})] {
                let (status, refused) = if *holder_row {
                    door.post_person(person, verb, &malformed).await
                } else {
                    door.post_owner(verb, &malformed).await
                };
                assert_eq!(
                    (status, &refused["error"]["code"]),
                    (StatusCode::BAD_REQUEST, &json!("BAD_REQUEST")),
                    "{verb} with {malformed}: {refused}"
                );
            }
            let (status, refused) = door.post_raw(verb, body.to_string(), None).await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "{verb} with no credential: {refused}"
            );
            let (status, refused) = if *holder_row {
                door.post_owner(verb, body).await
            } else {
                door.post_person(stranger, verb, body).await
            };
            assert_eq!(
                (status, &refused["error"]["code"]),
                (StatusCode::FORBIDDEN, &json!("FORBIDDEN")),
                "{verb} by a caller it does not take: {refused}"
            );
        }

        let (status, refused) = door
            .post_owner("vault.decisions.asks.answer", &answer)
            .await;
        assert_eq!(
            refusal(status, &refused),
            (
                StatusCode::FORBIDDEN,
                json!("FORBIDDEN"),
                json!(
                    "vault.decisions.asks.answer acts for a person or a bound agent that holds a role"
                )
            ),
            "{refused}"
        );
        let (status, refused) = door
            .post_person(stranger, "vault.decisions.asks.answer", &answer)
            .await;
        assert_eq!(
            refusal(status, &refused),
            (
                StatusCode::BAD_REQUEST,
                json!("BAD_REQUEST"),
                json!("the answerer does not hold the decision ask's role")
            ),
            "{refused}"
        );
        let (status, refused) = door
            .post_raw(
                "vault.decisions.asks.answer",
                "{not json".to_owned(),
                Some(door.person_credential(person)),
            )
            .await;
        assert_eq!(
            refused["error"]["message"], "invalid JSON request body",
            "{status}: {refused}"
        );

        // The refusals settled nothing: the ask is still its person's to answer.
        let (status, answered) = door
            .post_person(person, "vault.decisions.asks.answer", &answer)
            .await;
        assert_eq!(status, StatusCode::OK, "{answered}");
    });
}
