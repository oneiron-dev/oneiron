//! Promise tests for the `vault.shares.*` doors, entered at
//! `POST /v1/core/facade/<verb>`. Canon: ARCH-0032
//! (oneiron/core/oneiron-arch-0032-agentic-notes-v1.md) and ARCH-0050
//! (oneiron/code-in-oneiron/oneiron-arch-0050-repo-as-world.md).
//!
//! - ARCH-0032 :63 "Every share is a receipted op. The receipt records the
//!   content, the recipient and the redaction."
//! - ARCH-0032 :63 "Shares are revocable, revocation is itself receipted,
//!   and a revoked share stops resolving."
//! - ARCH-0032 :63 with `Vault::revoke_share` (FIX 1610): only the issuer or
//!   the vault's live owner stops a share, and a refused revoke never proves
//!   that a share exists.
//! - ARCH-0050 :187 "documents for KNOWN scoped principals": only the share's
//!   recipient sees it; the viewer is the caller, never a named field.
//! - ARCH-0032 :61 and :63 "A share's reach is one stored Scope, and view
//!   resolution is the one evaluator": each view re-resolves the live read
//!   policy, and a viewer's narrowing only takes away.
//! - ARCH-0050 :187 "re-resolved at view time, genuinely revocable": a view
//!   link is issued only for a live share, by its issuer or the owner.
//!
//! The fixture follows SURFACES-03 (tests/e2e/surfaces.test.ts): a research
//! NOTE, one owner claim about it, the person-stamped brief kind, a brief
//! citing the claim, and the owner's policy grants written at the policy door.

#![cfg(unix)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{
    AgentTier, CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof_challenge,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

/// The header every facade reply states its call receipt in.
const RECEIPT_REF_HEADER: &str = "x-oneiron-receipt-ref";

/// When the claim was said: 17 Oct 2026.
const OCCURRED_AT: u64 = 1_792_238_400;

/// The source NOTE's text.
const SOURCE_TEXT: &str = "The harbour pilot is Wren Halloway, who keeps the tide tables.";

/// The claim's value, a span of [`SOURCE_TEXT`] the brief cites.
const CLAIM_WORDS: &str = "Wren Halloway";

/// The brief's own sentence.
const BRIEF_WORDS: &str = "Ask the harbour pilot before the boats leave.";

/// The one refusal every refused revoke answers (`verbs/share.rs`).
const REVOKE_REFUSAL: &str = "vault.shares.revoke: share revocation requires issuer or owner";

/// The one refusal every refused view link answers (`share/view_link.rs`).
const LINK_REFUSAL: &str = "share link requires issuer or owner";

/// The share doors' refusal of a credential that names no principal
/// (`share_doors.rs` `principal`).
const NO_PRINCIPAL: &str = "acts as the credential's own principal";

/// One served vault, called by its owner on the host root.
struct Host {
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    slip: CapabilitySlip,
    token: String,
    owner: EntityId,
}

/// A caller on its own slip, signed by its own key.
struct Principal {
    id: EntityId,
    slip: CapabilitySlip,
    key: SigningKey,
}

/// Who sends a request.
#[derive(Clone, Copy)]
enum Caller<'a> {
    /// The host root slip: an owner-grade credential that names no principal.
    Root,
    As(&'a Principal),
}

/// One reply: its status, its JSON and the receipt its header states.
struct Reply {
    status: StatusCode,
    body: Value,
    receipt: Option<String>,
}

impl Reply {
    /// The body of a 200, or a failure naming the call and the reply.
    fn ok(self, call: &str) -> Value {
        assert_eq!(self.status, StatusCode::OK, "{call} answered {}", self.body);
        self.body
    }

    /// Asserts a 403 `FORBIDDEN` whose message holds `words`.
    fn forbidden(&self, call: &str, words: &str) {
        assert_eq!(
            self.status,
            StatusCode::FORBIDDEN,
            "{call} answered {}",
            self.body
        );
        assert_eq!(self.body["error"]["code"], "FORBIDDEN", "{call}");
        assert!(
            self.body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains(words)),
            "{call} must name `{words}`: {}",
            self.body
        );
    }

    /// The call receipt the reply's header names, which must be a stored one.
    fn call_receipt(&self, call: &str) -> String {
        let receipt = self
            .receipt
            .clone()
            .unwrap_or_else(|| panic!("{call} states no {RECEIPT_REF_HEADER}"));
        assert!(
            receipt.starts_with("call:"),
            "{call} states the receipt {receipt:?}, not a stored call receipt"
        );
        receipt
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A policy scope with every axis open.
fn top_scope() -> Value {
    json!({
        "worlds": {"kind": "all"}, "facets": {"kind": "all"}, "bands": {"kind": "all"},
        "audience": {"kind": "all"}, "verbs": {"kind": "all"}, "sensitivity": {"kind": "all"}
    })
}

/// A `core:read` grant to `agent` over one band, as SURFACES-03's `noteRead`
/// (band 111, NOTE rows) and `claimRead` (band 0, claim rows).
fn read_grant(agent: &EntityId, band: u64) -> Value {
    let mut scope = top_scope();
    scope["bands"] = json!({"kind": "some", "values": [band]});
    scope["verbs"] = json!({"kind": "some", "values": ["read"]});
    json!({
        "actor_class": "agent", "actor_ref": agent.to_hex(), "effector": "core:read",
        "receipt_required": false, "scope": scope
    })
}

impl Host {
    fn new(path: &Path) -> Self {
        let vault = Arc::new(Vault::open(path, VaultConfig::device()).expect("open fresh vault"));
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        let server = Arc::new(
            SyncServer::new(
                Arc::clone(&vault),
                SyncServerConfig {
                    auth_secret: Some("vault-shares-doors".into()),
                    ..Default::default()
                },
            )
            .expect("create the vault's server"),
        );
        let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
        let slip = vault
            .ensure_host_root_slip(&issuer)
            .expect("owner root slip");
        let token = slip.to_token().expect("owner slip token");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's live machine profile");
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        Self {
            vault,
            app: build_app(server),
            issuer,
            slip,
            token,
            owner,
        }
    }

    /// `caller`'s call to `verb` at its facade route.
    async fn send(&self, caller: Caller<'_>, verb: &str, input: &Value) -> Reply {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let (token, signature) = match caller {
            Caller::Root => (
                self.token.clone(),
                hex(&self
                    .issuer
                    .binding_proof(&self.slip, &challenge)
                    .expect("owner holder proof")),
            ),
            Caller::As(principal) => (
                principal.slip.to_token().expect("caller slip token"),
                hex(&principal
                    .key
                    .sign(
                        &principal
                            .slip
                            .binding_transcript(&challenge)
                            .expect("caller binding transcript"),
                    )
                    .to_bytes()),
            ),
        };
        let request = Request::post(format!("/v1/core/facade/{verb}"))
            .header("authorization", format!("Bearer {token}"))
            .header(
                "x-oneiron-binding",
                json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string(),
            )
            .header("content-type", "application/json")
            .body(Body::from(input.to_string()))
            .expect("facade request");
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("the app's response");
        let status = response.status();
        let receipt = response
            .headers()
            .get(RECEIPT_REF_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("the response body");
        let body = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
            panic!(
                "{verb} answered no JSON: {}",
                String::from_utf8_lossy(&bytes)
            )
        });
        Reply {
            status,
            body,
            receipt,
        }
    }

    /// The host root's call to `verb`, which must answer 200.
    async fn root_ok(&self, verb: &str, input: Value) -> Value {
        self.send(Caller::Root, verb, &input).await.ok(verb)
    }

    /// The scope a fresh vault's own claims take: base reality, the owner's
    /// substrate facet, every relationship and the default project
    /// (tests/e2e/support/fixtures.ts `ownerBaseClaimScope`).
    async fn base_claim_scope(&self) -> Value {
        let facets = self
            .root_ok(
                "vault.neighbors",
                json!({
                    "entity_ref": self.owner.to_hex(),
                    "opts": {"edge_kind": "has_facet", "limit": 100}
                }),
            )
            .await;
        for facet in facets["value"].as_array().expect("the owner's facets") {
            let read = self
                .root_ok("vault.get", json!({"entity_ref": facet["short_id"]}))
                .await;
            let row = &read["value"];
            if row["kind"] == "FACET" && row["body"]["kind"] == "substrate" {
                return json!({
                    "world_id": "00000000000000000000000000000001",
                    "scope_facet_id": row["id_hex"],
                    "scope_relationship_id": "all",
                    "scope_project_id": "00000000000000000000000000000002"
                });
            }
        }
        panic!("a fresh vault has no readable owner substrate facet: {facets}");
    }

    /// The default policy manifest's row.
    async fn default_policy(&self) -> Value {
        let policy = self.root_ok("vault.gate.policy.get", json!({})).await;
        policy["manifests"]
            .as_array()
            .expect("policy manifests")
            .iter()
            .find(|row| row["manifest_ref"] == policy["default_manifest_ref"])
            .cloned()
            .expect("the default policy manifest")
    }

    /// Sets the default policy's scoped grants to `grants` at the policy door
    /// (SURFACES-03's `setGrants`), and reads them back.
    async fn set_grants(&self, grants: Vec<Value>) {
        let row = self.default_policy().await;
        let count = grants.len();
        let mut manifest = row["manifest"].clone();
        manifest["scoped_grants"] = Value::Array(grants);
        let written = self
            .root_ok(
                "vault.gate.policy.put",
                json!({
                    "manifest_ref": row["manifest_ref"],
                    "expected_body_hash": row["body_hash"],
                    "manifest": manifest
                }),
            )
            .await;
        assert!(
            written["receipt_ref"]
                .as_str()
                .is_some_and(|receipt| !receipt.is_empty()),
            "the policy write's receipt: {written}"
        );
        let saved = self.default_policy().await;
        assert_eq!(
            saved["manifest"]["scoped_grants"].as_array().map(Vec::len),
            Some(count),
            "the policy readback: {saved}"
        );
    }

    /// A PERSON this vault knows.
    fn person(&self, name: &str) -> EntityId {
        let id = EntityId::now();
        let now = self.vault.now_recorded_at();
        let mut body = Vec::new();
        rmpv::encode::write_value(
            &mut body,
            &rmpv::Value::Map(vec![(rmpv::Value::from("name"), rmpv::Value::from(name))]),
        )
        .expect("the person's PERSON body");
        self.vault
            .put_entity(
                &id,
                ENTITY_TYPE_PERSON,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                &body,
            )
            .expect("the person's PERSON row");
        id
    }

    /// `holder`'s own read-and-write slip as a `class` caller, signed by the
    /// key `seed` makes.
    fn principal(&self, holder: EntityId, class: &str, seed: u8) -> Principal {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let mut claims = self.slip.claims.clone();
        claims.parent_id = None;
        claims.holder_ref = holder.to_hex();
        claims.binding_key = key.verifying_key().to_bytes();
        claims.actor_class = Some(class.to_owned());
        claims.scope = Scope::top();
        claims.scope.verbs = ScopeAxis::Some(
            ["core:read", "core:write"]
                .iter()
                .map(|verb| (*verb).to_owned())
                .collect(),
        );
        claims.slip_id = [seed; 32];
        let slip = self
            .vault
            .mint_capability_slip(&self.issuer, claims)
            .expect("mint the caller's slip");
        Principal {
            id: holder,
            slip,
            key,
        }
    }

    /// The vault's own agent `name`, bound with full access, on its own slip.
    fn agent(&self, name: &str, seed: u8) -> Principal {
        let agent = self
            .vault
            .ensure_agent_principal(name)
            .expect("the vault's own agent");
        let owner = self
            .vault
            .authenticate_owner(
                self.owner,
                &self.owner.to_hex(),
                true,
                GateDecisionId::now(),
            )
            .expect("the owner's proof");
        self.vault
            .bind_and_grant_agent_principal(
                &self.issuer,
                &owner,
                agent,
                AgentTier::FullAccess.ceiling(),
            )
            .expect("bind the vault's own agent");
        self.principal(agent, "agent", seed)
    }

    /// `caller`'s stored call receipt `receipt`, read again for a while: the
    /// row commits with the vault's group commit after the reply.
    async fn receipt_soon(&self, caller: Caller<'_>, receipt: &str) -> Value {
        let input = json!({"receipt_ref": receipt});
        for _ in 0..50 {
            let row = self
                .send(caller, "vault.receipts.get", &input)
                .await
                .ok("vault.receipts.get");
            if !row.is_null() {
                return row;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("the call receipt {receipt} never reads back");
    }
}

/// One vault with a brief ready to share: the owner on a human slip of its
/// own, the recipient (one of the vault's own agents), a stranger PERSON, the
/// source NOTE, the claim the brief cites and the brief.
struct Shared {
    _dir: tempfile::TempDir,
    host: Host,
    owner: Principal,
    recipient: Principal,
    stranger: Principal,
    claim: String,
    brief: String,
    scope: Value,
    /// The default policy's scoped grants before the test wrote any.
    original: Vec<Value>,
}

impl Shared {
    async fn new() -> Self {
        let dir = tempfile::tempdir().expect("a fresh vault directory");
        let host = Host::new(dir.path());
        let owner = host.principal(host.owner, "human", 0x61);
        let recipient = host.agent("share-recipient", 0x62);
        let olu = host.person("Olu");
        let stranger = host.principal(olu, "human", 0x63);
        let me = Caller::As(&owner);

        let source = host
            .send(
                me,
                "vault.notes.create",
                &json!({"kind": "research", "markdown": SOURCE_TEXT}),
            )
            .await
            .ok("vault.notes.create");
        let source = source["id_hex"].as_str().expect("the NOTE's id").to_owned();
        let scope = host.base_claim_scope().await;
        let written = host
            .send(
                me,
                "vault.claims.upsert",
                &json!({
                    "scope": scope, "subject_ref": source, "predicate": "identity.name",
                    "value": CLAIM_WORDS, "source": "user_stated", "confidence": 1,
                    "occurred_at": OCCURRED_AT
                }),
            )
            .await
            .ok("vault.claims.upsert");
        assert_eq!(written["approval"], "auto", "{written}");
        let claim = written["claim"]["id"]
            .as_str()
            .expect("the claim's id")
            .to_owned();
        let stamp = host
            .send(me, "vault.notes.bless_brief_kind", &json!({}))
            .await
            .ok("vault.notes.bless_brief_kind");
        assert_eq!(stamp["person_ref"], host.owner.to_hex(), "{stamp}");
        let start = SOURCE_TEXT
            .find(CLAIM_WORDS)
            .expect("the claim is a span of the source");
        let brief = host
            .send(
                me,
                "vault.notes.author_brief",
                &json!({
                    "markdown": format!("# Harbour brief\n\n{BRIEF_WORDS}"),
                    "citations": [{
                        "claim_ref": claim, "document_ref": source,
                        "start": start, "end": start + CLAIM_WORDS.len()
                    }]
                }),
            )
            .await
            .ok("vault.notes.author_brief");
        let brief = brief["id_hex"].as_str().expect("the brief's id").to_owned();
        let original = host.default_policy().await["manifest"]["scoped_grants"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let shared = Self {
            _dir: dir,
            host,
            owner,
            recipient,
            stranger,
            claim,
            brief,
            scope,
            original,
        };
        shared.grant(false).await;
        shared
    }

    /// The default policy's own grants, the owner's standing grant to share
    /// briefs and the recipient's read of NOTE rows; with `claims`, the
    /// recipient's read of claim rows too (SURFACES-03's `ownerShare`,
    /// `noteRead` and `claimRead`).
    async fn grant(&self, claims: bool) {
        let mut grants = self.original.clone();
        grants.push(json!({
            "actor_class": "human", "actor_ref": self.host.owner.to_hex(),
            "effector": "share_brief", "scope": top_scope(), "receipt_required": true
        }));
        grants.push(read_grant(&self.recipient.id, 111));
        if claims {
            grants.push(read_grant(&self.recipient.id, 0));
        }
        self.host.set_grants(grants).await;
    }

    /// The owner's share of the brief with the recipient, over the claim's
    /// world and facet.
    async fn create(&self) -> Reply {
        let input = json!({
            "recipient": self.recipient.id.to_hex(), "brief_ref": self.brief,
            "world_refs": [self.scope["world_id"]], "facet_refs": [self.scope["scope_facet_id"]],
            "include_unscoped": true, "travel": {"born_with": []}
        });
        self.host
            .send(Caller::As(&self.owner), "vault.shares.create", &input)
            .await
    }

    /// The id of a new share.
    async fn share(&self) -> String {
        let created = self.create().await.ok("vault.shares.create");
        created["share_id"]
            .as_str()
            .expect("the share's id")
            .to_owned()
    }

    /// `caller`'s view of `share`, narrowed by `narrowing` if given.
    async fn view(&self, caller: Caller<'_>, share: &str, narrowing: Option<Value>) -> Reply {
        let mut input = json!({"share_ref": share});
        if let Some(narrowing) = narrowing {
            input["narrowing"] = narrowing;
        }
        self.host.send(caller, "vault.shares.view", &input).await
    }

    /// The recipient's view of `share`, which must render, and its one citation.
    async fn rendered(&self, share: &str, narrowing: Option<Value>, call: &str) -> (Value, Value) {
        let view = self
            .view(Caller::As(&self.recipient), share, narrowing)
            .await
            .ok(call);
        let value = view["value"].clone();
        assert_eq!(value["share_ref"], share, "{call}: {view}");
        let citations = value["citations"].as_array().expect("the view's citations");
        assert_eq!(citations.len(), 1, "{call}: {view}");
        let citation = citations[0].clone();
        (value, citation)
    }

    /// `caller`'s revoke of `share`.
    async fn revoke(&self, caller: Caller<'_>, share: &str) -> Reply {
        self.host
            .send(caller, "vault.shares.revoke", &json!({"share_ref": share}))
            .await
    }

    /// `caller`'s view link for `share`'s recipient.
    async fn link(&self, caller: Caller<'_>, share: &str) -> Reply {
        self.host
            .send(
                caller,
                "vault.shares.issue_view_link",
                &json!({"share_ref": share, "actor_class": "agent", "slip_lifetime_secs": 3600}),
            )
            .await
    }
}

/// Asserts `citation` hides its claim: the fixed placeholder, no quote,
/// confidence or lifecycle (SURFACES-03's `redacted`).
fn assert_redacted(citation: &Value, claim: &str, call: &str) {
    assert_eq!(citation["redacted"], true, "{call}: {citation}");
    assert_ne!(
        citation["claim_ref"], claim,
        "{call} names the claim: {citation}"
    );
    assert_eq!(
        (
            &citation["quote"],
            &citation["confidence"],
            &citation["lifecycle"]
        ),
        (&Value::Null, &Value::Null, &Value::Null),
        "{call}: {citation}"
    );
    assert_eq!(citation["stale"], false, "{call}: {citation}");
    assert_eq!(citation["drifted"], false, "{call}: {citation}");
}

/// ARCH-0032 :63: "Every share is a receipted op. The receipt records the
/// content, the recipient and the redaction." The create answers the share it
/// admitted, and its reply names a stored call receipt that reads back as the
/// owner's `vault.shares.create`, with the request's digest.
#[test]
fn every_share_is_a_receipted_op_naming_its_recipient() {
    run_on_engine_stack("shares-doors-receipted", || async {
        let s = Shared::new().await;
        let created = s.create().await;
        let receipt = created.call_receipt("vault.shares.create");
        let body = created.ok("vault.shares.create");
        assert_eq!(body["recipient"], s.recipient.id.to_hex(), "{body}");
        assert_eq!(body["brief_ref"], s.brief, "{body}");
        assert_eq!(body["travel"], json!({"born_with": []}), "{body}");
        assert!(
            body["created_at"].as_u64().is_some_and(|at| at > 0),
            "{body}"
        );
        let share = body["share_id"].as_str().expect("the share's id");
        assert_eq!(share.len(), 32, "{body}");

        let row = s.host.receipt_soon(Caller::As(&s.owner), &receipt).await;
        assert_eq!(row["receipt_ref"], receipt, "{row}");
        assert_eq!(
            row["verb"]
                .as_str()
                .and_then(|verb| verb.rsplit('/').next()),
            Some("vault.shares.create"),
            "{row}"
        );
        assert_eq!(row["actor_ref"], s.host.owner.to_hex(), "{row}");
        assert_eq!(row["actor_class"], "human", "{row}");
        assert_eq!(row["outcome"], "ok", "{row}");
        assert!(
            row["request_digest"]
                .as_str()
                .is_some_and(|digest| !digest.is_empty()),
            "{row}"
        );

        s.rendered(share, None, "the recipient's view").await;
    });
}

/// ARCH-0032 :63: "Shares are revocable, revocation is itself receipted, and
/// a revoked share stops resolving." After the owner's revoke, the recipient's
/// view and a saved citation answer nothing; a second revoke answers the first
/// receipt unchanged.
#[test]
fn a_revoked_share_stops_resolving_and_its_revoke_is_receipted() {
    run_on_engine_stack("shares-doors-revoked", || async {
        let s = Shared::new().await;
        let share = s.share().await;
        s.rendered(&share, None, "the view before the revoke").await;

        let revoke = s.revoke(Caller::As(&s.owner), &share).await;
        let receipt = revoke.call_receipt("vault.shares.revoke");
        let revoked = revoke.ok("vault.shares.revoke");
        assert_eq!(revoked["share_ref"], share, "{revoked}");
        assert_eq!(revoked["status"], "revoked", "{revoked}");
        assert!(revoked["revoked_at"].as_u64().is_some(), "{revoked}");
        let row = s.host.receipt_soon(Caller::As(&s.owner), &receipt).await;
        assert_eq!(
            row["verb"]
                .as_str()
                .and_then(|verb| verb.rsplit('/').next()),
            Some("vault.shares.revoke"),
            "{row}"
        );
        assert_eq!(row["outcome"], "ok", "{row}");

        let after = s
            .view(Caller::As(&s.recipient), &share, None)
            .await
            .ok("the view after the revoke");
        assert!(
            after["value"].is_null(),
            "a revoked share still resolves: {after}"
        );
        let follow = s
            .host
            .send(
                Caller::As(&s.recipient),
                "vault.notes.follow_citation",
                &json!({"share_ref": share, "claim_ref": s.claim}),
            )
            .await
            .ok("the saved citation after the revoke");
        assert!(
            follow["value"].is_null(),
            "a revoked share's citation still resolves: {follow}"
        );

        let again = s
            .revoke(Caller::As(&s.owner), &share)
            .await
            .ok("the second revoke");
        assert_eq!(again, revoked, "a second revoke answers the first receipt");
    });
}

/// ARCH-0032 :63 ("Shares are revocable") as `Vault::revoke_share` keeps it
/// (FIX 1610): only the issuer or the vault's live owner stops a share. The
/// recipient and a stranger are refused with the one refusal a missing share
/// gets too, so a refusal proves nothing; a credential naming no principal is
/// refused before the engine; the share still resolves until its issuer stops it.
#[test]
fn only_the_issuer_or_the_owner_stops_a_share_and_a_refusal_proves_nothing() {
    run_on_engine_stack("shares-doors-who-stops", || async {
        let s = Shared::new().await;
        let share = s.share().await;

        let by_recipient = s.revoke(Caller::As(&s.recipient), &share).await;
        by_recipient.forbidden("the recipient's revoke", REVOKE_REFUSAL);
        assert_eq!(by_recipient.body["error"]["message"], REVOKE_REFUSAL);
        let by_stranger = s.revoke(Caller::As(&s.stranger), &share).await;
        by_stranger.forbidden("a stranger's revoke", REVOKE_REFUSAL);
        let missing = EntityId::now().to_hex();
        let of_nothing = s.revoke(Caller::As(&s.recipient), &missing).await;
        of_nothing.forbidden("a revoke of no share", REVOKE_REFUSAL);
        assert_eq!(
            (
                &of_nothing.body["error"]["message"],
                &of_nothing.body["error"]["suggestions"]
            ),
            (
                &by_recipient.body["error"]["message"],
                &by_recipient.body["error"]["suggestions"]
            ),
            "a refused revoke tells a missing share from a live one"
        );
        s.revoke(Caller::Root, &share)
            .await
            .forbidden("the host root's revoke", NO_PRINCIPAL);

        s.rendered(&share, None, "the view after the refused revokes")
            .await;
        let revoked = s
            .revoke(Caller::As(&s.owner), &share)
            .await
            .ok("the issuer's revoke");
        assert_eq!(revoked["status"], "revoked", "{revoked}");
    });
}

/// ARCH-0050 :187: shares are "documents for KNOWN scoped principals". Only
/// the recipient sees the share: a stranger and the issuer itself read
/// nothing, and a credential naming no principal is refused.
#[test]
fn only_the_recipient_sees_a_share() {
    run_on_engine_stack("shares-doors-recipient", || async {
        let s = Shared::new().await;
        let share = s.share().await;

        let by_stranger = s
            .view(Caller::As(&s.stranger), &share, None)
            .await
            .ok("a stranger's view");
        assert!(
            by_stranger["value"].is_null(),
            "a stranger sees the share: {by_stranger}"
        );
        let by_issuer = s
            .view(Caller::As(&s.owner), &share, None)
            .await
            .ok("the issuer's view");
        assert!(
            by_issuer["value"].is_null(),
            "the issuer sees the recipient's share: {by_issuer}"
        );
        let follow = s
            .host
            .send(
                Caller::As(&s.stranger),
                "vault.notes.follow_citation",
                &json!({"share_ref": share, "claim_ref": s.claim}),
            )
            .await
            .ok("a stranger's citation follow");
        assert!(
            follow["value"].is_null(),
            "a stranger follows the share's citation: {follow}"
        );
        s.view(Caller::Root, &share, None)
            .await
            .forbidden("the host root's view", NO_PRINCIPAL);

        s.rendered(&share, None, "the recipient's view").await;
    });
}

/// ARCH-0032 :61 ("Claim refs resolve while the reader looks") and :63 ("A
/// share's reach is one stored Scope, and view resolution is the one
/// evaluator"), with `resolve_share_for_view`'s "the stored maximum intersects
/// live core:read policy, never a cached view": the same share shows its claim
/// redacted, then in full once the owner grants the recipient the claim read,
/// and a viewer's narrowing only takes away.
#[test]
fn a_view_re_resolves_live_read_policy_and_narrowing_only_takes_away() {
    run_on_engine_stack("shares-doors-narrowing", || async {
        let s = Shared::new().await;
        let share = s.share().await;

        let (_, citation) = s
            .rendered(&share, None, "the view without the claim read")
            .await;
        assert_redacted(&citation, &s.claim, "the view without the claim read");

        s.grant(true).await;
        let (value, citation) = s
            .rendered(&share, None, "the view with the claim read")
            .await;
        assert_eq!(citation["claim_ref"], s.claim, "{citation}");
        assert_eq!(citation["redacted"], false, "{citation}");
        assert_eq!(citation["quote"], CLAIM_WORDS, "{citation}");
        assert_eq!(citation["lifecycle"], "active", "{citation}");
        assert_eq!(citation["confidence"].as_f64(), Some(1.0), "{citation}");
        assert_eq!(citation["drifted"], false, "{citation}");
        assert!(
            value["html"]
                .as_str()
                .is_some_and(|html| html.contains(BRIEF_WORDS)),
            "the view renders the brief: {value}"
        );

        let narrowed = json!({"world_refs": [], "facet_refs": [], "include_unscoped": false});
        let (_, citation) = s
            .rendered(&share, Some(narrowed), "the view narrowed to nothing")
            .await;
        assert_redacted(&citation, &s.claim, "the view narrowed to nothing");

        let whole = json!({
            "world_refs": [s.scope["world_id"]], "facet_refs": [s.scope["scope_facet_id"]],
            "include_unscoped": true
        });
        let (_, same) = s
            .rendered(
                &share,
                Some(whole),
                "the view narrowed to the share's own scope",
            )
            .await;
        assert_eq!(
            same["claim_ref"], s.claim,
            "a narrowing to the share's own scope took away: {same}"
        );
        assert_eq!(same["quote"], CLAIM_WORDS, "{same}");
    });
}

/// ARCH-0050 :187: shares are "re-resolved at view time, genuinely
/// revocable", and a view link is "one-use link for the live share's own
/// recipient" (`slip_pairing/issue.rs`). The issuer gets a link for a live
/// share; the recipient gets none, and nobody gets one once the share is revoked.
#[test]
fn a_view_link_is_issued_only_for_a_live_share_by_its_issuer() {
    run_on_engine_stack("shares-doors-view-link", || async {
        let s = Shared::new().await;
        let share = s.share().await;

        let link = s
            .link(Caller::As(&s.owner), &share)
            .await
            .ok("the issuer's view link");
        assert!(
            link["code"].as_str().is_some_and(|code| !code.is_empty()),
            "{link}"
        );
        assert!(
            link["expires_at"].as_u64().is_some_and(|at| at > 0),
            "{link}"
        );

        let refused = |reply: &Reply, call: &str| {
            assert!(
                matches!(
                    reply.status,
                    StatusCode::BAD_REQUEST | StatusCode::FORBIDDEN
                ),
                "{call} answered {} {}",
                reply.status,
                reply.body
            );
            assert!(
                reply.body["error"]["message"]
                    .as_str()
                    .is_some_and(|message| message.contains(LINK_REFUSAL)),
                "{call} must name `{LINK_REFUSAL}`: {}",
                reply.body
            );
        };
        let by_recipient = s.link(Caller::As(&s.recipient), &share).await;
        refused(&by_recipient, "the recipient's view link");

        s.revoke(Caller::As(&s.owner), &share)
            .await
            .ok("the issuer's revoke");
        let after = s.link(Caller::As(&s.owner), &share).await;
        refused(&after, "the issuer's view link after the revoke");
    });
}
