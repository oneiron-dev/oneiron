//! The owner's field editor saves its fields to a draft (ARCH-0064 SGN-07; RULING
//! ESIGN-EDITOR-SAVES-DRAFT = A, Engine 15 Nov 13:48). The editor shell mints its owner-grade
//! caller a draft-fields token beside its computation token. `POST /sign/fields` admits that
//! token alone and runs `vault.esign.fields.place` through the verb door as the token's caller,
//! whose credential it re-checks live. Every row drives the real router built by
//! `oneiron_server::build_app` over a rooted vault and the owner's own exact top slip, which is
//! owner-grade and revocable by itself:
//! - the fields token places a draft's fields, as the owner;
//! - the computation token, and no token, are refused at the fields door;
//! - the fields token is refused at the editor's computation doors, the ceremony and the facade;
//! - a sent document keeps its fields;
//! - a revoked caller places nothing.
//!
//! The draft is the vault's own row, so this file builds at the base, where the shell mints one
//! token and no `/sign/fields` route exists, and every row fails there by its asserts.
//! Run with `cargo test --locked -p oneiron-server --all-features --features oneiron/test-support
//! --test esign_editor_draft_fields`.

// Integration-test helpers (non-`#[test]` fns) are not covered by
// allow-unwrap-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use ed25519_dalek::SigningKey;
use engine_stack::run_on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, holder_proof};
use oneiron::blob_artifact::esign::{
    DocumentKind, DocumentStatus, EsignAuditActor, EsignDocument, EsignEvent, EsignField,
    EsignItem, EsignRecipient, FieldGeometry, FieldMeta, RecipientRole,
};
use oneiron::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

const SECRET: &str = "esign-editor-draft-fields";
const EDITOR_HEADER: &str = "x-oneiron-esign-editor";
const DAY: u64 = 86_400;

fn original_pdf() -> &'static [u8] {
    include_bytes!("../../oneiron-seal/tests/fixtures/pdf-input/classic_1page.pdf")
}

/// The key the owner's slip binds; the holder proves it per request.
fn holder_key() -> SigningKey {
    SigningKey::from_bytes(&[0x5E; 32])
}

/// `recipient`'s signature field `id` on the first page of the only item, at `geometry`.
fn signature_field(id: &str, recipient: &str, geometry: [f64; 4]) -> EsignField {
    let [x_percent, y_percent, width_percent, height_percent] = geometry;
    EsignField {
        id: id.into(),
        item: 0,
        recipient: recipient.into(),
        required: true,
        geometry: FieldGeometry {
            page: 1,
            x_percent,
            y_percent,
            width_percent,
            height_percent,
        },
        meta: FieldMeta::Signature,
    }
}

/// The token the editor page carries in the meta tag `id`, if it carries that tag.
fn meta_token(page: &str, id: &str) -> Option<String> {
    let tag = &page[page.find(&format!("<meta id={id} "))?..];
    let content = &tag[tag.find("content=\"")? + "content=\"".len()..];
    Some(content[..content.find('"')?].to_owned())
}

/// A rooted server whose embedded owner drafted a one-signer document on an uploaded one-page
/// PDF, with one signature field near the top left, and the owner's own exact top slip.
struct Editor {
    _dir: tempfile::TempDir,
    app: Router,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    owner: EntityId,
    slip: CapabilitySlip,
    document: EntityId,
    recipient: String,
    drafted: EsignField,
}

fn editor() -> Editor {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("vault"));
    // `oneiron serve` installs the install's keystore at open; the server roots the vault
    // with the issuer it holds.
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some(SECRET.to_owned()),
                ..Default::default()
            },
        )
        .expect("a server"),
    );
    let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
    assert!(
        vault
            .authority_vault_id()
            .expect("authority fold")
            .is_some(),
        "the server rooted its vault"
    );
    let owner = vault.ensure_embedded_owner_actor().expect("owner");

    // The owner's own slip, cut whole from the root: owner-grade, and revoked by its own id.
    let mut claims = vault
        .ensure_host_root_slip(&issuer)
        .expect("the host root slip")
        .claims;
    claims.slip_id = [0x5E; 32];
    claims.parent_id = None;
    claims.holder_ref = owner.to_hex();
    claims.actor_class = Some("human".to_owned());
    claims.binding_key = holder_key().verifying_key().to_bytes();
    let slip = vault
        .mint_capability_slip(&issuer, claims)
        .expect("the owner's slip");

    let at = TimeRange { start: 1, end: 1 };
    let document = EntityId::now();
    vault
        .put_blob_artifact(
            &document,
            &BlobArtifactBody::new("agreement.pdf", "application/pdf"),
            at,
            1,
        )
        .expect("store the signing PDF artifact");
    vault
        .append_blob_artifact_version(
            &document,
            original_pdf(),
            &BlobVersionProvenance::UserUpload,
            WriteActor::new(owner, EdgeActorClass::Human),
            at,
            1,
        )
        .expect("append the signing PDF version");
    let now = vault.now_recorded_at();
    let recipient = EntityId::now().to_hex();
    let drafted = signature_field(
        &EntityId::now().to_hex(),
        &recipient,
        [10.0, 10.0, 30.0, 8.0],
    );
    let draft = EsignDocument {
        schema_version: 1,
        kind: DocumentKind::Document,
        title: "Agreement".into(),
        sequential: false,
        expires_at: now + 90 * DAY,
        token_expires_at: None,
        items: vec![EsignItem {
            artifact_ref: document.to_hex(),
            original_version: 1,
        }],
        recipients: vec![EsignRecipient {
            id: recipient.clone(),
            email: "owen@example.com".into(),
            name: "Owen".into(),
            role: RecipientRole::Signer,
            order: 0,
            expires_at: now + 90 * DAY,
            principal_ref: None,
            automated: false,
            natural_person: None,
        }],
        fields: vec![drafted.clone()],
        full_trail_appendix: true,
        lifecycle: None,
        project: None,
        commitments: Vec::new(),
    };
    vault
        .create_esign_document(document, &draft, owner_actor(owner), now)
        .expect("draft the signing document");
    Editor {
        _dir: dir,
        app: build_app(server),
        vault,
        issuer,
        owner,
        slip,
        document,
        recipient,
        drafted,
    }
}

fn owner_actor(owner: EntityId) -> EsignAuditActor {
    EsignAuditActor {
        actor: owner.to_hex(),
        ip: None,
        user_agent: None,
    }
}

impl Editor {
    /// The tokens the editor shell mints the owner's slip: its computation token, and its
    /// draft-fields token when the page carries one.
    async fn tokens(&self) -> (String, Option<String>) {
        let binding = holder_proof(&self.slip, &holder_key(), self.vault.now_recorded_at())
            .expect("holder proof");
        let response = self
            .app
            .clone()
            .oneshot(
                Request::get("/sign/editor")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {}", self.slip.to_token().expect("token")),
                    )
                    .header("x-oneiron-binding", binding.to_string())
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "the owner's slip opens the editor shell"
        );
        let page = to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("page body");
        let page = String::from_utf8(page.to_vec()).expect("page text");
        let computation =
            meta_token(&page, "editor-capability").expect("the shell's computation token");
        (computation, meta_token(&page, "editor-fields-capability"))
    }

    /// The draft-fields token the editor shell mints the owner's slip.
    async fn fields_token(&self) -> String {
        let (_, fields) = self.tokens().await;
        assert!(
            fields.is_some(),
            "the shell carries a draft-fields token beside its computation token"
        );
        fields.expect("a draft-fields token")
    }

    /// One POST through the router with `headers` and `body`: its status and JSON body.
    async fn post(
        &self,
        path: &str,
        content_type: &str,
        headers: &[(&str, &str)],
        body: Vec<u8>,
    ) -> (StatusCode, Value) {
        let mut request = Request::post(path).header(header::CONTENT_TYPE, content_type);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = self
            .app
            .clone()
            .oneshot(request.body(Body::from(body)).expect("request"))
            .await
            .expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("response body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// The input `vault.esign.fields.place` takes for this document and `fields`.
    fn placement(&self, fields: &[EsignField]) -> Vec<u8> {
        json!({
            "document_ref": self.document.to_hex(),
            "fields": serde_json::to_value(fields).expect("fields"),
        })
        .to_string()
        .into_bytes()
    }

    /// `POST /sign/fields` of `fields`, under the editor `token` when there is one.
    async fn place(&self, token: Option<&str>, fields: &[EsignField]) -> (StatusCode, Value) {
        let headers: Vec<(&str, &str)> = token
            .map(|token| (EDITOR_HEADER, token))
            .into_iter()
            .collect();
        self.post(
            "/sign/fields",
            "application/json",
            &headers,
            self.placement(fields),
        )
        .await
    }

    /// The signature field moved to the lower right, as the editor exports it.
    fn moved(&self) -> EsignField {
        signature_field(&self.drafted.id, &self.recipient, [55.0, 70.0, 30.0, 8.0])
    }

    /// The fields the draft holds now.
    fn fields(&self) -> Vec<EsignField> {
        self.vault
            .esign_document(self.document)
            .expect("the signing document")
            .document
            .fields
    }
}

fn code(body: &Value) -> Option<&str> {
    body["error"]["code"].as_str()
}

#[test]
fn the_fields_token_places_the_drafts_fields_as_its_caller() {
    run_on_engine_stack("esign-editor-fields-place", || async {
        let editor = editor();
        let token = editor.fields_token().await;
        let moved = editor.moved();
        let (status, answer) = editor
            .place(Some(token.as_str()), std::slice::from_ref(&moved))
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the fields token places the draft's fields: {answer}"
        );
        assert_eq!(
            answer["status"], "draft",
            "the document stays a draft: {answer}"
        );
        assert_eq!(
            answer["fields"], 1,
            "the draft places the one field: {answer}"
        );
        assert_eq!(
            editor.fields(),
            [moved.clone()],
            "the draft holds the placed field in place of its own"
        );
        let audit = editor.vault.esign_audit(editor.document).expect("audit");
        let last = audit.last().expect("a trail event");
        let EsignEvent::Drafted { document: redraft } = &last.event else {
            panic!("the placement lands as a redraft: {:?}", last.event);
        };
        assert_eq!(
            redraft.fields,
            [moved],
            "the redraft holds the placed field"
        );
        assert_eq!(
            last.actor.actor,
            editor.owner.to_hex(),
            "the redraft names the token's caller, the owner"
        );
    });
}

#[test]
fn the_computation_token_and_no_token_are_refused_at_the_fields_door() {
    run_on_engine_stack("esign-editor-fields-computation", || async {
        let editor = editor();
        let (computation, _) = editor.tokens().await;
        let moved = editor.moved();
        for (token, refusal) in [
            (Some(computation.as_str()), "editor_token_unadmitted"),
            (None, "editor_token_missing"),
        ] {
            let (status, body) = editor.place(token, std::slice::from_ref(&moved)).await;
            assert_eq!(
                (status, code(&body)),
                (StatusCode::UNAUTHORIZED, Some(refusal)),
                "the fields door admits its own token alone: {body}"
            );
        }
        assert_eq!(
            editor.fields(),
            [editor.drafted.clone()],
            "the draft keeps its fields"
        );
    });
}

#[test]
fn the_fields_token_is_refused_at_every_other_door() {
    run_on_engine_stack("esign-editor-fields-other-doors", || async {
        let editor = editor();
        let token = editor.fields_token().await;
        let editor_header = [(EDITOR_HEADER, token.as_str())];

        // The editor's computation doors read the same header: the fields token buys no
        // computation there, and is never served as their anonymous door.
        let layout = json!({"fields": [], "values": {}, "pages": []}).to_string();
        let (status, body) = editor
            .post(
                "/sign/layout",
                "application/json",
                &editor_header,
                layout.into_bytes(),
            )
            .await;
        assert_eq!(
            (status, code(&body)),
            (StatusCode::UNAUTHORIZED, Some("editor_token_unadmitted")),
            "the fields token at /sign/layout: {body}"
        );
        let (status, body) = editor
            .post(
                "/sign/geometry",
                "application/pdf",
                &editor_header,
                original_pdf().to_vec(),
            )
            .await;
        assert_eq!(
            (status, code(&body)),
            (StatusCode::UNAUTHORIZED, Some("editor_token_unadmitted")),
            "the fields token at /sign/geometry: {body}"
        );

        // It is no signing link at the ceremony, and no credential at the verb's own route.
        let (status, body) = editor
            .post(
                "/sign/action",
                "application/json",
                &[("x-oneiron-esign-capability", token.as_str())],
                json!({"action": {"action": "load"}})
                    .to_string()
                    .into_bytes(),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "the fields token at the ceremony: {body}"
        );
        let bearer = format!("Bearer {token}");
        let (status, body) = editor
            .post(
                "/v1/core/facade/vault.esign.fields.place",
                "application/json",
                &[(header::AUTHORIZATION.as_str(), bearer.as_str())],
                editor.placement(std::slice::from_ref(&editor.moved())),
            )
            .await;
        assert!(
            matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN),
            "the fields token as the facade's bearer: {status} {body}"
        );
        assert_eq!(
            editor.fields(),
            [editor.drafted.clone()],
            "the draft keeps its fields"
        );
    });
}

#[test]
fn a_sent_document_keeps_its_fields() {
    run_on_engine_stack("esign-editor-fields-sent", || async {
        let editor = editor();
        let token = editor.fields_token().await;
        oneiron::test_support::mark_esign_sent(
            &editor.vault,
            editor.document,
            owner_actor(editor.owner),
            editor.vault.now_recorded_at(),
        )
        .expect("send the document");
        let (status, body) = editor
            .place(Some(token.as_str()), std::slice::from_ref(&editor.moved()))
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "the verb refuses a sent document's fields: {body}"
        );
        assert!(
            body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("sent content is frozen")),
            "the refusal is the verb's own: {body}"
        );
        let state = editor
            .vault
            .esign_document(editor.document)
            .expect("the signing document");
        assert_eq!(state.status, DocumentStatus::Pending);
        assert_eq!(
            state.document.fields,
            [editor.drafted.clone()],
            "a sent document keeps its fields"
        );
    });
}

#[test]
fn a_revoked_caller_places_nothing() {
    run_on_engine_stack("esign-editor-fields-revoked", || async {
        let editor = editor();
        let token = editor.fields_token().await;
        editor
            .vault
            .revoke_capability_slip(&editor.issuer, editor.slip.claims.slip_id)
            .expect("revoke the owner's slip");
        let (status, body) = editor
            .place(Some(token.as_str()), std::slice::from_ref(&editor.moved()))
            .await;
        assert_eq!(
            (status, code(&body)),
            (StatusCode::UNAUTHORIZED, Some("editor_caller_not_live")),
            "a token whose caller's credential is revoked places nothing: {body}"
        );
        assert_eq!(
            editor.fields(),
            [editor.drafted.clone()],
            "the draft keeps its fields"
        );
    });
}
