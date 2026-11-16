//! The `vault.decisions.bands.*` rows across a server restart, at the public door:
//! arch-0076:275 (promise-dura-10) "A learned decision-band mode and its version stay
//! in effect after a restart."
//!
//! The three rows are host doors, so these tests drive `build_app` at
//! `POST /v1/core/facade/<verb>` with the self-hosted root credential
//! (`HostSlipIssuer::from_secret`), the vault's embedded owner. A restart drops the
//! server and builds a new one over the same vault, as a restart of `serve` does: the
//! new host keeps nothing of the old one's memory, so what it reads came from the vault.
//! Every body runs on the engine's stack.
//!
//! - `a_learned_and_enforced_band_stays_in_effect_after_a_restart`: the band, its
//!   version and its enforce mode read the same after the restart.
//! - `a_band_learned_before_a_restart_enforces_after_it`: the restarted host enforces
//!   a band only the old host learned, in shadow until then.
//! - `a_band_version_still_only_advances_after_a_restart`: the restarted host refuses
//!   a learn at the stored version or below it, and takes a later one in shadow.
//!
//! Red on main (FIX-LIST DECISION-BANDS-NOT-DURABLE): band rows lived in the host's
//! memory (`DecisionBandPolicy`), so the restarted host read the seed in shadow at
//! version 0, refused the enforce as unlearned, and took the same version again.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --test decision_bands_restart_doors`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

const SECRET: &str = "decision-bands-restart-doors-secret";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A yes-or-no question under a fresh id, as the band rows take it.
fn question_json() -> Value {
    json!({
        "id": EntityId::now().to_hex(),
        "version": 1,
        "text": "band question",
        "class": "judgment",
        "contract": {"kind": "noul"},
        "accept_type": false,
    })
}

/// A refusal's (status, code, message): what a caller tells apart.
fn refusal(status: StatusCode, body: &Value) -> (StatusCode, Value, Value) {
    (
        status,
        body["error"]["code"].clone(),
        body["error"]["message"].clone(),
    )
}

/// A server over `vault`, as a start of `serve` builds it.
fn serve(vault: &Arc<Vault>) -> Router {
    let server = SyncServer::new(
        Arc::clone(vault),
        SyncServerConfig {
            auth_secret: Some(SECRET.to_owned()),
            ..Default::default()
        },
    )
    .unwrap();
    build_app(Arc::new(server))
}

/// One rooted vault, its server's router and the self-hosted root credential.
struct Door {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    root: CapabilitySlip,
}

impl Door {
    fn open() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
        let app = serve(&vault);
        let issuer = HostSlipIssuer::from_secret(SECRET.as_bytes()).unwrap();
        let root = vault.ensure_host_root_slip(&issuer).unwrap();
        vault.ensure_embedded_owner_actor().unwrap();
        Self {
            _dir: dir,
            vault,
            app,
            issuer,
            root,
        }
    }

    /// The server dropped and built again over the same vault, as a restart of `serve`
    /// does.
    fn restart(&mut self) {
        self.app = Router::new();
        self.app = serve(&self.vault);
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

    /// `POST /v1/core/facade/<verb>` with `body` under the owner's credential.
    async fn post_owner(&self, verb: &str, body: &Value) -> (StatusCode, Value) {
        let (token, binding) = self.owner_credential();
        let request = Request::builder()
            .method("POST")
            .uri(format!("/v1/core/facade/{verb}"))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .header("x-oneiron-binding", binding)
            .body(Body::from(body.to_string()))
            .unwrap();
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1_048_576).await.unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn learn(&self, asked: &Value, band: &Value, version: u32) -> (StatusCode, Value) {
        self.post_owner(
            "vault.decisions.bands.learn",
            &json!({"question": asked, "reversibility": "reversible_read", "band": band, "version": version}),
        )
        .await
    }

    async fn enforce(&self, asked: &Value) -> (StatusCode, Value) {
        self.post_owner(
            "vault.decisions.bands.enforce",
            &json!({"question": asked, "reversibility": "reversible_read"}),
        )
        .await
    }

    async fn read(&self, asked: &Value) -> (StatusCode, Value) {
        self.post_owner(
            "vault.decisions.bands.read",
            &json!({"question": asked, "reversibility": "reversible_read", "seed": {"low": 0.35, "high": 0.65}}),
        )
        .await
    }
}

/// arch-0076:275: a band learned at version 3 and enforced reads, after the restart,
/// as the band at version 3 in enforce mode, not as the seed in shadow at version 0.
#[test]
fn a_learned_and_enforced_band_stays_in_effect_after_a_restart() {
    run_on_engine_stack("decision-bands-restart-enforced", || async {
        let mut door = Door::open();
        let asked = question_json();
        let band = json!({"low": 0.3, "high": 0.7});
        let (status, learned) = door.learn(&asked, &band, 3).await;
        assert_eq!(status, StatusCode::OK, "{learned}");
        let (status, enforced) = door.enforce(&asked).await;
        assert_eq!(status, StatusCode::OK, "{enforced}");
        let held = json!({"band": band, "version": 3, "mode": "enforce"});
        assert_eq!(enforced, held, "{enforced}");

        door.restart();

        let (status, now) = door.read(&asked).await;
        assert_eq!((status, &now), (StatusCode::OK, &held), "{now}");
    });
}

/// arch-0076:275: a band the old host learned stays learned on the restarted host,
/// in shadow at its version, and that host's owner enforces it.
#[test]
fn a_band_learned_before_a_restart_enforces_after_it() {
    run_on_engine_stack("decision-bands-restart-learned", || async {
        let mut door = Door::open();
        let asked = question_json();
        let band = json!({"low": 0.2, "high": 0.6});
        let (status, learned) = door.learn(&asked, &band, 1).await;
        assert_eq!(status, StatusCode::OK, "{learned}");

        door.restart();

        let (status, shadow) = door.read(&asked).await;
        assert_eq!(
            (status, &shadow),
            (
                StatusCode::OK,
                &json!({"band": band, "version": 1, "mode": "shadow"})
            ),
            "{shadow}"
        );
        let (status, enforced) = door.enforce(&asked).await;
        assert_eq!(status, StatusCode::OK, "{enforced}");
        let held = json!({"band": band, "version": 1, "mode": "enforce"});
        assert_eq!(enforced, held, "{enforced}");
        let (status, now) = door.read(&asked).await;
        assert_eq!((status, &now), (StatusCode::OK, &held), "{now}");
    });
}

/// arch-0076:275, the version: after the restart a learn at the stored version or
/// below it is refused, and a later version is learned in shadow.
#[test]
fn a_band_version_still_only_advances_after_a_restart() {
    run_on_engine_stack("decision-bands-restart-version", || async {
        let mut door = Door::open();
        let asked = question_json();
        let band = json!({"low": 0.3, "high": 0.7});
        let (status, learned) = door.learn(&asked, &band, 3).await;
        assert_eq!(status, StatusCode::OK, "{learned}");

        door.restart();

        let later = json!({"low": 0.25, "high": 0.75});
        for version in [3, 2] {
            let (status, refused) = door.learn(&asked, &later, version).await;
            assert_eq!(
                refusal(status, &refused),
                (
                    StatusCode::BAD_REQUEST,
                    json!("BAD_REQUEST"),
                    json!("learned band version must advance")
                ),
                "version {version}: {refused}"
            );
        }
        let (status, now) = door.read(&asked).await;
        assert_eq!(
            (status, &now),
            (
                StatusCode::OK,
                &json!({"band": band, "version": 3, "mode": "shadow"})
            ),
            "{now}"
        );
        let (status, relearned) = door.learn(&asked, &later, 4).await;
        assert_eq!(
            (status, &relearned),
            (
                StatusCode::OK,
                &json!({"band": later, "version": 4, "mode": "shadow"})
            ),
            "{relearned}"
        );
    });
}
