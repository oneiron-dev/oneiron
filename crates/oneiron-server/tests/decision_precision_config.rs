//! `[models.decisions.precision]` seats the precision band on the host's decision ladder
//! (`cross/models.md#oneiron-roles`, the band row: "Same wire and codec as the head"). The
//! table takes the System One seat's shape; the seat it binds is pinned on the Precision
//! rung, and the merge doors' useful-upstream question may start there. The owner's
//! `remote_opt_in` is one choice for the host's ladder, so the head's table and the band's
//! must agree on it. A managed tenant may not name the band's key by an environment
//! variable, as it may not name the head's.
//!
//! On main the file does not compile: `HeldLadder` has no `precision` slot, and
//! `[models.decisions]` refuses a `precision` table as an unknown field.

#[path = "support/fake_llm.rs"]
mod fake_llm;

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::sync::Arc;
use std::time::Duration;

use engine_stack::run_on_engine_stack;
use fake_llm::FakeLlm;
use oneiron::llm::decision::{DecisionRung, ProviderPin};
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::{Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::ai_host::AiHost;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::config::models::ModelsConfig;
use oneiron_server::server::SyncServer;
use oneiron_vault_contract::settings_policy::{ENVIRONMENT_KEYS, matches_any};

// The configured server secret that selects secret-based rooting at boot; it is
// config, not issuer key material.
const AUTH_SECRET: &str = "decision-precision-config-auth-secret";
/// A variable `cargo test` sets in every test process: the seat's bearer is
/// read from it at bind. Binding sends nothing.
const BEARER_ENV: &str = "CARGO_PKG_NAME";
/// The precision band's model and revision (`cross/models.md`, the band row).
const BAND_MODEL: &str = "Cloudflare/clef";
const BAND_REVISION: &str = "2f3de3d";
/// The hot-path head's model and revision (`cross/models.md`, the head row).
const HEAD_MODEL: &str = "vllm-sr/d3-flash";
const HEAD_REVISION: &str = "521525e";

/// `[models]` with one local provider at `base_url`, then `decisions`.
fn models_toml(base_url: &str, decisions: &str) -> String {
    format!(
        "default = \"local:test-model\"\n\
         [providers.local]\n\
         kind = \"local-openai-compat\"\n\
         base_url = \"{base_url}\"\n\
         {decisions}"
    )
}

/// A `[decisions.<table>]` seat on the System One wire, its key in [`BEARER_ENV`].
fn seat_table(table: &str, model: &str, version: &str, remote_opt_in: bool) -> String {
    format!(
        "[decisions.{table}]\n\
         endpoint = \"http://127.0.0.1:9/v1/systemone\"\n\
         key_env = \"{BEARER_ENV}\"\n\
         model = \"{model}\"\n\
         version = \"{version}\"\n\
         remote_opt_in = {remote_opt_in}\n"
    )
}

/// The load's refusal with its whole chain, or a panic when it loads.
fn refusal(text: &str) -> String {
    match ModelsConfig::from_toml(text, None) {
        Ok(_) => panic!("the config loads, and it must be refused"),
        Err(error) => format!("{error:#}"),
    }
}

#[test]
fn precision_settings_fill_the_precision_rung() {
    assert!(
        std::env::var(BEARER_ENV).is_ok_and(|value| !value.trim().is_empty()),
        "cargo test sets {BEARER_ENV}"
    );
    run_on_engine_stack("precision-settings-fill", precision_settings_fill);
}

async fn precision_settings_fill() {
    let dir = tempfile::tempdir().expect("precision config dir");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let fake = FakeLlm::start(Vec::new(), None).await;
    let server = SyncServer::new(
        vault,
        SyncServerConfig {
            auth_secret: Some(AUTH_SECRET.to_owned()),
            ..Default::default()
        },
    )
    .expect("precision config server");
    let toml = models_toml(
        &fake.base_url,
        &seat_table("precision", BAND_MODEL, BAND_REVISION, false),
    );
    let models = ModelsConfig::from_toml(&toml, None).expect("the precision table loads");
    assert!(models.decisions.system_one.is_none());
    let (server, _host) = AiHost::attach(server, Some(&models)).await;

    let ladder = server.decision_ladder();
    let band = ladder
        .precision
        .as_deref()
        .expect("the precision seat fills its rung");
    assert_eq!(
        oneiron::llm::decision::DecisionProvider::pin(band),
        ProviderPin {
            rung: DecisionRung::Precision,
            model: BAND_MODEL.into(),
            version: BAND_REVISION.into(),
        }
    );
    assert!(oneiron::llm::decision::DecisionProvider::leaves_host(band));
    assert!(ladder.system_one.is_none());

    // The merge doors' useful-upstream question starts at the band on a host
    // whose ladder has no head seat.
    let deadline = RetrievalDeadline::after(Duration::from_secs(60));
    let useful = server
        .decision_host()
        .useful_upstream(&deadline)
        .expect("a precision seat answers useful-upstream");
    assert_eq!(useful.dial.first, DecisionRung::Precision);
}

#[test]
fn head_and_band_must_agree_on_the_remote_opt_in() {
    let both = |head: bool, band: bool| {
        models_toml(
            "http://127.0.0.1:9/v1",
            &(seat_table("system_one", HEAD_MODEL, HEAD_REVISION, head)
                + &seat_table("precision", BAND_MODEL, BAND_REVISION, band)),
        )
    };

    let error = refusal(&both(false, true));
    assert!(
        error.contains(
            "models.decisions.precision.remote_opt_in must equal models.decisions.system_one.remote_opt_in"
        ),
        "{error}"
    );
    let models = ModelsConfig::from_toml(&both(true, true), None).expect("agreeing opt-ins load");
    assert!(
        models
            .decisions
            .precision
            .as_ref()
            .is_some_and(|seat| seat.remote_opt_in && seat.model == BAND_MODEL)
    );
    assert!(
        models
            .decisions
            .system_one
            .as_ref()
            .is_some_and(|seat| seat.model == HEAD_MODEL)
    );

    // A refusal of the band's table names the band's table.
    let keyless = models_toml(
        "http://127.0.0.1:9/v1",
        &seat_table("precision", BAND_MODEL, BAND_REVISION, false)
            .replace(&format!("key_env = \"{BEARER_ENV}\"\n"), ""),
    );
    let error = refusal(&keyless);
    assert!(
        error.contains("models.decisions.precision: set exactly one of key_env and key_secret"),
        "{error}"
    );
}

#[test]
fn a_managed_tenant_may_not_name_the_band_key_by_environment() {
    for table in ["system_one", "precision"] {
        assert!(
            matches_any(&["models", "decisions", table, "key_env"], ENVIRONMENT_KEYS),
            "models.decisions.{table}.key_env is an environment key"
        );
    }
}
