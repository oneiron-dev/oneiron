//! L2-37 PR-3: the idle Keep refresh resends a parked run's last request
//! with only `max_tokens` set to 1, so the provider reads (and so keeps)
//! its cached prefix one more lifetime.
//!
//! Reaches the refresh through `oneiron_server::test_doors::prefix_refresh`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! `--all-features --test idle_prefix_refresh`.
#![cfg(oneiron_test_support)]

#[path = "support/fake_llm.rs"]
mod fake_llm;

use std::sync::Arc;

use fake_llm::{FakeLlm, Reply};
use oneiron::{Vault, VaultConfig};
use oneiron_server::config::models::ModelsConfig;
use oneiron_server::models::ModelRuntime;
use oneiron_server::test_doors::prefix_refresh::warm_then_refresh;
use serde_json::json;

/// The cached prefix's extent in the provider's own tokens.
const PREFIX_TOKENS: u64 = 1234;

/// An anthropic-compat route at the fake, as `models/tests.rs` builds it:
/// the default seat serves the chat role through it.
fn models_text(base_url: &str) -> String {
    format!(
        "default = \"claude:proxy/claude-family-latest\"\n[providers.claude]\nkind = \"anthropic-compat\"\nbase_url = \"{base_url}\"\nkey_env = \"HOME\"\nmax_output_tokens = 900\n",
    )
}

async fn runtime_at(fake_base_url: &str) -> (tempfile::TempDir, Arc<Vault>, Arc<ModelRuntime>) {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    let config = ModelsConfig::from_toml(&models_text(fake_base_url), None).expect("models config");
    let runtime = Arc::new(ModelRuntime::build(
        Some(&config),
        oneiron::HostingPrivacyPosture::SelfHostLocal,
    ));
    (dir, vault, runtime)
}

/// The Keep refresh resends the warm send byte-identical but for `max_tokens`,
/// set to 1, and stamps the horizon the provider confirmed for the read.
#[tokio::test]
async fn keep_sends_one_prefix_identical_refresh() {
    let fake = FakeLlm::start(
        vec![
            Reply::CachedText {
                text: "warm".into(),
                model: "claude-family-latest".into(),
                cache_write: PREFIX_TOKENS,
                cache_read: 0,
            },
            Reply::CachedText {
                text: "kept".into(),
                model: "claude-family-latest".into(),
                cache_write: 0,
                cache_read: PREFIX_TOKENS,
            },
        ],
        None,
    )
    .await;
    let (_dir, vault, runtime) = runtime_at(&fake.base_url).await;
    let horizon = warm_then_refresh(vault, runtime).await;
    let seen = fake.seen();
    assert_eq!(seen.len(), 2, "the warm send and its one refresh");
    assert!(seen.iter().all(|s| s.path == "/v1/messages"));
    let mut first = seen[0].body.clone();
    let mut second = seen[1].body.clone();
    assert_eq!(second["max_tokens"], json!(1));
    first.as_object_mut().expect("object").remove("max_tokens");
    second.as_object_mut().expect("object").remove("max_tokens");
    assert_eq!(
        first, second,
        "the refresh resends the warm send but for max_tokens"
    );
    let horizon = horizon.expect("the refresh stamps the horizon it read");
    assert_eq!(horizon.tokens, PREFIX_TOKENS);
}

/// A prefix the provider never wrote gets no refresh: nothing is sent twice.
#[tokio::test]
async fn a_cold_prefix_gets_no_refresh() {
    let fake = FakeLlm::start(vec![Reply::text("cold")], None).await;
    let (_dir, vault, runtime) = runtime_at(&fake.base_url).await;
    let horizon = warm_then_refresh(vault, runtime).await;
    assert_eq!(horizon, None);
    assert_eq!(
        fake.seen().len(),
        1,
        "the warm send alone; no refresh went out"
    );
}
