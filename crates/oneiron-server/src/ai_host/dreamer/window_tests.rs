//! The input windows the Dreamer lends its models (FIX
//! DREAMER-WINDOW-RESERVES-NO-OUTPUT-WITHOUT-PROVIDER-CAP).
use oneiron::ModelId;
use oneiron::dreamer_consolidation::EXTRACTION_MAX_TOKENS;

use super::dream_windows;
use crate::ai_host::test_support::models_toml;

/// The house layout (deploy/house-model/models.toml): a 32,768-token server
/// that names no output ceiling, and beside it one that names 2,048.
const MODELS: &str = r#"
[providers.house]
kind = "local-openai-compat"
base_url = "http://127.0.0.1:18091"
context_tokens = 32768

[providers.capped]
kind = "local-openai-compat"
base_url = "http://127.0.0.1:18134"
context_tokens = 32768
max_output_tokens = 2048

[roles.dreamer_current]
rungs = [{ model = "house:qwen" }, { model = "capped:qwen" }]
"#;

/// The window the Dreamer lends `provider`'s model.
fn window(provider: &str) -> u64 {
    let model = ModelId::new(format!("{provider}/qwen@live")).unwrap();
    dream_windows(&models_toml(MODELS))[&model]
}

#[test]
fn a_provider_naming_no_output_ceiling_leaves_the_extraction_ask_room() {
    assert_eq!(window("house"), 32_768 - EXTRACTION_MAX_TOKENS);
}

#[test]
fn a_provider_output_ceiling_stays_its_reserve() {
    assert_eq!(window("capped"), 32_768 - 2_048);
}
