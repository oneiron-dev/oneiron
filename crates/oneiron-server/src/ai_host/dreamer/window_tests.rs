//! The input windows the Dreamer and code mode's reader child lend their
//! models (FIX DREAMER-WINDOW-RESERVES-NO-OUTPUT-WITHOUT-PROVIDER-CAP).
use oneiron::ModelId;
use oneiron::dreamer_consolidation::EXTRACTION_MAX_TOKENS;

use super::{dream_windows, reader_windows};
use crate::ai_host::test_support::models_toml;

/// The house layout (deploy/house-model/models.toml): a 32,768-token server
/// that names no output ceiling, and beside it one that names 2,048; then
/// two servers with no ceiling, one a token past the extraction ask and one
/// below it.
const MODELS: &str = r#"
[providers.house]
kind = "local-openai-compat"
base_url = "http://127.0.0.1/house"
context_tokens = 32768

[providers.capped]
kind = "local-openai-compat"
base_url = "http://127.0.0.1/capped"
context_tokens = 32768
max_output_tokens = 2048

[providers.tight]
kind = "local-openai-compat"
base_url = "http://127.0.0.1/tight"
context_tokens = 12289

[providers.small]
kind = "local-openai-compat"
base_url = "http://127.0.0.1/small"
context_tokens = 8192

[roles.dreamer_current]
rungs = [
    { model = "house:qwen" },
    { model = "capped:qwen" },
    { model = "tight:qwen" },
    { model = "small:qwen" },
]
"#;

/// The engine id of `provider`'s model.
fn model(provider: &str) -> ModelId {
    ModelId::new(format!("{provider}/qwen@live")).unwrap()
}

/// The window the Dreamer lends `provider`'s model.
fn window(provider: &str) -> u64 {
    dream_windows(&models_toml(MODELS))[&model(provider)]
}

/// The window code mode lends its reader child on `provider`'s model.
fn reader_window(provider: &str) -> u64 {
    reader_windows(&models_toml(MODELS))[&model(provider)]
}

#[test]
fn a_provider_naming_no_output_ceiling_leaves_the_extraction_ask_room() {
    assert_eq!(window("house"), 32_768 - EXTRACTION_MAX_TOKENS);
}

#[test]
fn a_provider_output_ceiling_stays_its_reserve() {
    assert_eq!(window("capped"), 32_768 - 2_048);
}

#[test]
fn an_uncapped_context_just_past_the_ask_keeps_half_its_window() {
    assert_eq!(EXTRACTION_MAX_TOKENS + 1, 12_289);
    assert_eq!(window("tight"), 12_289 - 12_289 / 2);
}

#[test]
fn an_uncapped_context_below_the_ask_keeps_its_whole_window() {
    assert_eq!(window("small"), 8_192);
}

#[test]
fn the_code_mode_reader_keeps_an_uncapped_context_whole() {
    assert_eq!(reader_window("house"), 32_768);
    assert_eq!(reader_window("tight"), 12_289);
}

#[test]
fn the_code_mode_reader_reserves_a_provider_output_ceiling() {
    assert_eq!(reader_window("capped"), 32_768 - 2_048);
}
