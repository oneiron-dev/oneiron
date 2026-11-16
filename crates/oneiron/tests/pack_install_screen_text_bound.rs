//! FIX SCREENING-PER-TOOL-SKIP (FIX-LIST 26659), PR D: the pack install
//! screen's text bound is the owner's Setting key
//! `pack_install.screen.text_max_bytes` (default 16384, today's bound; Engine
//! ANSWER SCREENING-SKIP-OVERRIDE-SCOPE 16 Nov 13:20). Guards prove the
//! default; the owner tests raise and lower the key.
//!
//! At the base (PR C + the Setting primitive) the key is not in the
//! catalogue, so the owner's set is refused and the two owner tests fail; the
//! default guards pass there and at the head.
//!
//! Public paths only. Run: `cargo test --locked -p oneiron --all-features
//! --test pack_install_screen_text_bound`.

use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::skill_hub::pack_catalog::{ConnectorToolScreen, PackObservedTool, ScreenRule};
use oneiron::store::GateDecisionId;
use oneiron::{Vault, VaultConfig};
use serde_json::json;

const HOLDER: &str = "docs";
const KEY: &str = "pack_install.screen.text_max_bytes";

fn fixture() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    (dir, vault)
}

/// A tool whose description is `bytes` ASCII bytes long.
fn described(name: &str, bytes: usize) -> PackObservedTool {
    PackObservedTool {
        name: name.into(),
        description: "a".repeat(bytes),
        input_schema: json!({
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Maximum number of rows to return"}
            }
        }),
    }
}

fn each(vault: &Vault, tools: &[PackObservedTool]) -> ConnectorToolScreen {
    vault
        .screen_connector_tools_each(tools, HOLDER)
        .expect("screen listed tools")
}

fn kept_out_by_the_bound(screen: &ConnectorToolScreen, tool: &str) -> bool {
    screen
        .skipped
        .iter()
        .any(|skip| skip.tool == tool && skip.rules.contains(&ScreenRule::TextBound))
}

fn set_owner_key(vault: &Vault, n: u32) {
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the vault's owner");
    let owner_proof = vault
        .authenticate_owner(owner, "principal:owner", true, GateDecisionId::now())
        .expect("owner proof");
    let outcome = vault
        .set_setting(
            SettingCaller::Owner(&owner_proof),
            SetSetting::vault_value(KEY, n.into()),
        )
        .expect("the owner sets the key");
    assert!(
        matches!(outcome, SetSettingOutcome::Applied { .. }),
        "{outcome:?}"
    );
}

/// Guard: by default a 16384-byte description passes and a 16385-byte one
/// is kept out, as before the key.
#[test]
fn the_default_bound_is_16384_bytes() {
    let (_dir, vault) = fixture();
    let screen = each(
        &vault,
        &[described("docs_fits", 16_384), described("docs_long", 16_385)],
    );
    assert!(screen.admits("docs_fits"), "{screen:?}");
    assert!(kept_out_by_the_bound(&screen, "docs_long"), "{screen:?}");
    let whole = vault
        .screen_connector_tools(&[described("docs_long", 16_385)], HOLDER)
        .expect("screen listed tools");
    assert_eq!(
        whole.as_deref(),
        Some("tool docs_long: manifest text bound exceeded")
    );
}

/// The owner raises the bound: a 16385-byte description passes, and one
/// past the new bound is still kept out.
#[test]
fn the_owner_raises_the_bound() {
    let (_dir, vault) = fixture();
    set_owner_key(&vault, 32_768);
    let screen = each(
        &vault,
        &[described("docs_long", 16_385), described("docs_longer", 32_769)],
    );
    assert!(screen.admits("docs_long"), "{screen:?}");
    assert!(kept_out_by_the_bound(&screen, "docs_longer"), "{screen:?}");
}

/// The owner lowers the bound: lower is tighter, so a 64-byte description
/// is kept out under a 32-byte bound.
#[test]
fn the_owner_lowers_the_bound() {
    let (_dir, vault) = fixture();
    set_owner_key(&vault, 32);
    let screen = each(
        &vault,
        &[described("docs_short", 16), described("docs_long", 64)],
    );
    assert!(screen.admits("docs_short"), "{screen:?}");
    assert!(kept_out_by_the_bound(&screen, "docs_long"), "{screen:?}");
}
