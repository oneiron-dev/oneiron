//! The owner's opt-out for the model licence refusal (`models.install.allow_noncommercial_licences`;
//! owner principle 16 Nov 00:44; lead ruling GENUI-OPTOUT-MODEL-LICENCE = A, 16 Nov 03:21).
//!
//! With no row a non-commercial or unknown licence is refused before any byte, as before. On a
//! self-hosted vault the owner's true admits both, and a conditional licence still needs its
//! named decision. A hosted vault refuses the owner's true, naming the standing grant, and its
//! installs stay refused.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --test model_licence_owner_key`.
#![cfg(oneiron_test_support)]

use oneiron::consent::AuthenticatedOwner;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::store::GateDecisionId;
use oneiron::{HostingPrivacyPosture, Vault, VaultConfig};
use oneiron_server::test_doors::model_licence::admit_licence;
use serde_json::json;

const KEY: &str = "models.install.allow_noncommercial_licences";
const NON_COMMERCIAL: &str = "cc-by-nc-4.0";
/// An id the server's licence table does not name.
const UNLISTED: &str = "example-unlisted-licence-1.0";

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner_proof: AuthenticatedOwner,
}

impl Fixture {
    fn open(config: VaultConfig) -> Self {
        let dir = tempfile::tempdir().expect("temporary vault directory");
        let vault = Vault::open(dir.path(), config).expect("open fixture vault");
        let owner = vault
            .ensure_embedded_owner_actor()
            .expect("the vault's owner");
        let owner_proof = vault
            .authenticate_owner(owner, "principal:owner", true, GateDecisionId::now())
            .expect("owner proof");
        Self {
            _dir: dir,
            vault,
            owner_proof,
        }
    }

    fn self_hosted() -> Self {
        Self::open(VaultConfig::default())
    }

    fn hosted() -> Self {
        let mut config = VaultConfig::device();
        config.privacy.posture = HostingPrivacyPosture::Hosted;
        Self::open(config)
    }

    fn set(&self, admits: bool) -> oneiron::Result<SetSettingOutcome> {
        self.vault.set_setting(
            SettingCaller::Owner(&self.owner_proof),
            SetSetting::vault_value(KEY, json!(admits)),
        )
    }

    fn admit(&self, licence_id: &str, decision: Option<&str>) -> Result<&'static str, String> {
        admit_licence(&self.vault, licence_id, decision)
    }
}

#[test]
fn with_no_row_non_commercial_and_unknown_licences_are_refused() {
    let fixture = Fixture::self_hosted();
    for licence in [NON_COMMERCIAL, UNLISTED] {
        let refused = fixture.admit(licence, None).expect_err("refused today");
        assert!(
            refused.contains("so the download is refused"),
            "{licence}: {refused}"
        );
    }
    assert_eq!(fixture.admit("apache-2.0", None), Ok("permissive"));
    assert_eq!(
        fixture.admit("llama3", Some("RULING-EXAMPLE")),
        Ok("conditional")
    );
}

#[test]
fn the_owners_true_admits_non_commercial_and_unknown_licences_on_a_self_hosted_node() {
    let fixture = Fixture::self_hosted();
    let outcome = fixture.set(true).expect("the owner sets the key");
    assert!(
        matches!(outcome, SetSettingOutcome::Applied { .. }),
        "the owner's change applies at once: {outcome:?}"
    );
    assert_eq!(fixture.admit(NON_COMMERCIAL, None), Ok("non-commercial"));
    assert_eq!(fixture.admit(UNLISTED, None), Ok("unknown"));
    assert!(
        fixture.admit("llama3", None).is_err(),
        "a conditional licence still needs its named decision"
    );
}

#[test]
fn a_hosted_node_refuses_the_owners_true_and_keeps_refusing_the_download() {
    let fixture = Fixture::hosted();
    let refused = fixture.set(true).expect_err("a hosted node refuses true");
    assert!(
        refused
            .to_string()
            .contains(oneiron::llm::NONCOMMERCIAL_LICENCES_HOSTED_REFUSAL),
        "the refusal names the standing grant: {refused}"
    );
    assert!(fixture.admit(NON_COMMERCIAL, None).is_err());
    assert!(!oneiron::llm::noncommercial_model_licences_admitted(&fixture.vault).expect("read"));
}
