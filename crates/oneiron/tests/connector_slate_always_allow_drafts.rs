//! Restriction wave 6, census C46 (Engine RULING RESTRICTION-WAVE-6-CANON-ROWS 16 Nov 03:35,
//! C46 = A): the owner key `connectors.slate.drafts_offer_always_allow` (off by default) lets a
//! connector's admission draft pre-fill `always allow` on a tool row where his past rulings show
//! he chose it. ARCH-0072:93: "The drafter pre-fills `always ask` or `never allow` only where the
//! owner's past rulings show he wants them. A draft grants nothing. The owner may accept it or
//! choose `always allow`."
//!
//! Red on the helper base (main with the Setting primitive #8025/#8259 merged): the key does not
//! exist, so the owner's change is refused and the key-on tests fail at their set. The default
//! tests pass there too: off, drafts behave exactly as today.

#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::connector_key::{
    SlateDataClass, SlateDisposition, SlateDraftRow, SlateManifest, SlateOwnerOverride,
    SlateToolManifest,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller, SettingMode, SettingScope};
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::json;

const T0: u64 = 1_790_000_000;
const KEY: &str = "connectors.slate.drafts_offer_always_allow";

struct Fixture {
    vault: Vault,
    _clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
    owner: AuthenticatedOwner,
}

impl Fixture {
    /// A rooted vault on a manual clock at `T0`, its embedded owner bound and proved.
    fn rooted() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let clock = ManualClock::new(T0);
        let keystore = Arc::new(MemoryKeystore::new());
        let mut config = VaultConfig::device();
        config.store_clock = clock.bundle();
        let vault = Vault::open_owned(dir.path(), config).expect("owned vault");
        vault.install_device_keystore(Arc::<MemoryKeystore>::clone(&keystore));
        vault.prepare_install_signing().expect("install signing");
        let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
        vault.ensure_host_root_slip(&issuer).expect("host root");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine machine identities");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("serving install profile");
        let owner_id = vault.ensure_embedded_owner_actor().expect("embedded owner");
        let owner = vault
            .authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        Self {
            vault,
            _clock: clock,
            _dir: dir,
            owner,
        }
    }

    /// The owner turns the key on for the vault; the change must apply.
    fn owner_turns_on_always_allow_drafts(&self) {
        let outcome = self
            .vault
            .set_setting(
                SettingCaller::Owner(&self.owner),
                SetSetting {
                    key: KEY.to_owned(),
                    item: None,
                    scope: SettingScope::Vault,
                    mode: SettingMode::Value,
                    value: Some(json!(true)),
                    expected_revision: None,
                    why: None,
                    check_in_ref: None,
                },
            )
            .unwrap_or_else(|error| panic!("the owner's change of `{KEY}` was refused: {error}"));
        assert!(
            matches!(outcome, SetSettingOutcome::Applied { .. }),
            "the owner's change of `{KEY}` did not apply: {outcome:?}"
        );
    }

    /// A connector with the one read tool `name`, admitted with a drafted slate; returns the
    /// slate's id.
    fn admit(&self, name: &str) -> EntityId {
        self.vault
            .draft_connector_admission_slate(
                &SlateManifest::new(vec![read_tool(name)], false),
                None,
            )
            .expect("admission draft")
    }

    /// The draft of `name`'s row on slate `id`, and whether anything stamped the slate.
    fn draft_of(&self, id: EntityId, name: &str) -> (SlateDraftRow, bool) {
        let slate = self
            .vault
            .connector_slate(id)
            .expect("slate read")
            .expect("slate");
        let row = slate.row(name).expect("tool row").draft.clone();
        (row, slate.owner_actor().is_some())
    }

    /// The owner's one tap on slate `id`, with `overrides`.
    fn stamp(&self, id: EntityId, overrides: &BTreeMap<String, SlateOwnerOverride>) {
        let revision = self
            .vault
            .connector_slate(id)
            .expect("slate read")
            .expect("slate")
            .revision();
        self.vault
            .override_connector_slate(&self.owner, id, revision, overrides)
            .expect("owner stamp");
    }

    /// `count` connectors whose read tool the owner chose `always allow` for: his past rulings.
    fn rule_always_allow_on(&self, count: usize) {
        for n in 0..count {
            let name = format!("past_search_{n}");
            let id = self.admit(&name);
            self.stamp(
                id,
                &BTreeMap::from([(
                    name,
                    SlateOwnerOverride {
                        disposition: SlateDisposition::AlwaysAllow,
                    },
                )]),
            );
        }
    }
}

/// A read tool over public data: its one trait is a read.
fn read_tool(name: &str) -> SlateToolManifest {
    SlateToolManifest {
        name: name.to_owned(),
        data_class: SlateDataClass::Public,
        header_parameters: vec![],
        resolved_input_schema: Some(json!({"type": "object",
            "properties": {"query": {"type": "string", "enum": ["a", "b"]}}})),
        trigger: None,
        destroys: false,
        spends: false,
        sends_outward: false,
        legacy_ask: false,
        read_only: false,
        idempotent: false,
        price: None,
    }
}

#[test]
fn with_the_key_on_a_draft_pre_fills_always_allow_where_past_rulings_show_it() {
    let fx = Fixture::rooted();
    fx.rule_always_allow_on(2);
    fx.owner_turns_on_always_allow_drafts();

    let id = fx.admit("lookup");
    let (draft, stamped) = fx.draft_of(id, "lookup");
    assert_eq!(
        draft.disposition,
        SlateDisposition::AlwaysAllow,
        "the draft did not pre-fill always allow although the owner turned the key on and \
         chose always allow for reads on two connectors: {draft:?}"
    );
    assert!(
        draft.rationale.contains("always allow"),
        "the draft does not say why it pre-filled always allow: {:?}",
        draft.rationale
    );
    assert!(
        !stamped,
        "the drafted slate is stamped: a draft must grant nothing"
    );

    fx.stamp(id, &BTreeMap::new());
    let slate = fx.vault.connector_slate(id).unwrap().unwrap();
    assert_eq!(
        slate.row("lookup").unwrap().stamped_disposition(),
        SlateDisposition::AlwaysAllow,
        "the owner's one tap did not accept the pre-filled always allow"
    );
}

#[test]
fn with_the_key_on_thin_evidence_still_drafts_auto() {
    let fx = Fixture::rooted();
    fx.rule_always_allow_on(1);
    fx.owner_turns_on_always_allow_drafts();

    let (draft, _) = fx.draft_of(fx.admit("lookup"), "lookup");
    assert_eq!(
        draft.disposition,
        SlateDisposition::Auto,
        "one past connector pre-filled always allow; the drafter needs two"
    );
}

#[test]
fn by_default_a_draft_never_pre_fills_always_allow() {
    let fx = Fixture::rooted();
    fx.rule_always_allow_on(2);

    let (draft, _) = fx.draft_of(fx.admit("lookup"), "lookup");
    assert_eq!(
        draft.disposition,
        SlateDisposition::Auto,
        "with the key off the draft pre-filled {:?}",
        draft.disposition
    );
}

#[test]
fn an_outside_draft_never_pre_fills_always_allow() {
    let fx = Fixture::rooted();
    let tool = read_tool("lookup");
    let row = SlateDraftRow {
        tool: tool.name.clone(),
        disposition: SlateDisposition::AlwaysAllow,
        data_class: tool.row_data_class(),
        rationale: "the model says so".to_owned(),
    };
    let output = serde_json::to_string(&vec![row]).expect("draft rows");
    assert!(
        fx.vault.store_connector_slate(&[tool], &output).is_err(),
        "a model's own slate draft pre-filled always allow"
    );
}
