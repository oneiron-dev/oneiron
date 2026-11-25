//! Design pass 34, sections 3.2 and 3.3 (row L1): `vault.gpu.lines.set { preset }`. A capability
//! pack carries a lane's line policy document in `knowledge/line-presets/<name>.json`; the owner
//! sets a line from it by naming the pack, the preset and the document's digest, and states only
//! the wallet, the anchor and the fields that differ:
//! - the line stores the full values (the document, his fields laid over it, the engine's neutral
//!   defaults for what neither states) and the preset's reference;
//! - a preset that is not installed, or a digest that is not the installed document's, is
//!   refused and sets nothing;
//! - a later version of the pack changes no line in force;
//! - a policy stated whole sets as before and keeps no preset;
//! - a document that leaves out its unit or budget reads with the defaults its install checked;
//! - the host's offer check reads the policy in force inside the write, after the intent replay,
//!   so a pack installed after an earlier read cannot skip it.
//!
//! The document holds the open-models lane's values of pass 34, 3.3.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test gpu_line_presets`
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::cell::RefCell;
use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::WalletRef;
use oneiron::gpu_line::{
    BudgetPolicy, GpuLineError, GpuLinePolicy, GpuLinePolicyFields, GpuLineSetWire, GpuLineView,
    LinePresetRef, RuleRef, gpu_seconds,
};
use oneiron::skill_hub::HubFile;
use oneiron::skill_hub::pack_catalog::{PackInstallDisposition, PackSource};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::room_facet_set::create_owner_project;
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::{Map, Value, json};

const PACK: &str = "example.lanepreset";
const PRESET: &str = "open-models";
const PRESET_FILE: &str = "knowledge/line-presets/open-models.json";
const PERIOD_SECS: u64 = 1_209_600;
const ANCHOR_MS: u64 = 1_000_000;
/// A moment inside period 0.
const NOW_MS: u64 = ANCHOR_MS + 60_000;

/// The open-models lane's line policy document (pass 34, 3.3).
fn open_models_document(allowance_units: u64) -> Value {
    json!({
        "unit": "gpu_seconds",
        "period_secs": PERIOD_SECS,
        "budget": {
            "allowance_units": allowance_units,
            "rung_caps_secs": [1_800, 10_800, 172_800],
            "pinned_track": "interest",
            "pinned_parts": [1, 3],
            "pinned_mode": "floor_plus_market",
            "floor_arms": 2,
            "seat_cap": 6,
            "seat_reserve_floors": 1,
            "new_idea_slots_per_period": 4,
            "pinned_seat_cap": 0,
            "review_check_secs": 600,
            "hold_ttl_secs": 259_200,
            "window_periods": 3,
            "forecast_required": true,
            "forecast_score_after": 20,
            "max_running_per_family": 1,
            "rules": [{ "rule": "payoff_share", "version": 1 }],
            "invalid_cost": "counts_as_cost",
            "draw_orders": [
                { "track": "demand", "first_rung": ["first_allowance", "floor", "market"], "later_rungs": ["market"] },
                { "track": "interest", "first_rung": ["first_allowance", "floor", "pinned", "market"], "later_rungs": ["pinned", "market"] },
                { "track": "new_idea", "first_rung": ["first_allowance", "floor"], "later_rungs": [] }
            ]
        }
    })
}

/// The preset pack at `version`, whose one preset is `document`.
fn preset_pack(version: &str, document: &Value) -> Vec<HubFile> {
    vec![
        HubFile::new(
            "PACK.md",
            format!(
                "---\nname: {PACK}\ndescription: A lane's line preset.\nversion: {version}\nkind: capability\n---\nA data-only pack: one line preset.\n"
            ),
        ),
        HubFile::new(PRESET_FILE, document.to_string()),
    ]
}

/// The reference to the preset as `files` carry it: its document's digest.
fn reference(files: Vec<HubFile>) -> LinePresetRef {
    let source = PackSource::from_files(files).expect("the preset pack reads");
    let preset = source
        .line_presets()
        .iter()
        .find(|preset| preset.name == PRESET)
        .expect("the pack carries the preset");
    LinePresetRef {
        pack: PACK.to_owned(),
        name: PRESET.to_owned(),
        digest: preset.digest.clone(),
    }
}

fn wallet() -> WalletRef {
    WalletRef {
        issuer: "host".to_owned(),
        id: "gpu".to_owned(),
    }
}

/// What the owner states over the preset: the wallet, the anchor, and one budget field.
fn stated(allowance_units: u64) -> GpuLinePolicyFields {
    let mut fields = Map::new();
    fields.insert("wallet".to_owned(), serde_json::to_value(wallet()).unwrap());
    fields.insert("period_anchor_ms".to_owned(), json!(ANCHOR_MS));
    fields.insert(
        "budget".to_owned(),
        json!({ "allowance_units": allowance_units }),
    );
    GpuLinePolicyFields(fields)
}

/// The budget the line holds when set from the 3.3 document with `allowance_units` stated: the
/// document's values, his allowance, and the engine's defaults for what neither states.
fn expected_budget(allowance_units: u64) -> BudgetPolicy {
    BudgetPolicy {
        allowance_units,
        pinned_parts: (1, 3),
        floor_arms: 2,
        rung_caps_secs: vec![1_800, 10_800, 172_800],
        seat_cap: 6,
        seat_reserve_floors: 1,
        new_idea_slots_per_period: 4,
        review_check_secs: 600,
        max_running_per_family: 1,
        forecast_required: true,
        window_periods: 3,
        rules: vec![RuleRef::PAYOFF_SHARE_1],
        ..BudgetPolicy::default()
    }
}

struct Fixture {
    vault: Vault,
    owner: EntityId,
    issuer: HostSlipIssuer,
    owner_proof: AuthenticatedOwner,
    _dir: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("owner bound to host");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let owner_proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    vault
        .sign_owner_project(
            &owner_proof,
            &vault
                .owner_project_signer(&issuer)
                .expect("owner project signer"),
            vault.root_project().expect("root project"),
        )
        .expect("the owner signs the root project");
    Fixture {
        vault,
        owner,
        issuer,
        owner_proof,
        _dir: dir,
    }
}

impl Fixture {
    /// An owner-born lane project under the root.
    fn lane(&self) -> EntityId {
        let id = EntityId::now();
        let root = self.vault.root_project().expect("root project");
        let mut record = ProjectRecord::new(id, Some(root), root, self.owner).expect("record");
        record.depth_remaining = 2;
        create_owner_project(
            &self.vault,
            &self.issuer,
            &self.owner_proof,
            &self
                .vault
                .owner_project_signer(&self.issuer)
                .expect("owner project signer"),
            self.owner,
            id,
            &record,
        )
        .expect("the owner bears the lane project");
        id
    }

    /// The owner's put of the preset pack; it lands Active.
    fn put(&self, files: Vec<HubFile>) {
        match self.vault.put_pack(&self.owner_proof, files) {
            Ok(PackInstallDisposition::Installed(receipt)) => assert_eq!(receipt.pack_name, PACK),
            other => panic!("the owner's put installs the preset pack: {other:?}"),
        }
    }

    /// The owner's set, with a host that manages every offer.
    fn set(
        &self,
        key: &str,
        lane: EntityId,
        preset: Option<LinePresetRef>,
        policy: GpuLinePolicyFields,
    ) -> Result<GpuLineView, GpuLineError> {
        self.set_checked(key, lane, preset, policy, &|_| Ok(()))
    }

    /// The owner's set, with `offers_managed` as the host's offer check.
    fn set_checked(
        &self,
        key: &str,
        lane: EntityId,
        preset: Option<LinePresetRef>,
        policy: GpuLinePolicyFields,
        offers_managed: &dyn Fn(&GpuLinePolicy) -> Result<(), GpuLineError>,
    ) -> Result<GpuLineView, GpuLineError> {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .set_gpu_line_from_wire(
                Some(&self.owner_proof),
                &GpuLineSetWire {
                    intent_key: key.to_owned(),
                    project: lane,
                    preset,
                    policy,
                },
                offers_managed,
                NOW_MS,
            )
    }
}

#[test]
fn a_line_set_from_a_preset_stores_full_values_and_the_presets_reference() {
    let fx = fixture();
    let lane = fx.lane();
    let files = preset_pack("1.0.0", &open_models_document(345_600));
    let preset = reference(files.clone());
    fx.put(files);

    let view = fx
        .set("from-preset", lane, Some(preset.clone()), stated(300_000))
        .expect("the owner sets the line from the preset");
    let line = &view.line;
    assert_eq!(line.budget, expected_budget(300_000));
    assert_eq!(line.unit, gpu_seconds());
    assert_eq!(line.period_secs, PERIOD_SECS);
    assert_eq!(line.period_anchor_ms, ANCHOR_MS);
    assert_eq!(line.wallet, wallet());
    assert_eq!(line.preset, Some(preset.clone()));
    let stored = fx.vault.gpu_line(&lane).expect("read").expect("the line");
    assert_eq!(stored.budget, expected_budget(300_000));
    assert_eq!(stored.preset, Some(preset));
}

#[test]
fn a_preset_must_be_installed_and_named_by_the_digest_of_its_installed_document() {
    let fx = fixture();
    let lane = fx.lane();
    let files = preset_pack("1.0.0", &open_models_document(345_600));
    let preset = reference(files.clone());

    let refused = fx.set("not-installed", lane, Some(preset.clone()), stated(300_000));
    assert!(
        matches!(refused, Err(GpuLineError::PresetNotInstalled)),
        "{refused:?}"
    );

    fx.put(files);
    let mut wrong = preset.clone();
    wrong.digest = "0".repeat(64);
    match fx.set("wrong-digest", lane, Some(wrong), stated(300_000)) {
        Err(GpuLineError::PresetDigestMismatch { installed }) => {
            assert_eq!(
                installed, preset.digest,
                "the refusal names the installed digest"
            );
        }
        other => panic!("a digest that is not the installed document's is refused: {other:?}"),
    }
    assert!(
        fx.vault.gpu_line(&lane).expect("read").is_none(),
        "a refused preset sets nothing"
    );
}

#[test]
fn a_pack_update_changes_no_line_in_force() {
    let fx = fixture();
    let lane = fx.lane();
    let first = preset_pack("1.0.0", &open_models_document(345_600));
    let preset = reference(first.clone());
    fx.put(first);
    fx.set("from-preset", lane, Some(preset.clone()), stated(300_000))
        .expect("the owner sets the line from the preset");

    let update = preset_pack("1.1.0", &open_models_document(100_000));
    let updated = reference(update.clone());
    assert_ne!(updated.digest, preset.digest);
    fx.put(update);
    let line = fx.vault.gpu_line(&lane).expect("read").expect("the line");
    assert_eq!(
        line.budget,
        expected_budget(300_000),
        "the update moved no value"
    );
    assert_eq!(line.preset, Some(preset.clone()));

    // The old document is no longer installed: naming it is refused.
    assert!(matches!(
        fx.set("old-preset", lane, Some(preset), stated(300_000)),
        Err(GpuLineError::PresetDigestMismatch { .. })
    ));
}

#[test]
fn a_policy_stated_whole_sets_as_before_and_keeps_no_preset() {
    let fx = fixture();
    let lane = fx.lane();
    let mut fields = stated(345_600).0;
    fields.insert("period_secs".to_owned(), json!(PERIOD_SECS));
    fields.insert(
        "budget".to_owned(),
        json!({ "allowance_units": 345_600, "rung_caps_secs": [1_800] }),
    );
    let view = fx
        .set("whole", lane, None, GpuLinePolicyFields(fields))
        .expect("a whole policy sets");
    assert_eq!(view.line.preset, None);
    assert_eq!(view.line.budget.rung_caps_secs, vec![1_800]);
    assert_eq!(
        view.line.budget.pinned_parts,
        (0, 1),
        "the engine's neutral default"
    );
}

#[test]
fn a_preset_document_with_no_budget_reads_as_its_install_checked_it() {
    let fx = fixture();
    let lane = fx.lane();
    // The install accepts a document that states only its period: its unit and budget are the
    // engine's defaults.
    let files = preset_pack("1.0.0", &json!({ "period_secs": PERIOD_SECS }));
    let preset = reference(files.clone());
    fx.put(files);

    // Stating no budget either leaves the allowance with no value: the line's own check
    // refuses it, as for a policy stated whole.
    let mut fields = stated(0).0;
    fields.remove("budget");
    let refused = fx.set(
        "no-allowance",
        lane,
        Some(preset.clone()),
        GpuLinePolicyFields(fields),
    );
    assert!(
        matches!(refused, Err(GpuLineError::Invalid(_))),
        "{refused:?}"
    );

    let mut fields = stated(300_000).0;
    fields.insert(
        "budget".to_owned(),
        json!({ "allowance_units": 300_000, "rung_caps_secs": [1_800] }),
    );
    let view = fx
        .set(
            "allowance",
            lane,
            Some(preset.clone()),
            GpuLinePolicyFields(fields),
        )
        .expect("the owner states the allowance and the rung caps");
    assert_eq!(view.line.unit, gpu_seconds());
    assert_eq!(
        view.line.budget,
        BudgetPolicy {
            allowance_units: 300_000,
            rung_caps_secs: vec![1_800],
            ..BudgetPolicy::default()
        }
    );
    assert_eq!(view.line.preset, Some(preset));
}

#[test]
fn the_hosts_offer_check_reads_the_policy_in_force_inside_the_write() {
    let fx = fixture();
    let lane = fx.lane();
    let files = preset_pack("1.0.0", &open_models_document(345_600));
    let preset = reference(files.clone());
    // The pack is Active before the write opens, as one installed by a concurrent put after
    // an earlier read would be: the owner states no unit, so only the preset gives it.
    fx.put(files);
    let mut fields = stated(300_000).0;
    fields.insert("offers".to_owned(), json!(["not-posted"]));
    let seen = RefCell::new(Vec::new());
    let host_posts_none = |policy: &GpuLinePolicy| {
        seen.borrow_mut()
            .push((policy.unit.clone(), policy.offers.clone()));
        match policy.offers.first() {
            Some(offer) => Err(GpuLineError::OfferNotManaged {
                offer: offer.clone(),
                unit: policy.unit.as_str().to_owned(),
            }),
            None => Ok(()),
        }
    };

    let refused = fx.set_checked(
        "unmanaged",
        lane,
        Some(preset.clone()),
        GpuLinePolicyFields(fields),
        &host_posts_none,
    );
    assert!(
        matches!(&refused, Err(GpuLineError::OfferNotManaged { offer, .. }) if offer == "not-posted"),
        "{refused:?}"
    );
    assert_eq!(
        seen.borrow().as_slice(),
        &[(gpu_seconds(), vec!["not-posted".to_owned()])],
        "the check reads the preset's unit and the stated offers"
    );
    assert!(
        fx.vault.gpu_line(&lane).expect("read").is_none(),
        "an offer the host refuses sets nothing"
    );

    // An applied ask replays before the check: the host's answer to it stands.
    let applied = fx
        .set("applied", lane, Some(preset.clone()), stated(300_000))
        .expect("the owner sets the line from the preset");
    let replayed = fx
        .set_checked("applied", lane, Some(preset), stated(300_000), &|_| {
            panic!("a replay never reaches the host's check")
        })
        .expect("the same ask replays");
    assert_eq!(replayed.line.budget, applied.line.budget);
    assert_eq!(replayed.line.revision, applied.line.revision);
}
