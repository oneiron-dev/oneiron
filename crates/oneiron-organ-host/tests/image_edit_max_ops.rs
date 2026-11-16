//! Restriction wave 13: the image edit op count is an owner key.
//!
//! Guards prove today's default (256 ops); the owner test sets
//! `organ_host.image.max_ops` to 300. Every edit names a missing artifact,
//! so the run stops at the count check or at NotFound before any organ call.
//!
//! `cargo test --locked -p oneiron-organ-host --all-features --test image_edit_max_ops`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::secret_custody::SecretSight;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use oneiron_organ_host::image::{ImageEdit, ImageEditRefusal, ImageOp, edit_image};
use oneiron_organ_host::{AskHandlers, CallClass, OrganRouter};

fn test_time(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    (dir, vault)
}

fn put_actor(vault: &Vault) -> WriteActor {
    let actor_id = EntityId::now();
    vault
        .put_entity(&actor_id, ENTITY_TYPE_PERSON, test_time(1), 1, b"human")
        .expect("put actor");
    WriteActor::new(actor_id, EdgeActorClass::Human)
}

fn set_owner_key(vault: &Vault, key: &str, n: u32) {
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the vault's owner");
    let owner_proof = vault
        .authenticate_owner(owner, "principal:owner", true, GateDecisionId::now())
        .expect("owner proof");
    let outcome = vault
        .set_setting(
            SettingCaller::Owner(&owner_proof),
            // The JSON number n (serde_json's From<u32>), without naming serde_json.
            SetSetting::vault_value(key, n.into()),
        )
        .expect("the owner sets the key");
    assert!(
        matches!(outcome, SetSettingOutcome::Applied { .. }),
        "{outcome:?}"
    );
}

fn crops(n: usize) -> Vec<ImageOp> {
    vec![
        ImageOp::Crop {
            x: 0,
            y: 0,
            w: 1,
            h: 1
        };
        n
    ]
}

fn edit_of(artifact: EntityId, ops: Vec<ImageOp>) -> ImageEdit {
    ImageEdit {
        artifact,
        version: None,
        ops,
        run_ref: "max-ops-probe".to_owned(),
        trigger: None,
        submitter: None,
        sight: SecretSight::Owner,
        grant: "image-edit-test".to_owned(),
        class: CallClass::Interactive,
        deadline: Duration::from_secs(20),
    }
}

#[test]
fn an_edit_of_257_ops_is_refused_by_default() {
    let (_dir, vault) = open_vault();
    let actor = put_actor(&vault);
    let router = OrganRouter::new();
    let edit = edit_of(EntityId::now(), crops(257));
    let refusal =
        edit_image(&router, &vault, &edit, actor, &AskHandlers::none()).expect_err("refused");
    assert!(
        matches!(refusal, ImageEditRefusal::TooManyOps { count: 257, .. }),
        "{refusal:?}"
    );
    assert_eq!(refusal.code(), "too_many_ops");
}

#[test]
fn an_edit_of_256_ops_passes_the_count_by_default() {
    let (_dir, vault) = open_vault();
    let actor = put_actor(&vault);
    let router = OrganRouter::new();
    let edit = edit_of(EntityId::now(), crops(256));
    let refusal =
        edit_image(&router, &vault, &edit, actor, &AskHandlers::none()).expect_err("not found");
    assert!(matches!(refusal, ImageEditRefusal::NotFound), "{refusal:?}");
}

#[test]
fn owner_op_count_admits_a_longer_edit() {
    let (_dir, vault) = open_vault();
    set_owner_key(&vault, "organ_host.image.max_ops", 300);
    let actor = put_actor(&vault);
    let router = OrganRouter::new();
    let edit = edit_of(EntityId::now(), crops(257));
    let refusal =
        edit_image(&router, &vault, &edit, actor, &AskHandlers::none()).expect_err("not found");
    assert!(matches!(refusal, ImageEditRefusal::NotFound), "{refusal:?}");
}
