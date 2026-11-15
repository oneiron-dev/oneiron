//! Restriction wave 13 (census C112), end to end: an owner who raises
//! `organ_host.image.max_ops` past 256 gets a longer edit run by the image
//! organ, not only admitted by the host. The host sends its count with the
//! `image.render` call, and the organ applies it in place of its own
//! default of 256. The defaults themselves are proved by
//! `oneiron-organ-host/tests/image_edit_max_ops.rs` (the host) and
//! `tests/image_ops.rs` (the organ, a call that names no count).
//!
//! `cargo test --locked -p oneiron-image --all-features --test image_edit_owner_max_ops`.
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod fixtures;

use std::sync::Arc;
use std::time::Duration;

use oneiron::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use oneiron::secret_custody::SecretSight;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use oneiron_organ_host::image::{
    ImageEdit, ImageEditRefusal, ImageEdited, ImageOp, edit_image, image_spec,
};
use oneiron_organ_host::{AskHandlers, CallClass, HostConfig, OrganHost, OrganRouter, Submitted};

const ORGAN: &str = env!("CARGO_BIN_EXE_oneiron-image-organ");

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

// Fields drop in order: the organ host, then the vault, then its folder.
struct Fixture {
    router: OrganRouter,
    vault: Vault,
    owner: EntityId,
    _dir: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open_unseeded_for_test(dir.path(), config).expect("open vault");
    // The vault has no authority root, so its embedded owner keeps as the owner.
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let host = Arc::new(OrganHost::new(HostConfig::default()));
    host.install(image_spec(ORGAN));
    Fixture {
        router: OrganRouter::new().with_local(host),
        vault,
        owner,
        _dir: dir,
    }
}

impl Fixture {
    fn actor(&self) -> WriteActor {
        WriteActor::new(self.owner, EdgeActorClass::Human)
    }

    fn set_owner_key(&self, key: &str, n: u32) {
        let owner_proof = self
            .vault
            .authenticate_owner(self.owner, "principal:owner", true, GateDecisionId::now())
            .expect("owner proof");
        let outcome = self
            .vault
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

    fn png_artifact(&self, w: u32, h: u32) -> EntityId {
        let bytes = fixtures::png(
            w,
            h,
            &fixtures::pixels(w, h, fixtures::coded),
            fixtures::Extra::default(),
        );
        let artifact = EntityId::now();
        self.vault
            .put_blob_artifact(
                &artifact,
                &BlobArtifactBody::new("photo.png", "image/png"),
                at(1),
                1,
            )
            .expect("artifact");
        self.vault
            .append_blob_artifact_version(
                &artifact,
                &bytes,
                &BlobVersionProvenance::UserUpload,
                self.actor(),
                at(2),
                2,
            )
            .expect("version");
        artifact
    }

    fn edit(
        &self,
        artifact: EntityId,
        ops: Vec<ImageOp>,
        run_ref: &str,
    ) -> Result<ImageEdited, ImageEditRefusal> {
        let edit = ImageEdit {
            artifact,
            version: None,
            ops,
            run_ref: run_ref.to_owned(),
            trigger: None,
            submitter: None,
            // The test's vault holds no secret marks, so every sight reads the stored bytes.
            sight: SecretSight::Owner,
            grant: "photo-edit".to_owned(),
            class: CallClass::Interactive,
            deadline: Duration::from_secs(20),
        };
        edit_image(
            &self.router,
            &self.vault,
            &edit,
            self.actor(),
            &AskHandlers::none(),
        )
    }
}

/// `n` crops of the whole 9x7 canvas: each keeps every pixel.
fn whole_crops(n: usize) -> Vec<ImageOp> {
    vec![
        ImageOp::Crop {
            x: 0,
            y: 0,
            w: 9,
            h: 7
        };
        n
    ]
}

#[test]
fn owner_op_count_runs_a_257_op_edit_through_the_organ() {
    let f = fixture();
    f.set_owner_key("organ_host.image.max_ops", 300);
    let artifact = f.png_artifact(9, 7);

    let edited = match f.edit(artifact, whole_crops(257), "ops-257") {
        Ok(edited) => edited,
        Err(err) => panic!("the organ runs the 257 ops the owner's count admits: {err}"),
    };
    let Submitted::Landed { mut proposals, .. } = edited.submitted else {
        panic!("the edit ran on this host and landed");
    };
    assert_eq!(proposals.len(), 1, "one proposal for the whole edit");
    let proposal = proposals.remove(0);
    assert_eq!(proposal.proposal_ref, "ops-257");
    // The body the organ rendered rides in the proposal's report: every op applied.
    let body = &proposal.summary["report"]["report"]["body"];
    assert_eq!(body["steps"].as_array().map(Vec::len), Some(257), "{body}");
    assert_eq!(body["canvas"]["w"].as_u64(), Some(9), "{body}");
    assert_eq!(body["canvas"]["h"].as_u64(), Some(7), "{body}");

    // The owner's count still bounds an edit: one op past it is refused
    // before the organ runs.
    let refusal = f
        .edit(artifact, whole_crops(301), "ops-301")
        .expect_err("past the owner's count");
    assert!(
        matches!(refusal, ImageEditRefusal::TooManyOps { count: 301, .. }),
        "{refusal:?}"
    );
    // The message names the owner's count (the base's variant has no `max` field to match).
    assert_eq!(
        refusal.to_string(),
        "an edit names at most 300 ops, not 301"
    );
}
