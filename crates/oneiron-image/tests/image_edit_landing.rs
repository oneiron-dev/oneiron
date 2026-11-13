//! An image artifact's edit through the image organ's host adapter
//! (`oneiron_organ_host::image`, L4-15): the organ runs as its own process
//! behind the host, over a real vault, and the PNG it exports waits as one
//! proposal until the owner keeps it. A JPEG artifact's edit lands on a new
//! PNG artifact born from it (RULING 09:34 Fri 13 Nov, IO-FORMAT B). With no
//! node to run it, the whole edit is one held call, and a redrive on a host
//! that runs the organ lands it (RULING 09:53, IO-HOLD C).
#![cfg(unix)]

mod fixtures;

use std::sync::Arc;
use std::time::Duration;

use oneiron::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use oneiron::edit_settle::{PendingProposalView, SettleConsent};
use oneiron::secret_custody::SecretSight;
use oneiron::{EdgeActorClass, EdgeKind, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use oneiron_organ_host::image::{
    ImageEdit, ImageEditRefusal, ImageEdited, ImageOp, ResizeFilter, edit_image, image_spec,
};
use oneiron_organ_host::{
    AskHandlers, CallClass, HostConfig, OrganHost, OrganRouter, Redrive, Submitted,
};

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

    fn artifact(&self, name: &str, media_type: &str, bytes: &[u8]) -> EntityId {
        let artifact = EntityId::now();
        self.vault
            .put_blob_artifact(
                &artifact,
                &BlobArtifactBody::new(name, media_type),
                at(1),
                1,
            )
            .expect("artifact");
        self.vault
            .append_blob_artifact_version(
                &artifact,
                bytes,
                &BlobVersionProvenance::UserUpload,
                self.actor(),
                at(2),
                2,
            )
            .expect("version");
        artifact
    }

    fn edit_through(
        &self,
        router: &OrganRouter,
        artifact: EntityId,
        version: Option<u64>,
        ops: Vec<ImageOp>,
        run_ref: &str,
    ) -> Result<ImageEdited, ImageEditRefusal> {
        let edit = ImageEdit {
            artifact,
            version,
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
            router,
            &self.vault,
            &edit,
            self.actor(),
            &AskHandlers::none(),
        )
    }

    fn edit(
        &self,
        artifact: EntityId,
        ops: Vec<ImageOp>,
        run_ref: &str,
    ) -> Result<ImageEdited, ImageEditRefusal> {
        self.edit_through(&self.router, artifact, None, ops, run_ref)
    }

    /// The owner keeps `proposal_ref`; answers the version it became.
    fn keep(&self, artifact: EntityId, proposal_ref: &str) -> u64 {
        let now = self.vault.now_recorded_at();
        self.vault
            .keep_pending_proposal(
                &artifact,
                proposal_ref,
                &SettleConsent::OwnerConsent { brief_ref: None },
                self.actor(),
                at(now),
                now,
            )
            .expect("the owner keeps the proposal")
            .version
            .version
    }

    fn head(&self, artifact: EntityId) -> Option<u64> {
        self.vault
            .blob_artifact_head(&artifact)
            .expect("head")
            .map(|head| head.version)
    }

    fn png_of(&self, artifact: EntityId, version: u64) -> image::RgbaImage {
        let bytes = self
            .vault
            .read_blob_artifact_version(&artifact, version)
            .expect("read")
            .expect("the kept version");
        fixtures::decode_png(&bytes)
    }

    /// Redrives every held call through this host, which runs the organ:
    /// the one proposal it landed beside `artifact` under `run_ref`.
    fn redrive(&self, artifact: EntityId, run_ref: &str) -> PendingProposalView {
        let mut redriven = self
            .router
            .redrive_waiting(&self.vault, &AskHandlers::none())
            .expect("redrive");
        assert_eq!(redriven.len(), 1, "one call was held");
        let one = redriven.remove(0);
        assert_eq!((one.artifact, one.run_ref.as_str()), (artifact, run_ref));
        let mut proposals = match one.state {
            Redrive::Landed(proposals) => proposals,
            other => panic!("the redrive ran the edit here and landed it: {other:?}"),
        };
        assert_eq!(proposals.len(), 1, "one proposal for the whole edit");
        assert!(
            self.vault.organ_waits(&artifact).expect("waits").is_empty(),
            "the hold is released"
        );
        proposals.remove(0)
    }

    fn nothing_waits(&self, artifact: EntityId) {
        assert_eq!(
            self.vault
                .pending_proposals(&artifact)
                .expect("proposals")
                .len(),
            0,
            "no proposal waits"
        );
        assert_eq!(
            self.vault.waiting_organ_calls().expect("held calls").len(),
            0,
            "no call is held"
        );
    }
}

/// The one proposal a landed edit made.
fn landed(edited: ImageEdited) -> PendingProposalView {
    let Submitted::Landed { mut proposals, .. } = edited.submitted else {
        panic!("the edit ran on this host and landed");
    };
    assert_eq!(proposals.len(), 1, "one proposal for the whole edit");
    proposals.remove(0)
}

fn coded_png(w: u32, h: u32) -> Vec<u8> {
    fixtures::png(
        w,
        h,
        &fixtures::pixels(w, h, fixtures::coded),
        fixtures::Extra::default(),
    )
}

#[test]
fn a_crop_of_a_png_artifact_waits_as_one_proposal_and_keep_makes_it_version_2() {
    let f = fixture();
    let artifact = f.artifact("photo.png", "image/png", &coded_png(9, 7));
    let crop = ImageOp::Crop {
        x: 2,
        y: 1,
        w: 6,
        h: 5,
    };
    let edited = match f.edit(artifact, vec![crop], "crop-1") {
        Ok(edited) => edited,
        Err(err) => panic!("FAILBEFORE: the crop of a PNG artifact lands: {err}"),
    };
    assert_eq!(
        edited.artifact, artifact,
        "a PNG artifact's edit lands on it"
    );
    assert!(!edited.born);
    let proposal = landed(edited);
    assert_eq!(proposal.proposal_ref, "crop-1");
    assert_eq!(proposal.base_version, Some(1), "made against the head");
    assert_eq!(f.head(artifact), Some(1), "nothing lands before Keep");
    // The body the organ rendered rides in the proposal's report.
    let body = &proposal.summary["report"]["report"]["body"];
    assert_eq!(body["canvas"]["w"].as_u64(), Some(6), "{body}");
    assert_eq!(body["canvas"]["h"].as_u64(), Some(5));
    assert_eq!(body["steps"][0]["crop"]["x"].as_u64(), Some(2));

    assert_eq!(f.keep(artifact, "crop-1"), 2);
    assert_eq!(f.head(artifact), Some(2));
    let image = f.png_of(artifact, 2);
    assert_eq!(image.dimensions(), (6, 5));
    for (x, y, pixel) in image.enumerate_pixels() {
        assert_eq!(pixel.0, fixtures::coded(x + 2, y + 1), "pixel {x},{y}");
    }
    f.nothing_waits(artifact);
}

#[test]
fn a_crop_then_a_resize_lands_one_proposal_at_the_resized_size() {
    let f = fixture();
    let artifact = f.artifact("photo.png", "image/png", &coded_png(12, 10));
    let ops = vec![
        ImageOp::Crop {
            x: 0,
            y: 0,
            w: 8,
            h: 6,
        },
        ImageOp::Resize {
            w: 4,
            h: 3,
            filter: ResizeFilter::Bilinear,
        },
    ];
    let edited = match f.edit(artifact, ops, "resize-1") {
        Ok(edited) => edited,
        Err(err) => panic!("FAILBEFORE: a crop then a resize lands: {err}"),
    };
    let proposal = landed(edited);
    let body = &proposal.summary["report"]["report"]["body"];
    assert_eq!(body["steps"].as_array().map(Vec::len), Some(2), "{body}");
    assert_eq!(
        body["steps"][1]["resize"]["filter"].as_str(),
        Some("bilinear")
    );

    assert_eq!(f.keep(artifact, "resize-1"), 2);
    assert_eq!(f.png_of(artifact, 2).dimensions(), (4, 3));
    // The first version is still there, as it was.
    assert_eq!(f.png_of(artifact, 1).dimensions(), (12, 10));
}

#[test]
fn a_crop_of_a_jpeg_artifact_lands_on_a_new_png_artifact_born_from_it() {
    let f = fixture();
    let jpeg = fixtures::jpeg_flat(8, 6, [200, 40, 40], None);
    let source = f.artifact("photo.jpg", "image/jpeg", &jpeg);
    let crop = ImageOp::Crop {
        x: 1,
        y: 1,
        w: 4,
        h: 3,
    };
    let edited = match f.edit(source, vec![crop], "crop-jpeg") {
        Ok(edited) => edited,
        Err(err) => panic!("FAILBEFORE: the crop of a JPEG artifact lands: {err}"),
    };
    assert!(edited.born, "the PNG lands on a new artifact");
    let born = edited.artifact;
    assert_ne!(born, source);
    let body = f
        .vault
        .get_blob_artifact(&born)
        .expect("read")
        .expect("the new artifact");
    assert_eq!(body.media_type, "image/png");
    assert_eq!(body.name, "photo.png");
    assert_eq!(
        f.vault
            .targets(&born, EdgeKind::DerivedFrom, None)
            .expect("edges"),
        vec![source],
        "the new artifact is derived from the source"
    );
    let proposal = landed(edited);
    assert_eq!(
        proposal.base_version, None,
        "the new artifact has no version yet"
    );
    let made_by = proposal.made_by.expect("the receipt's made_by");
    assert!(
        made_by.inputs.iter().any(|input| input.row == source),
        "the proposal names the source it read: {made_by:?}"
    );
    assert_eq!(f.head(born), None, "nothing lands before Keep");

    assert_eq!(f.keep(born, "crop-jpeg"), 1);
    let image = f.png_of(born, 1);
    assert_eq!(image.dimensions(), (4, 3));
    for pixel in image.pixels() {
        let [r, g, b, a] = pixel.0;
        assert_eq!(a, 255);
        assert!(
            r.abs_diff(200) <= 8 && g.abs_diff(40) <= 8 && b.abs_diff(40) <= 8,
            "{:?}",
            pixel.0
        );
    }
    // The source stays as it was: one version, nothing waiting beside it.
    assert_eq!(
        f.vault
            .blob_artifact_versions(&source)
            .expect("versions")
            .len(),
        1
    );
    f.nothing_waits(source);
}

#[test]
fn a_16_bit_png_gives_the_organs_unsupported_and_nothing_waits() {
    let f = fixture();
    let artifact = f.artifact("deep.png", "image/png", &fixtures::png_rgb16(2, 2));
    let crop = ImageOp::Crop {
        x: 0,
        y: 0,
        w: 1,
        h: 1,
    };
    let refusal = match f.edit(artifact, vec![crop], "crop-deep") {
        Ok(edited) => panic!("a 16-bit PNG is not edited: {edited:?}"),
        Err(refusal) => refusal,
    };
    assert_eq!(
        refusal.code(),
        "unsupported",
        "FAILBEFORE: the organ's own refusal comes back: {refusal}"
    );
    assert!(matches!(refusal, ImageEditRefusal::Organ(_)));
    assert_eq!(f.head(artifact), Some(1));
    f.nothing_waits(artifact);
}

#[test]
fn an_edit_the_adapter_cannot_run_is_refused_with_its_reason_and_nothing_waits() {
    let f = fixture();
    let artifact = f.artifact("photo.png", "image/png", &coded_png(4, 4));
    let crop = ImageOp::Crop {
        x: 0,
        y: 0,
        w: 2,
        h: 2,
    };
    let code = |result: Result<ImageEdited, ImageEditRefusal>| match result {
        Ok(edited) => panic!("refused, not {edited:?}"),
        Err(refusal) => refusal.code(),
    };
    assert_eq!(
        code(f.edit(artifact, Vec::new(), "none")),
        "no_ops",
        "FAILBEFORE: an edit with no ops is refused as such"
    );
    assert_eq!(
        code(f.edit(artifact, vec![crop; 257], "many")),
        "too_many_ops"
    );
    assert_eq!(
        code(f.edit_through(&f.router, artifact, Some(9), vec![crop], "gone")),
        "not_found"
    );
    let text = f.artifact("notes.txt", "text/plain", b"not an image");
    assert_eq!(code(f.edit(text, vec![crop], "text")), "not_an_image");
    assert_eq!(f.head(artifact), Some(1));
    f.nothing_waits(artifact);
}

#[test]
fn with_no_node_the_whole_edit_is_held_and_a_redrive_lands_it_as_one_proposal() {
    let f = fixture();
    let artifact = f.artifact("photo.png", "image/png", &coded_png(9, 7));
    let crop = ImageOp::Crop {
        x: 2,
        y: 1,
        w: 6,
        h: 5,
    };
    // No host here and no mesh: no node can run the edit now.
    let nowhere = OrganRouter::new();
    let edited = match f.edit_through(&nowhere, artifact, None, vec![crop], "held-1") {
        Ok(edited) => edited,
        Err(err) => panic!("FAILBEFORE: with no node the whole edit is held: {err}"),
    };
    assert_eq!(edited.artifact, artifact);
    assert!(!edited.born);
    let wait = match edited.submitted {
        Submitted::Waiting(wait) => wait,
        Submitted::Landed { .. } => panic!("no node runs it, so nothing lands"),
    };
    assert_eq!(
        (
            wait.organ.as_str(),
            wait.verb.as_str(),
            wait.run_ref.as_str()
        ),
        ("image", "image.render", "held-1"),
        "the whole edit is one held call"
    );
    assert!(wait.reason.contains("image.render"), "{}", wait.reason);
    assert_eq!(f.vault.organ_waits(&artifact).expect("waits").len(), 1);
    assert_eq!(
        f.vault
            .pending_proposals(&artifact)
            .expect("proposals")
            .len(),
        0,
        "nothing waits for Keep while the edit is held"
    );
    assert_eq!(f.head(artifact), Some(1));

    // This host runs the organ: the redrive lands the edit as if it had run at once.
    let proposal = f.redrive(artifact, "held-1");
    assert_eq!(proposal.proposal_ref, "held-1");
    assert_eq!(proposal.base_version, Some(1), "made against the head");
    let body = &proposal.summary["report"]["report"]["body"];
    assert_eq!(body["canvas"]["w"].as_u64(), Some(6), "{body}");
    assert_eq!(f.head(artifact), Some(1), "nothing lands before Keep");

    assert_eq!(f.keep(artifact, "held-1"), 2);
    let image = f.png_of(artifact, 2);
    assert_eq!(image.dimensions(), (6, 5));
    for (x, y, pixel) in image.enumerate_pixels() {
        assert_eq!(pixel.0, fixtures::coded(x + 2, y + 1), "pixel {x},{y}");
    }
    f.nothing_waits(artifact);
}

#[test]
fn a_held_jpeg_edit_waits_beside_its_new_png_artifact_and_lands_there() {
    let f = fixture();
    let jpeg = fixtures::jpeg_flat(8, 6, [200, 40, 40], None);
    let source = f.artifact("photo.jpg", "image/jpeg", &jpeg);
    let crop = ImageOp::Crop {
        x: 1,
        y: 1,
        w: 4,
        h: 3,
    };
    let nowhere = OrganRouter::new();
    let edited = match f.edit_through(&nowhere, source, None, vec![crop], "held-jpeg") {
        Ok(edited) => edited,
        Err(err) => panic!("FAILBEFORE: with no node the JPEG's edit is held: {err}"),
    };
    assert!(
        matches!(edited.submitted, Submitted::Waiting(_)),
        "{:?}",
        edited.submitted
    );
    assert!(
        edited.born,
        "the new PNG artifact is made as the edit is held"
    );
    let born = edited.artifact;
    assert_ne!(born, source);
    let body = f
        .vault
        .get_blob_artifact(&born)
        .expect("read")
        .expect("the new artifact");
    assert_eq!(
        (body.name.as_str(), body.media_type.as_str()),
        ("photo.png", "image/png")
    );
    assert_eq!(
        f.vault
            .targets(&born, EdgeKind::DerivedFrom, None)
            .expect("edges"),
        vec![source],
        "the new artifact is derived from the source"
    );
    assert_eq!(
        f.vault.organ_waits(&born).expect("waits").len(),
        1,
        "the edit waits beside the new artifact"
    );
    assert!(
        f.vault.organ_waits(&source).expect("waits").is_empty(),
        "nothing waits beside the source"
    );
    assert_eq!(f.head(born), None);

    let proposal = f.redrive(born, "held-jpeg");
    assert_eq!(
        proposal.base_version, None,
        "the new artifact has no version yet"
    );
    let made_by = proposal.made_by.expect("the receipt's made_by");
    assert!(
        made_by.inputs.iter().any(|input| input.row == source),
        "the proposal names the source it read: {made_by:?}"
    );
    assert_eq!(f.keep(born, "held-jpeg"), 1);
    assert_eq!(f.png_of(born, 1).dimensions(), (4, 3));
    assert_eq!(
        f.vault
            .blob_artifact_versions(&source)
            .expect("versions")
            .len(),
        1,
        "the source stays as it was"
    );
    f.nothing_waits(source);
    f.nothing_waits(born);
}
