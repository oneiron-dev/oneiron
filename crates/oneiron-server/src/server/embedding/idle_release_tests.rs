//! The idle publisher releases each send to an embedder off this device
//! (census L5-32; DEC-0005 #private-world-vectors: "A private world never
//! falls back to a shared or hosted embedder", and "Without that model, the
//! world has no vectors. Keywords, names, links and time still find it").
//!
//! On unmodified main the idle provider hands an owner-hosted embedder the
//! body of a claim a device-local world keeps. The control: an embedder on
//! this device still embeds that claim.
//!
//! Deterministic: an in-process vault, a recording embedder, no ports, no
//! sleeps, no models.

use std::sync::{Arc, Mutex};

use oneiron::embed::{Embedder, EmbedderLocality, PendingEmbeddingInput};
use oneiron::memory::{IndexedRevisionEmbedder, IndexedRevisionInput, ReadMode};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    TimeRange, Vault, VaultConfig,
};
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;
use oneiron_keystore::MemoryKeystore;

use super::IndexedProvider;
use crate::embedder::QueryEmbedder;

const DIMS: usize = 4;
/// The recording embedder's model, which the vault also names: the idle pass
/// writes the vectors of released rows, and a vector write needs the vault's
/// model identity.
const MODEL_ID: &str = "test/recording@v1";
const KEPT_TEXT: &str = "the lantern key is under the mat";
const OPEN_TEXT: &str = "the ferry leaves at noon";

/// An embedder at `locality` that records the row of every input it embeds.
struct RecordingEmbedder {
    locality: EmbedderLocality,
    embedded: Mutex<Vec<EntityId>>,
}

impl RecordingEmbedder {
    fn at(locality: EmbedderLocality) -> Arc<Self> {
        Arc::new(Self {
            locality,
            embedded: Mutex::new(Vec::new()),
        })
    }

    fn embedded(&self) -> Vec<EntityId> {
        self.embedded.lock().expect("recorded rows").clone()
    }
}

impl Embedder for RecordingEmbedder {
    fn model_id(&self) -> &str {
        MODEL_ID
    }

    fn dimensions(&self) -> usize {
        DIMS
    }

    fn locality(&self) -> EmbedderLocality {
        self.locality
    }

    fn embed(&self, inputs: &[PendingEmbeddingInput]) -> oneiron::Result<Vec<Vec<f32>>> {
        self.embedded
            .lock()
            .expect("recorded rows")
            .extend(inputs.iter().map(|input| input.entity_id));
        let mut unit = vec![0.0; DIMS];
        unit[0] = 1.0;
        Ok(vec![unit; inputs.len()])
    }
}

impl QueryEmbedder for RecordingEmbedder {
    fn embed_query(&self, _text: &str) -> oneiron::Result<Vec<f32>> {
        let mut unit = vec![0.0; DIMS];
        unit[0] = 1.0;
        Ok(unit)
    }

    fn truncations(&self) -> u64 {
        0
    }
}

/// A device vault with the owner's claim `kept` in a world kept on this
/// machine and the owner's claim `open` in base reality.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    world: EntityId,
    kept: EntityId,
    open: EntityId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let mut config = VaultConfig::device();
    config.embedding_model = Some(MODEL_ID.to_owned());
    config.dimensions = DIMS;
    let vault = Vault::open(dir.path(), config).expect("open vault");
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let world = EntityId::from_bytes([0x61; 16]).expect("world id");
    vault
        .put_entity(
            &world,
            oneiron::registry::ENTITY_TYPE_WORLD,
            TimeRange { start: 1, end: 1 },
            1,
            b"world",
        )
        .expect("the world");
    let kept = EntityId::from_bytes([0x62; 16]).expect("kept claim id");
    let open = EntityId::from_bytes([0x63; 16]).expect("open claim id");
    put_claim(&vault, owner, kept, Some(world), KEPT_TEXT);
    put_claim(&vault, owner, open, None, OPEN_TEXT);
    vault
        .keep_world_on_this_machine_for_test(world, true)
        .expect("keep the world on this machine");
    assert_eq!(
        vault
            .rows_released_off_device(&[kept, open])
            .expect("judge the rows"),
        vec![false, true],
        "the kept world holds its claim, base reality does not",
    );
    Fixture {
        _dir: dir,
        vault,
        owner,
        world,
        kept,
        open,
    }
}

/// The owner's claim `id` in `world` (base reality for `None`), saying `text`.
fn put_claim(vault: &Vault, owner: EntityId, id: EntityId, world: Option<EntityId>, text: &str) {
    let mut body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(owner),
        rmpv::Value::from(text),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("claim body");
    body.source = Some(ClaimSource::UserStated);
    body.world = world;
    vault
        .put_claim(&id, &body, TimeRange { start: 10, end: 10 }, 10)
        .expect("store the claim");
}

/// The live revision of `id` as the idle publisher hands it to an embedder.
fn live_revision(vault: &Vault, id: EntityId) -> IndexedRevisionInput {
    let raw = vault
        .get_raw_with_mode(&id, ReadMode::Live)
        .expect("read the live revision")
        .expect("the claim's live revision");
    IndexedRevisionInput {
        entity: id,
        entity_type: raw[0],
        source_revision_ref: vault.pin_entity_revision(&id).expect("pin the revision"),
        body: raw[ENTITY_METADATA_HEADER_LEN..].to_vec(),
        fields: Vec::new(),
    }
}

#[test]
fn an_owner_hosted_embedder_never_receives_a_kept_revision() {
    let host = fixture();
    let embedder = RecordingEmbedder::at(EmbedderLocality::OwnerServer);
    let provider = IndexedProvider {
        provider: embedder.clone(),
        vault: &host.vault,
    };
    let open = provider.embed_revision_marked(&live_revision(&host.vault, host.open));
    assert!(
        open.is_ok(),
        "a base-reality revision still embeds off this device: {open:?}",
    );
    let kept = provider.embed_revision_marked(&live_revision(&host.vault, host.kept));
    assert!(
        !embedder.embedded().contains(&host.kept),
        "a revision a device-local world keeps reached an owner-hosted embedder: {kept:?}",
    );
    assert!(
        matches!(
            &kept,
            Err(oneiron::Error::UpstreamToolFailure { code, .. }) if code == "device_local_row"
        ),
        "the kept revision is refused as a device-local row: {kept:?}",
    );
    assert_eq!(embedder.embedded(), vec![host.open]);
}

#[test]
fn an_embedder_on_this_device_still_embeds_a_kept_revision() {
    let host = fixture();
    let embedder = RecordingEmbedder::at(EmbedderLocality::OnDevice);
    let provider = IndexedProvider {
        provider: embedder.clone(),
        vault: &host.vault,
    };
    let kept = provider.embed_revision_marked(&live_revision(&host.vault, host.kept));
    assert!(kept.is_ok(), "{kept:?}");
    assert_eq!(embedder.embedded(), vec![host.kept]);
}

#[test]
fn idle_publication_keeps_a_kept_revision_from_an_owner_hosted_embedder() {
    let host = fixture();
    // A rewrite leaves the claim's new revision for idle publication.
    put_claim(
        &host.vault,
        host.owner,
        host.kept,
        Some(host.world),
        "the lantern key moved to the shed",
    );
    let live = host
        .vault
        .pin_entity_revision(&host.kept)
        .expect("pin the rewrite");
    assert_ne!(
        host.vault
            .indexed_revision(&host.kept)
            .expect("read the indexed revision"),
        Some(live),
        "the rewrite waits for idle publication",
    );
    host.vault
        .set_indexed_idle_delay_ms(0)
        .expect("no idle delay");
    let embedder = RecordingEmbedder::at(EmbedderLocality::OwnerServer);
    let provider = IndexedProvider {
        provider: embedder.clone(),
        vault: &host.vault,
    };
    let mut published = Vec::new();
    let pass =
        host.vault
            .refresh_indexed_at_idle_with_publication(u64::MAX, &provider, |publication| {
                published.push(publication.entity);
            });
    assert!(
        !embedder.embedded().contains(&host.kept),
        "idle publication sent a revision a device-local world keeps to an owner-hosted embedder: {pass:?}",
    );
    let report = pass.expect("one kept row does not stop the idle pass");
    assert!(
        published.contains(&host.kept),
        "the kept revision publishes with no vector: {report:?}",
    );
    assert_eq!(
        host.vault
            .indexed_revision(&host.kept)
            .expect("read the indexed revision"),
        Some(live),
    );
    assert!(
        host.vault
            .get_vector(&host.kept)
            .expect("read the vector")
            .is_none(),
        "a kept row gets no vector from an embedder off this device",
    );
}
