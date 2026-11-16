//! DEC-0005 #private-world-vectors: a private world's optional small local model
//! owns its text vectors; its rows never fall back to the vault or a hosted embedder.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test world_small_embedding_model`
#![cfg(all(feature = "sync", oneiron_test_support))]

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use oneiron::authority::{
    ActSurface, MachineOwnership, MachineRole, ModelOrder, ReadLocation, SealedCopies,
    WORLD_MODEL_ROUTE_MAX_BYTES, WorldPrivacy,
};
use oneiron::claim::{base_world_id, default_project_id};
use oneiron::consent::AuthenticatedOwner;
use oneiron::embed::{
    EMBEDDING_SPACE_ID_MAX_LEN, EgressDecision, EgressPredicate, Embedder, EmbedderLocality,
    EmbeddingSpace, InputKind, MediaEmbedder, MediaEmbeddingInput, PendingEmbeddingInput,
    PendingEmbeddingReconciler, RemoteRung, payload_text,
};
use oneiron::memory::{AllRelationships, ClaimRelationships, ClaimScope, ScopedClaimInput};
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::json;

const WORLD_SPACE_ID: &str = "local/tiny-test@0123456789abcdef0123456789abcdef01234567@device";
const VAULT_MODEL_ID: &str = "test/vault-text@v1";
const DIMENSIONS: usize = 8;

fn text_vector(bytes: &[u8]) -> Vec<f32> {
    let mut vector = vec![1.0; DIMENSIONS];
    for (index, byte) in bytes.iter().enumerate() {
        vector[index % DIMENSIONS] += f32::from(*byte) / 256.0;
    }
    vector
}

struct RecordingVaultEmbedder {
    locality: EmbedderLocality,
    seen: Mutex<Vec<EntityId>>,
}

impl RecordingVaultEmbedder {
    fn new(locality: EmbedderLocality) -> Self {
        Self {
            locality,
            seen: Mutex::new(Vec::new()),
        }
    }

    fn seen(&self) -> Vec<EntityId> {
        self.seen
            .lock()
            .expect("text embedder recording lock")
            .clone()
    }
}

impl Embedder for RecordingVaultEmbedder {
    fn model_id(&self) -> &str {
        VAULT_MODEL_ID
    }

    fn dimensions(&self) -> usize {
        DIMENSIONS
    }

    fn locality(&self) -> EmbedderLocality {
        self.locality
    }

    fn embed(&self, inputs: &[PendingEmbeddingInput]) -> oneiron::Result<Vec<Vec<f32>>> {
        self.seen
            .lock()
            .expect("record text embedder inputs")
            .extend(inputs.iter().map(|input| input.entity_id));
        inputs
            .iter()
            .map(|input| payload_text(&input.payload).map(|text| text_vector(text.as_bytes())))
            .collect()
    }
}

#[derive(Default)]
struct FixedTextEmbedder {
    seen: Mutex<Vec<EntityId>>,
}

impl MediaEmbedder for FixedTextEmbedder {
    fn space_id(&self) -> &str {
        WORLD_SPACE_ID
    }

    fn dimensions(&self) -> usize {
        DIMENSIONS
    }

    fn locality(&self) -> EmbedderLocality {
        EmbedderLocality::OnDevice
    }

    fn embed_media(&self, inputs: &[MediaEmbeddingInput<'_>]) -> oneiron::Result<Vec<Vec<f32>>> {
        self.seen
            .lock()
            .expect("record world-space embedder inputs")
            .extend(inputs.iter().map(|input| input.entity_id));
        Ok(inputs
            .iter()
            .map(|input| text_vector(input.bytes))
            .collect())
    }
}

struct AllowAll;

impl EgressPredicate for AllowAll {
    fn decide(&self, _input: &PendingEmbeddingInput) -> EgressDecision {
        EgressDecision::Allow
    }
}

fn text_space(id: &str) -> EmbeddingSpace {
    EmbeddingSpace {
        id: id.to_owned(),
        dimensions: DIMENSIONS,
        accepts: BTreeSet::from([InputKind::Text]),
        query_towers: BTreeSet::from([InputKind::Text]),
        evidence: None,
    }
}

fn private_settings(models: ModelOrder) -> WorldPrivacy {
    WorldPrivacy {
        read: ReadLocation::MyMachines,
        sealed: SealedCopies::MyMachines,
        models,
    }
}

struct WorldSpaceFixture {
    vault: Arc<Vault>,
    owner: AuthenticatedOwner,
    world: EntityId,
    world_claim: EntityId,
    base_claim: EntityId,
    primary: Arc<RecordingVaultEmbedder>,
    _dir: tempfile::TempDir,
}

impl WorldSpaceFixture {
    fn reconciler(&self) -> PendingEmbeddingReconciler {
        PendingEmbeddingReconciler::new(Arc::clone(&self.vault), self.primary.clone())
    }

    fn set_models(&self, models: ModelOrder) {
        self.vault
            .set_world_privacy_as(
                &self.owner,
                ActSurface::ThisInstall,
                self.world,
                private_settings(models),
                None,
            )
            .expect("owner updates the world's model order");
    }
}

fn world_space_fixture() -> WorldSpaceFixture {
    let dir = tempfile::tempdir().expect("temporary world-space vault directory");
    let mut config = VaultConfig::device();
    config.dimensions = DIMENSIONS;
    config.embedding_model = Some(VAULT_MODEL_ID.to_owned());
    let vault = Arc::new(Vault::open(dir.path(), config).expect("fresh world-space vault"));
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault
        .prepare_install_signing()
        .expect("install signing key");
    let person = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let issuer = vault
        .bootstrap_host_slip_issuer()
        .expect("host slip issuer");
    vault
        .ensure_host_root_slip(&issuer)
        .expect("host root slip");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Owned(MachineOwnership::Yours))
        .expect("this install is one of the owner's machines");
    let owner = vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("authenticated owner");
    let at = vault.now_recorded_at();
    let world = vault
        .create_world(&owner, "Private text world", at)
        .expect("owner creates the private world");
    vault
        .declare_embedding_space(&owner, text_space(WORLD_SPACE_ID))
        .expect("owner declares the small on-device text space");
    let fixture = WorldSpaceFixture {
        vault,
        owner,
        world,
        world_claim: EntityId::now(),
        base_claim: EntityId::now(),
        primary: Arc::new(RecordingVaultEmbedder::new(EmbedderLocality::OnDevice)),
        _dir: dir,
    };
    fixture.set_models(ModelOrder::Ordered(vec![WORLD_SPACE_ID.to_owned()]));
    // The normal opener seeds claims; settle those before the two rows under test exist.
    fixture
        .reconciler()
        .with_batch_size(usize::MAX)
        .reconcile_once()
        .expect("embed bootstrap claims before writing A and B");
    fixture
        .primary
        .seen
        .lock()
        .expect("clear bootstrap inputs")
        .clear();
    let facet = fixture.vault.default_facet().expect("owner default facet");
    for (id, world_id, text) in [
        (
            fixture.world_claim,
            world,
            "private-world text for the small model",
        ),
        (
            fixture.base_claim,
            base_world_id(),
            "base-world text for the vault model",
        ),
    ] {
        fixture
            .vault
            .memory(person, EdgeActorClass::Human)
            .with_owner_authorship(&fixture.owner)
            .claim_upsert_scoped(&ScopedClaimInput {
                id: Some(id.to_hex()),
                predicate: "profile.preference".to_owned(),
                subject_ref: person.to_hex(),
                value: json!(text),
                confidence: 1.0,
                source: "user_stated".to_owned(),
                scope: ClaimScope {
                    world_id: world_id.to_hex(),
                    scope_facet_id: facet.to_hex(),
                    scope_relationship_id: ClaimRelationships::All(AllRelationships::All),
                    scope_project_id: default_project_id().to_hex(),
                },
                sensitivity: None,
                evidence_turn_refs: Vec::new(),
                valid_from: None,
                valid_to: None,
                occurred_at: Some(at),
                learned_at: Some(at),
                salience: None,
            })
            .expect("owner writes a text claim in its requested world");
    }
    fixture
}

#[test]
fn world_rows_embed_only_in_their_own_small_space() {
    let fixture = world_space_fixture();
    let report = fixture
        .reconciler()
        .reconcile_once()
        .expect("vault text pass");
    assert_eq!(
        report.world_space, 1,
        "A stays pending for its world's space"
    );
    assert_eq!(report.embedded, 1, "only base claim B uses the vault index");
    assert_eq!(report.leased, 1, "A is not leased for the vault index");
    assert_eq!(fixture.primary.seen(), vec![fixture.base_claim]);

    let bindings = fixture
        .vault
        .kind_slot_bindings()
        .expect("kind slot bindings");
    assert_eq!(bindings.space_for(InputKind::Text), None);
    assert_eq!(bindings.space_for(InputKind::Image), None);
    assert_eq!(bindings.space_for(InputKind::Audio), None);
    let fixed = FixedTextEmbedder::default();
    let media = fixture
        .vault
        .reconcile_media_embeddings(&fixed, 64)
        .expect("the world's text space fills without a kind slot binding");
    assert_eq!(
        media.embedded, 1,
        "only world claim A fills the small space"
    );
    assert_eq!(
        *fixed.seen.lock().expect("world-space embedder inputs"),
        vec![fixture.world_claim],
        "B is never handed to the world's embedder",
    );
    assert_eq!(
        fixture
            .vault
            .world_text_space(fixture.world)
            .expect("world text space"),
        Some(text_space(WORLD_SPACE_ID)),
    );
    let inheriting = fixture
        .vault
        .create_world(
            &fixture.owner,
            "Inheriting world",
            fixture.vault.now_recorded_at(),
        )
        .expect("owner creates a world that inherits");
    assert_eq!(
        fixture
            .vault
            .world_text_space(inheriting)
            .expect("inherited text space"),
        None
    );
}

#[test]
fn world_space_never_falls_back() {
    let fixture = world_space_fixture();
    let remote = Arc::new(RecordingVaultEmbedder::new(EmbedderLocality::ThirdParty));
    let reconciler = fixture
        .reconciler()
        .with_remote_rung(RemoteRung::new(remote.clone(), Arc::new(AllowAll)))
        .expect("public remote rung with an allow-all egress predicate");
    let report = reconciler
        .reconcile_once()
        .expect("text pass with a remote rung");
    assert_eq!(
        report.world_space, 1,
        "A never reaches any vault-index rung"
    );
    assert_eq!(report.leased, 1, "only B is leased");
    assert_eq!(report.embedded, 1);
    assert_eq!(
        report.routed_remote, 1,
        "B proves the remote rung is active"
    );
    assert_eq!(
        remote.seen(),
        vec![fixture.base_claim],
        "the remote rung never sees A"
    );
    assert!(
        fixture.primary.seen().is_empty(),
        "A never falls back to the primary either"
    );
}

#[test]
fn order_back_to_inherit_requeues_for_vault_index() {
    let fixture = world_space_fixture();
    let reconciler = fixture.reconciler();
    let before = reconciler
        .reconcile_once()
        .expect("text pass with a world space");
    assert_eq!(before.world_space, 1, "A stays pending for the small model");
    assert_eq!(before.embedded, 1, "only B embeds before the order change");
    assert_eq!(fixture.primary.seen(), vec![fixture.base_claim]);

    fixture.set_models(ModelOrder::Inherit);
    assert_eq!(
        fixture
            .vault
            .world_text_space(fixture.world)
            .expect("inherited world text space"),
        None
    );
    let after = reconciler
        .reconcile_once()
        .expect("text pass after inheriting");
    assert_eq!(after.world_space, 0);
    assert_eq!(after.embedded, 1, "A now embeds without a lease wait");
    assert_eq!(after.leased, 1);
    assert_eq!(after.active_leases, 0);
    assert_eq!(
        fixture.primary.seen(),
        vec![fixture.base_claim, fixture.world_claim]
    );
}

#[test]
fn long_space_id_fits_world_route() {
    let fixture = world_space_fixture();
    let suffix = "@0123456789abcdef0123456789abcdef01234567@device";
    let model_padding = "m".repeat(200 - "local/".len() - suffix.len());
    let space_id = format!("local/{model_padding}{suffix}");
    assert_eq!(space_id.len(), 200, "the route is exactly 200 ASCII bytes");
    fixture
        .vault
        .declare_embedding_space(&fixture.owner, text_space(&space_id))
        .expect("owner declares a valid 200-byte text space");
    let result = fixture.vault.set_world_privacy_as(
        &fixture.owner,
        ActSurface::ThisInstall,
        fixture.world,
        private_settings(ModelOrder::Ordered(vec![space_id.clone()])),
        None,
    );
    assert!(
        result.is_ok(),
        "a declared 200-byte space fits a world route: {result:?}"
    );
    assert_eq!(WORLD_MODEL_ROUTE_MAX_BYTES, EMBEDDING_SPACE_ID_MAX_LEN);
    assert_eq!(
        fixture
            .vault
            .world_text_space(fixture.world)
            .expect("long world text space"),
        Some(text_space(&space_id)),
    );
}

#[test]
fn a_space_off_the_device_is_not_a_world_text_space() {
    let fixture = world_space_fixture();
    let space_id = "local/tiny-test@0123456789abcdef0123456789abcdef01234567@openai";
    fixture
        .vault
        .declare_embedding_space(&fixture.owner, text_space(space_id))
        .expect("owner declares a text space off this device");
    fixture.set_models(ModelOrder::Ordered(vec![space_id.to_owned()]));
    assert_eq!(
        fixture
            .vault
            .world_text_space(fixture.world)
            .expect("off-device world text space"),
        None
    );
    let report = fixture
        .reconciler()
        .reconcile_once()
        .expect("ordinary vault text pass");
    assert_eq!(report.world_space, 0, "a hosted space does not redirect A");
    assert_eq!(report.leased, 2, "A and B both use the vault index");
    assert_eq!(report.embedded, 2);
    let seen = fixture.primary.seen();
    assert_eq!(seen.len(), 2);
    assert!(
        seen.contains(&fixture.world_claim),
        "A is sent to the vault embedder"
    );
    assert!(
        seen.contains(&fixture.base_claim),
        "B is sent to the vault embedder"
    );
}
