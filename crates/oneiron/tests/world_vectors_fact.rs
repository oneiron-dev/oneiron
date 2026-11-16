//! DEC-0005 #private-world-vectors; FIX [WORLD-VECTORS-FACT]: the engine's typed
//! world-vectors read answers per world `world_space` when its model order names
//! its own declared text space, else `vault_space` when a live reconciler on this
//! vault runs the vault's pinned model for the world (and, where the owner's
//! egress rung holds that model off this device, the world's order admits the
//! rung), else `none`. Unknown, non-live or malformed ids are left out silently.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test world_vectors_fact`
#![cfg(all(feature = "sync", oneiron_test_support))]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{
    ActSurface, MachineOwnership, MachineRole, ModelOrder, ReadLocation, SealedCopies, WorldPrivacy,
};
use oneiron::claim::base_world_id;
use oneiron::consent::AuthenticatedOwner;
use oneiron::embed::world_vectors::{
    WorldVectorsAnswer, WorldVectorsRequest, WorldVectorsVerdict, read_world_vectors_as_owner,
};
use oneiron::embed::{
    EgressDecision, EgressPredicate, Embedder, EmbedderLocality, EmbeddingSpace, InputKind,
    PendingEmbeddingInput, PendingEmbeddingReconciler,
};
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, Vault, VaultConfig};

const WORLD_SPACE_ID: &str = "local/tiny-test@0123456789abcdef0123456789abcdef01234567@device";
const VAULT_MODEL_ID: &str = "test/vault-text@v1";
const DIMENSIONS: usize = 8;
/// A route no declared space and no rung of this vault is: an order naming only it admits no
/// embedder the owner's egress rung holds.
const REMOTE_ROUTE: &str = "remote/text@owner-server";

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

/// The owner's egress rule, sending every row.
struct AllowEveryRow;

impl EgressPredicate for AllowEveryRow {
    fn decide(&self, _input: &PendingEmbeddingInput) -> EgressDecision {
        EgressDecision::Allow
    }
}

struct FixedEmbedder {
    model: &'static str,
    locality: EmbedderLocality,
}

impl FixedEmbedder {
    fn on_device() -> Self {
        Self {
            model: VAULT_MODEL_ID,
            locality: EmbedderLocality::OnDevice,
        }
    }

    fn off_device() -> Self {
        Self {
            model: VAULT_MODEL_ID,
            locality: EmbedderLocality::OwnerServer,
        }
    }

    fn other_model() -> Self {
        Self {
            model: "test/other-text@v1",
            locality: EmbedderLocality::OnDevice,
        }
    }
}

impl Embedder for FixedEmbedder {
    fn model_id(&self) -> &str {
        self.model
    }

    fn dimensions(&self) -> usize {
        DIMENSIONS
    }

    fn locality(&self) -> EmbedderLocality {
        self.locality
    }

    fn embed(&self, inputs: &[PendingEmbeddingInput]) -> oneiron::Result<Vec<Vec<f32>>> {
        Ok(inputs.iter().map(|_| vec![1.0; DIMENSIONS]).collect())
    }
}

struct WorldVectorsFixture {
    vault: Arc<Vault>,
    owner: AuthenticatedOwner,
    person: EntityId,
    world: EntityId,
    config: VaultConfig,
    dir: tempfile::TempDir,
}

impl WorldVectorsFixture {
    fn set_models(&self, models: ModelOrder) {
        self.set_settings(private_settings(models));
    }

    fn set_settings(&self, settings: WorldPrivacy) {
        self.vault
            .set_world_privacy_as(
                &self.owner,
                ActSurface::ThisInstall,
                self.world,
                settings,
                None,
            )
            .expect("owner updates the world's settings");
    }

    fn reconciler(&self, embedder: FixedEmbedder) -> PendingEmbeddingReconciler {
        PendingEmbeddingReconciler::new(Arc::clone(&self.vault), Arc::new(embedder))
    }

    fn read(&self) -> WorldVectorsAnswer {
        read_world_vectors_as_owner(
            &self.vault,
            &self.owner,
            &WorldVectorsRequest { worlds: Vec::new() },
        )
        .expect("owner reads world vectors")
    }

    fn read_worlds(&self, worlds: Vec<String>) -> WorldVectorsAnswer {
        read_world_vectors_as_owner(&self.vault, &self.owner, &WorldVectorsRequest { worlds })
            .expect("owner reads the named worlds")
    }
}

fn world_vectors_fixture() -> WorldVectorsFixture {
    let dir = tempfile::tempdir().expect("temporary world-vectors vault directory");
    let mut config = VaultConfig::device();
    config.dimensions = DIMENSIONS;
    config.embedding_model = Some(VAULT_MODEL_ID.to_owned());
    let vault =
        Arc::new(Vault::open(dir.path(), config.clone()).expect("fresh world-vectors vault"));
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
    // `FoldedMachine` carries no public machine id of its own (its chains' profiles do), so
    // the fixture keeps no machine: only the reopen test compares `machine`, whole-answer.
    let _folded = vault
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
    WorldVectorsFixture {
        vault,
        owner,
        person,
        world,
        config,
        dir,
    }
}

fn verdict(answer: &WorldVectorsAnswer, world: EntityId) -> (WorldVectorsVerdict, Option<String>) {
    for entry in &answer.worlds {
        if entry.world == world.to_hex() {
            return (entry.vectors, entry.space.clone());
        }
    }
    panic!("world {} missing from {answer:?}", world.to_hex())
}

#[test]
fn a_world_whose_order_names_its_space_answers_world_space_and_base_answers_vault_space() {
    let fixture = world_vectors_fixture();
    fixture.set_models(ModelOrder::Ordered(vec![WORLD_SPACE_ID.to_owned()]));
    let _reconciler = fixture.reconciler(FixedEmbedder::on_device());
    let answer = fixture.read();
    assert_eq!(
        verdict(&answer, fixture.world),
        (
            WorldVectorsVerdict::WorldSpace,
            Some(WORLD_SPACE_ID.to_owned())
        ),
        "W names its space, so it answers world_space",
    );
    assert_eq!(
        verdict(&answer, base_world_id()),
        (WorldVectorsVerdict::VaultSpace, None),
        "base reality inherits, so it answers vault_space",
    );
    assert_eq!(
        answer.worlds[0].world,
        base_world_id().to_hex(),
        "base reality answers first",
    );
    let named = fixture.read_worlds(vec![
        fixture.world.to_hex(),
        EntityId::now().to_hex(),
        "not-an-id".to_owned(),
    ]);
    assert_eq!(
        named.worlds.len(),
        1,
        "unknown and malformed ids are left out"
    );
    assert_eq!(
        named.worlds[0].world,
        fixture.world.to_hex(),
        "only W answers"
    );
    assert_eq!(
        (named.worlds[0].vectors, named.worlds[0].space.clone()),
        (
            WorldVectorsVerdict::WorldSpace,
            Some(WORLD_SPACE_ID.to_owned())
        ),
        "the named read keeps W's verdict",
    );
}

#[test]
fn a_private_world_kept_from_an_off_device_embedder_answers_none() {
    let fixture = world_vectors_fixture();
    fixture.set_models(ModelOrder::Inherit);
    {
        let _off = fixture.reconciler(FixedEmbedder::off_device());
        let answer = fixture.read();
        assert_eq!(
            verdict(&answer, fixture.world),
            (WorldVectorsVerdict::None, None),
            "a private world is withheld from an off-device endpoint nobody proved",
        );
        assert_eq!(
            verdict(&answer, base_world_id()),
            (WorldVectorsVerdict::VaultSpace, None),
            "base reality is not withheld, so it answers vault_space",
        );
    }
    {
        let _on = fixture.reconciler(FixedEmbedder::on_device());
        let answer = fixture.read();
        assert_eq!(
            verdict(&answer, fixture.world),
            (WorldVectorsVerdict::VaultSpace, None),
            "on this device the private world answers vault_space",
        );
    }
}

#[test]
fn with_no_live_reconciler_of_the_vault_model_every_world_answers_none() {
    let fixture = world_vectors_fixture();
    fixture.set_models(ModelOrder::Inherit);
    let answer = fixture.read();
    assert_eq!(
        verdict(&answer, fixture.world),
        (WorldVectorsVerdict::None, None),
        "with no reconciler W answers none",
    );
    assert_eq!(
        verdict(&answer, base_world_id()),
        (WorldVectorsVerdict::None, None),
        "with no reconciler base answers none",
    );
    {
        let _other = fixture.reconciler(FixedEmbedder::other_model());
        let answer = fixture.read();
        assert_eq!(
            verdict(&answer, fixture.world),
            (WorldVectorsVerdict::None, None),
            "another model is not the vault model",
        );
        assert_eq!(
            verdict(&answer, base_world_id()),
            (WorldVectorsVerdict::None, None),
            "another model leaves base at none",
        );
    }
    {
        let _on = fixture.reconciler(FixedEmbedder::on_device());
        let answer = fixture.read();
        assert_eq!(
            verdict(&answer, fixture.world),
            (WorldVectorsVerdict::VaultSpace, None),
            "the vault model on this device answers W",
        );
        assert_eq!(
            verdict(&answer, base_world_id()),
            (WorldVectorsVerdict::VaultSpace, None),
            "the vault model on this device answers base",
        );
    }
    let answer = fixture.read();
    assert_eq!(
        verdict(&answer, fixture.world),
        (WorldVectorsVerdict::None, None),
        "dropping the reconciler withdraws W again",
    );
    assert_eq!(
        verdict(&answer, base_world_id()),
        (WorldVectorsVerdict::None, None),
        "dropping the reconciler withdraws base again",
    );
}

#[test]
fn setting_the_order_back_to_inherit_answers_vault_space_again() {
    let fixture = world_vectors_fixture();
    let _reconciler = fixture.reconciler(FixedEmbedder::on_device());
    fixture.set_models(ModelOrder::Ordered(vec![WORLD_SPACE_ID.to_owned()]));
    let answer = fixture.read();
    assert_eq!(
        verdict(&answer, fixture.world),
        (
            WorldVectorsVerdict::WorldSpace,
            Some(WORLD_SPACE_ID.to_owned())
        ),
        "the named order answers world_space",
    );
    fixture.set_models(ModelOrder::Inherit);
    let answer = fixture.read();
    assert_eq!(
        verdict(&answer, fixture.world),
        (WorldVectorsVerdict::VaultSpace, None),
        "back to inherit, W answers vault_space again",
    );
}

#[test]
fn the_answer_survives_a_reopen_once_a_reconciler_runs_again() {
    let fixture = world_vectors_fixture();
    fixture.set_models(ModelOrder::Ordered(vec![WORLD_SPACE_ID.to_owned()]));
    let before = {
        let _reconciler = fixture.reconciler(FixedEmbedder::on_device());
        fixture.read()
    };
    let WorldVectorsFixture {
        vault,
        owner,
        person: old_person,
        world,
        config,
        dir,
    } = fixture;
    drop(owner);
    drop(vault);
    let vault = Arc::new(Vault::open(dir.path(), config).expect("reopened world-vectors vault"));
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    let person = vault
        .ensure_embedded_owner_actor()
        .expect("embedded owner after reopen");
    assert_eq!(
        person, old_person,
        "the embedded owner actor survives the reopen"
    );
    let owner = vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("authenticated owner after reopen");
    let answer =
        read_world_vectors_as_owner(&vault, &owner, &WorldVectorsRequest { worlds: Vec::new() })
            .expect("owner reads after reopen before any reconciler");
    assert_eq!(
        verdict(&answer, world),
        (
            WorldVectorsVerdict::WorldSpace,
            Some(WORLD_SPACE_ID.to_owned())
        ),
        "the named order survives the reopen",
    );
    assert_eq!(
        verdict(&answer, base_world_id()),
        (WorldVectorsVerdict::None, None),
        "with no reconciler yet, base answers none",
    );
    let _reconciler =
        PendingEmbeddingReconciler::new(Arc::clone(&vault), Arc::new(FixedEmbedder::on_device()));
    let after =
        read_world_vectors_as_owner(&vault, &owner, &WorldVectorsRequest { worlds: Vec::new() })
            .expect("owner reads after reopen with a reconciler");
    assert_eq!(
        after, before,
        "the whole answer, machine included, survives"
    );
}

#[test]
fn an_open_world_whose_order_never_names_the_held_primary_answers_none() {
    let fixture = world_vectors_fixture();
    fixture.set_settings(WorldPrivacy {
        read: ReadLocation::Everywhere,
        sealed: SealedCopies::CloudAndMyMachines,
        models: ModelOrder::Ordered(vec![REMOTE_ROUTE.to_owned()]),
    });
    {
        let _free = fixture.reconciler(FixedEmbedder::off_device());
        let answer = fixture.read();
        assert_eq!(
            verdict(&answer, fixture.world),
            (WorldVectorsVerdict::VaultSpace, None),
            "an off-device primary no rung holds takes the open world's rows",
        );
    }
    let _held = fixture
        .reconciler(FixedEmbedder::off_device())
        .with_primary_rung(Arc::new(AllowEveryRow))
        .expect("the owner's egress rung holds the off-device primary");
    let answer = fixture.read();
    assert_eq!(
        verdict(&answer, fixture.world),
        (WorldVectorsVerdict::None, None),
        "the world's order never names the held primary, so its rows stay pending",
    );
    assert_eq!(
        verdict(&answer, base_world_id()),
        (WorldVectorsVerdict::VaultSpace, None),
        "base reality inherits, so the held primary takes its rows",
    );
}
