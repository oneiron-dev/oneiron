//! The home computes one machine's prediction (census L7-46 + L10-14; ARCH-0023b
//! #predicted-residence). Through the owner-grade view a home holds of its own linked machine,
//! a touch predicts its linked windows, a withheld world moves no score, an unchanged prediction
//! pushes nothing, a machine off the predicted level is refused, and a prediction keeps to the
//! owner's budget.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test predicted_residence_home`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::authority::{
    ActSurface, HostSlipIssuer, MachineRole, PredictedResidenceSet, ReadLocation, ResidenceAct,
    WorldPrivacy,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::sync::WindowKey;
use oneiron::sync::residence::{PredictedResidenceAnswer, ResidenceDirectiveState};
use oneiron::test_doors::predicted_residence::predict_residence_withholding;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EdgeKind,
    EntityId, TimeRange, Vault, VaultConfig,
};

/// The secret of the fixture host's slip issuer.
const FIXTURE_HOST_SECRET: &[u8] = b"predicted-residence-home";

/// When the fixture's first claims learned: one month.
const LEARNED_AT_A: u64 = 1_780_000_000;
/// When the fixture's linked claims learned: 62 days later, so always another month.
const LEARNED_AT_B: u64 = LEARNED_AT_A + 62 * 86_400;

/// A device vault holding a world and a world kept on the owner's machines, which this device is
/// not. Copied from `it_sync::device_world_follow::Device`, which this target cannot name.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: AuthenticatedOwner,
    issuer: HostSlipIssuer,
    machine: EntityId,
    world: EntityId,
    kept: EntityId,
}

impl Fixture {
    fn open() -> Self {
        let dir = tempfile::tempdir().expect("fixture vault directory");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh fixture vault");
        let person = vault.ensure_embedded_owner_actor().expect("embedded owner");
        let issuer = HostSlipIssuer::from_secret(FIXTURE_HOST_SECRET).expect("fixture host issuer");
        vault.ensure_host_root_slip(&issuer).expect("host root");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("a live install profile, never marked yours");
        let owner = vault
            .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
            .expect("authenticated owner");
        let machine = vault
            .local_machine()
            .expect("the install's machine")
            .expect("a minted machine")
            .id;
        let world = vault
            .create_world(&owner, "World", vault.now_recorded_at())
            .expect("world");
        let kept = vault
            .create_world(&owner, "Kept on my machines", vault.now_recorded_at())
            .expect("kept world");
        vault
            .set_world_privacy_as(
                &owner,
                ActSurface::ThisInstall,
                kept,
                WorldPrivacy {
                    read: ReadLocation::MyMachines,
                    ..WorldPrivacy::default()
                },
                None,
            )
            .expect("the owner keeps the world on their machines");
        assert!(
            !oneiron::sync::residence::local_is_elected_home(&vault)
                .expect("the home election reads"),
            "this install is not the elected home"
        );
        Self {
            _dir: dir,
            vault,
            owner,
            issuer,
            machine,
            world,
            kept,
        }
    }
}

/// One more world on the fixture, readable everywhere.
fn another_world(fixture: &Fixture, name: &str) -> EntityId {
    fixture
        .vault
        .create_world(&fixture.owner, name, fixture.vault.now_recorded_at())
        .expect("another world")
}

/// One person for claims to speak about.
fn person_in(vault: &Vault, learned_at: u64) -> EntityId {
    let id = EntityId::now();
    let occurred = TimeRange {
        start: learned_at,
        end: learned_at,
    };
    vault
        .put_entity(&id, ENTITY_TYPE_PERSON, occurred, learned_at, b"subject")
        .expect("subject entity");
    id
}

/// One claim about `subject` in `world`, learned at `learned_at`.
fn claim_in(
    vault: &Vault,
    id: &EntityId,
    subject: EntityId,
    world: Option<EntityId>,
    learned_at: u64,
) {
    let mut body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        rmpv::Value::from(format!("harbor note {}", id.to_hex())),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("claim body");
    body.source = Some(ClaimSource::UserStated);
    body.world = world;
    let occurred = TimeRange {
        start: learned_at,
        end: learned_at,
    };
    vault
        .put_claim(id, &body, occurred, learned_at)
        .expect("seed claim");
}

/// One link from `source` to `target` for the prediction walk to follow.
fn link(vault: &Vault, source: &EntityId, target: &EntityId) {
    vault
        .put_edge(source, EdgeKind::Mentions, target, 1.0)
        .expect("link edge");
}

/// Puts the owner at the predicted level with `window_budget` windows and `document_budget`
/// entity documents; answers the approval's directive id.
fn predict_level(fixture: &Fixture, window_budget: u32, document_budget: u32) -> EntityId {
    fixture
        .vault
        .issue_residence_directive_as(
            &fixture.owner,
            &fixture.issuer,
            EntityId::now(),
            fixture.machine,
            ResidenceAct::SyncPredicted {
                window_budget,
                document_budget,
            },
        )
        .expect("the owner's predicted approval")
        .directive
        .id
}

/// The home's prediction for the fixture's machine.
fn predict(fixture: &Fixture) -> PredictedResidenceAnswer {
    predict_residence_withholding(&fixture.vault, &fixture.issuer, fixture.machine)
        .expect("the home's prediction")
}

/// The predictions naming the fixture's machine.
fn predictions_of(fixture: &Fixture) -> Vec<ResidenceDirectiveState> {
    fixture
        .vault
        .residence_directives_as(&fixture.owner, Some(fixture.machine))
        .expect("the owner's read-back")
        .into_iter()
        .filter(|state| matches!(state.directive.act, ResidenceAct::Predicted { .. }))
        .collect()
}

/// A prediction's parent, set digest, window count and document count.
fn predicted_act(state: &ResidenceDirectiveState) -> (EntityId, [u8; 32], u32, u32) {
    match &state.directive.act {
        ResidenceAct::Predicted {
            parent,
            set_digest,
            window_count,
            document_count,
        } => (*parent, *set_digest, *window_count, *document_count),
        _ => panic!("a Predicted act"),
    }
}

/// The verified predicted set the home holds for the fixture's machine under `digest`.
fn predicted_set_of(fixture: &Fixture, digest: &[u8; 32]) -> PredictedResidenceSet {
    let body = fixture
        .vault
        .predicted_residence_body(fixture.machine, digest)
        .expect("the set body reads")
        .expect("the home holds the pushed body");
    PredictedResidenceSet::decode_verified(&body, digest).expect("the body decodes")
}

/// The window key of `world` at `learned_at`.
fn window_of(learned_at: u64, world: EntityId) -> String {
    WindowKey::for_world(learned_at, world).as_str().to_owned()
}

/// The world a window key names, or none for the base partition.
fn window_world(key: &str) -> Option<EntityId> {
    WindowKey::try_new(key).expect("a window key").world()
}

#[test]
fn home_pushes_predicted_windows() {
    let fixture = Fixture::open();
    let subject = person_in(&fixture.vault, LEARNED_AT_A);
    let a = EntityId::now();
    let b = EntityId::now();
    claim_in(
        &fixture.vault,
        &a,
        subject,
        Some(fixture.world),
        LEARNED_AT_A,
    );
    claim_in(
        &fixture.vault,
        &b,
        subject,
        Some(fixture.world),
        LEARNED_AT_B,
    );
    link(&fixture.vault, &a, &b);
    let parent = predict_level(&fixture, 32, 128);
    fixture
        .vault
        .record_machine_touch(fixture.machine, a)
        .expect("the touch lands");

    let answer = predict(&fixture);
    assert!(
        matches!(answer, PredictedResidenceAnswer::Pushed(_)),
        "a first prediction pushes"
    );
    let predictions = predictions_of(&fixture);
    assert_eq!(predictions.len(), 1, "exactly one prediction");
    let (named, digest, window_count, document_count) = predicted_act(&predictions[0]);
    assert_eq!(named, parent, "the parent is the owner's approval");
    let set = predicted_set_of(&fixture, &digest);
    assert_eq!(
        u32::try_from(set.windows.len()).expect("a window count"),
        window_count,
        "the act counts its windows"
    );
    assert_eq!(
        u32::try_from(set.documents.len()).expect("a document count"),
        document_count,
        "the act counts its documents"
    );
    assert!(
        set.windows
            .contains(window_of(LEARNED_AT_A, fixture.world).as_str()),
        "A's window predicts: {:?}",
        set.windows
    );
    assert!(
        set.windows
            .contains(window_of(LEARNED_AT_B, fixture.world).as_str()),
        "its linked B's window predicts: {:?}",
        set.windows
    );
    assert!(
        set.windows
            .iter()
            .all(|key| window_world(key).is_none_or(|world| world == fixture.world)),
        "no window of another world: {:?}",
        set.windows
    );
}

#[test]
fn a_withheld_world_moves_no_score() {
    let fixture = Fixture::open();
    let far = another_world(&fixture, "Far world");
    // One subject per claim, so X is reachable only through k.
    let a = EntityId::now();
    let k = EntityId::now();
    let x = EntityId::now();
    claim_in(
        &fixture.vault,
        &a,
        person_in(&fixture.vault, LEARNED_AT_A),
        Some(fixture.world),
        LEARNED_AT_A,
    );
    claim_in(
        &fixture.vault,
        &k,
        person_in(&fixture.vault, LEARNED_AT_A),
        Some(fixture.kept),
        LEARNED_AT_A,
    );
    claim_in(
        &fixture.vault,
        &x,
        person_in(&fixture.vault, LEARNED_AT_A),
        Some(far),
        LEARNED_AT_A,
    );
    link(&fixture.vault, &a, &k);
    link(&fixture.vault, &k, &x);
    predict_level(&fixture, 32, 128);
    fixture
        .vault
        .record_machine_touch(fixture.machine, a)
        .expect("the touch lands");

    assert!(matches!(
        predict(&fixture),
        PredictedResidenceAnswer::Pushed(_)
    ));
    let predictions = predictions_of(&fixture);
    assert_eq!(predictions.len(), 1, "exactly one prediction");
    let (_, digest, _, _) = predicted_act(&predictions[0]);
    let set = predicted_set_of(&fixture, &digest);
    assert!(
        set.windows
            .contains(window_of(LEARNED_AT_A, fixture.world).as_str()),
        "A's window still predicts: {:?}",
        set.windows
    );
    for key in &set.windows {
        let world = window_world(key);
        assert!(
            world.is_none() || world == Some(fixture.world),
            "no window of the kept or the far world: {key}"
        );
    }
    assert!(!set.documents.contains(&k), "the kept claim is no document");
    assert!(
        !set.documents.contains(&x),
        "the claim past it is no document"
    );
}

#[test]
fn an_unchanged_prediction_pushes_no_directive() {
    let fixture = Fixture::open();
    let subject = person_in(&fixture.vault, LEARNED_AT_A);
    let a = EntityId::now();
    claim_in(
        &fixture.vault,
        &a,
        subject,
        Some(fixture.world),
        LEARNED_AT_A,
    );
    predict_level(&fixture, 32, 128);
    fixture
        .vault
        .record_machine_touch(fixture.machine, a)
        .expect("the touch lands");

    assert!(matches!(
        predict(&fixture),
        PredictedResidenceAnswer::Pushed(_)
    ));
    assert_eq!(
        predict(&fixture),
        PredictedResidenceAnswer::Unchanged,
        "no new touch pushes nothing"
    );
    assert_eq!(predictions_of(&fixture).len(), 1, "one Predicted directive");
}

#[test]
fn the_home_refuses_a_machine_not_at_the_predicted_level() {
    let fixture = Fixture::open();
    predict_level(&fixture, 32, 128);
    fixture
        .vault
        .issue_residence_directive_as(
            &fixture.owner,
            &fixture.issuer,
            EntityId::now(),
            fixture.machine,
            ResidenceAct::SyncOpened,
        )
        .expect("the owner's opened approval");
    let before = fixture
        .vault
        .residence_directives_as(&fixture.owner, Some(fixture.machine))
        .expect("the owner's read-back")
        .len();

    let error = predict_residence_withholding(&fixture.vault, &fixture.issuer, fixture.machine)
        .expect_err("opened refuses a prediction");
    assert!(
        matches!(error, oneiron::Error::InvalidConfig(_)),
        "an engine refusal: {error:?}"
    );
    let after = fixture
        .vault
        .residence_directives_as(&fixture.owner, Some(fixture.machine))
        .expect("the owner's read-back")
        .len();
    assert_eq!(before, after, "the refusal appends nothing");
}

#[test]
fn a_prediction_keeps_to_the_owner_budget() {
    let fixture = Fixture::open();
    let second = another_world(&fixture, "Second world");
    let third = another_world(&fixture, "Third world");
    let subject = person_in(&fixture.vault, LEARNED_AT_A);
    for world in [fixture.world, second, third] {
        let touched = EntityId::now();
        claim_in(&fixture.vault, &touched, subject, Some(world), LEARNED_AT_A);
        fixture
            .vault
            .record_machine_touch(fixture.machine, touched)
            .expect("the touch lands");
    }
    predict_level(&fixture, 1, 1);

    assert!(matches!(
        predict(&fixture),
        PredictedResidenceAnswer::Pushed(_)
    ));
    let predictions = predictions_of(&fixture);
    assert_eq!(predictions.len(), 1, "exactly one prediction");
    let (_, digest, window_count, document_count) = predicted_act(&predictions[0]);
    let set = predicted_set_of(&fixture, &digest);
    assert_eq!(set.windows.len(), 1, "one window: {:?}", set.windows);
    assert!(
        set.documents.len() <= 1,
        "at most one document: {:?}",
        set.documents
    );
    assert_eq!(
        u32::try_from(set.windows.len()).expect("a window count"),
        window_count,
        "the act counts its windows"
    );
    assert_eq!(
        u32::try_from(set.documents.len()).expect("a document count"),
        document_count,
        "the act counts its documents"
    );
}
