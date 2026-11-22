//! The home computes one machine's prediction (census L7-46 + L10-14; ARCH-0023b
//! #predicted-residence). Through the owner-grade view a home holds of its own linked machine,
//! a touch predicts its linked windows, a withheld world moves no score, an unchanged prediction
//! pushes nothing, a machine off the predicted level is refused, a prediction keeps to the
//! owner's budget, and a key the machine no longer stands on gets neither a prediction nor a set
//! body (REVIEW-7955). An entity document a touch reaches predicts beside the windows, and the
//! owner's document budget binds it (PREDICTED-DOC-BRANCH-NO-FIXTURE). A second ask inside the
//! home's push spacing appends nothing, a push leaves the home's memory once the spacing has
//! passed, and a later prediction the home holds no body for leaves its own last set the base of
//! the hysteresis (PREDICTED-DIRECTIVES-GROW-AUTHORITY-LOG, REVIEW-9762).
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test predicted_residence_home`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{
    ActAuthority, ActSurface, HostSlipIssuer, MachineOwnership, MachineRole, PeerMachine,
    PredictedResidenceSet, ReadLocation, ResidenceAct, WorldPrivacy,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::entity_doc::{DocAuthorization, TextField};
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::sync::WindowKey;
use oneiron::sync::residence::{PredictedResidenceAnswer, ResidenceDirectiveState};
use oneiron::test_doors::predicted_residence::{
    age_predicted_pushes, append_prediction_dated, noted_predicted_pushes,
    predict_residence_withholding,
};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EdgeKind, EntityId, TimeRange, Vault, VaultConfig, WriteActor,
};

/// The secret of the fixture host's slip issuer.
const FIXTURE_HOST_SECRET: &[u8] = b"predicted-residence-home";

/// When the fixture's first claims learned: one month.
const LEARNED_AT_A: u64 = 1_780_000_000;
/// When the fixture's linked claims learned: 62 days later, so always another month.
const LEARNED_AT_B: u64 = LEARNED_AT_A + 62 * 86_400;

/// A key the fixture's machine never stood on: the key a connection proved before the machine's
/// key rotated, or before the machine was removed.
const STALE_MACHINE_KEY: [u8; 32] = [0x5a; 32];

/// A device vault holding a world and a world kept on the owner's machines, which this device is
/// not. Copied from `it_sync::device_world_follow::Device`, which this target cannot name. The
/// owner answers its machine as a work or school machine: its proof stands here, so it takes the
/// owner's residence directives (FIX 8888), and it is still never "mine".
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
        vault
            .enrol_device_owner_signing_key(
                &ActAuthority::Owner(owner.clone(), ActSurface::ThisInstall),
                &issuer,
            )
            .expect("the owner enrols this install's owner signing key");
        let landing = vault
            .set_machine_role(
                &owner,
                ActSurface::ThisInstall,
                machine,
                MachineRole::Owned(MachineOwnership::WorkSchool),
                None,
            )
            .expect("the owner answers the device's machine");
        assert!(
            landing.held().is_none(),
            "FIXTURE: the owner key this install holds proves the work-or-school answer"
        );
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

/// One ASSET whose text the owner moved onto the document plane, learned at `learned_at`: an
/// entity-document head holder, planted through the public migration door as
/// `entity_doc_capture_retained_versions` plants one.
fn document_holder(fixture: &Fixture, learned_at: u64) -> EntityId {
    let id = EntityId::now();
    let occurred = TimeRange {
        start: learned_at,
        end: learned_at,
    };
    fixture
        .vault
        .put_entity(
            &id,
            ENTITY_TYPE_ASSET,
            occurred,
            learned_at,
            format!("harbor document {}", id.to_hex()).as_bytes(),
        )
        .expect("text asset");
    let person = fixture
        .vault
        .ensure_embedded_owner_actor()
        .expect("embedded owner");
    fixture
        .vault
        .migrate_entity_text(
            &id,
            &TextField::Utf8Body,
            WriteActor::new(person, EdgeActorClass::Human),
            &DocAuthorization::Owner(&fixture.owner),
        )
        .expect("the owner moves the asset's text to its document");
    id
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

/// The key the fixture's machine stands on here now.
fn standing_key(fixture: &Fixture) -> [u8; 32] {
    fixture
        .vault
        .authority_fold()
        .expect("the authority fold")
        .machine_proof_key(fixture.machine)
        .expect("the machine's proof stands here")
}

/// The home's prediction for the fixture's machine, asked on the key it stands on.
fn predict(fixture: &Fixture) -> PredictedResidenceAnswer {
    predict_residence_withholding(
        &fixture.vault,
        &fixture.issuer,
        fixture.machine,
        standing_key(fixture),
    )
    .expect("the home's prediction")
}

/// The home's spacing between two predictions it pushes one machine under one parent, in seconds
/// (`PREDICT_PUSH_MIN_SPACING` in `sync/residence/predict.rs`, crate-private).
const PUSH_SPACING_SECS: u64 = 30 * 60;

/// Lets the push spacing pass since the home's last push, as time passing does.
fn advance_past_push_spacing(fixture: &Fixture) {
    age_predicted_pushes(&fixture.vault, PUSH_SPACING_SECS);
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

/// The verified predicted set the home holds for the fixture's machine under `digest`, fetched on
/// the key it stands on.
fn predicted_set_of(fixture: &Fixture, digest: &[u8; 32]) -> PredictedResidenceSet {
    let peer = PeerMachine::Proven {
        machine: fixture.machine,
        key: standing_key(fixture),
    };
    let body = fixture
        .vault
        .predicted_residence_body(peer, digest)
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
    // Past the push spacing, so only the unchanged set holds the next ask back.
    advance_past_push_spacing(&fixture);
    assert_eq!(
        predict(&fixture),
        PredictedResidenceAnswer::Unchanged,
        "no new touch pushes nothing"
    );
    assert_eq!(predictions_of(&fixture).len(), 1, "one Predicted directive");
}

/// FIX PREDICTED-DIRECTIVES-GROW-AUTHORITY-LOG: a machine that asks again at once, with a touch
/// that changes its set, appends no second signed entry to the owner's authority log until the
/// home's push spacing has passed; then the changed set pushes.
#[test]
fn a_second_ask_inside_the_push_spacing_appends_nothing() {
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
    // C speaks of another person a month later, linked to nothing A reaches.
    let other = person_in(&fixture.vault, LEARNED_AT_B);
    let c = EntityId::now();
    claim_in(&fixture.vault, &c, other, Some(fixture.world), LEARNED_AT_B);
    predict_level(&fixture, 32, 128);
    fixture
        .vault
        .record_machine_touch(fixture.machine, a)
        .expect("the touch lands");
    assert!(
        matches!(predict(&fixture), PredictedResidenceAnswer::Pushed(_)),
        "a first prediction pushes"
    );
    let window_c = window_of(LEARNED_AT_B, fixture.world);
    let (_, first_digest, _, _) = predicted_act(&predictions_of(&fixture)[0]);
    assert!(
        !predicted_set_of(&fixture, &first_digest)
            .windows
            .contains(window_c.as_str()),
        "FIXTURE: C's window is not in the first prediction"
    );

    // The machine touches C and asks again at once: its set would now name C's window.
    fixture
        .vault
        .record_machine_touch(fixture.machine, c)
        .expect("the second touch lands");
    assert_eq!(
        predict(&fixture),
        PredictedResidenceAnswer::Unchanged,
        "an ask inside the push spacing appends nothing"
    );
    assert_eq!(
        predictions_of(&fixture).len(),
        1,
        "one Predicted directive inside the push spacing"
    );

    advance_past_push_spacing(&fixture);
    assert!(
        matches!(predict(&fixture), PredictedResidenceAnswer::Pushed(_)),
        "an ask after the push spacing pushes the changed set"
    );
    let predictions = predictions_of(&fixture);
    assert_eq!(
        predictions.len(),
        2,
        "a second Predicted directive after the push spacing"
    );
    let (_, second_digest, _, _) = predictions
        .iter()
        .map(predicted_act)
        .find(|(_, digest, _, _)| *digest != first_digest)
        .expect("a prediction with the changed set");
    assert!(
        predicted_set_of(&fixture, &second_digest)
            .windows
            .contains(window_c.as_str()),
        "C's window predicts after the push spacing"
    );
}

/// REVIEW-9762 round 2: the home forgets a push once the spacing has passed, so pushes under
/// predicted-level approvals the owner has since replaced do not pile up while the vault is open.
#[test]
fn a_push_leaves_the_home_memory_once_the_spacing_has_passed() {
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
    assert!(
        matches!(predict(&fixture), PredictedResidenceAnswer::Pushed(_)),
        "a first prediction pushes"
    );
    assert_eq!(
        noted_predicted_pushes(&fixture.vault),
        1,
        "FIXTURE: the home notes its push"
    );

    // The owner approves the predicted level again: the next prediction names the new approval.
    let replaced = predict_level(&fixture, 32, 128);
    advance_past_push_spacing(&fixture);
    assert!(
        matches!(predict(&fixture), PredictedResidenceAnswer::Pushed(_)),
        "a first prediction under the new approval pushes"
    );
    let (named, _, _, _) =
        predicted_act(predictions_of(&fixture).last().expect("the new prediction"));
    assert_eq!(
        named, replaced,
        "FIXTURE: the new prediction names the new approval"
    );
    assert_eq!(
        noted_predicted_pushes(&fixture.vault),
        1,
        "the push under the replaced approval left once the spacing had passed"
    );
}

/// REVIEW-9762 round 2: a later prediction this home holds no body for (another home's, dated by
/// this home's clock) never stands in for this home's own last set. The hysteresis keeps toward
/// the set the home pushed, and the home pushes it again, so the machine applies it last.
#[test]
fn a_later_foreign_prediction_leaves_the_home_its_own_set() {
    let fixture = Fixture::open();
    // Two lone entity documents that score alike: `early` takes the lower id, so it ranks first.
    let early = document_holder(&fixture, LEARNED_AT_B);
    let late = document_holder(&fixture, LEARNED_AT_B);
    let parent = predict_level(&fixture, 32, 1);
    fixture
        .vault
        .record_machine_touch(fixture.machine, late)
        .expect("the touch lands");
    assert!(
        matches!(predict(&fixture), PredictedResidenceAnswer::Pushed(_)),
        "a first prediction pushes"
    );
    let own = predictions_of(&fixture)
        .pop()
        .expect("the home's prediction");
    let (_, own_digest, _, _) = predicted_act(&own);
    assert_eq!(
        predicted_set_of(&fixture, &own_digest).documents,
        BTreeSet::from([late]),
        "FIXTURE: the home's first set names the touched document"
    );

    // Another home's prediction at the same date, with a later id: it sorts after the home's own.
    let foreign = PredictedResidenceSet {
        windows: BTreeSet::new(),
        documents: BTreeSet::from([EntityId::now()]),
    };
    append_prediction_dated(
        &fixture.vault,
        &fixture.issuer,
        fixture.machine,
        parent,
        &foreign,
        own.directive.issued_at,
    )
    .expect("the foreign prediction appends");
    // The machine touches `early` too: from no previous set, `early` alone would fill the budget.
    fixture
        .vault
        .record_machine_touch(fixture.machine, early)
        .expect("the second touch lands");
    advance_past_push_spacing(&fixture);

    let PredictedResidenceAnswer::Pushed(pushed) = predict(&fixture) else {
        panic!("the home pushes again over a later prediction it holds no body for");
    };
    let (_, digest, _, _) = predicted_act(&pushed);
    assert_eq!(
        predicted_set_of(&fixture, &digest).documents,
        BTreeSet::from([late]),
        "the hysteresis keeps the home's own last document, ranked second"
    );
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

    let error = predict_residence_withholding(
        &fixture.vault,
        &fixture.issuer,
        fixture.machine,
        standing_key(&fixture),
    )
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

#[test]
fn the_home_predicts_a_linked_entity_document() {
    let fixture = Fixture::open();
    let a = EntityId::now();
    claim_in(
        &fixture.vault,
        &a,
        person_in(&fixture.vault, LEARNED_AT_A),
        Some(fixture.world),
        LEARNED_AT_A,
    );
    let document = document_holder(&fixture, LEARNED_AT_B);
    link(&fixture.vault, &a, &document);
    predict_level(&fixture, 32, 128);
    fixture
        .vault
        .record_machine_touch(fixture.machine, a)
        .expect("the touch lands");

    assert!(
        matches!(predict(&fixture), PredictedResidenceAnswer::Pushed(_)),
        "a first prediction pushes"
    );
    let predictions = predictions_of(&fixture);
    assert_eq!(predictions.len(), 1, "exactly one prediction");
    let (_, digest, _, document_count) = predicted_act(&predictions[0]);
    let set = predicted_set_of(&fixture, &digest);
    assert_eq!(
        set.documents,
        BTreeSet::from([document]),
        "the linked asset's entity document predicts, and the touched claim holds none"
    );
    assert_eq!(document_count, 1, "the act counts its document");
    assert!(
        set.windows
            .contains(window_of(LEARNED_AT_A, fixture.world).as_str()),
        "the touched claim's window still predicts: {:?}",
        set.windows
    );
}

#[test]
fn a_prediction_keeps_documents_to_the_owner_budget() {
    let fixture = Fixture::open();
    let a = EntityId::now();
    claim_in(
        &fixture.vault,
        &a,
        person_in(&fixture.vault, LEARNED_AT_A),
        Some(fixture.world),
        LEARNED_AT_A,
    );
    let first = document_holder(&fixture, LEARNED_AT_B);
    let second = document_holder(&fixture, LEARNED_AT_B);
    link(&fixture.vault, &a, &first);
    link(&fixture.vault, &a, &second);
    predict_level(&fixture, 32, 1);
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
    let (_, digest, _, document_count) = predicted_act(&predictions[0]);
    let set = predicted_set_of(&fixture, &digest);
    assert_eq!(
        set.documents.len(),
        1,
        "one document under a budget of one: {:?}",
        set.documents
    );
    assert!(
        set.documents
            .iter()
            .all(|document| *document == first || *document == second),
        "the kept document is one of the linked assets: {:?}",
        set.documents
    );
    assert_eq!(document_count, 1, "the act counts its document");
}

#[test]
fn a_stale_machine_key_gets_no_prediction_and_no_set() {
    let fixture = Fixture::open();
    let a = EntityId::now();
    claim_in(
        &fixture.vault,
        &a,
        person_in(&fixture.vault, LEARNED_AT_A),
        Some(fixture.world),
        LEARNED_AT_A,
    );
    predict_level(&fixture, 32, 128);
    fixture
        .vault
        .record_machine_touch(fixture.machine, a)
        .expect("the touch lands");
    assert!(
        matches!(predict(&fixture), PredictedResidenceAnswer::Pushed(_)),
        "the standing key's prediction pushes"
    );
    let (_, digest, _, _) = predicted_act(&predictions_of(&fixture)[0]);
    assert_ne!(
        standing_key(&fixture),
        STALE_MACHINE_KEY,
        "the stale key is not the one the machine stands on"
    );

    let stale = PeerMachine::Proven {
        machine: fixture.machine,
        key: STALE_MACHINE_KEY,
    };
    assert_eq!(
        fixture
            .vault
            .predicted_residence_body(stale, &digest)
            .expect("the set body reads"),
        None,
        "a stale key is served no set body"
    );
    assert_eq!(
        fixture
            .vault
            .predicted_residence_body(PeerMachine::Unknown, &digest)
            .expect("the set body reads"),
        None,
        "an unproved peer is served no set body"
    );

    // A new touch in another month: a standing key's ask would push a new prediction.
    let b = EntityId::now();
    claim_in(
        &fixture.vault,
        &b,
        person_in(&fixture.vault, LEARNED_AT_B),
        Some(fixture.world),
        LEARNED_AT_B,
    );
    fixture
        .vault
        .record_machine_touch(fixture.machine, b)
        .expect("the touch lands");
    let error = predict_residence_withholding(
        &fixture.vault,
        &fixture.issuer,
        fixture.machine,
        STALE_MACHINE_KEY,
    )
    .expect_err("a stale key is refused a prediction");
    assert!(
        matches!(error, oneiron::Error::InvalidConfig(_)),
        "an engine refusal: {error:?}"
    );
    assert_eq!(
        predictions_of(&fixture).len(),
        1,
        "the refusal appends nothing"
    );
}
