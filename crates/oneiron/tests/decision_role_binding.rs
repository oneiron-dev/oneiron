//! A vault manifest's decision-role binding holds its rung to that model (ruling
//! L9-27-ROLEBIND = A). DECIDE-SWITCHOVER = A (2026-10-16): each decision role is a backend
//! inside decide(). The host fills the head (`SystemOne`), precision (`Precision`) and
//! escalation (`Escalation`) rungs from its own `[models]`; the manifest's `decision_head`,
//! `decision_band` and `decision_escalation` bindings name the one model each rung may
//! answer with. A rung whose model is not the bound one abstains before any call, and the
//! ladder steps on; a role the manifest leaves unbound keeps the host's rung.
//!
//! Review of #7732, round 2: the binding holds the route too (a remote seat serving the bound
//! model is held under an on-device pin); a held rung is sent nothing, so its pin stays on
//! the receipt with no image pinned to it; and a manifest change that holds a rung misses
//! the auto check's verdict cache.
//!
//! On main the file does not compile: there is no `oneiron::llm::decision::ManifestBoundRung`.
//! `cargo test --locked -p oneiron --all-features --test decision_role_binding`.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use oneiron::claim::base_world_id;
use oneiron::claim_check::AutoCheckNotes;
use oneiron::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionCall, DecisionClass,
    DecisionDial, DecisionImage, DecisionLadder, DecisionProvider, DecisionQuestion, DecisionRung,
    EvidenceVersion, HeldLadder, HumanDecisionQueue, HumanDecisionRequest, ManifestBoundRung,
    ProviderDecision, ProviderPin, Reversibility, TypedDecision,
};
use oneiron::llm::image::ImageBytes;
use oneiron::llm::manifest::{
    MODEL_ROLES, ModelBinding, ModelManifest, ModelRole, ModelSlot, TeacherProbeApproval,
};
use oneiron::llm::{
    AutoCheckCandidate, AutoCheckDecisions, AutoCheckOutcome, AutoCheckSignals, BoundedAutoChecker,
};
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::{
    ClaimSource, EntityId, ModelId, ModelLocality, ModelTierRef, Result, Vault, VaultConfig,
};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

/// The hot-path head's model and revision (`cross/models.md`, the head row).
const HEAD_MODEL: &str = "vllm-sr/d3-flash";
const HEAD_REVISION: &str = "521525e";
/// The precision band's model and revision (`cross/models.md`, the band row).
const BAND_MODEL: &str = "Cloudflare/clef";
const BAND_REVISION: &str = "2f3de3d";
/// The house read's pin names its whole model id, and its version is the recipe's revision.
const HOUSE_MODEL: &str = "house/reader@q4km";
const HOUSE_REVISION: &str = "q4km+recipe.0123456789abcdef";
/// A model no rung here serves.
const OTHER_MODEL: &str = "other/model@1";
const TIER: &str = "decision-role-binding";

/// A clock these reads never reach.
fn deadline() -> RetrievalDeadline {
    RetrievalDeadline::hard(Instant::now(), Duration::from_secs(60))
}

fn question() -> DecisionQuestion {
    DecisionQuestion {
        id: EntityId::now(),
        version: 1,
        text: "Does this note answer the task?".into(),
        class: DecisionClass::Judgment,
        contract: AnswerContract::Noul,
        accept_type: false,
    }
}

fn pin(rung: DecisionRung, model: &str, version: &str) -> ProviderPin {
    ProviderPin {
        rung,
        model: model.into(),
        version: version.into(),
    }
}

fn head_pin() -> ProviderPin {
    pin(DecisionRung::SystemOne, HEAD_MODEL, HEAD_REVISION)
}

fn band_pin() -> ProviderPin {
    pin(DecisionRung::Precision, BAND_MODEL, BAND_REVISION)
}

fn house_pin() -> ProviderPin {
    pin(DecisionRung::Escalation, HOUSE_MODEL, HOUSE_REVISION)
}

/// A rung that gives `answer` with P = `probability` to every call and counts its calls. It
/// computes in this process, unless it stands for a remote seat whose calls leave the host.
struct Scripted {
    pin: ProviderPin,
    answer: DecisionAnswer,
    probability: f64,
    leaves_host: bool,
    reads_images: bool,
    calls: AtomicUsize,
}

impl Scripted {
    /// A rung on this device that answers yes.
    fn new(pin: ProviderPin, probability: f64) -> Arc<Self> {
        Self::built(pin, DecisionAnswer::Noul(true), probability, false, false)
    }

    /// A remote seat that answers yes: every call leaves the host.
    fn seat(pin: ProviderPin, probability: f64) -> Arc<Self> {
        Self::built(pin, DecisionAnswer::Noul(true), probability, true, false)
    }

    /// A rung on this device that reads images and answers yes.
    fn seeing(pin: ProviderPin, probability: f64) -> Arc<Self> {
        Self::built(pin, DecisionAnswer::Noul(true), probability, false, true)
    }

    /// A rung on this device that answers every auto check `allow`.
    fn allowing(pin: ProviderPin) -> Arc<Self> {
        Self::built(
            pin,
            DecisionAnswer::Choice("allow".into()),
            0.99,
            false,
            false,
        )
    }

    fn built(
        pin: ProviderPin,
        answer: DecisionAnswer,
        probability: f64,
        leaves_host: bool,
        reads_images: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            pin,
            answer,
            probability,
            leaves_host,
            reads_images,
            calls: AtomicUsize::new(0),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl DecisionProvider for Scripted {
    fn pin(&self) -> ProviderPin {
        self.pin.clone()
    }

    fn reads_images(&self) -> bool {
        self.reads_images
    }

    fn leaves_host(&self) -> bool {
        self.leaves_host
    }

    fn runs_on_device(&self) -> bool {
        !self.leaves_host
    }

    fn decide(&self, _: &DecisionCall<'_>) -> Result<ProviderDecision> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(ProviderDecision {
            answer: self.answer.clone(),
            probability: Some(self.probability),
            paired: None,
            person: None,
            served: None,
            cost_per_thousand: None,
        })
    }
}

/// The person rung; these dials never reach it.
#[derive(Default)]
struct Queue(Mutex<Vec<HumanDecisionRequest>>);

impl HumanDecisionQueue for Queue {
    fn queue(&self, request: HumanDecisionRequest) -> Result<()> {
        self.0.lock().expect("queue").push(request);
        Ok(())
    }
}

/// A v2 manifest binding every required role to a model of its own, and each decision
/// role in `decision` to the model given; a decision role not in `decision` is unbound.
fn manifest(decision: &[(ModelRole, &str)]) -> TestResult<ModelManifest> {
    let mut roles = BTreeMap::new();
    for role in MODEL_ROLES {
        let model = match decision.iter().find(|(bound, _)| *bound == role) {
            Some((_, model)) => ModelId::new(*model)?,
            None if role.is_optional() => continue,
            None => ModelId::new(format!("role-binding/{role:?}@r1"))?,
        };
        roles.insert(
            role,
            ModelBinding {
                model,
                slot: if role == ModelRole::ExtractionEncoder {
                    ModelSlot::Oneironer
                } else {
                    ModelSlot::Llm
                },
                tier: ModelTierRef(TIER.to_owned()),
                route_models: BTreeMap::new(),
                disposition: None,
                reads_audio: false,
            },
        );
    }
    Ok(ModelManifest {
        version: 2,
        roles,
        routes: BTreeMap::from([
            (ModelSlot::Llm, ModelLocality::OnDevice),
            (ModelSlot::Embedder, ModelLocality::OnDevice),
            (ModelSlot::Oneironer, ModelLocality::OnDevice),
        ]),
        verdict: None,
        seat_policy: None,
    })
}

/// A device vault whose manifest binds the decision roles in `decision`, pinned with a
/// passing teacher-probe approval as the bench publishes one.
fn vault(decision: &[(ModelRole, &str)]) -> TestResult<(tempfile::TempDir, Arc<Vault>)> {
    let directory = tempfile::tempdir()?;
    let vault = Vault::open(directory.path(), VaultConfig::device())?;
    bind(&vault, decision)?;
    Ok((directory, Arc::new(vault)))
}

/// Sets `vault`'s manifest to [`manifest`]`(decision)`, pinned with a passing probe approval.
fn bind(vault: &Vault, decision: &[(ModelRole, &str)]) -> TestResult {
    let manifest = manifest(decision)?;
    let policy = vault.teacher_probe_policy(None)?;
    let approval = TeacherProbeApproval::for_scored_checkpoint(&manifest, &policy, 1_000_000)?;
    vault.set_model_manifest_with_teacher_approval(&manifest, &approval)?;
    Ok(())
}

/// `rung` held to `vault`'s binding for `role`.
fn bound(
    vault: &Arc<Vault>,
    role: ModelRole,
    rung: &Arc<Scripted>,
) -> TestResult<ManifestBoundRung> {
    let inner: Arc<dyn DecisionProvider> = Arc::<Scripted>::clone(rung);
    Ok(ManifestBoundRung::new(Arc::clone(vault), role, inner)?)
}

/// The default band (0.35 to 0.65), learned and enforced for `question`.
fn enforced(question: &DecisionQuestion) -> TestResult<DecisionBandPolicy> {
    let mut policy = DecisionBandPolicy::default();
    policy.learn_shadow(
        question,
        Reversibility::ReversibleRead,
        DecisionBand::default(),
        1,
    )?;
    policy.enforce(question, Reversibility::ReversibleRead)?;
    Ok(policy)
}

/// One call over `images` from the head up to the Big rung, its band enforced.
fn decide(
    head: &dyn DecisionProvider,
    band: Option<&dyn DecisionProvider>,
    house: &dyn DecisionProvider,
    images: &[DecisionImage],
) -> TestResult<TypedDecision> {
    let question = question();
    let policy = enforced(&question)?;
    let queue = Queue::default();
    let decision = DecisionLadder {
        rule: None,
        local: None,
        system_one: Some(head),
        precision: band,
        escalation: Some(house),
        big: None,
        human: &queue,
        human_pin: pin(DecisionRung::Human, "owner-asks", "1"),
        ask_to: None,
        paired: None,
        person: None,
        presence: None,
        correlation: None,
    }
    .run_images(
        &question,
        EntityId::now(),
        &[],
        images,
        &serde_json::json!({}),
        DecisionDial {
            first: DecisionRung::SystemOne,
            ceiling: DecisionRung::Big,
            band: DecisionBand::default(),
        },
        &policy,
        Reversibility::ReversibleRead,
        &deadline(),
    )?;
    assert!(queue.0.lock().expect("queue").is_empty());
    Ok(decision)
}

fn answered(decision: &TypedDecision) -> Option<DecisionRung> {
    decision.receipt.time.and_then(|time| time.answered)
}

#[test]
fn manifest_binding_to_another_model_skips_the_head() -> TestResult {
    let (_directory, vault) = vault(&[(ModelRole::DecisionHead, OTHER_MODEL)])?;
    let head = Scripted::new(head_pin(), 0.95);
    let house = Scripted::new(house_pin(), 0.9);

    let decision = decide(
        &bound(&vault, ModelRole::DecisionHead, &head)?,
        None,
        &*house,
        &[],
    )?;

    // The head abstained before any call; the receipt names it, and the house read answered.
    assert_eq!(head.calls(), 0);
    assert_eq!(house.calls(), 1);
    assert_eq!(decision.answer, DecisionAnswer::Noul(true));
    assert_eq!(decision.probability, Some(0.9));
    assert_eq!(decision.receipt.providers, vec![head_pin(), house_pin()]);
    assert_eq!(answered(&decision), Some(DecisionRung::Escalation));
    Ok(())
}

#[test]
fn manifest_binding_to_the_same_model_uses_the_head() -> TestResult {
    let head_model = format!("{HEAD_MODEL}@{HEAD_REVISION}");
    let (_directory, vault) = vault(&[(ModelRole::DecisionHead, head_model.as_str())])?;
    let head = Scripted::new(head_pin(), 0.95);
    let house = Scripted::new(house_pin(), 0.9);

    let decision = decide(
        &bound(&vault, ModelRole::DecisionHead, &head)?,
        None,
        &*house,
        &[],
    )?;

    assert_eq!((head.calls(), house.calls()), (1, 0));
    assert_eq!(decision.probability, Some(0.95));
    assert_eq!(decision.receipt.providers, vec![head_pin()]);
    assert_eq!(answered(&decision), Some(DecisionRung::SystemOne));
    Ok(())
}

#[test]
fn unbound_role_keeps_the_host_rung() -> TestResult {
    // The manifest binds the band and the escalation read, and leaves the head unbound.
    let (_directory, vault) = vault(&[
        (ModelRole::DecisionBand, OTHER_MODEL),
        (ModelRole::DecisionEscalation, OTHER_MODEL),
    ])?;
    let head = Scripted::new(head_pin(), 0.95);
    let house = Scripted::new(house_pin(), 0.9);

    let decision = decide(
        &bound(&vault, ModelRole::DecisionHead, &head)?,
        None,
        &*house,
        &[],
    )?;

    assert_eq!((head.calls(), house.calls()), (1, 0));
    assert_eq!(decision.receipt.providers, vec![head_pin()]);
    assert_eq!(answered(&decision), Some(DecisionRung::SystemOne));
    Ok(())
}

#[test]
fn band_bound_elsewhere_steps_on_to_the_bound_house_read() -> TestResult {
    // The house read's pin names its whole model id; the manifest binds the escalation
    // role to that model and the band role to another.
    let (_directory, vault) = vault(&[
        (ModelRole::DecisionBand, OTHER_MODEL),
        (ModelRole::DecisionEscalation, HOUSE_MODEL),
    ])?;
    let head = Scripted::new(head_pin(), 0.5);
    let band = Scripted::new(band_pin(), 0.95);
    let house = Scripted::new(house_pin(), 0.9);
    let band_rung = bound(&vault, ModelRole::DecisionBand, &band)?;

    // The head's in-band answer steps to the band, which abstains unspent; the house read
    // answers.
    let decision = decide(
        &bound(&vault, ModelRole::DecisionHead, &head)?,
        Some(&band_rung as &dyn DecisionProvider),
        &bound(&vault, ModelRole::DecisionEscalation, &house)?,
        &[],
    )?;

    assert_eq!((head.calls(), band.calls(), house.calls()), (1, 0, 1));
    assert_eq!(decision.probability, Some(0.9));
    assert_eq!(
        decision.receipt.providers,
        vec![head_pin(), band_pin(), house_pin()]
    );
    assert_eq!(answered(&decision), Some(DecisionRung::Escalation));
    Ok(())
}

#[test]
fn a_role_holds_only_the_rung_it_fills() -> TestResult {
    let (_directory, vault) = vault(&[])?;
    let head = Scripted::new(head_pin(), 0.95);
    let band = Scripted::new(band_pin(), 0.95);

    assert!(bound(&vault, ModelRole::DecisionBand, &head).is_err());
    assert!(bound(&vault, ModelRole::DecisionHead, &band).is_err());
    assert!(bound(&vault, ModelRole::GenerativeReasoner, &head).is_err());
    assert!(bound(&vault, ModelRole::DecisionBand, &band).is_ok());
    Ok(())
}

/// A rung that serves the bound model but whose calls leave the host is held under an
/// on-device pin: the model id matches, the route does not, and the seat is sent nothing.
#[test]
fn a_remote_seat_serving_the_bound_model_is_held_under_an_on_device_route() -> TestResult {
    let head_model = format!("{HEAD_MODEL}@{HEAD_REVISION}");
    let (_directory, vault) = vault(&[(ModelRole::DecisionHead, head_model.as_str())])?;
    let head = Scripted::seat(head_pin(), 0.95);
    let house = Scripted::new(house_pin(), 0.9);

    let decision = decide(
        &bound(&vault, ModelRole::DecisionHead, &head)?,
        None,
        &*house,
        &[],
    )?;

    assert_eq!((head.calls(), house.calls()), (0, 1));
    assert_eq!(decision.probability, Some(0.9));
    assert_eq!(decision.receipt.providers, vec![head_pin(), house_pin()]);
    assert_eq!(answered(&decision), Some(DecisionRung::Escalation));
    Ok(())
}

/// A 4 x 3 PNG the question reads as `camera`.
fn camera() -> TestResult<DecisionImage> {
    let mut bytes = std::io::Cursor::new(Vec::new());
    image::RgbImage::new(4, 3).write_to(&mut bytes, image::ImageFormat::Png)?;
    Ok(DecisionImage {
        name: "camera".to_owned(),
        evidence: EvidenceVersion {
            id: EntityId::now(),
            body_hash: [7; 32],
        },
        image: ImageBytes {
            bytes: bytes.into_inner(),
            media_type: "image/png".to_owned(),
        },
        frame: None,
    })
}

/// A held rung is sent nothing: its pin stays on the receipt, and no image is pinned to it.
/// The rung that answered is pinned with what it was sent.
#[test]
fn a_held_rung_has_no_image_pinned_to_it() -> TestResult {
    let (_directory, vault) = vault(&[(ModelRole::DecisionHead, OTHER_MODEL)])?;
    let head = Scripted::seeing(head_pin(), 0.95);
    let house = Scripted::seeing(house_pin(), 0.9);

    let decision = decide(
        &bound(&vault, ModelRole::DecisionHead, &head)?,
        None,
        &*house,
        &[camera()?],
    )?;

    assert_eq!((head.calls(), house.calls()), (0, 1));
    assert_eq!(decision.receipt.providers, vec![head_pin(), house_pin()]);
    let pinned: Vec<(ProviderPin, &str)> = decision
        .receipt
        .images
        .iter()
        .map(|row| (row.provider.clone(), row.name.as_str()))
        .collect();
    assert_eq!(
        pinned,
        vec![(house_pin(), "camera")],
        "an image was pinned to the held head"
    );
    Ok(())
}

/// No hold reasons: the scripted checker only allows.
struct NoNotes;

impl AutoCheckNotes for NoNotes {
    fn hold_reasons(
        &self,
        _candidate: &AutoCheckCandidate<'_>,
        _due: Instant,
    ) -> Result<Vec<String>> {
        Ok(Vec::new())
    }
}

/// An agent's Generated `profile.name` candidate in base reality.
fn candidate() -> AutoCheckCandidate<'static> {
    AutoCheckCandidate {
        predicate: "profile.name",
        value_preview: "Ada Lovelace",
        source: ClaimSource::Generated,
        lineage: None,
        actor_class: "agent",
        sensitivity_band: Some(0),
        burst: None,
        signals: AutoCheckSignals::default(),
        world: base_world_id(),
    }
}

/// A verdict the head gave never answers once a manifest change holds the head: the next
/// check of the same candidate goes to the ladder, where the held head abstains unspent, and
/// with no other rung the check is Unavailable.
#[test]
fn a_manifest_change_that_holds_the_head_misses_the_auto_check_cache() -> TestResult {
    let head_model = format!("{HEAD_MODEL}@{HEAD_REVISION}");
    let (_directory, vault) = vault(&[(ModelRole::DecisionHead, head_model.as_str())])?;
    let head = Scripted::allowing(head_pin());
    let checker = BoundedAutoChecker::new(AutoCheckDecisions {
        ladder: HeldLadder {
            system_one: Some(Arc::new(bound(&vault, ModelRole::DecisionHead, &head)?)
                as Arc<dyn DecisionProvider>),
            ..HeldLadder::unstaffed()
        },
        principal: EntityId::now(),
        dial: DecisionDial {
            first: DecisionRung::SystemOne,
            ceiling: DecisionRung::SystemOne,
            band: DecisionBand::default(),
        },
        bands: DecisionBandPolicy::default(),
        wording: "May this write land without the owner's review?".to_owned(),
        notes: Arc::new(NoNotes),
        calibrated: None,
        world_hold: None,
    });

    assert_eq!(checker.check(&candidate()), AutoCheckOutcome::Allow);
    assert_eq!(head.calls(), 1);

    // The owner binds the head role to another model.
    bind(&vault, &[(ModelRole::DecisionHead, OTHER_MODEL)])?;

    assert_eq!(
        checker.check(&candidate()),
        AutoCheckOutcome::Unavailable,
        "the cached Allow answered after the manifest held the head"
    );
    assert_eq!(head.calls(), 1);
    Ok(())
}
