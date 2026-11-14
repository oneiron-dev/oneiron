//! A vault manifest's decision-role binding holds its rung to that model (ruling
//! L9-27-ROLEBIND = A). DECIDE-SWITCHOVER = A (2026-10-16): each decision role is a backend
//! inside decide(). The host fills the head (`SystemOne`), precision (`Precision`) and
//! escalation (`Escalation`) rungs from its own `[models]`; the manifest's `decision_head`,
//! `decision_band` and `decision_escalation` bindings name the one model each rung may
//! answer with. A rung whose model is not the bound one abstains before any call, and the
//! ladder steps on; a role the manifest leaves unbound keeps the host's rung.
//!
//! On main the file does not compile: there is no `oneiron::llm::decision::ManifestBoundRung`.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use oneiron::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionCall, DecisionClass,
    DecisionDial, DecisionLadder, DecisionProvider, DecisionQuestion, DecisionRung,
    HumanDecisionQueue, HumanDecisionRequest, ManifestBoundRung, ProviderDecision, ProviderPin,
    Reversibility, TypedDecision,
};
use oneiron::llm::manifest::{
    MODEL_ROLES, ModelBinding, ModelManifest, ModelRole, ModelSlot, TeacherProbeApproval,
};
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::{EntityId, ModelId, ModelLocality, ModelTierRef, Result, Vault, VaultConfig};

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

/// A rung that answers yes with P(yes) = `probability` to every call and counts its calls.
struct Scripted {
    pin: ProviderPin,
    probability: f64,
    calls: AtomicUsize,
}

impl Scripted {
    fn new(pin: ProviderPin, probability: f64) -> Arc<Self> {
        Arc::new(Self {
            pin,
            probability,
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

    fn decide(&self, _: &DecisionCall<'_>) -> Result<ProviderDecision> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(ProviderDecision {
            answer: DecisionAnswer::Noul(true),
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
    let manifest = manifest(decision)?;
    let policy = vault.teacher_probe_policy(None)?;
    let approval = TeacherProbeApproval::for_scored_checkpoint(&manifest, &policy, 1_000_000)?;
    vault.set_model_manifest_with_teacher_approval(&manifest, &approval)?;
    Ok((directory, Arc::new(vault)))
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

/// One call from the head up to the Big rung, its band enforced.
fn decide(
    head: &dyn DecisionProvider,
    band: Option<&dyn DecisionProvider>,
    house: &dyn DecisionProvider,
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
    .run(
        &question,
        EntityId::now(),
        &[],
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
