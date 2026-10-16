//! The host's decision ladder (ARCH-0076): built once at serve start and lent
//! to every caller that asks a typed question, a route or a runtime job.
//!
//! The slots come from what the server already serves. The rule table sits
//! first and abstains on a question it holds no row for, so every dial can
//! start there. The house model's decision read fills the escalation rung when
//! `[models.decision_read]` binds it and its recipe names the paired question;
//! the recipe's person question is the ladder's own. The System One seat fills
//! its rung when `[models.decisions.system_one]` binds it, and the big model
//! fills the Big rung when `[models.decisions.big]` names its seat
//! ([`crate::big_rung`]). The local head has no typed provider on this host
//! yet, so its slot stays empty and the ladder steps past it. The last rung is the vault owner's
//! ask queue ([`DecisionAsks`]): durable, answered at `/v1/owner/decisions`.
//!
//! Every model rung blocks on the server's runtime: run a ladder call on a
//! blocking thread.
use std::sync::Arc;

use oneiron::llm::decision::catalogue::{ASK_UP, THINK_MORE};
use oneiron::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionAsks, DecisionBand, DecisionBandPolicy, DecisionCall,
    DecisionDial, DecisionPack, DecisionProvider, DecisionQuestion, DecisionReadProvider,
    DecisionRung, HeldLadder, ModelDecisionProvider, ProviderCapability, ProviderDecision,
    ProviderPin, RemoteDecisionSeat, RuleDecisionProvider, SeatPhase, SeatRequest,
};
use oneiron::llm::seat::{SeatCandidate, SeatDecisions, SeatNotes, SeatTask};
use oneiron::llm::{
    AutoCheckCandidate, AutoCheckDecisions, AutoCheckNotes, BoundedAutoChecker, LabelReadModel,
    ModelId, ReasoningEffort,
};
use oneiron::{BudgetExhaustionPolicy, BudgetGuard, EntityId, HostingPrivacyPosture, Vault};

use crate::config::models::{BigSettings, ModelsConfig, SeatPickSettings, SystemOneSettings};
use crate::models::DecisionReadDoor;
use crate::server::SyncServer;

/// The rule table's identity on this host.
const RULE_TABLE: &str = "host-rules";
/// The owner ask queue's identity, the ladder's human pin.
const OWNER_ASKS: &str = "owner-asks";
const ONE: &str = "1";
/// The PersonThreshold row's version a host's start value takes.
const PERSON_THRESHOLD_VERSION: u32 = 1;

/// The ladder, its person queue and the bands every caller starts from.
#[derive(Clone)]
pub struct DecisionHost {
    ladder: HeldLadder,
    asks: Arc<DecisionAsks>,
    bands: DecisionBandPolicy,
    auto_checker: Option<BoundedAutoChecker>,
}

impl DecisionHost {
    /// The rule table and the owner's ask queue: what every server has.
    pub(crate) fn new(vault: &Arc<Vault>) -> Self {
        let asks = Arc::new(DecisionAsks::new(Arc::clone(vault)));
        let rule = RuleDecisionProvider::new(RULE_TABLE.into(), ONE.into())
            .ok()
            .map(|rule| Arc::new(rule) as Arc<dyn DecisionProvider>);
        Self {
            ladder: HeldLadder {
                rule,
                local: None,
                system_one: None,
                escalation: None,
                big: None,
                human: asks.clone(),
                human_pin: pin(DecisionRung::Human, OWNER_ASKS, ONE),
                person: None,
            },
            asks,
            bands: DecisionBandPolicy::default(),
            auto_checker: None,
        }
    }

    /// The house model's decision read on the escalation rung, read on
    /// `meter`, and its recipe's person question as the ladder's. Without a
    /// paired question in the recipe the rung stays empty.
    pub(crate) fn with_house_read(
        mut self,
        read: Option<&(DecisionReadDoor, BudgetGuard)>,
    ) -> Self {
        self.ladder.escalation = None;
        self.ladder.person = None;
        self.bands = DecisionBandPolicy::default();
        let Some((door, meter)) = read else {
            return self;
        };
        let Some(probe) = door.probe() else {
            tracing::warn!(
                "the decision read's recipe names no paired question; the escalation rung stays empty"
            );
            return self;
        };
        match HouseRead::new(door.reader(), meter.clone(), &probe.paired) {
            Ok(read) => self.ladder.escalation = Some(Arc::new(read)),
            Err(error) => {
                tracing::warn!(%error, "the house model's decision read cannot fill the escalation rung");
            }
        }
        if let Some(wording) = &probe.person {
            match ASK_UP.question(&[], wording.clone(), AnswerContract::Noul) {
                Ok(person) => {
                    let mut bands = DecisionBandPolicy::default();
                    match bands
                        .set_person_threshold(door.person_threshold(), PERSON_THRESHOLD_VERSION)
                    {
                        Ok(()) => {
                            self.ladder.person = Some(person);
                            self.bands = bands;
                        }
                        Err(error) => tracing::warn!(%error, "the person threshold is invalid"),
                    }
                }
                Err(error) => tracing::warn!(%error, "the recipe's person question is invalid"),
            }
        }
        self
    }

    /// The System One seat on its rung, its measurements sent on `runtime`.
    fn with_system_one(
        mut self,
        settings: Option<&SystemOneSettings>,
        default_units: u64,
        posture: HostingPrivacyPosture,
        runtime: tokio::runtime::Handle,
    ) -> Self {
        self.ladder.system_one = None;
        let Some(settings) = settings else {
            return self;
        };
        match SystemOneRung::bind(settings, default_units, posture, runtime) {
            Ok(rung) => self.ladder.system_one = Some(Arc::new(rung)),
            Err(error) => tracing::warn!(%error, "the System One seat cannot fill its rung"),
        }
        self
    }

    /// The big model on its rung (OF-495), through the seat
    /// `[models.decisions.big]` names; its calls block on `runtime`.
    fn with_big(
        mut self,
        settings: Option<&BigSettings>,
        models: &Arc<crate::models::ModelRuntime>,
        vault: &Arc<Vault>,
        default_units: u64,
        runtime: tokio::runtime::Handle,
    ) -> Self {
        self.ladder.big = None;
        let Some(settings) = settings else {
            return self;
        };
        let bound = crate::big_rung::BigModel::bind(
            settings,
            Arc::clone(models),
            Arc::clone(vault),
            default_units,
            runtime,
        )
        .and_then(|model| {
            let pin = model.pin();
            ModelDecisionProvider::new(pin, Arc::new(model)).map_err(anyhow::Error::from)
        });
        match bound {
            Ok(rung) => self.ladder.big = Some(Arc::new(rung)),
            Err(error) => tracing::warn!(%error, "the big model cannot fill its rung"),
        }
        self
    }

    /// The write gate's auto check through this ladder, worded `wording`,
    /// for `principal`.
    fn with_auto_check(mut self, wording: Option<&str>, principal: Option<EntityId>) -> Self {
        self.auto_checker = wording.zip(principal).map(|(wording, principal)| {
            BoundedAutoChecker::new(AutoCheckDecisions {
                ladder: self.ladder.clone(),
                principal,
                dial: self.dial(DecisionRung::Big),
                bands: self.bands.clone(),
                wording: wording.to_owned(),
                notes: Arc::new(LadderNotes),
                calibrated: None,
            })
        });
        self
    }

    /// The ladder every typed decision on this host goes through.
    #[must_use]
    pub fn ladder(&self) -> &HeldLadder {
        &self.ladder
    }

    /// The ladder's last rung: the vault owner's durable ask queue. A caller
    /// whose decision came back with a human ask finds it with
    /// [`DecisionAsks::latest`] and waits on [`DecisionAsks::answered`].
    #[must_use]
    pub fn asks(&self) -> &Arc<DecisionAsks> {
        &self.asks
    }

    /// The bands a caller starts from: the host's PersonThreshold row when
    /// the house read names a person question.
    #[must_use]
    pub fn bands(&self) -> DecisionBandPolicy {
        self.bands.clone()
    }

    /// A dial from the rule table up to `ceiling`, with the default band.
    #[must_use]
    pub fn dial(&self, ceiling: DecisionRung) -> DecisionDial {
        let first = [
            (DecisionRung::Rule, self.ladder.rule.is_some()),
            (DecisionRung::Local, self.ladder.local.is_some()),
            (DecisionRung::SystemOne, self.ladder.system_one.is_some()),
            (DecisionRung::Escalation, self.ladder.escalation.is_some()),
            (DecisionRung::Big, self.ladder.big.is_some()),
        ]
        .into_iter()
        .find_map(|(rung, filled)| filled.then_some(rung))
        .unwrap_or(DecisionRung::Human)
        .min(ceiling);
        DecisionDial {
            first,
            ceiling,
            band: DecisionBand::default(),
        }
    }

    /// The write gate's auto check through this ladder, when
    /// `[models.decisions].auto_check` words it.
    #[must_use]
    pub fn auto_checker(&self) -> Option<&BoundedAutoChecker> {
        self.auto_checker.as_ref()
    }

    /// The code-mode seat pick through this ladder, for `principal`.
    pub(crate) fn seat_decisions(
        &self,
        settings: &SeatPickSettings,
        principal: EntityId,
    ) -> SeatDecisions {
        SeatDecisions {
            ladder: self.ladder.clone(),
            principal,
            dial: self.dial(DecisionRung::Big),
            bands: self.bands.clone(),
            model_wording: settings.model_wording.clone(),
            effort_wording: settings.effort_wording.clone(),
            budget: settings.budget,
            notes: Arc::new(LadderNotes),
        }
    }
}

impl SyncServer {
    /// The host's decision ladder, built once at serve start. Every typed
    /// decision a route or runtime job asks goes through it
    /// (`decision_ladder().ladder()` for one call).
    #[must_use]
    pub fn decision_ladder(&self) -> &HeldLadder {
        self.decisions.ladder()
    }

    /// The ladder with its owner ask queue, starting bands, dials and the
    /// hooks built on it.
    #[must_use]
    pub fn decision_host(&self) -> &DecisionHost {
        &self.decisions
    }

    /// Fills the ladder's rungs `[models]` binds beyond the house read, and
    /// builds the hooks `[models.decisions]` words.
    pub(crate) fn with_decision_config(mut self, models: Option<&ModelsConfig>) -> Self {
        let Some(models) = models else {
            return self;
        };
        let principal = match self.vault.ensure_embedded_owner_actor() {
            Ok(owner) => Some(owner),
            Err(error) => {
                tracing::warn!(%error, "no owner principal; the host's own decisions stay unbound");
                None
            }
        };
        let posture = self.vault.privacy_posture();
        self.decisions = self
            .decisions
            .clone()
            .with_system_one(
                models.decisions.system_one.as_ref(),
                models.raw_budget_units,
                posture,
                tokio::runtime::Handle::current(),
            )
            .with_big(
                models.decisions.big.as_ref(),
                self.ai.models(),
                &self.vault,
                models.raw_budget_units,
                tokio::runtime::Handle::current(),
            )
            .with_auto_check(models.decisions.auto_check.as_deref(), principal);
        self
    }

    /// The code-mode seat pick `[models.decisions.seat]` words, and its facet.
    pub(crate) fn seat_router(&self, models: &ModelsConfig) -> Option<(SeatDecisions, String)> {
        let settings = models.decisions.seat.as_ref()?;
        let principal = self
            .vault
            .ensure_embedded_owner_actor()
            .inspect_err(|error| {
                tracing::warn!(%error, "no owner principal; the seat pick stays unbound");
            })
            .ok()?;
        Some((
            self.decisions.seat_decisions(settings, principal),
            settings.facet.clone(),
        ))
    }
}

fn pin(rung: DecisionRung, model: &str, version: &str) -> ProviderPin {
    ProviderPin {
        rung,
        model: model.to_owned(),
        version: version.to_owned(),
    }
}

/// The house model's decision read, owned. Each call lends it to the
/// engine's [`DecisionReadProvider`], which admits and settles one lease per
/// read on the meter. The reader blocks on the server's runtime.
struct HouseRead {
    pin: ProviderPin,
    reader: Arc<dyn LabelReadModel>,
    guard: BudgetGuard,
    paired: DecisionQuestion,
}

impl HouseRead {
    fn new(
        reader: Arc<dyn LabelReadModel>,
        guard: BudgetGuard,
        paired: &str,
    ) -> oneiron::Result<Self> {
        let read = Self {
            pin: pin(DecisionRung::Escalation, reader.model(), reader.revision()),
            paired: THINK_MORE.question(&[], paired.to_owned(), AnswerContract::Noul)?,
            reader,
            guard,
        };
        read.provider()?;
        Ok(read)
    }

    fn provider(&self) -> oneiron::Result<DecisionReadProvider<'_>> {
        DecisionReadProvider::new(
            self.pin.clone(),
            self.reader.as_ref(),
            &self.guard,
            &self.paired,
        )
    }
}

impl DecisionProvider for HouseRead {
    fn pin(&self) -> ProviderPin {
        self.pin.clone()
    }

    fn capability(&self) -> ProviderCapability {
        ProviderCapability {
            max_options: self.reader.max_labels(),
            score: false,
        }
    }

    fn decide(&self, call: &DecisionCall<'_>) -> oneiron::Result<ProviderDecision> {
        self.provider()?.decide(call)
    }

    fn decide_pack(&self, pack: &DecisionPack<'_>) -> oneiron::Result<Vec<ProviderDecision>> {
        self.provider()?.decide_pack(pack)
    }
}

/// The remote System One seat as a ladder rung: each question is one
/// measurement admitted and settled on the seat's own meter, sent on the
/// server's runtime (so a call blocks its thread). It takes noul and choice
/// questions; a score question's level labels are the caller's, and a ladder
/// call does not carry them.
struct SystemOneRung {
    seat: Arc<dyn RemoteDecisionSeat>,
    guard: BudgetGuard,
    posture: HostingPrivacyPosture,
    remote_opt_in: bool,
    runtime: tokio::runtime::Handle,
}

impl SystemOneRung {
    fn bind(
        settings: &SystemOneSettings,
        default_units: u64,
        posture: HostingPrivacyPosture,
        runtime: tokio::runtime::Handle,
    ) -> anyhow::Result<Self> {
        let bearer = std::env::var(&settings.key_env)
            .map_err(|_| anyhow::anyhow!("{} is not set", settings.key_env))?;
        let seat = oneiron_llm_systemone::SystemOneSeat::new(
            settings.endpoint.clone(),
            bearer,
            settings.model.clone(),
            settings.version.clone(),
        )
        .map_err(|error| anyhow::anyhow!("invalid System One seat: {error}"))?;
        Ok(Self {
            seat: Arc::new(seat),
            guard: BudgetGuard::new(
                "system-one",
                settings.budget_units.unwrap_or(default_units),
                BudgetExhaustionPolicy::Suspend,
            ),
            posture,
            remote_opt_in: settings.remote_opt_in,
            runtime,
        })
    }
}

impl DecisionProvider for SystemOneRung {
    fn pin(&self) -> ProviderPin {
        self.seat.pin()
    }

    fn capability(&self) -> ProviderCapability {
        ProviderCapability {
            score: false,
            ..ProviderCapability::default()
        }
    }

    /// The seat sends a call's images as named wire assets.
    fn reads_images(&self) -> bool {
        true
    }

    fn decide(&self, call: &DecisionCall<'_>) -> oneiron::Result<ProviderDecision> {
        let failed = |what: &str| oneiron::Error::InvalidConfig(format!("system one: {what}"));
        let request = SeatRequest {
            question: call.question.clone(),
            state: call.state.clone(),
            images: call.images.to_vec(),
            score_levels: Vec::new(),
            posture: self.posture,
            remote_opt_in: self.remote_opt_in,
            phase: SeatPhase::Background,
        };
        request
            .validate_remote()
            .map_err(|_| failed("the posture or the request keeps this call local"))?;
        let lease = self
            .guard
            .admit()
            .map_err(|_| failed("refused by the budget"))?
            .lease;
        // A measurement admitted after the work time is spent never starts.
        if call.deadline.decision_time_left().is_zero() {
            self.guard
                .settle_reserved(&lease)
                .map_err(|_| failed("settlement refused"))?;
            return Err(failed("admitted after the work time"));
        }
        let asked = self.runtime.block_on(self.seat.ask(
            request,
            &lease,
            call.deadline.decision_time_left(),
        ));
        let answer = match asked {
            Ok(answer) => {
                self.guard
                    .settle_per_call(&lease, &answer.usage)
                    .map_err(|_| failed("settlement refused"))?;
                answer
            }
            Err(error) => {
                // The seat may still bill a failed call.
                self.guard
                    .settle_reserved(&lease)
                    .map_err(|_| failed("settlement refused"))?;
                return Err(failed(&format!("the seat failed: {error}")));
            }
        };
        let abstained = answer.answer == DecisionAnswer::Abstain;
        Ok(ProviderDecision {
            answer: answer.answer,
            probability: (!abstained).then_some(answer.probability),
            paired: None,
            person: None,
        })
    }
}

/// The receipts' notes beside a decided answer, written from the decision
/// itself: the answer is already decided, and a note cannot change it.
struct LadderNotes;

impl AutoCheckNotes for LadderNotes {
    fn hold_reasons(&self, candidate: &AutoCheckCandidate<'_>) -> oneiron::Result<Vec<String>> {
        Ok(vec![format!(
            "the host's decision ladder held this {} write from a {} source",
            candidate.predicate,
            candidate.source.as_str()
        )])
    }
}

impl SeatNotes for LadderNotes {
    fn why(
        &self,
        task: &SeatTask,
        candidates: &[SeatCandidate],
        model: &ModelId,
        effort: ReasoningEffort,
    ) -> oneiron::Result<String> {
        let effort = match serde_json::to_value(effort) {
            Ok(serde_json::Value::String(label)) => label,
            _ => format!("{effort:?}"),
        };
        let described = candidates
            .iter()
            .find(|candidate| candidate.model == *model)
            .and_then(|candidate| candidate.description.first())
            .map(|line| format!(" ({})", line.text))
            .unwrap_or_default();
        Ok(format!(
            "The host's decision ladder picked {model}{described} at {effort} effort for the {} profile, from {} eligible models.",
            task.facet,
            candidates.len()
        ))
    }
}
