//! The host's decision ladder (ARCH-0076): built once at serve start and lent
//! to every caller that asks a typed question, a route or a runtime job.
//!
//! The slots come from what the server already serves. The rule table sits
//! first and abstains on a question it holds no row for, so every dial can
//! start there. The house model's decision read fills the escalation rung when
//! `[models.decision_read]` binds it and its recipe names the paired question;
//! the recipe's person question is the ladder's own. Each of its reads is
//! admitted as the `/v1/llm/decision_read` probe's are: a
//! `limits.decision_reads` turn, then a run of its own with its receipts. The
//! System One seat fills its rung when `[models.decisions.system_one]` binds
//! it, and the big model fills the Big rung when `[models.decisions.big]`
//! names its seat
//! ([`crate::big_rung`]). The Local-vision seat fills the Local rung when
//! `[models.roles.local_vision]` binds one: it answers Box, Point and image
//! questions and abstains, unspent, on a call with no image. The last rung is
//! the vault owner's ask queue ([`DecisionAsks`]): durable, answered at
//! `/v1/owner/decisions`.
//!
//! Every model rung blocks on the server's runtime: run a ladder call on a
//! blocking thread.
use std::sync::Arc;

use oneiron::autoreason_campaign::{
    CAMPAIGN_TASTE_DIAL, CampaignTasteDecisions, CampaignTasteWording,
};
use oneiron::booking::constraint::BookingDecisions;
use oneiron::critic::review::{REVIEW_DIAL, ReviewDecisions, ReviewWording};
use oneiron::fanout_auto::FanoutDecisions;
use oneiron::llm::decision::catalogue::{ASK_UP, IMAGE_PRESENCE, TASK_SURFACE, THINK_MORE};
use oneiron::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionAsks, DecisionBand, DecisionBandPolicy, DecisionCall,
    DecisionDial, DecisionLadder, DecisionPack, DecisionProvider, DecisionQuestion,
    DecisionReadGate, DecisionReadProvider, DecisionRung, GatedRead, HeldLadder, HostRuleProvider,
    ModelDecisionProvider, PersonThreshold, ProviderCapability, ProviderDecision, ProviderPin,
    RemoteDecisionSeat, SeatPhase, SeatRequest, ThinkThreshold,
};
use oneiron::llm::run_admission::{CallOutcome, HostAccount, PaidConnector, RunReceiptSink};
use oneiron::llm::seat::{SeatCandidate, SeatDecisions, SeatNotes, SeatTask};
use oneiron::llm::{
    AutoCheckCandidate, AutoCheckDecisions, AutoCheckNotes, BoundedAutoChecker, LabelReadModel,
    ModelId, ReasoningEffort,
};
use oneiron::memory::ImagePick;
use oneiron::policy_model::PolicyDecisions;
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::saved_query::MembershipDecisions;
use oneiron::skill_attribution::{
    ATTRIBUTION_DIAL, AttributionDecisions, AttributionNotes, AttributionRules,
};
use oneiron::skill_hub::{ClaimReplayDecisions, UsefulUpstreamDecisions};
use oneiron::task_type::PlacementDecisions;
use oneiron::task_verb::TaskDecisions;
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, ConsolidationDecisions, EntityId,
    HostingPrivacyPosture, ModelLocality, Vault,
};

use crate::config::models::{
    BigSettings, BookingParseSettings, ConnectorSlateSettings, ImagePickSettings,
    ImportAudienceSettings, ModelsConfig, SeatPickSettings, SystemOneSettings,
};
use crate::models::DecisionReadDoor;
use crate::server::SyncServer;

mod adapters;
mod attach;
mod claim_merge;
mod doors;
mod notes;
mod refresh;

pub(crate) use adapters::description_notes;
pub(crate) use refresh::{spawn_person_threshold, spawn_person_threshold_admitted};

/// The rule table's identity on this host: the vault's host rule rows, which the owner's
/// reasons write ([`oneiron::llm::decision::HostRule`]).
const RULE_TABLE: &str = "host-rules";
/// The owner ask queue's identity, the ladder's human pin.
const OWNER_ASKS: &str = "owner-asks";
/// The task surface's questions: this host's wording.
const TASK_TAKE_WORDING: &str = "Should this agent take the proposed task? Yes only when the \
task fits what the agent's definition says it does and what it may touch.";
const TASK_DONE_MET_WORDING: &str = "Does this result meet the task's brief? Yes only when the \
result meets every state.criteria yes_if_all line and no state.criteria no_if_any line holds; \
a state.criteria not_a_reason_to_say_no line is never a reason to say no.";
const TASK_ASK_UP_WORDING: &str = "Should this task ask its owner now? Yes when the listed \
escalation trigger needs a person's answer before the work goes on.";
/// How long one task surface question may take.
const TASK_DECISION_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);
/// The placement question (OF-541): this host's wording.
const PLACEMENT_WORDING: &str = "Which node of the task-type tree is this task? Answer the most \
specific live node whose kind fits the task's subgoal and site, or the root when none fits.";
/// How long one placement may take before the rule rung's reading stands.
pub(crate) const PLACEMENT_BUDGET: std::time::Duration = std::time::Duration::from_secs(10);
/// The planner's shape question (OF-541, OF-389): this host's wording.
const PLANNER_WORDING: &str = "Which team shape should take this need? Pick the option whose \
model, pattern and width fit the need and its care level at the least expected spend.";
/// How long one shape pick may take before the planner's deterministic pick stands.
const PLANNER_BUDGET: std::time::Duration = std::time::Duration::from_secs(10);
/// A served wave cut's fan-out AUTO ruling (FIX 939): this host's wording.
const WAVE_FANOUT_WORDING: &str = "Should this wave's fan-out launch go ahead without its owner? \
Answer allow when its width and the history of launches like it show the owner would let it \
run, deny when they show the owner would refuse it, and escalate-to-human when they settle \
neither.";
/// How long one wave cut's fan-out ruling may take; a ruling still open then
/// leaves the cut held for the owner's approval.
pub(crate) const WAVE_FANOUT_BUDGET: std::time::Duration = std::time::Duration::from_secs(10);
/// The skill-attribution sweep's per-outcome question (OF-420): this host's
/// wording.
const ATTRIBUTION_WORDING: &str = "Which label fits this finished attempt's outcome? Answer \
skill_defect when the skill's own text was wrong, execution_lapse when the attempt did not do \
what the skill said, discovery when the skill left out the step that was needed, environment \
when neither the skill nor the attempt caused it, and unclear when the record does not settle \
it.";
/// How long one outcome's attribution may take; an outcome still open then
/// abstains and attributes to nobody.
const ATTRIBUTION_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);
/// A critic review's four typed questions, asked after each lens's own
/// prompt contract: this host's wording.
const REVIEW_VERDICT_WORDING: &str = "Under this lens, what should happen to the artifact? \
Answer accept when it stands as it is, revise when it needs changes first, and discard when \
no change would make it stand.";
const REVIEW_SEVERITY_WORDING: &str = "Under this lens, how serious is the worst problem it \
finds? Answer info, low, medium, high or blocking; info when it finds none.";
const REVIEW_HARD_CHECK_WORDING: &str = "Does the artifact pass this lens's hard check? Yes \
only when the check's condition holds in full.";
const REVIEW_OUT_OF_SCOPE_WORDING: &str = "Is this artifact outside what this lens reviews? Yes \
when the lens's contract does not apply to it, so its answers should not count.";
/// How long one lens's questions may take; a lens still open then fails the
/// review, as a failed critic call did.
const REVIEW_LENS_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);
/// A campaign split's two taste questions over its blind input (FIX 655):
/// this host's wording.
const CAMPAIGN_TASTE_SCORE_WORDING: &str = "How good is this claim, read against its evidence \
and the held-out gold it is anchored to? Answer 0 when it is wrong or unsupported and 1 when it \
is right, fully supported and worth keeping.";
const CAMPAIGN_TASTE_USEFUL_WORDING: &str = "Would the vault's owner want this claim kept as a \
memory? Yes when it is true and worth recalling; no when it is trivial, redundant or wrong.";
/// How long a split's taste pack may take; a score still open then refuses
/// the report.
const CAMPAIGN_TASTE_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);
const ONE: &str = "1";
/// The PersonThreshold row's version a host's start value takes.
const PERSON_THRESHOLD_VERSION: u32 = 1;
/// The ThinkThreshold row's version a host's start value takes.
const THINK_THRESHOLD_VERSION: u32 = 1;
/// The purpose the host's Local-vision rung budgets its calls under.
const LOCAL_VISION_PURPOSE: &str = "decision.local_vision";
/// The run each house read on the ladder is admitted as.
const HOUSE_READ_RUN: &str = "decision-read:ladder";
/// How long the person row may trail an accept whose commit sent no change
/// signal.
const PERSON_THRESHOLD_SWEEP: std::time::Duration = std::time::Duration::from_secs(60);
/// The dial of a ladder over one named model
/// ([`DecisionHost::ladder_for_model`]): its Big rung and no other.
pub const MODEL_DIAL: DecisionDial = DecisionDial {
    first: DecisionRung::Big,
    ceiling: DecisionRung::Big,
    band: DecisionBand {
        low: 0.35,
        high: 0.65,
    },
};

/// The ladder, its person queue and the bands every caller starts from.
#[derive(Clone)]
pub struct DecisionHost {
    ladder: HeldLadder,
    asks: Arc<DecisionAsks>,
    bands: DecisionBandPolicy,
    /// The configured start row, when the recipe names a person question.
    person_start: Option<PersonThreshold>,
    /// The configured ThinkThreshold start row, when the recipe names a
    /// paired question with one (FIX 2437).
    think_start: Option<ThinkThreshold>,
    /// One threshold-row refresh at a time (the person row's or the think
    /// row's), so an older read never lands last.
    person_refresh: Arc<std::sync::Mutex<()>>,
    auto_checker: Option<BoundedAutoChecker>,
    image_pick: Option<ImagePickSettings>,
    booking_parse: Option<BookingParseSettings>,
    connector_slate: Option<ConnectorSlateSettings>,
    import_audience: Option<ImportAudienceSettings>,
    /// `[models.decisions].wire_health`: the wire health question's wording.
    wire_health: Option<String>,
    /// The owner's explicit opt-in to send unit text off the host,
    /// `[models.decisions.system_one].remote_opt_in`.
    remote_opt_in: bool,
    /// The big model on the Big rung, kept so one named model can be asked
    /// as it asks ([`Self::ladder_for_model`]).
    big_model: Option<Arc<crate::big_rung::BigModel>>,
    /// The Big rung for a question whose posture keeps unit text on the
    /// host: the same big model, sent only where its route keeps the text
    /// (FIX 9525, [`Self::under_posture`]).
    big_on_host: Option<Arc<dyn DecisionProvider>>,
    /// Each caller's `ai.verdict` spend this window, for its check (FIX 1123).
    verdict_spend: Arc<crate::decision_verdict::VerdictSpend>,
    /// The vault's credential-broker context, which a `key_secret` System
    /// One seat sends through; `None` until serve sets one.
    broker: Option<crate::models::BrokerContext>,
    /// The notes beside decided answers: the big model's when one is bound,
    /// else the template (FIX 3040, 654).
    notes: notes::HostNotes,
}

impl DecisionHost {
    /// The rule table and the owner's ask queue: what every server has.
    pub(crate) fn new(vault: &Arc<Vault>) -> Self {
        let asks = Arc::new(DecisionAsks::new(Arc::clone(vault)));
        let rule = HostRuleProvider::new(Arc::clone(vault), RULE_TABLE.into(), ONE.into())
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
                paired: None,
                person: None,
                presence: None,
            },
            asks,
            bands: DecisionBandPolicy::default(),
            person_start: None,
            think_start: None,
            person_refresh: Arc::default(),
            auto_checker: None,
            image_pick: None,
            booking_parse: None,
            connector_slate: None,
            import_audience: None,
            wire_health: None,
            remote_opt_in: false,
            big_model: None,
            big_on_host: None,
            verdict_spend: Arc::default(),
            broker: None,
            notes: notes::HostNotes::default(),
        }
    }

    /// Each caller's `ai.verdict` spend this window (FIX 1123).
    pub(crate) fn verdict_spend(&self) -> &crate::decision_verdict::VerdictSpend {
        &self.verdict_spend
    }

    /// The house model's decision read on the escalation rung, each read
    /// admitted by `admission` as a run on `meter`, and its recipe's paired
    /// and person questions as the ladder's, each with its threshold row.
    /// Without a paired question in the recipe the rung stays empty.
    pub(crate) fn with_house_read(
        mut self,
        read: Option<&(DecisionReadDoor, BudgetGuard)>,
        admission: ReadAdmission,
    ) -> Self {
        self.ladder.escalation = None;
        self.ladder.paired = None;
        self.ladder.person = None;
        self.ladder.presence = None;
        self.bands = DecisionBandPolicy::default();
        self.person_start = None;
        self.think_start = None;
        let Some((door, meter)) = read else {
            // No house read: the ladder's paired is none, and the bound
            // big model tracks it (FIX 11466).
            self.update_big_paired(None);
            return self;
        };
        let Some(probe) = door.probe() else {
            tracing::warn!(
                "the decision read's recipe names no paired question; the escalation rung stays empty"
            );
            self.update_big_paired(None);
            return self;
        };
        // Q2: the house read asks it jointly; a generated read asks the
        // ladder's beside each of its questions.
        let paired = match THINK_MORE.question(&[], probe.paired.clone(), AnswerContract::Noul) {
            Ok(paired) => Some(paired),
            Err(error) => {
                tracing::warn!(%error, "the recipe's paired question is invalid");
                None
            }
        };
        let mut bands = DecisionBandPolicy::default();
        // Q2's threshold home: a paired reading at the row climbs a rung. An
        // accepted Coach row replaces this start value with a higher version
        // ([`Self::refresh_think_threshold`], FIX 2437).
        if let Some(threshold) = door.think_threshold() {
            match bands.set_think_threshold(threshold, THINK_THRESHOLD_VERSION) {
                Ok(()) => self.think_start = bands.think_threshold(),
                Err(error) => tracing::warn!(%error, "the think threshold is invalid"),
            }
        }
        if let Some(wording) = &probe.person {
            match ASK_UP.question(&[], wording.clone(), AnswerContract::Noul) {
                // Q3's threshold home: an accepted Coach row replaces this
                // start value with a higher version
                // ([`Self::refresh_person_threshold`]).
                Ok(person) => match bands
                    .set_person_threshold(door.person_threshold(), PERSON_THRESHOLD_VERSION)
                {
                    Ok(()) => {
                        self.ladder.person = Some(person);
                        self.person_start = bands.person_threshold();
                    }
                    Err(error) => tracing::warn!(%error, "the person threshold is invalid"),
                },
                Err(error) => tracing::warn!(%error, "the recipe's person question is invalid"),
            }
        }
        self.bands = bands;
        // A Box or Point call asks the recipe's presence question first.
        if let Some(wording) = &probe.presence {
            match IMAGE_PRESENCE.question(&[], wording.clone(), AnswerContract::Noul) {
                Ok(presence) => self.ladder.presence = Some(presence),
                Err(error) => tracing::warn!(%error, "the recipe's presence question is invalid"),
            }
        }
        self.ladder.paired.clone_from(&paired);
        // The bound big model reads the rebuilt paired question jointly
        // (FIX 1557); a rebuild binds it to the new one, or none (FIX 11466).
        self.update_big_paired(paired.clone());
        let Some(paired) = paired else {
            return self;
        };
        // The read takes the ladder's person question, which it reads apart.
        let gate = HouseGate {
            meter: meter.clone(),
            connector: door.connector().clone(),
            admission,
        };
        match HouseRead::new(
            door.reader(),
            gate,
            paired,
            self.ladder.person.clone(),
            door.connector().locality == ModelLocality::ThirdParty,
        ) {
            Ok(read) => self.ladder.escalation = Some(Arc::new(read)),
            Err(error) => {
                tracing::warn!(%error, "the house model's decision read cannot fill the escalation rung");
            }
        }
        self
    }

    /// The bound big model reads `paired` jointly from now on: a house-read
    /// rebuild reaches the rung `with_big` bound, which keeps no copy of its
    /// own (FIX 11466). Nothing bound, nothing to update.
    fn update_big_paired(&self, paired: Option<DecisionQuestion>) {
        if let Some(big) = self.big_model.as_ref() {
            big.set_paired(paired);
        }
    }

    /// The Local-vision seat on the Local rung, when
    /// `[models.roles.local_vision]` binds one, spending on its own meter of
    /// `default_units` for the server's life. A Box, Point or image question
    /// reaches it; it abstains on a call with no image before any call, so a
    /// text question steps past it unspent. A caller with a turn budget still
    /// seats its own per-call rung in its place.
    fn with_local_vision(
        mut self,
        ai: &crate::ai_host::AiHandle,
        vault: &Arc<Vault>,
        default_units: u64,
        runtime: tokio::runtime::Handle,
    ) -> Self {
        self.ladder.local = None;
        let meter = BudgetGuard::new(
            LOCAL_VISION_PURPOSE,
            default_units,
            BudgetExhaustionPolicy::Suspend,
        );
        let run = ai.undeclared_run(format!("{LOCAL_VISION_PURPOSE}:host"), meter);
        let Some(seat) = crate::ai_host::LocalVisionModel::new(ai, Arc::clone(vault), run, runtime)
        else {
            return self;
        };
        match seat.rung() {
            Ok(rung) => self.ladder.local = Some(Arc::new(rung)),
            Err(error) => tracing::warn!(%error, "the Local-vision seat cannot fill its rung"),
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
        self.remote_opt_in = settings.is_some_and(|settings| settings.remote_opt_in);
        let Some(settings) = settings else {
            return self;
        };
        match SystemOneRung::bind(
            settings,
            default_units,
            posture,
            runtime,
            self.broker.as_ref(),
        ) {
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
        self.big_model = None;
        self.big_on_host = None;
        self.notes = notes::HostNotes::default();
        let Some(settings) = settings else {
            return self;
        };
        // The house read's paired question, read jointly where the route
        // reports token scores (FIX 1557).
        let paired = self.ladder.paired.clone();
        let bound = crate::big_rung::BigModel::bind(
            settings,
            Arc::clone(models),
            Arc::clone(vault),
            default_units,
            runtime,
        )
        .map(|model| Arc::new(model.with_paired(paired)))
        .and_then(|model| {
            let pin = model.pin();
            let provider = ModelDecisionProvider::new(pin, Arc::clone(&model) as _)
                .map_err(anyhow::Error::from)?;
            Ok((model, provider))
        });
        match bound {
            Ok((model, rung)) => {
                self.ladder.big = Some(Arc::new(rung));
                self.big_on_host =
                    ModelDecisionProvider::new(model.pin(), Arc::new(model.kept_on_host()))
                        .ok()
                        .map(|rung| Arc::new(rung) as Arc<dyn DecisionProvider>);
                self.notes = notes::HostNotes::new(Some(Arc::clone(&model)));
                self.big_model = Some(model);
            }
            Err(error) => tracing::warn!(%error, "the big model cannot fill its rung"),
        }
        self
    }

    /// A ladder whose one rung is `model` on the Big rung (OF-184): asked as
    /// the configured big model is, worded and on its meter, but of that
    /// model alone with no owner's fallback, so the model that answers is
    /// the one named. Every other slot is empty and no person is asked: run
    /// it with [`MODEL_DIAL`]. Fails when `[models.decisions.big]` fills no
    /// Big rung, or no chat model with that id is served alone by its own
    /// id (a seat is not one model).
    pub fn ladder_for_model(&self, model: &ModelId) -> anyhow::Result<HeldLadder> {
        let big = self
            .big_model
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no [models.decisions.big] fills the Big rung"))?;
        let exact = big.for_model(model)?;
        let pin = exact.pin();
        let provider = ModelDecisionProvider::new(pin, Arc::new(exact))?;
        Ok(HeldLadder {
            big: Some(Arc::new(provider)),
            ..HeldLadder::unstaffed()
        })
    }

    /// A held-out arm over one exact configured backend, retaining provider
    /// usage for the engine's priced trial evidence.
    pub(crate) fn ladder_for_trial(
        &self,
        backend: &oneiron::llm::registry::ModelBackendPin,
        usage: Arc<std::sync::Mutex<Vec<oneiron::LlmUsage>>>,
    ) -> anyhow::Result<HeldLadder> {
        let big = self
            .big_model
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no [models.decisions.big] fills the Big rung"))?;
        let exact = big.for_trial(backend, usage)?;
        let provider = ModelDecisionProvider::new(exact.pin(), Arc::new(exact))?;
        Ok(HeldLadder {
            big: Some(Arc::new(provider)),
            ..HeldLadder::unstaffed()
        })
    }

    /// A ladder whose one rung is `role`'s seat on the Big rung (OF-568):
    /// asked as the configured big model is, worded and on its meter, but
    /// routed to that role's seat. Every other slot is empty and no person
    /// is asked: run it with [`MODEL_DIAL`]. Fails when `[models.decisions.big]`
    /// fills no Big rung, or no rung serves the role's seat.
    pub fn ladder_for_role(
        &self,
        role: oneiron::llm::manifest::ModelRole,
    ) -> anyhow::Result<HeldLadder> {
        let big = self
            .big_model
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no [models.decisions.big] fills the Big rung"))?;
        let seat = big.for_role(role)?;
        let pin = seat.pin();
        let provider = ModelDecisionProvider::new(pin, Arc::new(seat))?;
        Ok(HeldLadder {
            big: Some(Arc::new(provider)),
            ..HeldLadder::unstaffed()
        })
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
                notes: Arc::new(self.notes.clone()),
                calibrated: None,
            })
        });
        self
    }

    /// The per-image pick's wording and budget (OF-329).
    fn with_image_pick(mut self, settings: Option<&ImagePickSettings>) -> Self {
        self.image_pick = settings.cloned();
        self
    }

    /// The cheap seat a booking page's free text is parsed on.
    fn with_booking_parse(mut self, settings: Option<BookingParseSettings>) -> Self {
        self.booking_parse = settings;
        self
    }

    /// The connector slate drafter's wording and budget (OF-189).
    fn with_connector_slate(mut self, settings: Option<&ConnectorSlateSettings>) -> Self {
        self.connector_slate = settings.cloned();
        self
    }

    /// The per-row wording `[models.decisions.connector_slate]` gives a
    /// connector registration's slate drafter; `None` leaves the rule rung
    /// drafting alone.
    #[must_use]
    pub fn connector_slate(&self) -> Option<&ConnectorSlateSettings> {
        self.connector_slate.as_ref()
    }

    /// The import audience questions' wording and budget (OF-492).
    fn with_import_audience(mut self, settings: Option<&ImportAudienceSettings>) -> Self {
        self.import_audience = settings.cloned();
        self
    }

    /// The two questions `[models.decisions.import_audience]` words for an
    /// imported topic; `None` asks nothing, and every import stays private.
    #[must_use]
    pub fn import_audience(&self) -> Option<&ImportAudienceSettings> {
        self.import_audience.as_ref()
    }

    /// The wire health question's wording (FIX 1088).
    fn with_wire_health(mut self, wording: Option<&str>) -> Self {
        self.wire_health = wording.map(str::to_owned);
        self
    }

    /// The wording `[models.decisions].wire_health` gives the wire health
    /// question; `None` asks in the host's own words.
    #[must_use]
    pub fn wire_health_wording(&self) -> Option<&str> {
        self.wire_health.as_deref()
    }

    /// The seat `[models.decisions.booking_parse]` names for a booking's
    /// free text; `None` refuses free text.
    #[must_use]
    pub fn booking_parse(&self) -> Option<&BookingParseSettings> {
        self.booking_parse.as_ref()
    }
}

fn pin(rung: DecisionRung, model: &str, version: &str) -> ProviderPin {
    ProviderPin {
        rung,
        model: model.to_owned(),
        version: version.to_owned(),
    }
}

/// What admits each house read on the ladder as the `/v1/llm/decision_read`
/// probe admits its own: the server's `limits.decision_reads` pool, its host
/// account and its run receipts.
pub(crate) struct ReadAdmission {
    pub(crate) turns: crate::admission::Admission<()>,
    pub(crate) host: Arc<HostAccount>,
    pub(crate) receipts: Arc<dyn RunReceiptSink>,
}

/// The house read's gate: a `limits.decision_reads` turn, then one run on
/// the meter per read, admitted and dispatched before the read and settled
/// once after it.
struct HouseGate {
    meter: BudgetGuard,
    connector: PaidConnector,
    admission: ReadAdmission,
}

/// The house model's decision read, owned. Each call lends it to the
/// engine's [`DecisionReadProvider`], which admits and settles each read
/// through its [`HouseGate`]. The reader blocks on the server's runtime.
struct HouseRead {
    pin: ProviderPin,
    reader: Arc<dyn LabelReadModel>,
    gate: HouseGate,
    paired: DecisionQuestion,
    person: Option<DecisionQuestion>,
    /// The reader's provider is a third party's.
    leaves: bool,
}

impl HouseRead {
    fn new(
        reader: Arc<dyn LabelReadModel>,
        gate: HouseGate,
        paired: DecisionQuestion,
        person: Option<DecisionQuestion>,
        leaves: bool,
    ) -> oneiron::Result<Self> {
        let read = Self {
            pin: pin(DecisionRung::Escalation, reader.model(), reader.revision()),
            paired,
            person,
            reader,
            gate,
            leaves,
        };
        read.provider()?;
        Ok(read)
    }

    fn provider(&self) -> oneiron::Result<DecisionReadProvider<'_>> {
        DecisionReadProvider::new(
            self.pin.clone(),
            self.reader.as_ref(),
            &self.gate,
            &self.paired,
            self.person.as_ref(),
        )
    }
}

/// The remote System One seat as a ladder rung: each question is one
/// measurement admitted and settled on the seat's own meter, sent on the
/// server's runtime (so a call blocks its thread, inside the pass or run of
/// the ladder call that asks it). It takes noul and choice questions; a
/// score question's level labels are the caller's, and a ladder call does
/// not carry them. A `key_env` seat holds its bearer from bind; a
/// `key_secret` seat reads its key at the vault's custody door for each
/// call, through the credential broker.
struct SystemOneRung {
    seat: Arc<oneiron_llm_systemone::SystemOneSeat>,
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
        broker: Option<&crate::models::BrokerContext>,
    ) -> anyhow::Result<Self> {
        let endpoint = settings.endpoint.clone();
        let (model, version) = (settings.model.clone(), settings.version.clone());
        let seat = match (&settings.key_env, &settings.key_secret) {
            (Some(env), _) => {
                let bearer = std::env::var(env).map_err(|_| anyhow::anyhow!("{env} is not set"))?;
                oneiron_llm_systemone::SystemOneSeat::new(endpoint, bearer, model, version)
            }
            (None, Some(secret)) => {
                let broker = broker.ok_or_else(|| {
                    anyhow::anyhow!(
                        "its key_secret needs the vault's credential broker, and none was opened"
                    )
                })?;
                oneiron_llm_systemone::SystemOneSeat::with_transport(
                    endpoint,
                    model,
                    version,
                    broker.system_one(secret),
                )
            }
            (None, None) => anyhow::bail!("it names no key_env or key_secret"),
        }
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

/// The receipts' notes beside a decided answer, written from the decision
/// itself: the answer is already decided, and a note cannot change it.
struct LadderNotes;
