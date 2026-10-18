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

use oneiron::booking::constraint::BookingDecisions;
use oneiron::critic::review::{REVIEW_DIAL, ReviewDecisions, ReviewWording};
use oneiron::fanout_auto::FanoutDecisions;
use oneiron::llm::decision::catalogue::{ASK_UP, IMAGE_PRESENCE, TASK_SURFACE, THINK_MORE};
use oneiron::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionAsks, DecisionBand, DecisionBandPolicy, DecisionCall,
    DecisionDial, DecisionPack, DecisionProvider, DecisionQuestion, DecisionReadGate,
    DecisionReadProvider, DecisionRung, GatedRead, HeldLadder, HostRuleProvider,
    ModelDecisionProvider, PersonThreshold, ProviderCapability, ProviderDecision, ProviderPin,
    RemoteDecisionSeat, SeatPhase, SeatRequest,
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

/// The rule table's identity on this host: the vault's host rule rows, which the owner's
/// reasons write ([`oneiron::llm::decision::HostRule`]).
const RULE_TABLE: &str = "host-rules";
/// The owner ask queue's identity, the ladder's human pin.
const OWNER_ASKS: &str = "owner-asks";
/// The task surface's questions: this host's wording.
const TASK_TAKE_WORDING: &str = "Should this agent take the proposed task? Yes only when the \
task fits what the agent's definition says it does and what it may touch.";
const TASK_DONE_MET_WORDING: &str = "Does this result meet the task's brief? Yes only when the \
result meets every yes_if_all criterion and no no_if_any criterion holds.";
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
    /// One person-row refresh at a time, so an older read never lands last.
    person_refresh: Arc<std::sync::Mutex<()>>,
    auto_checker: Option<BoundedAutoChecker>,
    image_pick: Option<ImagePickSettings>,
    booking_parse: Option<BookingParseSettings>,
    connector_slate: Option<ConnectorSlateSettings>,
    import_audience: Option<ImportAudienceSettings>,
    /// The owner's explicit opt-in to send unit text off the host,
    /// `[models.decisions.system_one].remote_opt_in`.
    remote_opt_in: bool,
    /// The big model on the Big rung, kept so one named model can be asked
    /// as it asks ([`Self::ladder_for_model`]).
    big_model: Option<Arc<crate::big_rung::BigModel>>,
    /// Each caller's `ai.verdict` spend this window, for its check (FIX 1123).
    verdict_spend: Arc<crate::decision_verdict::VerdictSpend>,
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
            person_refresh: Arc::default(),
            auto_checker: None,
            image_pick: None,
            booking_parse: None,
            connector_slate: None,
            import_audience: None,
            remote_opt_in: false,
            big_model: None,
            verdict_spend: Arc::default(),
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
        let Some((door, meter)) = read else {
            return self;
        };
        let Some(probe) = door.probe() else {
            tracing::warn!(
                "the decision read's recipe names no paired question; the escalation rung stays empty"
            );
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
        // Q2's threshold home: a paired reading at the row climbs a rung.
        if let Some(threshold) = door.think_threshold()
            && let Err(error) = bands.set_think_threshold(threshold, THINK_THRESHOLD_VERSION)
        {
            tracing::warn!(%error, "the think threshold is invalid");
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
        self.big_model = None;
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
        .map(Arc::new)
        .and_then(|model| {
            let pin = model.pin();
            let provider = ModelDecisionProvider::new(pin, Arc::clone(&model) as _)
                .map_err(anyhow::Error::from)?;
            Ok((model, provider))
        });
        match bound {
            Ok((model, rung)) => {
                self.ladder.big = Some(Arc::new(rung));
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
                notes: Arc::new(LadderNotes),
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

    /// The seat `[models.decisions.booking_parse]` names for a booking's
    /// free text; `None` refuses free text.
    #[must_use]
    pub fn booking_parse(&self) -> Option<&BookingParseSettings> {
        self.booking_parse.as_ref()
    }

    /// The ladder every typed decision on this host goes through.
    #[must_use]
    pub fn ladder(&self) -> &HeldLadder {
        &self.ladder
    }

    /// Whether the owner opted in to sending unit text off the host, for
    /// [`oneiron::llm::decision::DecisionLadder::under_posture`].
    #[must_use]
    pub fn remote_opt_in(&self) -> bool {
        self.remote_opt_in
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

    /// Installs the newest accepted Coach revision of the person row (Q3)
    /// above the configured start row, else the start row, on every clone of
    /// the host's bands. A host whose recipe names no person question keeps
    /// none.
    pub(crate) fn refresh_person_threshold(&self, vault: &Vault) -> oneiron::Result<()> {
        let Some(start) = self.person_start else {
            return Ok(());
        };
        let _turn = self
            .person_refresh
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let row = vault
            .latest_accepted_person_threshold()?
            .map(|(_, row)| row)
            .filter(|row| row.version > start.version)
            .unwrap_or(start);
        if self.bands.person_threshold() != Some(row) {
            self.bands.replace_person_threshold(row)?;
            tracing::info!(
                threshold = row.threshold,
                version = row.version,
                "the person threshold row changed"
            );
        }
        Ok(())
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

    /// The task highway's three surface questions through this ladder, up
    /// to the Big rung: a question no model answers asks up on the TASK.
    pub(crate) fn task_decisions(&self) -> oneiron::Result<TaskDecisions<'_>> {
        let question = |which: &[u8], wording: &str| {
            TASK_SURFACE.question(&[which], wording.to_owned(), AnswerContract::Noul)
        };
        Ok(TaskDecisions {
            ladder: self.ladder.ladder(),
            dial: self.dial(DecisionRung::Big),
            bands: self.bands.clone(),
            take: question(b"take".as_slice(), TASK_TAKE_WORDING)?,
            done: question(b"done_met".as_slice(), TASK_DONE_MET_WORDING)?,
            ask_up: question(b"ask_up".as_slice(), TASK_ASK_UP_WORDING)?,
            budget: TASK_DECISION_BUDGET,
        })
    }

    /// The placement question through this ladder for `principal`, up to the
    /// Big rung (a placement never asks a person), within `deadline`.
    pub(crate) fn placement_decisions<'a>(
        &'a self,
        principal: EntityId,
        deadline: &'a RetrievalDeadline,
    ) -> PlacementDecisions<'a> {
        PlacementDecisions {
            ladder: self.ladder.ladder(),
            principal,
            dial: self.dial(DecisionRung::Big),
            bands: self.bands.clone(),
            wording: PLACEMENT_WORDING.to_owned(),
            deadline,
        }
    }

    /// A leased agent run's planner ladder (OF-541, OF-389): the shape pick
    /// and the type placement for `principal`, up to the Big rung, each call
    /// on its own fresh clock.
    pub(crate) fn host_planner_decisions(
        &self,
        principal: EntityId,
    ) -> oneiron::code_run::HostPlannerDecisions<'_> {
        oneiron::code_run::HostPlannerDecisions {
            ladder: &self.ladder,
            principal,
            bands: self.bands.clone(),
            planner_wording: PLANNER_WORDING.to_owned(),
            planner_budget: PLANNER_BUDGET,
            placement_dial: self.dial(DecisionRung::Big),
            placement_wording: PLACEMENT_WORDING.to_owned(),
            placement_budget: PLACEMENT_BUDGET,
        }
    }

    /// The Dreamer's consolidation questions through this ladder, in the
    /// shipped wording: the verdict role's generated read sits at the Local
    /// slot, and an answer still in the band steps up the host's stronger
    /// rungs under the host's bands. A consolidation verdict never asks a
    /// person: the executor caps its dial at Big (`VERDICT_CEILING`, OF-023),
    /// and a verdict still in band parks its pair as a `conflict.open` with
    /// both claims standing.
    pub(crate) fn consolidation_decisions(&self) -> oneiron::Result<ConsolidationDecisions> {
        Ok(ConsolidationDecisions {
            ladder: self.ladder.clone(),
            dial: DecisionDial {
                first: DecisionRung::Local,
                ceiling: DecisionRung::Human,
                band: DecisionBand::default(),
            },
            bands: self.bands.clone(),
            ..ConsolidationDecisions::shipped()?
        })
    }

    /// The fast per-image pick (OF-329) for `principal`'s `task`, when
    /// `[models.decisions.image_pick]` words it. It asks the quick rungs
    /// only, up to System One, under the host's bands; a pick no rung
    /// answers in band serves the image in full.
    #[must_use]
    pub fn image_pick(&self, principal: EntityId, task: String) -> Option<ImagePick<'_>> {
        let settings = self.image_pick.as_ref()?;
        Some(ImagePick {
            ladder: self.ladder.ladder(),
            principal,
            dial: self.dial(DecisionRung::SystemOne),
            bands: self.bands.clone(),
            wording: settings.wording.clone(),
            task,
            budget: settings.budget,
        })
    }

    /// The saved-query membership judge through this ladder, in the shipped
    /// wording and budget: the judge's generated read sits at the Local slot,
    /// and an answer still in the band steps up the host's stronger rungs to
    /// the Big rung, under the host's bands.
    pub fn membership_decisions(&self) -> oneiron::Result<MembershipDecisions> {
        Ok(MembershipDecisions {
            ladder: self.ladder.clone(),
            dial: DecisionDial {
                first: DecisionRung::Local,
                ceiling: DecisionRung::Big,
                band: DecisionBand::default(),
            },
            bands: self.bands.clone(),
            ..MembershipDecisions::shipped()?
        })
    }

    /// A booking's free-text parse through this ladder for `principal`, on
    /// the shipped budget: the parse tier's read sits at System One, and an
    /// answer still in the band steps up to the Big rung.
    #[must_use]
    pub fn booking_decisions(&self, principal: EntityId) -> BookingDecisions {
        BookingDecisions {
            ladder: self.ladder.clone(),
            dial: DecisionDial {
                first: DecisionRung::SystemOne,
                ceiling: DecisionRung::Big,
                band: DecisionBand::default(),
            },
            bands: self.bands.clone(),
            ..BookingDecisions::shipped(principal)
        }
    }

    /// The fan-out AUTO ruling through this ladder for `principal`, worded
    /// `wording`, up to the Big rung: the fan-out's own approval asks the
    /// person, so this dial never does.
    #[must_use]
    pub fn fanout_decisions<'a>(
        &'a self,
        principal: EntityId,
        wording: String,
        deadline: &'a RetrievalDeadline,
    ) -> FanoutDecisions<'a> {
        FanoutDecisions {
            ladder: self.ladder.ladder(),
            principal,
            dial: self.dial(DecisionRung::Big),
            bands: self.bands.clone(),
            wording,
            deadline,
        }
    }

    /// A served wave cut's fan-out AUTO ruling (FIX 939) for `principal`, the
    /// actor whose request queued the cut, in this host's wording, on
    /// `deadline` ([`WAVE_FANOUT_BUDGET`] from the ask).
    #[must_use]
    pub(crate) fn wave_fanout_decisions<'a>(
        &'a self,
        principal: EntityId,
        deadline: &'a RetrievalDeadline,
    ) -> FanoutDecisions<'a> {
        self.fanout_decisions(principal, WAVE_FANOUT_WORDING.to_owned(), deadline)
    }

    /// The skill-attribution sweep's ladder (OF-420): this host's, with the
    /// rule tier ([`AttributionRules`]) on its Rule rung, so a settled cause
    /// is routed before any model is asked.
    #[must_use]
    pub(crate) fn attribution_ladder(&self) -> HeldLadder {
        HeldLadder {
            rule: Some(Arc::new(AttributionRules) as Arc<dyn DecisionProvider>),
            ..self.ladder.clone()
        }
    }

    /// The attempt sweep's attribution for `principal` on `ladder` (from
    /// [`Self::attribution_ladder`]), in this host's wording: the rules
    /// first, then this host's model rungs up to Big, never a person, since
    /// a doubtful outcome already holds in the unclear ledger. Each doubtful
    /// answer takes its note from `notes`.
    #[must_use]
    pub(crate) fn attribution_decisions<'a>(
        &self,
        ladder: &'a HeldLadder,
        principal: EntityId,
        notes: &'a dyn AttributionNotes,
    ) -> AttributionDecisions<'a> {
        AttributionDecisions {
            ladder: ladder.ladder(),
            principal,
            dial: DecisionDial {
                first: DecisionRung::Rule,
                ..ATTRIBUTION_DIAL
            },
            bands: self.bands.clone(),
            wording: ATTRIBUTION_WORDING.to_owned(),
            budget: ATTRIBUTION_BUDGET,
            notes: Some(notes),
        }
    }

    /// A critic review's questions through this ladder for `principal`, the
    /// caller, over `state`, the target as the caller reads it: the engine's
    /// review dial, this host's bands and wording, one clock per lens, and no
    /// notes.
    #[must_use]
    pub(crate) fn review_decisions<'a>(
        &'a self,
        principal: EntityId,
        state: &'a serde_json::Value,
    ) -> ReviewDecisions<'a> {
        ReviewDecisions {
            ladder: self.ladder.ladder(),
            principal,
            dial: REVIEW_DIAL,
            bands: self.bands.clone(),
            state,
            budget: REVIEW_LENS_BUDGET,
            wording: ReviewWording {
                verdict: REVIEW_VERDICT_WORDING.to_owned(),
                severity: REVIEW_SEVERITY_WORDING.to_owned(),
                hard_check: REVIEW_HARD_CHECK_WORDING.to_owned(),
                out_of_scope: REVIEW_OUT_OF_SCOPE_WORDING.to_owned(),
            },
            notes: None,
        }
    }

    /// The merge doors' useful-upstream question through this ladder, on
    /// `deadline`. The doors require a System One or escalation seat to
    /// answer first, so the dial starts at the first of those this host
    /// fills; with neither, the question cannot be asked here.
    pub fn useful_upstream<'a>(
        &'a self,
        deadline: &'a RetrievalDeadline,
    ) -> oneiron::Result<UsefulUpstreamDecisions<'a>> {
        let first = if self.ladder.system_one.is_some() {
            DecisionRung::SystemOne
        } else if self.ladder.escalation.is_some() {
            DecisionRung::Escalation
        } else {
            return Err(oneiron::Error::InvalidConfig(
                "useful-upstream needs a System One seat or the house read on this host".into(),
            ));
        };
        Ok(UsefulUpstreamDecisions {
            ladder: self.ladder.ladder(),
            dial: DecisionDial {
                first,
                ceiling: DecisionRung::Big,
                band: DecisionBand::default(),
            },
            bands: self.bands.clone(),
            deadline,
        })
    }

    /// A claim refinement's held-out replay score through this ladder,
    /// worded `wording`, on `deadline`, up to the Big rung.
    #[must_use]
    pub fn claim_replay<'a>(
        &'a self,
        wording: String,
        deadline: &'a RetrievalDeadline,
    ) -> ClaimReplayDecisions<'a> {
        ClaimReplayDecisions {
            ladder: self.ladder.ladder(),
            dial: self.dial(DecisionRung::Big),
            bands: self.bands.clone(),
            wording,
            deadline,
        }
    }

    /// The policy safeguard's typed read through this ladder for `principal`,
    /// worded `wording` at `revision`, up to the Big rung, each read on
    /// `budget`: one per enabled plane, held by the plane's policy config.
    pub fn policy_decisions(
        &self,
        principal: EntityId,
        revision: String,
        wording: String,
        budget: std::time::Duration,
    ) -> oneiron::Result<PolicyDecisions> {
        PolicyDecisions::new(
            Arc::new(self.ladder.clone()),
            principal,
            self.dial(DecisionRung::Big),
            self.bands.clone(),
            revision,
            wording,
            budget,
        )
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

    /// [`DecisionHost::ladder_for_model`] on this server's ladder.
    pub fn decision_ladder_for_model(&self, model: &ModelId) -> anyhow::Result<HeldLadder> {
        self.decisions.ladder_for_model(model)
    }

    /// [`DecisionHost::ladder_for_role`] on this server's ladder.
    pub fn decision_ladder_for_role(
        &self,
        role: oneiron::llm::manifest::ModelRole,
    ) -> anyhow::Result<HeldLadder> {
        self.decisions.ladder_for_role(role)
    }

    /// The family `model` belongs to, as its provider's config or its
    /// registry row names it; a seat's when every rung shares one. `None`
    /// when nothing names it, never guessed.
    pub fn model_family(&self, model: &ModelId) -> oneiron::Result<Option<String>> {
        self.ai.models().model_family(&self.vault, model)
    }

    /// Every chat model served alone by its own id whose known family is
    /// none of `models`', in id order: where a third opinion may come from,
    /// each one a [`Self::decision_ladder_for_model`] takes. Empty when any
    /// of `models` has no known family.
    pub fn models_outside_families(&self, models: &[&ModelId]) -> oneiron::Result<Vec<ModelId>> {
        self.ai
            .models()
            .models_outside_families(&self.vault, models)
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
            .with_local_vision(
                &self.ai,
                &self.vault,
                models.raw_budget_units,
                tokio::runtime::Handle::current(),
            )
            .with_big(
                models.decisions.big.as_ref(),
                self.ai.models(),
                &self.vault,
                models.raw_budget_units,
                tokio::runtime::Handle::current(),
            )
            .with_auto_check(models.decisions.auto_check.as_deref(), principal)
            .with_image_pick(models.decisions.image_pick.as_ref())
            .with_booking_parse(models.decisions.booking_parse.clone())
            .with_connector_slate(models.decisions.connector_slate.as_ref())
            .with_import_audience(models.decisions.import_audience.as_ref());
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

/// Keeps the host's person row on the newest accepted Coach revision: it
/// re-reads after each committed change, and every sweep for an accept whose
/// commit sent no change signal. `None` when the recipe names no person
/// question.
pub(crate) fn spawn_person_threshold(
    server: &Arc<SyncServer>,
) -> Option<tokio::task::JoinHandle<()>> {
    server.decision_host().person_start?;
    let weak = Arc::downgrade(server);
    // Subscribed before the first read, so no change between them is lost.
    let mut changes = server.vault().subscribe_proactivity_changes();
    Some(tokio::spawn(async move {
        loop {
            let Some(server) = weak.upgrade() else {
                break;
            };
            let ran = tokio::task::spawn_blocking(move || {
                server
                    .decision_host()
                    .refresh_person_threshold(server.vault())
            })
            .await;
            match ran {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    tracing::warn!(kind = ?error.kind(), "the person threshold refresh failed; it runs again on the next change");
                }
                Err(error) => tracing::warn!(%error, "the person threshold refresh stopped"),
            }
            tokio::select! {
                () = tokio::time::sleep(PERSON_THRESHOLD_SWEEP) => {}
                changed = changes.changed() => {
                    if changed.is_err() {
                        break;
                    }
                }
            }
        }
    }))
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

impl DecisionReadGate for HouseGate {
    fn read(&self, read: &mut dyn FnMut(&BudgetLease) -> GatedRead) -> oneiron::Result<GatedRead> {
        let refused = |what: &str| oneiron::Error::InvalidConfig(format!("decision read: {what}"));
        // The host's own work: its turn comes while no caller waits for one.
        let _turn = self
            .admission
            .turns
            .admit_background_blocking()
            .map_err(|_| refused("waited out its turn"))?;
        // Inside a verdict, the caller's own line (FIX 1123).
        let meter = crate::decision_verdict::rung_meter(&self.meter);
        let run = crate::models::undeclared_run(
            HOUSE_READ_RUN,
            meter.clone(),
            Some(Arc::clone(&self.admission.host)),
            Arc::clone(&self.admission.receipts),
        );
        let permit = run
            .admit_paid(&self.connector, meter.reserve_units())
            .map_err(|_| refused("refused by the budget"))?;
        run.dispatch_paid(permit.lease(), &self.connector)
            .map_err(|_| refused("refused at dispatch"))?;
        let gated = read(permit.lease());
        let unread = oneiron::llm::LlmUsage::zero();
        // A read that went out and failed keeps its reservation as spend.
        let outcome = match &gated {
            GatedRead::NotStarted => CallOutcome::Answered(&unread),
            GatedRead::Read(Ok(answer)) => CallOutcome::Answered(&answer.usage),
            GatedRead::Read(Err(_)) => CallOutcome::Failed,
        };
        if let Err(denied) = permit.settle(outcome) {
            tracing::error!(%denied, "a house decision read's settlement was refused");
        }
        Ok(gated)
    }
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

impl DecisionProvider for HouseRead {
    fn pin(&self) -> ProviderPin {
        self.pin.clone()
    }

    fn capability(&self) -> ProviderCapability {
        self.provider()
            .map_or_else(|_| ProviderCapability::default(), |read| read.capability())
    }

    fn leaves_host(&self) -> bool {
        self.leaves
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

    /// The seat sends a call's images as named wire assets, when the posture
    /// lets a call leave the host at all.
    fn reads_images(&self) -> bool {
        (self.posture == HostingPrivacyPosture::Hosted || self.remote_opt_in)
            && self.posture != HostingPrivacyPosture::Relay
    }

    fn image_edge(&self) -> Option<u32> {
        self.seat.image_edge()
    }

    /// The seat is remote: every call leaves the host.
    fn leaves_host(&self) -> bool {
        true
    }

    fn decide(&self, call: &DecisionCall<'_>) -> oneiron::Result<ProviderDecision> {
        let failed = |what: &str| oneiron::Error::InvalidConfig(format!("system one: {what}"));
        let request = SeatRequest {
            question: call.question.clone(),
            state: call.state.clone(),
            images: call.images.to_vec(),
            audio: call.audio.to_vec(),
            score_levels: Vec::new(),
            posture: self.posture,
            remote_opt_in: self.remote_opt_in,
            phase: SeatPhase::Background,
        };
        request
            .validate_remote()
            .map_err(|_| failed("the posture or the request keeps this call local"))?;
        // Inside a verdict, the caller's own line (FIX 1123).
        let guard = crate::decision_verdict::rung_meter(&self.guard);
        let lease = guard
            .admit()
            .map_err(|_| failed("refused by the budget"))?
            .lease;
        // A measurement admitted after the work time is spent never starts.
        if call.deadline.decision_time_left().is_zero() {
            guard
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
                guard
                    .settle_per_call(&lease, &answer.usage)
                    .map_err(|_| failed("settlement refused"))?;
                answer
            }
            Err(error) => {
                // The seat may still bill a failed call.
                guard
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
            served: None,
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
