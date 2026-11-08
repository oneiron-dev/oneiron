//! The house model's decision read as the ladder's escalation rung, built from
//! the `--models-toml` file as the server's decision host builds it: the
//! `[models.decision_read]` door's reader on the `local_reasoner` rung, its
//! recipe's paired question as the ladder's own, and the ThinkThreshold row at
//! the door's start value and the host's start version. Each read is admitted
//! and settled on one bare meter. When the file binds
//! `[models.decisions.big]`, the Big rung is the served host's own binding of
//! it ([`big_rung`]); no other rung is filled and no person is asked, so one
//! run measures exactly the routes these rungs return.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::llm::LabelReadModel;
use oneiron::llm::decision::catalogue::THINK_MORE;
use oneiron::llm::decision::{
    AnswerContract, DecisionBandPolicy, DecisionDial, DecisionProvider, DecisionQuestion,
    DecisionReadProvider, DecisionRung, HeldLadder, ProviderPin, Reversibility, TypedDecision,
};
use oneiron::llm::manifest::ModelRole;
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::{BudgetExhaustionPolicy, BudgetGuard, EntityId, HostingPrivacyPosture};
use oneiron_server::config::ModelsConfig;
use oneiron_server::config::models::BigSettings;
use oneiron_server::decision_host::{BigRung, THINK_THRESHOLD_VERSION};
use oneiron_server::models::ModelRuntime;
use serde::Serialize;

use super::failure;
use crate::eval::EvalResult;

mod big_rung;
use big_rung::BigPins;

/// The units the read meter holds: far past any bench run, so no case is
/// refused for spend while every read still reserves and settles on it.
const READ_METER_UNITS: u64 = 1_000_000_000_000;
/// The attempt the read meter names.
const READ_METER_ATTEMPT: &str = "eval-route-calibration";

/// What the models TOML pins, as the run header names it.
#[derive(Clone, Serialize)]
pub(super) struct ModelPins {
    pub(super) models_toml: String,
    /// BLAKE3 of the file's bytes, as read.
    pub(super) models_toml_blake3: String,
    /// The `local_reasoner` rung the read serves, as `provider:model`.
    pub(super) local_reasoner: String,
    /// The rung's provider revision, as the file names it.
    pub(super) provider_revision: String,
    /// The recipe's fingerprint: its templates, labels and verbalizer tokens.
    pub(super) recipe_fingerprint: String,
    /// The pin every answer of this run is measured under.
    pub(super) escalation: ProviderPin,
    /// The recipe's paired question ("does this need more thinking?").
    pub(super) paired_question: String,
    pub(super) think_threshold: Option<f64>,
    pub(super) think_threshold_version: Option<u32>,
    /// The PersonThreshold row's start value; no dial this bench runs reaches
    /// the person, so it routes nothing here.
    pub(super) person_threshold: f64,
    /// The Big rung `[models.decisions.big]` binds; none without the section.
    pub(super) big: Option<BigPins>,
}

/// The escalation rung's parts, and the Big rung once bound, owned for the
/// run; each call lends them to one ladder.
pub(super) struct HouseReadRung {
    pins: ModelPins,
    reader: Arc<dyn LabelReadModel>,
    meter: BudgetGuard,
    paired: DecisionQuestion,
    bands: DecisionBandPolicy,
    /// The runtime the reader was bound on, held for the run; the Big rung
    /// binds on it too.
    models: Arc<ModelRuntime>,
    /// `[models.decisions.big]` as the file binds it, with the raw routes'
    /// units its meter falls back to; none without the section.
    big_section: Option<(BigSettings, u64)>,
    /// The Big rung, once bound on the run's vault.
    big: Option<BigRung>,
}

impl HouseReadRung {
    /// The rung `path` configures, its reads sent on `runtime`. Refused when
    /// the file binds no decision read, its provider is not ready, or its
    /// recipe names no paired question.
    pub(super) fn load(path: &Path, runtime: &tokio::runtime::Runtime) -> EvalResult<Self> {
        let bytes = std::fs::read(path)?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| failure(format!("--models-toml {} is not UTF-8", path.display())))?;
        let body = crate::infer::config::section_body(text);
        let config = ModelsConfig::from_toml(&body, path.parent())
            .map_err(|error| failure(format!("--models-toml {}: {error:#}", path.display())))?;
        let settings = config.decision_read.as_ref().ok_or_else(|| {
            failure(format!(
                "--models-toml {} binds no [models.decision_read]",
                path.display()
            ))
        })?;
        let rung = config
            .roles
            .get(&ModelRole::LocalReasoner)
            .and_then(|ladder| ladder.first())
            .ok_or_else(|| failure("the decision read needs roles.local_reasoner".to_owned()))?;
        let provider = config.providers.get(&rung.model.provider).ok_or_else(|| {
            failure(format!(
                "--models-toml has no provider `{}`",
                rung.model.provider
            ))
        })?;
        // Built inside the runtime, as `serve` builds it, so the reader binds to it.
        let models = {
            let _entered = runtime.enter();
            ModelRuntime::build(Some(&config), HostingPrivacyPosture::default())
        };
        provider_ready(&models, &rung.model.provider)?;
        let big_section = big_rung::ready_section(&config, &models)?;
        let door = models.decision_read().ok_or_else(|| {
            failure(
                "the models runtime bound no decision read: its local_reasoner rung keeps work on the device and is third-party, or the read could not bind"
                    .to_owned(),
            )
        })?;
        if !door.permitted() {
            return Err(failure(
                "the decision read is not permitted on its local_reasoner rung".to_owned(),
            ));
        }
        let probe = door.probe().ok_or_else(|| {
            failure(
                "the decision read's recipe names no [probe] paired question; without it the escalation rung stays empty"
                    .to_owned(),
            )
        })?;
        let paired = THINK_MORE.question(&[], probe.paired.clone(), AnswerContract::Noul)?;
        let think_threshold = door.think_threshold();
        let mut bands = DecisionBandPolicy::default();
        if let Some(threshold) = think_threshold {
            bands.set_think_threshold(threshold, THINK_THRESHOLD_VERSION)?;
        }
        let reader = door.reader();
        let pins = ModelPins {
            models_toml: path.display().to_string(),
            models_toml_blake3: blake3::hash(&bytes).to_hex().to_string(),
            local_reasoner: rung.model.to_string(),
            provider_revision: provider.revision.clone(),
            recipe_fingerprint: settings.recipe.fingerprint().to_owned(),
            escalation: ProviderPin {
                rung: DecisionRung::Escalation,
                model: reader.model().to_owned(),
                version: reader.revision().to_owned(),
            },
            paired_question: paired.id.to_hex(),
            think_threshold,
            think_threshold_version: think_threshold.map(|_| THINK_THRESHOLD_VERSION),
            person_threshold: door.person_threshold(),
            big: None,
        };
        let meter = BudgetGuard::new(
            READ_METER_ATTEMPT,
            READ_METER_UNITS,
            BudgetExhaustionPolicy::Suspend,
        );
        Ok(Self {
            pins,
            reader,
            meter,
            paired,
            bands,
            models: Arc::new(models),
            big_section,
            big: None,
        })
    }

    pub(super) fn pins(&self) -> &ModelPins {
        &self.pins
    }

    /// One typed decision of `question` for `principal` over `state`, on a
    /// ladder whose escalation rung is this read and whose Big rung is the
    /// bound one, inside `dial`, on a hard clock of `budget`. A read blocks
    /// on the models runtime, so this runs on a thread outside it.
    pub(super) fn decide(
        &self,
        question: &DecisionQuestion,
        principal: EntityId,
        evidence: &[EntityId],
        state: &serde_json::Value,
        dial: DecisionDial,
        budget: Duration,
    ) -> oneiron::Result<TypedDecision> {
        let provider = DecisionReadProvider::new(
            self.pins.escalation.clone(),
            self.reader.as_ref(),
            &self.meter,
            &self.paired,
            None,
        )?;
        let held = HeldLadder::unstaffed();
        let mut ladder = held.ladder();
        ladder.escalation = Some(&provider as &dyn DecisionProvider);
        ladder.big = self.big.as_ref().map(BigRung::provider);
        ladder.paired = Some(&self.paired);
        let deadline = RetrievalDeadline::hard(Instant::now(), budget);
        ladder.run(
            question,
            principal,
            evidence,
            state,
            dial,
            &self.bands,
            Reversibility::ReversibleRead,
            &deadline,
        )
    }
}

/// Refuses a models runtime whose `provider` did not come up, as the
/// inference bench does before its first call.
fn provider_ready(models: &ModelRuntime, provider: &str) -> EvalResult<()> {
    let status = models
        .status()
        .providers
        .iter()
        .find(|status| status.name == provider)
        .ok_or_else(|| failure(format!("the models config built no provider `{provider}`")))?;
    if status.state != "ready" {
        return Err(failure(format!(
            "provider `{provider}` is {}: {}",
            status.state,
            status.reason.as_deref().unwrap_or("no reason given")
        )));
    }
    Ok(())
}
