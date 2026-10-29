//! The after-bind calibration of a slot's Candle baseline (FIX 7108): the
//! survey a first start used to run before the listener bound, run instead
//! on a thread of its own that the serving build starts.
//!
//! The slot serves on the built-in engine meanwhile ([`Pick::Calibrating`]),
//! as a slot whose bundle ships no reference serves. The survey measures
//! each engine with no row here, every reference case after
//! [`CALIBRATION_IDLE`](super::calibration::CALIBRATION_IDLE), and keeps its
//! rows; an engine with a row is read, never measured again. When it lands:
//!
//! - the preferred clearing engine serves at rank 0. When that is not the
//!   built-in engine, its worker is added and the built-in one is retired,
//!   so no second model stays loaded beside it;
//! - when no engine clears, the built-in worker is retired as
//!   `parity_failed`: `auto` serves no answer the reference disowns, as a
//!   start that measured none clearing refuses;
//! - the slot's platform admission ([`super::Admission`]) starts against the
//!   measured baseline, as it starts at once on a start whose rows were all
//!   kept.
//!
//! A survey that fails leaves the built-in engine serving, and the next start
//! measures again.

use std::path::{Path, PathBuf};

use super::super::dispatcher::{DispatcherHandle, WorkerId, WorkerSpec};
use super::super::endpoint::ModelCard;
use super::super::local::LocalTagger;
use super::admission::PARITY_FAILED;
use super::{Admission, Pick, Serving, survey};
use crate::config::OneironerConfig;

/// The down reason of the built-in worker once a preferred engine replaced
/// it.
const REPLACED_BY_MEASURED: &str = "replaced_by_measured";

/// A slot's baseline calibration, prepared as the slot is built and started
/// once by the serving build.
pub(crate) struct BaselineCalibration {
    config: OneironerConfig,
    rows_location: Option<PathBuf>,
    dispatcher: DispatcherHandle,
    /// The built-in engine serving until the calibration lands, and its
    /// worker.
    provisional: Serving,
    provisional_worker: WorkerId,
    /// The slot's card, which a platform worker must answer as.
    card: ModelCard,
}

impl BaselineCalibration {
    /// The calibration of a slot whose engine was picked
    /// [`Pick::Calibrating`]; `None` for any other pick, which has nothing
    /// left to measure.
    pub(crate) fn new(
        config: &OneironerConfig,
        rows_location: Option<&Path>,
        dispatcher: DispatcherHandle,
        provisional: Serving,
        provisional_worker: WorkerId,
        card: ModelCard,
    ) -> Option<Self> {
        (provisional.pick == Pick::Calibrating).then(|| Self {
            config: config.clone(),
            rows_location: rows_location.map(Path::to_path_buf),
            dispatcher,
            provisional,
            provisional_worker,
            card,
        })
    }

    /// Starts it on its own thread, which ends once the measured baseline
    /// serves and its platform admission has started.
    pub(crate) fn start(self) {
        let spawned = std::thread::Builder::new()
            .name("oneironer calibration".to_owned())
            .spawn(move || self.run());
        if let Err(error) = spawned {
            tracing::warn!(
                %error,
                "oneironer calibration did not start; the built-in engine serves"
            );
        }
    }

    fn run(self) {
        let survey = match survey(&self.config, self.rows_location.as_deref()) {
            Ok(survey) => survey,
            Err(error) => {
                tracing::warn!(%error, "oneironer calibration failed; the built-in engine serves");
                return;
            }
        };
        let Some(engine) = survey.default else {
            tracing::warn!(
                "no oneironer engine on this machine clears the bundle's parity bar; name one with oneironer.device"
            );
            self.dispatcher.retire(self.provisional_worker, PARITY_FAILED);
            return;
        };
        let worker = if engine == self.provisional.engine {
            self.provisional_worker
        } else {
            let loaded = match survey.loaded {
                Some(tagger) => Ok(tagger),
                None => LocalTagger::load(&engine.configured(&self.config)),
            };
            let added =
                loaded.and_then(|tagger| self.dispatcher.add(WorkerSpec::local(engine, tagger)));
            match added {
                Ok(worker) => {
                    self.dispatcher.publish_rank(worker, 0);
                    self.dispatcher
                        .retire(self.provisional_worker, REPLACED_BY_MEASURED);
                    worker
                }
                Err(error) => {
                    tracing::warn!(
                        engine = %engine.id(),
                        %error,
                        "the calibrated oneironer engine did not start; the built-in engine serves"
                    );
                    return;
                }
            }
        };
        tracing::info!(
            engine = %engine.id(),
            pick = Pick::Measured.as_str(),
            "oneironer engine serving"
        );
        let baseline = Serving {
            engine,
            pick: Pick::Measured,
        };
        if let Some(admission) = Admission::new(
            &self.config,
            self.rows_location.as_deref(),
            self.dispatcher,
            baseline,
            worker,
            self.card,
        ) {
            admission.start();
        }
    }
}
