//! The Big rung on the bench's ladder (FIX 22229 run 2), bound from the
//! `--models-toml` file's `[models.decisions.big]` through the served host's
//! own binding ([`BigRung::bind`]): the same seat, wording, reply and meter,
//! reading the house read's paired question jointly where its route reports
//! token scores, as the host's Big rung reads the ladder's. Each of its
//! calls is routed and admitted against the run's vault. Without the section
//! the ladder has no Big rung, and the run is the house read's alone.

use std::sync::Arc;

use oneiron::Vault;
use oneiron::llm::decision::ProviderPin;
use oneiron::llm::manifest::ModelRole;
use oneiron_server::config::ModelsConfig;
use oneiron_server::config::models::{BigReply, BigSettings};
use oneiron_server::decision_host::BigRung;
use oneiron_server::models::ModelRuntime;
use serde::Serialize;

use super::{HouseReadRung, failure, provider_ready};
use crate::eval::EvalResult;

/// What `[models.decisions.big]` pins, as the run header names it.
#[derive(Clone, Serialize)]
pub(in crate::eval::route_calibration) struct BigPins {
    /// The pin every Big answer carries; its version is the section's
    /// `version`.
    pin: ProviderPin,
    /// The seat whose model answers.
    role: ModelRole,
    /// BLAKE3 of the section's `wording`, every call's system message.
    wording_blake3: String,
    /// How the model is asked to reply: `json` or `lines`.
    reply: &'static str,
}

/// `[models.decisions.big]` as `config` binds it, with the raw routes' units
/// its meter falls back to, once the provider of its seat's first rung is
/// ready on `models`; none without the section.
pub(super) fn ready_section(
    config: &ModelsConfig,
    models: &ModelRuntime,
) -> EvalResult<Option<(BigSettings, u64)>> {
    let Some(settings) = config.decisions.big.as_ref() else {
        return Ok(None);
    };
    let rung = config
        .roles
        .get(&settings.role)
        .and_then(|ladder| ladder.first())
        .ok_or_else(|| {
            failure(format!(
                "[models.decisions.big] names the {:?} seat, and no [models.roles] rung fills it",
                settings.role
            ))
        })?;
    provider_ready(models, &rung.model.provider)?;
    Ok(Some((settings.clone(), config.raw_budget_units)))
}

impl HouseReadRung {
    /// Binds the Big rung the file's `[models.decisions.big]` names on the
    /// run's `vault`, its calls blocking on `runtime`, and names its pin in
    /// the run header. Without the section the ladder keeps no Big rung.
    /// Refused when the section's seat cannot fill the rung.
    pub(in crate::eval::route_calibration) fn bind_big(
        &mut self,
        vault: &Arc<Vault>,
        runtime: tokio::runtime::Handle,
    ) -> EvalResult<()> {
        let Some((settings, default_units)) = self.big_section.as_ref() else {
            return Ok(());
        };
        let rung = BigRung::bind(
            settings,
            &self.models,
            vault,
            *default_units,
            runtime,
            Some(self.paired.clone()),
        )
        .map_err(|error| {
            failure(format!(
                "[models.decisions.big] cannot fill the Big rung: {error:#}"
            ))
        })?;
        self.pins.big = Some(BigPins {
            pin: rung.pin(),
            role: settings.role,
            wording_blake3: blake3::hash(settings.wording.as_bytes())
                .to_hex()
                .to_string(),
            reply: match settings.reply {
                BigReply::Json => "json",
                BigReply::Lines => "lines",
            },
        });
        self.big = Some(rung);
        Ok(())
    }
}
