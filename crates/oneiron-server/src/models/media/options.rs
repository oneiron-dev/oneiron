//! Media seat queries and model option rows.
//! Entry: MediaRuntime::options.
//! Media types stay in the parent; ModelRuntime is owned by crate::models.

use super::{
    AiOperation, Arc, BTreeMap, BTreeSet, FallbackRung, MediaRow, MediaRuntime, Modality, ModelId,
    ModelLocality, OfferLadder, RungHealth, VoiceBackendBinding, text_caps,
};

impl MediaRuntime {
    /// Every row that serves `operation` (every operation when `None`)
    /// over `inputs`.
    #[must_use]
    pub fn options(
        &self,
        operation: Option<AiOperation>,
        inputs: &BTreeSet<Modality>,
    ) -> Vec<MediaRow> {
        self.seats
            .iter()
            .filter(|(op, _)| operation.is_none_or(|wanted| wanted == **op))
            .flat_map(|(_, seat)| &seat.rows)
            .filter(|row| inputs.is_subset(&row.inputs))
            .cloned()
            .collect()
    }

    /// Whether the rung `model` of `operation`'s seat can take a call now
    /// (FIX 2942): it was built, and its offer is live ([`RungHealth::live_now`]).
    pub(in crate::models) fn rung_live(&self, operation: AiOperation, model: &str) -> bool {
        let Some(seat) = self.seats.get(&operation) else {
            return false;
        };
        ModelId::new(model.to_owned())
            .ok()
            .and_then(|id| seat.rungs.get(&id))
            .is_some_and(|alone| alone.health().iter().all(|(_, health)| health.live_now()))
    }

    /// What the media meter has left to spend, in token units.
    #[must_use]
    pub fn units_left(&self) -> Option<u64> {
        self.meter
            .as_ref()
            .map(|meter| meter.read().remaining_units)
    }

    /// The seat id and widest locality that serve `operation`.
    #[must_use]
    pub fn seat(&self, operation: AiOperation) -> Option<(ModelId, ModelLocality)> {
        self.seats
            .get(&operation)
            .map(|seat| (seat.model.clone(), seat.locality))
    }

    /// One rung alone of each media seat, as a model that a parked offer's
    /// media calls may fall back to once the owner names it (OF-305).
    pub(in crate::models) fn fallback_rungs(&self) -> Vec<FallbackRung> {
        self.seats
            .values()
            .flat_map(|seat| seat.rungs.values())
            .filter_map(OfferLadder::fallback_rung)
            .collect()
    }

    /// The ladder of the media seat that the status route lists as `role`
    /// (`media.<operation>`).
    pub(in crate::models) fn seat_ladder(&self, role: &str) -> Option<&Arc<OfferLadder>> {
        let operation = role.strip_prefix("media.")?;
        self.seats
            .iter()
            .find(|(seat, _)| seat.as_str() == operation)
            .map(|(_, seat)| &seat.ladder)
    }

    /// Where `model` runs, when a media seat or one of its rungs has that
    /// id: the host's attestation for the vault's inference check.
    #[must_use]
    pub fn locality(&self, operation: AiOperation, model: &ModelId) -> Option<ModelLocality> {
        let seat = self.seats.get(&operation)?;
        if &seat.model == model {
            return Some(seat.locality);
        }
        seat.rows
            .iter()
            .find(|row| row.model == model.as_str())
            .map(|row| row.locality)
    }

    /// Each voice tier a rung of `operation`'s seat is bound to, as the
    /// vault's voice routing reads it: the rung's own id, its tier and
    /// where it runs.
    #[must_use]
    pub fn voice_backends(&self, operation: AiOperation) -> Vec<VoiceBackendBinding> {
        let Some(seat) = self.seats.get(&operation) else {
            return Vec::new();
        };
        seat.tiers
            .iter()
            .filter_map(|(tier, model)| {
                let row = seat.rows.iter().find(|row| row.model == model.as_str())?;
                Some(VoiceBackendBinding {
                    model: model.clone(),
                    tier: tier.clone(),
                    locality: row.locality,
                })
            })
            .collect()
    }

    /// The rungs a call naming `model` may reach, in ladder order: every
    /// rung for the seat's id, the one rung for a rung's. Each comes with
    /// its provider, the render target the voice bank keys its clones by,
    /// and where it runs.
    #[must_use]
    pub fn rung_targets(
        &self,
        operation: AiOperation,
        model: &ModelId,
    ) -> Vec<(ModelId, String, ModelLocality)> {
        let Some(seat) = self.seats.get(&operation) else {
            return Vec::new();
        };
        seat.rows
            .iter()
            .filter(|row| seat.model == *model || row.model == model.as_str())
            .filter_map(|row| {
                let id = ModelId::new(row.model.clone()).ok()?;
                Some((id, row.provider.clone(), row.locality))
            })
            .collect()
    }
}

impl crate::models::ModelRuntime {
    /// Every row of the `ai.*` family that serves `operation` (every one
    /// when `None`) over `inputs`: each available rung of each text seat,
    /// each model the mesh discovered, then each media row. Only a rung that
    /// can take a call now is listed (FIX 2942): one whose provider is down,
    /// whose one probation request is out, or that a limit holds is left out
    /// until it is back. A text row's inputs are what a call naming its own
    /// id reaches: that rung's route alone, else its seat's.
    #[must_use]
    pub fn ai_options(
        &self,
        operation: Option<AiOperation>,
        inputs: &BTreeSet<Modality>,
    ) -> Vec<MediaRow> {
        let mut rows = Vec::new();
        if operation.is_none_or(|wanted| wanted == AiOperation::Text) {
            for (role, seat) in &self.seats {
                if *role == oneiron::llm::manifest::ModelRole::Reranker {
                    continue;
                }
                let seat_caps = text_caps(&seat.ladder, &seat.model);
                let status = self
                    .status
                    .seats
                    .iter()
                    .find(|status| status.seat_model.as_deref() == Some(seat.model.as_str()));
                let health: BTreeMap<usize, RungHealth> =
                    seat.ladder.health().into_iter().collect();
                let rungs = status
                    .into_iter()
                    .flat_map(|status| status.rungs.iter().enumerate());
                for (position, rung) in rungs {
                    let live = health.get(&position).is_none_or(RungHealth::live_now);
                    let Some(model) = rung.engine_model.clone().filter(|_| rung.available && live)
                    else {
                        continue;
                    };
                    // A call naming the rung's id takes its own route.
                    let caps = ModelId::new(model.clone())
                        .ok()
                        .and_then(|id| {
                            let (_, ladder) = self.raw_router.served(&id)?;
                            Some(text_caps(&ladder, &id))
                        })
                        .unwrap_or_else(|| seat_caps.clone());
                    if !inputs.is_subset(&caps.inputs) {
                        continue;
                    }
                    rows.push(MediaRow {
                        operation: AiOperation::Text,
                        model,
                        seat_model: seat.model.to_string(),
                        provider: rung.provider.clone(),
                        wire_model: rung.model.clone(),
                        locality: rung.locality,
                        inputs: caps.inputs,
                        outputs: caps.outputs,
                        native_rates: Vec::new(),
                        max_references: 0,
                        peer: None,
                    });
                }
            }
            // Each model the mesh discovered that can take a call now, by
            // its own id on the raw routes (FIX 3229).
            for (model, peer, ladder) in self.raw_router.discovered_routes() {
                let caps = text_caps(&ladder, &model);
                let health = ladder.health();
                if !inputs.is_subset(&caps.inputs)
                    || health.is_empty()
                    || !health.iter().all(|(_, rung)| rung.live_now())
                {
                    continue;
                }
                rows.push(MediaRow {
                    operation: AiOperation::Text,
                    model: model.to_string(),
                    seat_model: model.to_string(),
                    provider: ladder.first_provider().unwrap_or_default().to_owned(),
                    wire_model: model.to_string(),
                    locality: ModelLocality::OwnServer,
                    inputs: caps.inputs,
                    outputs: caps.outputs,
                    native_rates: Vec::new(),
                    max_references: 0,
                    peer: Some(peer),
                });
            }
        }
        rows.extend(
            self.media
                .options(operation, inputs)
                .into_iter()
                .filter(|row| self.media.rung_live(row.operation, &row.model)),
        );
        rows
    }
}
