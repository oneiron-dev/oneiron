use super::{
    AiOperation, BTreeMap, BTreeSet, CallClass, CallEnvelope, CallPurpose, EgressPredicate,
    EmbedderLocality, EmbeddingSpace, InputKind, MediaEgress, MediaEmbedRefusal, MediaEmbedReport,
    MediaPart, MediaRequest, Modality, ModelId, ModelLocality, ModelTierRef, ResponseFormat,
    SyncServer, TierPrecedence, media_part,
};
use crate::models::MediaRow;
use oneiron::embed::{KindSlotBindings, PendingEmbedderBinding};
use oneiron::machine_destination::PeerMachine;
use oneiron::settings::ReadDestination;

fn request(model: &ModelId, locality: ModelLocality, parts: Vec<MediaPart>) -> MediaRequest {
    let purpose = CallPurpose::Other {
        name: format!("ai.{}", AiOperation::Embed.as_str()),
    };
    MediaRequest {
        model: model.clone(),
        envelope: CallEnvelope {
            scope: Default::default(),
            tier: TierPrecedence::for_purpose(
                &purpose,
                ModelTierRef(format!("media-{}", AiOperation::Embed.as_str())),
            ),
            purpose,
            class: CallClass::BestEffort,
            response_format: ResponseFormat::Text,
            locality,
            host_keyless: false,
            host_paid: false,
            seat_effort: None,
        },
        operation: AiOperation::Embed,
        parts,
        references: Vec::new(),
        // The first real answer supplies the native width; none is guessed or requested.
        params: BTreeMap::new(),
        voice: None,
    }
}

fn modality(kind: InputKind) -> Modality {
    match kind {
        InputKind::Text => Modality::Text,
        InputKind::Image => Modality::Image,
        InputKind::Audio => Modality::Audio,
    }
}

impl SyncServer {
    pub(super) fn declare_waiting_stock_spaces(
        &self,
        runtime: &tokio::runtime::Handle,
    ) -> Vec<(String, Result<MediaEmbedReport, MediaEmbedRefusal>)> {
        let media = self.ai.model_runtime().media();
        if media.seat(AiOperation::Embed).is_none() {
            return Vec::new();
        }
        let pending = match self.vault.embedder_binding_moves() {
            Ok(pending) => pending,
            Err(error) => return vec![(String::new(), Err(error.into()))],
        };
        let rows = media.options(Some(AiOperation::Embed), &BTreeSet::new());
        let mut failures = Vec::new();
        for pending in pending {
            let model = pending.binding.model.as_str();
            let (bindings, kinds) = match self.vault.stock_embedder_binding_inputs(&pending) {
                Ok(Some(inputs)) => inputs,
                Ok(None) => continue,
                Err(error) => {
                    failures.push((model.to_owned(), Err(error.into())));
                    continue;
                }
            };
            let Some(row) = rows.iter().find(|row| row.model == model) else {
                failures.push((
                    model.to_owned(),
                    Err(MediaEmbedRefusal::Unmapped(model.into())),
                ));
                continue;
            };
            let candidate = format!("{model}@{}", row.provider);
            if let Some(missing) = kinds
                .iter()
                .copied()
                .map(modality)
                .find(|kind| !row.inputs.contains(kind))
            {
                failures.push((
                    candidate,
                    Err(MediaEmbedRefusal::NoInput {
                        model: pending.binding.model.clone(),
                        modality: missing,
                    }),
                ));
                continue;
            }
            match self.declare_stock_space(&pending, &bindings, &kinds, row, runtime) {
                Ok(true) => {
                    tracing::info!(%candidate, "embedding space declared for a staged stock binding")
                }
                Ok(false) => {}
                Err(error) => failures.push((candidate, Err(error))),
            }
        }
        failures
    }

    fn declare_stock_space(
        &self,
        pending: &PendingEmbedderBinding,
        bindings: &KindSlotBindings,
        kinds: &BTreeSet<InputKind>,
        row: &MediaRow,
        runtime: &tokio::runtime::Handle,
    ) -> Result<bool, MediaEmbedRefusal> {
        let model = &pending.binding.model;
        // As with declared spaces, @where chooses the offer and admission locality.
        // The existing media wire route is model-scoped, not physical-provider proof.
        let locality = match row.locality {
            ModelLocality::OnDevice => EmbedderLocality::OnDevice,
            ModelLocality::OwnServer => EmbedderLocality::OwnerServer,
            ModelLocality::ThirdParty => EmbedderLocality::ThirdParty,
        };
        let destination = if locality == EmbedderLocality::OnDevice {
            ReadDestination::on_device()
        } else {
            ReadDestination::toward(PeerMachine::Unknown)
        };
        let gate_request = request(model, row.locality, Vec::new()).admission_request();
        let gate = self
            .extraction_egress
            .as_deref()
            .is_some_and(|egress| egress.permits(&gate_request))
            .then_some(MediaEgress);
        let egress = gate.as_ref().map(|gate| gate as &dyn EgressPredicate);
        let Some(sample) =
            self.vault
                .first_unbound_media_input(kinds, locality, egress, &destination)?
        else {
            return Ok(false);
        };
        let input = sample.input();
        let release = || -> oneiron::Result<()> {
            if self
                .vault
                .unbound_media_may_leave(locality, egress, &destination, &input)?
            {
                Ok(())
            } else {
                Err(oneiron::Error::UpstreamToolFailure {
                    tool: "media-embedder-remote",
                    code: "media_egress".to_owned(),
                })
            }
        };
        release()?;
        let part = media_part(input.kind, input.media_type, input.bytes.to_vec())?;
        let admitted = super::super::media_door::admit_media_at(
            &self.vault,
            row.locality,
            self.extraction_egress.as_deref(),
            request(model, row.locality, vec![part]),
        )
        .map_err(|refused| match refused {
            super::super::MediaRefusal::Denied(error) => MediaEmbedRefusal::Denied(error),
            super::super::MediaRefusal::UnknownModel
            | super::super::MediaRefusal::SelectorOverride(_) => {
                MediaEmbedRefusal::Call(oneiron::FatalLlmError::InvalidRequest.into())
            }
        })?;
        let dispatch_release = || -> oneiron::LlmResult<()> {
            release().map_err(|error| {
                oneiron::RetryableLlmError::not_sent("media_release", error.to_string()).into()
            })
        };
        let response = runtime
            .block_on(self.ai.model_runtime().media().run_released(
                admitted,
                None,
                input.source_rows.map(<[oneiron::EntityId]>::to_vec),
                Some(&dispatch_release),
            ))
            .map_err(MediaEmbedRefusal::Call)?;
        let mut vectors = response.parts.into_iter().filter_map(|part| match part {
            MediaPart::Embedding { vector } => Some(vector),
            _ => None,
        });
        let (Some(vector), None) = (vectors.next(), vectors.next()) else {
            return Err(MediaEmbedRefusal::Malformed);
        };
        if vector.iter().any(|value| !value.is_finite()) {
            return Err(MediaEmbedRefusal::Malformed);
        }
        let space = EmbeddingSpace {
            id: format!("{}@{}", model.as_str(), row.provider),
            dimensions: vector.len(),
            accepts: kinds.clone(),
            query_towers: kinds.clone(),
            evidence: None,
        };
        Ok(self
            .vault
            .declare_staged_stock_embedder_space(pending, bindings, &space)?)
    }
}
