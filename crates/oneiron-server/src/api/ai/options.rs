//! `ai.options` (OF-131, OF-140; FIX 2942): the model rows a caller could
//! call now. Every door that lists them (`GET /v1/ai/options`, the facade's
//! and MCP's `ai.options`, a pumped run's host row) lists through here, so
//! each lists only what its caller's own call doors would admit: no row for
//! a caller those doors refuse, only rows the vault's inference policy
//! admits, and only rungs live now. Each row carries its price as the
//! vault's model registry holds it, and what the meter its call spends has
//! left. Listing reserves nothing, and a call is judged again at its door.
use std::collections::{BTreeMap, BTreeSet};

use oneiron::llm::media::{AiOperation, MediaRequest, Modality};
use oneiron::llm::{HostInferenceBinding, HostInferenceContext, LlmCatalogCost};
use oneiron::{
    CallClass, CallEnvelope, CallPurpose, ModelId, ModelTierRef, ResponseFormat, TierPrecedence,
};
use serde::Serialize;

use crate::models::MediaRow;
use crate::server::{SyncServer, admit_media};

/// One row a caller could call now: the model row, its price per million
/// tokens as the vault's model registry holds it (`None` when no
/// registered row prices it), and what the meter a call of it spends has
/// left, in token units (`None` when that meter is not built).
#[derive(Debug, Serialize)]
pub(crate) struct OptionRow {
    #[serde(flatten)]
    row: MediaRow,
    cost: Option<LlmCatalogCost>,
    units_left: Option<u64>,
}

/// The rows a caller could call now, and what the media meter has left for
/// it.
pub(crate) struct CallerOptions {
    pub(crate) options: Vec<OptionRow>,
    pub(crate) media_units_left: Option<u64>,
}

/// The rows that serve `operation` (every one when `None`) over `inputs`
/// that a caller could call now. Every `ai.*` call door is the owner's, so a
/// caller that is not `owner_grade` could call none and gets none, with no
/// meter. An owner-grade caller gets each live row the vault's inference
/// policy admits, judged as its door judges a plain call of its operation.
pub(crate) fn caller_options(
    server: &SyncServer,
    owner_grade: bool,
    operation: Option<AiOperation>,
    inputs: &BTreeSet<Modality>,
) -> CallerOptions {
    if !owner_grade {
        return CallerOptions {
            options: Vec::new(),
            media_units_left: None,
        };
    }
    let runtime = server.ai.model_runtime();
    let media_left = runtime.media().units_left();
    // A text row is called through the raw routes, on their meter.
    let raw_left = server
        .llm
        .as_ref()
        .map(|raw| raw.meter().read().remaining_units);
    let options = runtime
        .ai_options(operation, inputs)
        .into_iter()
        .filter(|row| policy_admits(server, row))
        .map(|row| {
            let units_left = if row.operation == AiOperation::Text {
                raw_left
            } else {
                media_left
            };
            let cost = ModelId::new(row.model.clone())
                .ok()
                .and_then(|model| server.vault.model_registry_row(&model).ok().flatten())
                .and_then(|registered| registered.catalog.cost);
            OptionRow {
                row,
                cost,
                units_left,
            }
        })
        .collect();
    CallerOptions {
        options,
        media_units_left: media_left,
    }
}

/// Whether the vault's inference policy admits a plain call of `row`'s
/// operation on its model, as the row's door builds and judges one: a media
/// row through the media door's admission, a text row through the raw
/// routes' (`api/llm.rs`).
fn policy_admits(server: &SyncServer, row: &MediaRow) -> bool {
    let Ok(model) = ModelId::new(row.model.clone()) else {
        return false;
    };
    let purpose = CallPurpose::Other {
        name: format!("ai.{}", row.operation.as_str()),
    };
    let request = MediaRequest {
        model: model.clone(),
        envelope: CallEnvelope {
            scope: Default::default(),
            tier: TierPrecedence::for_purpose(
                &purpose,
                ModelTierRef(format!("media-{}", row.operation.as_str())),
            ),
            purpose,
            class: CallClass::BestEffort,
            response_format: ResponseFormat::Text,
            locality: row.locality,
            seat_effort: None,
        },
        operation: row.operation,
        parts: Vec::new(),
        references: Vec::new(),
        params: BTreeMap::new(),
        voice: None,
    };
    if row.operation != AiOperation::Text {
        return admit_media(
            &server.vault,
            server.ai.model_runtime().media(),
            server.extraction_egress.as_deref(),
            request,
        )
        .is_ok();
    }
    let binding = match server.ai.model_locality(&model) {
        Some(locality) => HostInferenceBinding::Advertised { model, locality },
        None => HostInferenceBinding::Registered,
    };
    let context = HostInferenceContext {
        binding,
        extraction_egress: server.extraction_egress.as_deref(),
    };
    server
        .vault
        .authorize_raw_inference(request.admission_request(), &context)
        .is_ok()
}
