//! `ai.options` (OF-131, OF-140; FIX 2942): the model rows a caller could
//! call now. Every door that lists them (`GET /v1/ai/options`, the facade's
//! and MCP's `ai.options`, a pumped run's host row) lists through here, so
//! each lists only what its caller's own call doors would admit: no row for
//! a caller those doors refuse, only rows the vault's inference policy
//! admits, and only rungs live now. Each row carries its price as the
//! vault's model registry holds it, beside the quote of the backend that
//! serves it when the registry holds one (FIX 3206), and what the meter its
//! call spends has left. Listing reserves nothing, and a call is judged again
//! at its door.
use std::collections::{BTreeMap, BTreeSet};

use oneiron::llm::media::{AiOperation, MediaRequest, Modality};
use oneiron::llm::registry::{ModelRegistryRow, PricedModelBackend};
use oneiron::llm::{HostInferenceBinding, HostInferenceContext, LlmCatalogCost};
use oneiron::{
    CallClass, CallEnvelope, CallPurpose, ModelId, ModelTierRef, ResponseFormat, TierPrecedence,
};
use serde::Serialize;

use crate::models::MediaRow;
use crate::server::{SyncServer, admit_media};

/// One row a caller could call now: the model row, its price per million
/// tokens as the vault's model registry holds it (`None` when no
/// registered row prices it), the serving backend's own quote (`None` when
/// the registry holds none for the backend the row is served by), and what
/// the meter a call of it spends has left, in token units (`None` when that
/// meter is not built).
#[derive(Debug, Serialize)]
pub(crate) struct OptionRow {
    #[serde(flatten)]
    row: MediaRow,
    cost: Option<LlmCatalogCost>,
    backend_quote: Option<PricedModelBackend>,
    units_left: Option<u64>,
}

impl OptionRow {
    /// `row` with its registered price and its serving backend's quote, and
    /// `units_left` on its meter.
    fn priced(server: &SyncServer, row: MediaRow, units_left: Option<u64>) -> Self {
        let registered = registered_row(server, &row);
        let backend_quote = registered
            .as_ref()
            .and_then(|registered| backend_quote(registered, &row));
        Self {
            cost: registered.and_then(|registered| registered.catalog.cost),
            backend_quote,
            row,
            units_left,
        }
    }
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
    // A text row is called through the raw routes, on their meter; an
    // uncapped meter reports none (FIX 10593).
    let raw_left = server
        .llm
        .as_ref()
        .and_then(|raw| raw.meter().read().capped_remaining_units());
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
            OptionRow::priced(server, row, units_left)
        })
        .collect();
    CallerOptions {
        options,
        media_units_left: media_left,
    }
}

/// The rows a pumped agent run could call now (FIX 3194): its `ai.speech`
/// door alone admits it, on the run's own line, so it lists each live
/// speech row over `inputs` the vault's inference policy admits, with what
/// that line has left (`run_left`). Any other operation lists none.
pub(crate) fn run_options(
    server: &SyncServer,
    run_left: Option<u64>,
    operation: Option<AiOperation>,
    inputs: &BTreeSet<Modality>,
) -> CallerOptions {
    if operation.is_some_and(|wanted| wanted != AiOperation::Speech) {
        return CallerOptions {
            options: Vec::new(),
            media_units_left: None,
        };
    }
    let options = server
        .ai
        .model_runtime()
        .ai_options(Some(AiOperation::Speech), inputs)
        .into_iter()
        .filter(|row| policy_admits(server, row))
        .map(|row| OptionRow::priced(server, row, run_left))
        .collect();
    CallerOptions {
        options,
        media_units_left: run_left,
    }
}

/// The rows a program's run could call now on its own line (FIX 780, FIX
/// 6083): each live row over `inputs` of an operation its doors call
/// (`callable`) that the vault's inference policy admits. A media row
/// carries what the line its call spends on has left (`run_left`); a text
/// row, for a caller whose credential reaches the raw routes, what their
/// meter has left, as [`caller_options`] lists it.
pub(crate) fn line_options(
    server: &SyncServer,
    run_left: Option<u64>,
    operation: Option<AiOperation>,
    inputs: &BTreeSet<Modality>,
    callable: impl Fn(AiOperation) -> bool,
) -> CallerOptions {
    // An uncapped raw meter reports none (FIX 10593).
    let raw_left = server
        .llm
        .as_ref()
        .and_then(|raw| raw.meter().read().capped_remaining_units());
    let options = server
        .ai
        .model_runtime()
        .ai_options(operation, inputs)
        .into_iter()
        .filter(|row| callable(row.operation))
        .filter(|row| policy_admits(server, row))
        .map(|row| {
            let units_left = if row.operation == AiOperation::Text {
                raw_left
            } else {
                run_left
            };
            OptionRow::priced(server, row, units_left)
        })
        .collect();
    CallerOptions {
        options,
        media_units_left: run_left,
    }
}

/// `row`'s model as the vault's model registry holds it.
fn registered_row(server: &SyncServer, row: &MediaRow) -> Option<ModelRegistryRow> {
    ModelId::new(row.model.clone())
        .ok()
        .and_then(|model| server.vault.model_registry_row(&model).ok().flatten())
}

/// The quote `registered` holds for the backend `row` is served by: the
/// backend row its configured provider names. A registry whose backends do
/// not read gives none, never another backend's price.
fn backend_quote(registered: &ModelRegistryRow, row: &MediaRow) -> Option<PricedModelBackend> {
    registered
        .backends()
        .ok()?
        .into_iter()
        .find(|backend| backend.pin.backend == row.provider)
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
