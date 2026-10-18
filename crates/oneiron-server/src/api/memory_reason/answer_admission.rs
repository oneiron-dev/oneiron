//! The reasoning read's answer boundary (OF-063, Engine ruling 1231): a deep
//! composition crosses the engine's one boundary, the one `memory.chat`
//! crosses ([`oneiron::memory::Memory::admit_answer`]), over the evidence this
//! read already collected. No second recall runs, and nothing here touches
//! depth, backend or lease accounting.

use oneiron::EdgeActorClass;
use oneiron::memory::AnswerAdmission;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::{MemoryReasonComposition, MemoryReasonEvidence};
use crate::auth::CoreAuth;
use crate::error::ApiError;

/// The row this read's boundary receipts name: the route has no verb-table
/// row, so its receipts name its own door, as `memory.chat`'s name chat's.
const REASON_ANSWER_ROW: &str = "memory.reason";

/// The answer boundary's refusal of a deep composition that cited a source
/// its evidence does not carry: the composition's text never escapes, and
/// the read answers from the evidence itself beside this.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MemoryReasonCompositionRefusal {
    /// The typed refusal, the shape a refused claim write and a refused
    /// `memory.chat` answer carry.
    #[schema(value_type = RecordRefusalSchema)]
    pub(crate) refusal: oneiron::memory::RecordRefusal,
    /// That refusal's own receipt. Absent when no record was kept, as in an
    /// anonymous off-record session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "reference_refusal:0123456789abcdef0123456789abcdef")]
    pub(crate) receipt_ref: Option<String>,
}

/// OpenAPI shape of the engine's typed refusal.
#[derive(ToSchema)]
#[expect(
    dead_code,
    reason = "OpenAPI schema mirror; response serializes the engine type"
)]
pub(crate) struct RecordRefusalSchema {
    /// Why it was refused: `INVENTED_REFERENCE` for a citation the evidence
    /// does not carry.
    #[schema(example = "INVENTED_REFERENCE")]
    reason: String,
    /// The facade error code it was refused with.
    #[schema(example = "INVENTED_REFERENCE")]
    code: String,
    /// What was refused, in words.
    message: String,
    /// Remediation hints.
    suggestions: Vec<String>,
    /// The JSON pointer of the refused citation, never the cited ref.
    #[schema(example = "/source_short_ids/0")]
    field: String,
}

/// One usable composition across the answer boundary, on the caller's own
/// surface: its sources when every citation is one the evidence carries
/// (its prose links read once, receipt-only), else the refusal of its
/// citations.
pub(super) fn admit_composition(
    vault: &oneiron::Vault,
    auth: &CoreAuth,
    composed: &MemoryReasonComposition,
    evidence: &[MemoryReasonEvidence],
) -> Result<AnswerAdmission, ApiError> {
    let memory = answer_memory(vault, auth)?;
    Ok(memory.admit_answer(
        REASON_ANSWER_ROW,
        &composed.source_short_ids,
        Some(composed.answer.as_str()),
        |cited| {
            let cited = cited.trim();
            evidence
                .iter()
                .find(|row| row.short_id == cited)
                .map(|row| row.short_id.clone())
        },
    ))
}

/// The caller's own surface the boundary receipts on and reads prose links
/// under: its credential's principal and class, read proof and locality,
/// inside the off-record session its request names (`credential_memory`).
/// A credential that names no principal acts as the host's owner actor, as
/// a facade door's hooks do, and binds no session (Engine ruling 2137/2271).
fn answer_memory<'a>(
    vault: &'a oneiron::Vault,
    auth: &CoreAuth,
) -> Result<oneiron::Memory<'a>, ApiError> {
    let actor = match crate::api::call_receipt::request_principal(auth) {
        Some(principal) => principal,
        None => oneiron::task_verb::verb_hook_boundary::host_actor().map_err(|error| {
            crate::api::core_engine_error("memory reason answer actor failed", error)
        })?,
    };
    let class = match auth.actor_class() {
        Some("agent") => EdgeActorClass::Agent,
        Some("system") => EdgeActorClass::System,
        Some(_) => EdgeActorClass::Human,
        None if auth.principal_ref().is_some() || auth.is_owner_grade() => EdgeActorClass::Human,
        None => EdgeActorClass::System,
    };
    Ok(crate::api::credential_memory(vault, Some(auth), actor, class).at(auth.locality()))
}
