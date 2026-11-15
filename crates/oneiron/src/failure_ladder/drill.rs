//! Owner-only vault-local drill-in to a custom-agent failure's tier-0 attempt
//! trace and terminal pack receipt, and an agent's drill beside it when the
//! owner turns `FAILURE_DRILL_DELEGATE` on for that agent (restriction
//! census C53). Classification and membership are never accepted from a
//! caller-held group snapshot.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptRecord, AttemptState};
use crate::claim::ClaimReadStatus;
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::receipt::{ReceiptKind, attempt_pack_receipt, attempt_pack_receipt_id};
use crate::self_heal::audit::doors::reference_row;
use crate::setting::SettingScope;

use super::custom_review::{FailureSignalClass, member_in_txn};
use super::setting_keys::FAILURE_DRILL_DELEGATE;

/// `vault.healer.failure_drill_as`, the name a Grant lists to name the
/// agent's drill.
const FAILURE_DRILL_AS_VERB: &str = "vault.healer.failure_drill_as";

/// The stored attempt is the tier-0 execution trace (including its events,
/// run id and result artifact reference). A terminal receipt is named only
/// when the vault still holds the actual receipt under that id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomFailureDrill {
    pub trace: AttemptRecord,
    pub receipt_refs: Vec<String>,
}

impl Vault {
    /// Reads one member of a vault-local failure group for its authenticated
    /// owner. No consent prompt or grant is minted: this is a read of the
    /// owner's own vault, not a disclosure to another audience.
    ///
    /// The class and attempt id are untrusted selectors, even when obtained
    /// from a prior `custom_agent_failure_groups` result. Membership, live
    /// custom-agent target and owner proof are checked on the same snapshot.
    /// No other actor can use this door; a host must use its separate scoped
    /// disclosure lane (and consent rules) for non-owner requests.
    pub fn drill_custom_agent_failure(
        &self,
        owner: &AuthenticatedOwner,
        class: FailureSignalClass,
        attempt_id: AttemptId,
    ) -> Result<CustomFailureDrill> {
        let trace = {
            let txn = self.store.env.read_txn()?;
            let actor = owner.revalidate_in_txn(self, &txn)?;
            if actor != crate::vault::embedded_owner_actor_id()? {
                // An unrooted vault has no authority-bound non-bootstrap owner.
                // Store-truth PERSON status alone is not a tier-0 read grant.
                let denied = || {
                    Error::Gate(crate::error::GateError::ConsentOwnerNotAuthenticated(
                        "failure drill requires a live owner binding",
                    ))
                };
                let fold = self
                    .authority_fold_readonly_in_txn(&txn)
                    .map_err(|_| denied())?;
                if fold.vault_id.is_none() || fold.vault_root_is_conflicted() {
                    return Err(denied());
                }
                crate::memory::verify_owner_actor_binding_in_txn(self, &txn, actor)
                    .map_err(|_| denied())?;
            }
            member_in_txn(self, &txn, attempt_id, class)?
        };
        let receipt_refs = terminal_receipt_refs(self, &trace)?;
        Ok(CustomFailureDrill {
            trace,
            receipt_refs,
        })
    }
}

/// The terminal pack receipt `trace` left, by id, when the vault still holds
/// the actual receipt under that id.
fn terminal_receipt_refs(vault: &Vault, trace: &AttemptRecord) -> Result<Vec<String>> {
    let id = attempt_pack_receipt_id(&trace.id);
    let mut receipt_refs = Vec::new();
    if let Some(receipt) = attempt_pack_receipt(vault, &id)? {
        if receipt.receipt_id != id
            || receipt.receipt_kind != ReceiptKind::Outbound
            || receipt.outcome != trace.state.as_str()
        {
            return Err(Error::CorruptedIndex(
                "custom-agent failure receipt mismatch",
            ));
        }
        receipt_refs.push(id);
    } else if !trace.manifest().is_empty()
        || crate::skill::resident::receipt_resident(vault, &id)?.is_some()
    {
        // Every terminal door stamps a pack/resident receipt in the same
        // transaction as the attempt; absence here is lost evidence.
        return Err(Error::CorruptedIndex(
            "custom-agent failure receipt missing",
        ));
    }
    Ok(receipt_refs)
}

/// `vault.healer.failure_drill_as`'s request: one member of a failure group,
/// named by the class it was listed under, and its attempt id in lowercase
/// hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FailureDrillRequest {
    pub class: FailureSignalClass,
    pub attempt: String,
}

/// One intervention on a drilled attempt, in order: its time, actor, kind
/// (`interrupt`, `pause`, `resume`, `cancel` or `redirect`) and note.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FailureDrillEvent {
    pub sequence: u64,
    pub at: u64,
    pub actor: String,
    pub kind: String,
    pub note: Option<String>,
}

/// A drilled custom-agent failure as an agent reads it: the fields the
/// owner's drill route serves (the ended attempt, its tries, error, refs and
/// interventions) and the terminal receipt ids its run left.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FailureDrillView {
    pub attempt: String,
    pub kind: String,
    pub state: AttemptState,
    pub tries: u32,
    pub last_error: Option<String>,
    pub task_ref: Option<String>,
    pub run_id: Option<String>,
    pub retry_of: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
    /// The artifact version the try's durable output lives in, if it left one.
    pub result_ref: Option<String>,
    pub events: Vec<FailureDrillEvent>,
    pub receipt_refs: Vec<String>,
}

impl FailureDrillView {
    fn of(trace: AttemptRecord, receipt_refs: Vec<String>) -> Self {
        let hex = |id: &AttemptId| bytes_to_hex_lower(id.as_bytes());
        Self {
            attempt: hex(&trace.id),
            kind: trace.kind,
            state: trace.state,
            tries: trace.attempt_count,
            last_error: trace.last_error,
            task_ref: trace.task_ref,
            run_id: trace.run_id,
            retry_of: trace.retry_of.as_ref().map(hex),
            created_at: trace.created_at,
            updated_at: trace.updated_at,
            result_ref: trace
                .result_ref
                .as_ref()
                .map(|result| result.as_str().to_owned()),
            events: trace
                .events
                .into_iter()
                .map(|event| FailureDrillEvent {
                    sequence: event.sequence,
                    at: event.at,
                    actor: event.actor,
                    kind: event.kind.as_str().to_owned(),
                    note: event.note,
                })
                .collect(),
            receipt_refs,
        }
    }
}

/// The rows an agent must read to read `trace`: its attempt's complete
/// recorded read set (FIX 7073), its TASK, the row its durable result names,
/// the failed custom agent's definition (the failure's subject) and the
/// project its dispatch ran in, as a seal's rows are (`seal_source_rows`,
/// `attempt_project`). `None` when its producers recorded no complete set,
/// or its dispatch does not decode: such a trace stays the owner's, as a
/// heal context's trace part does (FIX 10093).
fn agent_trace_rows(trace: &AttemptRecord) -> Option<Vec<EntityId>> {
    let mut rows = trace.source_rows()?.to_vec();
    rows.extend(trace.task_ref.as_deref().and_then(reference_row));
    rows.extend(
        trace
            .result_ref
            .as_ref()
            .and_then(|result| reference_row(result.as_str())),
    );
    let dispatch = crate::agent_dispatch::record_dispatch_input(trace)?;
    rows.push(dispatch.target.agent_definition_ref().ok()?);
    rows.extend(dispatch.project_ref);
    rows.sort_unstable();
    rows.dedup();
    Some(rows)
}

/// `vault.healer.failure_drill_as`: [`Vault::drill_custom_agent_failure`]
/// for the handle's own agent, under its live Grant listing the verb and the
/// owner's `FAILURE_DRILL_DELEGATE` row for it, judged with the membership
/// in one snapshot of the agent's read lane. A member whose trace the lane
/// may not read whole (`agent_trace_rows`) answers not found, as a
/// non-member does.
///
/// # Errors
/// `FORBIDDEN` for a caller that is no agent, an agent with no such Grant,
/// and an agent the owner has not turned the key on for; `BAD_REQUEST` for
/// an attempt that is no attempt id; `NOT_FOUND` for no member the agent may
/// read; a credential that no longer holds; storage faults.
pub fn failure_drill_as_agent(
    memory: &Memory<'_>,
    input: FailureDrillRequest,
) -> MemoryResult<FailureDrillView> {
    if memory.actor_class() != EdgeActorClass::Agent {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{FAILURE_DRILL_AS_VERB} is an agent's door: the caller is no agent"),
            &["Drill through the owner's door with the owner's own credential."],
        ));
    }
    let agent = memory.actor();
    let attempt = EntityId::from_hex(&input.attempt)
        .ok()
        .and_then(|id| AttemptId::from_bytes(id.as_bytes()).ok())
        .ok_or_else(|| MemoryError::bad_request("attempt must be an attempt id in hex"))?;
    let vault = memory.vault();
    let lane = memory.read_lane(ClaimReadStatus::Recorded)?;
    let read = lane.read_projected(&[], None, |txn, _| {
        memory.prove_read_authority_in_txn(txn)?;
        if crate::authority::principal_standing_in_txn(
            vault,
            txn,
            agent,
            EdgeActorClass::Agent,
            FAILURE_DRILL_AS_VERB,
        )?
        .is_none()
        {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                format!(
                    "{FAILURE_DRILL_AS_VERB} takes a live Grant listing {FAILURE_DRILL_AS_VERB}: no live Grant from a live owner names this caller and lists the verb"
                ),
                &["Have the owner grant this caller the verb by name."],
            ));
        }
        let delegated = FAILURE_DRILL_DELEGATE
            .read_in_txn(vault, txn, &[SettingScope::Agent(agent)], None)?
            .value;
        if !delegated {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                format!(
                    "{FAILURE_DRILL_AS_VERB} is the vault owner's: the owner has not turned on {} for this agent",
                    FAILURE_DRILL_DELEGATE.spec.name
                ),
                &["Ask the owner to turn the setting on for this agent."],
            ));
        }
        let trace = member_in_txn(vault, txn, attempt, input.class)?;
        let rows = agent_trace_rows(&trace).ok_or(Error::EntityNotFound)?;
        if lane.entities_readable_in_txn(txn, &rows)?.contains(&false) {
            return Err(Error::EntityNotFound.into());
        }
        Ok::<_, MemoryError>((trace, rows))
    })?;
    let (trace, rows) = read.value;
    let receipt_refs = terminal_receipt_refs(vault, &trace)?;
    memory.produced_from(rows);
    Ok(FailureDrillView::of(trace, receipt_refs))
}
