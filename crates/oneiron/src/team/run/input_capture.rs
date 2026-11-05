//! Canonical original inputs for an explicitly scoped team receipt.

use std::collections::BTreeSet;

use rmpv::Value;

use crate::Vault;
use crate::batch::VadPostcommitScope;
use crate::claim::{ClaimBody, ClaimLifecycleStatus};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::memory::ClaimRelationships;
use crate::temporal::TimeRange;
use crate::vault::entity_refs::resolve_entity_ref;
use crate::write_envelope::claim_body::ClaimSubject;
use crate::write_envelope::{ClaimCandidate, WriteEnvelope};

use super::{TeamRecordInput, TeamRunAnswer};

const INPUT_PREDICATE: &str = "team.record.input";

type Answer = std::result::Result<TeamRunAnswer, &'static str>;

/// Captures only when the caller selected a position and the host supplied its
/// real envelope. Capture failures keep the ordinary receipt path unchanged.
pub(crate) fn record_led_team_captured(
    vault: &Vault,
    leader: crate::attempt_queue::AttemptId,
    input: &TeamRecordInput,
    envelope: Option<&WriteEnvelope>,
    now: u64,
) -> Result<Answer> {
    let (Some(selected), Some(envelope)) = (input.capture_scope.as_ref(), envelope) else {
        return super::record_led_team(vault, leader, input, now);
    };
    // Reference selection is data, not authority. Resolve before opening the
    // writer: short-ref hydration owns a read transaction of its own.
    let Some(position) = CapturePosition::resolve(vault, selected) else {
        return super::record_led_team(vault, leader, input, now);
    };
    vault.with_write_txn_grouped(|parent| {
        // A replay or an uncertain lookup uses the original body, including its
        // validation order and storage errors, without minting a source row.
        if matches!(
            crate::team::receipt::team_receipt_in_txn(vault, parent, &input.team_ref),
            Ok(None)
        ) && let Some(answer) =
            capture_receipt_in_txn(vault, parent, leader, input, &position, envelope, now)?
        {
            return Ok(answer);
        }
        super::record_led_team_in_txn(vault, parent, leader, input, now)
    })
}

fn capture_receipt_in_txn(
    vault: &Vault,
    parent: &mut heed::RwTxn<'_>,
    leader: crate::attempt_queue::AttemptId,
    input: &TeamRecordInput,
    position: &CapturePosition,
    envelope: &WriteEnvelope,
    now: u64,
) -> Result<Option<Answer>> {
    let Ok(mut child) = vault.store.env.nested_write_txn(parent) else {
        return Ok(None);
    };
    let postcommit = VadPostcommitScope::new(vault, &child);
    let Ok(decoded) = capture_input_in_txn(vault, &mut child, input, position, envelope, now)
    else {
        return Ok(None);
    };
    // Receipt errors are not capture errors. Propagate them; a refusal or replay
    // returns its ordinary answer but discards the newly captured source.
    let answer = super::record_led_team_in_txn(vault, &mut child, leader, &decoded, now)?;
    if matches!(&answer, Ok(TeamRunAnswer::Recorded { replay: false, .. })) {
        child.commit()?;
        postcommit.merge_into(vault, parent);
    }
    Ok(Some(answer))
}

fn capture_input_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    input: &TeamRecordInput,
    position: &CapturePosition,
    envelope: &WriteEnvelope,
    now: u64,
) -> Result<TeamRecordInput> {
    let original = serde_json::to_string(input).map_err(|_| unavailable())?;
    let id = EntityId::from_bytes(vault.store.clock.ulid()?)?;
    let subject = ClaimSubject::Entity(envelope.actor().entity_ref());
    // Text takes the ordinary claim secret-scan/custody path, unlike opaque
    // blob bytes. A rewrite must still decode to the exact original input.
    let candidate = ClaimCandidate::new(INPUT_PREDICATE, subject, Value::from(original), 1.0)
        .with_world(position.world)
        .with_relationships(position.relationships.clone())
        .with_scope(position.scope.clone())
        .with_scope_stamps(position.facet, position.project);
    let mut retained = envelope.clone();
    vault.sign_retained_machine_claim_in_txn(&*txn, &id, &candidate, &mut retained)?;
    let occurred = TimeRange {
        start: now,
        end: now,
    };
    vault
        .batch_in()
        .claim_candidate(&id, candidate, &retained, occurred, now)
        .apply_actor(txn, &envelope.actor())?;
    let body = vault
        .get_claim_in_txn(&*txn, &id)?
        .ok_or_else(unavailable)?;
    if body.predicate != INPUT_PREDICATE
        || body.subject != subject
        || body.lifecycle != ClaimLifecycleStatus::Active
        || body.stale
        || !position.matches(&body)
    {
        return Err(unavailable());
    }
    let decoded: TeamRecordInput =
        serde_json::from_str(body.value.as_str().ok_or_else(unavailable)?)
            .map_err(|_| unavailable())?;
    if decoded != *input {
        return Err(unavailable());
    }
    Ok(decoded)
}

struct CapturePosition {
    world: EntityId,
    facet: EntityId,
    relationships: Option<BTreeSet<EntityId>>,
    project: EntityId,
    scope: Value,
}

impl CapturePosition {
    fn resolve(vault: &Vault, position: &crate::memory::ClaimScope) -> Option<Self> {
        let relationships = match &position.scope_relationship_id {
            ClaimRelationships::All(_) => None,
            ClaimRelationships::Relationships(ids) => Some(
                ids.iter()
                    .map(|id| resolve_entity_ref(vault, id))
                    .collect::<std::result::Result<BTreeSet<_>, _>>()
                    .ok()?,
            ),
        };
        let world = resolve_entity_ref(vault, &position.world_id).ok()?;
        let facet = resolve_entity_ref(vault, &position.scope_facet_id).ok()?;
        let project = resolve_entity_ref(vault, &position.scope_project_id).ok()?;
        // Match the native scoped claim door's annotations, derived only from
        // its explicit position. No caller map can override a selected axis.
        let scope = Value::Map(vec![
            (Value::from("facet"), Value::from(facet.to_hex())),
            (Value::from("scopeProjectId"), Value::from(project.to_hex())),
        ]);
        Some(Self {
            world,
            facet,
            relationships,
            project,
            scope,
        })
    }

    fn matches(&self, body: &ClaimBody) -> bool {
        body.world.unwrap_or_else(crate::claim::base_world_id) == self.world
            && body.scope_facet == self.facet
            && body.rel == self.relationships
            && body.scope_project == self.project
            && body.scope.as_ref() == Some(&self.scope)
    }
}

fn unavailable() -> Error {
    Error::InvariantViolation("team original-input capture unavailable")
}
