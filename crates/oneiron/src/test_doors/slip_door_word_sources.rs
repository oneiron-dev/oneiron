//! Production writers for the derived-row slip-door fixtures.

use std::sync::Arc;
use std::time::Duration;

use crate::agent_def::{CompactionOwnership, MemoryProfile};
use crate::compaction::{
    CompactionBackend, CompactionBackendRegistry, CompactionCheck, CompactionDriver,
    CompactionGatePolicy, CompactionProduct, CompactionRefusal, CompactionRequest,
    CompactionTierClass, CompactionWatermark, CompactionWindowMessage, gate_compaction,
};
use crate::error::{Error, Result};
use crate::{EdgeActorClass, EdgeKind, EntityId, FinishReason, ModelTierRef, Vault, WriteActor};

/// Records the finding notice whose subjects are `finding` and `subject`.
///
/// # Errors
/// The notification writer's or the store's.
pub fn file_finding_notice(
    vault: &Vault,
    finding: EntityId,
    subject: EntityId,
    at: u64,
) -> Result<EntityId> {
    vault.with_write_txn_grouped(|txn| {
        vault.record_finding_notification_in_txn(txn, finding, subject, at)
    })
}

/// Mints a base epoch whose intent NOTE carries the call's one live source.
/// Returns the NOTE the epoch mint stages, not the epoch summary.
///
/// # Errors
/// The compaction driver, gate or writer refused the fixture.
pub fn file_compaction_intent(
    vault: &Vault,
    owner: EntityId,
    source: EntityId,
) -> Result<EntityId> {
    let summary = file_epoch_summary_from(vault, owner, vec![source])?;
    vault
        .edges_in(&summary)?
        .into_iter()
        .find(|edge| edge.kind == EdgeKind::About)
        .map(|edge| edge.target)
        .ok_or(Error::InvariantViolation(
            "the epoch mint left no intent NOTE",
        ))
}

/// Mints a base epoch from the call's live `sources` through the production
/// compaction driver, gate and epoch mint, and returns the epoch SUMMARY
/// (stored epoch Yes). The mint's `DerivedFrom` edges start with the sealed
/// request's sources (`summary_dependencies`), so a TURN passed here is a
/// source the epoch's word-source fence walks.
///
/// # Errors
/// The compaction driver, gate or writer refused the fixture.
pub fn file_epoch_summary_from(
    vault: &Vault,
    owner: EntityId,
    sources: Vec<EntityId>,
) -> Result<EntityId> {
    let mut backends = CompactionBackendRegistry::new();
    let backend = Arc::new(IntentBackend);
    let profile = MemoryProfile::new(
        1_000,
        ModelTierRef(backend.backend_key().into()),
        CompactionOwnership::Engine,
    );
    backends.register(backend)?;
    let mut driver = CompactionDriver::for_profile(&profile, &backends)?.ok_or(
        Error::InvariantViolation("the engine profile has no compaction driver"),
    )?;
    let session = vault.store.clock.entity_id()?;
    let run = vault.store.clock.entity_id()?;
    let _ = driver.begin_positioned(CompactionWatermark {
        learned_at: vault.now_recorded_at(),
        turn_id: None,
        turn: Some(0),
    });
    let content = "The morning was quiet and the afternoon was clear.";
    let request = driver.request_for_log(
        vault.store.clock.entity_id()?,
        &session,
        vec![CompactionWindowMessage {
            message_id: vault.store.clock.entity_id()?,
            turn_id: vault.store.clock.entity_id()?,
            content: content.into(),
            turn: 0,
            tokens: crate::count_context_pack_tokens(content) as u64,
        }],
        vec!["quiet".into()],
        sources,
        None,
        1,
        None,
        run,
    )?;
    let product = driver
        .backend()
        .compact(&request, None)
        .map_err(|_| Error::InvariantViolation("the fixture backend refused compaction"))?;
    let gated = gate_compaction(
        &request,
        &product,
        &CompactionGatePolicy {
            floor_tokens: 0,
            ..Default::default()
        },
    )
    .map_err(|failure| Error::InvalidConfig(failure.to_string()))?;
    let plan = driver.integrate(
        vault,
        &session,
        WriteActor::new(owner, EdgeActorClass::Human),
        gated,
        &[],
    )?;
    Ok(plan.summary_id)
}

struct IntentBackend;

impl CompactionBackend for IntentBackend {
    fn backend_key(&self) -> &str {
        "slip-door-intent-test"
    }

    fn tier_class(&self) -> CompactionTierClass {
        CompactionTierClass::Cheap
    }

    fn compact(
        &self,
        _request: &CompactionRequest,
        _retry: Option<CompactionCheck>,
    ) -> std::result::Result<CompactionProduct, CompactionRefusal> {
        Ok(CompactionProduct {
            summary_text: r#"{"from":0,"through":0,"summary":"quiet"}"#.into(),
            finish: FinishReason::Stop,
            latency: Duration::ZERO,
        })
    }
}
