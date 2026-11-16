//! Doors for `tests/dreamer_promotion_seconds.rs` (UC-03 PR 0a; FIX
//! GATE-ROW-CREATED-AT-MILLISECONDS, DREAMER-RUN-NOW-MS-INTO-SECONDS-PARAMS):
//! a Dreamer promotion run whose clock is milliseconds, as the attempt sink
//! builds it, on a vault whose policy grants the Dreamer's Auto request, and
//! the seconds stamps the run leaves on a parked replacement's pending Gate
//! row and tray row and on a landed claim's Finding notice.

use rmpv::Value as Mp;

use crate::claim::{ClaimSource, ClaimSubject};
use crate::dreamer_consolidation::PromotionCandidate;
use crate::dreamer_promotion::DreamerRunContext;
use crate::dreamer_runner::{
    DreamerRunnerStore, EnqueueDreamerAttempt, EnqueueDreamerAttemptOutcome,
};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::inbox::{
    NOTIFICATION_PRODUCER_FINDING, NotificationSource, decode_notification_body, notification_id,
};
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN};
use crate::temporal::TimeRange;
use crate::vault::Vault;
use crate::write_envelope::ClaimCandidate;

/// One queued Dreamer attempt's run, over a subject and the TURN that
/// evidences its claims.
pub struct PromotionRun {
    pub run: DreamerRunContext,
    pub subject: EntityId,
    pub turn: EntityId,
}

/// The `created_at` of the pending Gate row that parks a claim, and of its
/// tray row (the pending-consent row).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingStamps {
    pub gate_row_created_at: u64,
    pub tray_row_created_at: u64,
}

fn occurred(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

/// Opens a vault at `path` as the `dreamer_promotion` unit tests open theirs:
/// a device vault with an in-memory keystore and provisioned engine machines,
/// whose policy manifest grants the Dreamer's Auto request (a `system` actor
/// ceiling, an auto permit for every provenance source, a manifest signature).
///
/// # Errors
///
/// The vault's.
pub fn open_auto_promotion_vault(path: &std::path::Path) -> Result<Vault> {
    let vault = Vault::open(path, crate::VaultConfig::device())?;
    vault.install_device_keystore(std::sync::Arc::new(
        oneiron_keystore::MemoryKeystore::default(),
    ));
    crate::test_fixtures::provision_engine_machines(&vault);
    crate::test_fixtures::put_policy_manifest_bytes(
        &vault,
        crate::gate::default_policy_manifest_id()?,
        &auto_permitting_manifest()?,
    )?;
    Ok(vault)
}

fn auto_permitting_manifest() -> Result<Vec<u8>> {
    let source_row = || {
        Mp::Map(vec![
            (Mp::from("max_auto_sensitivity"), Mp::from(3_u64)),
            (Mp::from("receipted"), Mp::Boolean(true)),
            (Mp::from("warned"), Mp::Boolean(true)),
        ])
    };
    let ceilings = ["system", "human", "first_party"]
        .into_iter()
        .map(|actor_class| {
            Mp::Map(vec![
                (Mp::from("actor_class"), Mp::from(actor_class)),
                (Mp::from("ceiling"), Mp::from("auto")),
            ])
        })
        .collect();
    let sources = [
        ClaimSource::UserStated,
        ClaimSource::Observed,
        ClaimSource::Inferred,
        ClaimSource::Imported,
        ClaimSource::ToolOutput,
        ClaimSource::Generated,
    ]
    .into_iter()
    .map(|source| (Mp::from(source.as_str()), source_row()))
    .collect();
    let manifest = Mp::Map(vec![
        (
            Mp::from("schema_version"),
            Mp::from(crate::gate::POLICY_SCHEMA_VERSION),
        ),
        (Mp::from("pack_id"), Mp::from("dreamer-promotion-seconds")),
        (Mp::from("pack_version"), Mp::from("v1")),
        (
            Mp::from("min_engine_version"),
            Mp::from(env!("CARGO_PKG_VERSION")),
        ),
        (
            Mp::from("defaults"),
            Mp::Map(vec![
                (Mp::from("criticality"), Mp::from("normal")),
                (Mp::from("sensitivity"), Mp::from("normal")),
            ]),
        ),
        (Mp::from("rules"), Mp::Array(Vec::new())),
        (Mp::from("actor_ceilings"), Mp::Array(ceilings)),
        (Mp::from("source_trust"), Mp::Map(sources)),
        (
            Mp::from("signature"),
            Mp::Map(vec![
                (Mp::from("alg"), Mp::from("ed25519")),
                (Mp::from("key_id"), Mp::from("promotion-test")),
                (Mp::from("sig"), Mp::from("promotion-test-signature")),
            ]),
        ),
    ]);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &manifest)
        .map_err(|_| Error::InvalidConfig("encode the policy manifest".into()))?;
    Ok(out)
}

/// Writes a PERSON subject and a user TURN in a SESSION, queues one Dreamer
/// attempt, and returns its run. The run's clock is the vault's recording
/// clock times 1,000, as `AttemptPromotionSink::promote` builds it.
///
/// # Errors
///
/// The vault's.
pub fn promotion_run(vault: &Vault) -> Result<PromotionRun> {
    let subject = EntityId::now();
    let conversation = EntityId::now();
    let turn = EntityId::now();
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred(1), 1, b"subject")?;
    vault.put_entity(
        &conversation,
        ENTITY_TYPE_SESSION,
        occurred(1),
        1,
        b"session",
    )?;
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &Mp::Map(vec![
            (Mp::from("txt"), Mp::from("my name is Ada")),
            (Mp::from("spkr"), Mp::from("user")),
        ]),
    )
    .map_err(|_| Error::InvalidConfig("encode the turn body".into()))?;
    vault
        .batch()
        .put(&turn, ENTITY_TYPE_TURN, occurred(5), 5, &body)
        .edge(&turn, EdgeKind::ChildOf, &conversation, 1.0)
        .commit()?;
    let status = match DreamerRunnerStore::new(vault).enqueue(EnqueueDreamerAttempt {
        attempt_type: "promotion-seconds".to_owned(),
        input: Mp::from("input"),
        parent_attempt: None,
        dedupe_key: None,
        run_id: Some("run-promotion-seconds".to_owned()),
        now: 6,
    })? {
        EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status) => status,
    };
    Ok(PromotionRun {
        run: DreamerRunContext {
            run_id: "run-promotion-seconds".to_owned(),
            attempt_id: status.attempt.id,
            agent_actor: vault.dreamer_authority()?,
            now_ms: vault.now_recorded_at().saturating_mul(1_000),
        },
        subject,
        turn,
    })
}

/// A Generated `predicate` claim about the run's subject, evidenced by its
/// TURN, that replaces `supersedes` when one is named.
#[must_use]
pub fn candidate(
    run: &PromotionRun,
    predicate: &str,
    value: &str,
    supersedes: Option<EntityId>,
) -> PromotionCandidate {
    PromotionCandidate {
        claim_id: EntityId::now(),
        candidate: ClaimCandidate::new(
            predicate,
            ClaimSubject::Entity(run.subject),
            Mp::from(value),
            0.7,
        ),
        evidence_turn_refs: vec![run.turn],
        provenance_chain: Vec::new(),
        supersedes,
        evidence_meet: ClaimSource::Generated,
        occurred: occurred(9_000),
        learned_at: 9_000,
        decisions: Vec::new(),
    }
}

/// The stamps of the pending Gate row and the tray row that park `claim`;
/// `None` when no tray row parks it.
///
/// # Errors
///
/// The store's, or a tray row whose Gate row is missing.
pub fn pending_stamps(vault: &Vault, claim: &EntityId) -> Result<Option<PendingStamps>> {
    let txn = vault.store.env.read_txn()?;
    let Some(tray) = vault.store.pending_gate_consent_in_txn(&txn, claim)? else {
        return Ok(None);
    };
    let gate = vault
        .store
        .gate_decision_in_txn(&txn, tray.decision_id)?
        .ok_or(Error::InvariantViolation(
            "a tray row names a missing Gate row",
        ))?;
    Ok(Some(PendingStamps {
        gate_row_created_at: gate.created_at,
        tray_row_created_at: tray.created_at,
    }))
}

/// The `created_at` of the Finding notice a landed `finding` raised; `None`
/// when it raised none.
///
/// # Errors
///
/// The vault's, or a notice body that does not decode.
pub fn finding_notice_created_at(vault: &Vault, finding: &EntityId) -> Result<Option<u64>> {
    let id = notification_id(&NotificationSource {
        producer: NOTIFICATION_PRODUCER_FINDING.to_owned(),
        event: finding.to_hex(),
        ..NotificationSource::default()
    })?;
    vault
        .get(&id)?
        .map(|raw| decode_notification_body(&raw).map(|body| body.created_at))
        .transpose()
}
