//! Doors for the untangle regression tests (`tests/untangle_regressions.rs`;
//! lead 19:05 9 Nov, TESTS-MUST-RUN): each is a thin door over one
//! crate-private item, or a port of a seed helper of the `#[cfg(test)]`
//! fixtures, so the ruled behaviour tests of X01, X02, CONSENT-RAMP and the
//! repeat revoke (#6874) run from an integration target while the lib test
//! target does not compile. Compiled only under `--cfg oneiron_test_support`
//! (`test_doors`); the existing `test_support` doors they call are on in every
//! test build through the crate's self dev-dependency. Hidden; never API.
//! Every assertion stays in the test file: these return plain values.

use std::collections::VecDeque;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use rmpv::Value;

use crate::config::VaultConfig;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::GateError;
use crate::temporal::TimeRange;
use crate::vault::Vault;
use crate::{AttemptId, Error, Result};

// ─── vaults ─────────────────────────────────────────────────────────────

/// A temporary vault opened with `cfg`, with a process-memory device keystore
/// installed, as the crate's legacy test opener
/// (`test_util::open_test_vault_with`) opens it, except that it keeps the
/// seeded default policy manifest. The legacy opener deletes that row
/// through the stale `#[cfg(test)]` helper `batch::deindex_entity_for_test`,
/// so its tests read the shipped default by fallback. The seeded row holds
/// those same bytes (`gate::default_policy_manifest`), so the policy every
/// door reads is unchanged.
#[doc(hidden)]
#[must_use]
pub fn open_test_vault_with(cfg: VaultConfig) -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), cfg).expect("open vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    (dir, vault)
}

/// The crate's embedding test config (`test_util::embedding_test_config`).
#[doc(hidden)]
#[must_use]
pub fn embedding_test_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = Some("test/model@v1".to_owned());
    config.max_readers = 16;
    config
}

// ─── Dreamer fixtures ───────────────────────────────────────────────────

/// The Dreamer tests' vault (`dreamer_consolidation::tests::open_vault`): the
/// legacy opener, the engine's MACHINE writers, owner-pinned test egress and
/// the shipped policy.
#[doc(hidden)]
#[must_use]
pub fn open_dreamer_vault() -> (tempfile::TempDir, Vault) {
    let (dir, vault) = open_test_vault_with(VaultConfig::device());
    let _issuer = crate::test_support::provision_engine_machines(&vault);
    authorize_test_inference(&vault).expect("owner-pinned test egress");
    install_shipped_policy(&vault).expect("shipped policy");
    (dir, vault)
}

/// Installs the shipped default policy manifest, which the legacy opener
/// clears; the Dreamer's read row (ARCH-0026) is in it.
///
/// # Errors
/// The store's.
#[doc(hidden)]
pub fn install_shipped_policy(vault: &Vault) -> Result<()> {
    crate::test_support::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id()?,
        &crate::gate::default_policy_manifest()?,
    )
}

/// Pins extraction to the owner's own server, as the Dreamer tests' egress
/// fixture does.
///
/// # Errors
/// The store's, or a purpose table with no extraction row.
#[doc(hidden)]
pub fn authorize_test_inference(vault: &Vault) -> Result<()> {
    let mut policy = vault.purpose_default_table()?;
    policy.extraction_max_locality = crate::ModelLocality::OwnServer;
    policy
        .purposes
        .get_mut(&crate::CallPurpose::Extraction)
        .ok_or_else(|| Error::InvalidConfig("missing extraction row".into()))?
        .locality = crate::ModelLocality::OwnServer;
    vault.set_purpose_default_table(&policy)?;
    Ok(())
}

/// This device's stable client id (`identity::load_or_mint_client_id`).
///
/// # Errors
/// The store's.
#[doc(hidden)]
pub fn load_or_mint_client_id(vault: &Vault) -> Result<u64> {
    crate::identity::load_or_mint_client_id(vault)
}

// ─── seed rows ──────────────────────────────────────────────────────────

fn occurred(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

/// A SESSION row at `[seed; 16]`.
#[doc(hidden)]
#[must_use]
pub fn seed_session(vault: &Vault, seed: u8, at: u64) -> EntityId {
    let id = EntityId::from_bytes([seed; 16]).expect("session id");
    vault
        .put_entity(
            &id,
            crate::registry::ENTITY_TYPE_SESSION,
            occurred(at),
            at,
            b"session",
        )
        .expect("seed session");
    id
}

/// A TURN carrying its own words, `ChildOf` its conversation, in one batch.
#[doc(hidden)]
#[must_use]
pub fn seed_turn(
    vault: &Vault,
    conversation: &EntityId,
    speaker: &str,
    text: &str,
    learned_at: u64,
) -> EntityId {
    let id = EntityId::now();
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &Value::Map(vec![
            (Value::from("txt"), Value::from(text)),
            (Value::from("spkr"), Value::from(speaker)),
        ]),
    )
    .expect("turn body encode");
    vault
        .batch()
        .put(
            &id,
            crate::registry::ENTITY_TYPE_TURN,
            occurred(learned_at),
            learned_at,
            &body,
        )
        .edge(&id, crate::EdgeKind::ChildOf, conversation, 1.0)
        .commit()
        .expect("seed turn");
    id
}

/// A PERSON row at `id` whose body names it `name`, so `name` is its
/// identity hint: a passage that says `name` lists it to an extraction call.
///
/// # Errors
/// The store's.
#[doc(hidden)]
pub fn seed_named_person(vault: &Vault, id: &EntityId, name: &str, at: u64) -> Result<()> {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &Value::Map(vec![(Value::from("name"), Value::from(name))]),
    )
    .expect("person body encode");
    vault.put_entity(
        id,
        crate::registry::ENTITY_TYPE_PERSON,
        occurred(at),
        at,
        &body,
    )
}

// ─── policy rows ────────────────────────────────────────────────────────

/// Whether a manifest row names the Dreamer as its actor.
fn names_actor(row: &Value, actor: &str) -> bool {
    row.as_map().is_some_and(|fields| {
        fields
            .iter()
            .any(|(key, value)| key.as_str() == Some("actor_ref") && value.as_str() == Some(actor))
    })
}

/// Removes the Dreamer's read row from the vault's default policy
/// (`test_util::withhold_dreamer_read`), as a vault seeded before
/// ARCH-0026's warm default, or whose owner removed the row, holds it. Every
/// other row, the Dreamer's ceiling and permit included, stays.
///
/// # Errors
/// No stored default manifest, or the store's.
#[doc(hidden)]
pub fn withhold_dreamer_read(vault: &Vault) -> Result<()> {
    let id = crate::gate::default_policy_manifest_id()?;
    let body = vault.get(&id)?.ok_or(Error::EntityNotFound)?;
    let Value::Map(mut entries) =
        rmpv::decode::read_value(&mut body.as_slice()).expect("default policy map")
    else {
        unreachable!("default policy manifest is a map");
    };
    let dreamer = crate::dreamer_runner::authority::dreamer_actor_id()?.to_hex();
    for (key, table) in &mut entries {
        if let (Some("scoped_grants"), Value::Array(rows)) = (key.as_str(), table) {
            rows.retain(|row| !names_actor(row, &dreamer));
        }
    }
    entries.retain(|(key, table)| {
        key.as_str() != Some("scoped_grants")
            || table.as_array().is_some_and(|rows| !rows.is_empty())
    });
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &Value::Map(entries)).expect("encode policy");
    crate::test_support::put_policy_manifest_bytes(vault, id, &data)
}

/// One of the two rows that let the Dreamer land Auto (X02).
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DreamerLandingRow {
    /// Its Auto actor ceiling.
    ActorCeiling,
    /// Its `Generated` source-trust permit.
    GeneratedPermit,
}

/// The owner narrowed the Dreamer's landing
/// (`test_util::seeded_without_dreamer_landing_row`): the seeded default
/// without `row`, its read grant and its other landing row kept, and still
/// the untouched seed.
///
/// # Errors
/// The store's.
#[doc(hidden)]
pub fn seeded_without_dreamer_landing_row(vault: &Vault, row: DreamerLandingRow) -> Result<()> {
    let dreamer = crate::dreamer_runner::authority::dreamer_actor_id()?.to_hex();
    let manifest = crate::gate::default_policy_manifest()?;
    let Value::Map(mut entries) = rmpv::decode::read_value(&mut &manifest[..]).expect("map") else {
        panic!("policy manifest is a map");
    };
    for (key, value) in &mut entries {
        match (key.as_str(), row) {
            (Some("actor_ceilings"), DreamerLandingRow::ActorCeiling) => {
                if let Value::Array(rows) = value {
                    rows.retain(|ceiling| !names_actor(ceiling, &dreamer));
                }
            }
            (Some("source_trust"), DreamerLandingRow::GeneratedPermit) => {
                if let Value::Map(sources) = value {
                    for (source, rows) in sources.iter_mut() {
                        if source.as_str() == Some("generated")
                            && let Value::Array(list) = rows
                        {
                            list.retain(|permit| !names_actor(permit, &dreamer));
                        }
                    }
                    // A permit that was the Dreamer's alone leaves no row.
                    sources.retain(|(source, rows)| {
                        source.as_str() != Some("generated")
                            || !(names_actor(rows, &dreamer)
                                || rows.as_array().is_some_and(Vec::is_empty))
                    });
                }
            }
            _ => {}
        }
    }
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &Value::Map(entries)).expect("encode");
    let id = crate::gate::default_policy_manifest_id()?;
    crate::test_support::put_policy_manifest_bytes(vault, id, &data)?;
    vault.with_write_txn(|txn| {
        vault.store.sync_state.put(
            txn,
            &oneiron_store::manifest_origin_keys::seeded_manifest_key(&id),
            blake3::hash(&data).as_bytes(),
        )?;
        Ok(())
    })
}

// ─── X01: the Dreamer's side doors ──────────────────────────────────────

/// A TURN record one of the Dreamer's side doors (gap scan, owner intent,
/// retrieval shadow) read, held so its writer's re-check can run after a
/// policy change (X01).
#[doc(hidden)]
pub struct SideDoorTurnText(crate::dreamer_consolidation::TurnText);

impl SideDoorTurnText {
    /// The TURN's words as the side door read them; `None` when it gave none.
    #[must_use]
    pub fn text(&self) -> Option<&str> {
        self.0.text()
    }

    /// The writer's re-check of this record (`TurnText::check_live_in`),
    /// read as the Dreamer in a fresh snapshot.
    ///
    /// # Errors
    /// The re-check's refusal.
    pub fn recheck_as_dreamer(&self, vault: &Vault, turn: &EntityId) -> Result<()> {
        crate::dreamer_consolidation::side_door_recheck_for_test(&self.0, vault, turn)
    }
}

/// The side doors' read of one TURN (`turn_text::read_turn_text`).
///
/// # Errors
/// The read's.
#[doc(hidden)]
pub fn side_door_turn_text(vault: &Vault, turn: &EntityId) -> Result<SideDoorTurnText> {
    crate::dreamer_consolidation::side_door_turn_text_for_test(vault, turn).map(SideDoorTurnText)
}

/// The retrieval tagger's shadow read of one TURN's words.
///
/// # Errors
/// Not a TURN, a TURN with no text the Dreamer may read, or the read's.
#[doc(hidden)]
pub fn turn_text_for_shadow(vault: &Vault, turn: &EntityId) -> Result<String> {
    crate::dreamer_consolidation::turn_text_for_shadow(vault, turn)
}

// ─── X02: one Micro wake pass and the strength archive ──────────────────

/// Queues the Micro partition attempts over the dirty TURNs, as the weave
/// tests' `enqueue_micro` does.
///
/// # Errors
/// The watermark scan's or the queue's.
#[doc(hidden)]
pub fn enqueue_micro(vault: &Vault, run: &str, now: u64) -> Result<()> {
    use crate::dreamer_consolidation::{
        enqueue_partition_attempts, read_watermark, scan_dirty_turns,
    };
    let scope = crate::DreamerConsolidationScope::Micro;
    let watermark = read_watermark(vault, scope)?;
    let dirty = scan_dirty_turns(vault, scope, &watermark, 10)?;
    enqueue_partition_attempts(vault, scope, &dirty, &watermark, run, now)?;
    Ok(())
}

/// A backend that answers each call with the next scripted reply.
struct ScriptedBackend {
    script: Mutex<VecDeque<crate::LlmResult<crate::LlmResponse>>>,
}

impl crate::LlmBackend for ScriptedBackend {
    fn generate<'a>(
        &'a self,
        _request: crate::LlmRequest,
        _lease: &'a crate::BudgetLease,
    ) -> crate::LlmGenerateFuture<'a> {
        let next = self
            .script
            .lock()
            .expect("script mutex")
            .pop_front()
            .expect("scripted backend exhausted");
        Box::pin(async move { next })
    }

    fn stream<'a>(
        &'a self,
        _request: crate::LlmRequest,
        _lease: &'a crate::BudgetLease,
    ) -> crate::LlmStreamResult<'a> {
        Err(crate::LlmError::Fatal(crate::FatalLlmError::InvalidRequest))
    }
}

/// One extraction reply: the listed entity `P1` has `profile.name`
/// `Oleksii`, quoted from the turn `T1`. The Dreamer tests'
/// `extraction_response` named the subject by its 32-hex id and cited a
/// byte range of the turn's id; since FIX 7506 (call-local labels) a model
/// reply names only what its call listed, and that shape is refused at
/// `executor/extraction/wire.rs` `contract_fault` ("breaks its contract at
/// subject"), so the partition parks. This is the same reply in the labelled
/// wire.
fn extraction_response() -> crate::LlmResponse {
    let json = "{\"candidates\": [{\"subject\": \"P1\", \"predicate\": \"profile.name\", \
                \"value\": \"Oleksii\", \"confidence\": 0.8, \
                \"evidence_refs\": [{\"source\": \"T1\", \"quote\": \"Oleksii\"}]}]}"
        .to_owned();
    crate::LlmResponse {
        message: crate::LlmMessage {
            role: crate::LlmMessageRole::Assistant,
            content: vec![crate::ContentPart::Text {
                text: json,
                signature: None,
            }],
        },
        usage: crate::LlmUsage {
            input: crate::LlmInputUsage {
                total: 90,
                cache_read: 0,
                cache_write: 0,
            },
            output: crate::LlmOutputUsage {
                total: 30,
                text: 30,
                reasoning: 0,
            },
            raw_provider: serde_json::Value::Null,
            call_metadata: None,
        },
        finish_reason: crate::FinishReason::Stop,
        reply_assertions: Default::default(),
        token_scores: None,
    }
}

fn allow_fixture_extraction(_: &crate::LlmRequest) -> bool {
    true
}

/// Polls a wake pass that never waits on I/O to its boundary.
fn ready<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..128 {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return value;
        }
    }
    panic!("wake pass did not reach a boundary");
}

/// One Micro wake pass through the owned attempt sink, its one extraction
/// call answered with the listed person `P1`'s `profile.name`, quoted from
/// the turn `T1` (the weave tests' `pass` with their `extraction_response`
/// script, in the labelled wire).
///
/// # Errors
/// The pass's.
#[doc(hidden)]
pub fn micro_wake_pass_with_extraction(
    vault: &Arc<Vault>,
    node_id: u64,
    now: u64,
) -> Result<crate::WakePassReport> {
    let backend = ScriptedBackend {
        script: Mutex::new(VecDeque::from([Ok(extraction_response())])),
    };
    let guard = crate::BudgetGuard::with_reserve_units(
        "wake",
        10_000,
        100,
        crate::BudgetExhaustionPolicy::Suspend,
    );
    let mut sink = crate::dreamer_promotion::AttemptPromotionSink::new(Arc::clone(vault));
    let model = crate::ModelId::new("test/model@r1").expect("model");
    let mut executor = crate::dreamer_consolidation::ConsolidationExecutor {
        roles: Default::default(),
        backend: &backend,
        guard: &guard,
        strategy: crate::DreamerClaimAuthoringStrategy::SinglePass,
        actor: vault.dreamer_authority()?,
        model: model.clone(),
        sink: &mut sink,
        inference: crate::llm::HostInferenceContext {
            binding: crate::llm::HostInferenceBinding::Advertised {
                model,
                locality: crate::ModelLocality::OwnServer,
                keyless: false,
            },
            extraction_egress: Some(&allow_fixture_extraction),
        },
        scope: None,
        decisions: crate::dreamer_consolidation::ConsolidationDecisions::shipped()?,
    };
    let mut driver =
        crate::DreamerWakeDriver::new(vault, "wake", crate::WakePassDeadline::new(180_000));
    ready(driver.run_wake_pass(
        crate::RunWakePass {
            trigger: crate::WakeTrigger::SessionEnd,
            scope: crate::DreamerConsolidationScope::Micro,
            local_node_id: node_id,
            lease_owner: "grant-test".to_owned(),
            budget_total_units: 10_000,
            reserve_units: 500,
            now,
            host_scope: None,
            destination_bound: None,
        },
        &mut executor,
        &crate::WakeCancellation::new(),
    ))
}

/// The first Micro attempt in the queue, if any.
///
/// # Errors
/// The queue's.
#[doc(hidden)]
pub fn micro_attempt(vault: &Vault) -> Result<Option<AttemptId>> {
    Ok(crate::attempt_queue::AttemptQueue::new(vault)
        .list()?
        .into_iter()
        .find(|row| row.kind == crate::DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND)
        .map(|row| row.id))
}

/// The strength archive (`strength::archive_quiet_claims`), as the scoring
/// attempt `attempt` runs it at `now_ms`. Returns how many claims it
/// archived.
///
/// # Errors
/// The archive's.
#[doc(hidden)]
pub fn archive_quiet_claims(vault: &Vault, attempt: AttemptId, now_ms: u64) -> Result<u64> {
    crate::dreamer_consolidation::strength::archive_quiet_claims(vault, attempt, now_ms)
}

/// One gate decision the ledger holds for a claim, in plain values.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimGateDecision {
    /// What the decision was about.
    pub content_kind: String,
    /// The grant or rows it was judged by.
    pub grant_ref: Option<String>,
    /// The read frontier it was judged under.
    pub read_frontier_hash: [u8; 32],
}

/// Every gate decision the ledger holds for `claim`.
///
/// # Errors
/// The ledger's.
#[doc(hidden)]
pub fn gate_decisions_for_claim(vault: &Vault, claim: &EntityId) -> Result<Vec<ClaimGateDecision>> {
    let txn = vault.store.env.read_txn()?;
    Ok(vault
        .store
        .gate_decisions_for_claim_in_txn(&txn, claim.as_bytes())?
        .into_iter()
        .map(|record| ClaimGateDecision {
            content_kind: record.content_kind,
            grant_ref: record.grant_ref,
            read_frontier_hash: record.read_frontier_hash,
        })
        .collect())
}

/// The rows a Dreamer write that takes back what it landed is judged by, as
/// its receipt names them (`gate::DREAMER_LANDING_ROWS_REF`).
#[doc(hidden)]
#[must_use]
pub fn dreamer_landing_rows_ref() -> &'static str {
    crate::gate::DREAMER_LANDING_ROWS_REF
}

// ─── #6874: the owner's revoke of a standing grant ──────────────────────

/// A revoke's answer through the owner door, in plain values.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeAnswer {
    /// The decision id (hex) of the consent revoke receipt the door returned.
    pub receipt: Option<String>,
    /// The grant was already revoked.
    pub already_revoked: bool,
    /// The record that revoked the current issuance without a consent receipt.
    pub revoked_by: Option<String>,
}

/// The owner revokes `grant_ref` (`Vault::consent_revocation`, the owner door
/// that answers a repeat revoke). A refusal is its error kind:
/// `ConsentGrantNotFound`, else the error's debug form.
///
/// # Errors
/// The door's refusal, as above.
#[doc(hidden)]
pub fn owner_revoke(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    grant_ref: &str,
) -> std::result::Result<RevokeAnswer, String> {
    match vault.consent_revocation(owner, grant_ref) {
        Ok(answer) => Ok(RevokeAnswer {
            receipt: answer.receipt.map(|receipt| receipt.decision_id().to_hex()),
            already_revoked: answer.already_revoked,
            revoked_by: answer.revoked_by,
        }),
        Err(error) => Err(error_kind(&error)),
    }
}

fn error_kind(error: &Error) -> String {
    match error {
        Error::Gate(GateError::ConsentGrantNotFound) => "ConsentGrantNotFound".to_owned(),
        other => format!("{other:?}"),
    }
}

/// The decision ids (hex) of every gate decision carrying `grant_ref`,
/// newest first.
///
/// # Errors
/// The ledger's.
#[doc(hidden)]
pub fn gate_decision_ids_for_grant(vault: &Vault, grant_ref: &str) -> Result<Vec<String>> {
    Ok(vault
        .store
        .gate_decisions_for_grant_ref(grant_ref)?
        .into_iter()
        .map(|record| record.decision_id.to_hex())
        .collect())
}

/// Every `Gate` receipt id the public receipt query returns, sorted.
///
/// # Errors
/// The query's.
#[doc(hidden)]
pub fn gate_receipt_ids(vault: &Vault) -> Result<Vec<String>> {
    let mut ids: Vec<String> = vault
        .receipts(
            crate::receipt::ReceiptQuery::default().with_kind(crate::receipt::ReceiptKind::Gate),
        )?
        .into_iter()
        .map(|record| record.receipt_id)
        .collect();
    ids.sort();
    Ok(ids)
}

/// The receipt ids of every graduation demotion, in log order.
///
/// # Errors
/// The query's.
#[doc(hidden)]
pub fn ramp_demotion_receipt_ids(vault: &Vault) -> Result<Vec<String>> {
    Ok(vault
        .receipts(
            crate::receipt::ReceiptQuery::default().with_kind(crate::receipt::ReceiptKind::Gate),
        )?
        .into_iter()
        .filter(crate::consent_graduation::is_ramp_demotion_receipt)
        .map(|record| record.receipt_id)
        .collect())
}
