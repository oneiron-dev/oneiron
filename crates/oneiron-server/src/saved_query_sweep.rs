//! The saved-query sweep (ARCH-0059 `eval`, decide-host 1193): every active
//! Wake or Reactive saved query the vault owner holds is evaluated over the
//! vault's people, one bounded wake a pass, each pass going on from where the
//! last stopped. A query's LLM judge asks the membership question through the
//! host's ladder, its first read on the query's named model, paid on the
//! owner's line. Verdicts land in the query's memo; a person whose evidence
//! has not moved costs nothing. A committed write also wakes a reactive pass:
//! each Reactive query is re-checked at once for the people the vault's
//! change log says a claim write moved, and its paged wake stays the backstop
//! for what that log cannot show.
//!
//! Only the home node sweeps, so a judge is paid once per vault.
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use oneiron::llm::{HostInferenceBinding, HostInferenceContext};
use oneiron::saved_query::{
    MatcherSpec, QueryScope, SWEEP_CANDIDATE_TYPE, SavedQueryEvaluator, SavedQueryJudgeBinding,
    SavedQueryRecord, WakeEvaluationReport, reactive_saved_queries, saved_query_change_head,
    saved_query_changes_after, sweep_owner_grants, sweep_saved_queries,
};
use oneiron::{
    BudgetExhaustionPolicy, BudgetLease, CallClass, CallEnvelope, CallPurpose, EdgeActorClass,
    EntityId, FatalLlmError, LlmBackend, LlmCapability, LlmGenerateFuture, LlmRequest, LlmResult,
    LlmStreamResult, ModelId, ModelLocality, ModelTierRef, ResponseFormat, TierPrecedence, Vault,
    WriteActor,
};

use crate::ladder_poll::block_on;
use crate::models::RunBackend;
use crate::server::SyncServer;

/// How long the sweep rests between paged passes.
const SWEEP: Duration = Duration::from_secs(60);
/// Change-log rows one reactive pass reads; a longer backlog drains over
/// passes that run back to back.
const REACTIVE_ROWS: usize = 256;

/// Starts the sweep. Each pass runs on a blocking thread, held by `admit` (a
/// managed vault frozen for reap skips it): the ladder's model rungs block on
/// the server's runtime. A committed write wakes a reactive pass at once; a
/// paged pass runs every [`SWEEP`].
pub(crate) fn spawn(
    server: &Arc<SyncServer>,
    admit: crate::server::HousekeepingAdmission,
) -> tokio::task::JoinHandle<()> {
    let weak = Arc::downgrade(server);
    // Subscribed before the change log's head is read, so no write between
    // them is missed.
    let mut changes = server.vault().subscribe_proactivity_changes();
    // The reactive pass reads only what changes from now on; the first
    // paged pass covers what came before.
    let head = saved_query_change_head(server.vault()).unwrap_or_else(|error| {
        tracing::warn!(kind = ?error.kind(), "the change log's head could not be read; reactive passes start from its beginning");
        None
    });
    tokio::spawn(async move {
        // Where each query's next wake goes on from.
        let mut cursors = BTreeMap::<EntityId, EntityId>::new();
        // The last change-log row a reactive pass read.
        let mut after = head;
        let mut next_wake = tokio::time::Instant::now();
        loop {
            let Some(server) = weak.upgrade() else {
                break;
            };
            let wake = tokio::time::Instant::now() >= next_wake;
            let Some(pass) = admit() else {
                if wake {
                    next_wake = tokio::time::Instant::now() + SWEEP;
                }
                tokio::select! {
                    () = tokio::time::sleep_until(next_wake) => {}
                    changed = changes.changed() => {
                        if changed.is_err() {
                            break;
                        }
                    }
                }
                continue;
            };
            let ran = tokio::task::spawn_blocking(move || {
                let _pass = pass;
                let now = oneiron_vault_contract::now_ts();
                let mut read = after;
                let result = (|| {
                    let home = crate::decision_graph::at_home(server.vault(), now)?;
                    let more = reactive_pass(&server, &mut read, home, now)?;
                    if wake && home {
                        sweep_pass(&server, &mut cursors, now)?;
                    }
                    Ok::<_, oneiron::Error>(more)
                })();
                (cursors, read, result)
            })
            .await;
            let mut more = false;
            match ran {
                Ok((kept, read, Ok(remaining))) => {
                    cursors = kept;
                    after = read;
                    more = remaining;
                }
                Ok((_, read, Err(error))) => {
                    cursors = BTreeMap::new();
                    after = read;
                    tracing::warn!(kind = ?error.kind(), "the saved-query sweep failed; it runs again next pass");
                }
                Err(error) => {
                    cursors = BTreeMap::new();
                    tracing::warn!(%error, "the saved-query sweep stopped");
                }
            }
            if wake {
                next_wake = tokio::time::Instant::now() + SWEEP;
            }
            if more {
                continue;
            }
            tokio::select! {
                () = tokio::time::sleep_until(next_wake) => {}
                changed = changes.changed() => {
                    if changed.is_err() {
                        break;
                    }
                }
            }
        }
    })
}

/// One read of the change log after `after`, then each Reactive query
/// re-checked for the people it moved, in one bounded wake each: a person
/// past the query's wake bounds waits for its paged pass. Off home, or with
/// no Reactive query, it skips to the log's head. Returns whether changes
/// remain to read.
fn reactive_pass(
    server: &SyncServer,
    after: &mut Option<[u8; 16]>,
    home: bool,
    now: u64,
) -> oneiron::Result<bool> {
    let vault = server.vault();
    let queries = if home {
        reactive_saved_queries(vault)?
    } else {
        Vec::new()
    };
    if queries.is_empty() {
        *after = saved_query_change_head(vault)?.or(*after);
        return Ok(false);
    }
    let changes = saved_query_changes_after(vault, *after, REACTIVE_ROWS)?;
    if changes.through.is_some() {
        *after = changes.through;
    }
    if changes.persons.is_empty() {
        return Ok(changes.more);
    }
    let page: Vec<EntityId> = changes.persons.into_iter().collect();
    for record in &queries {
        let Some(grants) = sweep_owner_grants(vault, record.definition.owner_actor)? else {
            continue;
        };
        match evaluate(server, record, &grants, &page, now) {
            Ok(report) => tracing::debug!(
                query = %record.query_ref.to_hex(),
                evaluated = report.evaluated,
                memo_hits = report.memo_hits,
                judges = report.judges_run,
                "a saved query's reactive re-check ran"
            ),
            Err(error) => tracing::warn!(
                query = %record.query_ref.to_hex(),
                kind = ?error.kind(),
                "a saved query's reactive re-check failed; its paged pass covers it"
            ),
        }
    }
    Ok(changes.more)
}

/// One wake of each query the sweep evaluates.
fn sweep_pass(
    server: &SyncServer,
    cursors: &mut BTreeMap<EntityId, EntityId>,
    now: u64,
) -> oneiron::Result<()> {
    let vault = server.vault();
    let queries = sweep_saved_queries(vault)?;
    cursors.retain(|query, _| queries.iter().any(|record| record.query_ref == *query));
    for record in &queries {
        let Some(grants) = sweep_owner_grants(vault, record.definition.owner_actor)? else {
            tracing::debug!(
                query = %record.query_ref.to_hex(),
                "the saved query's owner is not the vault owner; the sweep leaves it to an explicit evaluation"
            );
            continue;
        };
        let wake = usize::try_from(record.definition.eval.max_entities_per_wake)
            .unwrap_or(usize::MAX)
            .max(1);
        let after = cursors.get(&record.query_ref).copied();
        let page = vault.entities_by_type_page(SWEEP_CANDIDATE_TYPE, after.as_ref(), wake)?;
        let report = match evaluate(server, record, &grants, &page, now) {
            Ok(report) => report,
            Err(error) => {
                tracing::warn!(
                    query = %record.query_ref.to_hex(),
                    kind = ?error.kind(),
                    "the saved query's wake failed; it goes on from the same place next pass"
                );
                continue;
            }
        };
        // A short page ended the people: the next wake starts over.
        match report.resume_after.or(page.last().copied()) {
            Some(last) if report.resume_after.is_some() || page.len() == wake => {
                cursors.insert(record.query_ref, last);
            }
            _ => {
                cursors.remove(&record.query_ref);
            }
        }
        tracing::debug!(
            query = %record.query_ref.to_hex(),
            evaluated = report.evaluated,
            memo_hits = report.memo_hits,
            judges = report.judges_run,
            "a saved-query wake ran"
        );
    }
    Ok(())
}

/// One bounded wake of `record` over `page`. An LLM judge's first read goes
/// on the query's named model under a run on the owner's line; a query whose
/// model this server does not serve is not evaluated.
fn evaluate(
    server: &SyncServer,
    record: &SavedQueryRecord,
    grants: &QueryScope,
    page: &[EntityId],
    now: u64,
) -> oneiron::Result<WakeEvaluationReport> {
    let vault = server.vault();
    let MatcherSpec::LlmJudge { model_id, .. } = &record.definition.matcher else {
        let evaluator = SavedQueryEvaluator {
            vault,
            owner_grants: grants,
            judge: None,
        };
        return block_on(evaluator.evaluate_wake_batch(record.query_ref, page, now));
    };
    let model = ModelId::new(model_id.clone()).map_err(|_| {
        oneiron::Error::InvalidConfig("the saved query names no valid model".into())
    })?;
    let (locality, ladder) = server
        .ai
        .model_runtime()
        .router()
        .and_then(|router| router.served(&model))
        .ok_or_else(|| {
            oneiron::Error::InvalidConfig(format!(
                "this server does not serve the saved query's model {}",
                model.as_str()
            ))
        })?;
    let owner = WriteActor::new(record.definition.owner_actor, EdgeActorClass::Human);
    let run_id = format!("saved_query:{}:{now}", record.query_ref.to_hex());
    let line = |run: String| {
        let units = server.ai.chat_settings().turn_budget_units;
        vault.policy_budget_guard(
            run,
            units,
            oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS.min(units),
            BudgetExhaustionPolicy::Suspend,
            owner,
        )
    };
    let backend = AdmittedBackend {
        inner: RunBackend::new(
            ladder,
            server
                .ai
                .undeclared_run(run_id.clone(), line(run_id.clone())?),
        ),
        vault,
        model: model.clone(),
        locality,
    };
    // The binding's lease is a carrier only: every send is admitted on the
    // run's own permits, and the carrier is released unspent.
    let carrier = line(format!("{run_id}/carrier"))?;
    let lease = carrier
        .admit()
        .map_err(|_| oneiron::Error::InvalidConfig("the owner's line admits no judge".into()))?
        .lease;
    let purpose = CallPurpose::Eval;
    let envelope = CallEnvelope {
        seat_effort: None,
        scope: Default::default(),
        tier: TierPrecedence::for_purpose(&purpose, ModelTierRef(model.as_str().to_owned())),
        purpose,
        class: CallClass::BestEffort,
        response_format: ResponseFormat::Text,
        locality,
    };
    let decisions = server.decision_host().membership_decisions()?;
    let evaluator = SavedQueryEvaluator {
        vault,
        owner_grants: grants,
        judge: Some(SavedQueryJudgeBinding {
            backend: &backend,
            lease: &lease,
            envelope: &envelope,
            decisions: &decisions,
        }),
    };
    let report = block_on(evaluator.evaluate_wake_batch(record.query_ref, page, now));
    let _ = carrier.abort(&lease);
    report
}

/// The run's backend with each request the judge builds admitted against the
/// vault's live model policy first: its defaults, catalog and locality.
struct AdmittedBackend<'v> {
    inner: RunBackend,
    vault: &'v Vault,
    model: ModelId,
    locality: ModelLocality,
}

impl AdmittedBackend<'_> {
    fn admit(&self, request: LlmRequest) -> LlmResult<LlmRequest> {
        if request.model != self.model {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        self.vault
            .authorize_raw_inference(
                request,
                &HostInferenceContext {
                    binding: HostInferenceBinding::Advertised {
                        model: self.model.clone(),
                        locality: self.locality,
                    },
                    extraction_egress: None,
                },
            )
            .map(|admitted| admitted.into_request())
            .map_err(|_| FatalLlmError::InvalidRequest.into())
    }
}

impl LlmBackend for AdmittedBackend<'_> {
    fn supports(&self, model: &ModelId, capability: LlmCapability) -> bool {
        self.inner.supports(model, capability)
    }

    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        match self.admit(request) {
            Ok(request) => self.inner.generate(request, lease),
            Err(error) => Box::pin(std::future::ready(Err(error))),
        }
    }

    fn stream<'a>(&'a self, request: LlmRequest, lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        self.inner.stream(self.admit(request)?, lease)
    }
}
