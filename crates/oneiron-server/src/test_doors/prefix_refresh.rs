//! Door for `tests/idle_prefix_refresh.rs` (L2-37 PR-3): one warm send
//! through a step call's ladder path, then the idle Keep refresh of it.

use std::collections::BTreeMap;
use std::sync::Arc;

use oneiron::llm::ServedCacheHorizon;
use oneiron::{BudgetExhaustionPolicy, BudgetGuard, Vault};

use crate::ai_host::{KeptPrefix, PrefixRefresh};
use crate::models::ModelRuntime;

/// Warms the chat seat's one model with a single request that marks its
/// prefix end as a cache boundary, then Keep-refreshes the answering rung
/// it comes back with, and returns what the refresh returned: the horizon
/// the refresh answer stamped, or `None` when nothing was sent or
/// answered.
///
/// The warm send takes the seat-bound step call's path: it names the
/// seat's one rung by its engine model id, as a step call names the model
/// its durable seat bound (the seat's own id routes to the seat ladder,
/// which is not one picked model, so the exact call refuses it before any
/// send); it is admitted with `admit_seat_bound` and sent on the admitted
/// one-model ladder as an exact recorded call. It is buffered rather than
/// stream-preferring, so the two wire bodies differ only in `max_tokens`.
/// The refresh runs on a blocking thread, as the pump's pass runs it, since
/// it blocks on the runtime.
///
/// # Errors
///
/// None: every failure (no seat, a refused admission, no answer, a cold
/// prefix) is `None`, as [`PrefixRefresh::refresh`] reports it.
#[doc(hidden)]
pub async fn warm_then_refresh(
    vault: Arc<Vault>,
    runtime: Arc<ModelRuntime>,
) -> Option<ServedCacheHorizon> {
    warm_erase_then_refresh(vault, runtime, |_| {}).await
}

/// [`warm_then_refresh`] with `erase` run on the vault, on a blocking
/// thread, after the warm send answered and before the refresh; a panic in
/// it is the caller's. The refresh keeps the source erase generation read
/// before the warm request was built, as a run's hold reads it as the run
/// enters (review P1 of #8428).
///
/// # Errors
///
/// None, as [`warm_then_refresh`].
#[doc(hidden)]
pub async fn warm_erase_then_refresh(
    vault: Arc<Vault>,
    runtime: Arc<ModelRuntime>,
    erase: impl FnOnce(&Vault) + Send + 'static,
) -> Option<ServedCacheHorizon> {
    let erase_generation = vault.source_erase_generation();
    let seat = runtime.seat(crate::ai_host::CHAT_ROLE)?;
    let model = seat.rung_models().into_iter().next()?.0;
    let mut request = oneiron::LlmRequest {
        model,
        envelope: oneiron::CallEnvelope {
            seat_effort: None,
            scope: Default::default(),
            purpose: oneiron::CallPurpose::AnswerGen,
            class: oneiron::CallClass::BestEffort,
            tier: oneiron::TierPrecedence::for_purpose(
                &oneiron::CallPurpose::AnswerGen,
                oneiron::ModelTierRef("answer".into()),
            ),
            response_format: oneiron::ResponseFormat::Text,
            locality: seat.locality,
            host_keyless: false,
            host_paid: false,
        },
        messages: vec![oneiron::LlmMessage {
            role: oneiron::LlmMessageRole::User,
            content: vec![oneiron::ContentPart::Text {
                text: "the cached prefix under test".into(),
                signature: None,
            }],
        }],
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
        host_segments: None,
    };
    // The request marks its one block, at the default five-minute tier the
    // host reads when the request names no tier of its own.
    oneiron::code_run::main_prefix_boundary(&mut request).ok()?;
    let admitted = runtime
        .admit_seat_bound(&vault, crate::ai_host::CHAT_ROLE, request)
        .ok()?;
    let guard = BudgetGuard::new(
        "prefix-refresh-test",
        100_000,
        BudgetExhaustionPolicy::Suspend,
    );
    let run = runtime.funded_run("prefix-refresh-test", guard.clone(), None);
    let (_, binding) = admitted
        .ladder
        .generate_exact_recorded_while(&run, admitted.request, None, &|| true)
        .await
        .ok()?;
    let kept = KeptPrefix::new(binding.answering?, erase_generation);
    let erased = Arc::clone(&vault);
    tokio::task::spawn_blocking(move || erase(&erased))
        .await
        .unwrap_or_else(|error| std::panic::resume_unwind(error.into_panic()));
    let refresh = PrefixRefresh::new(
        vault,
        runtime,
        guard,
        Default::default(),
        tokio::runtime::Handle::current(),
    );
    tokio::task::spawn_blocking(move || refresh.refresh(None, &kept))
        .await
        .ok()
        .flatten()
}
