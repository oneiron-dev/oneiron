//! `ai.verdict` for a generative fact hook (FIX 10068, 10075): the same
//! ladder and the same clock as any caller's verdict, with two things the
//! host binds from the hook's binding, never from its request. Its evidence
//! reaches the ladder only as the hook's current grant shows it, judged on
//! the very views its reader hydrated ([`evidence_views`]). Every model rung
//! it reaches admits and settles its own calls once on the hook's pack
//! line, the line the host resolved for the binding; the calls it settled
//! come back beside the verdict, a refused verdict's included, as
//! references nothing settles again. Nothing here caps, suspends or
//! refuses spend (rule 5), and the hook's deadline never shortens the ask.

use std::cell::RefCell;

use oneiron::llm::run_admission::{RunEvent, capture_settlements};
use oneiron::memory::{EntityView, Memory, MemoryResult};
use oneiron::runtime_hooks::{
    HookGrant, HookSettledCallRef, HookVerdictContext, hook_evidence_views,
};
use oneiron::task_verb::sdk::{AiVerdict, AiVerdictRequest};
use oneiron::{BudgetGuard, EntityId};

use super::{VERDICT_SPEND_CHECK_UNITS, answer_verdict, on_caller_meter, on_caller_payer};
use crate::server::SyncServer;

thread_local! {
    /// The grant the hook verdict on this thread shows its evidence under.
    static HOOK_GRANT: RefCell<Option<HookGrant>> = const { RefCell::new(None) };
}

/// Asks `request` through the host's ladder for the hook `context` names:
/// its evidence read by `reader`, the grant's reader, and shown only as the
/// grant shows it; every rung spending on `line`, the hook's pack line,
/// with no payer but the vault owner, as a hook's verdict always billed.
/// The caller's spend check counts this verdict's own spend on the line.
/// Beside the verdict, each call its rungs settled, in settlement order.
/// Blocks: call it on a blocking thread.
pub(crate) fn run_hook_verdict(
    server: &SyncServer,
    context: &HookVerdictContext,
    line: &BudgetGuard,
    reader: &Memory<'_>,
    request: &AiVerdictRequest,
    evidence_read: &mut Vec<EntityId>,
) -> (MemoryResult<AiVerdict>, Vec<HookSettledCallRef>) {
    let vault = server.vault();
    let principal = context.grant.reader;
    let class = context.reader_class();
    let before = line.read().used_units;
    let (answered, settled) = capture_settlements(|| {
        on_hook_grant(&context.grant, || {
            on_caller_meter(line, || {
                on_caller_payer(None, || {
                    answer_verdict(
                        server,
                        principal,
                        class,
                        reader,
                        None,
                        None,
                        request,
                        evidence_read,
                    )
                })
            })
        })
    });
    // The line is shared by the pack's verdicts: this one's spend is what
    // the line gained while it ran.
    let spent = line.read().used_units.saturating_sub(before);
    let now = vault.now_recorded_at();
    if let Some((window, tally)) = server
        .decision_host()
        .verdict_spend()
        .add(principal, spent, now)
    {
        tracing::warn!(
            caller = %principal.to_hex(),
            spent = tally,
            threshold = VERDICT_SPEND_CHECK_UNITS,
            pack = %context.pack,
            "a caller's ai.verdict spend crossed its check; is everything okay?"
        );
        if let Err(error) = crate::wire_health::raise_verdict_spend(
            vault,
            principal,
            tally,
            VERDICT_SPEND_CHECK_UNITS,
            window,
            now,
        ) {
            tracing::warn!(%error, "the ai.verdict spend check was not kept");
        }
    }
    let calls = settled
        .into_iter()
        .filter_map(|receipt| match receipt.event {
            RunEvent::Settled { lease, .. } => Some(HookSettledCallRef {
                instance: receipt.instance,
                lease,
            }),
            _ => None,
        })
        .collect();
    (answered, calls)
}

/// The evidence views a verdict's ladder reads: every ref hydrated by
/// `reader`, as for any caller; inside a hook's verdict, only those its
/// grant shows, judged on these same views (FIX 10068). A view the grant
/// does not show is named in the host's log by its id, never passed on.
pub(super) fn evidence_views(
    reader: &Memory<'_>,
    evidence: &[String],
) -> MemoryResult<Vec<EntityView>> {
    if evidence.is_empty() {
        return Ok(Vec::new());
    }
    let views = reader.hydrate(evidence)?.value;
    let Some(grant) = HOOK_GRANT.with(|slot| slot.borrow().clone()) else {
        return Ok(views);
    };
    let (shown, withheld) = hook_evidence_views(reader, &grant, views)?;
    if !withheld.is_empty() {
        let withheld: Vec<String> = withheld.iter().map(EntityId::to_hex).collect();
        tracing::debug!(
            ?withheld,
            "a hook verdict's evidence its grant does not show was withheld"
        );
    }
    Ok(shown)
}

/// Runs `call` with this thread's hook verdict showing its evidence under
/// `grant`, and puts back what was there before, panic or not.
fn on_hook_grant<T>(grant: &HookGrant, call: impl FnOnce() -> T) -> T {
    struct Restore(Option<HookGrant>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let previous = self.0.take();
            HOOK_GRANT.with(|slot| *slot.borrow_mut() = previous);
        }
    }
    let _restore = Restore(HOOK_GRANT.with(|slot| slot.replace(Some(grant.clone()))));
    call()
}
