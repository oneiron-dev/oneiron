//! Door for `tests/handed_on_person_sweep.rs` (L2 sweep handle-build Red 2 + Guard 4):
//! dispatch one `SelfCall` as a code run's opener.

use crate::EntityId;
use crate::Vault;
use crate::WriteActor;
use crate::code_run::{ExecutorCallSite, HostSelfDispatcher, SelfCall, SelfDispatchOutcome};
use crate::error::Result;

/// Dispatches `call` as a code run opened by `actor` (no opener credential
/// binding, no proof).
///
/// # Errors
///
/// Dispatch errors.
pub fn dispatch_self_call_for_test(
    vault: &Vault,
    actor: WriteActor,
    call: SelfCall,
) -> Result<SelfDispatchOutcome> {
    let dispatcher = HostSelfDispatcher::new(vault, actor, "red-run")?;
    let site = ExecutorCallSite {
        run_id: EntityId::now(),
        seq: 0,
        step_start: 0,
        earlier: &[],
        reply_publisher: None,
    };
    dispatcher
        .dispatch_for_executor_run(site, call)
        .map(|(outcome, _)| outcome)
}
