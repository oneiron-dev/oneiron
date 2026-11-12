//! FIX AGENT-RUN-START-LATENCY-4S: a QuickJS runtime handle reuses its
//! factory's compiled component.
//!
//! Every agent run, `execute_code` call and reader child takes its guest from
//! `QuickJsRuntimeFactory::runtime()`. Before the fix each call built a new
//! Wasmtime Engine and ran a full Cranelift compile of the 1.1 MB first-party
//! component, so every run paid that compile before its first model call.
//! The factory compiles once, at its readiness probe, and each handle is a
//! fresh one on that compiled code: its own Store per step, no capability or
//! adapter of another handle's.
//!
//! The bound is relative, so it holds on any host: four handles must take
//! less than half of what building the factory took (one compile plus the
//! probe step). Before the fix four handles were four compiles.
//!
//! `cargo test --locked -p oneiron-agent-runtime --all-features --test quickjs_factory_compiles_once`
#![cfg(feature = "code-sandbox-wasmtime")]

#[path = "wait_park/fixture.rs"]
mod fixture;

use std::time::Instant;

use fixture::first_party_factory;
use oneiron::code_run::{CodeRunDeterminism, SelfCall};
use oneiron::code_sandbox::{SandboxBoundaryContract, SandboxGuestTier};
use oneiron::engine_executor::{
    JsCodeModeHost, JsCodeModeRuntime, JsCodeModeStep, SelfDispatchResponse,
};
use oneiron::{EntityId, Error, Result};

/// A host for a step that makes no host call.
struct NoCallHost;

impl JsCodeModeHost for NoCallHost {
    fn dispatch_self(&mut self, _: SelfCall) -> Result<SelfDispatchResponse> {
        Err(Error::InvalidConfig("this guest makes no host call".into()))
    }
}

/// Runs one step that computes `factor * 7` and returns its observation.
fn seven_times(runtime: &mut dyn JsCodeModeRuntime, factor: u8) -> String {
    let script = format!("finish(JSON.stringify({factor} * 7));");
    let outcome = runtime
        .run_step(
            JsCodeModeStep {
                run_id: EntityId::from_bytes([factor; 16]).expect("run id"),
                seq: 0,
                script: &script,
                boundary: SandboxBoundaryContract::for_tier(SandboxGuestTier::FirstPartyDreamer),
                determinism: CodeRunDeterminism::new(1_700_000_000_000, [factor; 32]),
            },
            &mut NoCallHost,
        )
        .expect("the guest's step runs");
    assert!(outcome.done, "the guest finished: {}", outcome.observation);
    outcome.observation
}

#[test]
fn factory_handles_reuse_the_one_compiled_component() {
    let started = Instant::now();
    let factory = first_party_factory();
    let built = started.elapsed();

    let started = Instant::now();
    let handles = (0..4)
        .map(|_| factory.runtime().expect("a runtime handle"))
        .collect::<Vec<_>>();
    let four_handles = started.elapsed();
    println!("factory built in {built:?}; four runtime handles in {four_handles:?}");
    assert!(
        four_handles.saturating_mul(2) < built,
        "four runtime handles took {four_handles:?}, against {built:?} to build the factory \
         (one compile and its probe): each handle compiled the component again"
    );

    // Each handle still runs its own steps, and two handles on the shared
    // compiled code run at once on their own threads.
    let observations = std::thread::scope(|scope| {
        let workers = handles
            .into_iter()
            .zip(2_u8..)
            .map(|(mut handle, factor)| {
                scope.spawn(move || (factor, seven_times(&mut handle, factor)))
            })
            .collect::<Vec<_>>();
        workers
            .into_iter()
            .map(|worker| worker.join().expect("the step's thread ends"))
            .collect::<Vec<_>>()
    });
    for (factor, observation) in observations {
        assert_eq!(observation, (u32::from(factor) * 7).to_string());
    }
}
