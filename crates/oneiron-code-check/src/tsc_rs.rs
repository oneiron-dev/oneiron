//! tsc-rs in process: the pinned Wasm build of the checker
//! (`components/tsc-rs`), run on the engine's Wasmtime by the shared runner
//! (`wasm.rs`).

use crate::wasm::{self, Abi, Host, WasmCheck};
use crate::{
    BackendId, CheckFailure, CheckInput, CheckReport, CodeCheck, DEFAULT_OUTPUT_BYTES,
    DEFAULT_WALL_TIME,
};
use std::time::Duration;
use wasmtime::Linker;

const ARTIFACT: &[u8] = include_bytes!("../../../components/tsc-rs/artifacts/ts_rust.wasm");
const SHA256: &str = "0f384de62ca87bb609a6a5ce82fabc8b02ffa0f3f28519337c1d048c1cf056e7";
/// The tsc-rs commit the module is built from (`components/tsc-rs/build.py`).
pub const TSC_RS_COMMIT: &str = "80f9944aab296595c4c9aa4d9d1ad65d1e5f76f6";

/// The checker recurses deeply. Its own shadow stack sits in linear memory;
/// this bounds the native stack its frames take on the check's thread.
const MAX_WASM_STACK: usize = 32 << 20;

/// The ABI of `crates/ts_wasm`.
const ABI: Abi = Abi {
    name: "tsc-rs",
    host: "ts_host",
    input: "ts_input",
    run: "ts_run",
    initialize: false,
    max_wasm_stack: MAX_WASM_STACK,
    link_host,
};

/// Bounds of the in-process checkers.
#[derive(Debug, Clone, Copy)]
pub struct TscRsBudget {
    pub wall_time: Duration,
    pub memory_bytes: usize,
    pub output_bytes: usize,
    /// Checks that may run at once; another waits its turn, in arrival
    /// order, until its deadline.
    pub concurrent: usize,
}

impl Default for TscRsBudget {
    fn default() -> Self {
        Self {
            wall_time: DEFAULT_WALL_TIME,
            memory_bytes: 1 << 30,
            output_bytes: DEFAULT_OUTPUT_BYTES,
            concurrent: 2,
        }
    }
}

/// tsc-rs, compiled once, checking each program in a fresh instance.
pub struct TscRsWasm(WasmCheck);

impl TscRsWasm {
    /// Verifies the pinned module and compiles it. Compiling takes seconds:
    /// load once, off any async runtime, and share the checker.
    ///
    /// # Errors
    ///
    /// [`CheckFailure::Unavailable`] when the module fails its pin or does
    /// not compile and link.
    pub fn load(budget: TscRsBudget) -> Result<Self, CheckFailure> {
        WasmCheck::load(ABI, ARTIFACT, SHA256, budget).map(Self)
    }
}

impl CodeCheck for TscRsWasm {
    fn backend(&self) -> BackendId {
        BackendId {
            name: "tsc-rs",
            pin: format!("{TSC_RS_COMMIT}+sha256:{SHA256}"),
        }
    }

    fn check(&self, input: &CheckInput<'_>) -> Result<CheckReport, CheckFailure> {
        let (exited, peak) = self.0.check(input)?;
        exited.report(self.backend(), Some(peak))
    }
}

/// Links `ts_host`, the file system `crates/ts_wasm/src/host.rs` reads
/// (`components/tsc-rs/build.py --check` reads these registrations).
fn link_host(linker: &mut Linker<Host>) -> wasmtime::Result<()> {
    linker.func_wrap("ts_host", "fs", wasm::fs)?;
    linker.func_wrap("ts_host", "fs_take", wasm::fs_take)?;
    Ok(())
}
