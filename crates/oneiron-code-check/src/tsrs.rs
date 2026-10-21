//! tsrs in process: the pinned Wasm build of oxc's Rust port of TypeScript 7
//! (`@tsrs/wasm`, vendored in `vendor/tsrs` by `scripts/vendor-tsrs.py`),
//! run on the engine's Wasmtime by the shared runner (`wasm.rs`).
//!
//! The module takes the request tsc-rs takes (`crates/tsrs_wasm/src/lib.rs`):
//! the working directory, the flags and tsc's arguments, NUL-separated, with
//! text diagnostics on stdout. It reads its files through `tsrs_host`, with
//! TypeScript's standard libraries built in, and no environment.

use crate::wasm::{self, Abi, Host, WasmCheck};
use crate::{BackendId, CheckFailure, CheckInput, CheckReport, CodeCheck, TscRsBudget};
use wasmtime::Linker;

const ARTIFACT: &[u8] = include_bytes!("../vendor/tsrs/tsrs.wasm");
const SHA256: &str = "bb070f1416dccc5956d177f527b81534a86032efd4d94898dfc20aae1a5c4d18";
/// The `@tsrs/wasm` release the module is (`vendor/tsrs/manifest.json`).
pub const TSRS_VERSION: &str = "0.18.0-ts7.1.0-dev.20260929";
/// The tsrs commit the release is built from: tag v0.18.0, as its npm
/// provenance names it.
pub const TSRS_COMMIT: &str = "5f92808bc92bb97b06212153ab73d28d551c0b9b";

/// The module keeps an 80 MiB shadow stack in its linear memory, and its
/// frames take native stack beside it. This bounds that native stack as
/// deep as the shadow stack, as tsc-rs's bound matches its own.
const MAX_WASM_STACK: usize = 80 << 20;

/// The ABI of `crates/tsrs_wasm`. The module exports no `_initialize`.
const ABI: Abi = Abi {
    name: "tsrs",
    host: "tsrs_host",
    input: "tsrs_input",
    run: "tsrs_run",
    initialize: false,
    max_wasm_stack: MAX_WASM_STACK,
    link_host,
};

/// tsrs, compiled once, checking each program in a fresh instance under the
/// bounds tsc-rs checks under.
pub struct TsrsWasm(WasmCheck);

impl TsrsWasm {
    /// Verifies the pinned module and compiles it. Compiling takes seconds:
    /// load once, off any async runtime, and share the checker.
    ///
    /// # Errors
    ///
    /// [`CheckFailure::Unavailable`] when the module fails its pin, imports a
    /// call no host serves, or does not compile and link.
    pub fn load(budget: TscRsBudget) -> Result<Self, CheckFailure> {
        WasmCheck::load(ABI, ARTIFACT, SHA256, budget).map(Self)
    }
}

impl CodeCheck for TsrsWasm {
    fn backend(&self) -> BackendId {
        BackendId {
            name: "tsrs",
            pin: format!("{TSRS_VERSION}+{TSRS_COMMIT}+sha256:{SHA256}"),
        }
    }

    fn check(&self, input: &CheckInput<'_>) -> Result<CheckReport, CheckFailure> {
        let (exited, peak) = self.0.check(input)?;
        exited.report(self.backend(), Some(peak))
    }
}

/// Links `tsrs_host`, the file system `crates/tsrs_wasm/src/host.rs` reads
/// (`scripts/vendor-tsrs.py --check` reads these registrations). The host
/// never stages an error text: a failed operation is "not found".
fn link_host(linker: &mut Linker<Host>) -> wasmtime::Result<()> {
    linker.func_wrap("tsrs_host", "fs", wasm::fs)?;
    linker.func_wrap("tsrs_host", "fs_take", wasm::fs_take)?;
    Ok(())
}
