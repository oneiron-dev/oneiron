//! Hash-pinned, readiness-checked QuickJS artifact factory.
//!
//! The deployer supplies a component built by `components/code-run-quickjs/build.py`
//! and its SHA-256 from the reviewed manifest. No source runs in a native JS engine.

use super::wasmtime_runtime::{ComponentBudget, WasmtimeComponentRuntime};
use super::{SandboxBoundaryContract, SandboxGuestTier};
use crate::code_run::{CodeRunDeterminism, SelfCall};
use crate::engine_executor::{
    JsCodeModeHost, JsCodeModeRuntime, JsCodeModeStep, SelfDispatchResponse,
};
use crate::{EntityId, Error, Result};
use sha2::{Digest, Sha256};

/// Pinned interpreter bytes. Each handle owns its Engine and epoch counter.
pub struct QuickJsRuntimeFactory {
    bytes: Box<[u8]>,
    budget: ComponentBudget,
    sha256: [u8; 32],
}

impl QuickJsRuntimeFactory {
    /// Verify the host pin, compile the real binary component and run a plain-JS
    /// readiness probe through its typed export before advertising execution.
    pub fn from_component(bytes: &[u8], sha256: [u8; 32], budget: ComponentBudget) -> Result<Self> {
        if !bytes.starts_with(b"\0asm\x0d\0\x01\0")
            || <[u8; 32]>::from(Sha256::digest(bytes)) != sha256
        {
            return Err(Error::InvalidConfig(
                "QuickJS component SHA-256/header mismatch".into(),
            ));
        }
        let mut template = WasmtimeComponentRuntime::from_component(
            bytes,
            *blake3::hash(bytes).as_bytes(),
            budget,
        )?;
        let mut host = ProbeHost;
        let result = template.run_step(JsCodeModeStep {
            run_id: EntityId::from_bytes([1; 16])?, seq: 0,
            script: "const xs = [1,2,3].map(x => x * 7); finish(JSON.stringify({sum:xs.reduce((a,b)=>a+b,0), now:Date.now(), clean:typeof process === 'undefined' && typeof fetch === 'undefined', typed:typeof self !== 'undefined' && ['search','put_claim','supersede_claim','put_edge'].every(k => typeof self.memory[k] === 'function') && ['ask_human','askHuman','speak','think','express'].every(k => typeof self[k] === 'function') && typeof sandbox.fs.read_file === 'function' && typeof sandbox.credential.call === 'function' && typeof oneiron.clock.now_unix_ms === 'function' && typeof oneiron.random.bytes === 'function'}));",
            boundary: SandboxBoundaryContract::for_tier(SandboxGuestTier::FirstPartyDreamer),
            determinism: CodeRunDeterminism::new(1_700_000_000_000, [7; 32]),
        }, &mut host)?;
        if !result.done
            || result.observation != r#"{"sum":42,"now":1700000000000,"clean":true,"typed":true}"#
            || !result.outputs.is_empty()
        {
            return Err(Error::InvalidConfig(
                "QuickJS component readiness probe failed".into(),
            ));
        }
        Ok(Self {
            bytes: bytes.into(),
            budget,
            sha256,
        })
    }

    /// A fresh runtime handle. Every step allocates its own Wasmtime Store.
    pub fn runtime(&self) -> Result<WasmtimeComponentRuntime> {
        WasmtimeComponentRuntime::from_component(
            &self.bytes,
            *blake3::hash(&self.bytes).as_bytes(),
            self.budget,
        )
    }

    /// Reviewed deployer pin; useful for run configuration identity.
    #[must_use]
    pub const fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
}

struct ProbeHost;
impl JsCodeModeHost for ProbeHost {
    fn dispatch_self(&mut self, _: SelfCall) -> Result<SelfDispatchResponse> {
        Err(Error::InvalidConfig(
            "readiness probe cannot dispatch effects".into(),
        ))
    }
}

#[cfg(test)]
mod tests;
