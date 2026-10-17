//! Named propose-only Dreamer runners over the existing foreign CLI sandbox.
use super::{ByoaConnectorSpec, ByoaError, ByoaResult, CliSandboxSpec};
use crate::{checkout::CheckoutId, code_sandbox::SandboxCredentialHandle};
use std::{collections::BTreeMap, sync::Arc};

#[derive(Debug, Clone)]
pub struct DreamerProviderInput {
    pub task: String,
    pub checkout_id: CheckoutId,
    pub egress_profile_ref: String,
    pub credential_handles: Vec<SandboxCredentialHandle>,
}
/// Produces only a connector. Execution returns exhaust through ByoaDispatcher;
/// no method carries a Vault, Gate permit, or write authority.
pub trait DreamerProviderAdapter: Send + Sync {
    fn name(&self) -> &'static str;
    fn connector(&self, input: DreamerProviderInput) -> ByoaResult<ByoaConnectorSpec>;
}
#[derive(Default)]
pub struct ProviderAdapterRegistry {
    adapters: BTreeMap<String, Arc<dyn DreamerProviderAdapter>>,
}
impl ProviderAdapterRegistry {
    pub fn register(&mut self, adapter: Arc<dyn DreamerProviderAdapter>) -> ByoaResult<()> {
        let name = adapter.name();
        if self.adapters.contains_key(name) {
            return Err(ByoaError::DuplicateProvider(name.into()));
        }
        self.adapters.insert(name.into(), adapter);
        Ok(())
    }
    pub fn resolve(&self, name: &str) -> ByoaResult<&dyn DreamerProviderAdapter> {
        self.adapters
            .get(name)
            .map(AsRef::as_ref)
            .ok_or_else(|| ByoaError::UnknownProvider(name.into()))
    }
    /// Whether a provider is registered under `name`.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.adapters.contains_key(name)
    }
    /// Every registered provider name, in name order.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.adapters.keys().map(String::as_str).collect()
    }
    pub fn standard() -> Self {
        let mut registry = Self::default();
        registry
            .adapters
            .insert("claude-code".into(), Arc::new(ClaudeCodeRunner));
        registry
            .adapters
            .insert("codex".into(), Arc::new(CodexRunner));
        registry
            .adapters
            .insert("opencode".into(), Arc::new(OpenCodeRunner));
        registry
    }
}
fn cli(program: &str, args: &[&str], input: DreamerProviderInput) -> ByoaResult<ByoaConnectorSpec> {
    let mut argv: Vec<String> = args.iter().map(|v| (*v).into()).collect();
    argv.push("--".into());
    argv.push(input.task);
    let connector = ByoaConnectorSpec::CliSandbox(CliSandboxSpec {
        program: program.into(),
        argv,
        checkout_id: input.checkout_id,
        egress_profile_ref: input.egress_profile_ref,
        credential_handles: input.credential_handles,
    });
    super::validate::validate_connector(&connector)?;
    Ok(connector)
}
/// The official Claude Code binary. Under the person's own sign-in it may run
/// on any runtime, their hosted vault VM included ([`super::login_placement`]).
pub const CLAUDE_CODE_PROGRAM: &str = "claude";
/// The official Codex CLI. A ChatGPT plan login runs only on the person's own
/// runtime.
pub const CODEX_PROGRAM: &str = "codex";
/// The OpenCode CLI.
pub const OPENCODE_PROGRAM: &str = "opencode";

pub struct ClaudeCodeRunner;
impl DreamerProviderAdapter for ClaudeCodeRunner {
    fn name(&self) -> &'static str {
        "claude-code"
    }
    fn connector(&self, input: DreamerProviderInput) -> ByoaResult<ByoaConnectorSpec> {
        cli(
            CLAUDE_CODE_PROGRAM,
            &["--print", "--output-format", "json"],
            input,
        )
    }
}
pub struct CodexRunner;
impl DreamerProviderAdapter for CodexRunner {
    fn name(&self) -> &'static str {
        "codex"
    }
    fn connector(&self, input: DreamerProviderInput) -> ByoaResult<ByoaConnectorSpec> {
        cli(CODEX_PROGRAM, &["exec", "--json"], input)
    }
}
pub struct OpenCodeRunner;
impl DreamerProviderAdapter for OpenCodeRunner {
    fn name(&self) -> &'static str {
        "opencode"
    }
    fn connector(&self, input: DreamerProviderInput) -> ByoaResult<ByoaConnectorSpec> {
        cli(OPENCODE_PROGRAM, &["run", "--format", "json"], input)
    }
}
