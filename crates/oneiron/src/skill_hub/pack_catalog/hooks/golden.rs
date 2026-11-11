//! A verb hook's golden inputs (ARCH-0080 §9): an optional `golden.json` in
//! its hook folder lists calls the hook takes, each with the outcome its body
//! returns on it. A hub pack's test runs them, since a verb hook its vault
//! never ran has no saved run to replay. Entry: [`parse_golden`].

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::super::invalid;
use super::{HookActorClass, HookOutcomeKind, HookPhase, HookSelector};
use crate::Result;
use crate::runtime_hooks::HookOutcome;

/// The golden-input file a verb hook's folder may carry.
pub(super) const HOOK_GOLDEN: &str = "golden.json";

/// One call a verb hook's test runs its body on, and the outcome expected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HookGoldenInput {
    /// The verb called: a row name, a SelfEffect label or a `host.*` verb.
    pub verb: String,
    /// The caller's class. Absent, the hook's first selected class, or
    /// `agent` for a hook that selects every class.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<HookActorClass>,
    /// The args the caller sends; `{}` when absent.
    #[serde(default = "no_args")]
    pub args: Value,
    /// The verb's result as its caller sees it: a post-hook's only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// The outcome the body returns on this call.
    pub expect: HookGoldenExpect,
}

/// The outcome a golden input expects: its kind, and for a Rewrite the args
/// it rewrites to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HookGoldenExpect {
    pub kind: HookOutcomeKind,
    /// A Rewrite's args, compared whole as JSON; no other kind names them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<Value>,
}

fn no_args() -> Value {
    Value::Object(serde_json::Map::new())
}

impl HookGoldenInput {
    /// The caller's class this call carries under `selector`.
    #[must_use]
    pub fn caller_class(&self, selector: &HookSelector) -> HookActorClass {
        self.class
            .or_else(|| selector.actors.first().copied())
            .unwrap_or(HookActorClass::Agent)
    }
}

impl HookGoldenExpect {
    /// Whether `outcome`, as the engine accepted it, is the one expected:
    /// the same kind, and for a Rewrite the same args. No outcome meets
    /// none.
    #[must_use]
    pub fn met_by(&self, outcome: Option<&HookOutcome>) -> bool {
        match outcome {
            Some(HookOutcome::Rewrite { args }) => {
                self.kind == HookOutcomeKind::Rewrite && self.args.as_ref() == Some(args)
            }
            Some(outcome) => outcome.kind() == self.kind,
            None => false,
        }
    }
}

/// The golden inputs `bytes` lists, a JSON array, for a hook of `selector`.
/// Only a verb hook carries them. Each names a class the hook selects, the
/// verb's result exactly when the hook is a post-hook, and an outcome kind
/// the hook returns, with args exactly when that is a Rewrite.
pub(super) fn parse_golden(bytes: &[u8], selector: &HookSelector) -> Result<Vec<HookGoldenInput>> {
    if selector.phase == HookPhase::Fact {
        return Err(invalid("only a verb hook carries golden.json"));
    }
    let golden: Vec<HookGoldenInput> = serde_json::from_slice(bytes)
        .map_err(|_| invalid("golden.json is a JSON array of golden inputs"))?;
    let post = selector.phase == HookPhase::Post;
    for input in &golden {
        if input.result.is_some() != post {
            return Err(invalid(
                "a post-hook's golden input carries the verb's result; a pre-hook's none",
            ));
        }
        if !selector.actors.is_empty() && !selector.actors.contains(&input.caller_class(selector)) {
            return Err(invalid("a golden input's class is one its hook selects"));
        }
        if !selector.outcomes.contains(&input.expect.kind) {
            return Err(invalid(
                "a golden input expects an outcome kind its hook returns",
            ));
        }
        if input.expect.args.is_some() != (input.expect.kind == HookOutcomeKind::Rewrite) {
            return Err(invalid(
                "a golden Rewrite names its args; no other outcome does",
            ));
        }
    }
    Ok(golden)
}
