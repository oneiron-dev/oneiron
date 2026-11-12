//! The contract text a regenerated hook body is written against (ARCH-0080
//! §8, FIX 4688): the hook world, and the declarations of the verbs a verb
//! hook's selector names with the request and answer types they use, cut
//! from the code-mode declarations the contract stamp hashes. A regenerator
//! reads the contract itself, never only its hash.

use std::collections::{BTreeSet, VecDeque};

use crate::skill_hub::pack_catalog::{HookPhase, HookSelector};

use super::super::filter::glob_match;

/// The code-mode declarations a hook body's verb shapes come from: the verb
/// table half of [`super::HookContractStamp`].
pub(super) const VERB_TABLE: &str = include_str!(concat!(env!("OUT_DIR"), "/code-mode.d.ts"));
/// The hook world: the sandbox half of [`super::HookContractStamp`].
pub(super) const HOOK_WORLD: &str = include_str!("../../../wit/hook/hook.wit");

/// The most declaration text one regen hands its regenerator; the cut stops
/// at a whole line before it.
pub const MAX_HOOK_CONTRACT_DECLARATIONS: usize = 64 * 1024;

/// The contract one regen hands its regenerator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookContractText {
    /// The hook world (`hook.wit`), whole.
    pub world: String,
    /// Each verb the selector names, as `// <verb>` over its declaration,
    /// then the declarations of the types those verbs use, cut from the
    /// code-mode declarations. Empty for a fact hook, which selects
    /// predicates, not verbs.
    pub verbs: String,
    /// Whether the cut stopped at [`MAX_HOOK_CONTRACT_DECLARATIONS`].
    pub truncated: bool,
}

impl HookContractText {
    /// This engine's contract for a hook selected by `selector`.
    #[must_use]
    pub fn for_selector(selector: &HookSelector) -> Self {
        let (verbs, truncated) = if matches!(selector.phase, HookPhase::Fact) {
            (String::new(), false)
        } else {
            verb_declarations(&selector.verbs)
        };
        Self {
            world: HOOK_WORLD.to_owned(),
            verbs,
            truncated,
        }
    }
}

/// A line's leading identifier: `name` of `name: {`, `name(`, `declare const
/// name:`, `declare namespace name {`, `declare function name(` or a
/// namespace member's `const name:`.
fn leading_name(line: &str) -> Option<&str> {
    let line = line
        .strip_prefix("declare const ")
        .or_else(|| line.strip_prefix("declare namespace "))
        .or_else(|| line.strip_prefix("declare function "))
        .or_else(|| line.strip_prefix("const "))
        .unwrap_or(line);
    let end = line
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(line.len());
    (end > 0).then(|| &line[..end])
}

/// The identifiers in `text` that start with an uppercase letter: the type
/// names a declaration may use.
fn type_names(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|word| word.starts_with(|c: char| c.is_ascii_uppercase()))
}

/// The declarations of every verb a glob in `globs` names, then the types
/// they use, to [`MAX_HOOK_CONTRACT_DECLARATIONS`].
fn verb_declarations(globs: &[String]) -> (String, bool) {
    let mut types: std::collections::BTreeMap<&str, &str> = std::collections::BTreeMap::new();
    let mut methods: Vec<(String, Option<&str>, &str)> = Vec::new();
    let mut path: Vec<&str> = Vec::new();
    let mut doc: Option<&str> = None;
    let mut in_types = false;
    for raw in VERB_TABLE.lines() {
        let line = raw.trim();
        if raw.starts_with("declare namespace Sdk") {
            in_types = true;
            continue;
        }
        if in_types {
            if raw.starts_with('}') {
                in_types = false;
            } else if let Some(rest) = line.strip_prefix("type ")
                && let Some(name) = leading_name(rest)
            {
                types.insert(name, line);
            }
            continue;
        }
        if line.starts_with("/**") && line.ends_with("*/") {
            doc = Some(line);
            continue;
        }
        if line.starts_with('}') {
            path.pop();
            doc = None;
            continue;
        }
        let Some(name) = leading_name(line) else {
            doc = None;
            continue;
        };
        // A verb is a method `name(`, a callable `const name: (...) =>`, or
        // a callable namespace `const name: ((...) => ...) & {`, whose
        // members follow it.
        let callable = if line.ends_with('{') {
            line.contains("=>")
        } else {
            line.contains('(') && line.ends_with(';')
        };
        if callable {
            let verb = path
                .iter()
                .copied()
                .chain(std::iter::once(name))
                .collect::<Vec<_>>()
                .join(".");
            if globs.iter().any(|glob| glob_match(glob, &verb)) {
                methods.push((verb, doc, line));
            }
        }
        if line.ends_with('{') {
            path.push(name);
        }
        doc = None;
    }
    let mut out = String::new();
    let mut truncated = false;
    let mut push = |out: &mut String, text: &str| {
        if out.len() + text.len() + 1 > MAX_HOOK_CONTRACT_DECLARATIONS {
            truncated = true;
            return false;
        }
        out.push_str(text);
        out.push('\n');
        true
    };
    let mut queue: VecDeque<&str> = VecDeque::new();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for (verb, doc, line) in &methods {
        let block = match doc {
            Some(doc) => format!("// {verb}\n{doc}\n{line}"),
            None => format!("// {verb}\n{line}"),
        };
        if !push(&mut out, &block) {
            break;
        }
        for name in type_names(line) {
            if types.contains_key(name) && seen.insert(name) {
                queue.push_back(name);
            }
        }
    }
    while let Some(name) = queue.pop_front() {
        let Some(line) = types.get(name).copied() else {
            continue;
        };
        if !push(&mut out, line) {
            break;
        }
        for used in type_names(line) {
            if types.contains_key(used) && seen.insert(used) {
                queue.push_back(used);
            }
        }
    }
    (out, truncated)
}
