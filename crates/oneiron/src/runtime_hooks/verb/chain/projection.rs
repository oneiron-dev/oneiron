//! A verb hook's input, built for each hook under what both its caller and
//! its current grant may read (FIX 10084): the caller's lane (its key, room
//! and destination), the grant reader's lane where that reader is someone
//! else, and the grant's predicates and worlds. The call's public metadata
//! and the caller's own args always reach the hook. Row-backed content
//! reaches it only when every row behind it is shown through all three; what
//! is not, and content whose rows no host names, reads as [`WITHHELD`] in
//! place, so every path in the input is the path of the same value in the
//! caller's own args and result. The caller's args and result themselves are
//! never changed here.

use serde::Serialize;
use serde_json::{Value, json};

use crate::claim::{PointRead, ScopedRead};
use crate::runtime_hooks::read::grant_view::shows_row;
use crate::runtime_hooks::{HookGrant, filter, grant};
use crate::skill_hub::pack_catalog::PackHookBinding;
use crate::{EntityId, Error, Result};

use super::super::{VerbDomain, served};
use super::{Chain, phase_token, session};

/// What a value withheld from a hook's input reads as there (CALLS, FIX
/// 10084): an object naming why, in the place the value had, so paths stay
/// the caller's own.
pub(super) const WITHHELD: &str = "withheld_by_hook_grant";

/// The host verbs' free text, whose rows no host names (CALLS, FIX 10084):
/// a compaction window's turn text and a generated turn's text. A hook
/// whose view is narrower than its caller's reads each as withheld; every
/// other field of a host verb is the host's own metadata.
const HOST_FREE_TEXT: [(&str, &[&str]); 2] = [
    ("host.compact", &["window", "*", "content"]),
    ("host.turn.generate", &["text"]),
];

/// What one hook may see of its call: the caller's lane, the grant reader's
/// lane as a cap when that reader is someone else (`Some(None)` when its
/// key did not build), and the grant.
pub(super) struct HookView<'a> {
    pub(super) lane: Option<&'a ScopedRead<'a>>,
    pub(super) cap: Option<Option<&'a ScopedRead<'a>>>,
    pub(super) grant: &'a HookGrant,
}

impl HookView<'_> {
    /// Whether the hook may see less than its caller: its grant reads as
    /// someone else or names predicates or worlds, or the caller has no
    /// lane to read through.
    fn narrows(&self) -> bool {
        self.lane.is_none()
            || self.cap.is_some()
            || !self.grant.predicates.is_empty()
            || !self.grant.worlds.is_empty()
    }

    /// Whether the row `id` is shown through the caller's lane, the cap and
    /// the grant.
    fn shows(&self, id: EntityId) -> Result<bool> {
        let Some(lane) = self.lane else {
            return Ok(false);
        };
        let reads = [PointRead::id(id)];
        let Some(row) = lane.read(&reads, None)?.value.into_iter().next().flatten() else {
            return Ok(false);
        };
        match self.cap {
            None => {}
            Some(None) => return Ok(false),
            Some(Some(cap)) => {
                if cap
                    .read(&reads, None)?
                    .value
                    .into_iter()
                    .next()
                    .flatten()
                    .is_none()
                {
                    return Ok(false);
                }
            }
        }
        shows_row(self.grant, &row)
    }

    /// Whether every row of `rows` is shown; `None` (a ref that did not
    /// resolve) shows nothing.
    fn shows_all(&self, rows: Option<&[EntityId]>) -> Result<bool> {
        let Some(rows) = rows else {
            return Ok(false);
        };
        for id in rows {
            if !self.shows(*id)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// A verb hook's `input`.
#[derive(Serialize)]
struct Input<'i> {
    hook: Value,
    verb: &'i str,
    phase: &'static str,
    invocation: String,
    actor: String,
    class: &'static str,
    scope: Option<&'i str>,
    args: &'i Value,
    board_epoch: Option<u64>,
    receipt_tail: &'i Value,
    /// Unix milliseconds from the vault clock at dispatch.
    now: u64,
    /// The caller's view of the verb's result so far; post only.
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<&'i Value>,
    /// The rows that view serves, when it is a pack, as the hook's served
    /// filter takes them; post only.
    #[serde(skip_serializing_if = "Option::is_none")]
    served: Option<Vec<served::ServedRow<'i>>>,
}

/// One hook's input, as JSON, and the rows whose content it shows.
pub(super) struct ProjectedInput {
    pub(super) json: String,
    pub(super) dependencies: Vec<EntityId>,
    /// It also shows content whose rows no host names: a hook that saw what
    /// its caller did saw it whole.
    pub(super) unattributed: bool,
}

impl Chain<'_> {
    /// The input of `binding`'s run over `args` (and, post, `result`), as
    /// `seen` shows them.
    pub(super) fn input(
        &self,
        id: EntityId,
        binding: &PackHookBinding,
        args: &Value,
        result: Option<&Value>,
        seen: &HookView<'_>,
    ) -> Result<ProjectedInput> {
        let mut dependencies = Vec::new();
        let mut unattributed = false;
        let args = self.project_args(args, seen, &mut unattributed);
        let result = match result {
            Some(result) => {
                Some(self.project_result(result, seen, &mut dependencies, &mut unattributed)?)
            }
            None => None,
        };
        let tail = self.project_tail(seen, &mut dependencies)?;
        let input = Input {
            hook: json!({
                "binding": id.to_hex(),
                "code": binding.code.to_hex(),
                "pack": binding.pack,
                "name": binding.hook,
                "version": binding.hook_version,
                "body_hash": binding.body_hash,
                "blocking": binding.selector.blocking,
            }),
            verb: &self.call.verb,
            phase: phase_token(self.phase),
            invocation: self.call.invocation.to_hex(),
            actor: self.call.actor.to_hex(),
            class: filter::class_token(self.call.class),
            scope: self.call.scope.as_deref(),
            args: &args,
            board_epoch: self.call.board_epoch,
            receipt_tail: &tail,
            now: self.now,
            result: result.as_ref(),
            served: result
                .as_ref()
                .and_then(|view| served::rows(view, &binding.selector.served)),
        };
        let json = serde_json::to_string(&input)
            .map_err(|_| Error::InvariantViolation("hook input encode"))?;
        Ok(ProjectedInput {
            json,
            dependencies,
            unattributed,
        })
    }

    /// Whether the post-hook `binding` (id `id`) runs on `result`: a hook
    /// with no served filter always does; one with a filter when a row it
    /// serves matches among those the hook is shown, after its grant, never
    /// before (FIX 10084).
    pub(super) fn served_for(
        &self,
        id: EntityId,
        binding: &PackHookBinding,
        result: &Value,
    ) -> Result<bool> {
        if binding.selector.served.is_empty() {
            return Ok(true);
        }
        let grant = session::hook_read(
            self.storage,
            "grant",
            grant::effective_grant(self.vault, id, binding),
        )?;
        let room = self.view()?;
        let (lane, cap) = self.lanes(&grant, room.as_ref());
        let seen = HookView {
            lane: lane.as_ref(),
            cap: cap.as_ref().map(Option::as_ref),
            grant: &grant,
        };
        let shown = self.project_result(result, &seen, &mut Vec::new(), &mut false)?;
        Ok(served::admits(&binding.selector.served, &shown))
    }

    /// The caller's args as the hook sees them: the caller's own, whole; a
    /// host verb's free text withheld from a hook narrower than its caller.
    fn project_args(&self, args: &Value, seen: &HookView<'_>, unattributed: &mut bool) -> Value {
        let mut args = args.clone();
        self.host_text(&mut args, seen, unattributed);
        args
    }

    /// Whether a Rewrite from a hook that saw `seen` was written over args
    /// with values withheld from it.
    pub(super) fn args_withheld(&self, seen: &HookView<'_>) -> bool {
        seen.narrows() && self.call.verb.starts_with("host.")
    }

    /// The result as the hook sees it. To a hook that sees what its caller
    /// does, the caller's view whole. Otherwise: a write's result is the
    /// caller's own; a host verb's is its metadata, its free text withheld;
    /// a read's pack keeps each item whose rows are all shown and withholds
    /// the rest, its rendering too unless every item is shown; any other
    /// read's result names no rows, so it is withheld whole.
    fn project_result(
        &self,
        result: &Value,
        seen: &HookView<'_>,
        dependencies: &mut Vec<EntityId>,
        unattributed: &mut bool,
    ) -> Result<Value> {
        let narrows = seen.narrows();
        let mut shown = result.clone();
        if self.call.verb.starts_with("host.") {
            self.host_text(&mut shown, seen, unattributed);
            return Ok(shown);
        }
        if self.call.domain == VerbDomain::Write {
            return Ok(shown);
        }
        if shown.get("pack_version").is_none() {
            if narrows {
                return Ok(withheld());
            }
            *unattributed = true;
            return Ok(shown);
        }
        let mut every = true;
        if let Some(items) = shown.get_mut("items").and_then(Value::as_array_mut) {
            for item in items {
                let rows = self.item_rows(item);
                if !narrows || seen.shows_all(rows.as_deref())? {
                    match rows {
                        Some(rows) => dependencies.extend(rows),
                        None => *unattributed = true,
                    }
                } else {
                    *item = withheld();
                    every = false;
                }
            }
        }
        if !every
            && let Some(rendered) = shown.get_mut("rendered")
            && !rendered.is_null()
        {
            *rendered = withheld();
        }
        Ok(shown)
    }

    /// The rows a pack item's content comes from: its own and each message
    /// it quotes; `None` when one of their refs does not resolve.
    fn item_rows(&self, item: &Value) -> Option<Vec<EntityId>> {
        let resolve = |reference: &Value| {
            reference
                .as_str()
                .and_then(|reference| crate::memory::resolve_entity_ref(self.vault, reference).ok())
        };
        let mut rows = vec![resolve(item.get("short_id")?)?];
        if let Some(cited) = item.get("cited_messages").and_then(Value::as_array) {
            for message in cited {
                rows.push(resolve(message.get("short_id")?)?);
            }
        }
        Some(rows)
    }

    /// The receipts the caller's tail holds, as the hook sees them: a
    /// receipt about a claim only while that claim is shown, read under the
    /// caller's own key; one about no claim as it is.
    fn project_tail(&self, seen: &HookView<'_>, dependencies: &mut Vec<EntityId>) -> Result<Value> {
        let mut tail = self.tail.clone();
        if let Some(receipts) = tail.as_array_mut() {
            for receipt in receipts {
                let Some(claim) = receipt.get("claim_ref").and_then(Value::as_str) else {
                    continue;
                };
                match EntityId::from_hex(claim) {
                    Ok(id) if seen.shows(id)? => dependencies.push(id),
                    _ => *receipt = withheld(),
                }
            }
        }
        Ok(tail)
    }

    /// This host verb's free text in `value`: withheld in place from a hook
    /// narrower than its caller; else shown, as content no host names rows
    /// for.
    fn host_text(&self, value: &mut Value, seen: &HookView<'_>, unattributed: &mut bool) {
        for (verb, path) in HOST_FREE_TEXT {
            if self.call.verb != verb {
                continue;
            }
            if seen.narrows() {
                withhold_at(value, path);
            } else {
                *unattributed = true;
            }
        }
    }
}

/// A Rewrite written over args some of whose values were withheld from its
/// hook, merged into the caller's `original` args (FIX 10084): a value the
/// hook left withheld keeps the caller's original; every value it wrote
/// stands. The merged args are then checked whole, as any Rewrite is.
pub(super) fn merge_withheld(original: &Value, rewritten: Value) -> Value {
    if is_withheld(&rewritten) {
        return original.clone();
    }
    match (original, rewritten) {
        (Value::Object(kept), Value::Object(mut written)) => {
            for (name, value) in &mut written {
                if let Some(before) = kept.get(name) {
                    *value = merge_withheld(before, std::mem::take(value));
                }
            }
            Value::Object(written)
        }
        (Value::Array(kept), Value::Array(mut written)) => {
            for (before, value) in kept.iter().zip(&mut written) {
                *value = merge_withheld(before, std::mem::take(value));
            }
            Value::Array(written)
        }
        (_, rewritten) => rewritten,
    }
}

fn withheld() -> Value {
    json!({ "withheld": WITHHELD })
}

fn is_withheld(value: &Value) -> bool {
    value.as_object().is_some_and(|fields| {
        fields.len() == 1 && fields.get("withheld").and_then(Value::as_str) == Some(WITHHELD)
    })
}

/// Replaces what `path` names in `node` with the withheld marker; `*` takes
/// every child. A path that names nothing changes nothing.
fn withhold_at(node: &mut Value, path: &[&str]) {
    let [segment, rest @ ..] = path else {
        *node = withheld();
        return;
    };
    let every = *segment == "*";
    match node {
        Value::Object(fields) if every => {
            for child in fields.values_mut() {
                withhold_at(child, rest);
            }
        }
        Value::Object(fields) => {
            if let Some(child) = fields.get_mut(*segment) {
                withhold_at(child, rest);
            }
        }
        Value::Array(items) if every => {
            for child in items {
                withhold_at(child, rest);
            }
        }
        Value::Array(items) => {
            if let Some(child) = segment
                .parse::<usize>()
                .ok()
                .and_then(|at| items.get_mut(at))
            {
                withhold_at(child, rest);
            }
        }
        _ => {}
    }
}
