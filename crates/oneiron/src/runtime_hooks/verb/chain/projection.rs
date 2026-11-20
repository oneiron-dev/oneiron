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
use crate::receipt::ReceiptKind;
use crate::runtime_hooks::read::grant_view::shows_row;
use crate::runtime_hooks::{HookGrant, filter, grant, store};
use crate::skill_hub::pack_catalog::PackHookBinding;
use crate::{EntityId, Error, Result};

use super::super::{VerbCallScope, VerbDomain, served};
use super::{Chain, phase_token, session};

/// The field a read result gives its narrowing receipt
/// ([`crate::claim::ScopedReadResult`]): the read's own metadata, no row's
/// content.
const NARROWING_FIELD: &str = "narrowing";

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
    scope: Option<&'i VerbCallScope>,
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
    /// Some of that content names no row this vault holds either
    /// ([`Unattributed::unnamed`]).
    pub(super) unnamed_content: bool,
}

/// What a hook's input showed of content whose rows no host names.
#[derive(Default)]
struct Unattributed {
    /// It showed some.
    shown: bool,
    /// Some of it names no row this vault holds either: a host verb's free
    /// text, a pack item whose refs did not resolve, or a read result with a
    /// value outside a row object that names its held rows
    /// ([`Chain::result_rows`]). Nothing tells which rows a body could copy
    /// from it into its receipt, so no screened reader reads that receipt
    /// (VERB-HOOK-RECEIPT-UNNAMED-SOURCE-PROVENANCE).
    unnamed: bool,
}

impl Unattributed {
    /// It showed content that names no row.
    fn show_unnamed(&mut self) {
        self.shown = true;
        self.unnamed = true;
    }
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
        let mut unattributed = Unattributed::default();
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
            scope: self.call.scope.as_ref(),
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
            unattributed: unattributed.shown,
            unnamed_content: unattributed.unnamed,
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
        let shown =
            self.project_result(result, &seen, &mut Vec::new(), &mut Unattributed::default())?;
        Ok(served::admits(&binding.selector.served, &shown))
    }

    /// The caller's args as the hook sees them: the caller's own, whole; a
    /// host verb's free text withheld from a hook narrower than its caller.
    fn project_args(
        &self,
        args: &Value,
        seen: &HookView<'_>,
        unattributed: &mut Unattributed,
    ) -> Value {
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
    /// read's result names no rows, so it is withheld whole. Rows are named
    /// from the result its producer gave ([`Chain::origin`]): a Redact that
    /// took a row's own ref leaves the content it drew from that row
    /// (review round 2 of #9643).
    fn project_result(
        &self,
        result: &Value,
        seen: &HookView<'_>,
        dependencies: &mut Vec<EntityId>,
        unattributed: &mut Unattributed,
    ) -> Result<Value> {
        let narrows = seen.narrows();
        let origin = self.origin.as_ref().unwrap_or(result);
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
            unattributed.shown = true;
            let mut rows = Vec::new();
            if self.result_rows(&shown, origin, &mut rows)? {
                dependencies.extend(rows);
            } else {
                unattributed.show_unnamed();
            }
            return Ok(shown);
        }
        // Each item the producer gave, by its place: a Redact nulls an item
        // in place or takes `items` whole, and the rendering still carries
        // what it hid.
        let mut every = true;
        let given = origin.get("items").and_then(Value::as_array);
        let mut items = shown.get_mut("items").and_then(Value::as_array_mut);
        for at in 0..given.map_or(0, Vec::len) {
            let rows = given
                .and_then(|given| given.get(at))
                .and_then(|item| self.item_rows(item));
            if !narrows || seen.shows_all(rows.as_deref())? {
                match rows {
                    Some(rows) => dependencies.extend(rows),
                    None => unattributed.show_unnamed(),
                }
            } else {
                if let Some(item) = items.as_mut().and_then(|items| items.get_mut(at)) {
                    *item = withheld();
                }
                every = false;
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

    /// Whether every value in a read's `result` lies in a row object, as a
    /// read's row views name their own row (a claim view's `claim_ref`); the
    /// rows they name go to `rows` (review round 1 of #9643). A row object
    /// is an object whose `id`, `*_id` or `*_ref` fields hold the 32-hex id
    /// of a row this vault holds; its whole value counts as those rows'. Any
    /// other string, number or boolean names no row: a count, a bare list of
    /// names, an id-shaped string alone. A `narrowing` field is the read's
    /// own receipt ([`crate::claim::ScopedReadResult`]). Each object's rows
    /// are read at its place in `origin`, the result its producer gave,
    /// which a Redact only narrowed (review round 2 of #9643); a place
    /// `origin` lacks names no row.
    fn result_rows(
        &self,
        result: &Value,
        origin: &Value,
        rows: &mut Vec<EntityId>,
    ) -> Result<bool> {
        let rtxn = self.vault.store.env.read_txn()?;
        self.rows_in(&rtxn, result, origin, rows)
    }

    /// [`Self::result_rows`] for `value`, whose producer gave `origin` at its
    /// place, read in `rtxn`.
    fn rows_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        value: &Value,
        origin: &Value,
        rows: &mut Vec<EntityId>,
    ) -> Result<bool> {
        match value {
            Value::Null => Ok(true),
            Value::Bool(_) | Value::Number(_) | Value::String(_) => Ok(false),
            Value::Array(items) => {
                let Some(given) = origin.as_array().filter(|given| given.len() == items.len())
                else {
                    return Ok(false);
                };
                for (item, origin) in items.iter().zip(given) {
                    if !self.rows_in(rtxn, item, origin, rows)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            Value::Object(fields) => {
                let Some(given) = origin.as_object() else {
                    return Ok(false);
                };
                let mut held = Vec::new();
                let named = given
                    .iter()
                    .filter(|(key, _)| is_row_ref_key(key))
                    .filter_map(|(_, field)| field.as_str())
                    .filter(|text| text.len() == 32)
                    .filter_map(|text| EntityId::from_hex(text).ok());
                for id in named {
                    if self.vault.entity_header_in_txn(rtxn, &id)?.is_some() {
                        held.push(id);
                    }
                }
                if !held.is_empty() {
                    rows.extend(held);
                    return Ok(true);
                }
                for (key, field) in fields {
                    if key == NARROWING_FIELD {
                        continue;
                    }
                    let Some(origin) = given.get(key) else {
                        return Ok(false);
                    };
                    if !self.rows_in(rtxn, field, origin, rows)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
        }
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

    /// The receipts the caller's tail holds, as the hook sees them: a room
    /// Hook receipt only while every one of its source rows is shown (FIX
    /// 5429); a Hook receipt of base's family as [`Self::tail_hook_receipt`]
    /// reads it, only while every row it names is shown, so no hook copies a
    /// note the receipt screen withholds into a receipt of its own (reviews
    /// of #9643); a receipt about a claim only while that claim is shown,
    /// read under the caller's own key; one about no claim as it is.
    fn project_tail(&self, seen: &HookView<'_>, dependencies: &mut Vec<EntityId>) -> Result<Value> {
        let mut tail = self.tail.clone();
        if let Some(receipts) = tail.as_array_mut() {
            for receipt in receipts {
                if let Some(sources) = self.room_receipt_sources(receipt) {
                    if !seen.shows_all(Some(sources))? {
                        *receipt = withheld();
                        continue;
                    }
                    dependencies.extend_from_slice(sources);
                } else if receipt.get("kind").and_then(Value::as_str)
                    == Some(ReceiptKind::Hook.as_str())
                {
                    match self.tail_hook_receipt(receipt)? {
                        Some((stored, rows)) if seen.shows_all(Some(rows.as_slice()))? => {
                            dependencies.extend(rows);
                            *receipt = stored;
                        }
                        _ => {
                            *receipt = withheld();
                            continue;
                        }
                    }
                }
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

    /// A Hook receipt of base's family as the tail shows it, with every row
    /// it names (its binding and CODE, and the rows its run stood on): read
    /// again from its store with those rows in one snapshot, so a payload an
    /// erase scrubbed after the tail was read never shows without the rows
    /// it drew on ([`store::hook_receipt_with_rows`]). `None` when those rows
    /// are unknown, it names no kept run, or it is a verb hook's receipt of
    /// another actor's call, as the receipt screen keeps one to the actor
    /// that made the call (review round 2 of #9643).
    fn tail_hook_receipt(&self, receipt: &Value) -> Result<Option<(Value, Vec<EntityId>)>> {
        let Some(run) = receipt.pointer("/fields/run_key").and_then(Value::as_str) else {
            return Ok(None);
        };
        let Some((stored, Some(rows))) = store::hook_receipt_with_rows(self.vault, run)? else {
            return Ok(None);
        };
        let caller = self.call.actor.to_hex();
        if crate::receipt::is_verb_hook_receipt(&stored)
            && stored.on_behalf_of.as_deref() != Some(caller.as_str())
        {
            return Ok(None);
        }
        let shown = serde_json::to_value(crate::memory::Memory::tail_receipt(stored))
            .map_err(|_| Error::InvariantViolation("hook tail receipt encode"))?;
        Ok(Some((shown, rows)))
    }

    /// The source rows of `receipt` when it is one of the room's own Hook
    /// receipts; `None` for a receipt of base's family.
    fn room_receipt_sources(&self, receipt: &Value) -> Option<&[EntityId]> {
        let reference = receipt.get("receipt_ref").and_then(Value::as_str)?;
        self.room_sources
            .iter()
            .find(|(room_ref, _)| room_ref == reference)
            .map(|(_, sources)| sources.as_slice())
    }

    /// This host verb's free text in `value`: withheld in place from a hook
    /// narrower than its caller; else shown, as content no host names rows
    /// for.
    fn host_text(&self, value: &mut Value, seen: &HookView<'_>, unattributed: &mut Unattributed) {
        for (verb, path) in HOST_FREE_TEXT {
            if self.call.verb != verb {
                continue;
            }
            if seen.narrows() {
                withhold_at(value, path);
            } else {
                unattributed.show_unnamed();
            }
        }
    }
}

/// A Rewrite written over args some of whose values were withheld from its
/// hook, merged into the caller's `original` args (FIX 10084): a value the
/// hook left withheld keeps the caller's original; every value it wrote
/// stands. The merged args are then checked whole, as any Rewrite is.
pub(crate) fn merge_withheld(original: &Value, rewritten: Value) -> Value {
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

/// Whether a read result's field `key` names a row by its id, as a row view
/// names its own: `id`, `*_id` or `*_ref` ([`Chain::result_rows`]).
fn is_row_ref_key(key: &str) -> bool {
    key == "id" || key.ends_with("_id") || key.ends_with("_ref")
}
