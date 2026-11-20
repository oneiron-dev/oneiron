//! The refs a scan's answers name, and the reads that follow them
//! ([CANARY-SCAN-COVERAGE] step 2): a list, search, feed, room, inbox or
//! receipt answer names rows by ref, and a leak can sit in a row only a
//! named ref reaches. Every answer is walked for refs as it is read; once
//! the scan's own surfaces are read, each ref is followed through the doors
//! of its form, and the refs those answers name in turn, until none is new.

use std::collections::BTreeSet;

use serde_json::{Value, json};

use super::{Canary, Reader};

/// Refs one scan follows before it reports the walk incomplete: far above
/// the rows a seeded fixture holds.
const MAX_FOLLOWED: usize = 4096;

/// The registry kind `vault.get` names a claim by.
const KIND_CLAIM: &str = "CLAIM";
/// The registry kind `vault.get` names a turn by.
const KIND_TURN: &str = "TURN";
/// The registry kind `vault.get` names a summary by.
const KIND_SUMMARY: &str = "SUMMARY";

/// One ref an answer named, by the form that says which door reads it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum NamedRef {
    /// A 32-hex entity id: `vault.get`, `vault.refs.resolve` and its kind's
    /// doors.
    Entity(String),
    /// A `call:<32 hex>` receipt handle: `vault.receipts.get`.
    CallReceipt(String),
    /// An `emit:<32 hex>` context receipt handle: `vault.receipts.context`.
    ContextReceipt(String),
    /// A report issue, named under `issue_ref`: `vault.reports.outbound`.
    ReportIssue(String),
    /// A summary proposal, named under `proposal_ref`:
    /// `vault.summaries.proposals.read`.
    SummaryProposal(String),
}

impl NamedRef {
    /// The ref `text` is, if any, as the field `key` names it.
    fn parse(key: Option<&str>, text: &str) -> Option<Self> {
        match key {
            Some("issue_ref") if is_entity_hex(text) => {
                return Some(Self::ReportIssue(text.to_owned()));
            }
            Some("proposal_ref") if !text.is_empty() => {
                return Some(Self::SummaryProposal(text.to_owned()));
            }
            _ => {}
        }
        if is_entity_hex(text) {
            return Some(Self::Entity(text.to_owned()));
        }
        if text.strip_prefix("call:").is_some_and(is_entity_hex) {
            return Some(Self::CallReceipt(text.to_owned()));
        }
        if text.strip_prefix("emit:").is_some_and(is_entity_hex) {
            return Some(Self::ContextReceipt(text.to_owned()));
        }
        None
    }
}

/// The refs one scan has met: those still to follow, in the order first
/// named, and every one ever queued, so none is followed twice.
#[derive(Debug, Default)]
pub(super) struct NamedRefs {
    pending: Vec<NamedRef>,
    known: BTreeSet<NamedRef>,
}

impl Reader<'_, '_> {
    /// Queues every ref `answer` names that this scan has not met yet.
    pub(super) fn discover(&mut self, answer: &Value) {
        let mut found = Vec::new();
        named_refs(answer, None, &mut found);
        for named in found {
            if self.refs.known.insert(named.clone()) {
                self.refs.pending.push(named);
            }
        }
    }

    /// Reads each seeded ref (a short ref) through every door an entity ref
    /// opens, whatever its kind, since a reader may hold a ref to a row it
    /// may not read; then each class's refs in one `vault.hydrate`.
    pub(super) fn read_seeded_refs(&mut self, canaries: &[Canary]) {
        for canary in canaries {
            for reference in &canary.refs {
                self.read_entity(reference, true);
            }
            if !canary.refs.is_empty() {
                self.read(
                    &format!("vault.hydrate ({})", canary.class),
                    "vault.hydrate",
                    json!({"refs": canary.refs}),
                );
            }
        }
    }

    /// Follows every queued ref, and each ref those answers name in turn,
    /// until none is left; past [`MAX_FOLLOWED`] the walk is reported
    /// incomplete.
    pub(super) fn follow_named_refs(&mut self) {
        let mut followed = 0_usize;
        while !self.refs.pending.is_empty() {
            for named in std::mem::take(&mut self.refs.pending) {
                if followed == MAX_FOLLOWED {
                    self.scan
                        .incomplete
                        .push(format!("named refs: more than {MAX_FOLLOWED} followed"));
                    return;
                }
                followed += 1;
                self.follow(&named);
            }
        }
    }

    fn follow(&mut self, named: &NamedRef) {
        let (verb, field, reference) = match named {
            NamedRef::Entity(id) => {
                self.read_entity(id, false);
                return;
            }
            NamedRef::CallReceipt(handle) => ("vault.receipts.get", "receipt_ref", handle),
            NamedRef::ContextReceipt(handle) => ("vault.receipts.context", "receipt_ref", handle),
            NamedRef::ReportIssue(issue) => ("vault.reports.outbound", "issue_ref", issue),
            NamedRef::SummaryProposal(proposal) => {
                ("vault.summaries.proposals.read", "proposal_ref", proposal)
            }
        };
        let mut input = serde_json::Map::new();
        input.insert(field.to_owned(), Value::String(reference.clone()));
        self.read(&format!("{verb} {reference}"), verb, Value::Object(input));
    }

    /// Reads one entity by `reference` (a short ref or 32 hex) through
    /// `vault.get` and `vault.refs.resolve`, then through the doors of its
    /// kind: a claim's `vault.claims.read_filtered` and
    /// `vault.claims.history`, a turn's `vault.refs.links` pages, a
    /// summary's `vault.summaries.read`. With `every_kind`, each kind's doors
    /// run whatever the row is (a wrong kind is refused and recorded);
    /// otherwise only the kind `vault.get` names, and a row it withholds
    /// gets no further read.
    fn read_entity(&mut self, reference: &str, every_kind: bool) {
        let got = self.read(
            &format!("vault.get {reference}"),
            "vault.get",
            json!({"entity_ref": reference}),
        );
        let kind = got
            .as_ref()
            .and_then(|answer| answer.pointer("/value/kind"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        if kind.is_none() && !every_kind {
            return;
        }
        self.read(
            &format!("vault.refs.resolve {reference}"),
            "vault.refs.resolve",
            json!({"reference": reference}),
        );
        let is = |wanted: &str| every_kind || kind.as_deref() == Some(wanted);
        if is(KIND_CLAIM) {
            self.read(
                &format!("vault.claims.read_filtered {reference}"),
                "vault.claims.read_filtered",
                json!({"claim_ref": reference}),
            );
            self.read(
                &format!("vault.claims.history {reference}"),
                "vault.claims.history",
                json!({"claim_ref": reference}),
            );
        }
        if is(KIND_TURN) {
            self.walk_cursor(
                &format!("vault.refs.links {reference}"),
                "vault.refs.links",
                json!({"turn_ref": reference}),
            );
        }
        if is(KIND_SUMMARY) {
            self.read(
                &format!("vault.summaries.read {reference}"),
                "vault.summaries.read",
                json!({"summary_ref": reference}),
            );
        }
    }
}

/// Every ref `value` names, with the field each string sits under (an array
/// keeps its field's name).
fn named_refs(value: &Value, key: Option<&str>, out: &mut Vec<NamedRef>) {
    match value {
        Value::String(text) => out.extend(NamedRef::parse(key, text)),
        Value::Array(items) => {
            for item in items {
                named_refs(item, key, out);
            }
        }
        Value::Object(fields) => {
            for (name, item) in fields {
                named_refs(item, Some(name.as_str()), out);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// Whether `text` is an entity id as every answer writes one: 32 lower-case
/// hex.
fn is_entity_hex(text: &str) -> bool {
    text.len() == 32
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
