//! What the health check reads: each kind of kept crossing past its cursor,
//! as one subject's crossing, and how a crossing folds into its subject's
//! check.
use std::collections::{BTreeMap, BTreeSet};

use oneiron::blob_artifact::esign::EsignRateCheck;
use oneiron::scan_check::ScanCheck;
use oneiron::{EntityId, Error, Result, Vault};
use serde_json::{Value, json};

use super::{CHECK, CheckState, CrossingSource, HealthCheck, decode, encode};
use crate::server::SyncServer;
use crate::wire_telemetry::{WireLimitQuestion, WireQuestion, WireThresholds, WireWindowReceipt};

/// How far the check has read the kept call-volume questions: the key of
/// the last one, in the order they were kept (FIX 9531).
const CURSOR_WIRE: &str = "wire:health:v1:cursor:wire";
/// How far it has read one `[limits]` row's questions.
const CURSOR_LIMIT: &str = "wire:health:v1:cursor:limit:";
/// How far it has read the e-sign ceremony's burst checks.
const CURSOR_ESIGN: &str = "wire:health:v1:cursor:esign";
/// Most actors or verbs one crossing's state names, busiest first.
const MAX_NAMED: usize = 16;

/// A kept crossing the check has not read yet.
pub(super) struct Crossing {
    subject: String,
    source: CrossingSource,
    raised_at: u64,
    summary: Value,
    /// The cursor to move once it is folded in.
    read: Option<(String, String)>,
}

fn cursor(vault: &Vault, key: &str) -> Result<Option<String>> {
    vault
        .sync_state_get(key)?
        .map(|bytes| {
            String::from_utf8(bytes).map_err(|_| Error::CorruptedIndex("wire health cursor"))
        })
        .transpose()
}

fn named(counts: &BTreeMap<String, u64>, over: u64) -> Vec<(String, u64)> {
    let mut named: Vec<(String, u64)> = counts
        .iter()
        .filter(|(_, calls)| **calls > over)
        .map(|(name, calls)| (name.clone(), *calls))
        .collect();
    named.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    named.truncate(MAX_NAMED);
    named
}

/// `names` with their calls in `counts`, busiest first: the most a state
/// names of them.
fn named_of(counts: &BTreeMap<String, u64>, names: &BTreeSet<String>) -> Vec<(String, u64)> {
    let counts: BTreeMap<String, u64> = names
        .iter()
        .map(|name| (name.clone(), counts.get(name).copied().unwrap_or(0)))
        .collect();
    named(&counts, 0)
}

/// The wire subject: everyone and everything past its row in the question,
/// every one of them. A later actor or verb makes a new subject, so a check
/// of its own, and an asked check never takes in facts it was not asked
/// about (FIX 9531). Each name is length-prefixed under its kind.
fn wire_subject(question: &WireQuestion) -> String {
    let mut hasher = blake3::Hasher::new();
    for (kind, names) in [
        (b'a', &question.crossed.actors),
        (b'v', &question.crossed.verbs),
    ] {
        for name in names {
            hasher.update(&[kind]);
            hasher.update(&(name.len() as u64).to_le_bytes());
            hasher.update(name.as_bytes());
        }
    }
    format!("wire:{}", &hasher.finalize().to_hex()[..32])
}

fn wire_crossing(key: String, question: &WireQuestion, thresholds: &WireThresholds) -> Crossing {
    let window = &question.evidence;
    let actors = named_of(&window.by_actor, &question.crossed.actors);
    let verbs = named_of(&window.by_verb, &question.crossed.verbs);
    Crossing {
        subject: wire_subject(question),
        source: CrossingSource::Wire,
        raised_at: window.started_at,
        summary: json!({
            "window": [window.started_at, window.ended_at],
            "seq": question.seq,
            "per_verb": thresholds.per_verb,
            "per_actor": thresholds.per_actor,
            "calls": window.by_actor.values().fold(0u64, |sum, calls| sum.saturating_add(*calls)),
            "verbs": verbs.iter().map(|(verb, calls)| json!({"verb": verb, "calls": calls})).collect::<Vec<_>>(),
            "actors": actors.iter().map(|(actor, calls)| json!({"actor": actor, "calls": calls})).collect::<Vec<_>>(),
            // Every actor and verb past its row, beyond the busiest named
            // above: what the grant rule judges (FIX 9531).
            "crossed": {
                "actors": question.crossed.actors,
                "verbs": question.crossed.verbs,
            },
            // Which tools the named callers called and who called each named
            // tool; MCP envelopes and their errors with no caller ride beside
            // the calls, never counted as any caller's (FIX 1085).
            "actor_tools": actor_tools(window, &actors),
            "tool_callers": tool_callers(window, &verbs),
            "mcp_envelopes": window.mcp_envelopes,
            "mcp_errors": window.mcp_errors,
        }),
        read: Some((CURSOR_WIRE.to_owned(), key)),
    }
}

/// The tools each named caller called, most first.
fn actor_tools(window: &WireWindowReceipt, actors: &[(String, u64)]) -> Vec<Value> {
    actors
        .iter()
        .filter_map(|(actor, _)| {
            let tools = named(window.by_actor_tool.get(actor)?, 0);
            let tools: Vec<Value> = tools
                .iter()
                .map(|(tool, calls)| json!({"tool": tool, "calls": calls}))
                .collect();
            Some(json!({"actor": actor, "tools": tools}))
        })
        .collect()
}

/// The callers of each named verb that is an MCP tool, most first.
fn tool_callers(window: &WireWindowReceipt, verbs: &[(String, u64)]) -> Vec<Value> {
    verbs
        .iter()
        .filter_map(|(verb, _)| {
            let callers: BTreeMap<String, u64> = window
                .by_actor_tool
                .iter()
                .filter_map(|(actor, tools)| Some((actor.clone(), *tools.get(verb)?)))
                .collect();
            let callers: Vec<Value> = named(&callers, 0)
                .iter()
                .map(|(actor, calls)| json!({"actor": actor, "calls": calls}))
                .collect();
            (!callers.is_empty()).then(|| json!({"tool": verb, "callers": callers}))
        })
        .collect()
}

fn limit_crossing(key: String, question: &WireLimitQuestion) -> Crossing {
    Crossing {
        subject: format!("limit:{}", question.row),
        source: CrossingSource::Limit,
        raised_at: question.raised_at,
        summary: json!({
            "row": question.row,
            "bound": question.bound,
            "observed": question.observed,
            "crossings": question.crossings,
        }),
        read: Some((format!("{CURSOR_LIMIT}{}", question.row), key)),
    }
}

fn scan_crossing(check: &ScanCheck) -> Crossing {
    let scope = check.scope.as_deref().unwrap_or("vault");
    Crossing {
        subject: format!("scan:{}:{scope}", check.scan),
        source: CrossingSource::Scan,
        raised_at: check.raised_at,
        summary: json!({
            "scan": check.scan,
            "scope": check.scope,
            "threshold": check.threshold,
            "rows": check.rows,
        }),
        read: None,
    }
}

fn esign_crossing(key: String, check: &EsignRateCheck) -> Crossing {
    if let Some(row) = &check.limit {
        return esign_limit_crossing(key, check, row);
    }
    let receipt = &check.receipt;
    let scope = receipt.recipient.as_deref().unwrap_or("all");
    Crossing {
        subject: format!("esign:{}:{scope}", receipt.document),
        source: CrossingSource::Esign,
        raised_at: receipt.window_started_at_secs,
        summary: json!({
            "kind": EsignRateCheck::KIND,
            "document": receipt.document,
            "recipient": receipt.recipient,
            "window_started_at": receipt.window_started_at_secs,
            "calls": receipt.count,
            "threshold": check.threshold,
        }),
        read: Some((CURSOR_ESIGN.to_owned(), key)),
    }
}

/// A signature upload past one of its `[limits]` rows (FIX 3807): its own
/// subject per document, recipient and row, so it is asked apart from the
/// recipient's ceremony burst, and an e-sign source, so its ask goes first to
/// the document's sender.
fn esign_limit_crossing(key: String, check: &EsignRateCheck, row: &str) -> Crossing {
    let receipt = &check.receipt;
    let scope = receipt.recipient.as_deref().unwrap_or("all");
    Crossing {
        subject: format!("esign:{}:{scope}:{row}", receipt.document),
        source: CrossingSource::Esign,
        raised_at: receipt.window_started_at_secs,
        summary: json!({
            "kind": EsignRateCheck::LIMIT_KIND,
            "document": receipt.document,
            "recipient": receipt.recipient,
            "window_started_at": receipt.window_started_at_secs,
            "row": row,
            "bound": check.threshold,
            "observed": receipt.count,
        }),
        read: Some((CURSOR_ESIGN.to_owned(), key)),
    }
}

/// A caller's `ai.verdict` spend past its window's check (FIX 1123, Engine
/// ruling 10-18), kept now as a held check the next sweep asks: "is
/// everything okay". It names its caller apart from the grant rule's
/// `actors`, so a known caller is not cleared by its grant alone. A check,
/// never a cap: every verdict it counts has answered.
pub(crate) fn raise_verdict_spend(
    vault: &Vault,
    caller: EntityId,
    spent_units: u64,
    threshold: u64,
    window_started_at: u64,
    raised_at: u64,
) -> Result<()> {
    fold(
        vault,
        Crossing {
            subject: format!("spend:ai.verdict:{}", caller.to_hex()),
            source: CrossingSource::Spend,
            raised_at,
            summary: json!({
                "kind": "ai.verdict.spend",
                "caller": caller.to_hex(),
                "spent_units": spent_units,
                "threshold": threshold,
                "window_started_at": window_started_at,
            }),
            read: None,
        },
    )
}

/// The kept crossings past each cursor. A scan check is sticky, so one with
/// a check of its own is read.
pub(super) fn unread(server: &SyncServer) -> Result<Vec<Crossing>> {
    let vault = server.vault();
    let telemetry = &server.wire_telemetry;
    let thresholds = telemetry.thresholds()?;
    let mut unread = Vec::new();
    let wire_after = cursor(vault, CURSOR_WIRE)?;
    for (key, question) in telemetry.kept_questions()? {
        if wire_after.as_ref().is_none_or(|after| key > *after) {
            unread.push(wire_crossing(key, &question, &thresholds));
        }
    }
    for (key, question) in telemetry.kept_limit_questions()? {
        // The connection pool's check is its live pressure check (FIX 7656),
        // not a second ask on the ladder.
        if question.row == crate::wire_telemetry::LimitRow::Connections.key() {
            continue;
        }
        let after = cursor(vault, &format!("{CURSOR_LIMIT}{}", question.row))?;
        if after.is_none_or(|after| key > after) {
            unread.push(limit_crossing(key, &question));
        }
    }
    let esign_after = cursor(vault, CURSOR_ESIGN)?;
    for (key, check) in vault.esign_rate_checks_after(esign_after.as_deref())? {
        unread.push(esign_crossing(key, &check));
    }
    for check in vault.scan_checks()? {
        let crossing = scan_crossing(&check);
        if vault
            .sync_state_get(&format!("{CHECK}{}", crossing.subject))?
            .is_none()
        {
            unread.push(crossing);
        }
    }
    Ok(unread)
}

/// Folds one crossing into its subject's check: an open check, or an answered
/// one that still covers it, counts it; otherwise it is a new held check. The
/// check and the cursor past the crossing are kept in one write, so a crossing
/// is never counted twice nor skipped.
pub(super) fn fold(vault: &Vault, crossing: Crossing) -> Result<()> {
    let key = format!("{CHECK}{}", crossing.subject);
    vault.with_write_txn_grouped(|txn| {
        let existing: Option<HealthCheck> = vault
            .sync_state_get_in_write_txn(txn, &key)?
            .map(|b| decode(&b))
            .transpose()?;
        let check = match existing {
            Some(mut check) if check.open() || check.covers(crossing.raised_at) => {
                check.crossings = check.crossings.saturating_add(1);
                check.last_raised = check.last_raised.max(crossing.raised_at);
                check
            }
            _ => HealthCheck {
                subject: crossing.subject,
                source: crossing.source,
                crossing: crossing.summary,
                first_raised: crossing.raised_at,
                last_raised: crossing.raised_at,
                crossings: 1,
                state: CheckState::Held,
                asked_in: None,
            },
        };
        vault.sync_state_put_in_write_txn(txn, &key, &encode(&check)?)?;
        if let Some((cursor, read)) = crossing.read {
            vault.sync_state_put_in_write_txn(txn, &cursor, read.as_bytes())?;
        }
        Ok(())
    })
}
