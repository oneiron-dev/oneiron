//! Compiling approved preferences into acting revisions (OF-379): every manual
//! edit is a critique of the generator.
//!
//! The miner turns repeated human deltas into Proposed preference claims:
//! bans and style rules from explicit compilation targets, phrasing swaps from
//! amendments, affirmations from untouched approvals, charter lines and brief
//! preferences. Once the decider approves them they are in force, but a claim
//! changes nothing the generator reads. This module compiles one principal's
//! in-force, approved preferences about one generator into a concrete revision
//! of what that generator acts on: its charter, or the brief its work was
//! written to. The revision is a proposal. The responsible role answers it,
//! starting at the principal whose preferences it compiles and ending at the
//! vault owner; an accepted revision is the published, cited text the
//! charter's or brief's owner applies. Nothing here edits a charter, a brief
//! or a skill, and no answer widens a Grant. The owner's apply door marks
//! the revision Applied in the transaction that writes its text, so a re-run
//! never applies it twice.
//!
//! Per-principal scoping and decay come from the read boundary
//! ([`super::miner::mined_preferences_for_principal`]): a preference outside
//! its principal or past its evidence window never compiles.

use std::collections::BTreeMap;

use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimSubject};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};
use crate::write_envelope::WriteActor;

use super::miner::{PREDICATE_PREFERENCE_PHRASING, mined_preferences_for_principal};

/// Acting revisions. Key: the revision id (64 lower-case hex).
const ACTING_REVISION: SideTable<String, ActingRevision, Named> =
    SideTable::new(&side_table::EDIT_DISTANCE_ACTING_REVISION);

/// Longest single compiled line, in bytes.
const MAX_LINE_BYTES: usize = 512;

/// Longest decline reason kept.
const MAX_REASON_BYTES: usize = 1024;

/// What a revision changes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ActingTarget {
    /// The generating actor's standing instructions.
    Charter { actor: EntityId },
    /// The brief the generator's reviewed work was written to, named by the
    /// review scope.
    Brief { actor: EntityId, scope: String },
}

/// The kind of one compiled line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledLineKind {
    Ban,
    StyleRule,
    Phrasing,
    Affirmed,
    CharterLine,
    BriefPreference,
}

impl CompiledLineKind {
    fn from_predicate(predicate: &str) -> Option<Self> {
        Some(match predicate {
            "preference.ban" => Self::Ban,
            "preference.style_rule" => Self::StyleRule,
            "preference.affirmed" => Self::Affirmed,
            "charter.line" => Self::CharterLine,
            "brief.preference" => Self::BriefPreference,
            p if p == PREDICATE_PREFERENCE_PHRASING => Self::Phrasing,
            _ => return None,
        })
    }

    const fn heading(self) -> &'static str {
        match self {
            Self::Ban => "Never",
            Self::StyleRule => "Style",
            Self::Phrasing => "Wording",
            Self::Affirmed => "Keep doing",
            Self::CharterLine => "Charter",
            Self::BriefPreference => "Brief",
        }
    }
}

/// One compiled line and the approved preference claim it came from.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CompiledLine {
    pub kind: CompiledLineKind,
    pub text: String,
    pub claim: EntityId,
}

/// Where a revision stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RevisionStatus {
    /// Waiting for the responsible role.
    Pending,
    /// Accepted by `by`: the published revision its target's owner applies.
    Accepted { by: EntityId, at: u64 },
    /// Declined by `by`, with the reason as written.
    Declined {
        by: EntityId,
        at: u64,
        reason: String,
    },
    /// Replaced, before an answer, by a newer compilation.
    Superseded { by_revision: String, at: u64 },
    /// Accepted, then applied by `by` at `at`: `version` of its target is
    /// the first that carries its text.
    Applied {
        accepted_by: EntityId,
        accepted_at: u64,
        by: EntityId,
        at: u64,
        version: String,
    },
}

/// One compiled acting revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActingRevision {
    pub id: String,
    /// Whose preferences it compiles.
    pub principal: EntityId,
    pub target: ActingTarget,
    pub lines: Vec<CompiledLine>,
    /// The revision text the target gains.
    pub text: String,
    /// Who may answer, in escalation order: the principal first, the vault
    /// owner role last.
    pub responsible: Vec<EntityId>,
    pub status: RevisionStatus,
    pub at: u64,
}

/// The responsible role's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevisionDecision {
    Accept,
    Decline { reason: String },
}

fn value_text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    let Value::Map(entries) = value else {
        return None;
    };
    entries
        .iter()
        .find(|(k, _)| k.as_str() == Some(key))
        .and_then(|(_, v)| v.as_str())
}

fn bounded_line(text: &str) -> String {
    let text = text.trim().replace(['\n', '\r'], " ");
    if text.len() <= MAX_LINE_BYTES {
        return text;
    }
    let mut end = MAX_LINE_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

/// The line one approved preference compiles to, if it carries one.
fn compiled_line(kind: CompiledLineKind, body: &ClaimBody) -> Option<String> {
    let line = match kind {
        CompiledLineKind::Phrasing => {
            let from = value_text(&body.value, "from")?;
            let to = value_text(&body.value, "to")?;
            format!("Say \u{201c}{to}\u{201d} rather than \u{201c}{from}\u{201d}.")
        }
        CompiledLineKind::Affirmed => {
            let predicate = value_text(&body.value, "reviewed_predicate").unwrap_or("output");
            let Value::Map(entries) = &body.value else {
                return None;
            };
            let reviewed = entries
                .iter()
                .find(|(k, _)| k.as_str() == Some("reviewed_value"))
                .map(|(_, v)| match v {
                    Value::String(s) => s.as_str().unwrap_or_default().to_owned(),
                    other => other.to_string(),
                })
                .unwrap_or_default();
            if reviewed.is_empty() {
                format!("Approved as written: keep producing {predicate} this way.")
            } else {
                format!("Approved as written ({predicate}): \u{201c}{reviewed}\u{201d}.")
            }
        }
        _ => value_text(&body.value, "text")?.to_owned(),
    };
    let line = bounded_line(&line);
    (!line.is_empty()).then_some(line)
}

fn target_for(kind: CompiledLineKind, body: &ClaimBody) -> Option<ActingTarget> {
    let ClaimSubject::Entity(actor) = body.subject else {
        return None;
    };
    Some(match kind {
        CompiledLineKind::BriefPreference => ActingTarget::Brief {
            actor,
            scope: crate::actor_claims::edit_cost_scope_name(body.scope.as_ref())
                .unwrap_or("unscoped")
                .to_owned(),
        },
        _ => ActingTarget::Charter { actor },
    })
}

fn revision_text(principal: &EntityId, lines: &[CompiledLine]) -> String {
    let mut out = format!(
        "Learned from reviews by {} ({} approved preference{}):\n",
        &principal.to_hex()[..8],
        lines.len(),
        if lines.len() == 1 { "" } else { "s" }
    );
    let mut current = None;
    for line in lines {
        if current != Some(line.kind) {
            out.push_str(line.kind.heading());
            out.push_str(":\n");
            current = Some(line.kind);
        }
        out.push_str("- ");
        out.push_str(&line.text);
        out.push('\n');
    }
    out
}

fn revision_id(principal: &EntityId, target: &ActingTarget, lines: &[CompiledLine]) -> String {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron acting revision v1");
    hasher.update(principal.as_bytes());
    match target {
        ActingTarget::Charter { actor } => {
            hasher.update(b"charter");
            hasher.update(actor.as_bytes());
        }
        ActingTarget::Brief { actor, scope } => {
            hasher.update(b"brief");
            hasher.update(actor.as_bytes());
            hasher.update(&(scope.len() as u64).to_be_bytes());
            hasher.update(scope.as_bytes());
        }
    }
    for line in lines {
        hasher.update(line.claim.as_bytes());
        hasher.update(&(line.text.len() as u64).to_be_bytes());
        hasher.update(line.text.as_bytes());
    }
    bytes_to_hex_lower(hasher.finalize().as_bytes())
}

/// Compiles `principal`'s approved, in-force preferences into one acting
/// revision per target, and supersedes any older pending revision of the
/// same target. Returns the revisions this pass wrote; a target whose
/// compilation is unchanged writes nothing.
///
/// # Errors
///
/// Storage errors.
pub fn compile_acting_revisions(
    vault: &Vault,
    principal: &EntityId,
    now: u64,
) -> Result<Vec<ActingRevision>> {
    let mut by_target: BTreeMap<ActingTarget, Vec<CompiledLine>> = BTreeMap::new();
    for (claim, body) in mined_preferences_for_principal(vault, principal, now)? {
        // Only the decider's approval puts a preference into what a generator
        // acts on; a Proposed claim is still a question.
        if body.approval != ClaimApprovalStatus::Approved {
            continue;
        }
        let Some(kind) = CompiledLineKind::from_predicate(&body.predicate) else {
            continue;
        };
        let (Some(text), Some(target)) = (compiled_line(kind, &body), target_for(kind, &body))
        else {
            continue;
        };
        by_target
            .entry(target)
            .or_default()
            .push(CompiledLine { kind, text, claim });
    }

    let mut written = Vec::new();
    vault.with_write_txn_grouped(|wtxn| {
        let existing = ACTING_REVISION.scan(&vault.store, wtxn)?;
        for (target, mut lines) in by_target {
            lines.sort();
            lines.dedup_by(|a, b| a.kind == b.kind && a.text == b.text);
            let id = revision_id(principal, &target, &lines);
            if existing.iter().any(|(key, _)| *key == id) {
                continue;
            }
            for (key, row) in &existing {
                if row.principal == *principal
                    && row.target == target
                    && row.status == RevisionStatus::Pending
                {
                    let mut row = row.clone();
                    row.status = RevisionStatus::Superseded {
                        by_revision: id.clone(),
                        at: now,
                    };
                    ACTING_REVISION.put(&vault.store, wtxn, key, &row)?;
                }
            }
            let revision = ActingRevision {
                text: revision_text(principal, &lines),
                id: id.clone(),
                principal: *principal,
                target,
                lines,
                responsible: vec![*principal],
                status: RevisionStatus::Pending,
                at: now,
            };
            ACTING_REVISION.put(&vault.store, wtxn, &id, &revision)?;
            written.push(revision);
        }
        Ok(())
    })?;
    Ok(written)
}

/// The responsible role answers a pending revision.
///
/// The principal whose preferences it compiles answers first; the vault owner
/// role answers last, so either may. The answering actor must pass the
/// owner-write check in the transaction that records the answer, and the
/// answer records who gave it.
///
/// # Errors
///
/// [`Error::EntityNotFound`] for an unknown revision; [`Error::InvalidClaimBody`]
/// for an answered or superseded revision or an over-long reason; the
/// owner-write refusal; storage errors.
pub fn resolve_acting_revision(
    vault: &Vault,
    actor: &WriteActor,
    revision_id: &str,
    decision: &RevisionDecision,
    now: u64,
) -> Result<ActingRevision> {
    if let RevisionDecision::Decline { reason } = decision
        && reason.len() > MAX_REASON_BYTES
    {
        return Err(Error::InvalidClaimBody(
            "a decline reason is a sentence, not a document",
        ));
    }
    vault.with_write_txn_grouped(|wtxn| {
        let mut row = ACTING_REVISION
            .get(&vault.store, wtxn, &revision_id.to_owned())?
            .ok_or(Error::EntityNotFound)?;
        if row.status != RevisionStatus::Pending {
            return Err(Error::InvalidClaimBody(
                "only a pending acting revision takes an answer",
            ));
        }
        // The chain ends at the vault owner role, which this check proves.
        vault.verify_owner_write_actor_in_txn(wtxn, actor)?;
        let by = actor.entity_ref();
        row.status = match decision {
            RevisionDecision::Accept => RevisionStatus::Accepted { by, at: now },
            RevisionDecision::Decline { reason } => RevisionStatus::Declined {
                by,
                at: now,
                reason: reason.clone(),
            },
        };
        ACTING_REVISION.put(&vault.store, wtxn, &row.id, &row)?;
        Ok(row)
    })
}

/// Every revision waiting for its responsible role.
///
/// # Errors
///
/// Storage errors.
pub fn pending_acting_revisions(vault: &Vault) -> Result<Vec<ActingRevision>> {
    acting_revisions_where(vault, |row| row.status == RevisionStatus::Pending)
}

/// Every accepted revision, optionally for one target: what a charter's or
/// brief's owner applies.
///
/// # Errors
///
/// Storage errors.
pub fn accepted_acting_revisions(
    vault: &Vault,
    target: Option<&ActingTarget>,
) -> Result<Vec<ActingRevision>> {
    acting_revisions_where(vault, |row| {
        matches!(row.status, RevisionStatus::Accepted { .. })
            && target.is_none_or(|target| row.target == *target)
    })
}

/// One acting revision in the caller's snapshot: what an apply door reads
/// before it writes the revision's text.
///
/// # Errors
///
/// Storage errors.
#[allow(dead_code, reason = "L09's apply_agent_acting_revision door calls it")]
pub(crate) fn acting_revision_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    revision_id: &str,
) -> Result<Option<ActingRevision>> {
    ACTING_REVISION.get(&vault.store, txn, &revision_id.to_owned())
}

/// Marks an accepted revision applied, in the transaction that wrote its
/// text into `version` of its target, by `by`. Only an accepted revision
/// takes the mark. The same mark again (same `by` and `version`) is a no-op
/// that returns the row, so a retried apply finds its own mark.
///
/// # Errors
///
/// [`Error::EntityNotFound`] for an unknown revision;
/// [`Error::InvalidClaimBody`] for a revision that is not accepted, or that
/// another apply already marked; storage errors.
#[allow(dead_code, reason = "L09's apply_agent_acting_revision door calls it")]
pub(crate) fn mark_acting_revision_applied_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    revision_id: &str,
    by: EntityId,
    version: &str,
    at: u64,
) -> Result<ActingRevision> {
    let mut row = ACTING_REVISION
        .get(&vault.store, txn, &revision_id.to_owned())?
        .ok_or(Error::EntityNotFound)?;
    match &row.status {
        RevisionStatus::Accepted {
            by: accepted_by,
            at: accepted_at,
        } => {
            row.status = RevisionStatus::Applied {
                accepted_by: *accepted_by,
                accepted_at: *accepted_at,
                by,
                at,
                version: version.to_owned(),
            };
            ACTING_REVISION.put(&vault.store, txn, &row.id, &row)?;
            Ok(row)
        }
        RevisionStatus::Applied {
            by: applied_by,
            version: applied,
            ..
        } if *applied_by == by && applied == version => Ok(row),
        _ => Err(Error::InvalidClaimBody(
            "only an accepted acting revision is applied, once",
        )),
    }
}

fn acting_revisions_where(
    vault: &Vault,
    keep: impl Fn(&ActingRevision) -> bool,
) -> Result<Vec<ActingRevision>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut rows: Vec<ActingRevision> = ACTING_REVISION
        .scan(&vault.store, &rtxn)?
        .into_iter()
        .map(|(_, row)| row)
        .filter(|row| keep(row))
        .collect();
    rows.sort_by(|a, b| a.at.cmp(&b.at).then_with(|| a.id.cmp(&b.id)));
    Ok(rows)
}
