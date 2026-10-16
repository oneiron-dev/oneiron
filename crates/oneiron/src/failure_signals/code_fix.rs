//! FIX6 code-fix exports (DEC-0005 #world-privacy-p8-tier2). Only two things
//! leave a vault for code fixes: the Coach's invented example of a failure (a
//! short general note and a made-up conversation that fails the same way,
//! verified by replay inside the vault, checked by the in-vault scrubber, and
//! sharing no verbatim span with the real chat), and the fixed or not-fixed
//! result of shadow-replaying a candidate fix inside the vault against the
//! real failure. Real chat text, and any id or digest of it, never leaves.
//!
//! Both follow the tier-1 participation switch
//! ([`FailureSignalConfig::exports`](crate::config::failure_signals::FailureSignalConfig::exports)):
//! automatic on Managed, off by default on SelfHost and Oss. A failure that
//! touched a private world sends its tier-1 counts only. Training stays a
//! separate opt-in.
//!
//! The replay runner and the scrubber are the host's: the Coach's model turn
//! and a candidate's build run there, inside the vault's boundary. Neither
//! has a default, and a missing or undecided one withholds the record.

use rand_core::RngCore;
use serde::{Deserialize, Serialize};

use super::FailureClassV1;
use super::verbatim::shares_verbatim_span;
use crate::agent_dispatch::{AGENT_DISPATCH_ATTEMPT_TYPE, decode_agent_dispatch_input};
use crate::attempt_queue::{AttemptQueue, AttemptRecord, AttemptState};
use crate::authority::{AuthorityFold, EffectiveRead};
use crate::batch::secret_scan::scan_joined_text;
use crate::dreamer_consolidation::whole_turn_text_as_in;
use crate::dreamer_runner::decode_dreamer_attempt_payload;
use crate::entity_id::bytes_to_hex_lower;
use crate::failure_ladder::{HealerCase, healer_case_in_txn};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Result, Vault};

pub const CODE_FIX_RECORD_VERSION: u16 = 1;
pub const CODE_FIX_MAX_NOTE_BYTES: usize = 1024;
pub const CODE_FIX_MAX_MESSAGES: usize = 32;
pub const CODE_FIX_MAX_MESSAGE_BYTES: usize = 4096;
pub const CODE_FIX_MAX_CANDIDATE_ID_BYTES: usize = 128;

/// Sealed records waiting for the host to drain them, with the worlds each
/// failure touched (local only). Key: id16, the record's public id.
const QUEUE: SideTable<[u8; 16], QueuedCodeFix, Named> =
    SideTable::new(&side_table::FAILURE_SIGNALS_CODE_FIX);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InventedRole {
    System,
    User,
    Assistant,
    Tool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventedMessage {
    pub role: InventedRole,
    pub text: String,
}

/// What the Coach drafted for one failure. The door decides whether it
/// leaves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventedExampleDraft {
    pub failure_class: FailureClassV1,
    /// A short general note on the failure.
    pub note: String,
    /// A made-up conversation that fails the same way.
    pub conversation: Vec<InventedMessage>,
}

/// One candidate fix the host shadow-replayed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateFix {
    /// The host's name for the candidate: a build, patch or skill revision.
    pub candidate_id: String,
    /// The invented example this result goes beside, when one left.
    pub example_id: Option<String>,
    pub failure_class: FailureClassV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventedFailureExample {
    pub version: u16,
    /// Random; derived from nothing in the vault.
    pub example_id: String,
    pub failure_class: FailureClassV1,
    pub note: String,
    pub conversation: Vec<InventedMessage>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixOutcome {
    Fixed,
    NotFixed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateFixResult {
    pub version: u16,
    /// Random; derived from nothing in the vault.
    pub result_id: String,
    pub candidate_id: String,
    pub example_id: Option<String>,
    pub failure_class: FailureClassV1,
    pub outcome: FixOutcome,
}

/// The only shapes a code-fix export takes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CodeFixExport {
    InventedExample(InventedFailureExample),
    FixResult(CandidateFixResult),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayRun {
    Reproduced,
    NotReproduced,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShadowRun {
    Fixed,
    NotFixed,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScrubRun {
    Clean,
    Flagged,
    Unavailable,
}

/// The host's replay runner, inside the vault's boundary. Every effect of a
/// replay stays in it: no tool call leaves and nothing is written.
pub trait CodeFixReplay {
    /// Replays the invented conversation: does it fail the way `case` did?
    fn reproduces(&self, case: &HealerCase, example: &InventedExampleDraft) -> Result<ReplayRun>;
    /// Shadow-replays `candidate_id` against the real failure of `case`.
    fn shadow_replay(&self, case: &HealerCase, candidate_id: &str) -> Result<ShadowRun>;
}

/// The host's in-vault scrubber. It judges the text and changes none of it.
pub trait ExportScrubber {
    fn scrub(&self, text: &str) -> Result<ScrubRun>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeFixWithheld {
    /// This deployment does not export.
    NotEligible,
    /// No durable failed case by that ref.
    UnknownCase,
    /// The failure touched a private world, or one whose privacy is unknown:
    /// its tier-1 counts are all that leaves.
    PrivateWorld,
    /// No source turn was named, or one is gone, has no text, or the Coach
    /// may not read all of it.
    SourceUnavailable,
    /// The draft or candidate is out of shape.
    Malformed,
    /// The example copies a span of the real chat.
    VerbatimSpan,
    /// The example carries a credential shape.
    Credential,
    /// The scrubber flagged the example or could not judge it.
    Scrubber,
    /// The invented conversation does not fail the same way.
    NotReproduced,
    /// The host has no replay for this case.
    ReplayUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum CodeFixVerdict {
    /// Sealed and waiting for [`Vault::export_code_fix_records`]; `id` is the
    /// record's public id.
    Queued {
        id: String,
    },
    Withheld {
        reason: CodeFixWithheld,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct QueuedCodeFix {
    worlds: Vec<EntityId>,
    record: CodeFixExport,
}

fn withheld(reason: CodeFixWithheld) -> Result<CodeFixVerdict> {
    Ok(CodeFixVerdict::Withheld { reason })
}

impl Vault {
    /// Seals the Coach's invented example of the failure `case_ref` for
    /// export. `source_turns` are the real turns the failure ran on; the
    /// example may copy no span of them. Every check runs before the record
    /// is queued, and the first that fails withholds it.
    pub fn prepare_invented_example(
        &self,
        case_ref: &str,
        source_turns: &[EntityId],
        draft: InventedExampleDraft,
        replay: &dyn CodeFixReplay,
        scrubber: &dyn ExportScrubber,
    ) -> Result<CodeFixVerdict> {
        use CodeFixWithheld as W;
        if !self.config.failure_signals.exports() {
            return withheld(W::NotEligible);
        }
        if !draft_in_shape(&draft) {
            return withheld(W::Malformed);
        }
        if source_turns.is_empty() {
            return withheld(W::SourceUnavailable);
        }
        let coach = self.coach_authority()?;
        self.store.authorization_now()?;
        let txn = self.store.env.read_txn()?;
        let Some((case, attempt)) = failed_case_in(self, &txn, case_ref)? else {
            return withheld(W::UnknownCase);
        };
        let Some(worlds) = touched_worlds_in(self, &txn, &attempt, source_turns)? else {
            return withheld(W::PrivateWorld);
        };
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        if !all_public(&fold, &worlds) {
            return withheld(W::PrivateWorld);
        }
        let mut sources = Vec::with_capacity(source_turns.len());
        for turn in source_turns {
            match whole_turn_text_as_in(self, &txn, coach, turn)? {
                Some(text) => sources.push(text),
                None => return withheld(W::SourceUnavailable),
            }
        }
        drop(txn);

        let joined = std::iter::once(draft.note.as_str())
            .chain(draft.conversation.iter().map(|m| m.text.as_str()))
            .collect::<Vec<_>>()
            .join("\n");
        if shares_verbatim_span(&sources, &joined) {
            return withheld(W::VerbatimSpan);
        }
        drop(sources);
        let credential = std::iter::once(draft.note.as_str())
            .chain(draft.conversation.iter().map(|m| m.text.as_str()))
            .chain(std::iter::once(joined.as_str()))
            .any(|text| scan_joined_text(text).is_some());
        if credential {
            return withheld(W::Credential);
        }
        if scrubber.scrub(&joined)? != ScrubRun::Clean {
            return withheld(W::Scrubber);
        }
        match replay.reproduces(&case, &draft)? {
            ReplayRun::Reproduced => {}
            ReplayRun::NotReproduced => return withheld(W::NotReproduced),
            ReplayRun::Unavailable => return withheld(W::ReplayUnavailable),
        }
        let InventedExampleDraft {
            failure_class,
            note,
            conversation,
        } = draft;
        self.queue_code_fix(case_ref, worlds, |id| {
            CodeFixExport::InventedExample(InventedFailureExample {
                version: CODE_FIX_RECORD_VERSION,
                example_id: id,
                failure_class,
                note,
                conversation,
            })
        })
    }

    /// Seals the fixed or not-fixed result of shadow-replaying one candidate
    /// against the real failure `case_ref`. A replay the host could not run
    /// emits nothing, never a `NotFixed`.
    pub fn record_candidate_fix_result(
        &self,
        case_ref: &str,
        candidate: CandidateFix,
        replay: &dyn CodeFixReplay,
    ) -> Result<CodeFixVerdict> {
        use CodeFixWithheld as W;
        if !self.config.failure_signals.exports() {
            return withheld(W::NotEligible);
        }
        if !candidate_in_shape(&candidate) {
            return withheld(W::Malformed);
        }
        let txn = self.store.env.read_txn()?;
        let Some((case, attempt)) = failed_case_in(self, &txn, case_ref)? else {
            return withheld(W::UnknownCase);
        };
        let Some(worlds) = touched_worlds_in(self, &txn, &attempt, &[])? else {
            return withheld(W::PrivateWorld);
        };
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        if !all_public(&fold, &worlds) {
            return withheld(W::PrivateWorld);
        }
        drop(txn);
        let outcome = match replay.shadow_replay(&case, &candidate.candidate_id)? {
            ShadowRun::Fixed => FixOutcome::Fixed,
            ShadowRun::NotFixed => FixOutcome::NotFixed,
            ShadowRun::Unavailable => return withheld(W::ReplayUnavailable),
        };
        let CandidateFix {
            candidate_id,
            example_id,
            failure_class,
        } = candidate;
        self.queue_code_fix(case_ref, worlds, |id| {
            CodeFixExport::FixResult(CandidateFixResult {
                version: CODE_FIX_RECORD_VERSION,
                result_id: id,
                candidate_id,
                example_id,
                failure_class,
                outcome,
            })
        })
    }

    /// Drains every queued code-fix record this deployment may still send.
    /// A record whose failure touched a world that has since turned private
    /// is dropped, and so is every record once the deployment stopped
    /// exporting. The host delivers what this returns; a drained record is
    /// gone from the vault.
    pub fn export_code_fix_records(&self) -> Result<Vec<CodeFixExport>> {
        let exports = self.config.failure_signals.exports();
        self.with_write_txn_grouped(|txn| {
            let rows = QUEUE.scan(&self.store, txn)?;
            if rows.is_empty() {
                return Ok(Vec::new());
            }
            let fold = self.authority_view_readonly_in_txn(txn)?;
            let mut out = Vec::new();
            for (key, row) in rows {
                QUEUE.delete(&self.store, txn, &key)?;
                if exports && all_public(&fold, &row.worlds) {
                    out.push(row.record);
                }
            }
            Ok(out)
        })
    }

    /// Queues one sealed record under a fresh random id, if its case still
    /// stands at commit.
    fn queue_code_fix(
        &self,
        case_ref: &str,
        worlds: Vec<EntityId>,
        record: impl FnOnce(String) -> CodeFixExport,
    ) -> Result<CodeFixVerdict> {
        let mut key = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut key);
        let id = bytes_to_hex_lower(&key);
        let row = QueuedCodeFix {
            worlds,
            record: record(id.clone()),
        };
        self.with_write_txn_grouped(|txn| {
            if failed_case_in(self, txn, case_ref)?.is_none() {
                return withheld(CodeFixWithheld::UnknownCase);
            }
            QUEUE.put(&self.store, txn, &key, &row)?;
            Ok(CodeFixVerdict::Queued { id })
        })
    }
}

/// The durable case and its attempt, while that attempt stands failed.
fn failed_case_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    case_ref: &str,
) -> Result<Option<(HealerCase, AttemptRecord)>> {
    let Some(case) = healer_case_in_txn(vault, txn, case_ref)? else {
        return Ok(None);
    };
    let Some(attempt) = AttemptQueue::new(vault).get_in_txn(txn, case.failing_attempt_id)? else {
        return Ok(None);
    };
    if attempt.state != AttemptState::Failed {
        return Ok(None);
    }
    Ok(Some((case, attempt)))
}

/// Every world the failure touched: the failing dispatch's scope, and each
/// source row's world (base reality for a row in none). `None` when one of
/// them cannot be proved. A source row that is gone is left to the text read.
fn touched_worlds_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: &AttemptRecord,
    sources: &[EntityId],
) -> Result<Option<Vec<EntityId>>> {
    use crate::ports::EntityStore;
    let base = crate::claim::base_world_id();
    let Some(dispatch) = dispatch_world(attempt) else {
        return Ok(None);
    };
    let mut worlds = vec![dispatch.unwrap_or(base)];
    for id in sources {
        let Some(row) = vault.port_entity_get(txn, id)? else {
            continue;
        };
        let Some(world) = crate::federation::record_scope::record_world_in(
            &vault.store,
            txn,
            *id,
            row.entity_type,
            &row.body,
        )?
        else {
            return Ok(None);
        };
        worlds.push(world.unwrap_or(base));
    }
    worlds.sort_unstable();
    worlds.dedup();
    Ok(Some(worlds))
}

/// The failing dispatch's world (`Some(None)` when it named none); `None`
/// when the attempt is no agent dispatch this can read.
fn dispatch_world(attempt: &AttemptRecord) -> Option<Option<EntityId>> {
    let payload = decode_dreamer_attempt_payload(&attempt.payload).ok()?;
    if payload.attempt_type != AGENT_DISPATCH_ATTEMPT_TYPE {
        return None;
    }
    let input = decode_agent_dispatch_input(&payload.input).ok()?;
    Some(input.scope.and_then(|scope| scope.world))
}

/// Readable everywhere: any narrower, conflicted or unknowable setting is
/// private.
fn all_public(fold: &AuthorityFold, worlds: &[EntityId]) -> bool {
    worlds
        .iter()
        .all(|world| fold.world_privacy(*world).read == EffectiveRead::Everywhere)
}

fn draft_in_shape(draft: &InventedExampleDraft) -> bool {
    let text_ok = |text: &str, max: usize| !text.trim().is_empty() && text.len() <= max;
    text_ok(&draft.note, CODE_FIX_MAX_NOTE_BYTES)
        && !draft.conversation.is_empty()
        && draft.conversation.len() <= CODE_FIX_MAX_MESSAGES
        && draft
            .conversation
            .iter()
            .all(|m| text_ok(&m.text, CODE_FIX_MAX_MESSAGE_BYTES))
}

/// A candidate id is a host token, never prose: printable ASCII with no
/// space, and no credential shape.
fn candidate_in_shape(candidate: &CandidateFix) -> bool {
    let id = &candidate.candidate_id;
    let token = !id.is_empty()
        && id.len() <= CODE_FIX_MAX_CANDIDATE_ID_BYTES
        && id.bytes().all(|b| b.is_ascii_graphic())
        && scan_joined_text(id).is_none();
    let example = candidate.example_id.as_deref().is_none_or(|example| {
        example.len() == 32
            && example
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    });
    token && example
}
