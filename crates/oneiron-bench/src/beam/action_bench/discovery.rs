//! The discovery arms (ARCH-0042 #action-bench): index-first against
//! search-only discovery, with stored memory held fixed.
//!
//! Both arms read the memory arms' vault and reach its claims only: the
//! history's authored claims, the derived memory the memory arms hold fixed.
//! So the two differ in how the reader finds a claim, and in nothing else.
//! Each takes two reader calls per follow-up. The first, under the pinned
//! discovery prompt, asks what to read. `search_only` sends the question
//! alone, and the reader answers one search, `{"search": <query>}`.
//! `index_first` also sends an index of every claim the follow-up may read,
//! one line per claim with its handle and predicate and never its value, and
//! the reader may fetch handles beside its search,
//! `{"fetch": [<handle>], "search": <query>}`. So `index_first` is
//! `search_only` with the index shown first, and the difference between them
//! is the index's own benefit (the MemCurrent review's ablations never
//! isolated it). The second call is the memory arms' act call over what the
//! first one read.
//!
//! The index is the agent's surfaceable claim list
//! (`Memory::claim_list_filtered`, the `vault.claims.list_filtered` read),
//! narrowed to base reality and the follow-up's world, as recall's
//! `world_ref` reads: the list has no world axis. A fetch reads its claim
//! with `Memory::claim_read_filtered`, the expand by handle; a search is
//! `Memory::recall` over claims. Handles are the bench's own (`m1`, `m2`,
//! ...): an engine short ref carries a name and the claim's content hash.

use std::time::Instant;

use oneiron::CallPurpose;
use oneiron::memory::{
    ClaimFilteredListRequest, ClaimFilteredReadRequest, ClaimView, Effort, RecallScope,
};
use serde::Serialize;

use super::super::{
    BeamError, BeamResult,
    judge::AnswerPromptPin,
    llm_host::{ModelPin, ModelSession},
    model_usage::sum_costs,
    report_model::CostComponentReport,
};
use super::{
    arms::{self, ArmContext, MemoryArm, VaultView},
    elapsed_us,
    tasks::FollowUp,
};

/// The most claims an index lists; past it the step says the index was cut.
const MAX_INDEX_ROWS: usize = 200;
/// Claims one listing reads, before the world narrowing.
const INDEX_LIST_LIMIT: usize = 4096;
/// Registry kind of the claims both arms reach.
const CLAIM_KIND: &str = "CLAIM";

/// The reader and prompt of every discovery step in a run.
pub(super) struct Discovery<'a> {
    pub(super) session: &'a ModelSession,
    pub(super) reader: &'a ModelPin,
    pub(super) prompt: &'a AnswerPromptPin,
    /// The most claims the act step reads, as one recall hands the reader.
    pub(super) recall_limit: usize,
}

/// One follow-up's discovery step: what the reader was shown, what it asked
/// to read and what reading it cost.
#[derive(Debug, Serialize)]
pub(super) struct DiscoveryStep {
    /// The index the reader was shown; empty for `search_only`.
    index: String,
    index_lines: usize,
    /// More claims stood in the follow-up's scope than the index lists.
    index_truncated: bool,
    reply: String,
    reply_truncated: bool,
    /// The listed handles the reply named and the act step read, in reply
    /// order, each once.
    fetched: Vec<String>,
    /// Handles the reply named that its index never listed; none is read.
    unknown_handles: Vec<String>,
    /// Listed handles the reply named past the recall limit; none is read.
    handles_over_limit: usize,
    /// The reply's search, when it asked one.
    query: Option<String>,
    /// The reply held no JSON object of `fetch` and `search`; the act step
    /// reads nothing.
    invalid: bool,
    index_elapsed_us: u64,
    fetch_elapsed_us: u64,
    search_elapsed_us: u64,
    reader: CostComponentReport,
}

/// One follow-up under a discovery arm: the index (for `index_first`), the
/// reader's choice, and the context the act step reads.
pub(super) fn discover(
    discovery: &Discovery<'_>,
    view: &VaultView<'_>,
    arm: MemoryArm,
    follow_up: &FollowUp,
    question: &str,
) -> BeamResult<ArmContext> {
    let shows_index = arm == MemoryArm::IndexFirst;
    let started = Instant::now();
    let index = if shows_index {
        Index::list(view, follow_up)?
    } else {
        Index::default()
    };
    let index_elapsed_us = elapsed_us(started);
    let index_text = index.text();
    let input = if shows_index {
        serde_json::json!({"question": question, "index": index_text})
    } else {
        serde_json::json!({"question": question})
    };
    let (reply, reader, reply_truncated) = discovery.session.invoke_capped(
        discovery.reader,
        CallPurpose::ToolRouting,
        &discovery.prompt.content,
        &serde_json::to_string(&input)?,
    )?;
    let request = parse_request(&reply);
    let invalid = request.is_none();
    let request = request.unwrap_or_default();
    let mut lines = Vec::new();
    let mut fetched = Vec::new();
    let mut unknown_handles = Vec::new();
    let mut handles_over_limit = 0;
    let started = Instant::now();
    for handle in &request.fetch {
        let Some(claim_ref) = index.claim_ref(handle) else {
            unknown_handles.push(handle.clone());
            continue;
        };
        if fetched.contains(handle) {
            continue;
        }
        if lines.len() >= discovery.recall_limit {
            handles_over_limit += 1;
            continue;
        }
        fetched.push(handle.clone());
        if let Some(claim) = read_claim(view, follow_up, claim_ref)? {
            push_once(&mut lines, claim_line(&claim));
        }
    }
    let fetch_elapsed_us = elapsed_us(started);
    let started = Instant::now();
    let mut items_off_arm = 0;
    if let Some(query) = &request.search {
        let scope = RecallScope {
            world_ref: view.world_ref(follow_up)?,
            kinds: Some(vec![CLAIM_KIND.to_owned()]),
            ..RecallScope::default()
        };
        let pack = view
            .memory()
            .recall(
                query,
                Effort::Light,
                &scope,
                discovery.recall_limit,
                None,
                None,
            )
            .map_err(|error| refused(follow_up, "recall", &error.to_string()))?;
        for item in &pack.items {
            if item.kind != CLAIM_KIND {
                items_off_arm += 1;
            } else if lines.len() < discovery.recall_limit {
                push_once(
                    &mut lines,
                    arms::item_line(&item.kind, item.predicate.as_deref(), &item.value_text),
                );
            }
        }
    }
    let search_elapsed_us = elapsed_us(started);
    Ok(ArmContext {
        lines: lines.len(),
        text: lines.join("\n"),
        items_off_arm,
        recall_elapsed_us: search_elapsed_us,
        discovery: Some(DiscoveryStep {
            index_lines: index.rows.len(),
            index: index_text,
            index_truncated: index.truncated,
            reply,
            reply_truncated,
            fetched,
            unknown_handles,
            handles_over_limit,
            query: request.search,
            invalid,
            index_elapsed_us,
            fetch_elapsed_us,
            search_elapsed_us,
            reader,
        }),
    })
}

/// The claims one follow-up may read, each under its bench handle.
#[derive(Default)]
struct Index {
    rows: Vec<IndexRow>,
    truncated: bool,
}

struct IndexRow {
    handle: String,
    predicate: String,
    /// The claim's 32-hex id, which a fetch reads.
    claim_ref: String,
}

impl Index {
    /// The surfaceable claims in base reality and the follow-up's world,
    /// in the list's order.
    fn list(view: &VaultView<'_>, follow_up: &FollowUp) -> BeamResult<Self> {
        let world = view.world_ref(follow_up)?;
        let listed = view
            .memory()
            .claim_list_filtered(&ClaimFilteredListRequest {
                limit: INDEX_LIST_LIMIT,
                ..ClaimFilteredListRequest::default()
            })
            .map_err(|error| refused(follow_up, "claim list", &error.to_string()))?
            .value;
        let in_scope: Vec<ClaimView> = listed
            .into_iter()
            .filter(|claim| claim.world_ref.is_none() || claim.world_ref == world)
            .collect();
        let truncated = in_scope.len() > MAX_INDEX_ROWS;
        let rows = in_scope
            .into_iter()
            .take(MAX_INDEX_ROWS)
            .enumerate()
            .map(|(place, claim)| IndexRow {
                handle: format!("m{}", place + 1),
                predicate: claim.predicate,
                claim_ref: claim.claim_ref,
            })
            .collect();
        Ok(Self { rows, truncated })
    }

    /// One line per claim: its handle, kind and predicate, never its value.
    fn text(&self) -> String {
        self.rows
            .iter()
            .map(|row| format!("- {} {CLAIM_KIND} {}", row.handle, row.predicate))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn claim_ref(&self, handle: &str) -> Option<&str> {
        self.rows
            .iter()
            .find(|row| row.handle == handle)
            .map(|row| row.claim_ref.as_str())
    }
}

/// One listed claim as retrieval serves it; none when it no longer reads.
fn read_claim(
    view: &VaultView<'_>,
    follow_up: &FollowUp,
    claim_ref: &str,
) -> BeamResult<Option<ClaimView>> {
    view.memory()
        .claim_read_filtered(&ClaimFilteredReadRequest {
            claim_ref: claim_ref.to_owned(),
            filter: None,
            project_refs: Vec::new(),
        })
        .map(|read| read.value)
        .map_err(|error| refused(follow_up, "claim read", &error.to_string()))
}

/// A fetched claim's context line, as the derived arm renders a recalled one.
fn claim_line(claim: &ClaimView) -> String {
    let value = claim
        .value
        .as_str()
        .map_or_else(|| claim.value.to_string(), str::to_owned);
    arms::item_line(CLAIM_KIND, Some(&claim.predicate), &value)
}

fn push_once(lines: &mut Vec<String>, line: String) {
    if !lines.contains(&line) {
        lines.push(line);
    }
}

/// What a discovery reply asks to read.
#[derive(Default)]
struct ReadRequest {
    fetch: Vec<String>,
    search: Option<String>,
}

/// The reply's outermost `{...}` (a fenced or prefaced reply still parses)
/// as a read request: `fetch`, a list of handles, and `search`, one query,
/// each optional. `None` when the reply holds no such object, or one with
/// any other field.
fn parse_request(reply: &str) -> Option<ReadRequest> {
    let start = reply.find('{')?;
    let end = reply.rfind('}')?;
    let value: serde_json::Value = serde_json::from_str(reply.get(start..=end)?).ok()?;
    let object = value.as_object()?;
    if object.keys().any(|key| key != "fetch" && key != "search") {
        return None;
    }
    let fetch = match object.get("fetch") {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(list) => list
            .as_array()?
            .iter()
            .map(|handle| Some(handle.as_str()?.trim().to_owned()))
            .collect::<Option<Vec<_>>>()?,
    };
    let search = match object.get("search") {
        None | Some(serde_json::Value::Null) => None,
        Some(query) => Some(query.as_str()?.trim().to_owned()).filter(|query| !query.is_empty()),
    };
    Some(ReadRequest { fetch, search })
}

/// One discovery arm's discovery stage over every follow-up it read.
#[derive(Debug, Serialize)]
pub(super) struct DiscoverySummary {
    /// Replies that held no read request.
    invalid: usize,
    index_lines: usize,
    index_chars: usize,
    fetched: usize,
    unknown_handles: usize,
    handles_over_limit: usize,
    searches: usize,
    index_elapsed_us: u64,
    fetch_elapsed_us: u64,
    search_elapsed_us: u64,
    /// The discovery reader calls, as the provider counted them.
    reader: CostComponentReport,
}

/// The discovery stage of one arm's steps; none for an arm with no step.
pub(super) fn summarize(steps: &[&DiscoveryStep]) -> BeamResult<Option<DiscoverySummary>> {
    if steps.is_empty() {
        return Ok(None);
    }
    let costs: Vec<CostComponentReport> = steps.iter().map(|step| step.reader.clone()).collect();
    Ok(Some(DiscoverySummary {
        invalid: steps.iter().filter(|step| step.invalid).count(),
        index_lines: steps.iter().map(|step| step.index_lines).sum(),
        index_chars: steps.iter().map(|step| step.index.chars().count()).sum(),
        fetched: steps.iter().map(|step| step.fetched.len()).sum(),
        unknown_handles: steps.iter().map(|step| step.unknown_handles.len()).sum(),
        handles_over_limit: steps.iter().map(|step| step.handles_over_limit).sum(),
        searches: steps.iter().filter(|step| step.query.is_some()).count(),
        index_elapsed_us: steps.iter().map(|step| step.index_elapsed_us).sum(),
        fetch_elapsed_us: steps.iter().map(|step| step.fetch_elapsed_us).sum(),
        search_elapsed_us: steps.iter().map(|step| step.search_elapsed_us).sum(),
        reader: sum_costs(&costs)?,
    }))
}

fn refused(follow_up: &FollowUp, read: &str, reason: &str) -> BeamError {
    BeamError::InvalidFixture {
        fixture_id: follow_up.id.clone(),
        reason: format!("action bench discovery {read} refused: {reason}"),
    }
}
