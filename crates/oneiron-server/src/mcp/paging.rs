//! MCP page budgets, cursors, snapshots, and canonical-JSON digests.

use super::endpoint_args::McpPageRequest;
use super::surface::{MCP_PAGE_ITEM_CAP, MCP_RESULT_TTL_MS};
use oneiron::context_board::BoardStreamFrame;
use serde::Serialize;
use serde_json::Value;
use serde_json::json;

/// Closed health enum every actor-derived result states.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpRetrievalHealth {
    Healthy,
    Degraded,
    Partial,
    Unavailable,
}

impl McpRetrievalHealth {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Partial => "partial",
            Self::Unavailable => "unavailable",
        }
    }
}

/// The explicit end marker. There is no "absent means done".
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpResultEnd {
    Complete,
    More,
}

impl McpResultEnd {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "Complete",
            Self::More => "More",
        }
    }
}

/// What a PRODUCER knows about its own page, before the budget caps it.
///
/// The end marker is derived from THIS, never from the returned count alone: a
/// producer that itself omitted rows can never be reported `Complete`.
///
/// The two omission axes are KEPT APART (ONE-1704 repair): rows the REQUESTED
/// ACTOR SCOPE removed are not the rows the producer's own page window
/// truncated away, and a result that merged them told a caller the scope had
/// hidden work when only the window had. Both still force a non-terminal end
/// marker, because neither is on this page.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct McpPageSource {
    /// Rows the producer actually produced for this page.
    pub produced: usize,
    /// Rows the REQUESTED ACTOR SCOPE removed. No page window and no
    /// continuation can reach these — the credential's ceiling did.
    pub scope_omitted: usize,
    /// Rows the PRODUCER's own page window truncated away (the engine-side
    /// board row cap or a capped scan). These are a transport window fact, not
    /// a scope fact.
    pub window_truncated: usize,
    /// True only when the producer reached the end of its own source.
    pub source_exhausted: bool,
}

impl McpPageSource {
    /// A producer that returned everything it has.
    #[must_use]
    pub const fn complete(produced: usize) -> Self {
        Self {
            produced,
            scope_omitted: 0,
            window_truncated: 0,
            source_exhausted: true,
        }
    }

    /// A producer that states rows the REQUESTED SCOPE removed.
    #[must_use]
    pub const fn truncated(produced: usize, scope_omitted: usize, source_exhausted: bool) -> Self {
        Self {
            produced,
            scope_omitted,
            window_truncated: 0,
            source_exhausted,
        }
    }

    /// A producer that states BOTH axes: what the requested scope removed and
    /// what its own page window truncated.
    #[must_use]
    pub const fn scoped_window(
        produced: usize,
        scope_omitted: usize,
        window_truncated: usize,
        source_exhausted: bool,
    ) -> Self {
        Self {
            produced,
            scope_omitted,
            window_truncated,
            source_exhausted,
        }
    }

    /// Rows this producer withheld on EITHER axis.
    #[must_use]
    pub const fn withheld(self) -> usize {
        self.scope_omitted.saturating_add(self.window_truncated)
    }

    /// The retrieval health this producer's own honesty bit forces.
    ///
    /// A capped scan does not know what it skipped, so it is `Degraded`; an
    /// exhausted scan that still withheld rows on either axis is `Partial`.
    /// Neither may be reported `Healthy`.
    #[must_use]
    pub const fn health(self) -> McpRetrievalHealth {
        match (self.withheld(), self.source_exhausted) {
            (0, true) => McpRetrievalHealth::Healthy,
            (_, true) => McpRetrievalHealth::Partial,
            (_, false) => McpRetrievalHealth::Degraded,
        }
    }
}

/// The adaptive page budget as it was actually resolved AND enforced.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpPageBudget {
    pub requested: Option<u32>,
    pub granted: u32,
    pub returned: u32,
    /// Rows not on this page for ANY reason: the transport page window's
    /// remainder plus both producer axes below. It is the total, and the two
    /// axes beside it say which is which.
    pub hidden: u32,
    /// Rows the REQUESTED ACTOR SCOPE removed. Stated on its own so a caller
    /// can tell a scope ceiling from a page window.
    pub scope_omitted: u32,
    /// Rows the PRODUCER's own page window truncated away, plus the remainder
    /// this transport page window did not return.
    pub window_truncated: u32,
    /// An owner/harness ceiling was exceeded because the caller explicitly
    /// forced it, and the record says so.
    pub forceful_override_honoured: bool,
    pub end: McpResultEnd,
    /// Where in the producer's own set this page starts. Server-side state and
    /// deliberately NOT wire data: publishing it would be exactly the offset
    /// the opaque handle exists to withhold.
    offset: u32,
    /// The producer position a continuation handle must name — `Some` exactly
    /// when this producer really can continue from here.
    successor: Option<u32>,
    /// The opaque BOUND continuation handle for
    /// [`Self::successor_position`], present only once a registry has minted
    /// and RETAINED it ([`McpConnectorActorRegistry::mint_page_cursor`]).
    pub cursor: Option<String>,
}

impl McpPageBudget {
    /// Resolves one page of a producer that CANNOT be continued.
    ///
    /// A non-terminal result from here carries no successor handle at all and
    /// states [`Self::continuation_unavailable`] instead: a `More` that cannot
    /// be followed is said out loud, never implied by a token nothing consumes
    /// (ONE-1704 M6).
    #[must_use]
    pub fn resolve(request: Option<&McpPageRequest>, source: McpPageSource) -> Self {
        Self::resolve_at(request, source, 0, false)
    }

    /// Resolves one page of a CONTINUABLE producer set, starting at `offset`.
    ///
    /// The caller mints and retains the handle for [`Self::successor_position`]
    /// and attaches it with [`Self::attach_cursor`]; page one plus the pages a
    /// consumed handle continues are exactly the producer's own set, with no
    /// row duplicated and none omitted.
    #[must_use]
    pub fn resolve_page(
        request: Option<&McpPageRequest>,
        source: McpPageSource,
        offset: u32,
    ) -> Self {
        Self::resolve_at(request, source, offset, true)
    }

    /// Adaptive `min`: a caller narrows the harness default, and only an
    /// explicit forceful override may exceed it — recorded when it does.
    fn resolve_at(
        request: Option<&McpPageRequest>,
        source: McpPageSource,
        offset: u32,
        continuable: bool,
    ) -> Self {
        let requested = request.and_then(|page| page.limit);
        let forced = request.is_some_and(|page| page.forceful_override);
        let granted = match (requested, forced) {
            (Some(limit), true) => limit,
            (Some(limit), false) => limit.min(MCP_PAGE_ITEM_CAP),
            (None, _) => MCP_PAGE_ITEM_CAP,
        };
        // `produced` is the producer's WHOLE set; this page starts at `offset`
        // inside it, so what is still ahead is what the successor continues.
        let available = source.produced.saturating_sub(offset as usize);
        let returned = available.min(granted as usize);
        let remaining = available.saturating_sub(returned);
        // The two axes stay apart: a page window — this transport's remainder
        // plus the producer's own truncation — is not the requested scope's
        // filtering, and `hidden` is their honest total rather than a merge
        // that hides which one withheld the rows.
        let window_truncated = remaining.saturating_add(source.window_truncated);
        let hidden = window_truncated.saturating_add(source.scope_omitted);
        let end = if hidden == 0 && source.source_exhausted {
            McpResultEnd::Complete
        } else {
            McpResultEnd::More
        };
        let returned = u32::try_from(returned).unwrap_or(u32::MAX);
        let successor = if continuable && remaining > 0 {
            Some(offset.saturating_add(returned))
        } else {
            None
        };
        Self {
            requested,
            granted,
            returned,
            hidden: u32::try_from(hidden).unwrap_or(u32::MAX),
            scope_omitted: u32::try_from(source.scope_omitted).unwrap_or(u32::MAX),
            window_truncated: u32::try_from(window_truncated).unwrap_or(u32::MAX),
            forceful_override_honoured: forced
                && requested.is_some_and(|limit| limit > MCP_PAGE_ITEM_CAP),
            end,
            offset,
            successor,
            cursor: None,
        }
    }

    /// The explicit end marker. There is no "absent means done".
    #[must_use]
    pub const fn end(&self) -> McpResultEnd {
        self.end
    }

    /// Where in the producer's own set this page started.
    #[must_use]
    pub const fn offset(&self) -> u32 {
        self.offset
    }

    /// The producer position a continuation handle must be BOUND to, if this
    /// producer can continue at all.
    #[must_use]
    pub const fn successor_position(&self) -> Option<u32> {
        self.successor
    }

    /// Attaches the minted, retained continuation handle for
    /// [`Self::successor_position`].
    pub fn attach_cursor(&mut self, cursor: String) {
        self.cursor = Some(cursor);
    }

    /// A non-terminal page that carries NO successor handle says so explicitly.
    ///
    /// This is derived from the two facts it is about, so a `More` can never
    /// silently ship without either a usable handle or this marker.
    #[must_use]
    pub const fn continuation_unavailable(&self) -> bool {
        matches!(self.end, McpResultEnd::More) && self.cursor.is_none()
    }

    /// ENFORCES the granted budget on one producer page.
    ///
    /// The budget is not advice: a result that states `granted` and then ships
    /// more rows than that is exactly the fail-open this closes. The window is
    /// `offset .. offset + returned` of the producer's own set, so a continued
    /// page returns the rows page one left behind and no others.
    #[must_use]
    pub fn cap(&self, rows: Vec<Value>) -> Vec<Value> {
        rows.into_iter()
            .skip(self.offset as usize)
            .take(self.returned as usize)
            .collect()
    }

    pub(super) fn to_value(&self) -> Value {
        let mut page = json!({
            "requested": self.requested,
            "granted": self.granted,
            "returned": self.returned,
            "hidden": self.hidden,
            "scope_omitted": self.scope_omitted,
            "window_truncated": self.window_truncated,
            "forceful_override_honoured": self.forceful_override_honoured,
        });
        if let Some(object) = page.as_object_mut() {
            if let Some(cursor) = &self.cursor {
                object.insert("cursor".to_owned(), Value::String(cursor.clone()));
            } else if self.continuation_unavailable() {
                object.insert("continuation_unavailable".to_owned(), Value::Bool(true));
            }
        }
        page
    }
}

/// Serializes JSON into a deterministic RFC-8785-shaped form for the values
/// used by MCP argument binding. In particular, every object is sorted
/// recursively; relying on `Value::to_string()` would preserve the workspace's
/// insertion order and make two equivalent nested objects hash differently.
fn canonical_json(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
        Value::Number(value) => out.push_str(&value.to_string()),
        Value::String(value) => {
            out.push_str(&serde_json::to_string(value).expect("JSON strings are serializable"));
        }
        Value::Array(values) => {
            out.push('[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                canonical_json(value, out);
            }
            out.push(']');
        }
        Value::Object(values) => {
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            out.push('{');
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key).expect("JSON keys are serializable"));
                out.push(':');
                canonical_json(&values[key], out);
            }
            out.push('}');
        }
    }
}

/// Returns canonical JSON bytes for tests and the continuation fence.
#[must_use]
pub fn mcp_canonical_json(value: &Value) -> String {
    let mut canonical = String::new();
    canonical_json(value, &mut canonical);
    canonical
}

/// The canonical digest one continuation handle binds a call's ARGUMENTS to.
///
/// The entire `page` member is excluded. Pagination controls are transport
/// mechanics, not producer-query identity: a continuation may omit `page`, use
/// a different limit, or add its cursor without changing the bound arguments.
/// Nested objects are recursively canonicalized before hashing, so insertion
/// order is not an identity axis.
#[must_use]
pub fn mcp_page_argument_digest<T: Serialize>(arguments: &T) -> [u8; 32] {
    let mut value =
        serde_json::to_value(arguments).expect("endpoint tool arguments are plain JSON data");
    if let Some(object) = value.as_object_mut() {
        object.remove("page");
    }
    let canonical = mcp_canonical_json(&value);
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron.mcp.page-arguments.v2");
    hasher.update(&(canonical.len() as u64).to_be_bytes());
    hasher.update(canonical.as_bytes());
    *hasher.finalize().as_bytes()
}

/// The exact producer material retained by a continuable page cursor. Keeping
/// the whole producer result, rather than only an offset, means page two stays
/// a partition of page one's immutable result even when the vault changes in
/// the meantime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct McpPageSnapshot {
    pub(crate) output: Value,
    pub(crate) source: McpPageSource,
    pub(crate) health: McpRetrievalHealth,
    pub(crate) keyframe: Option<BoardStreamFrame>,
}

/// The state returned after a valid cursor is consumed before any producer or
/// facade is called.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct McpPageCursorState {
    pub(crate) position: u32,
    pub(crate) snapshot_epoch: u64,
    pub(crate) snapshot: Option<McpPageSnapshot>,
}

/// Why a presented continuation handle was refused (ONE-1704 M6).
///
/// Every variant is fail-closed and carries the SAME stable wire code: a
/// mismatch is never a silent restart at page one, which would re-ship rows the
/// caller already has and call the enumeration complete.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum McpPageCursorError {
    #[error("this page cursor is not a live continuation for this connector")]
    Unknown,
    #[error("this page cursor was minted for another tool")]
    ToolMismatch,
    #[error("this page cursor was minted for another argument set")]
    ArgumentsMismatch,
    #[error("this page cursor was minted against another board snapshot epoch")]
    SnapshotMismatch,
    #[error("this operation does not support page continuations")]
    Unsupported,
}

impl McpPageCursorError {
    /// The one stable wire code every continuation refusal carries.
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        MCP_PAGE_CURSOR_INVALID_CODE
    }
}

/// The stable structured-error code for every continuation refusal.
pub const MCP_PAGE_CURSOR_INVALID_CODE: &str = "mcp_page_cursor_invalid";

/// One connection's live producer continuation, retained by the registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct McpPageContinuation {
    /// The exact handle that was minted and published.
    pub(super) cursor: String,
    pub(super) tool: String,
    pub(super) argument_digest: [u8; 32],
    pub(super) snapshot_epoch: u64,
    /// The producer position this handle continues from.
    pub(super) position: u32,
    /// The immutable producer result this position indexes.
    pub(super) snapshot: Option<McpPageSnapshot>,
    /// Mint order within this registry, from its own monotonic counter and no
    /// clock. It is the ONLY input to the retention bound's eviction choice, so
    /// which handle a full connection loses is deterministic and replayable.
    pub(super) minted_seq: u64,
}

/// A foreign TTL can only narrow this endpoint's refusal to cache.
#[must_use]
pub fn clamp_foreign_cache_ttl_ms(_foreign_ttl_ms: Option<u64>) -> u64 {
    // MCP_RESULT_TTL_MS is zero — a literal refusal to cache — so the narrower
    // of it and ANY foreign hint is still zero, and an absent hint keeps ours.
    // The endpoint constant IS the clamp; taking a minimum here could never
    // move the answer, so the parameter is accepted and deliberately unread.
    MCP_RESULT_TTL_MS
}
