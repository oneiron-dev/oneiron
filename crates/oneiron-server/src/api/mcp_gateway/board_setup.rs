//! Board state, setup grammar, and page preflight.

pub(super) use self::assembly::*;
pub(super) use self::carrier::*;
pub(crate) use self::run::*;
pub(crate) use self::setup::*;
use super::device_release::{mcp_carrier_releases, mcp_release_listed, mcp_snapshot_releases};
use super::stream_reads::{mcp_live_task_lines, mcp_own_task_lines};
use super::{
    McpCallContext, McpGatewayError, board_observations, device_release, mcp_actor_result,
    mcp_api_error, mcp_credential_reads, mcp_engine_error, mcp_facade_error,
    mcp_scope_covers_entity, mcp_scoped_read, mcp_scoped_tasks_section, mcp_text_content,
};
use crate::mcp::McpPageBudget;
use crate::mcp::McpPageCursorState;
use crate::mcp::McpPageSnapshot;
use crate::mcp::McpResolvedActor;
use crate::mcp::McpRetrievalHealth;
use crate::server::SyncServer;
use serde_json::Value;
use serde_json::json;
use std::sync::Arc;

mod assembly;
mod carrier;
mod run;
mod setup;

/// The most WORLDS rows one keyframe renders, as the HTTP board's.
const MCP_BOARD_WORLDS_CAP: usize = 16;

/// How one result relates to this connector's queued STREAM state.
#[derive(Debug)]
pub(super) enum McpCarrierPolicy {
    /// An ordinary result: drain AT MOST ONE pending frame beside it.
    Drain,
    /// The response's capability channel, never retained as session state.
    DrainWithCapabilities(Vec<oneiron::context_board::CapabilityHit>),
    /// This result carries its OWN freshly minted keyframe. `Some` is a frame
    /// the producer has not enqueued yet (setup mints one outside the
    /// registry); `None` is one the producer already enqueued (the engine's own
    /// `self.focus.refresh` does). Either way the queue behind it is EXPLICITLY
    /// superseded and then drained, so no older carrier rides beside a fresh
    /// keyframe and none is left stranded.
    ///
    /// Only a result that states a keyframe the caller has NOT already been
    /// given may say this. A paged producer states its keyframe on page ONE;
    /// its continuations restate that same retained frame and therefore
    /// [`McpCarrierPolicy::Drain`] instead — re-superseding on an already
    /// delivered keyframe destroys the transitions queued behind it.
    FreshKeyframe(Option<oneiron::context_board::BoardStreamFrame>),
}

/// One connector's CURRENT board: the sections, the state-derived snapshot
/// epoch, and the scope label the header states.
pub(super) struct McpBoardState {
    pub(super) sections: Vec<oneiron::context_board::BoardSection>,
    pub(super) scope_label: String,
    /// The monotonic snapshot epoch this exact state owns (ONE-1704 M5).
    pub(super) epoch: u64,
    pub(super) changes: oneiron::context_board::ChangedLine,
    /// Every row the sections and the changed line were derived from: what a
    /// retained page of this board is judged by again at release.
    pub(super) rows: Vec<oneiron::EntityId>,
    /// TASKS rows the credential's REQUESTED SCOPE withheld inside its own
    /// world and facet (`mcp_scoped_tasks_section`).
    scope_omitted: usize,
    /// TASKS rows the engine's own render row cap truncated away. A page
    /// WINDOW fact, kept apart from the scope fact above (ONE-1704 repair).
    window_truncated: usize,
    /// False when the producer's own TASK scan stopped at its cap, so the
    /// truncation count above is a lower bound rather than a census.
    source_exhausted: bool,
    /// The hook blocks this board carries, spent only when it goes out.
    pub(super) hooks: McpBoardHooks,
}

impl McpBoardState {
    /// The COMPLETE omission facts this rendered board carries, on both axes
    /// and with the producer's own exhaustion bit.
    ///
    /// Every consumer of a board's honesty reads it from here, so no caller can
    /// derive a result fact from one axis while the board states two.
    pub(super) const fn omissions(&self) -> McpBoardOmissions {
        McpBoardOmissions {
            scope_omitted: self.scope_omitted,
            window_truncated: self.window_truncated,
            source_exhausted: self.source_exhausted,
        }
    }
}

/// What one rendered board did NOT show, on its two independent axes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct McpBoardOmissions {
    /// Rows the REQUESTED ACTOR SCOPE removed.
    pub(crate) scope_omitted: usize,
    /// Rows the producer's own render window truncated away.
    pub(crate) window_truncated: usize,
    pub(crate) source_exhausted: bool,
}

impl McpBoardOmissions {
    /// The retrieval health these omission facts force, in the SAME meanings
    /// every other producer states ([`crate::mcp::McpPageSource::health`]).
    ///
    /// ONE-1704 repair: a board that withheld rows on EITHER axis is not
    /// healthy, and a board whose own TASK scan stopped at its cap is degraded
    /// rather than partial, because it does not know what it skipped. Reading
    /// only the scope axis let a board the render WINDOW had truncated be
    /// reported healthy, which told a caller an incomplete working set was the
    /// whole one.
    ///
    /// `produced` is not a health axis — [`crate::mcp::McpPageSource::health`]
    /// reads only the two omission counts and the exhaustion bit — so the row
    /// count is deliberately not restated here.
    pub(crate) const fn health(self) -> McpRetrievalHealth {
        crate::mcp::McpPageSource::scoped_window(
            0,
            self.scope_omitted,
            self.window_truncated,
            self.source_exhausted,
        )
        .health()
    }
}

/// The hook blocks one rendered board carries (ARCH-0080 §11, OF-579): the
/// blocks whose rows it shows, and the receipt its pinned MEMORIES rows owe.
/// A board rendered for its epoch alone spends neither. Setup's page one, a
/// `self.focus.refresh` and a keyed `describe` record the receipt before
/// their result goes out and spend the blocks once it has; a code-mode
/// board read, and a pumped run's own board row, do both as the answer
/// returns to the run.
#[derive(Default)]
pub(crate) struct McpBoardHooks {
    /// The blocks naming a TASKS row the board shows.
    blocks: std::collections::BTreeSet<oneiron::EntityId>,
    receipt: Option<crate::api::context_board::PinsReceipt>,
    /// Each MEMORIES section the board shows, by its name: its pinned rows
    /// and the blocks naming them.
    memories: std::collections::BTreeMap<String, oneiron::context_board::HookShare>,
}

impl McpBoardHooks {
    /// The share of these hooks a keyed `describe` of section `key` shows:
    /// the TASKS blocks for TASKS, that one world's blocks and the receipt
    /// for its rows for a MEMORIES section, and none for any other.
    pub(super) fn shown_by(mut self, key: &str) -> Self {
        match key.split_once(' ').map_or(key, |(name, _)| name) {
            "TASKS" => Self {
                blocks: self.blocks,
                ..Self::default()
            },
            "MEMORIES" => match self.memories.remove(key) {
                Some(share) => Self {
                    receipt: self.receipt.map(|receipt| receipt.only(&share.rows)),
                    memories: std::iter::once((key.to_owned(), share)).collect(),
                    ..Self::default()
                },
                None => Self::default(),
            },
            _ => Self::default(),
        }
    }

    /// The owner's receipt for what the hook rows disclose under a contact's
    /// standing clearance, recorded before the board goes out, as the HTTP
    /// board records it. A receipt that fails refuses the result.
    pub(super) async fn record_receipt(
        &mut self,
        server: &SyncServer,
    ) -> Result<(), McpGatewayError> {
        match self.receipt.take() {
            Some(receipt) => receipt
                .record(&server.vault)
                .await
                .map_err(super::mcp_api_error),
            None => Ok(()),
        }
    }

    /// Spends one delivery of each block a board that went out carried. A
    /// failed record leaves the block to show again, never to vanish unseen.
    pub(super) fn spend(&self, server: &SyncServer) {
        let mut blocks = self.blocks.clone();
        for share in self.memories.values() {
            blocks.extend(share.blocks.iter().copied());
        }
        if let Err(error) = server.vault.record_board_hook_deliveries(&blocks) {
            tracing::warn!(kind = ?error.kind(), "mcp board hook delivery record failed");
        }
    }
}

/// Only the implemented, read-only claim family can enter this host's board.
/// Other typed pack recipes stay installed as source, not invented board data.
struct McpPackSectionBindings;
impl oneiron::context_board::SectionBindingResolver for McpPackSectionBindings {
    fn state_family_exists(&self, family: &oneiron::context_board::StateFamilyRef) -> bool {
        family.family == "claim" && family.version == 1
    }
    fn authority_lane_exists(&self, authority: &oneiron::context_board::AuthorityLaneRef) -> bool {
        authority.0 == "read"
    }
    fn budget_policy_exists(&self, budget: &oneiron::context_board::BudgetPolicyRef) -> bool {
        budget.0 == oneiron::context_board::PLUGIN_SECTION_BUDGET_POLICY_REF
    }
}

/// The pre-dispatch page state. A live cursor is consumed here, before the
/// producer is allowed to call a facade or mutate a registry. Its retained
/// snapshot is then used directly for the continuation, so no second producer
/// read can replace page one's result.
#[derive(Clone, Debug)]
pub(super) struct McpPageDispatchState {
    pub(super) continuation: Option<McpPageCursorState>,
    continuable: bool,
    pub(super) producer_epoch: Option<u64>,
}
