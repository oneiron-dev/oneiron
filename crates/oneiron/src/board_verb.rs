use crate::EntityId;
use crate::context_board::{
    BoardBlockHeader, BoardBudgetRequest, BoardFrame, BoardFrameError, BoardLegend, BoardRender,
    BoardSection, BoardSnapshot, BoardStreamFrame, BoardStreamRegistry, StreamConnectionId,
    render_board_block,
};
use crate::context_board::{SubscriptionError, SubscriptionReceipt, SubscriptionScope};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BoardWorldScope(EntityId);
impl BoardWorldScope {
    pub const fn single(world: EntityId) -> Self {
        Self(world)
    }
    pub const fn world(&self) -> EntityId {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoardVerbCall {
    Expand {
        key: String,
        frame_epoch: Option<u64>,
    },
    Refresh {
        frame_epoch: Option<u64>,
    },
    Subscribe {
        scopes: BTreeSet<SubscriptionScope>,
    },
    Unsubscribe {
        scopes: BTreeSet<SubscriptionScope>,
    },
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoardVerbOutput {
    Expanded { key: String, lines: Vec<String> },
    Frame(BoardStreamFrame),
    Subscription(SubscriptionReceipt),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoardVerbError {
    StaleFrame {
        observed_epoch: u64,
        current_epoch: u64,
    },
    CurrentTargetMissing {
        key: String,
        current_epoch: u64,
    },
    InvalidArguments {
        verb: &'static str,
        current_epoch: u64,
    },
    Source(String),
    SubscriptionOutsideAllowedSet {
        requested: BTreeSet<SubscriptionScope>,
        allowed: BTreeSet<SubscriptionScope>,
    },
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveBoardView {
    pub snapshot: BoardSnapshot,
    pub expansions: BTreeMap<String, Vec<String>>,
}
pub fn render_current_keyframe(
    header: &BoardBlockHeader,
    sections: &[BoardSection],
    request: BoardBudgetRequest,
) -> Result<BoardRender, BoardFrameError> {
    let legend = BoardLegend::canonical();
    render_board_block(
        &BoardFrame {
            changes: None,
            header,
            legend: &legend,
            sections,
        },
        request,
    )
}
pub trait LiveBoardSource {
    fn read_current(&self, scope: &BoardWorldScope) -> Result<LiveBoardView, BoardVerbError>;
}
pub struct BoardVerbContext<'a, S: LiveBoardSource> {
    pub connection: &'a StreamConnectionId,
    pub scope: &'a BoardWorldScope,
    pub source: &'a S,
    pub streams: &'a mut BoardStreamRegistry,
    pub budget: BoardBudgetRequest,
}
pub fn dispatch_board_verb<S: LiveBoardSource>(
    context: &mut BoardVerbContext<'_, S>,
    call: BoardVerbCall,
) -> Result<BoardVerbOutput, BoardVerbError> {
    if let BoardVerbCall::Subscribe { scopes } = call {
        return context
            .streams
            .subscribe(context.connection, &scopes)
            .map(BoardVerbOutput::Subscription)
            .map_err(|e| match e {
                SubscriptionError::ConnectionMissing(c) => {
                    BoardVerbError::Source(format!("missing connection: {c:?}"))
                }
                SubscriptionError::OutsideAllowedSet { requested, allowed } => {
                    BoardVerbError::SubscriptionOutsideAllowedSet { requested, allowed }
                }
            });
    }
    if let BoardVerbCall::Unsubscribe { scopes } = call {
        return context
            .streams
            .unsubscribe(context.connection, &scopes)
            .map(BoardVerbOutput::Subscription)
            .map_err(|e| match e {
                SubscriptionError::ConnectionMissing(c) => {
                    BoardVerbError::Source(format!("missing connection: {c:?}"))
                }
                SubscriptionError::OutsideAllowedSet { requested, allowed } => {
                    BoardVerbError::SubscriptionOutsideAllowedSet { requested, allowed }
                }
            });
    }
    let view = context.source.read_current(context.scope)?;
    let epoch = view.snapshot.epoch;
    match call {
        BoardVerbCall::Refresh { .. } => {
            let frame = view.snapshot.as_keyframe();
            context.streams.enqueue(context.connection, frame.clone());
            Ok(BoardVerbOutput::Frame(frame))
        }
        BoardVerbCall::Subscribe { .. } | BoardVerbCall::Unsubscribe { .. } => unreachable!(),
        BoardVerbCall::Expand { key, frame_epoch } => {
            if let Some(observed) = frame_epoch
                && observed != epoch
            {
                return Err(BoardVerbError::StaleFrame {
                    observed_epoch: observed,
                    current_epoch: epoch,
                });
            }
            match view.expansions.get(&key) {
                Some(lines) => Ok(BoardVerbOutput::Expanded {
                    key,
                    lines: lines.clone(),
                }),
                None => Err(BoardVerbError::CurrentTargetMissing {
                    key,
                    current_epoch: epoch,
                }),
            }
        }
    }
}
