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
pub const BOARD_VERBS: [&str; 4] = [
    "board.expand",
    "board.refresh",
    "board.subscribe",
    "board.unsubscribe",
];
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoardVerb {
    Expand,
    Refresh,
    Subscribe,
    Unsubscribe,
}
impl BoardVerb {
    pub const ALL: [Self; 4] = [
        Self::Expand,
        Self::Refresh,
        Self::Subscribe,
        Self::Unsubscribe,
    ];
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Expand => "board.expand",
            Self::Refresh => "board.refresh",
            Self::Subscribe => "board.subscribe",
            Self::Unsubscribe => "board.unsubscribe",
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context_board::BoardBudgetRequest;
    struct Source {
        view: LiveBoardView,
    }
    impl LiveBoardSource for Source {
        fn read_current(&self, _: &BoardWorldScope) -> Result<LiveBoardView, BoardVerbError> {
            Ok(self.view.clone())
        }
    }
    fn setup() -> (
        Source,
        BoardWorldScope,
        StreamConnectionId,
        BoardStreamRegistry,
    ) {
        let mut rows = BTreeMap::new();
        rows.insert("present".into(), "line".into());
        (
            Source {
                view: LiveBoardView {
                    snapshot: BoardSnapshot {
                        epoch: 7,
                        keyframe: "full".into(),
                        rows,
                    },
                    expansions: BTreeMap::new(),
                },
            },
            BoardWorldScope::single(crate::EntityId::from_bytes([3; 16]).expect("valid")),
            StreamConnectionId("test".into()),
            BoardStreamRegistry::default(),
        )
    }
    #[test]
    fn two_refreshes_same_epoch() {
        let (source, scope, connection, mut streams) = setup();
        streams.attach_connection(
            connection.clone(),
            crate::context_board::BoardRenderMode::Stream,
            "actor".into(),
            BTreeSet::new(),
            0,
        );
        let req = BoardBudgetRequest {
            harness_default_tok: 100,
            caller_limit_tok: None,
            explicit_override_tok: None,
        };
        let mut c = BoardVerbContext {
            connection: &connection,
            scope: &scope,
            source: &source,
            streams: &mut streams,
            budget: req,
        };
        let a = dispatch_board_verb(
            &mut c,
            BoardVerbCall::Refresh {
                frame_epoch: Some(1),
            },
        )
        .expect("refresh");
        let b = dispatch_board_verb(
            &mut c,
            BoardVerbCall::Refresh {
                frame_epoch: Some(2),
            },
        )
        .expect("refresh");
        assert_eq!(a, b);
        assert_eq!(source.view.snapshot.epoch, 7);
    }
    #[test]
    fn stale_refresh_and_expand_missing() {
        let (source, scope, connection, mut streams) = setup();
        streams.attach_connection(
            connection.clone(),
            crate::context_board::BoardRenderMode::Stream,
            "actor".into(),
            BTreeSet::new(),
            0,
        );
        let req = BoardBudgetRequest {
            harness_default_tok: 100,
            caller_limit_tok: None,
            explicit_override_tok: None,
        };
        let mut c = BoardVerbContext {
            connection: &connection,
            scope: &scope,
            source: &source,
            streams: &mut streams,
            budget: req,
        };
        assert!(matches!(
            dispatch_board_verb(
                &mut c,
                BoardVerbCall::Refresh {
                    frame_epoch: Some(1)
                }
            ),
            Ok(BoardVerbOutput::Frame(_))
        ));
        assert!(matches!(
            dispatch_board_verb(
                &mut c,
                BoardVerbCall::Expand {
                    key: "old".into(),
                    frame_epoch: Some(6)
                }
            ),
            Err(BoardVerbError::StaleFrame { .. })
        ));
        assert!(matches!(
            dispatch_board_verb(
                &mut c,
                BoardVerbCall::Expand {
                    key: "old".into(),
                    frame_epoch: None
                }
            ),
            Err(BoardVerbError::CurrentTargetMissing { .. })
        ));
    }
    #[test]
    fn subscription_verbs_are_sorted_agent_free_and_typed() {
        assert_eq!(
            BOARD_VERBS,
            [
                "board.expand",
                "board.refresh",
                "board.subscribe",
                "board.unsubscribe"
            ]
        );
        let (source, scope, connection, mut streams) = setup();
        streams.attach_connection(
            connection.clone(),
            crate::context_board::BoardRenderMode::Stream,
            "actor".into(),
            BTreeSet::from([SubscriptionScope::MyTasks]),
            0,
        );
        let mut context = BoardVerbContext {
            connection: &connection,
            scope: &scope,
            source: &source,
            streams: &mut streams,
            budget: BoardBudgetRequest {
                harness_default_tok: 1,
                caller_limit_tok: None,
                explicit_override_tok: None,
            },
        };
        let forbidden = BTreeSet::from([SubscriptionScope::Counts]);
        assert!(matches!(
            dispatch_board_verb(&mut context, BoardVerbCall::Subscribe { scopes: forbidden }),
            Err(BoardVerbError::SubscriptionOutsideAllowedSet { .. })
        ));
        assert!(matches!(
            dispatch_board_verb(
                &mut context,
                BoardVerbCall::Unsubscribe {
                    scopes: BTreeSet::from([SubscriptionScope::MyTasks])
                }
            ),
            Ok(BoardVerbOutput::Subscription(_))
        ));
    }
}
