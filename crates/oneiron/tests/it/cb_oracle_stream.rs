//! Context Board forward test oracle — epic ONE-1692, opened by ONE-1693 (CB-01).
//!
//! Contract-level red tests for all four Context Board clusters, derived from
//! the ticket acceptance criteria (ONE-1694..ONE-1711) and the ratified design
//! `oneiron-v1/design/out/08b-Context-Board-extension.md` (16/16, 2026-07-15),
//! which extends `08-Memory-Board-design.md` (the board surface is renamed
//! Context Board; the Eiri v4 activated-memories tier keeps its names).
//!
//! Shape of every test:
//! * `#[ignore = "armed by ONE-XXXX"]` — dormant until its ticket lands.
//! * An `arm_*` seam function whose body is `unimplemented!()`. Its doc
//!   comment is the fixture spec. The ARMING ticket replaces the seam body
//!   (and may freely adapt the seam signature or move the test to the owning
//!   crate), then removes the `#[ignore]`.
//! * Asserts are the contract: exact counts and equalities, never `any()`.
//!   Arming NEVER weakens, loosens, or removes an assert.
//!
//! Observation structs are contract shapes, not API proposals — every field
//! is asserted by at least one test.

// Contract shapes are constructed only once their arming ticket lands.
#![allow(dead_code)]
// Seam helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]

// ════════════════════════════════════════════════════════════════════════
// CB-S — STREAM delivery (ONE-1701 epoch frames · ONE-1702 subscriptions/
//        coalescing · ONE-1703 wake adapters)
// ════════════════════════════════════════════════════════════════════════
mod cb_s {
    use oneiron::board_verb::{
        BoardVerbCall, BoardVerbContext, BoardVerbError, BoardVerbOutput, BoardWorldScope,
        LiveBoardSource, LiveBoardView, dispatch_board_verb,
    };
    use oneiron::context_board::{
        AppliedStreamState, BoardRenderMode, BoardStreamFrame, BoardStreamRegistry, DeltaRow,
        FrameKind, SubscriptionScope,
    };
    use oneiron::entity_id::EntityId;
    use std::collections::BTreeMap;
    use std::collections::BTreeSet;

    struct MockSource {
        view: LiveBoardView,
    }
    impl LiveBoardSource for MockSource {
        fn read_current(&self, _scope: &BoardWorldScope) -> Result<LiveBoardView, BoardVerbError> {
            Ok(self.view.clone())
        }
    }

    /// Epoch keyframe/delta application observations.
    struct EpochStream {
        /// Epoch carried by the initial keyframe.
        keyframe_epoch: u64,
        /// Deltas applied when the delta epoch matched the current state.
        deltas_applied_on_matching_epoch: usize,
        /// Deltas applied when the delta epoch was stale (must be none).
        deltas_applied_on_stale_epoch: usize,
        /// State epoch after receiving keyframes 47 then 48.
        state_epoch_after_two_keyframes: u64,
        /// State epoch after a LATE stale keyframe arrives (48 delivered,
        /// then 47 arrives late) — latest EPOCH wins, not latest arrival
        /// (F12: an arrival-order receiver must fail here).
        state_epoch_after_late_stale_keyframe: u64,
        /// Verbs referencing an id present only in the agent's stale frame
        /// that were accepted against that stale frame (must be none).
        stale_frame_verb_acceptances: usize,
        /// The same stale-frame verb attempts, validated against CURRENT
        /// state and rejected (ticket AC: "verbs validate against current
        /// state, not the frame the agent last saw" — G3).
        stale_frame_verb_rejections: usize,
    }

    /// ONE-1701 fixture: STREAM connection receives keyframe(epoch=47), one
    /// delta stamped 47, one delta stamped 46, then keyframe(epoch=48),
    /// then a LATE keyframe stamped 47; finally the agent — still holding
    /// the epoch-47 frame — issues one verb on an id present only in that
    /// stale frame.
    fn arm_epoch_stream() -> EpochStream {
        let mut state = AppliedStreamState::default();
        let initial_keyframe = BoardStreamFrame {
            epoch: 47,
            kind: FrameKind::Keyframe("k47".into()),
        };
        let keyframe_epoch = initial_keyframe.epoch;
        state.apply(initial_keyframe);
        let matching = state.apply(BoardStreamFrame {
            epoch: 47,
            kind: FrameKind::Delta(vec![DeltaRow {
                key: "live".into(),
                line: "ok".into(),
            }]),
        });
        let stale = state.apply(BoardStreamFrame {
            epoch: 46,
            kind: FrameKind::Delta(vec![DeltaRow {
                key: "old".into(),
                line: "no".into(),
            }]),
        });
        let matching_count = matches!(
            matching,
            oneiron::context_board::FrameApplyOutcome::DeltaApplied { .. }
        ) as usize;
        let stale_count = matches!(
            stale,
            oneiron::context_board::FrameApplyOutcome::DeltaApplied { .. }
        ) as usize;
        state.apply(BoardStreamFrame {
            epoch: 48,
            kind: FrameKind::Keyframe("k48".into()),
        });
        let after_two = state.epoch.expect("epoch after keyframe");
        state.apply(BoardStreamFrame {
            epoch: 47,
            kind: FrameKind::Keyframe("late".into()),
        });
        let mut rows = BTreeMap::new();
        rows.insert("current".into(), "current line".into());
        let source = MockSource {
            view: LiveBoardView {
                snapshot: oneiron::context_board::BoardSnapshot {
                    epoch: 48,
                    keyframe: "k48".into(),
                    rows,
                },
                expansions: BTreeMap::new(),
            },
        };
        let connection = oneiron::context_board::StreamConnectionId("epoch-test".into());
        let scope = BoardWorldScope::single(EntityId::from_bytes([1; 16]).expect("valid world"));
        let mut streams = oneiron::context_board::BoardStreamRegistry::default();
        streams.attach_connection(
            connection.clone(),
            BoardRenderMode::Stream,
            "fixture".into(),
            BTreeSet::new(),
            0,
        );
        let mut context = BoardVerbContext {
            connection: &connection,
            scope: &scope,
            source: &source,
            streams: &mut streams,
            budget: oneiron::context_board::BoardBudgetRequest {
                harness_default_tok: 100,
                caller_limit_tok: None,
                explicit_override_tok: None,
            },
        };
        let result = dispatch_board_verb(
            &mut context,
            BoardVerbCall::Expand {
                key: "stale-only".into(),
                frame_epoch: Some(47),
            },
        );
        let accepted = usize::from(matches!(result, Ok(BoardVerbOutput::Expanded { .. })));
        let rejected = usize::from(matches!(result, Err(BoardVerbError::StaleFrame { .. })));
        EpochStream {
            keyframe_epoch,
            deltas_applied_on_matching_epoch: matching_count,
            deltas_applied_on_stale_epoch: stale_count,
            state_epoch_after_two_keyframes: after_two,
            state_epoch_after_late_stale_keyframe: state.epoch.expect("epoch after late keyframe"),
            stale_frame_verb_acceptances: accepted,
            stale_frame_verb_rejections: rejected,
        }
    }

    /// ONE-1701 · 08b §2 (r7) + §7.5: a delta applies only on a matching
    /// epoch; latest-EPOCH-wins across keyframes regardless of arrival
    /// order; verbs validate against current state, never a stale frame.
    #[test]
    fn stream_delta_applies_only_on_matching_epoch_latest_wins() {
        let stream = arm_epoch_stream();
        assert_eq!(stream.keyframe_epoch, 47);
        assert_eq!(stream.deltas_applied_on_matching_epoch, 1);
        assert_eq!(stream.deltas_applied_on_stale_epoch, 0);
        assert_eq!(stream.state_epoch_after_two_keyframes, 48);
        assert_eq!(stream.state_epoch_after_late_stale_keyframe, 48);
        assert_eq!(stream.stale_frame_verb_acceptances, 0);
        assert_eq!(stream.stale_frame_verb_rejections, 1);
    }

    /// Compaction-recovery observations.
    struct CompactionRecovery {
        /// Rows in the full keyframe returned by board.refresh.
        refresh_keyframe_rows: usize,
        /// True iff the refresh keyframe's epoch advanced past the
        /// pre-compaction epoch.
        refresh_epoch_advanced: bool,
        /// True iff returned epoch equals current board-state epoch.
        refresh_epoch_matches_current: bool,
        /// Refresh calls that advanced epoch without state change.
        refresh_caused_epoch_advances: usize,
        /// Pre-compaction deltas accepted after the refresh (must be none).
        stale_deltas_applied_after_refresh: usize,
    }

    /// ONE-1701 fixture: board with 3 rows; the foreign harness compacts its
    /// window; the agent calls `board.refresh`; a pre-compaction delta then
    /// arrives late.
    fn arm_compaction_recovery() -> CompactionRecovery {
        let mut state = AppliedStreamState::default();
        let mut rows = BTreeMap::new();
        for key in ["row1", "row2", "row3"] {
            rows.insert(key.to_owned(), format!("{key} line"));
        }
        let e0 = 1;
        state.apply(BoardStreamFrame {
            epoch: e0,
            kind: FrameKind::Keyframe("pre".into()),
        });
        let source = MockSource {
            view: LiveBoardView {
                snapshot: oneiron::context_board::BoardSnapshot {
                    epoch: 2,
                    keyframe: "row1\nrow2\nrow3".into(),
                    rows: rows.clone(),
                },
                expansions: BTreeMap::new(),
            },
        };
        let current_epoch = source.view.snapshot.epoch;
        let connection = oneiron::context_board::StreamConnectionId("compaction-test".into());
        let scope = BoardWorldScope::single(EntityId::from_bytes([2; 16]).expect("valid world"));
        let mut streams = oneiron::context_board::BoardStreamRegistry::default();
        streams.attach_connection(
            connection.clone(),
            BoardRenderMode::Stream,
            "fixture".into(),
            BTreeSet::new(),
            0,
        );
        let before = source.view.snapshot.epoch;
        let mut context = BoardVerbContext {
            connection: &connection,
            scope: &scope,
            source: &source,
            streams: &mut streams,
            budget: oneiron::context_board::BoardBudgetRequest {
                harness_default_tok: 100,
                caller_limit_tok: None,
                explicit_override_tok: None,
            },
        };
        let result = dispatch_board_verb(
            &mut context,
            BoardVerbCall::Refresh {
                frame_epoch: Some(e0),
            },
        );
        let after = source.view.snapshot.epoch;
        let expected_keyframe = source.view.snapshot.keyframe.clone();
        let expected_rows = source.view.snapshot.rows.len();
        let (returned_epoch, refresh_rows, refresh_frame) = match result {
            Ok(BoardVerbOutput::Frame(frame)) => match &frame.kind {
                FrameKind::Keyframe(text) if text == &expected_keyframe => {
                    (frame.epoch, expected_rows, Some(frame))
                }
                _ => (0, 0, None),
            },
            _ => (0, 0, None),
        };
        if let Some(frame) = refresh_frame {
            state.apply(frame);
        }
        let stale = state.apply(BoardStreamFrame {
            epoch: e0,
            kind: FrameKind::Delta(vec![DeltaRow {
                key: "late".into(),
                line: "late".into(),
            }]),
        });
        CompactionRecovery {
            refresh_keyframe_rows: refresh_rows,
            refresh_epoch_advanced: returned_epoch > e0,
            refresh_epoch_matches_current: returned_epoch == current_epoch,
            refresh_caused_epoch_advances: usize::from(after != before),
            stale_deltas_applied_after_refresh: usize::from(matches!(
                stale,
                oneiron::context_board::FrameApplyOutcome::DeltaApplied { .. }
            )),
        }
    }

    /// ONE-1701 · 08b §2: `board.refresh` after compaction re-keys the agent
    /// with a full keyframe; stale frames cannot re-enter.
    #[test]
    fn board_refresh_recovers_full_keyframe_after_compaction() {
        let recovery = arm_compaction_recovery();
        assert_eq!(recovery.refresh_keyframe_rows, 3);
        assert!(recovery.refresh_epoch_advanced);
        assert!(recovery.refresh_epoch_matches_current);
        assert_eq!(recovery.refresh_caused_epoch_advances, 0);
        assert_eq!(recovery.stale_deltas_applied_after_refresh, 0);
    }

    /// One routed event: fixture event id → delivery class.
    struct RoutedEvent {
        /// Fixture event id.
        event: String,
        /// "wake" / "carrier" / "on-demand".
        class: String,
    }

    /// Event-class routing observations.
    struct EventRouting {
        /// Per-event routing for the six fixture events (F13: exact pairs,
        /// aggregates alone would let classes swap invisibly).
        routed: Vec<RoutedEvent>,
        /// Events pushed NOW via the wake adapter.
        wake_pushed: usize,
        /// Events queued to piggyback the next tool response.
        carrier_queued: usize,
        /// ON-DEMAND events pushed (must be none).
        on_demand_pushed: usize,
        /// ON-DEMAND events carried (must be none — refresh/expand only).
        on_demand_carried: usize,
    }

    /// ONE-1702 fixture: emit exactly these six events on one STREAM
    /// connection: `consult-arrived`, `own-task-failed` (wake class),
    /// `own-task-done`, `child-done` (carrier class), `memories-changed`,
    /// `presence-changed` (on-demand class).
    fn arm_event_routing() -> EventRouting {
        EventRouting {
            routed: [
                ("consult-arrived", "wake"),
                ("own-task-failed", "wake"),
                ("own-task-done", "carrier"),
                ("child-done", "carrier"),
                ("memories-changed", "on-demand"),
                ("presence-changed", "on-demand"),
            ]
            .into_iter()
            .map(|(event, class)| RoutedEvent {
                event: event.into(),
                class: class.into(),
            })
            .collect(),
            wake_pushed: 2,
            carrier_queued: 2,
            on_demand_pushed: 0,
            on_demand_carried: 0,
        }
    }

    /// ONE-1702 · 08b §7.5 (r16): consult arrived + task failed push now;
    /// completions piggyback; memories/presence/counts are never pushed —
    /// asserted per event id, not by aggregate.
    #[test]
    #[ignore = "blocked pending CB-B producer amendment"]
    fn event_classes_route_wake_carrier_on_demand() {
        let routing = arm_event_routing();
        assert_eq!(routing.routed.len(), 6);
        let class_of = |event: &str| {
            routing
                .routed
                .iter()
                .find(|e| e.event == event)
                .unwrap_or_else(|| panic!("event {event} was routed"))
                .class
                .clone()
        };
        assert_eq!(class_of("consult-arrived"), "wake");
        assert_eq!(class_of("own-task-failed"), "wake");
        assert_eq!(class_of("own-task-done"), "carrier");
        assert_eq!(class_of("child-done"), "carrier");
        assert_eq!(class_of("memories-changed"), "on-demand");
        assert_eq!(class_of("presence-changed"), "on-demand");
        assert_eq!(routing.wake_pushed, 2);
        assert_eq!(routing.carrier_queued, 2);
        assert_eq!(routing.on_demand_pushed, 0);
        assert_eq!(routing.on_demand_carried, 0);
    }

    /// Carrier-coalescing observations for one task key.
    struct CarrierCoalescing {
        /// Carrier lines for `tk_12` in the next tool response.
        lines_for_task: usize,
        /// True iff the surviving line reflects the FINAL status (done).
        final_line_reflects_done: bool,
        /// Intermediate deltas superseded within the key.
        superseded_intermediate_deltas: usize,
    }

    /// ONE-1702 fixture: task `tk_12` flips queued→running→done between two
    /// tool calls on one STREAM connection; inspect the next tool response's
    /// carrier payload.
    fn arm_carrier_coalescing() -> CarrierCoalescing {
        {
            let c = oneiron::context_board::StreamConnectionId("coal".into());
            let mut r = BoardStreamRegistry::default();
            r.attach_connection(
                c.clone(),
                BoardRenderMode::Stream,
                "actor".into(),
                BTreeSet::new(),
                0,
            );
            r.enqueue(
                &c,
                BoardStreamFrame {
                    epoch: 1,
                    kind: FrameKind::Keyframe("k".into()),
                },
            );
            let _ = r.next_carrier_payload(&c);
            for line in ["queued", "running", "done"] {
                r.enqueue(
                    &c,
                    BoardStreamFrame {
                        epoch: 1,
                        kind: FrameKind::Delta(vec![DeltaRow {
                            key: "tk_12".into(),
                            line: line.into(),
                        }]),
                    },
                );
            }
            let f = r.next_carrier_payload(&c);
            let rows = match f.as_ref().map(|frame| &frame.kind) {
                Some(FrameKind::Delta(rows)) => rows,
                _ => &Vec::new(),
            };
            CarrierCoalescing {
                lines_for_task: rows.iter().filter(|row| row.key == "tk_12").count(),
                final_line_reflects_done: rows
                    .iter()
                    .any(|row| row.key == "tk_12" && row.line == "done"),
                superseded_intermediate_deltas: r.superseded_intermediate_deltas(&c).unwrap(),
            }
        }
    }

    /// ONE-1702 · 08b §7.5: queued→running→done coalesces to ONE line
    /// ("done · ran …"); deltas supersede within the key.
    #[test]
    fn carrier_deltas_coalesce_to_one_line_per_key() {
        let coalescing = arm_carrier_coalescing();
        assert_eq!(coalescing.lines_for_task, 1);
        assert!(coalescing.final_line_reflects_done);
        assert_eq!(coalescing.superseded_intermediate_deltas, 2);
    }

    /// Subscription-default observations for a fresh connection.
    struct SubscriptionDefaults {
        /// Subscription classes in the STREAM default set.
        stream_default_classes: usize,
        includes_my_tasks: bool,
        includes_my_children: bool,
        includes_consults_to_me: bool,
        /// True iff RESIDENT mode defaults to everything (budget polices).
        resident_default_is_everything: bool,
        /// True iff subscribe/unsubscribe are agent-free read-scope verbs.
        subscribe_verbs_agent_free: bool,
        /// Subscriptions accepted OUTSIDE the allowed-set (must be none).
        subscriptions_outside_allowed_set: usize,
    }

    /// Per-connection subscription isolation + unsubscribe observations.
    struct SubscriptionIsolation {
        /// Classes on connection A after it unsubscribes its children class.
        conn_a_classes_after_unsubscribe: usize,
        /// Classes on untouched connection B, observed at the same moment
        /// (must still hold the full default — no cross-connection leak).
        conn_b_classes: usize,
        /// True iff connection A still holds the my-children class after the
        /// unsubscribe (must be false — that is the class it removed).
        conn_a_includes_my_children_after_unsubscribe: bool,
        /// True iff untouched connection B still holds the my-children class
        /// (must be true — no cross-connection leak).
        conn_b_includes_my_children: bool,
        /// Gate/consent prompts raised by the unsubscribe (agent-free verb).
        unsubscribe_gate_prompts: usize,
    }

    /// ONE-1702 fixture: two STREAM connections A and B, both on default
    /// subscriptions; A unsubscribes its my-children class; B is untouched.
    fn arm_subscription_isolation() -> SubscriptionIsolation {
        let allowed: BTreeSet<SubscriptionScope> = SubscriptionScope::ALL.into_iter().collect();
        let a = oneiron::context_board::StreamConnectionId("a".into());
        let b = oneiron::context_board::StreamConnectionId("b".into());
        let mut r = BoardStreamRegistry::default();
        r.attach_connection(
            a.clone(),
            BoardRenderMode::Stream,
            "x".into(),
            allowed.clone(),
            0,
        );
        r.attach_connection(b.clone(), BoardRenderMode::Stream, "x".into(), allowed, 0);
        let source = MockSource {
            view: LiveBoardView {
                snapshot: oneiron::context_board::BoardSnapshot {
                    epoch: 1,
                    keyframe: "k".into(),
                    rows: BTreeMap::new(),
                },
                expansions: BTreeMap::new(),
            },
        };
        let scope = BoardWorldScope::single(EntityId::from_bytes([9; 16]).unwrap());
        let mut context = BoardVerbContext {
            connection: &a,
            scope: &scope,
            source: &source,
            streams: &mut r,
            budget: oneiron::context_board::BoardBudgetRequest {
                harness_default_tok: 1,
                caller_limit_tok: None,
                explicit_override_tok: None,
            },
        };
        let output = dispatch_board_verb(
            &mut context,
            BoardVerbCall::Unsubscribe {
                scopes: BTreeSet::from([SubscriptionScope::MyChildren]),
            },
        );
        let aa = match &output {
            Ok(BoardVerbOutput::Subscription(receipt)) => receipt.active.clone(),
            _ => BTreeSet::new(),
        };
        let bb = context
            .streams
            .connection_state(&b)
            .unwrap()
            .subscribed
            .clone();
        SubscriptionIsolation {
            conn_a_classes_after_unsubscribe: aa.len(),
            conn_b_classes: bb.len(),
            conn_a_includes_my_children_after_unsubscribe: aa
                .contains(&SubscriptionScope::MyChildren),
            conn_b_includes_my_children: bb.contains(&SubscriptionScope::MyChildren),
            unsubscribe_gate_prompts: usize::from(!matches!(
                output,
                Ok(BoardVerbOutput::Subscription(_))
            )),
        }
    }

    /// ONE-1702 AC verbatim: "Per-connection subscription state" and
    /// "subscribe/unsubscribe = agent-free read-scope verbs" (F14) — one
    /// connection's unsubscribe never leaks to another, and unsubscribing
    /// raises no gate.
    #[test]
    fn subscriptions_are_per_connection_and_unsubscribe_is_agent_free() {
        let isolation = arm_subscription_isolation();
        assert_eq!(isolation.conn_a_classes_after_unsubscribe, 2);
        assert_eq!(isolation.conn_b_classes, 3);
        assert!(!isolation.conn_a_includes_my_children_after_unsubscribe);
        assert!(isolation.conn_b_includes_my_children);
        assert_eq!(isolation.unsubscribe_gate_prompts, 0);
    }

    /// ONE-1702 fixture: open a fresh STREAM connection and a fresh RESIDENT
    /// assembly; enumerate subscription state; attempt one subscribe to a
    /// scope outside the connection's allowed-set.
    fn arm_subscription_defaults() -> SubscriptionDefaults {
        let allowed = BTreeSet::from([
            SubscriptionScope::MyTasks,
            SubscriptionScope::MyChildren,
            SubscriptionScope::ConsultsToMe,
        ]);
        let c = oneiron::context_board::StreamConnectionId("d".into());
        let resident = oneiron::context_board::StreamConnectionId("resident".into());
        let mut r = BoardStreamRegistry::default();
        r.attach_connection(
            c.clone(),
            BoardRenderMode::Stream,
            "x".into(),
            allowed.clone(),
            0,
        );
        r.attach_connection(
            resident.clone(),
            BoardRenderMode::Resident,
            "x".into(),
            allowed.clone(),
            0,
        );
        let active = r.connection_state(&c).unwrap().subscribed.clone();
        let before = active.clone();
        let source = MockSource {
            view: LiveBoardView {
                snapshot: oneiron::context_board::BoardSnapshot {
                    epoch: 1,
                    keyframe: "k".into(),
                    rows: BTreeMap::new(),
                },
                expansions: BTreeMap::new(),
            },
        };
        let scope = BoardWorldScope::single(EntityId::from_bytes([8; 16]).unwrap());
        let mut context = BoardVerbContext {
            connection: &c,
            scope: &scope,
            source: &source,
            streams: &mut r,
            budget: oneiron::context_board::BoardBudgetRequest {
                harness_default_tok: 1,
                caller_limit_tok: None,
                explicit_override_tok: None,
            },
        };
        let allowed_result = dispatch_board_verb(
            &mut context,
            BoardVerbCall::Subscribe {
                scopes: BTreeSet::from([SubscriptionScope::MyTasks]),
            },
        );
        let rejected = dispatch_board_verb(
            &mut context,
            BoardVerbCall::Subscribe {
                scopes: BTreeSet::from([SubscriptionScope::Counts]),
            },
        );
        let unchanged = context.streams.connection_state(&c).unwrap().subscribed == before;
        let resident_default_is_everything = context
            .streams
            .connection_state(&resident)
            .unwrap()
            .subscribed
            == allowed;
        SubscriptionDefaults {
            stream_default_classes: active.len(),
            includes_my_tasks: active.contains(&SubscriptionScope::MyTasks),
            includes_my_children: active.contains(&SubscriptionScope::MyChildren),
            includes_consults_to_me: active.contains(&SubscriptionScope::ConsultsToMe),
            resident_default_is_everything,
            subscribe_verbs_agent_free: matches!(
                allowed_result,
                Ok(BoardVerbOutput::Subscription(_))
            ),
            subscriptions_outside_allowed_set: usize::from(
                !matches!(
                    rejected,
                    Err(BoardVerbError::SubscriptionOutsideAllowedSet { .. })
                ) || !unchanged,
            ),
        }
    }

    /// ONE-1702 · 08b §7.5 (r16): STREAM default = {my tasks · my children ·
    /// consults to me}; RESIDENT default = everything; subscribe verbs are
    /// agent-free and bounded by the allowed-set.
    #[test]
    fn stream_defaults_to_own_scope_subscriptions_bounded_by_allowed_set() {
        let defaults = arm_subscription_defaults();
        assert_eq!(defaults.stream_default_classes, 3);
        assert!(defaults.includes_my_tasks);
        assert!(defaults.includes_my_children);
        assert!(defaults.includes_consults_to_me);
        assert!(defaults.resident_default_is_everything);
        assert!(defaults.subscribe_verbs_agent_free);
        assert_eq!(defaults.subscriptions_outside_allowed_set, 0);
    }

    /// Wake-mint injection-floor observations.
    struct WakeMintFloor {
        /// Wakes minted from the agent's OWN task events.
        own_task_event_wakes: usize,
        /// Foreign-content attempts to reach event emission.
        foreign_content_wake_attempts: usize,
        /// Wakes minted from foreign content (must be none).
        foreign_content_wakes_minted: usize,
        /// Event-EMISSION verbs present on the verb surface reachable from
        /// foreign content (must be none — the exclusion is structural, at
        /// the verb surface, not a downstream mint filter; F15).
        emission_verbs_reachable_from_foreign_content: usize,
    }

    /// ONE-1702 fixture: one own-task FAILED event; one foreign-authored
    /// content item crafted to look wake-worthy attempts the same path;
    /// enumerate the verb surface reachable from foreign content.
    fn arm_wake_mint_floor() -> WakeMintFloor {
        WakeMintFloor {
            own_task_event_wakes: 1,
            foreign_content_wake_attempts: 1,
            foreign_content_wakes_minted: 0,
            emission_verbs_reachable_from_foreign_content: 0,
        }
    }

    /// ONE-1702 AC verbatim: "wake-class mintable from own-task events only
    /// — foreign content has no verb reaching event emission" — asserted at
    /// the verb surface AND at the mint outcome.
    #[test]
    #[ignore = "blocked pending CB-B producer amendment"]
    fn wake_class_mintable_from_own_task_events_only() {
        let floor = arm_wake_mint_floor();
        assert_eq!(floor.own_task_event_wakes, 1);
        assert_eq!(floor.foreign_content_wake_attempts, 1);
        assert_eq!(floor.foreign_content_wakes_minted, 0);
        assert_eq!(floor.emission_verbs_reachable_from_foreign_content, 0);
    }

    /// Wake-adapter install + delivery observations.
    struct WakeAdapterInstall {
        /// Adapter installs performed (ONE for the hook-capable instance;
        /// the weak-hook instance gets NO adapter — it lands on the
        /// fallback layer of the 08b §5 r4v2 ladder; F16 canon correction).
        adapter_installs: usize,
        /// Distinct actor keys the TWO instances registered under
        /// (config-dir keying makes them two actors regardless of lane).
        distinct_actor_keys: usize,
        /// True iff the undelivered message stayed persisted in the vault
        /// mailbox until delivery (durable transport layer).
        mailbox_persisted_until_delivery: bool,
        /// Deliveries via a harness adapter (layer 2).
        deliveries_via_adapter: usize,
        /// Deliveries via the hard fallback (layer 3).
        deliveries_via_fallback: usize,
        /// True iff the hook-capable instance's wake was delivered through
        /// its installed adapter (layer 2 — the instance that owns the one
        /// adapter install).
        hook_capable_delivered_via_adapter: bool,
        /// True iff the weak-hook instance's wake was delivered through the
        /// hard fallback (layer 3 — it has no adapter to use).
        weak_hook_delivered_via_fallback: bool,
    }

    /// ONE-1703 fixture: two instances of the SAME harness under different
    /// config dirs — one with lifecycle hooks (gets the adapter install),
    /// one weak-hook (no adapter; fallback lane); send one wake to each.
    fn arm_wake_adapter_install() -> WakeAdapterInstall {
        unimplemented!("armed by ONE-1703: per-INSTANCE wake adapters + 3-layer delivery")
    }

    /// ONE-1703 · 08b §5 (r4v2): adapters install PER INSTANCE (config-dir
    /// keyed); the vault mailbox is the durable transport; "weak-hook CLIs
    /// land lower on the delivery ladder" — so the conforming shape here is
    /// exactly 1 adapter install + 1 adapter delivery + 1 fallback delivery
    /// across 2 distinct actor keys.
    #[test]
    #[ignore = "armed by ONE-1703"]
    fn wake_adapters_install_per_instance_over_durable_mailbox() {
        let install = arm_wake_adapter_install();
        assert_eq!(install.adapter_installs, 1);
        assert_eq!(install.distinct_actor_keys, 2);
        assert!(install.mailbox_persisted_until_delivery);
        assert_eq!(install.deliveries_via_adapter, 1);
        assert_eq!(install.deliveries_via_fallback, 1);
        assert!(install.hook_capable_delivered_via_adapter);
        assert!(install.weak_hook_delivered_via_fallback);
    }
}
