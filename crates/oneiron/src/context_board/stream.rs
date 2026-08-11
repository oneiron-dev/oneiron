use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, VecDeque};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoardRenderMode {
    Resident,
    Stream,
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StreamConnectionId(pub String);
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoardStreamFrame {
    pub epoch: u64,
    pub kind: FrameKind,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
pub enum FrameKind {
    Keyframe(String),
    Delta(Vec<DeltaRow>),
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeltaRow {
    pub key: String,
    pub line: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoardSnapshot {
    pub epoch: u64,
    pub keyframe: String,
    pub rows: BTreeMap<String, String>,
}
impl BoardSnapshot {
    pub fn as_keyframe(&self) -> BoardStreamFrame {
        BoardStreamFrame {
            epoch: self.epoch,
            kind: FrameKind::Keyframe(self.keyframe.clone()),
        }
    }
    pub fn frame_since(&self, previous: Option<&Self>) -> Option<BoardStreamFrame> {
        let Some(old) = previous else {
            return Some(self.as_keyframe());
        };
        if old.epoch != self.epoch || old.rows.keys().any(|k| !self.rows.contains_key(k)) {
            return Some(self.as_keyframe());
        }
        // Fence before ordering: post-fence collisions use last-write-wins,
        // matching the delta overlay's insertion semantics.
        let mut fenced_rows = BTreeMap::new();
        for (key, line) in self
            .rows
            .iter()
            .filter(|(key, line)| old.rows.get(*key) != Some(*line))
        {
            fenced_rows.insert(super::one_line_token(key), super::one_line_token(line));
        }
        let rows = fenced_rows
            .into_iter()
            .map(|(key, line)| DeltaRow { key, line })
            .collect::<Vec<_>>();
        (!rows.is_empty()).then_some(BoardStreamFrame {
            epoch: self.epoch,
            kind: FrameKind::Delta(rows),
        })
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameApplyOutcome {
    KeyframeTaken { previous_epoch: Option<u64> },
    DeltaApplied { rows: usize },
    IgnoredStale { held_epoch: Option<u64> },
    IgnoredUntilKeyframe { held_epoch: Option<u64> },
}
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AppliedStreamState {
    pub epoch: Option<u64>,
    pub keyframe: Option<String>,
    pub delta_overlay: BTreeMap<String, String>,
}
impl AppliedStreamState {
    pub fn apply(&mut self, frame: BoardStreamFrame) -> FrameApplyOutcome {
        match frame.kind {
            FrameKind::Keyframe(text) => {
                if self.epoch.is_some_and(|e| frame.epoch < e) {
                    return FrameApplyOutcome::IgnoredStale {
                        held_epoch: self.epoch,
                    };
                }
                let old = self.epoch;
                self.epoch = Some(frame.epoch);
                self.keyframe = Some(text);
                self.delta_overlay.clear();
                FrameApplyOutcome::KeyframeTaken {
                    previous_epoch: old,
                }
            }
            FrameKind::Delta(rows) => {
                if self.epoch != Some(frame.epoch) {
                    return if self.epoch.is_some_and(|e| frame.epoch < e) {
                        FrameApplyOutcome::IgnoredStale {
                            held_epoch: self.epoch,
                        }
                    } else {
                        FrameApplyOutcome::IgnoredUntilKeyframe {
                            held_epoch: self.epoch,
                        }
                    };
                }
                let n = rows.len();
                for row in rows {
                    self.delta_overlay.insert(
                        super::one_line_token(&row.key),
                        super::one_line_token(&row.line),
                    );
                }
                FrameApplyOutcome::DeltaApplied { rows: n }
            }
        }
    }
}
#[derive(Debug, Default)]
struct PendingFrames {
    epoch: Option<u64>,
    frames: VecDeque<BoardStreamFrame>,
}
#[derive(Debug, Default)]
pub struct BoardStreamRegistry {
    connections: HashMap<StreamConnectionId, PendingFrames>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameEnqueueOutcome {
    Queued,
    ReplacedWithKeyframe,
    DroppedStale,
    DroppedUntilKeyframe,
}
impl BoardStreamRegistry {
    pub fn attach(&mut self, c: StreamConnectionId) {
        self.connections.entry(c).or_default();
    }
    pub fn detach(&mut self, c: &StreamConnectionId) {
        self.connections.remove(c);
    }
    pub fn enqueue(
        &mut self,
        c: &StreamConnectionId,
        frame: BoardStreamFrame,
    ) -> FrameEnqueueOutcome {
        let Some(p) = self.connections.get_mut(c) else {
            return FrameEnqueueOutcome::DroppedUntilKeyframe;
        };
        match frame.kind {
            FrameKind::Keyframe(_) => {
                if p.epoch.is_some_and(|e| frame.epoch < e) {
                    return FrameEnqueueOutcome::DroppedStale;
                }
                p.epoch = Some(frame.epoch);
                p.frames.retain(|f| f.epoch > frame.epoch);
                p.frames.push_back(frame);
                FrameEnqueueOutcome::ReplacedWithKeyframe
            }
            FrameKind::Delta(ref _rows) => {
                if p.epoch != Some(frame.epoch) {
                    return if p.epoch.is_some_and(|e| frame.epoch < e) {
                        FrameEnqueueOutcome::DroppedStale
                    } else {
                        FrameEnqueueOutcome::DroppedUntilKeyframe
                    };
                }
                let mut clean = frame;
                if let FrameKind::Delta(rs) = &mut clean.kind {
                    for r in rs {
                        r.key = super::one_line_token(&r.key);
                        r.line = super::one_line_token(&r.line);
                    }
                }
                p.frames.push_back(clean);
                FrameEnqueueOutcome::Queued
            }
        }
    }
    pub fn next_carrier_payload(&mut self, c: &StreamConnectionId) -> Option<BoardStreamFrame> {
        self.connections.get_mut(c)?.frames.pop_front()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn k(e: u64) -> BoardStreamFrame {
        BoardStreamFrame {
            epoch: e,
            kind: FrameKind::Keyframe(format!("k{e}")),
        }
    }
    fn d(e: u64, key: &str) -> BoardStreamFrame {
        BoardStreamFrame {
            epoch: e,
            kind: FrameKind::Delta(vec![DeltaRow {
                key: key.into(),
                line: "x".into(),
            }]),
        }
    }
    #[test]
    fn latest() {
        let mut s = AppliedStreamState::default();
        assert!(matches!(
            s.apply(k(47)),
            FrameApplyOutcome::KeyframeTaken { .. }
        ));
        assert!(matches!(
            s.apply(d(47, "a")),
            FrameApplyOutcome::DeltaApplied { rows: 1 }
        ));
        assert!(matches!(
            s.apply(d(48, "b")),
            FrameApplyOutcome::IgnoredUntilKeyframe { .. }
        ));
        s.apply(k(48));
        s.apply(k(47));
        assert_eq!(s.epoch, Some(48));
    }
    #[test]
    fn queue_barrier() {
        let c = StreamConnectionId("x".into());
        let mut r = BoardStreamRegistry::default();
        r.attach(c.clone());
        r.enqueue(&c, k(1));
        r.enqueue(&c, d(1, "a"));
        r.enqueue(&c, k(1));
        assert!(matches!(
            r.next_carrier_payload(&c).unwrap().kind,
            FrameKind::Keyframe(_)
        ));
        assert!(r.next_carrier_payload(&c).is_none());
    }
    #[test]
    fn stale_lower_delta_is_ignored() {
        let mut state = AppliedStreamState::default();
        state.apply(k(47));
        assert!(matches!(
            state.apply(d(46, "old")),
            FrameApplyOutcome::IgnoredStale {
                held_epoch: Some(47)
            }
        ));
        assert!(state.delta_overlay.is_empty());
    }

    #[test]
    fn future_delta_is_discarded_not_replayed() {
        let mut state = AppliedStreamState::default();
        state.apply(k(47));
        assert!(matches!(
            state.apply(d(48, "future")),
            FrameApplyOutcome::IgnoredUntilKeyframe {
                held_epoch: Some(47)
            }
        ));
        assert_eq!(state.epoch, Some(47));
        state.apply(k(48));
        assert_eq!(state.epoch, Some(48));
        assert!(!state.delta_overlay.contains_key("future"));
    }

    #[test]
    fn frame_since_removal_falls_back_to_keyframe() {
        let mut old_rows = BTreeMap::new();
        old_rows.insert("removed".into(), "line".into());
        let old = BoardSnapshot {
            epoch: 4,
            keyframe: "old".into(),
            rows: old_rows,
        };
        let current = BoardSnapshot {
            epoch: 4,
            keyframe: "new".into(),
            rows: BTreeMap::new(),
        };
        assert!(matches!(
            current.frame_since(Some(&old)).unwrap().kind,
            FrameKind::Keyframe(_)
        ));
    }

    #[test]
    fn frame_since_deltas_are_key_sorted_and_fenced() {
        let old = BoardSnapshot {
            epoch: 4,
            keyframe: "old".into(),
            rows: BTreeMap::new(),
        };
        let mut rows = BTreeMap::new();
        rows.insert("z\n".into(), "line\r".into());
        rows.insert("a\t".into(), "line\n".into());
        let current = BoardSnapshot {
            epoch: 4,
            keyframe: "new".into(),
            rows,
        };
        let frame = current.frame_since(Some(&old)).unwrap();
        let FrameKind::Delta(rows) = frame.kind else {
            panic!("expected delta")
        };
        assert_eq!(
            rows.iter().map(|row| row.key.as_str()).collect::<Vec<_>>(),
            vec!["a ", "z "]
        );
        assert!(
            rows.iter().all(|row| !row.key.contains(['\n', '\r', '\t'])
                && !row.line.contains(['\n', '\r', '\t']))
        );
        let mut state = AppliedStreamState::default();
        state.apply(k(4));
        state.apply(BoardStreamFrame {
            epoch: 4,
            kind: FrameKind::Delta(rows),
        });
        assert_eq!(state.delta_overlay.len(), 2);
        assert!(
            state
                .delta_overlay
                .keys()
                .all(|key| !key.contains(['\n', '\r', '\t']))
        );
    }

    fn permutations(items: &mut [usize], start: usize, output: &mut Vec<Vec<usize>>) {
        if start == items.len() {
            output.push(items.to_vec());
            return;
        }
        for index in start..items.len() {
            items.swap(start, index);
            permutations(items, start + 1, output);
            items.swap(start, index);
        }
    }

    #[test]
    fn epoch_permutations_never_decrease_and_deltas_match_held_epoch() {
        let frames = [k(47), d(47, "same"), d(46, "stale"), k(48), k(47)];
        let mut indices = [0, 1, 2, 3, 4];
        let mut orders = Vec::new();
        permutations(&mut indices, 0, &mut orders);
        assert_eq!(orders.len(), 120);
        for order in orders {
            let mut state = AppliedStreamState::default();
            let mut max_accepted_keyframe_epoch = None;
            for index in order {
                let frame = frames[index].clone();
                let epoch = frame.epoch;
                let is_delta = matches!(frame.kind, FrameKind::Delta(_));
                let held_before = state.epoch;
                let overlay_before = state.delta_overlay.clone();
                let outcome = state.apply(frame);
                if !is_delta && !matches!(outcome, FrameApplyOutcome::IgnoredStale { .. }) {
                    max_accepted_keyframe_epoch =
                        Some(max_accepted_keyframe_epoch.map_or(epoch, |max: u64| max.max(epoch)));
                    assert!(
                        state.epoch.expect("accepted keyframe holds epoch")
                            >= max_accepted_keyframe_epoch.expect("max epoch")
                    );
                }
                if is_delta && held_before != Some(epoch) {
                    assert!(matches!(
                        outcome,
                        FrameApplyOutcome::IgnoredStale { .. }
                            | FrameApplyOutcome::IgnoredUntilKeyframe { .. }
                    ));
                    assert_eq!(state.delta_overlay, overlay_before);
                }
            }
            assert_eq!(state.epoch, Some(48));
        }
    }

    #[test]
    fn fenced_key_collisions_are_unique_and_sorted_after_fencing() {
        let old = BoardSnapshot {
            epoch: 1,
            keyframe: "old".into(),
            rows: BTreeMap::new(),
        };
        let mut values = BTreeMap::new();
        values.insert("a\nz".into(), "first".into());
        values.insert("a\tz".into(), "last".into());
        values.insert("a x".into(), "middle".into());
        let current = BoardSnapshot {
            epoch: 1,
            keyframe: "new".into(),
            rows: values,
        };
        let FrameKind::Delta(rows) = current.frame_since(Some(&old)).expect("delta").kind else {
            panic!("delta")
        };
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows.iter().map(|row| row.key.as_str()).collect::<Vec<_>>(),
            vec!["a x", "a z"]
        );
        assert_eq!(rows[1].line, "first");
    }

    #[test]
    fn snapshots() {
        let mut a = BTreeMap::new();
        a.insert("z".into(), "z".into());
        let mut b = a.clone();
        b.insert("a".into(), "a".into());
        let x = BoardSnapshot {
            epoch: 1,
            keyframe: "x".into(),
            rows: a,
        };
        let y = BoardSnapshot {
            epoch: 1,
            keyframe: "y".into(),
            rows: b,
        };
        assert!(matches!(
            y.frame_since(Some(&x)).unwrap().kind,
            FrameKind::Delta(_)
        ));
    }
}
