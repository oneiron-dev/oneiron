//! Board stream frames, snapshots and carrier coalescing.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameEnqueueOutcome {
    Queued,
    ReplacedWithKeyframe,
    DroppedStale,
    DroppedUntilKeyframe,
}

#[derive(Debug, Default)]
pub struct CarrierCoalesceBuffer {
    pub(super) epoch: Option<u64>,
    pending_keyframe: Option<BoardStreamFrame>,
    rows: BTreeMap<String, DeltaRow>,
    superseded_intermediate_deltas: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoalesceOutcome {
    Inserted,
    Superseded,
    ReplacedEpoch,
    DroppedStale,
    DroppedUntilKeyframe,
}

impl CarrierCoalesceBuffer {
    pub fn push(&mut self, f: BoardStreamFrame) -> CoalesceOutcome {
        match f.kind {
            FrameKind::Keyframe(_) => {
                if self.epoch.is_some_and(|e| f.epoch < e) {
                    return CoalesceOutcome::DroppedStale;
                }
                self.epoch = Some(f.epoch);
                self.rows.clear();
                self.pending_keyframe = Some(f);
                CoalesceOutcome::ReplacedEpoch
            }
            FrameKind::Delta(rs) => {
                if self.epoch != Some(f.epoch) {
                    return match self.epoch {
                        None => CoalesceOutcome::DroppedUntilKeyframe,
                        Some(epoch) if f.epoch > epoch => CoalesceOutcome::DroppedUntilKeyframe,
                        Some(_) => CoalesceOutcome::DroppedStale,
                    };
                }
                let mut out = CoalesceOutcome::Inserted;
                for mut r in rs {
                    r.key = super::one_line_token(&r.key);
                    r.line = super::one_line_token(&r.line);
                    if self.rows.insert(r.key.clone(), r).is_some() {
                        self.superseded_intermediate_deltas += 1;
                        out = CoalesceOutcome::Superseded;
                    }
                }
                out
            }
        }
    }
    pub fn drain(&mut self) -> Option<BoardStreamFrame> {
        if let Some(k) = self.pending_keyframe.take() {
            return Some(k);
        }
        if self.rows.is_empty() {
            return None;
        }
        let rows = std::mem::take(&mut self.rows).into_values().collect();
        let epoch = self.epoch?;
        Some(BoardStreamFrame {
            epoch,
            kind: FrameKind::Delta(rows),
        })
    }
    pub const fn superseded_intermediate_deltas(&self) -> usize {
        self.superseded_intermediate_deltas
    }
}
