//! Session read-set tracking, separate from the stateless board renderer.

use super::{BoardStreamFrame, DeltaRow, FrameKind, one_line_token};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Lifecycle version served to a caller. The claim lifecycle chain is the
/// version; this rider does not introduce a second revision counter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServedLifecycle {
    Active,
    Superseded(String),
    Retracted,
}

/// Session-owned state. Serialize with the session checkpoint, not the epoch
/// keyframe, so loaded bodies survive a compaction/epoch rollover.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionReadSet {
    rows: BTreeMap<String, ServedLifecycle>,
    loaded_skills: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangedLine {
    pub rows: Vec<(String, ServedLifecycle)>,
    pub overflow: usize,
}

impl SessionReadSet {
    pub(super) fn require_capacity(&self, id: &str) -> crate::Result<()> {
        if self.rows.len() >= 4096 && !self.rows.contains_key(id) {
            return Err(crate::Error::IndexOverflow(
                "context board session read set",
            ));
        }
        Ok(())
    }

    /// Called only for rows actually served after budget shedding, or a get()
    /// body actually appended to the log. A new observation replaces the old.
    pub fn served(&mut self, id: impl Into<String>, lifecycle: ServedLifecycle) {
        self.rows.insert(id.into(), lifecycle);
    }

    pub fn loaded_skill(&mut self, id: impl Into<String>, version: impl Into<String>) {
        let id = id.into();
        self.served(id.clone(), ServedLifecycle::Active);
        self.loaded_skills.insert(id, version.into());
    }

    pub fn loaded_skills(&self) -> impl Iterator<Item = (&str, &str)> {
        self.loaded_skills
            .iter()
            .map(|(id, version)| (id.as_str(), version.as_str()))
    }

    /// A read-time fold, never a publisher. The host resolves current lifecycle
    /// through its ordinary scoped read and omits no-longer-readable rows.
    pub fn changed(
        &self,
        cap: usize,
        mut current: impl FnMut(&str) -> Option<ServedLifecycle>,
    ) -> ChangedLine {
        let changed: Vec<_> = self
            .rows
            .iter()
            .filter_map(|(id, served)| {
                let now = current(id)?;
                (now != *served && now != ServedLifecycle::Active).then(|| (id.clone(), now))
            })
            .collect();
        let overflow = changed.len().saturating_sub(cap);
        ChangedLine {
            rows: changed.into_iter().take(cap).collect(),
            overflow,
        }
    }
}

impl ChangedLine {
    pub fn render(&self) -> Vec<String> {
        let mut lines = Vec::new();
        if !self.rows.is_empty() {
            lines.push(format!("changed[{}:]{{id,to}}:", self.rows.len()));
            lines.extend(self.rows.iter().map(|(id, state)| {
                let to = match state {
                    ServedLifecycle::Active => "active".to_owned(),
                    ServedLifecycle::Superseded(to) => format!("superseded:{}", one_line_token(to)),
                    ServedLifecycle::Retracted => "retracted".to_owned(),
                };
                format!("{}: {}", one_line_token(id), to)
            }));
        }
        if self.overflow > 0 {
            lines.push(format!("changed: +{}", self.overflow));
        }
        lines
    }

    /// Adds a rider only to an already-produced frame. `None` stays `None`:
    /// lifecycle movement can never create a push in STREAM mode.
    pub fn ride(&self, frame: Option<BoardStreamFrame>) -> Option<BoardStreamFrame> {
        frame.map(|mut frame| {
            let lines = self.render();
            match &mut frame.kind {
                FrameKind::Keyframe(text) => {
                    if !lines.is_empty()
                        && let Some(at) = text.find("\nlegend:")
                    {
                        text.insert_str(
                            at,
                            &format!(
                                "\n{}",
                                lines
                                    .iter()
                                    .map(|line| super::frame::xml_text_token(line))
                                    .collect::<Vec<_>>()
                                    .join("\n")
                            ),
                        );
                    }
                }
                FrameKind::Delta(rows) => {
                    rows.insert(
                        0,
                        DeltaRow {
                            key: "changed".to_owned(),
                            line: lines.join(" "),
                        },
                    );
                }
            }
            frame
        })
    }
}
