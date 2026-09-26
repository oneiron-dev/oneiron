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
    Installed(String),
}

/// Session-owned state. Serialize with the session checkpoint, not the epoch
/// keyframe, so loaded bodies survive a compaction/epoch rollover.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionReadSet {
    rows: BTreeMap<String, ServedLifecycle>,
    loaded_skills: BTreeMap<String, String>,
    /// First actually served pack inventory for this session. New versions
    /// remain on the changed line until the session ends or explicitly resets.
    #[serde(default)]
    served_packs: Option<BTreeMap<String, String>>,
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

    /// Capture only a session's first served inventory. Installation itself
    /// never pushes a frame or impersonates an actor/session.
    pub fn observe_pack_inventory(&mut self, packs: &[(String, String)]) {
        if self.served_packs.is_none() {
            self.served_packs = Some(packs.iter().cloned().collect());
        }
    }

    /// New/changed exact content identities since the session first read its
    /// installed inventory. A session with no prior read gets no invented event.
    pub fn pack_changes(&self, packs: &[(String, String)], cap: usize) -> ChangedLine {
        let Some(served) = &self.served_packs else {
            return ChangedLine::default();
        };
        let changed: Vec<_> = packs
            .iter()
            .filter(|(name, hash)| served.get(name).is_none_or(|previous| previous != hash))
            .map(|(name, hash)| (name.clone(), ServedLifecycle::Installed(hash.clone())))
            .collect();
        ChangedLine {
            overflow: changed.len().saturating_sub(cap),
            rows: changed.into_iter().take(cap).collect(),
        }
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
                    ServedLifecycle::Installed(hash) => {
                        format!("installed:{}", one_line_token(hash))
                    }
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
