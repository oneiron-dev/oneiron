//! Session read-set tracking, separate from the stateless board renderer.

use super::{BoardStreamFrame, DeltaRow, FrameKind, one_line_token};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

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
    /// Only proposals authored by this session may enter its changed rider.
    #[serde(default)]
    own_proposals: BTreeSet<String>,
    #[serde(default)]
    proposal_changes: BTreeMap<String, ProposalChange>,
    /// The cached prefix is frozen until the next successfully committed keyframe.
    #[serde(default)]
    prefix_epoch: Option<u64>,
    #[serde(default)]
    connector_changes: BTreeMap<String, ConnectorStateChange>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangedLine {
    pub rows: Vec<(String, ServedLifecycle)>,
    pub events: Vec<ChangedEvent>,
    pub overflow: usize,
}

/// The answer is a reference to a person's actual word or to the answering
/// rule row, never a copied free-text explanation promoted to authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalReason {
    PersonWord(String),
    RuleRow(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalChange {
    pub to: String,
    pub reason: ProposalReason,
    /// A rejected proposal's diagnostic is delivered on the next board wake.
    pub diagnostic: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorChange {
    Installed,
    Narrowed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorStateChange {
    pub change: ConnectorChange,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangedEvent {
    Proposal {
        id: String,
        change: ProposalChange,
    },
    Connector {
        id: String,
        change: ConnectorStateChange,
    },
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

    /// Record authorship when an agent's proposal is admitted. Seeing someone
    /// else's proposal on a board never makes it part of this agent's rider.
    pub fn own_proposal(&mut self, id: impl Into<String>) {
        self.own_proposals.insert(id.into());
    }

    /// Fold a settled proposal into the next tail render. The caller supplies
    /// the authoritative state, reason reference and any rejection diagnostic;
    /// this method has no delivery side effect. Unknown authors are ignored.
    pub fn proposal_changed(
        &mut self,
        id: &str,
        to: impl Into<String>,
        reason: ProposalReason,
        diagnostic: Option<String>,
    ) -> bool {
        if !self.own_proposals.contains(id) {
            return false;
        }
        self.proposal_changes.insert(
            id.to_owned(),
            ProposalChange {
                to: to.into(),
                reason,
                diagnostic,
            },
        );
        true
    }

    /// Call only after the next keyframe was successfully assembled from the
    /// current connector state. Same-epoch retries and older frames must not
    /// clear mid-epoch changes or rewrite a cached prefix.
    pub fn keyframe_committed(&mut self, epoch: u64) {
        if self.prefix_epoch.is_none_or(|previous| epoch > previous) {
            self.prefix_epoch = Some(epoch);
            self.connector_changes.clear();
        }
    }

    /// Record the *current* post-commit state of an installed/narrowed mount.
    /// A second change to the same mount replaces the earlier state, without
    /// emitting a frame; it is visible only on the next ordinary render/wake.
    pub fn connector_changed(
        &mut self,
        id: impl Into<String>,
        change: ConnectorChange,
        state: impl Into<String>,
    ) {
        if self.prefix_epoch.is_some() {
            self.connector_changes.insert(
                id.into(),
                ConnectorStateChange {
                    change,
                    state: state.into(),
                },
            );
        }
    }

    /// A read-time fold, never a publisher. The host resolves current lifecycle
    /// through its ordinary scoped read and omits no-longer-readable rows.
    pub fn changed(
        &self,
        cap: usize,
        mut current: impl FnMut(&str) -> Option<ServedLifecycle>,
    ) -> ChangedLine {
        // The next-wake diagnostic cannot be starved by a long read set.
        // One shared cap covers proposal, connector and lifecycle changes.
        let events = self
            .proposal_changes
            .iter()
            .map(|(id, change)| ChangedEvent::Proposal {
                id: id.clone(),
                change: change.clone(),
            })
            .chain(
                self.connector_changes
                    .iter()
                    .map(|(id, change)| ChangedEvent::Connector {
                        id: id.clone(),
                        change: change.clone(),
                    }),
            )
            .collect::<Vec<_>>();
        let changed: Vec<_> = self
            .rows
            .iter()
            .filter_map(|(id, served)| {
                let now = current(id)?;
                (now != *served && now != ServedLifecycle::Active).then(|| (id.clone(), now))
            })
            .collect();
        let event_count = events.len().min(cap);
        let row_cap = cap - event_count;
        let overflow =
            events.len().saturating_sub(event_count) + changed.len().saturating_sub(row_cap);
        ChangedLine {
            rows: changed.into_iter().take(row_cap).collect(),
            events: events.into_iter().take(event_count).collect(),
            overflow,
        }
    }
}

impl ChangedLine {
    pub fn render(&self) -> Vec<String> {
        let mut lines = Vec::new();
        let n = self.rows.len() + self.events.len();
        if n > 0 {
            lines.push(format!("changed[{n}:]{{id,to}}:"));
            lines.extend(self.events.iter().map(|event| match event {
                ChangedEvent::Proposal { id, change } => {
                    let reason = match &change.reason {
                        ProposalReason::PersonWord(reference) => {
                            format!("word:{}", one_line_token(reference))
                        }
                        ProposalReason::RuleRow(reference) => {
                            format!("rule:{}", one_line_token(reference))
                        }
                    };
                    let diagnostic = change.diagnostic.as_deref().map_or(String::new(), |text| {
                        format!(" diagnostic={}", one_line_token(text))
                    });
                    format!(
                        "{}: {} why={}{}",
                        one_line_token(id),
                        one_line_token(&change.to),
                        reason,
                        diagnostic
                    )
                }
                ChangedEvent::Connector { id, change } => {
                    let kind = match change.change {
                        ConnectorChange::Installed => "installed",
                        ConnectorChange::Narrowed => "narrowed",
                    };
                    format!(
                        "{}: {} state={}",
                        one_line_token(id),
                        kind,
                        one_line_token(&change.state)
                    )
                }
            }));
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
