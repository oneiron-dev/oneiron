//! Session read-set tracking, separate from the stateless board renderer.

use super::{BoardStreamFrame, DeltaRow, FrameKind, MAX_BOARD_ROW_BYTES, one_line_token};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Open own proposals one session watches; every board read checks each, so
/// a burst past it is not watched by this session.
const MAX_OWN_PROPOSALS: usize = 1024;
/// Byte ceilings for the free-text parts of one changed event, so one event
/// row stays far inside the board's row-byte limit whatever the stored or
/// deserialized inputs hold.
pub(super) const MAX_EVENT_REF_BYTES: usize = 256;
const MAX_EVENT_DIAGNOSTIC_BYTES: usize = 1024;

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
    /// This session's own proposals still owed an outcome, by proposal ref.
    /// Only the actor's own submission receipts ever enter it.
    #[serde(default)]
    own_proposals: BTreeSet<String>,
    /// The actor's submission count already folded into `own_proposals`;
    /// `None` until the first delivered render sets the baseline.
    #[serde(default)]
    proposal_count: Option<u64>,
    /// Connector mounts the last committed keyframe carried, by connector.
    /// A change against it rides the tail until the next keyframe.
    #[serde(default)]
    prefix_connectors: Option<BTreeMap<String, ConnectorMount>>,
    /// Moves once per acknowledged delivery, so an older fold that finishes
    /// late cannot replay outcomes or roll the prefix back.
    #[serde(default)]
    delivery_generation: u64,
    /// Settled outcomes delivered from past the point a full watch stopped
    /// the cursor, by proposal ref and receipt count. Each leaves once the
    /// cursor passes it.
    #[serde(default)]
    delivered_ahead: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangedLine {
    pub rows: Vec<(String, ServedLifecycle)>,
    pub overflow: usize,
    pub install_rows: Vec<crate::skill_hub::HubImportReceipt>,
    pub install_overflow: usize,
    /// This session's own proposal outcomes and connector changes. They
    /// render ahead of lifecycle rows and share their cap.
    pub events: Vec<ChangedEvent>,
    /// What a successful delivery of this line acknowledges.
    pub delivery: ChangedDelivery,
}

/// The answer behind a proposal outcome, always by reference: the policy row
/// that decided it, or the gate receipt that records who answered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalReason {
    /// The person's own answer: the owner's resolution the decision rests on.
    PersonWord(String),
    RuleRow(String),
    Receipt(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalChange {
    /// approved, rejected, retracted, superseded or erased.
    pub to: String,
    pub reason: Option<ProposalReason>,
    /// Set on every rejection; it rides the next wake with the outcome.
    pub diagnostic: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorChange {
    Installed,
    Changed,
    Removed,
}

/// One live connector mount: its key and a fingerprint of the terms it runs
/// under (manifest, slate and protocol revisions, charter, budgets).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorMount {
    pub key: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangedEvent {
    Proposal {
        id: String,
        change: ProposalChange,
    },
    Connector {
        id: String,
        change: ConnectorChange,
        mount: Option<ConnectorMount>,
    },
}

/// The session state a delivered line moves forward. Nothing moves until a
/// host has actually returned the render that carried it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangedDelivery {
    /// The session generation the fold read.
    pub(super) generation: u64,
    /// The actor's submission count the fold read through.
    pub(super) proposal_count: Option<u64>,
    /// Submissions the fold read, by count, oldest first.
    pub(super) opened: Vec<(u64, String)>,
    /// Own proposals whose outcome this line rendered.
    pub(super) settled: Vec<String>,
    /// Connector mounts as the fold read them, for a first baseline.
    pub(super) mounts: Option<BTreeMap<String, ConnectorMount>>,
    /// Connector changes this line rendered, for the next keyframe.
    pub(super) connectors: Vec<(String, Option<ConnectorMount>)>,
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
            ..ChangedLine::default()
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
            ..ChangedLine::default()
        }
    }

    /// The proposals this session watches and the submission count it folded.
    pub(super) fn own_proposals(&self) -> (Option<u64>, &BTreeSet<String>) {
        (self.proposal_count, &self.own_proposals)
    }

    pub(super) fn delivery_generation(&self) -> u64 {
        self.delivery_generation
    }

    pub(super) fn delivered_ahead(&self, proposal: &str) -> bool {
        self.delivered_ahead.contains_key(proposal)
    }

    pub(super) fn prefix_connectors(&self) -> Option<&BTreeMap<String, ConnectorMount>> {
        self.prefix_connectors.as_ref()
    }

    /// Call once the render carrying `line` was returned to the session. Its
    /// settled outcomes leave the watch; anything the cap held back stays
    /// owed, so a later rejection is delivered on a following wake. A fold
    /// older than the last acknowledgement moves nothing: what it carried is
    /// delivered again rather than lost.
    pub fn acknowledge(&mut self, line: &ChangedLine) {
        self.deliver(line, false);
    }

    /// Call once a keyframe rendered from `line`'s fold was returned: the
    /// connector changes it carried are now in the prefix, so the tail drops
    /// those and only those.
    pub fn keyframe_committed(&mut self, line: &ChangedLine) {
        self.deliver(line, true);
    }

    fn deliver(&mut self, line: &ChangedLine, keyframe: bool) {
        let delivery = &line.delivery;
        if delivery.generation != self.delivery_generation {
            return;
        }
        self.delivery_generation += 1;
        for id in &delivery.settled {
            self.own_proposals.remove(id);
        }
        // Watch every submission read, oldest first. When the watch is full
        // the cursor stops there, so the rest are read again later.
        let mut through = delivery.proposal_count;
        for (count, id) in &delivery.opened {
            if delivery.settled.contains(id) || self.own_proposals.contains(id) {
                continue;
            }
            if self.own_proposals.len() >= MAX_OWN_PROPOSALS {
                through = Some(count.saturating_sub(1));
                break;
            }
            self.own_proposals.insert(id.clone());
        }
        if let Some(stop) = through {
            for (count, id) in &delivery.opened {
                if *count > stop && delivery.settled.contains(id) {
                    self.delivered_ahead.insert(id.clone(), *count);
                }
            }
        }
        if let Some(count) = through {
            self.proposal_count = Some(self.proposal_count.map_or(count, |seen| seen.max(count)));
        }
        if let Some(seen) = self.proposal_count {
            self.delivered_ahead.retain(|_, count| *count > seen);
        }
        match &mut self.prefix_connectors {
            None => self.prefix_connectors.clone_from(&delivery.mounts),
            Some(prefix) if keyframe => {
                for (connector, mount) in &delivery.connectors {
                    match mount {
                        Some(mount) => {
                            prefix.insert(connector.clone(), mount.clone());
                        }
                        None => {
                            prefix.remove(connector);
                        }
                    }
                }
            }
            Some(_) => {}
        }
    }
}

/// One served row whose lifecycle moved.
pub(super) fn lifecycle_line(id: &str, state: &ServedLifecycle) -> String {
    let to = match state {
        ServedLifecycle::Active => "active".to_owned(),
        ServedLifecycle::Superseded(to) => format!("superseded:{}", one_line_token(to)),
        ServedLifecycle::Retracted => "retracted".to_owned(),
        ServedLifecycle::Installed(hash) => format!("installed:{}", one_line_token(hash)),
    };
    format!("{}: {}", one_line_token(id), to)
}

/// Cut `text` to at most `max` bytes on a character boundary.
fn clip(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

impl ChangedEvent {
    /// One bounded row. Every free-text field is clipped first, so no stored
    /// or deserialized value can carry a row past the board's byte limit.
    pub fn line(&self) -> String {
        let token = |text: &str| one_line_token(clip(text, MAX_EVENT_REF_BYTES));
        match self {
            Self::Proposal { id, change } => {
                let mut row = format!("{}: {}", token(id), token(&change.to));
                match &change.reason {
                    Some(ProposalReason::PersonWord(word)) => {
                        row.push_str(&format!(" why=word:{}", token(word)));
                    }
                    Some(ProposalReason::RuleRow(row_ref)) => {
                        row.push_str(&format!(" why=rule:{}", token(row_ref)));
                    }
                    Some(ProposalReason::Receipt(receipt)) => {
                        row.push_str(&format!(" why=receipt:{}", token(receipt)));
                    }
                    None => {}
                }
                if let Some(diagnostic) = &change.diagnostic {
                    row.push_str(&format!(
                        " diagnostic={}",
                        one_line_token(clip(diagnostic, MAX_EVENT_DIAGNOSTIC_BYTES))
                    ));
                }
                row
            }
            Self::Connector { id, change, mount } => {
                let kind = match change {
                    ConnectorChange::Installed => "installed",
                    ConnectorChange::Changed => "changed",
                    ConnectorChange::Removed => "removed",
                };
                let mut row = format!("{}: connector {kind}", token(id));
                if let Some(mount) = mount {
                    row.push_str(&format!(
                        " key={} terms={}",
                        token(&mount.key),
                        token(&mount.fingerprint)
                    ));
                }
                row
            }
        }
    }
}

impl ChangedLine {
    pub fn render(&self) -> Vec<String> {
        let mut lines = Vec::new();
        let count = self.rows.len() + self.events.len();
        if count > 0 {
            lines.push(format!("changed[{count}:]{{id,to}}:"));
            lines.extend(self.events.iter().map(ChangedEvent::line));
            lines.extend(
                self.rows
                    .iter()
                    .map(|(id, state)| lifecycle_line(id, state)),
            );
        }
        if self.overflow > 0 {
            lines.push(format!("changed: +{}", self.overflow));
        }
        if !self.install_rows.is_empty() {
            lines.push(format!(
                "changed_install[{}:]{{id,hub,ref,pin,to,ask}}:",
                self.install_rows.len()
            ));
            lines.extend(self.install_rows.iter().map(|receipt| {
                let source = receipt.ref_string.chars().take(128).collect::<String>();
                let pin = receipt.pin_value.as_deref().unwrap_or("none");
                let ask = if receipt.disposition.is_pending() {
                    let requested = receipt
                        .requested_permissions
                        .iter()
                        .take(3)
                        .map(|s| one_line_token(s))
                        .collect::<Vec<_>>()
                        .join("|");
                    serde_json::to_string(
                        &format!(
                            "{} [{}]",
                            receipt.fit_analysis.as_deref().unwrap_or(""),
                            requested
                        )
                        .chars()
                        .take(256)
                        .collect::<String>(),
                    )
                    .expect("string serializes")
                } else {
                    "-".to_owned()
                };
                format!(
                    "{}: {},{},{},{}/{},{}",
                    one_line_token(&receipt.entity),
                    one_line_token(&receipt.hub_id),
                    serde_json::to_string(&source).expect("string serializes"),
                    serde_json::to_string(&format!(
                        "{}:{}",
                        receipt.pin_type,
                        pin.chars().take(128).collect::<String>()
                    ))
                    .expect("string serializes"),
                    receipt.installed_as.as_str(),
                    receipt.disposition.as_str(),
                    ask
                )
            }));
        }
        if self.install_overflow > 0 {
            lines.push(format!("changed_install: +{}", self.install_overflow));
        }
        lines
            .into_iter()
            .map(|line| clip(&line, MAX_BOARD_ROW_BYTES).to_owned())
            .collect()
    }

    /// The lines one STREAM delta row carries, joined inside the board's row
    /// limit. Rows past it are dropped whole and counted in the overflow, so
    /// every table header still counts the rows that follow it: install
    /// receipts first, then lifecycle rows, then events from the end, which
    /// keeps rejections, ranked first, the last to go.
    fn delta_line(&self) -> String {
        let mut line = self.clone();
        loop {
            let joined = line.render().join(" ");
            if joined.len() <= MAX_BOARD_ROW_BYTES {
                return joined;
            }
            if line.install_rows.pop().is_some() {
                line.install_overflow += 1;
            } else if line.rows.pop().is_some() || line.events.pop().is_some() {
                line.overflow += 1;
            } else {
                return clip(&joined, MAX_BOARD_ROW_BYTES).to_owned();
            }
        }
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
                            line: self.delta_line(),
                        },
                    );
                }
            }
            frame
        })
    }
}
