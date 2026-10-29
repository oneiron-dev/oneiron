//! The front tab's in-page frames, read into its outline (FIX 205, FIX
//! 8336). Chromium reads one document's accessibility tree per call: the
//! page's own, then each frame's, a frame of the page's process by its
//! frame on the page's session, an out-of-process frame (OOPIF) on its own
//! session, which the browser attached for it, and an OOPIF nested in one
//! on its own, after the frame it is in (FIX 10332). Each frame's tree is
//! grafted under the element that holds the frame, its node ids kept apart
//! by the frame's, so its rows read where the page shows them and are
//! classified as every row is, by the same read. A nested OOPIF's element
//! is found in the frame it is in, on that frame's session. A frame whose
//! tree the read already holds, or that does not read, is left as it was.
//! An OOPIF's rows act as the engine allows them: a row with no DOM node on
//! the page's session stays read-only.
//!
//! A screenshot masks an OOPIF's secret rows on the frame's own session,
//! and its secret-marked fields there too, as the front document's are
//! (`secrets`). Lightpanda reads its main document's tree only.

use super::{CALL, CdpDriver};
use crate::BrowserEngine;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::time::Instant;

impl CdpDriver {
    /// Grafts each in-page frame's tree into `nodes`, the page's own tree,
    /// on Chromium.
    pub(super) fn graft_frames(&self, nodes: &mut Vec<Value>) {
        if self.engine != BrowserEngine::Chromium {
            return;
        }
        let oopifs = self.pipe.oopifs(&self.session);
        // The page's own frames, then its OOPIFs, each after the frame it
        // is in: a nested one's element is in that frame's tree.
        let mut frames: Vec<(String, Option<(String, String)>)> = self
            .child_frames()
            .into_iter()
            .filter(|frame| !oopifs.iter().any(|(oopif, _, _)| oopif == frame))
            .map(|frame| (frame, None))
            .collect();
        for (frame, _, parent) in &oopifs {
            let within = oopifs
                .iter()
                .find(|(_, session, _)| session == parent)
                .map(|(outer, session, _)| (outer.clone(), session.clone()));
            frames.push((frame.clone(), within));
        }
        for (frame, within) in frames {
            let apart = self.frame_session(Some(&frame)) != self.session;
            if let Some(tree) = self.frame_tree(&frame) {
                let (outer, session) = within.unzip();
                let owner = self.frame_owner(&frame, session.as_deref());
                graft(nodes, &frame, tree, owner, apart, outer.as_deref());
            }
        }
    }

    /// Every frame under the front tab's main frame, as its frame tree
    /// names them, read with an explicit stack.
    fn child_frames(&self) -> Vec<String> {
        let Ok(tree) = self.page("Page.getFrameTree", json!({})) else {
            return Vec::new();
        };
        let mut frames = Vec::new();
        let mut stack: Vec<&Value> = tree
            .pointer("/frameTree/childFrames")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .collect();
        while let Some(child) = stack.pop() {
            if let Some(id) = child.pointer("/frame/id").and_then(Value::as_str) {
                frames.push(id.to_owned());
            }
            stack.extend(child["childFrames"].as_array().into_iter().flatten());
        }
        frames
    }

    /// The session a frame's document is read and masked on: an OOPIF's
    /// own, a nested one's too, else the front tab's.
    pub(super) fn frame_session(&self, frame: Option<&str>) -> String {
        frame
            .and_then(|frame| {
                self.pipe
                    .oopifs(&self.session)
                    .into_iter()
                    .find(|(oopif, _, _)| oopif == frame)
            })
            .map_or_else(|| self.session.clone(), |(_, session, _)| session)
    }

    /// The front tab's OOPIF sessions, nested ones too, for a screenshot's
    /// masks.
    pub(super) fn oopif_sessions(&self) -> Vec<String> {
        self.pipe
            .oopifs(&self.session)
            .into_iter()
            .map(|(_, session, _)| session)
            .collect()
    }

    /// `frame`'s accessibility nodes: on its own session where it is an
    /// OOPIF, else by its frame on the front tab's.
    fn frame_tree(&self, frame: &str) -> Option<Vec<Value>> {
        let session = self.frame_session(Some(frame));
        let params = if session == self.session {
            json!({"frameId": frame})
        } else {
            json!({})
        };
        let deadline = Instant::now() + CALL;
        let mut tree = self
            .pipe
            .call(
                Some(&session),
                "Accessibility.getFullAXTree",
                params,
                deadline,
            )
            .ok()?;
        match tree.get_mut("nodes").map(Value::take) {
            Some(Value::Array(nodes)) if !nodes.is_empty() => Some(nodes),
            _ => None,
        }
    }

    /// The backend node of the element that holds `frame`: in its page, or,
    /// for a nested OOPIF, in the frame it is in, on that frame's `session`.
    fn frame_owner(&self, frame: &str, session: Option<&str>) -> Option<u64> {
        let session = session.unwrap_or(&self.session);
        let owner = self
            .pipe
            .call(
                Some(session),
                "DOM.getFrameOwner",
                json!({"frameId": frame}),
                Instant::now() + CALL,
            )
            .ok()?;
        owner.get("backendNodeId").and_then(Value::as_u64)
    }
}

/// Grafts `frame`'s tree `tree` into `nodes`: its node ids prefixed by the
/// frame, its root under the node of `owner`, the element holding it (else
/// under the page's root), each node named by its frame. A same-process
/// frame's tree whose nodes `nodes` already holds (by backend node) is the
/// page's own read; an OOPIF's (`apart`) node ids are its own process's. A
/// nested OOPIF's element is sought only among the nodes of `within`, the
/// grafted frame it is in, whose backend nodes are that frame's process's.
fn graft(
    nodes: &mut Vec<Value>,
    frame: &str,
    tree: Vec<Value>,
    owner: Option<u64>,
    apart: bool,
    within: Option<&str>,
) {
    if !apart {
        let held: HashSet<u64> = nodes
            .iter()
            .filter_map(|node| node.get("backendDOMNodeId").and_then(Value::as_u64))
            .collect();
        let read = tree
            .iter()
            .filter_map(|node| node.get("backendDOMNodeId").and_then(Value::as_u64));
        if read.into_iter().any(|backend| held.contains(&backend)) {
            return;
        }
    }
    let inside = within.map(|outer| format!("{outer}/"));
    let host = nodes
        .iter()
        .position(|node| {
            let placed = inside.as_deref().is_none_or(|prefix| {
                node.get("nodeId")
                    .and_then(Value::as_str)
                    .is_some_and(|id| id.starts_with(prefix))
            });
            owner.is_some()
                && placed
                && node.get("backendDOMNodeId").and_then(Value::as_u64) == owner
        })
        .or_else(|| nodes.iter().position(|node| node.get("parentId").is_none()));
    let Some(host) = host else {
        return;
    };
    let id = |raw: &Value| raw.as_str().map(|id| Value::from(format!("{frame}/{id}")));
    let mut root = None;
    for mut node in tree {
        let own = node.get("nodeId").and_then(id);
        if let Some(own) = &own {
            node["nodeId"] = own.clone();
        }
        match node.get("parentId").and_then(id) {
            Some(parent) => node["parentId"] = parent,
            None if root.is_none() => {
                root.clone_from(&own);
                node["parentId"] = nodes[host]["nodeId"].clone();
            }
            None => {}
        }
        if let Some(children) = node.get_mut("childIds").and_then(Value::as_array_mut) {
            for child in children.iter_mut() {
                if let Some(prefixed) = id(child) {
                    *child = prefixed;
                }
            }
        }
        if node.get("frameId").is_none() {
            node["frameId"] = Value::from(frame);
        }
        nodes.push(node);
    }
    if let Some(root) = root {
        let children = &mut nodes[host]["childIds"];
        if !children.is_array() {
            *children = Value::Array(Vec::new());
        }
        if let Some(children) = children.as_array_mut() {
            children.push(root);
        }
    }
}
