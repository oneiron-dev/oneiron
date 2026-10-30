//! The front tab's in-page frames, read into its outline (FIX 205, FIX
//! 8336). Chromium reads one document's accessibility tree per call: the
//! page's own, then each frame's, a frame of the page's process by its
//! frame on the page's session, an out-of-process frame (OOPIF) on its own
//! session, which the browser attached for it, and an OOPIF nested in one
//! on its own, after the frame it is in (FIX 10332). Each frame's tree is
//! grafted under the element that holds the frame, its node ids kept apart
//! by the frame's, so its rows read where the page shows them and are
//! classified as every row is, by the same read. A nested OOPIF's element
//! is found in the frame it is in, on that frame's session. An OOPIF
//! session's own same-process children read on that session and graft
//! under it the same way (FIX 11577). A frame whose tree the read already
//! holds, or that does not read, is left as it was. An OOPIF's rows act
//! on their own frame session (FIX 11576).
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
        // Each OOPIF session's own same-process children, grafted under it
        // (FIX 11577): its frame tree names them, and its session reads
        // them. A nested OOPIF already listed above is never grafted twice.
        for (_, session, _) in &oopifs {
            for (child, parent) in self.child_frames_in(session) {
                let listed = oopifs.iter().any(|(frame, _, _)| frame == &child)
                    || frames.iter().any(|(frame, _)| frame == &child);
                if !listed {
                    frames.push((child, Some((parent, session.clone()))));
                }
            }
        }
        for (frame, within) in frames {
            // An OOPIF's node ids are its process's, and so is anything
            // under one (FIX 11577); a same-process frame's are the page's.
            let apart = self.frame_session(Some(&frame)) != self.session || within.is_some();
            let session = within.as_ref().map(|(_, session)| session.as_str());
            if let Some((tree, read_on)) = self.frame_tree(&frame, session) {
                let (outer, session) = within.unzip();
                let owner = self.frame_owner(&frame, session.as_deref());
                graft(
                    nodes,
                    &frame,
                    tree,
                    owner,
                    apart,
                    outer.as_deref(),
                    &read_on,
                );
            }
        }
    }

    /// Every frame under the front tab's main frame, as its frame tree
    /// names them, read with an explicit stack.
    fn child_frames(&self) -> Vec<String> {
        self.child_frames_in(&self.session)
            .into_iter()
            .map(|(frame, _)| frame)
            .collect()
    }

    /// Every frame under `session`'s main frame, with the frame it is in,
    /// as its frame tree names them (FIX 11577): an OOPIF session names
    /// its own same-process children, each under its own parent frame.
    /// Read with an explicit stack, a parent always before its children;
    /// none where it does not read.
    fn child_frames_in(&self, session: &str) -> Vec<(String, String)> {
        let deadline = Instant::now() + CALL;
        let Ok(tree) = self
            .pipe
            .call(Some(session), "Page.getFrameTree", json!({}), deadline)
        else {
            return Vec::new();
        };
        let Some(root) = tree.pointer("/frameTree/frame/id").and_then(Value::as_str) else {
            return Vec::new();
        };
        let mut frames = Vec::new();
        let mut stack: Vec<(&Value, String)> = tree
            .pointer("/frameTree/childFrames")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|child| (child, root.to_owned()))
            .collect();
        while let Some((child, parent)) = stack.pop() {
            let Some(id) = child.pointer("/frame/id").and_then(Value::as_str) else {
                continue;
            };
            let id = id.to_owned();
            frames.push((id.clone(), parent));
            stack.extend(
                child["childFrames"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|grandchild| (grandchild, id.clone())),
            );
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

    /// `frame`'s accessibility nodes, with the session they were read
    /// on: its own session where it is an OOPIF, else by its frame on
    /// `within`, an OOPIF's own same-process child (FIX 11577), or on
    /// the front tab's.
    fn frame_tree(&self, frame: &str, within: Option<&str>) -> Option<(Vec<Value>, String)> {
        let own = self.frame_session(Some(frame));
        let (session, params) = if own != self.session {
            (own, json!({}))
        } else if let Some(within) = within {
            (within.to_owned(), json!({"frameId": frame}))
        } else {
            (self.session.clone(), json!({"frameId": frame}))
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
            Some(Value::Array(nodes)) if !nodes.is_empty() => Some((nodes, session)),
            _ => None,
        }
    }

    /// The offset of `session`'s viewport in the main frame's, in CSS
    /// pixels (FIX 11576): a box read on an out-of-process frame's session
    /// is in that frame's viewport, while a mouse press is routed by the
    /// main frame's. The offset is the frame element's content box, read
    /// on the session holding that element, plus that session's own
    /// offset, out to the front tab's session, whose offset is zero.
    /// None where a step of the chain does not read.
    pub(super) fn frame_page_offset(&self, session: &str) -> Option<(f64, f64)> {
        let mut sessions = vec![self.session.clone()];
        sessions.extend(self.oopif_sessions());
        let (mut x, mut y) = (0.0, 0.0);
        let mut held = session.to_owned();
        let mut steps = 0;
        while held != self.session {
            steps += 1;
            if steps > sessions.len() {
                return None;
            }
            let root = self.frame_root(&held)?;
            let outer = sessions
                .iter()
                .find(|candidate| **candidate != held && self.session_holds(candidate, &root))?;
            let owner = self.frame_owner(&root, Some(outer.as_str()))?;
            let model = self
                .call_in(outer, "DOM.getBoxModel", json!({"backendNodeId": owner}))
                .ok()?;
            let quad: Vec<f64> = model
                .pointer("/model/content")
                .and_then(Value::as_array)
                .map(|q| q.iter().filter_map(Value::as_f64).collect())
                .unwrap_or_default();
            if quad.len() != 8 {
                return None;
            }
            x += quad[0].min(quad[2]).min(quad[4]).min(quad[6]);
            y += quad[1].min(quad[3]).min(quad[5]).min(quad[7]);
            held = outer.clone();
        }
        Some((x, y))
    }

    /// The main frame of `session`'s frame tree, where it reads.
    fn frame_root(&self, session: &str) -> Option<String> {
        let tree = self
            .pipe
            .call(
                Some(session),
                "Page.getFrameTree",
                json!({}),
                Instant::now() + CALL,
            )
            .ok()?;
        tree.pointer("/frameTree/frame/id")
            .and_then(Value::as_str)
            .map(str::to_owned)
    }

    /// Whether `frame` is a child frame somewhere in `session`'s frame
    /// tree: the element holding it is in that session's document.
    fn session_holds(&self, session: &str, frame: &str) -> bool {
        let Ok(tree) = self.pipe.call(
            Some(session),
            "Page.getFrameTree",
            json!({}),
            Instant::now() + CALL,
        ) else {
            return false;
        };
        let mut stack: Vec<&Value> = tree
            .pointer("/frameTree/childFrames")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .collect();
        while let Some(child) = stack.pop() {
            if child.pointer("/frame/id").and_then(Value::as_str) == Some(frame) {
                return true;
            }
            stack.extend(child["childFrames"].as_array().into_iter().flatten());
        }
        false
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
    read_on: &str,
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
        // The session this tree was read on is the one its backend nodes
        // resolve on (FIX 11576): a same-process frame under an OOPIF has
        // no session of its own, and its frame id alone would name the
        // page's.
        node["sessionId"] = Value::from(read_on);
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
