//! Typed read-only file-face verbs. All operations open the caller's own
//! Memory read lane; a mount is a content selector, not an authority token.
mod types;
pub use types::*;

use base64::Engine;

use super::{Memory, MemoryError, MemoryResult};
use crate::claim::ClaimReadStatus;
use crate::graph_fs::{
    GRAPH_FS_PROJECTION_VERSION, GraphFsCommandOutput, GraphFsCoreutilsDecision,
    GraphFsEntryKind, GraphFsOptions, GraphFsResolver,
};

impl GraphFsMountRequest {
    fn options(&self) -> GraphFsOptions {
        let options = GraphFsOptions::default();
        let options = self.page_byte_cap.map_or(options, |cap| options.with_page_byte_cap(cap));
        self.max_entries.map_or(options, |cap| options.with_max_entries(cap))
    }
}

fn descriptor(tree: &GraphFsResolver<'_, '_>, request: &GraphFsMountRequest) -> GraphFsMountRequest {
    let options = request.options();
    GraphFsMountRequest {
        reference: tree.reference(),
        page_byte_cap: Some(options.page_byte_cap()),
        max_entries: Some(options.max_entries()),
    }
}

fn call_key(verb: &str, parameters: impl serde::Serialize) -> MemoryResult<String> {
    serde_json::to_string(&(verb, parameters))
        .map_err(|_| MemoryError::bad_request("graph-fs parameters did not encode"))
}

fn output(
    tree: &GraphFsResolver<'_, '_>, request: &GraphFsMountRequest,
    path: String, call: &str, result: GraphFsCommandOutput,
) -> GraphFsOutput {
    let next_cursor = result.next_cursor().map(|cursor| tree.seal_public_cursor(call, cursor));
    let plan = match result.decision() {
        GraphFsCoreutilsDecision::Pushdown => GraphFsPlan::Pushdown,
        GraphFsCoreutilsDecision::Walk => GraphFsPlan::Walk,
    };
    let (output, encoding) = match String::from_utf8(result.into_bytes()) {
        Ok(text) => (text, GraphFsEncoding::Utf8),
        Err(bytes) => (base64::engine::general_purpose::STANDARD.encode(bytes.into_bytes()), GraphFsEncoding::Base64),
    };
    GraphFsOutput { mount: descriptor(tree, request), path, output, encoding, next_cursor, plan }
}

impl Memory<'_> {
    pub fn graph_fs_mount(&self, input: GraphFsMountRequest) -> MemoryResult<GraphFsMounted> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let tree = lane.mount_graph_fs(&input.reference, input.options())?;
        Ok(GraphFsMounted {
            mount: descriptor(&tree, &input), root: "/".to_owned(),
            projection: GRAPH_FS_PROJECTION_VERSION.to_owned(),
        })
    }

    pub fn graph_fs_readdir(&self, input: GraphFsPathRequest) -> MemoryResult<GraphFsDirectoryView> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let tree = lane.mount_graph_fs(&input.mount.reference, input.mount.options())?;
        let call = call_key("graph_fs.readdir", &input.path)?;
        let cursor = tree.open_public_cursor(&call, input.cursor.as_deref())?;
        let page = tree.readdir(&input.path, cursor.as_deref())?;
        let entries = page.entries().iter().map(|entry| GraphFsEntryView {
            name: entry.name().to_owned(),
            kind: match entry.kind() {
                GraphFsEntryKind::Directory => GraphFsKind::Directory,
                GraphFsEntryKind::File => GraphFsKind::File,
                GraphFsEntryKind::Symlink => GraphFsKind::Symlink,
                GraphFsEntryKind::Cursor => GraphFsKind::Cursor,
            },
            target: entry.target().map(str::to_owned),
            cursor: entry.cursor_token().map(|cursor| tree.seal_public_cursor(&call, cursor)),
            byte_len: entry.byte_len(),
        }).collect();
        Ok(GraphFsDirectoryView {
            mount: descriptor(&tree, &input.mount), path: page.path().to_owned(), entries,
            next_cursor: page.next_cursor().map(|cursor| tree.seal_public_cursor(&call, cursor)),
        })
    }

    pub fn graph_fs_read_file(&self, input: GraphFsPathRequest) -> MemoryResult<GraphFsOutput> {
        self.graph_fs_bytes(input, "graph_fs.read_file")
    }

    pub fn graph_fs_cat(&self, input: GraphFsPathRequest) -> MemoryResult<GraphFsOutput> {
        self.graph_fs_bytes(input, "graph_fs.cat")
    }

    fn graph_fs_bytes(&self, input: GraphFsPathRequest, verb: &str) -> MemoryResult<GraphFsOutput> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let tree = lane.mount_graph_fs(&input.mount.reference, input.mount.options())?;
        let call = call_key(verb, &input.path)?;
        let cursor = tree.open_public_cursor(&call, input.cursor.as_deref())?;
        let result = tree.cat(&input.path, cursor.as_deref())?;
        Ok(output(&tree, &input.mount, input.path, &call, result))
    }

    pub fn graph_fs_read_link(&self, input: GraphFsLinkRequest) -> MemoryResult<GraphFsLinkView> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let tree = lane.mount_graph_fs(&input.mount.reference, input.mount.options())?;
        Ok(GraphFsLinkView {
            mount: descriptor(&tree, &input.mount), target: tree.read_link(&input.path)?, path: input.path,
        })
    }

    pub fn graph_fs_ls(&self, input: GraphFsLsRequest) -> MemoryResult<GraphFsOutput> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let tree = lane.mount_graph_fs(&input.mount.reference, input.mount.options())?;
        let call = call_key("graph_fs.ls", (&input.path, input.by_time))?;
        let cursor = tree.open_public_cursor(&call, input.cursor.as_deref())?;
        let result = tree.ls(&input.path, input.by_time, cursor.as_deref())?;
        Ok(output(&tree, &input.mount, input.path, &call, result))
    }

    pub fn graph_fs_find(&self, input: GraphFsFindRequest) -> MemoryResult<GraphFsOutput> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let tree = lane.mount_graph_fs(&input.mount.reference, input.mount.options())?;
        let call = call_key("graph_fs.find", (&input.path, input.newer_than))?;
        let cursor = tree.open_public_cursor(&call, input.cursor.as_deref())?;
        let result = tree.find(&input.path, input.newer_than, cursor.as_deref())?;
        Ok(output(&tree, &input.mount, input.path, &call, result))
    }

    pub fn graph_fs_grep(&self, input: GraphFsGrepRequest) -> MemoryResult<GraphFsOutput> {
        if input.pattern.is_empty() { return Err(MemoryError::bad_request("grep needs a pattern")); }
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let tree = lane.mount_graph_fs(&input.mount.reference, input.mount.options())?;
        let call = call_key("graph_fs.grep", (&input.path, &input.pattern, input.recursive))?;
        let cursor = tree.open_public_cursor(&call, input.cursor.as_deref())?;
        let result = tree.grep(&input.pattern, &input.path, input.recursive, cursor.as_deref())?;
        Ok(output(&tree, &input.mount, input.path, &call, result))
    }

    pub fn graph_fs_head(&self, input: GraphFsHeadRequest) -> MemoryResult<GraphFsOutput> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let tree = lane.mount_graph_fs(&input.mount.reference, input.mount.options())?;
        let lines = input.lines.unwrap_or(10);
        let call = call_key("graph_fs.head", (&input.path, lines))?;
        let cursor = tree.open_public_cursor(&call, input.cursor.as_deref())?;
        let result = tree.head(&input.path, lines, cursor.as_deref())?;
        Ok(output(&tree, &input.mount, input.path, &call, result))
    }

    pub fn graph_fs_wc(&self, input: GraphFsLinkRequest) -> MemoryResult<GraphFsOutput> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let tree = lane.mount_graph_fs(&input.mount.reference, input.mount.options())?;
        let call = call_key("graph_fs.wc", &input.path)?;
        let result = tree.wc(&input.path)?;
        Ok(output(&tree, &input.mount, input.path, &call, result))
    }
}
