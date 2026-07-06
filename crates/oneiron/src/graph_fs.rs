//! Graph-FS read projection over the vault graph.
//!
//! This is a Plan-9-style read lens, not a storage backend: files are an
//! interface, while memory remains the typed bitemporal graph. Every directory
//! walk is a lazy query through [`crate::claim::ScopedRead`], bounded by a
//! cumulative byte cap and stable cursor order.

use std::collections::BTreeSet;
use std::ops::Bound;

use rmpv::Value;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ScopedRead, decode_claim_body};
use crate::code_sandbox::{SandboxImportClass, SandboxLinkedImport};
use crate::error::{Error, Result};
use crate::gate::{
    PolicyManifestResolution, SCOPED_READ_EFFECTOR_CORE_READ, resolve_policy_manifest,
};
use crate::store::Store;
use crate::types::{
    EDGE_KEY_LEN, ENTITY_ID_LEN, ENTITY_TYPE_CLAIM, ENTITY_TYPE_WORLD, EdgeKind, EntityId,
    bytes_to_hex_lower,
};

pub const GRAPH_FS_PROJECTION_VERSION: &str = "graph-fs.v1";
pub const GRAPH_FS_DEFAULT_PAGE_BYTE_CAP: usize = 16 * 1024;
pub const GRAPH_FS_MIN_PAGE_BYTE_CAP: usize = 256;
pub const GRAPH_FS_MAX_PAGE_BYTE_CAP: usize = 256 * 1024;
pub const GRAPH_FS_DEFAULT_MAX_ENTRIES: usize = 512;
pub const GRAPH_FS_MAX_PAGE_ENTRIES: usize = 4096;
pub const GRAPH_FS_MORE_ENTRY: &str = "_more";

const GRAPH_FS_MAX_SCAN_ROWS: usize = 100_000;
const GRAPH_FS_READDIR_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("graph_fs.readdir", SandboxImportClass::ReadOnly);
const GRAPH_FS_READ_FILE_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("graph_fs.read_file", SandboxImportClass::ReadOnly);
const GRAPH_FS_READ_LINK_IMPORT: SandboxLinkedImport =
    SandboxLinkedImport::new("graph_fs.read_link", SandboxImportClass::ReadOnly);
const GRAPH_FS_MORE_RESERVE_BYTES: usize = 96;

pub const GRAPH_FS_HOST_IMPORTS: &[SandboxLinkedImport] = &[
    GRAPH_FS_READDIR_IMPORT,
    GRAPH_FS_READ_FILE_IMPORT,
    GRAPH_FS_READ_LINK_IMPORT,
];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum GraphFsMount {
    #[default]
    LiveHead,
    ForkHash([u8; 32]),
}

impl GraphFsMount {
    #[must_use]
    pub fn stable_label(self) -> String {
        match self {
            Self::LiveHead => "live-head".to_owned(),
            Self::ForkHash(hash) => format!("forkHash:{}", bytes_to_hex_lower(&hash)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GraphFsOptions {
    mount: GraphFsMount,
    page_byte_cap: usize,
    max_entries: usize,
}

impl Default for GraphFsOptions {
    fn default() -> Self {
        Self {
            mount: GraphFsMount::LiveHead,
            page_byte_cap: GRAPH_FS_DEFAULT_PAGE_BYTE_CAP,
            max_entries: GRAPH_FS_DEFAULT_MAX_ENTRIES,
        }
    }
}

impl GraphFsOptions {
    #[must_use]
    pub fn mount(self) -> GraphFsMount {
        self.mount
    }

    #[must_use]
    pub fn page_byte_cap(self) -> usize {
        self.page_byte_cap
    }

    #[must_use]
    pub fn max_entries(self) -> usize {
        self.max_entries
    }

    #[must_use]
    pub fn with_mount(mut self, mount: GraphFsMount) -> Self {
        self.mount = mount;
        self
    }

    #[must_use]
    pub fn with_page_byte_cap(mut self, page_byte_cap: usize) -> Self {
        self.page_byte_cap =
            page_byte_cap.clamp(GRAPH_FS_MIN_PAGE_BYTE_CAP, GRAPH_FS_MAX_PAGE_BYTE_CAP);
        self
    }

    #[must_use]
    pub fn with_max_entries(mut self, max_entries: usize) -> Self {
        self.max_entries = max_entries.clamp(1, GRAPH_FS_MAX_PAGE_ENTRIES);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphFsEntryKind {
    Directory,
    File,
    Symlink,
    Cursor,
}

impl GraphFsEntryKind {
    fn stable_label(self) -> &'static str {
        match self {
            Self::Directory => "dir",
            Self::File => "file",
            Self::Symlink => "symlink",
            Self::Cursor => "cursor",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphFsEntry {
    name: String,
    kind: GraphFsEntryKind,
    target: Option<String>,
    cursor: Option<String>,
    byte_len: Option<usize>,
}

impl GraphFsEntry {
    #[must_use]
    pub fn directory(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: GraphFsEntryKind::Directory,
            target: None,
            cursor: None,
            byte_len: None,
        }
    }

    #[must_use]
    pub fn file(name: impl Into<String>, byte_len: Option<usize>) -> Self {
        Self {
            name: name.into(),
            kind: GraphFsEntryKind::File,
            target: None,
            cursor: None,
            byte_len,
        }
    }

    #[must_use]
    pub fn symlink(name: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: GraphFsEntryKind::Symlink,
            target: Some(target.into()),
            cursor: None,
            byte_len: None,
        }
    }

    #[must_use]
    pub fn cursor(cursor: impl Into<String>) -> Self {
        Self {
            name: GRAPH_FS_MORE_ENTRY.to_owned(),
            kind: GraphFsEntryKind::Cursor,
            target: None,
            cursor: Some(cursor.into()),
            byte_len: None,
        }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn kind(&self) -> GraphFsEntryKind {
        self.kind
    }

    #[must_use]
    pub fn target(&self) -> Option<&str> {
        self.target.as_deref()
    }

    #[must_use]
    pub fn cursor_token(&self) -> Option<&str> {
        self.cursor.as_deref()
    }

    #[must_use]
    pub fn byte_len(&self) -> Option<usize> {
        self.byte_len
    }

    fn byte_cost(&self) -> usize {
        self.kind.stable_label().len()
            + self.name.len()
            + self.target.as_ref().map_or(0, String::len)
            + self.cursor.as_ref().map_or(0, String::len)
            + self.byte_len.map_or(0, decimal_len)
            + 8
    }

    fn render_line(&self, out: &mut String) {
        out.push_str("entry\t");
        out.push_str(self.kind.stable_label());
        out.push('\t');
        out.push_str(&self.name);
        if let Some(target) = &self.target {
            out.push_str("\ttarget=");
            out.push_str(target);
        }
        if let Some(cursor) = &self.cursor {
            out.push_str("\tcursor=");
            out.push_str(cursor);
        }
        if let Some(byte_len) = self.byte_len {
            out.push_str("\tbytes=");
            out.push_str(&byte_len.to_string());
        }
        out.push('\n');
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphFsPage {
    path: String,
    mount: GraphFsMount,
    entries: Vec<GraphFsEntry>,
    next_cursor: Option<String>,
    byte_count: usize,
}

impl GraphFsPage {
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub fn mount(&self) -> GraphFsMount {
        self.mount
    }

    #[must_use]
    pub fn entries(&self) -> &[GraphFsEntry] {
        &self.entries
    }

    #[must_use]
    pub fn next_cursor(&self) -> Option<&str> {
        self.next_cursor.as_deref()
    }

    #[must_use]
    pub fn byte_count(&self) -> usize {
        self.byte_count
    }

    #[must_use]
    pub fn render_bytes(&self) -> Vec<u8> {
        let mut out = String::new();
        out.push_str(GRAPH_FS_PROJECTION_VERSION);
        out.push('\n');
        out.push_str("path\t");
        out.push_str(&self.path);
        out.push('\n');
        out.push_str("mount\t");
        out.push_str(&self.mount.stable_label());
        out.push('\n');
        for entry in &self.entries {
            entry.render_line(&mut out);
        }
        out.into_bytes()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphFsFile {
    path: String,
    mount: GraphFsMount,
    bytes: Vec<u8>,
}

impl GraphFsFile {
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub fn mount(&self) -> GraphFsMount {
        self.mount
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

pub struct GraphFsResolver<'read, 'vault> {
    scoped_read: &'read ScopedRead<'vault>,
    options: GraphFsOptions,
}

impl<'vault> ScopedRead<'vault> {
    #[must_use]
    pub fn graph_fs(&self, options: GraphFsOptions) -> GraphFsResolver<'_, 'vault> {
        GraphFsResolver::new(self, options)
    }
}

impl<'read, 'vault> GraphFsResolver<'read, 'vault> {
    #[must_use]
    pub fn new(scoped_read: &'read ScopedRead<'vault>, options: GraphFsOptions) -> Self {
        Self {
            scoped_read,
            options,
        }
    }

    #[must_use]
    pub fn host_imports(&self) -> &'static [SandboxLinkedImport] {
        GRAPH_FS_HOST_IMPORTS
    }

    pub fn readdir(&self, path: &str, cursor: Option<&str>) -> Result<GraphFsPage> {
        let normalized = normalize_path(path)?;
        let components = path_components(&normalized)?;
        match components.as_slice() {
            [] => Ok(self.fixed_page(
                &normalized,
                vec![
                    GraphFsEntry::directory("worlds"),
                    GraphFsEntry::directory("entities"),
                    GraphFsEntry::directory("claims"),
                    GraphFsEntry::directory("backlinks"),
                ],
                cursor,
            )),
            ["worlds"] => self.listdir_worlds(&normalized, cursor),
            ["worlds", world] => {
                let page = self.fixed_page(
                    &normalized,
                    vec![
                        GraphFsEntry::directory("claims"),
                        GraphFsEntry::directory("backlinks"),
                        GraphFsEntry::file("scope", None),
                    ],
                    cursor,
                );
                if *world == "base" || EntityId::from_hex(world).is_ok() {
                    Ok(page)
                } else {
                    Ok(empty_page(&normalized, self.options.mount))
                }
            }
            ["worlds", world, "claims"] => self.listdir_claims_in_world(&normalized, world, cursor),
            ["worlds", world, "backlinks"] => {
                if *world == "base" {
                    Ok(empty_page(&normalized, self.options.mount))
                } else {
                    self.listdir_backlinks(&normalized, &parse_entity_id(world)?, cursor)
                }
            }
            ["entities"] => self.listdir_entities(&normalized, cursor),
            ["entities", entity] => {
                let id = parse_entity_id(entity)?;
                if self.scoped_read.is_entity_readable(&id)? {
                    Ok(self.fixed_page(
                        &normalized,
                        vec![
                            GraphFsEntry::directory("claims"),
                            GraphFsEntry::directory("backlinks"),
                            GraphFsEntry::file("body", self.scoped_read.get(&id)?.map(|b| b.len())),
                        ],
                        cursor,
                    ))
                } else {
                    Ok(empty_page(&normalized, self.options.mount))
                }
            }
            ["entities", entity, "claims"] => {
                self.listdir_claims_for_subject(&normalized, &parse_entity_id(entity)?, cursor)
            }
            ["entities", entity, "backlinks"] => {
                self.listdir_backlinks(&normalized, &parse_entity_id(entity)?, cursor)
            }
            ["claims"] => Ok(self.fixed_page(
                &normalized,
                vec![
                    GraphFsEntry::directory("by-time"),
                    GraphFsEntry::directory("by-id"),
                ],
                cursor,
            )),
            ["claims", "by-time"] => self.listdir_claim_days(&normalized, cursor),
            ["claims", "by-time", day] => self.listdir_claims_in_day(&normalized, day, cursor),
            ["claims", "by-id"] => self.listdir_claims_by_id(&normalized, cursor),
            ["backlinks"] => self.listdir_entities(&normalized, cursor),
            ["backlinks", entity] => {
                self.listdir_backlinks(&normalized, &parse_entity_id(entity)?, cursor)
            }
            _ => Ok(empty_page(&normalized, self.options.mount)),
        }
    }

    pub fn readdir_bytes(&self, path: &str, cursor: Option<&str>) -> Result<Vec<u8>> {
        Ok(self.readdir(path, cursor)?.render_bytes())
    }

    pub fn read_file(&self, path: &str) -> Result<Option<GraphFsFile>> {
        let normalized = normalize_path(path)?;
        let components = path_components(&normalized)?;
        match components.as_slice() {
            ["claims", claim] | ["claims", "by-id", claim] => {
                self.read_claim_file(&normalized, &parse_entity_id(claim)?)
            }
            ["entities", entity, "body"] => {
                let id = parse_entity_id(entity)?;
                let Some(bytes) = self.scoped_read.get(&id)? else {
                    return Ok(None);
                };
                Ok(Some(GraphFsFile {
                    path: normalized,
                    mount: self.options.mount,
                    bytes,
                }))
            }
            ["worlds", world, "scope"] => {
                let bytes = if *world == "base" {
                    b"base\n".to_vec()
                } else {
                    let id = parse_entity_id(world)?;
                    format!("world_ref:{}\n", id.to_hex()).into_bytes()
                };
                Ok(Some(GraphFsFile {
                    path: normalized,
                    mount: self.options.mount,
                    bytes,
                }))
            }
            _ => Ok(None),
        }
    }

    pub fn read_link(&self, path: &str) -> Result<Option<String>> {
        let normalized = normalize_path(path)?;
        let components = path_components(&normalized)?;
        let [component] = components.as_slice() else {
            return Ok(None);
        };
        let Some(claim_hex) = component
            .strip_prefix("[[claim:")
            .and_then(|rest| rest.strip_suffix("]]"))
        else {
            return Ok(None);
        };
        let claim_id = parse_entity_id(claim_hex)?;
        if self.scoped_read.get(&claim_id)?.is_some() {
            Ok(Some(format!("/claims/{}", claim_id.to_hex())))
        } else {
            Ok(None)
        }
    }

    fn read_claim_file(&self, path: &str, claim_id: &EntityId) -> Result<Option<GraphFsFile>> {
        let Some((entity_type, learned_at, body)) = self.scoped_read.get_entity_parts(claim_id)?
        else {
            return Ok(None);
        };
        if entity_type != ENTITY_TYPE_CLAIM {
            return Ok(None);
        }
        let mut bytes = Vec::new();
        bytes.extend_from_slice(GRAPH_FS_PROJECTION_VERSION.as_bytes());
        bytes.extend_from_slice(b"\nkind\tclaim\nmount\t");
        bytes.extend_from_slice(self.options.mount.stable_label().as_bytes());
        bytes.extend_from_slice(b"\nid\t");
        bytes.extend_from_slice(claim_id.to_hex().as_bytes());
        bytes.extend_from_slice(b"\nlearned_at\t");
        bytes.extend_from_slice(learned_at.to_string().as_bytes());
        bytes.extend_from_slice(b"\nbody_msgpack_hex\t");
        bytes.extend_from_slice(bytes_to_hex_lower(&body).as_bytes());
        bytes.push(b'\n');
        Ok(Some(GraphFsFile {
            path: path.to_owned(),
            mount: self.options.mount,
            bytes,
        }))
    }

    fn fixed_page(
        &self,
        path: &str,
        entries: Vec<GraphFsEntry>,
        cursor: Option<&str>,
    ) -> GraphFsPage {
        let after = cursor.unwrap_or_default();
        let mut builder = PageBuilder::new(path, self.options);
        let mut sorted = entries;
        sorted.sort_by(|left, right| left.name.cmp(&right.name));
        let mut next_cursor = None;
        for entry in sorted {
            if !after.is_empty() && entry.name.as_str() <= after {
                continue;
            }
            if !builder.try_push(entry.clone()) {
                next_cursor = builder.last_entry_name();
                break;
            }
        }
        builder.finish(next_cursor)
    }

    fn listdir_worlds(&self, path: &str, cursor: Option<&str>) -> Result<GraphFsPage> {
        let policy = self.policy()?;
        if policy.diagnostics().loaded_manifest_forces_fail_closed() {
            return Ok(empty_page(path, self.options.mount));
        }

        let names = if policy.has_scoped_read_grants() {
            self.world_names_from_matching_grants(&policy)
        } else {
            return self.listdir_world_rows(path, cursor);
        };
        let entries = names.into_iter().map(GraphFsEntry::directory).collect();
        Ok(self.fixed_page(path, entries, cursor))
    }

    fn listdir_world_rows(&self, path: &str, cursor: Option<&str>) -> Result<GraphFsPage> {
        let after = cursor.unwrap_or_default();
        let after_world = if after.is_empty() || after == "base" {
            None
        } else {
            Some(parse_entity_id(after)?)
        };
        let mut builder = PageBuilder::new(path, self.options);
        let mut next_cursor = None;
        if after.is_empty() && !builder.try_push(GraphFsEntry::directory("base")) {
            return Ok(builder.finish(None));
        }

        let rows = self.scoped_read.vault().entities_by_type_page(
            ENTITY_TYPE_WORLD,
            after_world.as_ref(),
            GRAPH_FS_MAX_PAGE_ENTRIES.saturating_add(1),
        )?;
        let has_more_rows = rows.len() > GRAPH_FS_MAX_PAGE_ENTRIES;
        for id in rows.into_iter().take(GRAPH_FS_MAX_PAGE_ENTRIES) {
            if !builder.try_push(GraphFsEntry::directory(id.to_hex())) {
                next_cursor = builder.last_entry_name();
                break;
            }
        }
        if next_cursor.is_none() && has_more_rows {
            next_cursor = builder.last_entry_name();
        }
        Ok(builder.finish(next_cursor))
    }

    fn world_names_from_matching_grants(&self, policy: &PolicyManifestResolution) -> Vec<String> {
        let mut names = BTreeSet::new();
        for grant in policy.scoped_grants() {
            if !read_grant_matches_actor(grant, self.scoped_read.actor_key()) {
                continue;
            }
            if grant.receipt_required || grant.budget.is_some() {
                continue;
            }
            if let Some(name) = grant_scope_world_name(grant.scope.as_ref()) {
                names.insert(name);
            }
        }
        names.into_iter().collect()
    }

    fn listdir_entities(&self, path: &str, cursor: Option<&str>) -> Result<GraphFsPage> {
        let cursor = TemporalCursor::parse_optional(cursor)?;
        let mut builder = PageBuilder::new(path, self.options);
        let mut next_cursor = None;
        let mut last_scanned = None;
        let rtxn = self.scoped_read.vault().store.env.read_txn()?;
        let policy = self.scoped_read.policy_manifest_in(&rtxn)?;
        let start_key = cursor.map_or_else(Vec::new, |cursor| cursor.next_temporal_key().to_vec());
        let lower = if start_key.is_empty() {
            Bound::Unbounded
        } else {
            Bound::Included(&start_key[..])
        };
        let upper = Bound::Unbounded;
        for (scanned, entry) in self
            .scoped_read
            .vault()
            .store
            .temporal_learned
            .range(&rtxn, &(lower, upper))?
            .enumerate()
        {
            if scanned >= GRAPH_FS_MAX_SCAN_ROWS {
                next_cursor = last_scanned.map(|cursor: TemporalCursor| cursor.encode());
                break;
            }
            let (key, _) = entry?;
            let cursor = temporal_cursor_from_key(key)?;
            last_scanned = Some(cursor);
            if !self
                .scoped_read
                .is_entity_readable_with_policy_in(&rtxn, &policy, &cursor.id)?
            {
                continue;
            }
            let entry = GraphFsEntry::directory(cursor.id.to_hex());
            if !builder.try_push(entry) {
                next_cursor = builder.last_temporal_cursor();
                break;
            }
            builder.set_last_temporal_cursor(cursor);
        }
        Ok(builder.finish(next_cursor))
    }

    fn listdir_claims_by_id(&self, path: &str, cursor: Option<&str>) -> Result<GraphFsPage> {
        let after = cursor.map(parse_entity_id).transpose()?;
        let mut builder = PageBuilder::new(path, self.options);
        let mut next_cursor = None;
        for id in self.scoped_read.vault().entities_by_type_page(
            ENTITY_TYPE_CLAIM,
            after.as_ref(),
            GRAPH_FS_MAX_PAGE_ENTRIES,
        )? {
            if self.scoped_read.get(&id)?.is_none() {
                continue;
            }
            let entry = GraphFsEntry::file(id.to_hex(), None);
            if !builder.try_push(entry) {
                next_cursor = builder.last_entry_name();
                break;
            }
        }
        Ok(builder.finish(next_cursor))
    }

    fn listdir_claims_for_subject(
        &self,
        path: &str,
        subject: &EntityId,
        cursor: Option<&str>,
    ) -> Result<GraphFsPage> {
        if !self.scoped_read.is_entity_readable(subject)? {
            return Ok(empty_page(path, self.options.mount));
        }
        let after = cursor.map(parse_entity_id).transpose()?;
        let mut builder = PageBuilder::new(path, self.options);
        let mut next_cursor = None;
        for claim in self.scoped_read.vault().sources_page(
            subject,
            EdgeKind::ClaimOf,
            Some(ENTITY_TYPE_CLAIM),
            after.as_ref(),
            GRAPH_FS_MAX_PAGE_ENTRIES,
        )? {
            if self.scoped_read.get(&claim)?.is_none() {
                continue;
            }
            let entry = GraphFsEntry::file(claim.to_hex(), None);
            if !builder.try_push(entry) {
                next_cursor = builder.last_entry_name();
                break;
            }
        }
        Ok(builder.finish(next_cursor))
    }

    fn listdir_claims_in_world(
        &self,
        path: &str,
        world: &str,
        cursor: Option<&str>,
    ) -> Result<GraphFsPage> {
        let world = parse_world_scope(world)?;
        let cursor = TemporalCursor::parse_optional(cursor)?;
        let mut builder = PageBuilder::new(path, self.options);
        let mut next_cursor = None;
        let mut last_scanned = None;
        let rtxn = self.scoped_read.vault().store.env.read_txn()?;
        let policy = self.scoped_read.policy_manifest_in(&rtxn)?;
        let start_key = cursor.map_or_else(Vec::new, |cursor| cursor.next_temporal_key().to_vec());
        let lower = if start_key.is_empty() {
            Bound::Unbounded
        } else {
            Bound::Included(&start_key[..])
        };
        let upper = Bound::Unbounded;
        for (scanned, entry) in self
            .scoped_read
            .vault()
            .store
            .temporal_learned
            .range(&rtxn, &(lower, upper))?
            .enumerate()
        {
            if scanned >= GRAPH_FS_MAX_SCAN_ROWS {
                next_cursor = last_scanned.map(|cursor: TemporalCursor| cursor.encode());
                break;
            }
            let (key, _) = entry?;
            let temporal = temporal_cursor_from_key(key)?;
            last_scanned = Some(temporal);
            if !self
                .scoped_read
                .is_entity_readable_with_policy_in(&rtxn, &policy, &temporal.id)?
            {
                continue;
            }
            if !claim_matches_world_in(&self.scoped_read.vault().store, &rtxn, &temporal.id, world)?
            {
                continue;
            }
            let entry = GraphFsEntry::file(temporal.id.to_hex(), None);
            if !builder.try_push(entry) {
                next_cursor = builder.last_temporal_cursor();
                break;
            }
            builder.set_last_temporal_cursor(temporal);
        }
        Ok(builder.finish(next_cursor))
    }

    fn listdir_backlinks(
        &self,
        path: &str,
        target: &EntityId,
        cursor: Option<&str>,
    ) -> Result<GraphFsPage> {
        if !self.scoped_read.is_entity_readable(target)? {
            return Ok(empty_page(path, self.options.mount));
        }
        let after = cursor.map(parse_edge_cursor).transpose()?;
        let mut builder = PageBuilder::new(path, self.options);
        let mut next_cursor = None;
        let mut last_cursor = after;
        let rtxn = self.scoped_read.vault().store.env.read_txn()?;
        let policy = self.scoped_read.policy_manifest_in(&rtxn)?;
        let prefix = target.as_bytes();
        let start_key = after.map(|cursor| edge_cursor_key(target, cursor));
        let lower = match &start_key {
            Some(key) => Bound::Excluded(&key[..]),
            None => Bound::Included(&prefix[..]),
        };
        let upper = Bound::Unbounded;
        for (scanned, entry) in self
            .scoped_read
            .vault()
            .store
            .edges_in
            .range(&rtxn, &(lower, upper))?
            .enumerate()
        {
            if scanned >= GRAPH_FS_MAX_SCAN_ROWS {
                next_cursor = last_cursor.map(|cursor| cursor.encode());
                break;
            }
            let (key, value) = entry?;
            if !key.starts_with(prefix) {
                break;
            }
            let cursor = edge_cursor_from_key(key)?;
            let edge = crate::vault::parse_edge_record(key, value)?;
            if !self
                .scoped_read
                .is_entity_readable_with_policy_in(&rtxn, &policy, &edge.target)?
            {
                continue;
            }
            let name = format!("{}-{}", edge.kind as u8, edge.target.to_hex());
            let entry = GraphFsEntry::symlink(name, format!("/entities/{}", edge.target.to_hex()));
            if !builder.try_push(entry) {
                next_cursor = last_cursor.map(|cursor| cursor.encode());
                break;
            }
            last_cursor = Some(cursor);
        }
        Ok(builder.finish(next_cursor))
    }

    fn listdir_claim_days(&self, path: &str, cursor: Option<&str>) -> Result<GraphFsPage> {
        let after_day = cursor.map(parse_day_shard).transpose()?;
        let mut days = BTreeSet::new();
        let mut builder = PageBuilder::new(path, self.options);
        let mut next_cursor = None;
        let rtxn = self.scoped_read.vault().store.env.read_txn()?;
        let policy = self.scoped_read.policy_manifest_in(&rtxn)?;
        let lower_key = after_day
            .and_then(|day| day.checked_add(1))
            .and_then(|day| day.checked_mul(86_400))
            .map(u64::to_be_bytes);
        let lower = match &lower_key {
            Some(key) => Bound::Included(&key[..]),
            None => Bound::Unbounded,
        };
        let upper = Bound::Unbounded;
        for (scanned, entry) in self
            .scoped_read
            .vault()
            .store
            .temporal_learned
            .range(&rtxn, &(lower, upper))?
            .enumerate()
        {
            if scanned >= GRAPH_FS_MAX_SCAN_ROWS {
                next_cursor = builder.last_entry_name();
                break;
            }
            let (key, _) = entry?;
            let temporal = temporal_cursor_from_key(key)?;
            if !self
                .scoped_read
                .is_entity_readable_with_policy_in(&rtxn, &policy, &temporal.id)?
            {
                continue;
            }
            let day = temporal.learned_at / 86_400;
            if !days.insert(day) {
                continue;
            }
            let day_name = format_day_shard(day);
            let entry = GraphFsEntry::directory(day_name);
            if !builder.try_push(entry) {
                next_cursor = builder.last_entry_name();
                break;
            }
        }
        Ok(builder.finish(next_cursor))
    }

    fn listdir_claims_in_day(
        &self,
        path: &str,
        day: &str,
        cursor: Option<&str>,
    ) -> Result<GraphFsPage> {
        let day = parse_day_shard(day)?;
        let start = day
            .checked_mul(86_400)
            .ok_or_else(|| Error::InvalidConfig("graph-fs day shard overflowed".to_owned()))?;
        let end = start
            .checked_add(86_400)
            .ok_or_else(|| Error::InvalidConfig("graph-fs day shard overflowed".to_owned()))?;
        let cursor = TemporalCursor::parse_optional(cursor)?;
        let mut builder = PageBuilder::new(path, self.options);
        let mut next_cursor = None;
        let mut last_scanned = None;
        let rtxn = self.scoped_read.vault().store.env.read_txn()?;
        let policy = self.scoped_read.policy_manifest_in(&rtxn)?;
        let start_key = cursor.map_or_else(
            || start.to_be_bytes().to_vec(),
            |cursor| cursor.next_temporal_key().to_vec(),
        );
        let end_key = end.to_be_bytes();
        for (scanned, entry) in self
            .scoped_read
            .vault()
            .store
            .temporal_learned
            .range(
                &rtxn,
                &(
                    Bound::Included(&start_key[..]),
                    Bound::Excluded(&end_key[..]),
                ),
            )?
            .enumerate()
        {
            if scanned >= GRAPH_FS_MAX_SCAN_ROWS {
                next_cursor = last_scanned.map(|cursor: TemporalCursor| cursor.encode());
                break;
            }
            let (key, _) = entry?;
            let temporal = temporal_cursor_from_key(key)?;
            last_scanned = Some(temporal);
            if !self
                .scoped_read
                .is_entity_readable_with_policy_in(&rtxn, &policy, &temporal.id)?
            {
                continue;
            }
            let entry = GraphFsEntry::file(temporal.id.to_hex(), None);
            if !builder.try_push(entry) {
                next_cursor = builder.last_temporal_cursor();
                break;
            }
            builder.set_last_temporal_cursor(temporal);
        }
        Ok(builder.finish(next_cursor))
    }

    fn policy(&self) -> Result<PolicyManifestResolution> {
        let rtxn = self.scoped_read.vault().store.env.read_txn()?;
        resolve_policy_manifest(&self.scoped_read.vault().store, &rtxn)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TemporalCursor {
    learned_at: u64,
    id: EntityId,
}

impl TemporalCursor {
    fn parse_optional(value: Option<&str>) -> Result<Option<Self>> {
        value.map(Self::parse).transpose()
    }

    fn parse(value: &str) -> Result<Self> {
        let Some((learned, id)) = value.split_once(':') else {
            return Err(Error::InvalidConfig(
                "invalid graph-fs temporal cursor".to_owned(),
            ));
        };
        let learned_at = learned
            .parse::<u64>()
            .map_err(|_| Error::InvalidConfig("invalid graph-fs temporal cursor".to_owned()))?;
        Ok(Self {
            learned_at,
            id: parse_entity_id(id)?,
        })
    }

    fn encode(self) -> String {
        format!("{}:{}", self.learned_at, self.id.to_hex())
    }

    fn next_temporal_key(self) -> [u8; 24] {
        let mut key = Store::encode_temporal_key(self.learned_at, &self.id);
        increment_lexicographic_key(&mut key);
        key
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct EdgeCursor {
    kind: u8,
    source: EntityId,
}

impl EdgeCursor {
    fn encode(self) -> String {
        format!("{}:{}", self.kind, self.source.to_hex())
    }
}

struct PageBuilder {
    path: String,
    mount: GraphFsMount,
    byte_cap: usize,
    max_entries: usize,
    entries: Vec<GraphFsEntry>,
    byte_count: usize,
    last_temporal_cursor: Option<TemporalCursor>,
}

impl PageBuilder {
    fn new(path: &str, options: GraphFsOptions) -> Self {
        Self {
            path: path.to_owned(),
            mount: options.mount,
            byte_cap: options.page_byte_cap,
            max_entries: options.max_entries,
            entries: Vec::new(),
            byte_count: 0,
            last_temporal_cursor: None,
        }
    }

    fn try_push(&mut self, entry: GraphFsEntry) -> bool {
        if self.entries.len() >= self.max_entries {
            return false;
        }
        let cost = entry.byte_cost();
        let entry_cap = if self.entries.is_empty() {
            self.byte_cap
        } else {
            self.byte_cap.saturating_sub(GRAPH_FS_MORE_RESERVE_BYTES)
        };
        if self.byte_count + cost > entry_cap {
            return false;
        }
        self.byte_count += cost;
        self.entries.push(entry);
        true
    }

    fn last_entry_name(&self) -> Option<String> {
        self.entries
            .iter()
            .rev()
            .find(|entry| entry.kind != GraphFsEntryKind::Cursor)
            .map(|entry| entry.name.clone())
    }

    fn set_last_temporal_cursor(&mut self, cursor: TemporalCursor) {
        self.last_temporal_cursor = Some(cursor);
    }

    fn last_temporal_cursor(&self) -> Option<String> {
        self.last_temporal_cursor.map(TemporalCursor::encode)
    }

    fn finish(mut self, next_cursor: Option<String>) -> GraphFsPage {
        if let Some(cursor) = next_cursor.clone() {
            let more = GraphFsEntry::cursor(cursor);
            while self.byte_count + more.byte_cost() > self.byte_cap {
                let Some(removed) = self.entries.pop() else {
                    break;
                };
                self.byte_count = self.byte_count.saturating_sub(removed.byte_cost());
            }
            if self.byte_count + more.byte_cost() <= self.byte_cap {
                self.byte_count += more.byte_cost();
                self.entries.push(more);
            }
        }
        GraphFsPage {
            path: self.path,
            mount: self.mount,
            entries: self.entries,
            next_cursor,
            byte_count: self.byte_count,
        }
    }
}

fn empty_page(path: &str, mount: GraphFsMount) -> GraphFsPage {
    GraphFsPage {
        path: path.to_owned(),
        mount,
        entries: Vec::new(),
        next_cursor: None,
        byte_count: 0,
    }
}

fn normalize_path(path: &str) -> Result<String> {
    if !path.starts_with('/') {
        return Err(Error::InvalidConfig(
            "graph-fs path must be absolute".to_owned(),
        ));
    }
    let normalized = path.trim_end_matches('/');
    if normalized.is_empty() {
        Ok("/".to_owned())
    } else {
        Ok(normalized.to_owned())
    }
}

fn path_components(path: &str) -> Result<Vec<&str>> {
    if path == "/" {
        return Ok(Vec::new());
    }
    let mut components = Vec::new();
    for component in path.trim_start_matches('/').split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(Error::InvalidConfig(
                "graph-fs path component is invalid".to_owned(),
            ));
        }
        components.push(component);
    }
    Ok(components)
}

fn parse_entity_id(value: &str) -> Result<EntityId> {
    EntityId::from_hex(value)
}

fn decimal_len(mut value: usize) -> usize {
    let mut len = 1;
    while value >= 10 {
        value /= 10;
        len += 1;
    }
    len
}

fn read_grant_matches_actor(
    grant: &crate::gate::PolicyScopedGrant,
    actor_key: &crate::claim::ScopedReadActorKey,
) -> bool {
    if grant.effector.trim() != SCOPED_READ_EFFECTOR_CORE_READ
        && grant.effector.trim() != "oneiron.read"
    {
        return false;
    }
    if let Some(actor_ref) = grant.actor_ref.as_deref()
        && actor_ref != actor_key.actor_ref()
    {
        return false;
    }
    if let Some(actor_class) = grant.actor_class.as_deref()
        && Some(actor_class) != actor_key.actor_class()
    {
        return false;
    }
    true
}

fn grant_scope_world_name(scope: Option<&Value>) -> Option<String> {
    let Some(scope) = scope else {
        return Some("base".to_owned());
    };
    match scope {
        Value::Nil => Some("base".to_owned()),
        Value::Map(entries) if entries.is_empty() => Some("base".to_owned()),
        Value::Map(entries) => {
            for (key, value) in entries {
                let key = key.as_str()?;
                if !matches!(key, "world" | "world_ref" | "worldRef") {
                    continue;
                }
                if matches!(value, Value::Nil) || value.as_str().is_some_and(|text| text == "base")
                {
                    return Some("base".to_owned());
                }
                let id = value
                    .as_str()
                    .and_then(|text| EntityId::from_hex(text).ok())
                    .or_else(|| match value {
                        Value::Binary(bytes) => bytes
                            .as_slice()
                            .try_into()
                            .ok()
                            .and_then(|bytes| EntityId::from_bytes(bytes).ok()),
                        _ => None,
                    })?;
                return Some(id.to_hex());
            }
            None
        }
        _ => None,
    }
}

fn parse_world_scope(value: &str) -> Result<Option<EntityId>> {
    if value == "base" {
        Ok(None)
    } else {
        parse_entity_id(value).map(Some)
    }
}

fn claim_matches_world_in(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    claim_id: &EntityId,
    world: Option<EntityId>,
) -> Result<bool> {
    let Some(raw) = store.entities.get(rtxn, claim_id.as_bytes())? else {
        return Ok(false);
    };
    let header = EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_CLAIM {
        return Ok(false);
    }
    let body = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
    Ok(body.world == world)
}

fn temporal_cursor_from_key(key: &[u8]) -> Result<TemporalCursor> {
    if key.len() != 24 {
        return Err(Error::CorruptedIndex("temporal learned key"));
    }
    let learned_at = u64::from_be_bytes(
        key[..8]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("temporal learned key"))?,
    );
    let id = EntityId::from_bytes(
        key[8..24]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("temporal learned key"))?,
    )
    .map_err(|_| Error::CorruptedIndex("temporal learned key"))?;
    Ok(TemporalCursor { learned_at, id })
}

fn edge_cursor_from_key(key: &[u8]) -> Result<EdgeCursor> {
    if key.len() != EDGE_KEY_LEN {
        return Err(Error::CorruptedIndex("edge record"));
    }
    let kind = key[ENTITY_ID_LEN];
    let source = EntityId::from_bytes(
        key[ENTITY_ID_LEN + 1..]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("edge record"))?,
    )
    .map_err(|_| Error::CorruptedIndex("edge record"))?;
    Ok(EdgeCursor { kind, source })
}

fn parse_edge_cursor(value: &str) -> Result<EdgeCursor> {
    let Some((kind, source)) = value.split_once(':') else {
        return Err(Error::InvalidConfig(
            "invalid graph-fs edge cursor".to_owned(),
        ));
    };
    let kind = kind
        .parse::<u8>()
        .map_err(|_| Error::InvalidConfig("invalid graph-fs edge cursor".to_owned()))?;
    Ok(EdgeCursor {
        kind,
        source: parse_entity_id(source)?,
    })
}

fn edge_cursor_key(target: &EntityId, cursor: EdgeCursor) -> Vec<u8> {
    let mut key = Vec::with_capacity(EDGE_KEY_LEN);
    key.extend_from_slice(target.as_bytes());
    key.push(cursor.kind);
    key.extend_from_slice(cursor.source.as_bytes());
    key
}

fn increment_lexicographic_key(key: &mut [u8]) {
    for byte in key.iter_mut().rev() {
        if *byte == u8::MAX {
            *byte = 0;
        } else {
            *byte += 1;
            return;
        }
    }
}

fn format_day_shard(day: u64) -> String {
    let (year, month, day_of_month) = civil_from_days(day as i64);
    format!("{year:04}-{month:02}-{day_of_month:02}")
}

fn parse_day_shard(value: &str) -> Result<u64> {
    let mut parts = value.split('-');
    let Some(year) = parts.next() else {
        return Err(Error::InvalidConfig(
            "invalid graph-fs day shard".to_owned(),
        ));
    };
    let Some(month) = parts.next() else {
        return Err(Error::InvalidConfig(
            "invalid graph-fs day shard".to_owned(),
        ));
    };
    let Some(day) = parts.next() else {
        return Err(Error::InvalidConfig(
            "invalid graph-fs day shard".to_owned(),
        ));
    };
    if parts.next().is_some() {
        return Err(Error::InvalidConfig(
            "invalid graph-fs day shard".to_owned(),
        ));
    }
    let year = year
        .parse::<i32>()
        .map_err(|_| Error::InvalidConfig("invalid graph-fs day shard".to_owned()))?;
    let month = month
        .parse::<u32>()
        .map_err(|_| Error::InvalidConfig("invalid graph-fs day shard".to_owned()))?;
    let day = day
        .parse::<u32>()
        .map_err(|_| Error::InvalidConfig("invalid graph-fs day shard".to_owned()))?;
    let days = days_from_civil(year, month, day)
        .ok_or_else(|| Error::InvalidConfig("invalid graph-fs day shard".to_owned()))?;
    u64::try_from(days).map_err(|_| Error::InvalidConfig("invalid graph-fs day shard".to_owned()))
}

fn civil_from_days(days_since_epoch: i64) -> (i32, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year as i32, m as u32, d as u32)
}

fn days_from_civil(year: i32, month: u32, day: u32) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let year = i64::from(year) - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let month = i64::from(month);
    let day = i64::from(day);
    let mp = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    if !(0..=365).contains(&doy) {
        return None;
    }
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let (roundtrip_year, roundtrip_month, roundtrip_day) = civil_from_days(days);
    if roundtrip_year == year as i32 + i32::from(month <= 2)
        && roundtrip_month == month as u32
        && roundtrip_day == day as u32
    {
        Some(days)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batch::{BatchOp, apply_ops};
    use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
    use crate::test_util::open_test_vault_with;
    use crate::types::{ENTITY_TYPE_PERSON, TimeRange, VaultConfig};

    fn test_id(seed: u8) -> EntityId {
        EntityId::from_bytes([seed; 16]).expect("valid id")
    }

    fn time_range(ts: u64) -> TimeRange {
        TimeRange { start: ts, end: ts }
    }

    fn put_entity(vault: &crate::Vault, id: EntityId, entity_type: u8) -> Result<()> {
        vault.put_entity(&id, entity_type, time_range(1), 1, b"entity")
    }

    fn put_claim(
        vault: &crate::Vault,
        id: EntityId,
        subject: EntityId,
        world: Option<EntityId>,
        learned_at: u64,
    ) -> Result<()> {
        let mut body = ClaimBody::new(
            "profile.note",
            ClaimSubject::Entity(subject),
            Value::from(format!("claim-{}", id.to_hex())),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        body.world = world;
        vault.put_claim(&id, &body, time_range(learned_at), learned_at)
    }

    fn encode_policy_manifest(scoped_grants: Vec<Value>) -> Vec<u8> {
        let value = Value::Map(vec![
            (Value::from("schema_version"), Value::from("1.1")),
            (Value::from("pack_id"), Value::from("graph-fs-test")),
            (Value::from("pack_version"), Value::from("1")),
            (Value::from("min_engine_version"), Value::from("0.0.0")),
            (Value::from("defaults"), Value::Map(Vec::new())),
            (Value::from("rules"), Value::Array(Vec::new())),
            (Value::from("actor_ceilings"), Value::Array(Vec::new())),
            (Value::from("scoped_grants"), Value::Array(scoped_grants)),
        ]);
        let mut data = Vec::new();
        rmpv::encode::write_value(&mut data, &value).expect("policy manifest encodes");
        data
    }

    fn core_read_world_grant(actor_ref: &str, world: EntityId) -> Value {
        Value::Map(vec![
            (Value::from("actor_ref"), Value::from(actor_ref)),
            (Value::from("effector"), Value::from("core:read")),
            (
                Value::from("scope"),
                Value::Map(vec![(
                    Value::from("world_ref"),
                    Value::from(world.to_hex()),
                )]),
            ),
            (Value::from("receipt_required"), Value::Boolean(false)),
        ])
    }

    fn put_policy_manifest(vault: &crate::Vault, id: EntityId, data: Vec<u8>) -> Result<()> {
        let ops = vec![BatchOp::Put {
            id,
            entity_type: crate::types::ENTITY_TYPE_POLICY_MANIFEST,
            occurred: time_range(1),
            learned_at: 1,
            data,
            allow_maintenance: true,
            allow_reserved_predicate: false,
        }];
        let mut wtxn = vault.store.env.write_txn()?;
        apply_ops(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            &mut wtxn,
            ops,
            true,
            false,
            true,
        )?;
        wtxn.commit()?;
        Ok(())
    }

    fn resolver<'read, 'vault>(
        read: &'read ScopedRead<'vault>,
        cap: usize,
    ) -> GraphFsResolver<'read, 'vault> {
        read.graph_fs(GraphFsOptions::default().with_page_byte_cap(cap))
    }

    #[test]
    fn worlds_readdir_omits_excluded_worlds_entirely() -> Result<()> {
        let (_tmp, vault) = open_test_vault_with(VaultConfig::default());
        let allowed_world = test_id(0x31);
        let excluded_world = test_id(0x32);
        let subject = test_id(0x33);
        let allowed_claim = test_id(0x41);
        let excluded_claim = test_id(0x42);
        put_entity(&vault, allowed_world, ENTITY_TYPE_WORLD)?;
        put_entity(&vault, excluded_world, ENTITY_TYPE_WORLD)?;
        put_entity(&vault, subject, ENTITY_TYPE_PERSON)?;
        put_claim(&vault, allowed_claim, subject, Some(allowed_world), 10)?;
        put_claim(&vault, excluded_claim, subject, Some(excluded_world), 11)?;
        put_policy_manifest(
            &vault,
            test_id(0x90),
            encode_policy_manifest(vec![core_read_world_grant("reader", allowed_world)]),
        )?;

        let reader =
            vault.scoped_read(crate::claim::ScopedReadActorKey::new("reader").expect("actor key"));
        let page = resolver(&reader, 1024).readdir("/worlds/", None)?;
        let names: Vec<_> = page.entries().iter().map(GraphFsEntry::name).collect();

        assert!(names.contains(&allowed_world.to_hex().as_str()));
        assert!(
            !names.contains(&excluded_world.to_hex().as_str()),
            "owner-excluded world must be absent from readdir, not listed as forbidden"
        );
        assert!(
            !page
                .render_bytes()
                .windows(excluded_world.to_hex().len())
                .any(|window| window == excluded_world.to_hex().as_bytes()),
            "rendered bytes must not leak the excluded world id"
        );

        let allowed_world_claims = resolver(&reader, 1024)
            .readdir(&format!("/worlds/{}/claims", allowed_world.to_hex()), None)?;
        let allowed_claim_names: Vec<_> = allowed_world_claims
            .entries()
            .iter()
            .map(GraphFsEntry::name)
            .collect();
        assert!(allowed_claim_names.contains(&allowed_claim.to_hex().as_str()));
        assert!(!allowed_claim_names.contains(&excluded_claim.to_hex().as_str()));

        let excluded_world_claims = resolver(&reader, 1024)
            .readdir(&format!("/worlds/{}/claims", excluded_world.to_hex()), None)?;
        assert!(
            excluded_world_claims.entries().is_empty(),
            "excluded world namespace must be empty, not forbidden"
        );
        Ok(())
    }

    #[test]
    fn large_day_shard_returns_first_page_and_more_under_byte_cap() -> Result<()> {
        let (_tmp, vault) = open_test_vault_with(VaultConfig::default());
        let subject = test_id(0x44);
        put_entity(&vault, subject, ENTITY_TYPE_PERSON)?;
        let learned_at = 1_771_027_200;
        let mut ops = Vec::with_capacity(100_000);
        for index in 0..100_000_u32 {
            let mut bytes = [0x60; 16];
            bytes[12..16].copy_from_slice(&index.to_be_bytes());
            let id = EntityId::from_bytes(bytes).expect("valid claim id");
            let mut body = ClaimBody::new(
                "profile.note",
                ClaimSubject::Entity(subject),
                Value::from(format!("claim-{index}")),
                1.0,
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Active,
            );
            body.valid_from = Some(learned_at);
            let data = crate::claim::encode_claim_body(&body)?;
            ops.push(BatchOp::Put {
                id,
                entity_type: ENTITY_TYPE_CLAIM,
                occurred: time_range(learned_at),
                learned_at,
                data,
                allow_maintenance: false,
                allow_reserved_predicate: false,
            });
        }
        let mut wtxn = vault.store.env.write_txn()?;
        apply_ops(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            &mut wtxn,
            ops,
            true,
            false,
            true,
        )?;
        wtxn.commit()?;

        let reader =
            vault.scoped_read(crate::claim::ScopedReadActorKey::new("reader").expect("actor key"));
        let day = format_day_shard(learned_at / 86_400);
        let page = resolver(&reader, 512).readdir(&format!("/claims/by-time/{day}/"), None)?;

        assert!(page.byte_count() <= 512);
        assert!(
            page.entries()
                .iter()
                .any(|entry| entry.name() == GRAPH_FS_MORE_ENTRY)
        );
        assert!(page.next_cursor().is_some());
        assert!(
            page.entries()
                .iter()
                .filter(|entry| entry.kind() == GraphFsEntryKind::File)
                .count()
                > 0
        );
        Ok(())
    }

    #[test]
    fn same_fork_hash_mount_renders_byte_identical_readdir() -> Result<()> {
        let (_tmp, vault) = open_test_vault_with(VaultConfig::default());
        let subject = test_id(0x55);
        let claim = test_id(0x56);
        put_entity(&vault, subject, ENTITY_TYPE_PERSON)?;
        put_claim(&vault, claim, subject, None, 20)?;

        let reader =
            vault.scoped_read(crate::claim::ScopedReadActorKey::new("reader").expect("actor key"));
        let options = GraphFsOptions::default()
            .with_mount(GraphFsMount::ForkHash([0xA5; 32]))
            .with_page_byte_cap(1024);
        let fs = reader.graph_fs(options);
        let first = fs.readdir_bytes("/claims/by-id", None)?;
        let second = fs.readdir_bytes("/claims/by-id", None)?;

        assert_eq!(first, second);
        assert!(
            first
                .windows(claim.to_hex().len())
                .any(|window| window == claim.to_hex().as_bytes())
        );
        Ok(())
    }

    #[test]
    fn graph_fs_host_imports_are_read_only() {
        assert!(
            GRAPH_FS_HOST_IMPORTS
                .iter()
                .all(|import| import.class() == SandboxImportClass::ReadOnly)
        );
        assert!(
            GRAPH_FS_HOST_IMPORTS
                .iter()
                .all(|import| !matches!(import.class(), SandboxImportClass::WriteTrap))
        );
    }

    #[test]
    fn wikilink_deeplink_resolves_to_claim_symlink() -> Result<()> {
        let (_tmp, vault) = open_test_vault_with(VaultConfig::default());
        let subject = test_id(0x70);
        let claim = test_id(0x71);
        put_entity(&vault, subject, ENTITY_TYPE_PERSON)?;
        put_claim(&vault, claim, subject, None, 30)?;
        let reader =
            vault.scoped_read(crate::claim::ScopedReadActorKey::new("reader").expect("actor key"));
        let link = resolver(&reader, 1024)
            .read_link(&format!("/[[claim:{}]]", claim.to_hex()))?
            .expect("claim link resolves");

        assert_eq!(link, format!("/claims/{}", claim.to_hex()));
        Ok(())
    }

    #[test]
    fn day_shard_date_round_trips() {
        let day = 1_771_027_200 / 86_400;
        let formatted = format_day_shard(day);
        assert_eq!(parse_day_shard(&formatted).expect("valid day"), day);
        assert_eq!(format_day_shard(0), "1970-01-01");
    }
}
