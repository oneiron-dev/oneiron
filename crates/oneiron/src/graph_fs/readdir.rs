//! Path-routing readdir, readdir_bytes, read_file and read_link, fixed pages, world, entity and claim listdir helpers, and the resolver policy helper.

use std::collections::BTreeSet;
use std::ops::Bound;

use crate::batch::EntityMetadataHeader;
use crate::claim::ScopedRead;
use crate::code_sandbox::SandboxLinkedImport;
use crate::edge::EdgeKind;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::gate::{PolicyManifestResolution, resolve_policy_manifest};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_WORLD};

use super::model::{
    GRAPH_FS_HOST_IMPORTS, GRAPH_FS_MAX_PAGE_ENTRIES, GRAPH_FS_MAX_SCAN_ROWS,
    GRAPH_FS_PROJECTION_VERSION, GraphFsEntry, GraphFsFile, GraphFsMount, GraphFsOptions,
    GraphFsPage, GraphFsResolver,
};

use super::coreutils::{claim_matches_world_in, grant_scope_world_name, read_grant_matches_actor};

use super::paging::{
    EdgeCursor, PageBuilder, TemporalCursor, edge_cursor_from_key, edge_cursor_key,
    format_day_shard, parse_day_shard, parse_edge_cursor, temporal_cursor_from_key,
};

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

    pub(super) fn entity_type_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<u8>> {
        let Some(raw) = self
            .scoped_read
            .vault()
            .store
            .entities
            .get(rtxn, id.as_bytes())?
        else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        Ok(Some(header.entity_type))
    }

    pub(super) fn read_claim_file(
        &self,
        path: &str,
        claim_id: &EntityId,
    ) -> Result<Option<GraphFsFile>> {
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

    pub(super) fn world_names_from_matching_grants(
        &self,
        policy: &PolicyManifestResolution,
    ) -> Vec<String> {
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
            let cursor = temporal_cursor_from_key(&key)?;
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
            let temporal = temporal_cursor_from_key(&key)?;
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
                next_cursor = last_cursor.map(EdgeCursor::encode);
                break;
            }
            let (key, value) = entry?;
            if !key.starts_with(prefix) {
                break;
            }
            let cursor = edge_cursor_from_key(&key)?;
            let edge = crate::vault::parse_edge_record(&key, &value)?;
            if !self
                .scoped_read
                .is_entity_readable_with_policy_in(&rtxn, &policy, &edge.target)?
            {
                continue;
            }
            let name = format!("{}-{}", edge.kind as u8, edge.target.to_hex());
            let entry = GraphFsEntry::symlink(name, format!("/entities/{}", edge.target.to_hex()));
            if !builder.try_push(entry) {
                next_cursor = last_cursor.map(EdgeCursor::encode);
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
            let temporal = temporal_cursor_from_key(&key)?;
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
            let temporal = temporal_cursor_from_key(&key)?;
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

    pub(super) fn policy(&self) -> Result<PolicyManifestResolution> {
        let rtxn = self.scoped_read.vault().store.env.read_txn()?;
        resolve_policy_manifest(&self.scoped_read.vault().store, &rtxn)
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

pub(super) fn normalize_path(path: &str) -> Result<String> {
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

pub(super) fn path_components(path: &str) -> Result<Vec<&str>> {
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

pub(super) fn parse_entity_id(value: &str) -> Result<EntityId> {
    EntityId::from_hex(value)
}

fn parse_world_scope(value: &str) -> Result<Option<EntityId>> {
    if value == "base" {
        Ok(None)
    } else {
        parse_entity_id(value).map(Some)
    }
}
