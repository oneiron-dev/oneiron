//! Path-routing readdir, readdir_bytes, read_file and read_link, fixed pages, world, entity and claim listdir helpers.

use crate::ports::EntityStoreRead;
use std::ops::Bound;

use crate::batch::EntityMetadataHeader;
use crate::claim::{PointRead, ReadRow, ScopedRead, ScopedReadReceipt, ScopedReadResult};
use crate::code_sandbox::SandboxLinkedImport;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::gate::PolicyManifestResolution;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_WORLD};

use super::model::{
    GRAPH_FS_HOST_IMPORTS, GRAPH_FS_MAX_PAGE_ENTRIES, GRAPH_FS_MAX_SCAN_ROWS,
    GRAPH_FS_PROJECTION_VERSION, GraphFsEntry, GraphFsFile, GraphFsMount, GraphFsOptions,
    GraphFsPage, GraphFsResolver,
};

use super::coreutils::{claim_matches_world_in, read_grant_matches_actor};

use super::paging::{
    DayPosition, EdgeCursor, PageBuilder, TemporalCursor, WorldPosition, format_day_shard,
    parse_day_shard,
};

/// File lookup and the receipt of the scoped read, if a stored row was read.
/// Fixed files and unmatched paths have no scoped-read receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphFsFileRead {
    pub value: Option<GraphFsFile>,
    pub receipt: Option<ScopedReadReceipt>,
}

impl From<ScopedReadResult<Option<GraphFsFile>>> for GraphFsFileRead {
    fn from(read: ScopedReadResult<Option<GraphFsFile>>) -> Self {
        Self {
            value: read.value,
            receipt: Some(read.receipt),
        }
    }
}

impl<'read, 'vault> GraphFsResolver<'read, 'vault> {
    #[must_use]
    pub fn new(scoped_read: &'read ScopedRead<'vault>, options: GraphFsOptions) -> Self {
        Self {
            scoped_read,
            options,
            snapshot: None,
        }
    }

    #[must_use]
    pub fn host_imports(&self) -> &'static [SandboxLinkedImport] {
        GRAPH_FS_HOST_IMPORTS
    }

    pub fn readdir(&self, path: &str, cursor: Option<&str>) -> Result<GraphFsPage> {
        let normalized = normalize_path(path)?;
        let components = path_components(&normalized)?;
        if self.snapshot.is_some() {
            return self.snapshot_readdir(&normalized, cursor);
        }
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
                let readable = self.scoped_read.is_entity_readable(&id)?;
                let body = self.file_row(id)?;
                let page = if readable {
                    self.fixed_page(
                        &normalized,
                        vec![
                            GraphFsEntry::directory("claims"),
                            GraphFsEntry::directory("backlinks"),
                            GraphFsEntry::file(
                                "body",
                                body.value.and_then(|row| row.body).map(|b| b.len()),
                            ),
                        ],
                        cursor,
                    )
                } else {
                    empty_page(&normalized, self.options.mount)
                };
                Ok(page.with_read_receipt(body.receipt))
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

    /// A file and any scoped-read receipt behind it. Fixed files and paths
    /// that name no file make no scoped read and carry no receipt.
    pub fn read_file(&self, path: &str) -> Result<GraphFsFileRead> {
        let normalized = normalize_path(path)?;
        let components = path_components(&normalized)?;
        if self.snapshot.is_some() {
            return self.snapshot_file(&normalized);
        }
        match components.as_slice() {
            ["claims", claim] | ["claims", "by-id", claim] => Ok(self
                .read_claim_file(&normalized, &parse_entity_id(claim)?)?
                .into()),
            ["entities", entity, "body"] => {
                let id = parse_entity_id(entity)?;
                let mount = self.options.mount;
                Ok(self.file_row(id)?
                    .map(|row| {
                        row.and_then(|row| row.body).map(|bytes| GraphFsFile {
                            path: normalized,
                            mount,
                            bytes,
                        })
                    })
                    .into())
            }
            ["worlds", world, "scope"] => {
                let bytes = if *world == "base" {
                    b"base\n".to_vec()
                } else {
                    let id = parse_entity_id(world)?;
                    format!("world_ref:{}\n", id.to_hex()).into_bytes()
                };
                Ok(GraphFsFileRead {
                    value: Some(GraphFsFile {
                        path: normalized,
                        mount: self.options.mount,
                        bytes,
                    }),
                    receipt: None,
                })
            }
            _ => Ok(GraphFsFileRead {
                value: None,
                receipt: None,
            }),
        }
    }

    pub fn read_link(&self, path: &str) -> Result<Option<String>> {
        let normalized = normalize_path(path)?;
        let components = path_components(&normalized)?;
        if self.snapshot.is_some() {
            return Ok(None);
        }
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
        if self
            .scoped_read
            .read(&[PointRead::id(claim_id)], None)?
            .single()
            .value
            .is_some()
        {
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
            .port_entity_record(rtxn, id)?
            .map(|row| row.encode())
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
    ) -> Result<ScopedReadResult<Option<GraphFsFile>>> {
        let ScopedReadResult { value, receipt } = self.file_row(*claim_id)?;
        let Some(ReadRow {
            entity_type: ENTITY_TYPE_CLAIM,
            learned_at,
            body: Some(body),
            ..
        }) = value
        else {
            return Ok(ScopedReadResult {
                value: None,
                receipt,
            });
        };
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
        Ok(ScopedReadResult {
            value: Some(GraphFsFile {
                path: path.to_owned(),
                mount: self.options.mount,
                bytes,
            }),
            receipt,
        })
    }

    /// One live point read, folded into a listing's receipt.
    pub(super) fn read_live_into(
        &self,
        id: EntityId,
        receipt: &mut ScopedReadReceipt,
    ) -> Result<Option<ReadRow>> {
        let row = self.file_row(id)?;
        receipt.restrict_with(&row.receipt);
        Ok(row.value)
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

    /// The vault's worlds this reader may walk into, base first, then each
    /// WORLD row by id ([`Self::world_visible`]), all judged in one snapshot.
    /// A manifest grant never lists a world of its own: it only says where a
    /// reader other than the owner may read. A page can end inside a run of
    /// worlds this reader may not see, so its cursor is sealed and names none
    /// of them. A reader that could read no row in that snapshot (a dead
    /// credential, one that reads nothing, or a peer of either) lists
    /// nothing, not even a cursor that would say how many worlds it passed
    /// over.
    fn listdir_worlds(&self, path: &str, cursor: Option<&str>) -> Result<GraphFsPage> {
        self.scoped_read.persist_grant_clock()?;
        let rtxn = self.scoped_read.vault().store.env.read_txn()?;
        let policy = self.scoped_read.live_policy_manifest_in(&rtxn)?;
        if !self.scoped_read.every_lane_in(&rtxn, |lane| {
            Ok(lane.proof_live_in(&rtxn)? && lane_reads_some_row(lane, &policy))
        })? {
            return Ok(empty_page(path, self.options.mount));
        }
        let scope = self.cursor_scope(path);
        let after: Option<WorldPosition> = scope.open(cursor)?;
        let mut builder = PageBuilder::new(path, self.options);
        if after.is_none()
            && self.world_visible(&rtxn, &policy, None)?
            && !builder.try_push(GraphFsEntry::directory("base"))
        {
            return Ok(builder.finish(None));
        }

        let after = after.and_then(|position| position.0);
        let rows = self
            .scoped_read
            .vault()
            .store
            .port_entity_ids_by_type(&rtxn, ENTITY_TYPE_WORLD, after)?
            .take(GRAPH_FS_MAX_PAGE_ENTRIES.saturating_add(1))
            .collect::<Result<Vec<_>>>()?;
        let has_more_rows = rows.len() > GRAPH_FS_MAX_PAGE_ENTRIES;
        let mut next_cursor = None;
        let (mut last_listed, mut last_scanned) = (after, after);
        for id in rows.into_iter().take(GRAPH_FS_MAX_PAGE_ENTRIES) {
            if self.world_visible(&rtxn, &policy, Some(id))? {
                if !builder.try_push(GraphFsEntry::directory(id.to_hex())) {
                    next_cursor = builder
                        .last_entry_name()
                        .map(|_| scope.seal(&WorldPosition(last_listed)));
                    break;
                }
                last_listed = Some(id);
            }
            last_scanned = Some(id);
        }
        if next_cursor.is_none() && has_more_rows {
            next_cursor = Some(scope.seal(&WorldPosition(last_scanned)));
        }
        Ok(builder.finish(next_cursor))
    }

    /// Whether this reader may walk into `world` (`None` is base reality) in
    /// `rtxn`: its own lane and each peer lane its reads conjoin
    /// ([`crate::claim::ScopedRead::with_peer_reads`]) must each walk there
    /// ([`lane_walks_world`]), as each must admit a row it serves (Sol R5-006).
    /// Off this device no reader walks into a world a device-local flag keeps
    /// (DEC-0005).
    pub(super) fn world_visible(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        world: Option<EntityId>,
    ) -> Result<bool> {
        if let Some(world) = world
            && self.scoped_read.off_device()
            && crate::settings::device_local_keeps_in(self.scoped_read.vault(), rtxn, &world)?
        {
            return Ok(false);
        }
        self.scoped_read
            .every_lane_in(rtxn, |lane| lane_walks_world(lane, rtxn, policy, world))
    }

    fn listdir_entities(&self, path: &str, cursor: Option<&str>) -> Result<GraphFsPage> {
        let scope = self.cursor_scope(path);
        let cursor = scope.open::<TemporalCursor>(cursor)?;
        let mut builder = PageBuilder::new(path, self.options);
        let mut next_cursor = None;
        let mut last_scanned = None;
        self.scoped_read.persist_grant_clock()?;
        let rtxn = self.scoped_read.vault().store.env.read_txn()?;
        let policy = self.scoped_read.live_policy_manifest_in(&rtxn)?;
        let query = crate::ports::TimelineQuery {
            after: cursor.map(TemporalCursor::port_position),
            ..Default::default()
        };
        for (scanned, entry) in self.admitted_timeline(&rtxn, query)?.enumerate() {
            if scanned >= GRAPH_FS_MAX_SCAN_ROWS {
                // Sealed: the last scanned row may be one the walk passed over.
                next_cursor = last_scanned.map(|cursor| scope.seal(&cursor));
                break;
            }
            let time = entry?;
            let cursor = TemporalCursor {
                learned_at: time.timestamp,
                id: time.id,
            };
            last_scanned = Some(cursor);
            if !sealed_is_absent(
                self.scoped_read
                    .is_entity_readable_with_policy_in(&rtxn, &policy, &cursor.id),
            )? {
                continue;
            }
            let entry = GraphFsEntry::directory(cursor.id.to_hex());
            if !builder.try_push(entry) {
                next_cursor = builder
                    .last_temporal_cursor()
                    .map(|cursor| scope.seal(&cursor));
                break;
            }
            builder.set_last_temporal_cursor(cursor);
        }
        Ok(builder.finish(next_cursor))
    }

    fn listdir_claims_in_world(
        &self,
        path: &str,
        world: &str,
        cursor: Option<&str>,
    ) -> Result<GraphFsPage> {
        let scope = self.cursor_scope(path);
        let world = parse_world_scope(world)?;
        let cursor = scope.open::<TemporalCursor>(cursor)?;
        let mut builder = PageBuilder::new(path, self.options);
        let mut next_cursor = None;
        let mut last_scanned = None;
        self.scoped_read.persist_grant_clock()?;
        let rtxn = self.scoped_read.vault().store.env.read_txn()?;
        let policy = self.scoped_read.live_policy_manifest_in(&rtxn)?;
        let query = crate::ports::TimelineQuery {
            after: cursor.map(TemporalCursor::port_position),
            ..Default::default()
        };
        for (scanned, entry) in self.admitted_timeline(&rtxn, query)?.enumerate() {
            if scanned >= GRAPH_FS_MAX_SCAN_ROWS {
                // Sealed: the last scanned row may be one the walk passed over.
                next_cursor = last_scanned.map(|cursor| scope.seal(&cursor));
                break;
            }
            let time = entry?;
            let temporal = TemporalCursor {
                learned_at: time.timestamp,
                id: time.id,
            };
            last_scanned = Some(temporal);
            if !sealed_is_absent(self.scoped_read.is_entity_readable_with_policy_in(
                &rtxn,
                &policy,
                &temporal.id,
            ))? {
                continue;
            }
            if !claim_matches_world_in(&self.scoped_read.vault().store, &rtxn, &temporal.id, world)?
            {
                continue;
            }
            let entry = GraphFsEntry::file(temporal.id.to_hex(), None);
            if !builder.try_push(entry) {
                next_cursor = builder
                    .last_temporal_cursor()
                    .map(|cursor| scope.seal(&cursor));
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
        let scope = self.cursor_scope(path);
        let after = scope.open::<EdgeCursor>(cursor)?;
        let mut builder = PageBuilder::new(path, self.options);
        let mut next_cursor = None;
        let mut last_emitted = after;
        let mut last_scanned = None;
        self.scoped_read.persist_grant_clock()?;
        let rtxn = self.scoped_read.vault().store.env.read_txn()?;
        let policy = self.scoped_read.live_policy_manifest_in(&rtxn)?;
        let edges = self.admitted_edges(
            &rtxn,
            target,
            crate::ports::EdgeDirection::In,
            after.map(EdgeCursor::port_position),
        )?;
        for (scanned, entry) in edges.enumerate() {
            if scanned >= GRAPH_FS_MAX_SCAN_ROWS {
                // Sealed: the last scanned edge may be one the walk passed over.
                next_cursor = last_scanned
                    .or(last_emitted)
                    .map(|cursor| scope.seal(&cursor));
                break;
            }
            let edge = entry?;
            let cursor = EdgeCursor::from_port(&edge);
            last_scanned = Some(cursor);
            if !sealed_is_absent(self.scoped_read.is_entity_readable_with_policy_in(
                &rtxn,
                &policy,
                &edge.target,
            ))? {
                continue;
            }
            let name = format!("{}-{}", edge.kind as u8, edge.target.to_hex());
            let entry = GraphFsEntry::symlink(name, format!("/entities/{}", edge.target.to_hex()));
            if !builder.try_push(entry) {
                next_cursor = last_emitted.map(|cursor| scope.seal(&cursor));
                break;
            }
            last_emitted = Some(cursor);
        }
        Ok(builder.finish(next_cursor))
    }

    fn listdir_claim_days(&self, path: &str, cursor: Option<&str>) -> Result<GraphFsPage> {
        self.listdir_claim_days_with_scan_cap(path, cursor, GRAPH_FS_MAX_SCAN_ROWS)
    }

    /// The days that hold a row this reader may read, oldest first.
    pub(super) fn listdir_claim_days_with_scan_cap(
        &self,
        path: &str,
        cursor: Option<&str>,
        max_scan_rows: usize,
    ) -> Result<GraphFsPage> {
        let scope = self.cursor_scope(path);
        let from: DayPosition = scope.open(cursor)?.unwrap_or_default();
        let day_of = |row: TemporalCursor| row.learned_at / 86_400;
        let mut listed = from.after.filter(|_| from.day_listed).map(day_of);
        let mut last_scanned = from.after;
        let mut builder = PageBuilder::new(path, self.options);
        let mut next_cursor = None;
        self.scoped_read.persist_grant_clock()?;
        let rtxn = self.scoped_read.vault().store.env.read_txn()?;
        let policy = self.scoped_read.live_policy_manifest_in(&rtxn)?;
        let query = crate::ports::TimelineQuery {
            after: from.after.map(TemporalCursor::port_position),
            ..Default::default()
        };
        // Resumes after `after`, with its day listed or not.
        let resume = |after: Option<TemporalCursor>, listed: Option<u64>| DayPosition {
            after,
            day_listed: after.is_some_and(|after| Some(day_of(after)) == listed),
        };
        for (scanned, entry) in self.admitted_timeline(&rtxn, query)?.enumerate() {
            if scanned >= max_scan_rows {
                // Sealed: the last scanned row may be one the walk passed over.
                next_cursor = Some(scope.seal(&resume(last_scanned, listed)));
                break;
            }
            let time = entry?;
            let temporal = TemporalCursor {
                learned_at: time.timestamp,
                id: time.id,
            };
            let scanned_before = last_scanned.replace(temporal);
            if !sealed_is_absent(self.scoped_read.is_entity_readable_with_policy_in(
                &rtxn,
                &policy,
                &temporal.id,
            ))? {
                continue;
            }
            let day = day_of(temporal);
            if listed.is_some_and(|listed| day <= listed) {
                continue;
            }
            if !builder.try_push(GraphFsEntry::directory(format_day_shard(day))) {
                // Resumes before this row, the first of a day not listed yet.
                next_cursor = Some(scope.seal(&resume(scanned_before, listed)));
                break;
            }
            listed = Some(day);
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
        let scope = self.cursor_scope(path);
        let cursor = scope.open::<TemporalCursor>(cursor)?;
        let mut builder = PageBuilder::new(path, self.options);
        let mut next_cursor = None;
        let mut last_scanned = None;
        self.scoped_read.persist_grant_clock()?;
        let rtxn = self.scoped_read.vault().store.env.read_txn()?;
        let policy = self.scoped_read.live_policy_manifest_in(&rtxn)?;
        let query = crate::ports::TimelineQuery {
            start: Bound::Included(start),
            end: Bound::Excluded(end),
            after: cursor.map(TemporalCursor::port_position),
            ..Default::default()
        };
        for (scanned, entry) in self.admitted_timeline(&rtxn, query)?.enumerate() {
            if scanned >= GRAPH_FS_MAX_SCAN_ROWS {
                // Sealed: the last scanned row may be one the walk passed over.
                next_cursor = last_scanned.map(|cursor| scope.seal(&cursor));
                break;
            }
            let time = entry?;
            let temporal = TemporalCursor {
                learned_at: time.timestamp,
                id: time.id,
            };
            last_scanned = Some(temporal);
            if !sealed_is_absent(self.scoped_read.is_entity_readable_with_policy_in(
                &rtxn,
                &policy,
                &temporal.id,
            ))? {
                continue;
            }
            let entry = GraphFsEntry::file(temporal.id.to_hex(), None);
            if !builder.try_push(entry) {
                next_cursor = builder
                    .last_temporal_cursor()
                    .map(|cursor| scope.seal(&cursor));
                break;
            }
            builder.set_last_temporal_cursor(temporal);
        }
        Ok(builder.finish(next_cursor))
    }
}

/// Whether `lane` may walk into `world` (`None` is base reality) in `rtxn`,
/// judged as claim admission judges a claim's world: the lane must read
/// some row ([`lane_reads_some_row`]), its credential must be live, and the
/// worlds the read asked for and its Scope must admit `world`; the owner then
/// reads every world of their vault (ARCH-0057). Any other reader reads where
/// a read grant for it reads the world
/// ([`crate::gate::scoped_read_grant_reads_world`]), anywhere while the
/// manifest holds no read grant, and, with a credential no grant names,
/// wherever that credential reads.
fn lane_walks_world(
    lane: &ScopedRead<'_>,
    rtxn: &heed::RoTxn<'_>,
    policy: &PolicyManifestResolution,
    world: Option<EntityId>,
) -> Result<bool> {
    let key = lane.actor_key();
    if !lane_reads_some_row(lane, policy) || !lane.world_readable_in(rtxn, world)? {
        return Ok(false);
    }
    if key.vault_owner_ref().is_some() {
        return Ok(true);
    }
    if !policy.has_scoped_read_grants() {
        return Ok(true);
    }
    let mut matched = false;
    for grant in policy.scoped_grants() {
        if !read_grant_matches_actor(grant, key) {
            continue;
        }
        matched = true;
        if crate::gate::scoped_read_grant_reads_world(grant, world, key.authority_scope()) {
            return Ok(true);
        }
    }
    Ok(key.authority_scope().is_some() && !matched)
}

/// Whether `lane`'s ordinary reads could admit any row under `policy`: the
/// retrieval floor every read applies leaves some row
/// ([`crate::gate::RetrievalPolicyFloor::reads_some_row`]). A credential
/// without the read verb, or with its bands, audience, sensitivity or worlds
/// at bottom, a fail-closed manifest, grants that read nothing, and a
/// credential whose bands share no type with its grants' each leave it none,
/// so it walks no world either (Sol R7-003, R11-001).
fn lane_reads_some_row(lane: &ScopedRead<'_>, policy: &PolicyManifestResolution) -> bool {
    policy
        .retrieval_floor_for_actor(Some(lane.actor_key()))
        .reads_some_row()
}

pub(super) fn empty_page(path: &str, mount: GraphFsMount) -> GraphFsPage {
    GraphFsPage {
        path: path.to_owned(),
        mount,
        entries: Vec::new(),
        next_cursor: None,
        byte_count: 0,
        read_receipt: None,
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
        path_components(normalized)?;
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

/// A walk passes over sealed secret custody as absent rather than failing:
/// it is never part of the tree, and a raw read of it still refuses.
pub(super) fn sealed_is_absent(readable: Result<bool>) -> Result<bool> {
    match readable {
        Err(error) if error.kind() == crate::error::ErrorKind::InvalidSecretCustodyBody => {
            Ok(false)
        }
        readable => readable,
    }
}
