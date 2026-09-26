//! grep, ls, find, cat, head and wc verbs with pushdown, walk, visibility and telemetry helpers, and the claim-grep render path.

use crate::ports::EntityStoreRead;
use std::collections::VecDeque;
use std::ops::Bound;
use std::time::Instant;

use rmpv::Value;

use crate::claim::{ScopedReadReceipt, decode_claim_body};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::gate::{PolicyManifestResolution, SCOPED_READ_EFFECTOR_CORE_READ};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_WORLD};
use crate::store::{RetrievalAction, RetrievalRunId, RetrievalRunRecord, RetrievalSignal, Store};

use super::model::{
    GRAPH_FS_COREUTILS_MAX_RESULT_CAP, GRAPH_FS_MAX_SCAN_ROWS, GraphFsCommandOutput,
    GraphFsCoreutilsDecision, GraphFsCoreutilsVerb, GraphFsEntryKind, GraphFsResolver,
};

use super::readdir::{normalize_path, parse_entity_id, path_components};

use super::paging::{CommandOutputBuilder, TemporalCursor};

impl GraphFsResolver<'_, '_> {
    pub fn grep(
        &self,
        pattern: &str,
        path: &str,
        recursive: bool,
        cursor: Option<&str>,
    ) -> Result<GraphFsCommandOutput> {
        let started = Instant::now();
        let started_at = self.scoped_read.vault().now_recorded_at();
        let normalized = normalize_path(path)?;
        if let Some(literal) = literal_grep_pattern(pattern)
            && recursive
            && matches!(normalized.as_str(), "/claims" | "/claims/by-id")
        {
            let page = self.grep_claims_pushdown(literal, cursor)?;
            return self.finish_coreutils_command(
                GraphFsCoreutilsVerb::Grep,
                started,
                started_at,
                GraphFsCoreutilsDecision::Pushdown,
                "claims text index",
                page.bytes,
                page.next_cursor,
                vec![RetrievalSignal::Text],
                page.total,
                Some(page.receipt),
            );
        }

        let walk = self.grep_walk(pattern, &normalized, recursive, cursor)?;
        self.finish_coreutils_command(
            GraphFsCoreutilsVerb::Grep,
            started,
            started_at,
            GraphFsCoreutilsDecision::Walk,
            "graph-fs bounded walk",
            walk.bytes,
            walk.next_cursor,
            Vec::new(),
            walk.total,
            walk.receipt,
        )
    }

    pub fn ls(
        &self,
        path: &str,
        sort_by_time: bool,
        cursor: Option<&str>,
    ) -> Result<GraphFsCommandOutput> {
        let started = Instant::now();
        let started_at = self.scoped_read.vault().now_recorded_at();
        let normalized = normalize_path(path)?;
        if sort_by_time && matches!(normalized.as_str(), "/claims" | "/claims/by-id") {
            let (bytes, next_cursor, total) = self.ls_claims_by_time_pushdown(cursor)?;
            return self.finish_coreutils_command(
                GraphFsCoreutilsVerb::Ls,
                started,
                started_at,
                GraphFsCoreutilsDecision::Pushdown,
                "claims temporal index",
                bytes,
                next_cursor,
                vec![RetrievalSignal::Temporal],
                total,
                None,
            );
        }

        let page = self.readdir(&normalized, cursor)?;
        let mut out = CommandOutputBuilder::new(self.options);
        let mut last_name = None;
        for entry in page.entries() {
            if entry.kind() == GraphFsEntryKind::Cursor {
                continue;
            }
            let mut line = entry.name().to_owned();
            line.push('\n');
            if !out.try_push(line.as_bytes()) {
                break;
            }
            last_name = Some(entry.name().to_owned());
        }
        let next_cursor = page
            .next_cursor()
            .map(str::to_owned)
            .or_else(|| if out.is_full() { last_name } else { None });
        let total = out.entries();
        self.finish_coreutils_command(
            GraphFsCoreutilsVerb::Ls,
            started,
            started_at,
            GraphFsCoreutilsDecision::Walk,
            "graph-fs readdir",
            out.into_bytes(),
            next_cursor,
            Vec::new(),
            total,
            page.read_receipt,
        )
    }

    pub fn find(
        &self,
        path: &str,
        newer_than: Option<u64>,
        cursor: Option<&str>,
    ) -> Result<GraphFsCommandOutput> {
        let started = Instant::now();
        let started_at = self.scoped_read.vault().now_recorded_at();
        let normalized = normalize_path(path)?;
        if let Some(newer_than) = newer_than {
            let (bytes, next_cursor, total) =
                self.find_newer_pushdown(&normalized, newer_than, cursor)?;
            return self.finish_coreutils_command(
                GraphFsCoreutilsVerb::Find,
                started,
                started_at,
                GraphFsCoreutilsDecision::Pushdown,
                "temporal learned index",
                bytes,
                next_cursor,
                vec![RetrievalSignal::Temporal],
                total,
                None,
            );
        }

        let walk = self.find_walk(&normalized, cursor)?;
        self.finish_coreutils_command(
            GraphFsCoreutilsVerb::Find,
            started,
            started_at,
            GraphFsCoreutilsDecision::Walk,
            "graph-fs bounded walk",
            walk.bytes,
            walk.next_cursor,
            Vec::new(),
            walk.total,
            walk.receipt,
        )
    }

    pub fn cat(&self, path: &str, cursor: Option<&str>) -> Result<GraphFsCommandOutput> {
        let started = Instant::now();
        let started_at = self.scoped_read.vault().now_recorded_at();
        let offset = parse_byte_cursor(cursor)?;
        let mut next_cursor = None;
        let read = self.read_file(path)?;
        let bytes = if let Some(file) = &read.value {
            let bytes = file.bytes();
            let start = offset.min(bytes.len());
            let end = start
                .saturating_add(self.options.page_byte_cap)
                .min(bytes.len());
            if end < bytes.len() {
                next_cursor = Some(end.to_string());
            }
            bytes[start..end].to_vec()
        } else {
            Vec::new()
        };
        self.finish_coreutils_command(
            GraphFsCoreutilsVerb::Cat,
            started,
            started_at,
            GraphFsCoreutilsDecision::Walk,
            "graph-fs read_file",
            bytes,
            next_cursor,
            Vec::new(),
            0,
            Some(read.receipt),
        )
    }

    pub fn head(&self, path: &str, lines: usize) -> Result<GraphFsCommandOutput> {
        let started = Instant::now();
        let started_at = self.scoped_read.vault().now_recorded_at();
        let mut out = CommandOutputBuilder::new(self.options);
        let read = self.read_file(path)?;
        if let Some(file) = &read.value {
            for line in String::from_utf8_lossy(file.bytes()).lines().take(lines) {
                let mut rendered = line.to_owned();
                rendered.push('\n');
                if !out.try_push(rendered.as_bytes()) {
                    break;
                }
            }
        }
        let total = out.entries();
        self.finish_coreutils_command(
            GraphFsCoreutilsVerb::Head,
            started,
            started_at,
            GraphFsCoreutilsDecision::Walk,
            "graph-fs read_file",
            out.into_bytes(),
            None,
            Vec::new(),
            total,
            Some(read.receipt),
        )
    }

    pub fn wc(&self, path: &str) -> Result<GraphFsCommandOutput> {
        let started = Instant::now();
        let started_at = self.scoped_read.vault().now_recorded_at();
        let read = self.read_file(path)?;
        let bytes = if let Some(file) = &read.value {
            let text = String::from_utf8_lossy(file.bytes());
            let lines = text.lines().count();
            let words = text.split_whitespace().count();
            format!("{lines} {words} {} {path}\n", file.bytes().len()).into_bytes()
        } else {
            format!("0 0 0 {path}\n").into_bytes()
        };
        self.finish_coreutils_command(
            GraphFsCoreutilsVerb::Wc,
            started,
            started_at,
            GraphFsCoreutilsDecision::Walk,
            "graph-fs read_file",
            bytes,
            None,
            Vec::new(),
            0,
            Some(read.receipt),
        )
    }

    fn grep_walk(
        &self,
        pattern: &str,
        path: &str,
        recursive: bool,
        cursor: Option<&str>,
    ) -> Result<WalkOutput> {
        let mut out = CommandOutputBuilder::new(self.options);
        let mut last_emitted = cursor.map(str::to_owned);
        let mut total = 0;
        if !recursive {
            let read = self.read_file(path)?;
            if let Some(file) = &read.value {
                append_grep_file_matches(path, file.bytes(), pattern, &mut out, &mut total);
            }
            return Ok(WalkOutput::new(out, None, total, Some(read.receipt)));
        }

        let (paths, mut receipt) = self.walk_paths(path, cursor)?;
        for path in paths {
            let read = self.read_file(&path)?;
            fold_receipt(&mut receipt, read.receipt);
            let Some(file) = read.value else {
                continue;
            };
            let before_entries = out.entries();
            append_grep_file_matches(&path, file.bytes(), pattern, &mut out, &mut total);
            if out.entries() > before_entries {
                last_emitted = Some(path);
            }
            if out.is_full() {
                return Ok(WalkOutput::new(out, last_emitted, total, receipt));
            }
        }
        Ok(WalkOutput::new(out, None, total, receipt))
    }

    fn ls_claims_by_time_pushdown(
        &self,
        cursor: Option<&str>,
    ) -> Result<(Vec<u8>, Option<String>, usize)> {
        self.ls_claims_by_time_pushdown_with_scan_cap(cursor, GRAPH_FS_MAX_SCAN_ROWS)
    }

    pub(super) fn ls_claims_by_time_pushdown_with_scan_cap(
        &self,
        cursor: Option<&str>,
        max_scan_rows: usize,
    ) -> Result<(Vec<u8>, Option<String>, usize)> {
        let mut out = CommandOutputBuilder::new(self.options);
        let cursor = TemporalCursor::parse_optional(cursor)?;
        let mut last_emitted = cursor.map(TemporalCursor::encode);
        let mut last_scanned: Option<TemporalCursor> = None;
        let mut total = 0;
        let rtxn = self.scoped_read.vault().store.env.read_txn()?;
        let policy = self.scoped_read.policy_manifest_in(&rtxn)?;
        let query = crate::ports::TimelineQuery {
            reverse: true,
            after: cursor.map(TemporalCursor::port_position),
            ..Default::default()
        };
        for (scanned, entry) in self
            .scoped_read
            .vault()
            .store
            .port_entity_timeline(&rtxn, query)?
            .enumerate()
        {
            if scanned >= max_scan_rows {
                let next_cursor = last_scanned.map(TemporalCursor::encode).or(last_emitted);
                return Ok((out.into_bytes(), next_cursor, total));
            }
            let time = entry?;
            let temporal = TemporalCursor {
                learned_at: time.timestamp,
                id: time.id,
            };
            last_scanned = Some(temporal);
            if !self
                .scoped_read
                .is_entity_readable_with_policy_in(&rtxn, &policy, &temporal.id)?
            {
                continue;
            }
            if self.entity_type_in(&rtxn, &temporal.id)? != Some(ENTITY_TYPE_CLAIM) {
                continue;
            }
            let line = format!("{}\n", temporal.id.to_hex());
            if !out.try_push(line.as_bytes()) {
                return Ok((out.into_bytes(), last_emitted, total));
            }
            total += 1;
            last_emitted = Some(temporal.encode());
        }
        Ok((out.into_bytes(), None, total))
    }

    fn find_newer_pushdown(
        &self,
        path: &str,
        newer_than: u64,
        cursor: Option<&str>,
    ) -> Result<(Vec<u8>, Option<String>, usize)> {
        self.find_newer_pushdown_with_scan_cap(path, newer_than, cursor, GRAPH_FS_MAX_SCAN_ROWS)
    }

    pub(super) fn find_newer_pushdown_with_scan_cap(
        &self,
        path: &str,
        newer_than: u64,
        cursor: Option<&str>,
        max_scan_rows: usize,
    ) -> Result<(Vec<u8>, Option<String>, usize)> {
        let mut out = CommandOutputBuilder::new(self.options);
        let cursor = TemporalCursor::parse_optional(cursor)?;
        let mut last_emitted = cursor.map(TemporalCursor::encode);
        let mut last_scanned: Option<TemporalCursor> = None;
        let mut total = 0;
        let rtxn = self.scoped_read.vault().store.env.read_txn()?;
        let policy = self.scoped_read.policy_manifest_in(&rtxn)?;
        let query = crate::ports::TimelineQuery {
            start: if cursor.is_some() {
                Bound::Unbounded
            } else {
                Bound::Included(newer_than.saturating_add(1))
            },
            after: cursor.map(TemporalCursor::port_position),
            ..Default::default()
        };
        for (scanned, entry) in self
            .scoped_read
            .vault()
            .store
            .port_entity_timeline(&rtxn, query)?
            .enumerate()
        {
            if scanned >= max_scan_rows {
                let next_cursor = last_scanned.map(TemporalCursor::encode).or(last_emitted);
                return Ok((out.into_bytes(), next_cursor, total));
            }
            let time = entry?;
            let temporal = TemporalCursor {
                learned_at: time.timestamp,
                id: time.id,
            };
            last_scanned = Some(temporal);
            if !self.coreutils_entity_visible_in(&rtxn, &policy, &temporal.id)? {
                continue;
            }
            let Some(line) = self.find_path_for_temporal_hit_in(&rtxn, path, &temporal.id)? else {
                continue;
            };
            if !out.try_push(line.as_bytes()) {
                return Ok((out.into_bytes(), last_emitted, total));
            }
            total += 1;
            last_emitted = Some(temporal.encode());
        }
        Ok((out.into_bytes(), None, total))
    }

    fn find_walk(&self, path: &str, cursor: Option<&str>) -> Result<WalkOutput> {
        let mut out = CommandOutputBuilder::new(self.options);
        let mut last_emitted = cursor.map(str::to_owned);
        let mut total = 0;
        let (paths, receipt) = self.walk_paths(path, cursor)?;
        for path in paths {
            let mut line = path.clone();
            line.push('\n');
            if !out.try_push(line.as_bytes()) {
                return Ok(WalkOutput::new(out, last_emitted, total, receipt));
            }
            total += 1;
            last_emitted = Some(path);
        }
        Ok(WalkOutput::new(out, None, total, receipt))
    }

    /// Visible paths under `path`, with the folded receipt of every listing
    /// the walk read.
    fn walk_paths(
        &self,
        path: &str,
        cursor: Option<&str>,
    ) -> Result<(Vec<String>, Option<ScopedReadReceipt>)> {
        let mut receipt = None;
        let mut paths = Vec::new();
        let mut queue = VecDeque::from([path.to_owned()]);
        let mut scanned = 0usize;
        let mut skipping = cursor.is_some();
        while let Some(current) = queue.pop_front() {
            if scanned >= GRAPH_FS_MAX_SCAN_ROWS {
                break;
            }
            scanned += 1;
            if !self.coreutils_path_visible(&current)? {
                continue;
            }
            if skipping {
                if cursor == Some(current.as_str()) {
                    skipping = false;
                }
            } else {
                paths.push(current.clone());
                if paths.len() >= self.coreutils_result_cap() {
                    break;
                }
            }

            let page = self.readdir(&current, None)?;
            if let Some(read) = page.read_receipt() {
                fold_receipt(&mut receipt, read.clone());
            }
            for entry in page.entries() {
                if entry.kind() == GraphFsEntryKind::Cursor {
                    continue;
                }
                let child = join_graph_path(&current, entry.name());
                if matches!(entry.kind(), GraphFsEntryKind::Directory) {
                    queue.push_back(child);
                } else if !skipping && self.coreutils_path_visible(&child)? {
                    paths.push(child);
                    if paths.len() >= self.coreutils_result_cap() {
                        return Ok((paths, receipt));
                    }
                }
            }
        }
        Ok((paths, receipt))
    }

    fn find_path_for_temporal_hit_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        path: &str,
        id: &EntityId,
    ) -> Result<Option<String>> {
        let entity_type = self.entity_type_in(rtxn, id)?;
        let is_claim = entity_type == Some(ENTITY_TYPE_CLAIM);
        let output = match path {
            "/" => {
                if is_claim {
                    format!("/claims/{}", id.to_hex())
                } else {
                    format!("/entities/{}", id.to_hex())
                }
            }
            "/claims" | "/claims/by-id" if is_claim => format!("/claims/{}", id.to_hex()),
            "/entities" => format!("/entities/{}", id.to_hex()),
            path if path.starts_with("/entities/") && path.ends_with(&id.to_hex()) => {
                path.to_owned()
            }
            _ => return Ok(None),
        };
        Ok(Some(format!("{output}\n")))
    }

    fn coreutils_path_visible(&self, path: &str) -> Result<bool> {
        let components = path_components(path)?;
        match components.as_slice() {
            ["claims", "by-id"] | ["claims", "by-time"] | ["claims", "by-time", _] => Ok(true),
            ["claims", "by-time", _, claim] => self
                .scoped_read
                .is_entity_readable(&parse_entity_id(claim)?),
            ["claims", claim] | ["claims", "by-id", claim] => self
                .scoped_read
                .is_entity_readable(&parse_entity_id(claim)?),
            ["entities", entity, ..] | ["backlinks", entity, ..] => {
                self.coreutils_entity_visible(&parse_entity_id(entity)?)
            }
            ["worlds", "base", ..] => Ok(true),
            ["worlds", world, ..] => self.coreutils_entity_visible(&parse_entity_id(world)?),
            _ => Ok(true),
        }
    }

    fn coreutils_entity_visible(&self, id: &EntityId) -> Result<bool> {
        let rtxn = self.scoped_read.vault().store.env.read_txn()?;
        let policy = self.scoped_read.policy_manifest_in(&rtxn)?;
        self.coreutils_entity_visible_in(&rtxn, &policy, id)
    }

    fn coreutils_entity_visible_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        id: &EntityId,
    ) -> Result<bool> {
        let Some(entity_type) = self.entity_type_in(rtxn, id)? else {
            return Ok(false);
        };
        if entity_type != ENTITY_TYPE_WORLD {
            return self
                .scoped_read
                .is_entity_readable_with_policy_in(rtxn, policy, id);
        }
        if policy.diagnostics().loaded_manifest_forces_fail_closed() {
            return Ok(false);
        }
        if !policy.has_scoped_read_grants() {
            return Ok(true);
        }
        let visible_worlds = self.world_names_from_matching_grants(policy);
        Ok(visible_worlds.iter().any(|world| world == &id.to_hex()))
    }

    pub(super) fn coreutils_result_cap(&self) -> usize {
        self.options
            .max_entries
            .clamp(1, GRAPH_FS_COREUTILS_MAX_RESULT_CAP)
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_coreutils_command(
        &self,
        verb: GraphFsCoreutilsVerb,
        started: Instant,
        started_at: u64,
        decision: GraphFsCoreutilsDecision,
        decision_reason: &str,
        bytes: Vec<u8>,
        next_cursor: Option<String>,
        signals: Vec<RetrievalSignal>,
        total_in_scope: usize,
        read_receipt: Option<ScopedReadReceipt>,
    ) -> Result<GraphFsCommandOutput> {
        let run_id = RetrievalRunId::from_bytes(self.scoped_read.vault().store.clock.ulid()?);
        let elapsed_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        let telemetry_reason = format!(
            "graph_fs_coreutils:{}:{}:{}",
            verb.stable_label(),
            decision.stable_label(),
            decision_reason
        );
        let record = RetrievalRunRecord::new(
            run_id,
            RetrievalAction::GraphFsCoreutils,
            started_at,
            elapsed_us,
            signals,
            Vec::new(),
            total_in_scope,
            0,
            Some(telemetry_reason),
        );
        if let Err(error) = self.scoped_read.vault().store.record_retrieval_run(&record) {
            tracing::warn!(
                ?error,
                command = verb.stable_label(),
                "graph-fs coreutils telemetry failed"
            );
        }
        Ok(GraphFsCommandOutput {
            bytes,
            next_cursor,
            decision,
            decision_reason: decision_reason.to_owned(),
            telemetry_run_id: run_id,
            read_receipt,
        })
    }
}

/// A walk's rendered output and the folded receipt of the reads behind it.
struct WalkOutput {
    bytes: Vec<u8>,
    next_cursor: Option<String>,
    total: usize,
    receipt: Option<ScopedReadReceipt>,
}

impl WalkOutput {
    fn new(
        out: CommandOutputBuilder,
        next_cursor: Option<String>,
        total: usize,
        receipt: Option<ScopedReadReceipt>,
    ) -> Self {
        Self {
            bytes: out.into_bytes(),
            next_cursor,
            total,
            receipt,
        }
    }
}

fn fold_receipt(into: &mut Option<ScopedReadReceipt>, later: ScopedReadReceipt) {
    match into {
        Some(receipt) => receipt.restrict_with(&later),
        None => *into = Some(later),
    }
}

fn parse_byte_cursor(cursor: Option<&str>) -> Result<usize> {
    match cursor {
        Some(cursor) => cursor
            .parse::<usize>()
            .map_err(|_| Error::InvalidConfig("invalid graph-fs byte cursor".to_owned())),
        None => Ok(0),
    }
}

fn literal_grep_pattern(pattern: &str) -> Option<&str> {
    let pattern = pattern.trim();
    if pattern.is_empty() || !pattern.is_ascii() {
        return None;
    }
    if pattern.bytes().any(|byte| {
        matches!(
            byte,
            b'.' | b'*'
                | b'+'
                | b'?'
                | b'['
                | b']'
                | b'('
                | b')'
                | b'{'
                | b'}'
                | b'|'
                | b'^'
                | b'$'
                | b'\\'
        )
    }) {
        return None;
    }
    Some(pattern)
}

fn append_grep_file_matches(
    path: &str,
    bytes: &[u8],
    pattern: &str,
    out: &mut CommandOutputBuilder,
    total: &mut usize,
) {
    let text = String::from_utf8_lossy(bytes);
    for line in text.lines().filter(|line| line.contains(pattern)) {
        let rendered = format!("{path}:{line}\n");
        if !out.try_push(rendered.as_bytes()) {
            break;
        }
        *total += 1;
    }
}

fn join_graph_path(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

pub(super) fn read_grant_matches_actor(
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

pub(super) fn grant_scope_world_name(scope: Option<&Value>) -> Option<String> {
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

pub(super) fn claim_matches_world_in(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    claim_id: &EntityId,
    world: Option<EntityId>,
) -> Result<bool> {
    let Some(row) = store.port_entity_record(rtxn, claim_id)? else {
        return Ok(false);
    };
    if row.entity_type != ENTITY_TYPE_CLAIM {
        return Ok(false);
    }
    Ok(decode_claim_body(&row.body, true)?.world == world)
}
