//! Linear issue snapshots from the team-scoped cursor-paged GraphQL connection.

use std::collections::BTreeMap;

use chrono::DateTime;
use oneiron::{
    LinearChangePage, LinearChangeSource, LinearIssueChange, LinearIssueRef, LinearSyncResult,
    MirroredTaskFields,
};
use serde_json::{Value, json};

use crate::http::{GraphQlCall, GraphQlExecutor};
use crate::{data, invalid, string};

// Linear sorts updatedAt newest first. Backward Relay pagination begins at
// the oldest tail, then walks toward the newest. Reverse each page so the
// engine observes ascending changes, including across page boundaries.
const PAGE_QUERY: &str = "query OneironLinearChanges($team: String!, $before: String, $last: Int!) { issues(filter: { team: { id: { eq: $team } } }, orderBy: updatedAt, last: $last, before: $before) { nodes { id identifier updatedAt title description priority team { id } state { id } assignee { id } } pageInfo { hasPreviousPage startCursor } } }";

/// Host-owned mapping between engine field tokens and Linear workflow/user IDs.
/// Unmapped values fail closed rather than silently changing tracker ownership.
#[derive(Debug, Clone)]
pub struct LinearTrackerConfig {
    pub team_id: String,
    pub status_ids: BTreeMap<String, String>,
    pub assignee_ids: BTreeMap<String, String>,
    pub page_size: u32,
}

impl LinearTrackerConfig {
    /// # Errors
    /// Refuses ambiguous reverse mappings and missing configuration.
    pub fn validate(&self) -> LinearSyncResult<()> {
        if self.team_id.trim().is_empty()
            || self.page_size == 0
            || self.page_size > 250
            || self.status_ids.is_empty()
            || self
                .status_ids
                .iter()
                .any(|(key, value)| key.trim().is_empty() || value.trim().is_empty())
            || self
                .assignee_ids
                .iter()
                .any(|(key, value)| key.trim().is_empty() || value.trim().is_empty())
        {
            return Err(invalid("Linear tracker configuration is invalid"));
        }
        for map in [&self.status_ids, &self.assignee_ids] {
            let mut seen = std::collections::BTreeSet::new();
            if !map.values().all(|value| seen.insert(value)) {
                return Err(invalid("Linear tracker mapping is ambiguous"));
            }
        }
        Ok(())
    }

    pub(crate) fn mapped<'a>(
        map: &'a BTreeMap<String, String>,
        token: &str,
    ) -> LinearSyncResult<&'a str> {
        map.get(token)
            .map(String::as_str)
            .ok_or_else(|| invalid("Linear tracker field has no configured mapping"))
    }

    fn reverse(map: &BTreeMap<String, String>, value: &str) -> LinearSyncResult<String> {
        map.iter()
            .find(|(_, id)| id.as_str() == value)
            .map(|(name, _)| name.clone())
            .ok_or_else(|| invalid("Linear tracker returned an unmapped field"))
    }

    pub(crate) fn issue(&self, node: &Value) -> LinearSyncResult<LinearIssueChange> {
        if string(
            node.get("team")
                .ok_or_else(|| invalid("Linear issue has no team"))?,
            "id",
        )? != self.team_id
        {
            return Err(invalid("Linear issue belongs to another team"));
        }
        let issue_id = string(node, "id")?.to_owned();
        let updated = string(node, "updatedAt")?;
        let updated_at_ms = DateTime::parse_from_rfc3339(updated)
            .map_err(|_| invalid("Linear issue has an invalid timestamp"))?
            .timestamp_millis()
            .try_into()
            .map_err(|_| invalid("Linear issue timestamp predates epoch"))?;
        let state_id = string(
            node.get("state")
                .ok_or_else(|| invalid("Linear issue has no state"))?,
            "id",
        )?;
        let assignee = node
            .get("assignee")
            .ok_or_else(|| invalid("Linear issue has no assignee field"))?;
        let assignee_id = if assignee.is_null() {
            None
        } else {
            Some(string(assignee, "id")?)
        };
        let priority = node
            .get("priority")
            .ok_or_else(|| invalid("Linear issue has no priority field"))?;
        let priority = if priority.is_null() {
            None
        } else {
            let value = priority
                .as_u64()
                .ok_or_else(|| invalid("Linear priority is invalid"))?;
            Some(u8::try_from(value).map_err(|_| invalid("Linear priority exceeds range"))?)
        };
        let description = node
            .get("description")
            .ok_or_else(|| invalid("Linear issue has no description field"))?;
        let description = if description.is_null() {
            None
        } else {
            Some(
                description
                    .as_str()
                    .ok_or_else(|| invalid("Linear description is invalid"))?
                    .to_owned(),
            )
        };
        let fields = MirroredTaskFields {
            title: string(node, "title")?.to_owned(),
            description,
            priority,
            assignee_ref: assignee_id
                .map(|id| Self::reverse(&self.assignee_ids, id))
                .transpose()?,
            status: Self::reverse(&self.status_ids, state_id)?,
        };
        // GraphQL exposes issue snapshots rather than an event stream. Bind the
        // event id to the issue, update stamp AND full snapshot, so distinct
        // snapshots at the same timestamp cannot collapse into one event.
        let mut hash = blake3::Hasher::new();
        hash.update(issue_id.as_bytes());
        hash.update(updated.as_bytes());
        hash.update(
            &serde_json::to_vec(&fields).map_err(|_| invalid("Linear issue encoding failed"))?,
        );
        Ok(LinearIssueChange {
            event_id: hash.finalize().to_hex().to_string(),
            issue: LinearIssueRef {
                issue_id,
                team_id: self.team_id.clone(),
                identifier: string(node, "identifier")?.to_owned(),
            },
            updated_at_ms,
            fields,
        })
    }
}

/// Real cursor-paged source. The host persists the returned cursor after the
/// engine successfully applies each page; a failed page is safe to replay.
pub struct LinearHostChangeSource<R> {
    reader: R,
    config: LinearTrackerConfig,
}

impl<R> LinearHostChangeSource<R> {
    /// # Errors
    /// Returns a configuration error before any network access.
    pub fn new(reader: R, config: LinearTrackerConfig) -> LinearSyncResult<Self> {
        config.validate()?;
        Ok(Self { reader, config })
    }

    pub fn into_reader(self) -> R {
        self.reader
    }
}

impl<R: GraphQlExecutor> LinearChangeSource for LinearHostChangeSource<R> {
    fn changes_since(&mut self, cursor: Option<&str>) -> LinearSyncResult<LinearChangePage> {
        let call = GraphQlCall {
            query: PAGE_QUERY,
            variables: json!({"team": self.config.team_id, "before": cursor, "last": self.config.page_size}),
        };
        let response = self.reader.execute(&call)?;
        let issues = data(&response, "issues")?;
        let nodes = issues
            .get("nodes")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("Linear issue page has no nodes"))?;
        if nodes.len() > self.config.page_size as usize {
            return Err(invalid("Linear issue page exceeds requested size"));
        }
        let changes: Vec<_> = nodes
            .iter()
            .rev()
            .map(|node| self.config.issue(node))
            .collect::<Result<_, _>>()?;
        if changes
            .windows(2)
            .any(|pair| pair[0].updated_at_ms > pair[1].updated_at_ms)
        {
            return Err(invalid("Linear issue page is not timestamp ordered"));
        }
        let page_info = issues
            .get("pageInfo")
            .ok_or_else(|| invalid("Linear issue page has no pageInfo"))?;
        let has_next = page_info
            .get("hasPreviousPage")
            .and_then(Value::as_bool)
            .ok_or_else(|| invalid("Linear issue page has no continuation flag"))?;
        let next_cursor = if has_next {
            let next = string(page_info, "startCursor")?;
            if next.is_empty() || cursor == Some(next) {
                return Err(invalid("Linear issue page has a non-progressing cursor"));
            }
            Some(next.to_owned())
        } else {
            None
        };
        Ok(LinearChangePage {
            changes,
            next_cursor,
        })
    }
}
