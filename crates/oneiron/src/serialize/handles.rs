//! Pack-local first-mention rendering. Citation IDs remain revision-qualified metadata.
use super::pack_entry::{PreparedEntity, PreparedPack};
use crate::context_pack::ContextPack;
use serde_json::Value;
use std::collections::{HashMap, HashSet};

/// An alias's entity: its short id, its name, and its source id.
type Handle = (String, String, [u8; 16]);

#[derive(Default)]
pub(super) struct Handles {
    aliases: HashMap<String, Handle>,
    seen: HashSet<String>,
}
impl Handles {
    pub(super) fn new(pack: &ContextPack, prepared: &mut PreparedPack) -> Self {
        // Names must come from the projected, already-truncated rows. Using
        // original bodies here would restore fields removed by a budget/profile.
        let names: HashMap<_, _> = prepared
            .results
            .iter()
            .chain(&prepared.neighbors)
            .flat_map(|(_, rows)| rows.iter())
            .map(|row| {
                let name = row
                    .fields
                    .iter()
                    .find(|(key, _)| key == "display_name")
                    .or_else(|| row.fields.iter().find(|(key, _)| key == "name"))
                    .and_then(|(_, value)| value.as_str())
                    .unwrap_or("")
                    .to_owned();
                (row.source_id, name)
            })
            .collect();
        let mut aliases = HashMap::new();
        // Each entity's aliases: its id, and its identity key.
        for entity in pack.results.iter().chain(&pack.neighbors) {
            if entity.short_id.is_empty() {
                continue;
            }
            let name = names.get(entity.id.as_bytes()).map_or("", String::as_str);
            let name = if name == entity.short_id { "" } else { name };
            let handle = (
                entity.short_id.clone(),
                name.to_owned(),
                *entity.id.as_bytes(),
            );
            aliases.insert(entity.id.to_hex(), handle.clone());
            if let Some(key) = entity
                .fields
                .as_ref()
                .and_then(|f| f.get("identity_key"))
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                aliases.insert(key.into(), handle);
            }
        }
        for (_, group) in prepared.results.iter_mut().chain(&mut prepared.neighbors) {
            for row in group {
                let identity = row
                    .source_id
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>();
                // Identity-key fields are engine lookup metadata, not context.
                row.fields.retain(|(key, _)| key != "identity_key");
                if aliases.contains_key(&identity) {
                    for (key, value) in &mut row.fields {
                        if matches!(key.as_str(), "name" | "display_name") && value.is_string() {
                            *value = Value::String(identity.clone());
                        }
                    }
                }
            }
        }
        Self {
            aliases,
            seen: HashSet::new(),
        }
    }
    /// `text` with each alias rendered: as its entity's name and short id at
    /// its first mention, as the short id after. In a row's own fields
    /// (`own`: its source id, and the field), its own id or identity key
    /// stands as its short id alone, but in its name: its name, set beside
    /// its own words, could finish a phrase they begin that no read of it
    /// saw. One pass reads the text once, so no render is read again.
    fn text(&mut self, text: &str, own: Option<([u8; 16], &str)>) -> String {
        let mut aliases = self.aliases.iter().collect::<Vec<_>>();
        aliases.sort_by_key(|(alias, _)| std::cmp::Reverse(alias.len()));
        let seen = &mut self.seen;
        let own = own
            .filter(|(_, field)| !matches!(*field, "name" | "display_name"))
            .map(|(row, _)| row);
        substitute(text, &aliases, |(id, name, entity)| {
            if own == Some(*entity) {
                id.clone()
            } else if seen.insert(id.clone()) && !name.is_empty() {
                format!("{name} ({id})")
            } else {
                id.clone()
            }
        })
    }
    /// Text outside every row: no alias in it is any entity's own.
    pub(super) fn value(&mut self, value: &mut Value) {
        self.walk(value, None);
    }
    /// The rows JSON and TOON build from `entities`, one each, in the order
    /// they are emitted, each read as its prepared row's own: a serialized
    /// row's `id` can be a body field's. `id` and `stats` stay as they are.
    pub(super) fn emitted_rows(&mut self, entities: &[PreparedEntity], rows: &mut [Value]) {
        for (entity, row) in entities.iter().zip(rows) {
            if let Value::Object(map) = row {
                for (key, value) in map {
                    if key != "stats" && key != "id" {
                        self.walk(value, Some((entity.source_id, key.as_str())));
                    }
                }
            }
        }
    }
    pub(super) fn rows(&mut self, groups: &mut super::pack_entry::PreparedGroups, table: bool) {
        for (_, rows) in groups {
            let mut columns = Vec::new();
            if table {
                for row in rows.iter() {
                    for (key, _) in &row.fields {
                        if !columns.contains(key) {
                            columns.push(key.clone());
                        }
                    }
                }
            }
            for row in rows {
                if table {
                    for column in &columns {
                        if let Some((key, value)) =
                            row.fields.iter_mut().find(|(key, _)| key == column)
                        {
                            self.walk(value, Some((row.source_id, key.as_str())));
                        }
                    }
                } else {
                    for (key, value) in &mut row.fields {
                        self.walk(value, Some((row.source_id, key.as_str())));
                    }
                }
            }
        }
    }

    /// Each string in `value` through [`Self::text`], read as `own`'s (a
    /// row's source id, and its top-level field) however deep it sits: no
    /// `id` or `name` key in a body names a row or its name field.
    fn walk(&mut self, value: &mut Value, own: Option<([u8; 16], &str)>) {
        match value {
            Value::String(string) => *string = self.text(string, own),
            Value::Array(values) => {
                for value in values {
                    self.walk(value, own);
                }
            }
            Value::Object(map) => {
                for (key, value) in map {
                    // Never substitute a short ref in a citation: its
                    // content-hash suffix is the revision gate.
                    if key != "stats" && key != "id" {
                        self.walk(value, own);
                    }
                }
            }
            _ => {}
        }
    }
}

/// `text` with each alias that stands as a whole word rendered by `render`,
/// the first of `aliases` that matches taken.
fn substitute(
    text: &str,
    aliases: &[(&String, &Handle)],
    mut render: impl FnMut(&Handle) -> String,
) -> String {
    let mut output = String::with_capacity(text.len());
    let mut tail = text;
    let mut left_boundary = true;
    while !tail.is_empty() {
        let matched = aliases.iter().find_map(|(alias, handle)| {
            if !left_boundary {
                return None;
            }
            let rest = tail.strip_prefix(alias.as_str())?;
            rest.chars()
                .next()
                .is_none_or(|c| !is_word(c))
                .then_some((alias, handle, rest))
        });
        if let Some((alias, handle, rest)) = matched {
            output.push_str(&render(handle));
            left_boundary = alias.chars().next_back().is_none_or(|c| !is_word(c));
            tail = rest;
        } else {
            let mut chars = tail.chars();
            if let Some(c) = chars.next() {
                output.push(c);
                left_boundary = !is_word(c);
            }
            tail = chars.as_str();
        }
    }
    output
}

/// What an alias's edges must not touch for it to stand as a whole word.
fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}
