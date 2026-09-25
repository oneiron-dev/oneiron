//! Pack-local first-mention rendering. Citation IDs remain revision-qualified metadata.
use super::pack_entry::PreparedPack;
use crate::context_pack::ContextPack;
use serde_json::Value;
use std::collections::{HashMap, HashSet};

#[derive(Default)]
pub(super) struct Handles {
    aliases: HashMap<String, (String, String)>,
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
        for entity in pack.results.iter().chain(&pack.neighbors) {
            if entity.short_id.is_empty() {
                continue;
            }
            let name = names.get(entity.id.as_bytes()).map_or("", String::as_str);
            let handle = (entity.short_id.clone(), name.to_owned());
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
        for (_, rows) in prepared.results.iter_mut().chain(&mut prepared.neighbors) {
            for row in rows {
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
    fn text(&mut self, text: &str) -> String {
        let mut aliases = self.aliases.iter().collect::<Vec<_>>();
        aliases.sort_by_key(|(alias, _)| std::cmp::Reverse(alias.len()));
        let mut output = String::with_capacity(text.len());
        let mut tail = text;
        let mut left_boundary = true;
        let is_word = |c: char| c.is_alphanumeric() || c == '_';
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
            if let Some((alias, (id, name), rest)) = matched {
                if self.seen.insert(id.clone()) && !name.is_empty() {
                    output.push_str(name);
                    output.push_str(" (");
                    output.push_str(id);
                    output.push(')');
                } else {
                    output.push_str(id);
                }
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
    pub(super) fn value(&mut self, value: &mut Value) {
        match value {
            Value::String(text) => *text = self.text(text),
            Value::Array(values) => {
                for value in values {
                    self.value(value);
                }
            }
            Value::Object(map) => {
                for (key, value) in map {
                    // Never substitute a short ref in a citation: its content-hash
                    // suffix is the revision gate.
                    if key != "stats" && key != "id" {
                        self.value(value);
                    }
                }
            }
            _ => {}
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
                        if let Some((_, value)) =
                            row.fields.iter_mut().find(|(key, _)| key == column)
                        {
                            self.value(value);
                        }
                    }
                } else {
                    for (_, value) in &mut row.fields {
                        self.value(value);
                    }
                }
            }
        }
    }
}
