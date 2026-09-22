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
    fn field(&mut self, key: &str, value: &mut Value) {
        if matches!(key, "name" | "display_name")
            && let Some((id, name)) = value.as_str().and_then(|alias| self.aliases.get(alias))
        {
            *value = Value::String(if self.seen.insert(id.clone()) && !name.is_empty() {
                format!("{name} ({id})")
            } else {
                id.clone()
            });
        }
    }
    pub(super) fn value(&mut self, value: &mut Value) {
        match value {
            Value::Array(values) => {
                for value in values {
                    self.value(value);
                }
            }
            Value::Object(map) if map.contains_key("id") => {
                // Never substitute a short ref in a citation: its content-hash
                // suffix is the revision gate.
                for key in ["display_name", "name"] {
                    if let Some(value) = map.get_mut(key) {
                        self.field(key, value);
                    }
                }
            }
            Value::Object(map) => {
                for (key, value) in map {
                    if key != "stats" {
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
                            self.field(column, value);
                        }
                    }
                } else {
                    for (key, value) in &mut row.fields {
                        self.field(key, value);
                    }
                }
            }
        }
    }
}
