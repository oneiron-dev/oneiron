//! Grouped reaction pills, chain history, and the one-line-per-glyph rendering
//! recall and context packs attach to a conversation record.
use super::chain::{StoredReaction, chain_in, reactions_on_in};
use super::value::ReactionExternalId;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::conversation::AudienceCache;
use crate::error::Result;
use crate::{EntityId, Vault};
use rmpv::Value;
use std::collections::{BTreeMap, BTreeSet};

/// The context-pack field that carries a record's grouped reaction lines.
pub const REACTIONS_FIELD: &str = "reactions";
/// Names shown before a group's remainder is summarized as `+N`.
const NAMED_REACTORS: usize = 2;
const RECORD_TEXT_KEYS: [&str; 4] = ["content", "text", "body", "title"];
const PERSON_NAME_KEYS: [&str; 2] = ["display_name", "name"];

/// One glyph's live reactions, contributors in first-put order.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ReactionPill {
    pub glyph: String,
    pub count: usize,
    pub by: Vec<EntityId>,
    pub mine: bool,
}

/// One claim of a (message, person, glyph) chain.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ReactionHistoryEntry {
    pub id: EntityId,
    pub glyph: String,
    pub by: EntityId,
    pub occurred_at: u64,
    pub recorded_at: u64,
    pub removed_at: Option<u64>,
    pub external_id: Option<ReactionExternalId>,
}

/// Groups the live reactions on `record` whose reactor was in the room
/// audience at the reaction's own time and which `admit` lets through.
/// Independent peers' copies of one (person, glyph) count once.
pub(crate) fn pills_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: EntityId,
    viewer: Option<EntityId>,
    audience: &mut AudienceCache,
    mut admit: impl FnMut(&StoredReaction) -> Result<bool>,
) -> Result<Vec<ReactionPill>> {
    let mut pills: Vec<ReactionPill> = Vec::new();
    let mut seen = BTreeSet::new();
    for row in reactions_on_in(vault, txn, record)? {
        if !row.live()
            || seen.contains(&(row.value.by, row.value.glyph.clone()))
            || !audience.readable(vault, txn, row.id, &[row.value.by])?
            || !admit(&row)?
        {
            continue;
        }
        seen.insert((row.value.by, row.value.glyph.clone()));
        let mine = viewer == Some(row.value.by);
        if let Some(pill) = pills.iter_mut().find(|pill| pill.glyph == row.value.glyph) {
            pill.count += 1;
            pill.by.push(row.value.by);
            pill.mine |= mine;
        } else {
            pills.push(ReactionPill {
                glyph: row.value.glyph,
                count: 1,
                by: vec![row.value.by],
                mine,
            });
        }
    }
    Ok(pills)
}

/// `👍×8 (Anna, Ben, +6)`: the glyph, its count, the first reactors' names
/// and how many more reacted.
#[must_use]
pub fn reaction_line(glyph: &str, count: usize, names: &[String]) -> String {
    let shown = names.len().min(NAMED_REACTORS);
    let mut people = names[..shown].join(", ");
    if count > shown {
        if !people.is_empty() {
            people.push_str(", ");
        }
        people.push_str(&format!("+{}", count - shown));
    }
    format!("{glyph}×{count} ({people})")
}

/// One grouped line per glyph for the reactions `admit` lets through.
pub(crate) fn grouped_lines_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: EntityId,
    admit: impl FnMut(&StoredReaction) -> Result<bool>,
) -> Result<Vec<String>> {
    let pills = pills_in(
        vault,
        txn,
        record,
        None,
        &mut AudienceCache::default(),
        admit,
    )?;
    pills
        .iter()
        .map(|pill| {
            let names = pill
                .by
                .iter()
                .take(NAMED_REACTORS)
                .map(|person| display_name_in(vault, txn, *person))
                .collect::<Result<Vec<_>>>()?;
            Ok(reaction_line(&pill.glyph, pill.count, &names))
        })
        .collect()
}

fn body_map(vault: &Vault, txn: &heed::RoTxn<'_>, id: EntityId) -> Result<Option<Value>> {
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &id)? else {
        return Ok(None);
    };
    if EntityMetadataHeader::parse(&raw).is_none() || raw.len() <= ENTITY_METADATA_HEADER_LEN {
        return Ok(None);
    }
    let mut body = &raw[ENTITY_METADATA_HEADER_LEN..];
    if let Ok(value @ Value::Map(_)) = rmpv::decode::read_value(&mut body) {
        return Ok(Some(value));
    }
    Ok(
        serde_json::from_slice::<serde_json::Value>(&raw[ENTITY_METADATA_HEADER_LEN..])
            .ok()
            .and_then(|json| {
                json.as_object().map(|object| {
                    Value::Map(
                        object
                            .iter()
                            .filter_map(|(key, value)| {
                                value
                                    .as_str()
                                    .map(|text| (Value::from(key.as_str()), Value::from(text)))
                            })
                            .collect(),
                    )
                })
            }),
    )
}

fn first_string(value: &Value, keys: &[&str]) -> Option<String> {
    let Value::Map(entries) = value else {
        return None;
    };
    keys.iter().find_map(|wanted| {
        entries.iter().find_map(|(key, value)| {
            (key.as_str() == Some(*wanted))
                .then(|| value.as_str().filter(|text| !text.trim().is_empty()))
                .flatten()
                .map(str::to_owned)
        })
    })
}

/// A PERSON's stored display name, when its body carries one.
pub(crate) fn person_name_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    person: EntityId,
) -> Result<Option<String>> {
    Ok(body_map(vault, txn, person)?.and_then(|body| first_string(&body, &PERSON_NAME_KEYS)))
}

fn display_name_in(vault: &Vault, txn: &heed::RoTxn<'_>, person: EntityId) -> Result<String> {
    Ok(person_name_in(vault, txn, person)?.unwrap_or_else(|| person.to_hex()[..8].to_owned()))
}

/// The text of a conversation record, when its body carries one.
pub(crate) fn record_text_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: EntityId,
) -> Result<Option<String>> {
    Ok(body_map(vault, txn, record)?.and_then(|body| first_string(&body, &RECORD_TEXT_KEYS)))
}

impl Vault {
    /// Groups each readable message's live reactions for `viewer` in one
    /// snapshot. A message the viewer cannot read gets no pills, and a
    /// reaction made while the viewer was outside the room is withheld.
    pub fn reaction_pills(
        &self,
        messages: &[EntityId],
        viewer: EntityId,
    ) -> Result<BTreeMap<EntityId, Vec<ReactionPill>>> {
        let txn = self.store.env.read_txn()?;
        let mut reactors = AudienceCache::default();
        let mut viewers = AudienceCache::default();
        let mut result = BTreeMap::new();
        for &message in messages {
            if !viewers.readable(self, &txn, message, &[viewer])? {
                continue;
            }
            let pills = pills_in(self, &txn, message, Some(viewer), &mut reactors, |row| {
                viewers.readable(self, &txn, row.id, &[viewer])
            })?;
            result.insert(message, pills);
        }
        Ok(result)
    }

    /// The (message, person, glyph) chain in order: every put, and when each
    /// was removed. Flip-flopping stays readable.
    pub fn reaction_history(
        &self,
        message: EntityId,
        by: EntityId,
        glyph: &str,
    ) -> Result<Vec<ReactionHistoryEntry>> {
        let txn = self.store.env.read_txn()?;
        Ok(chain_in(self, &txn, message, by, glyph)?
            .into_iter()
            .map(|row| ReactionHistoryEntry {
                id: row.id,
                removed_at: row.retracted_at(),
                glyph: row.value.glyph,
                by: row.value.by,
                occurred_at: row.value.occurred_at,
                recorded_at: row.learned_at,
                external_id: row.value.external_id,
            })
            .collect())
    }
}
