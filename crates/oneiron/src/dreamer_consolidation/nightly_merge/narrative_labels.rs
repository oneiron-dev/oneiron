//! A nightly narrative stored in durable names (FIX 7576). The narrative
//! call shows each proposal and subject by a call-local label (`C1`, `P1`,
//! FIX 7506) that means nothing once the call is over, so before the text is
//! stored each label it writes as a whole word becomes what it stood for:
//! an entity its stored name (its id when the Dreamer may read no name), a
//! proposal its predicate and value. Every other byte of the prose stays as
//! the model wrote it. The prompt also asks for names; this is the
//! guarantee.

use std::collections::BTreeMap;

use super::Proposal;
use crate::Vault;
use crate::claim::ScopedRead;
use crate::dreamer_consolidation::call_labels::{CallLabelMap, LabelKind};
use crate::dreamer_consolidation::value_projection::rmpv_to_json;
use crate::error::Result;

/// What each label of one narrative call stands for after it: each entity
/// label its entity's name as the Dreamer reads it now, else its id; each
/// proposal label `[predicate = value]`.
pub(super) fn durable_names(
    vault: &Vault,
    read: &ScopedRead<'_>,
    labels: &CallLabelMap,
    members: &[&Proposal],
) -> Result<BTreeMap<String, String>> {
    let mut names = BTreeMap::new();
    let entities: Vec<_> = labels.labelled(LabelKind::Entity).collect();
    if !entities.is_empty() {
        let txn = vault.store.env.read_txn()?;
        let ids: Vec<_> = entities.iter().map(|(_, id)| *id).collect();
        let rows = read.get_entities_parts_in_txn(&txn, &ids)?;
        for ((label, id), row) in entities.into_iter().zip(rows) {
            let name = row
                .and_then(|(_, _, body)| entity_name(&body))
                .unwrap_or_else(|| id.to_hex());
            names.insert(label.to_string(), name);
        }
    }
    for (label, id) in labels.labelled(LabelKind::Claim) {
        if let Some(member) = members.iter().find(|member| member.id == id) {
            names.insert(
                label.to_string(),
                format!(
                    "[{} = {}]",
                    member.body.predicate,
                    rmpv_to_json(&member.body.value)
                ),
            );
        }
    }
    Ok(names)
}

/// `text` with each label in `names` that it writes as a whole word (an
/// ASCII capital, then digits, neither joined to a letter, digit or `_` on
/// either side) replaced by what it stands for; all else byte for byte.
pub(super) fn durable_text(text: &str, names: &BTreeMap<String, String>) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at].is_ascii_uppercase() && (at == 0 || !word_byte(bytes[at - 1])) {
            let mut end = at + 1;
            while end < bytes.len() && bytes[end].is_ascii_digit() {
                end += 1;
            }
            if end > at + 1
                && bytes.get(end).is_none_or(|next| !word_byte(*next))
                && let Some(name) = names.get(&text[at..end])
            {
                out.push_str(&text[copied..at]);
                out.push_str(name);
                copied = end;
                at = end;
                continue;
            }
        }
        at += 1;
    }
    out.push_str(&text[copied..]);
    out
}

fn word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// An entity body's `name`, when it carries one.
fn entity_name(body: &[u8]) -> Option<String> {
    let mut cursor = body;
    let value = rmpv::decode::read_value(&mut cursor).ok()?;
    let name = rmpv_to_json(&value)
        .get("name")?
        .as_str()?
        .trim()
        .to_owned();
    (!name.is_empty()).then_some(name)
}
