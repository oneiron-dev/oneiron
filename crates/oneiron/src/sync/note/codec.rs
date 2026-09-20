//! Binding validation of native NOTE snapshots, heads, and mutable workflows.
use super::*;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::recovery::{CanonicalHead, CanonicalHeadMove};

pub(super) fn read(doc: &LoroDoc) -> Result<State> {
    let mut state = State::default();
    for (key, raw) in rows(doc, "entities")? {
        if EntityMetadataHeader::parse(&raw)
            .is_some_and(|h| h.entity_type == crate::registry::ENTITY_TYPE_NOTE)
            && raw.len() > ENTITY_METADATA_HEADER_LEN
        {
            state.cores.insert(id(&key)?, raw);
        }
    }
    let mut format = false;
    for (key, bytes) in rows(doc, "documents")? {
        if key == FORMAT_KEY {
            if bytes != FORMAT {
                return Err(invalid("unknown NOTE sync format"));
            }
            format = true;
            continue;
        }
        let parts: Vec<_> = key.split(':').collect();
        if parts.len() != 4 || parts[0] != "note_doc" || parts[1] != "v1" {
            return Err(invalid("NOTE document key"));
        }
        state.docs.insert((id(parts[2])?, id(parts[3])?), bytes);
    }
    if !format {
        return Err(invalid("missing NOTE sync format"));
    }
    for (key, bytes) in rows(doc, "document_heads")? {
        let row: CanonicalHead = unpack(&bytes)?;
        let note = EntityId::from_bytes(row.entity_id)?;
        if id(&key)? != note {
            return Err(invalid("NOTE head key"));
        }
        state.heads.insert(note, EntityId::from_bytes(row.head)?);
    }
    for (key, bytes) in rows(doc, "head_move_receipts")? {
        let wrapper: CanonicalHeadMove = unpack(&bytes)?;
        let row: NoteLandingReceipt = unpack(&wrapper.receipt)?;
        if id(&key)? != row.id
            || wrapper.id != *row.id.as_bytes()
            || wrapper.entity_id != *row.note.as_bytes()
        {
            return Err(invalid("NOTE receipt key"));
        }
        state.receipts.insert(row.id, row);
    }
    for (key, bytes) in rows(doc, "note_forks")? {
        let row: NoteFork = unpack(&bytes)?;
        if id(&key)? != row.fork {
            return Err(invalid("NOTE fork key"));
        }
        state.forks.insert(row.fork, row);
    }
    for (key, bytes) in rows(doc, "note_proposals")? {
        let row: NoteReviewBundle = unpack(&bytes)?;
        if id(&key)? != row.id {
            return Err(invalid("NOTE proposal key"));
        }
        state.bundles.insert(row.id, row);
    }
    Ok(state)
}

impl State {
    pub(super) fn validate(&self) -> Result<()> {
        let mut documents = BTreeMap::new();
        for ((note, head), bytes) in &self.docs {
            if !self.cores.contains_key(note) || !self.heads.contains_key(note) {
                return Err(invalid("NOTE document owner absent"));
            }
            let doc = LoroDoc::from_snapshot(bytes).map_err(|_| invalid("NOTE snapshot"))?;
            let LoroValue::Map(root) = doc.get_deep_value() else {
                return Err(invalid("NOTE snapshot root"));
            };
            if root.len() != 2
                || !matches!(root.get("body"), Some(LoroValue::String(_)))
                || !matches!(root.get("meta"), Some(LoroValue::Map(_)))
            {
                return Err(invalid("NOTE snapshot containers"));
            }
            let meta = doc.get_map("meta");
            let read = |key| match meta.get(key) {
                Some(ValueOrContainer::Value(LoroValue::String(value))) => Ok(value.to_string()),
                _ => Err(invalid("NOTE snapshot birth")),
            };
            if meta.len() != 2 {
                return Err(invalid("NOTE snapshot metadata"));
            }
            id(&read("birth_actor")?)?;
            read("birth_at")?
                .parse::<u64>()
                .map_err(|_| invalid("NOTE birth timestamp"))?;
            documents.insert((*note, *head), doc);
        }
        for (note, raw) in &self.cores {
            let core = crate::note::decode_note_body_using(
                &raw[ENTITY_METADATA_HEADER_LEN..],
                crate::note::NoteKind::wire,
            )?;
            if core.document_head != self.heads.get(note).copied() {
                return Err(invalid("NOTE core/head mismatch"));
            }
        }
        for (note, head) in &self.heads {
            if !documents.contains_key(&(*note, *head)) {
                return Err(invalid("NOTE current snapshot absent"));
            }
        }
        let mut landed = BTreeSet::new();
        for row in self.receipts.values() {
            let fork = self
                .forks
                .get(&row.fork)
                .ok_or(invalid("NOTE receipt fork absent"))?;
            if !fork.decided
                || fork.note != row.note
                || !landed.insert(row.fork)
                || !documents.contains_key(&(row.note, row.previous_head))
                || !documents.contains_key(&(row.note, row.head))
            {
                return Err(invalid("NOTE receipt binding"));
            }
            match row.verdict {
                crate::note::NoteVerdict::Switch if row.head == row.fork => {}
                crate::note::NoteVerdict::Merge
                    if !fork.rewrite && row.head == row.previous_head => {}
                crate::note::NoteVerdict::Reject
                    if row.head == row.previous_head
                        && !documents.contains_key(&(row.note, row.fork)) => {}
                _ => return Err(invalid("NOTE receipt verdict")),
            }
        }
        let mut membership = BTreeMap::new();
        for bundle in self.bundles.values() {
            if !(1..=256).contains(&(bundle.waiting.len() + bundle.landed.len()))
                || bundle.explainer.trim().is_empty()
            {
                return Err(invalid("NOTE proposal shape"));
            }
            for fork in &bundle.waiting {
                if self.forks.get(&fork.fork) != Some(fork)
                    || fork.decided
                    || membership.insert(fork.fork, bundle.id).is_some()
                {
                    return Err(invalid("NOTE waiting fork binding"));
                }
            }
            for row in &bundle.landed {
                if self.receipts.get(&row.id) != Some(row)
                    || membership.insert(row.fork, bundle.id).is_some()
                {
                    return Err(invalid("NOTE landed fork binding"));
                }
            }
        }
        for fork in self.forks.values() {
            if fork.recovery_merge.is_some()
                && (!fork.frontier.is_empty() || fork.rewrite || fork.decided)
                || (!fork.decided
                    && !fork.rewrite
                    && fork.frontier.is_empty()
                    && fork.recovery_merge.is_none())
            {
                return Err(invalid("NOTE fork merge basis"));
            }
            let parent = documents
                .get(&(fork.note, fork.parent))
                .ok_or(invalid("NOTE fork parent absent"))?;
            if fork.parent == fork.fork
                || fork.proposal != membership.get(&fork.fork).copied()
                || fork.decided != landed.contains(&fork.fork)
            {
                return Err(invalid("NOTE fork workflow binding"));
            }
            if !fork.decided {
                let proposed = documents
                    .get(&(fork.note, fork.fork))
                    .ok_or(invalid("NOTE fork snapshot absent"))?;
                if !fork.frontier.is_empty() {
                    let frontier = loro::Frontiers::decode(&fork.frontier)
                        .map_err(|_| invalid("NOTE fork frontier"))?;
                    let base = parent
                        .fork_at(&frontier)
                        .map_err(|_| invalid("NOTE parent frontier"))?;
                    let other = proposed
                        .fork_at(&frontier)
                        .map_err(|_| invalid("NOTE proposed frontier"))?;
                    if base.get_deep_value() != other.get_deep_value() {
                        return Err(invalid("NOTE fork ancestry"));
                    }
                }
            }
        }
        Ok(())
    }

    pub(super) fn write(&self, doc: &LoroDoc) -> Result<bool> {
        let mut maps: BTreeMap<&str, BTreeMap<String, Vec<u8>>> = MAPS
            .into_iter()
            .map(|name| (name, BTreeMap::new()))
            .collect();
        maps.entry("documents")
            .or_default()
            .insert(FORMAT_KEY.to_owned(), FORMAT.to_vec());
        for ((note, head), raw) in &self.docs {
            maps.entry("documents")
                .or_default()
                .insert(doc_key(*note, *head), raw.clone());
        }
        for (note, head) in &self.heads {
            maps.entry("document_heads").or_default().insert(
                note.to_hex(),
                pack(&CanonicalHead {
                    entity_id: *note.as_bytes(),
                    head: *head.as_bytes(),
                })?,
            );
        }
        for receipt in self.receipts.values() {
            maps.entry("head_move_receipts").or_default().insert(
                receipt.id.to_hex(),
                pack(&CanonicalHeadMove {
                    id: *receipt.id.as_bytes(),
                    entity_id: *receipt.note.as_bytes(),
                    receipt: pack(receipt)?,
                })?,
            );
        }
        for fork in self.forks.values() {
            maps.entry("note_forks")
                .or_default()
                .insert(fork.fork.to_hex(), pack(fork)?);
        }
        for bundle in self.bundles.values() {
            maps.entry("note_proposals")
                .or_default()
                .insert(bundle.id.to_hex(), pack(bundle)?);
        }
        let mut changed = false;
        for (name, values) in maps {
            let map = doc.get_map(name);
            let mut keys = Vec::new();
            map.for_each(|key, _| {
                keys.push(key.to_owned());
            });
            for key in keys {
                if !values.contains_key(&key) {
                    crate::sync::loro_support::map_delete(&map, &key)?;
                    changed = true;
                }
            }
            for (key, bytes) in values {
                if crate::sync::loro_support::map_get_bytes(&map, &key).as_deref()
                    != Some(bytes.as_slice())
                {
                    crate::sync::loro_support::map_insert_bytes(&map, &key, &bytes)?;
                    changed = true;
                }
            }
        }
        Ok(changed)
    }
}
