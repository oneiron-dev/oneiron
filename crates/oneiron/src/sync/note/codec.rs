//! Binding validation of untrusted NOTE proposal values and workflow metadata.
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
        if parts.len() != 4 || parts[0] != "note_proposal_doc" || parts[1] != "v1" {
            return Err(invalid("NOTE document key"));
        }
        state
            .docs
            .insert((id(parts[2])?, id(parts[3])?), unpack::<String>(&bytes)?);
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
        for ((note, head), text) in &self.docs {
            if !self.cores.contains_key(note) || !self.heads.contains_key(note) {
                return Err(invalid("NOTE document owner absent"));
            }
            if note == head {
                return Err(invalid("window cannot carry active NOTE state"));
            }
            crate::note::validate_markdown(text)?;
            documents.insert((*note, *head), text);
        }
        for raw in self.cores.values() {
            crate::note::decode_note_body_using(
                &raw[ENTITY_METADATA_HEADER_LEN..],
                crate::note::NoteKind::wire,
            )?;
        }
        for (note, head) in &self.heads {
            if note != head || !self.cores.contains_key(note) {
                return Err(invalid("NOTE program identity is not its entity"));
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
                || row.previous_head != row.note
                || row.head != row.note
            {
                return Err(invalid("NOTE receipt binding"));
            }
            match row.verdict {
                crate::note::NoteVerdict::Switch if row.head == row.note => {}
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
            if fork.parent != fork.note || !self.heads.contains_key(&fork.note) {
                return Err(invalid("NOTE proposal parent identity"));
            }
            if fork.parent == fork.fork
                || fork.proposal != membership.get(&fork.fork).copied()
                || fork.decided != landed.contains(&fork.fork)
            {
                return Err(invalid("NOTE fork workflow binding"));
            }
            if let Some((_, target)) = &fork.recovery_merge
                && documents.get(&(fork.note, fork.fork)).copied() != Some(target)
            {
                return Err(invalid("NOTE merge target differs from proposal value"));
            }
            if !fork.decided {
                if !documents.contains_key(&(fork.note, fork.fork)) || !fork.frontier.is_empty() {
                    return Err(invalid("NOTE proposal value absent or carries raw history"));
                }
            }
        }
        for (note, head) in documents.keys() {
            if self
                .forks
                .get(head)
                .is_none_or(|fork| fork.note != *note || fork.decided)
            {
                return Err(invalid("NOTE proposal value has no pending fork"));
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
        for ((note, head), text) in &self.docs {
            maps.entry("documents")
                .or_default()
                .insert(doc_key(*note, *head), pack(text)?);
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
