//! Reconcile durable NOTE edits with a window that may be ahead after a crash.
use super::*;

pub(super) fn reaches(state: &State, note: EntityId, from: EntityId, to: EntityId) -> bool {
    let mut visited = BTreeSet::from([from]);
    for _ in 0..state.receipts.len() {
        let before = visited.len();
        for row in state.receipts.values() {
            if row.note == note
                && row.verdict == super::super::NoteVerdict::Switch
                && visited.contains(&row.previous_head)
            {
                visited.insert(row.head);
            }
        }
        if visited.len() == before {
            break;
        }
    }
    visited.contains(&to)
}

impl State {
    pub(super) fn merge_carried(
        &mut self,
        mut carried: State,
        removed: &BTreeSet<EntityId>,
    ) -> Result<()> {
        carried.drop_deleted(removed);
        for (key, row) in carried.receipts {
            if let Some(local) = self.receipts.get(&key)
                && local != &row
            {
                return Err(invalid("NOTE receipt divergence during mirror"));
            }
            self.receipts.insert(key, row);
        }
        for (key, remote) in carried.forks {
            if let Some(local) = self.forks.get(&key) {
                if local.note != remote.note
                    || local.parent != remote.parent
                    || local.actor != remote.actor
                    || local.rewrite != remote.rewrite
                    || local.frontier != remote.frontier
                    || (local.proposal.is_some()
                        && remote.proposal.is_some()
                        && local.proposal != remote.proposal)
                    || (!local.decided
                        && !remote.decided
                        && local.recovery_merge != remote.recovery_merge)
                {
                    return Err(invalid("NOTE fork divergence during mirror"));
                }
                if local.decided || (local.proposal.is_some() && remote.proposal.is_none()) {
                    continue;
                }
            }
            self.forks.insert(key, remote);
        }
        for (key, incoming) in carried.docs {
            if let Some(local) = self.docs.get(&key) {
                self.docs.insert(key, merge_document(local, &incoming)?);
            } else {
                self.docs.insert(key, incoming);
            }
        }
        for row in self.receipts.values() {
            if row.verdict == super::super::NoteVerdict::Reject {
                self.docs.remove(&(row.note, row.fork));
            }
        }
        for (note, remote_head) in carried.heads {
            let chosen = match self.heads.get(&note).copied() {
                None => remote_head,
                Some(local) if local == remote_head || reaches(self, note, remote_head, local) => {
                    local
                }
                Some(local) if reaches(self, note, local, remote_head) => remote_head,
                Some(_) => return Err(invalid("concurrent NOTE head moves require review")),
            };
            self.heads.insert(note, chosen);
            if let Some(raw) = self.cores.get_mut(&note) {
                let header = raw[..crate::batch::ENTITY_METADATA_HEADER_LEN].to_vec();
                let mut body = super::super::decode_note_body_using(
                    &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
                    super::super::NoteKind::wire,
                )?;
                body.document_head = Some(chosen);
                body.markdown.clear();
                *raw = [header, super::super::encode_note_body(&body)?].concat();
            }
        }
        for (key, bundle) in carried.bundles {
            self.bundles.entry(key).or_insert(bundle);
        }
        // Rebuild mutable membership from the merged fork and receipt records.
        // The free-text explainer is immutable except for local privacy scrubs.
        for bundle in self.bundles.values_mut() {
            bundle.waiting = self
                .forks
                .values()
                .filter(|fork| fork.proposal == Some(bundle.id) && !fork.decided)
                .cloned()
                .collect();
            bundle.landed = self
                .receipts
                .values()
                .filter(|receipt| {
                    self.forks
                        .get(&receipt.fork)
                        .is_some_and(|fork| fork.proposal == Some(bundle.id))
                })
                .cloned()
                .collect();
        }
        Ok(())
    }
}
