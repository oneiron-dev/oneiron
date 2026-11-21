//! The private note reads a reader's key admits and the diary links graph
//! reads show.

use super::*;

/// Whether a reader's key may read a NOTE (`ScopedRead::note_readable_in`):
/// a kind every reader may read, its author's own, or a diary the reader
/// reaches through a `SameAs` link to its own diary that both authors
/// granted, at a position the reader's grants admit.
pub(in crate::recovery::checkpoint::decisions) struct NoteReads;

impl Decision for NoteReads {
    type Subject = (EntityId, Reader);
    type Answer = bool;

    fn subjects(vaults: [&Vault; 2]) -> Result<BTreeSet<Self::Subject>> {
        let notes = kept(vaults, &[ENTITY_TYPE_NOTE])?;
        // Only a diary's author reads it through a link, so the authors are
        // every reader a link can admit. One only one vault holds returns or
        // leaves with the restore.
        let mut authors = BTreeSet::new();
        for vault in vaults {
            let txn = vault.store.env.read_txn()?;
            for id in vault
                .store
                .port_entity_ids_by_type(&txn, ENTITY_TYPE_NOTE, None)?
            {
                if let Some(raw) = vault.store.port_entity_raw(&txn, &id?)?
                    && let Some(body) = raw.get(ENTITY_METADATA_HEADER_LEN..)
                    && let Ok(note) = crate::note::decode_note_core_using(body, NoteKind::wire)
                    && let Some(author) = note.author_ref.id()
                {
                    // An erased author is no reader: only live ones are kept.
                    authors.insert(author);
                }
            }
        }
        let classes = [
            EdgeActorClass::Human,
            EdgeActorClass::Agent,
            EdgeActorClass::System,
        ]
        .map(|class| class.gate_actor_class().to_owned());
        let actors: BTreeSet<String> = undeleted(vaults, authors)?
            .iter()
            .map(EntityId::to_hex)
            .collect();
        // No author: what a note's kind lets every reader read.
        let mut readers = vec![Reader::Asserted(stranger(&actors), None)];
        for actor in &actors {
            readers.extend(
                classes
                    .iter()
                    .map(|class| Reader::Asserted(actor.clone(), Some(class.clone()))),
            );
        }
        readers.extend(owners(vaults)?.into_iter().map(Reader::Owner));
        Ok(notes
            .iter()
            .flat_map(|note| readers.iter().map(move |reader| (*note, reader.clone())))
            .collect())
    }

    fn answers(
        vault: &Vault,
        subjects: &BTreeSet<Self::Subject>,
    ) -> Result<Vec<Option<Self::Answer>>> {
        let Ok(policy) = vault.store.policy_as_next_opened() else {
            return Ok(vec![None; subjects.len()]);
        };
        let txn = vault.store.env.read_txn()?;
        let mut note: Option<(EntityId, Option<Vec<u8>>)> = None;
        let mut answers = Vec::with_capacity(subjects.len());
        for (id, reader) in subjects {
            if note.as_ref().is_none_or(|(held, _)| held != id) {
                note = Some((*id, vault.store.port_entity_raw(&txn, id).ok().flatten()));
            }
            answers.push(
                note.as_ref()
                    .and_then(|(_, raw)| raw.as_deref()?.get(ENTITY_METADATA_HEADER_LEN..))
                    .and_then(|body| {
                        vault
                            .scoped_read(reader.key()?)
                            .note_readable_in(&txn, id, body, &policy)
                            .ok()
                    }),
            );
        }
        Ok(answers)
    }

    fn loosens(live: &bool, restored: &bool) -> bool {
        !live && *restored
    }

    fn refusal() -> Option<bool> {
        Some(false)
    }
}

/// Whether a graph read shows a `SameAs` link between two diary notes
/// (`note::diary_edge_access_in`, which the scoped graph door asks of each
/// link it returns): the link stored, and both authors' grants on that very
/// pair. A note readable through another shared link does not show this
/// one.
pub(in crate::recovery::checkpoint::decisions) struct DiaryLinks;

impl Decision for DiaryLinks {
    type Subject = (EntityId, EntityId);
    type Answer = bool;

    /// Every pair of notes both vaults keep that a `SameAs` link joins in
    /// either; a pair joined in neither shows in neither.
    fn subjects(vaults: [&Vault; 2]) -> Result<BTreeSet<Self::Subject>> {
        let notes = kept(vaults, &[ENTITY_TYPE_NOTE])?;
        let mut pairs = BTreeSet::new();
        for vault in vaults {
            let txn = vault.store.env.read_txn()?;
            for note in &notes {
                for direction in [EdgeDirection::Out, EdgeDirection::In] {
                    for edge in vault.store.port_edges(
                        &txn,
                        note,
                        direction,
                        Some(EdgeKind::SameAs),
                        None,
                    )? {
                        let other = edge?.target;
                        if notes.contains(&other) {
                            pairs.insert((*note.min(&other), *note.max(&other)));
                        }
                    }
                }
            }
        }
        Ok(pairs)
    }

    fn answers(
        vault: &Vault,
        subjects: &BTreeSet<Self::Subject>,
    ) -> Result<Vec<Option<Self::Answer>>> {
        let txn = vault.store.env.read_txn()?;
        Ok(subjects
            .iter()
            .map(|(left, right)| {
                crate::note::diary_edge_access_in(vault, &txn, *left, EdgeKind::SameAs, *right).ok()
            })
            .collect())
    }

    fn loosens(live: &bool, restored: &bool) -> bool {
        !live && *restored
    }

    fn refusal() -> Option<bool> {
        Some(false)
    }
}
