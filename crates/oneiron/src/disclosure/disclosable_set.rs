//! The ILDF2 room rule (ONE-1592, ratified 2026-09-23):
//! `disclosable_set = public ∪ (∩ clearances of all non-owner present)`.
//! A clearance is the contact's Scope, so ∩ is the meet of Scopes. The meet
//! itself is `room_scope` (R17: one function, one implementation).

use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{ErrorKind, Result};
use crate::federation::{Scope, Sensitivity, SensitivityCeiling};
use crate::interlocutor::{InterlocutorClass, InterlocutorSet};
use crate::limits::MAX_ANCESTOR_DEPTH;
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead};
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::scope_summary::WordSources;
use std::collections::{BTreeMap, BTreeSet};

pub use crate::context_board::room_scope as disclosable_set;

/// What one audience may be shown. The clearance half is a Scope; the
/// public half is a property of the record (P7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisclosableSet(Scope);

impl DisclosableSet {
    /// An unknown party's set: the empty clearance, so public-only.
    #[must_use]
    pub fn unknown_reader() -> Self {
        Self(Scope::default())
    }

    /// The set for `roster`. The owner's entry contributes no clearance
    /// term, so with no non-owner present the fold is the top of the Scope
    /// lattice (P1), never bottom. An unknown party, a missing or revoked
    /// clearance, or a row that does not decode contributes bottom, so that
    /// party narrows the set to public-only. An empty roster names no one
    /// and is public-only too. `reader` adds a proven reader of the
    /// assembly, the owner or one of the vault's own agents, as one more
    /// party with no term. Only storage I/O errors surface.
    pub fn resolve(vault: &Vault, roster: &InterlocutorSet, reader: bool) -> Result<Self> {
        Self::resolve_with_once(vault, roster, reader, &BTreeMap::new())
    }

    /// [`Self::resolve`] under the owner's `once` answers this assembly
    /// spent (OF-365): a contact in `once` contributes that answer's Scope in
    /// place of its clearance, as a standing answer would replace it. It
    /// still meets every other party's term, so a once answer for one
    /// contact never reaches anyone else present.
    pub fn resolve_with_once(
        vault: &Vault,
        roster: &InterlocutorSet,
        reader: bool,
        once: &BTreeMap<EntityId, Scope>,
    ) -> Result<Self> {
        let txn = vault.store.env.read_txn()?;
        let mut terms = roster
            .entries()
            .iter()
            .map(|party| match (party.class(), party.contact_ref()) {
                (InterlocutorClass::Owner, _) => Ok(None),
                (_, Some(hex)) => {
                    let contact = EntityId::from_hex(hex)?;
                    match once.get(&contact) {
                        Some(scope) => Ok(Some(scope.clone())),
                        None => contact_clearance_in(vault, &txn, contact).map(Some),
                    }
                }
                (_, None) => Ok(Some(Scope::default())),
            })
            .collect::<Result<Vec<_>>>()?;
        if reader {
            terms.push(None);
        }
        Ok(Self(disclosable_set(&terms)?))
    }

    /// The met clearance of every non-owner present.
    #[must_use]
    pub fn clearance(&self) -> &Scope {
        &self.0
    }

    /// P7: a record is disclosed iff it is positively public, or its Scope
    /// sits at or under the met clearance. Relevance never bypasses this,
    /// and a missing sensitivity stamp is never public.
    #[must_use]
    pub fn admits(&self, record: &Scope) -> bool {
        admits(&self.0, record)
    }
}

fn admits(clearance: &Scope, record: &Scope) -> bool {
    record.sensitivity == SensitivityCeiling::AtMost(Sensitivity::Public)
        || clearance.admits("read", record, &Scope::top())
}

/// P7 for the stored revision `raw` of `id` under a [`disclosable_set`]
/// Scope: [`DisclosableSet::admits`] over the revision's own stamp. A
/// revision with no stamp is never public. A revision's words may be other
/// records', so it is disclosed only with each of them: a TURN's text and
/// vector are its messages' (`embed::turn_text_in_txn`), so each live
/// message `PartOf` it, and a scope summary, a TURN copying one, or a merge
/// header naming one carries the words of every record and MESSAGE the
/// summary came from. Sources that no longer resolve disclose nothing, nor
/// does a closure that cycles or outgrows [`MAX_WORD_CLOSURE`].
pub(crate) fn discloses_raw(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    scope: &Scope,
    id: EntityId,
    raw: &[u8],
) -> Result<bool> {
    WordClosure {
        vault,
        txn,
        scope,
        path: BTreeSet::new(),
        judged: BTreeSet::new(),
        held: 0,
    }
    .discloses(id, raw)
}

/// How many records one P7 decision may follow, and how many source slots
/// its stack may hold at once: room for a summary's whole covers list and
/// its messages, each bounded by `MAX_ANCESTOR_DEPTH`.
const MAX_WORD_CLOSURE: usize = 4 * MAX_ANCESTOR_DEPTH;

/// One record a revision's words may have come from, and how its row reads.
#[derive(Clone, Copy)]
enum WordSource {
    /// A word source: one that no longer resolves discloses nothing.
    Word(EntityId),
    /// A record `PartOf` a TURN: only a live, nonempty MESSAGE carries
    /// words.
    Part(EntityId),
}

impl WordSource {
    fn id(self) -> EntityId {
        match self {
            Self::Word(id) | Self::Part(id) => id,
        }
    }
}

/// One P7 decision's walk over the records whose words a revision carries.
struct WordClosure<'a> {
    vault: &'a Vault,
    txn: &'a heed::RoTxn<'a>,
    scope: &'a Scope,
    /// The records on the way to the current one: meeting one again is a
    /// cycle.
    path: BTreeSet<EntityId>,
    /// Every record entered so far; each passed or is on the path, or the
    /// walk has stopped.
    judged: BTreeSet<EntityId>,
    /// Source slots the frames on the stack hold, visited or not, until
    /// each frame is dropped.
    held: usize,
}

impl WordClosure<'_> {
    /// Walks the closure depth first on a heap stack, never the call stack,
    /// reading one source row at a time: a closure as deep or as wide as
    /// its budget must deny, not overflow.
    fn discloses(&mut self, id: EntityId, raw: &[u8]) -> Result<bool> {
        let Some(sources) = self.enter(id, raw)? else {
            return Ok(false);
        };
        let mut stack = vec![(id, sources, 0)];
        while let Some((_, sources, cursor)) = stack.last_mut() {
            let Some(&source) = sources.get(*cursor) else {
                if let Some((node, sources, _)) = stack.pop() {
                    self.path.remove(&node);
                    self.held -= sources.capacity();
                }
                continue;
            };
            *cursor += 1;
            let id = source.id();
            if self.judged.contains(&id) && !self.path.contains(&id) {
                continue;
            }
            let raw = match (source, self.vault.store.port_entity_record(self.txn, &id)?) {
                (WordSource::Word(_), None) => return Ok(false),
                (WordSource::Part(_), None) => continue,
                (WordSource::Part(_), Some(row))
                    if row.entity_type != ENTITY_TYPE_MESSAGE || row.body.is_empty() =>
                {
                    continue;
                }
                (_, Some(row)) => row.encode(),
            };
            if self.path.contains(&id) {
                return Ok(false);
            }
            let Some(gathered) = self.enter(id, &raw)? else {
                return Ok(false);
            };
            stack.push((id, gathered, 0));
        }
        Ok(true)
    }

    /// Judges `id`'s own stamp and gathers each record its words may have
    /// come from, putting `id` on the path. `None` when `id` is not
    /// disclosed: its stamp, a summary that no longer resolves, or the
    /// budget.
    fn enter(&mut self, id: EntityId, raw: &[u8]) -> Result<Option<Vec<WordSource>>> {
        self.judged.insert(id);
        if self.judged.len() > MAX_WORD_CLOSURE {
            return Ok(None);
        }
        let store = &self.vault.store;
        if !crate::federation::record_scope::scope_for_blob(store, self.txn, id, raw)?
            .is_some_and(|record| admits(self.scope, &record))
        {
            return Ok(None);
        }
        let mut sources =
            match crate::scope_summary::word_sources_in(self.vault, self.txn, &id, raw)? {
                WordSources::Own => Vec::new(),
                WordSources::From(ids) => ids.into_iter().map(WordSource::Word).collect(),
                WordSources::Unresolved => return Ok(None),
            };
        if EntityMetadataHeader::parse(raw)
            .is_some_and(|header| header.entity_type == ENTITY_TYPE_TURN)
        {
            for part in store.port_edges(
                self.txn,
                &id,
                EdgeDirection::In,
                Some(EdgeKind::PartOf),
                None,
            )? {
                if self.held + sources.len() >= MAX_WORD_CLOSURE {
                    return Ok(None);
                }
                sources.push(WordSource::Part(part?.target));
            }
        }
        if self.held + sources.capacity() > MAX_WORD_CLOSURE {
            return Ok(None);
        }
        self.held += sources.capacity();
        self.path.insert(id);
        Ok(Some(sources))
    }
}

/// `contact`'s clearance as `txn` reads it: bottom when the contact has
/// none, or its row does not decode. Only storage I/O errors surface.
pub(crate) fn contact_clearance_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    contact: EntityId,
) -> Result<Scope> {
    match super::vault_context::DISCLOSURE_SCOPES.get(&vault.store, txn, &contact) {
        Ok(Some(clearance)) => Ok(clearance.effective_scope()),
        Ok(None) => Ok(Scope::default()),
        Err(error) if error.kind() == ErrorKind::InvalidDisclosureScope => Ok(Scope::default()),
        Err(error) => Err(error),
    }
}
