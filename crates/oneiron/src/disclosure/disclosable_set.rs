//! The ILDF2 room rule (ONE-1592, ratified 2026-09-23):
//! `disclosable_set = public ∪ (∩ clearances of all non-owner present)`.
//! A clearance is the contact's Scope, so ∩ is the meet of Scopes. The meet
//! itself is `room_scope` (R17: one function, one implementation).

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{ErrorKind, Result};
use crate::interlocutor::{InterlocutorClass, InterlocutorSet};
use crate::office_body::{RESERVE_STEP, document_resources, machine_memory_refused};
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead};
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::scan_check::{EngineScan, ScanCount};
use crate::scope_summary::WordSources;
use oneiron_authority::federation::{Scope, Sensitivity, SensitivityCeiling};
use oneiron_docedit::resource::{Hold, bytes_of};
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
        Self::resolve_with_once_in(vault, &txn, roster, reader, once)
    }

    /// [`Self::resolve_with_once`] read in the caller's snapshot `txn`
    /// (fix list row 17645): the same fold, opening no snapshot of its own,
    /// for a caller that judges other rows in that one read.
    pub(crate) fn resolve_with_once_in(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        roster: &InterlocutorSet,
        reader: bool,
        once: &BTreeMap<EntityId, Scope>,
    ) -> Result<Self> {
        let mut terms = roster
            .entries()
            .iter()
            .map(|party| match (party.class(), party.contact_ref()) {
                (InterlocutorClass::Owner, _) => Ok(None),
                (_, Some(hex)) => {
                    let contact = EntityId::from_hex(hex)?;
                    match once.get(&contact) {
                        Some(scope) => Ok(Some(scope.clone())),
                        None => contact_clearance_in(vault, txn, contact).map(Some),
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

    /// Explicit consent of an anonymous phone call's current line. Only the
    /// native phone reader supplies this; it is not a contact clearance.
    pub(super) fn phone_line(scope: Scope) -> Self {
        Self(scope)
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
/// does a closure that cycles.
///
/// Every record of the closure is judged, however many (rule 5; FIX 9787):
/// past its threshold row the walk asks whether everything is okay, counted
/// on every way out, a deny and an error included, and walks on. No count
/// withholds a record. Only the machine's memory floor stops the walk, or
/// the host's wait for that memory running out: either is an error the read
/// surfaces (a memory-floor refusal, or a timed-out read a caller may run
/// again), never a withheld record and never a partly judged one.
pub(crate) fn discloses_raw(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    scope: &Scope,
    id: EntityId,
    raw: &[u8],
) -> Result<bool> {
    let mut count = ScanCount::start(
        &vault.store,
        txn,
        EngineScan::WordSourceRecords,
        id.as_bytes(),
    )?;
    let mut closure = WordClosure {
        vault,
        txn,
        scope,
        path: BTreeSet::new(),
        judged: BTreeSet::new(),
        memory: WalkMemory::default(),
    };
    let disclosed = closure.discloses(id, raw);
    count.rows(closure.judged.len());
    count.defer(&vault.store);
    disclosed
}

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

/// One record on the walk's stack: the records its words may have come
/// from, the next one to judge, and the bytes the walk took for it.
struct Frame {
    id: EntityId,
    sources: Vec<WordSource>,
    cursor: usize,
    bytes: u64,
}

/// The machine memory one walk holds (FIX 9787). A walk that fits in one
/// reservation step, the least any reservation asks the host's memory line
/// for, asks the line nothing. Past it the walk reserves every byte it
/// holds, at its peak, before it holds it: a reservation that cannot be met
/// at once waits its fair turn for the host's queue wait, and only the
/// machine's floor or that wait running out refuses it.
#[derive(Default)]
struct WalkMemory {
    /// Bytes the walk's sets and stack hold now.
    held: u64,
    /// The most the walk has held at once, once past one step: what its
    /// hold has taken.
    taken: u64,
    /// The walk's hold on the host's memory line, opened when it first
    /// outgrows one step.
    hold: Option<Hold>,
}

impl WalkMemory {
    /// Takes `bytes` more the walk is about to hold.
    fn grow(&mut self, bytes: u64) -> Result<()> {
        self.held = self.held.saturating_add(bytes);
        if self.held <= self.taken.max(RESERVE_STEP) {
            return Ok(());
        }
        self.hold
            .get_or_insert_with(|| document_resources().hold())
            .take(self.held - self.taken)
            .map_err(machine_memory_refused)?;
        self.taken = self.held;
        Ok(())
    }

    /// Gives back `bytes` the walk no longer holds. Its hold keeps the
    /// peak until the walk ends, so growth back up to it asks nothing.
    fn release(&mut self, bytes: u64) {
        self.held = self.held.saturating_sub(bytes);
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
    /// The memory the sets and the stack hold.
    memory: WalkMemory,
}

impl WordClosure<'_> {
    /// Walks the closure depth first on a heap stack, never the call stack,
    /// reading one source row at a time: however deep or wide the closure,
    /// the walk judges all of it and never overflows.
    fn discloses(&mut self, id: EntityId, raw: &[u8]) -> Result<bool> {
        let Some(frame) = self.enter(id, raw)? else {
            return Ok(false);
        };
        let mut stack = vec![frame];
        while let Some(frame) = stack.last_mut() {
            let Some(&source) = frame.sources.get(frame.cursor) else {
                if let Some(frame) = stack.pop() {
                    self.path.remove(&frame.id);
                    self.memory.release(frame.bytes);
                }
                continue;
            };
            frame.cursor += 1;
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
            stack.push(gathered);
        }
        Ok(true)
    }

    /// Judges `id`'s own stamp and gathers each record its words may have
    /// come from, putting `id` on the path. `None` when `id` is not
    /// disclosed: its stamp, or a summary that no longer resolves. The
    /// memory the walk takes for `id` is reserved before it is held.
    fn enter(&mut self, id: EntityId, raw: &[u8]) -> Result<Option<Frame>> {
        self.memory.grow(bytes_of::<EntityId>(1))?;
        self.judged.insert(id);
        let store = &self.vault.store;
        // A NOTE sits at one world it is in that the clearance holds
        // (FIX-LIST 9433).
        let held = [&self.scope.worlds];
        if !crate::federation::record_scope::note_world::blob_scope_held_at(
            store, self.txn, id, raw, &held,
        )?
        .is_some_and(|record| admits(self.scope, &record))
        {
            return Ok(None);
        }
        if let Some(header) = EntityMetadataHeader::parse(raw)
            && !super::retained_copy_admits(
                store,
                self.txn,
                &id,
                header.entity_type,
                None,
                &raw[ENTITY_METADATA_HEADER_LEN..],
            )?
        {
            return Ok(None);
        }
        // The frame and its place on the path, then its sources.
        let place = bytes_of::<Frame>(1).saturating_add(bytes_of::<EntityId>(1));
        let mut bytes = place;
        let mut sources =
            match crate::scope_summary::word_sources_in(self.vault, self.txn, &id, raw)? {
                WordSources::Own => Vec::new(),
                WordSources::From(ids) => {
                    let more = bytes_of::<WordSource>(ids.len());
                    self.memory.grow(more)?;
                    bytes = bytes.saturating_add(more);
                    ids.into_iter().map(WordSource::Word).collect()
                }
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
                let part = part?.target;
                if sources.len() == sources.capacity() {
                    let room = sources.capacity().max(1);
                    let more = bytes_of::<WordSource>(room);
                    self.memory.grow(more)?;
                    bytes = bytes.saturating_add(more);
                    sources.reserve_exact(room);
                }
                sources.push(WordSource::Part(part));
            }
        }
        self.memory.grow(place)?;
        self.path.insert(id);
        Ok(Some(Frame {
            id,
            sources,
            cursor: 0,
            bytes,
        }))
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
