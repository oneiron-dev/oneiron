//! Who reads or witnesses what: a record's audience, the disclosure clamp a
//! conversation runs under and the tier it holds a record to, who may speak
//! in a leader chat, and which projects the read fold lets anyone see.
use super::{Decision, held, held_by_both};
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::conversation::{AudienceCache, room_for_record_in};
use crate::counterparty_contact::read_counterparty_contact_in_txn;
use crate::disclosure::{DisclosureContext, DisclosureMode};
use crate::edge::EdgeKind;
use crate::federation::Scope;
use crate::interlocutor::{
    Interlocutor, InterlocutorPartyInput, InterlocutorResolutionInput, InterlocutorSet,
};
use crate::ports::EntityStoreRead;
use crate::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_COUNTERPARTY_CONTACT,
    ENTITY_TYPE_RELATIONSHIP,
};
use crate::side_table::RawValue;
use crate::voice_identity::VoiceSessionRosterV1;
use crate::workspace_roster::{LEADER_CHAT_FIELD, LeaderChat, ProjectReader};
use crate::{EntityId, Result, Vault};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

/// Who may read a record, as the audience check every scoped read conjoins
/// decides it (`AudienceCache::readable`): its room's membership windows or
/// the roster a project room takes its audience from, its relationship's
/// participants, and the same of every record it covers, through the room
/// its edges and subject lead to.
pub(super) struct RecordAudiences;

/// The audiences a record admits. An audience is admitted only when each of
/// its members alone is, so the members who are admitted alone are the
/// answer.
pub(super) enum Readers {
    /// Any audience, the empty one included: no room or relationship
    /// limits the record.
    Everyone,
    /// Only audiences of these.
    Only(BTreeSet<EntityId>),
}

impl Decision for RecordAudiences {
    type Subject = EntityId;
    type Answer = Readers;

    fn subjects(vaults: [&Vault; 2]) -> Result<BTreeSet<Self::Subject>> {
        live_in_both(vaults, 0..=u8::MAX)
    }

    fn answers(
        vault: &Vault,
        subjects: &BTreeSet<Self::Subject>,
    ) -> Result<Vec<Option<Self::Answer>>> {
        // The room readers open their own transactions, so they read first.
        let rooms: BTreeMap<EntityId, BTreeSet<EntityId>> = held(vault, ENTITY_TYPE_CONVERSATION)?
            .into_iter()
            .map(|room| (room, room_people(vault, room)))
            .collect();
        let relationships = held(vault, ENTITY_TYPE_RELATIONSHIP)?;
        let txn = vault.store.env.read_txn()?;
        let mut named: BTreeSet<EntityId> = rooms.values().flatten().copied().collect();
        for relationship in relationships {
            named.extend(participants(vault, &txn, relationship));
        }
        let mut cache = AudienceCache::default();
        let mut readers = |id: EntityId| -> Result<Readers> {
            if cache.readable(vault, &txn, id, &[])? {
                return Ok(Readers::Everyone);
            }
            // Anyone the vault does not name is admitted only where every
            // audience is, and a record in a room only where its room names
            // them.
            let candidates = match room_for_record_in(vault, &txn, id) {
                Ok(Some(room)) => rooms.get(&room).unwrap_or(&named),
                _ => &named,
            };
            let mut only = BTreeSet::new();
            for person in candidates {
                if cache.readable(vault, &txn, id, &[*person])? {
                    only.insert(*person);
                }
            }
            Ok(Readers::Only(only))
        };
        Ok(subjects.iter().map(|id| readers(*id).ok()).collect())
    }

    fn loosens(live: &Readers, restored: &Readers) -> bool {
        match (live, restored) {
            (Readers::Everyone, _) => false,
            (Readers::Only(_), Readers::Everyone) => true,
            (Readers::Only(live), Readers::Only(restored)) => !restored.is_subset(live),
        }
    }

    fn refusal() -> Option<Readers> {
        Some(Readers::Only(BTreeSet::new()))
    }
}

/// Everyone `vault`'s rows can admit to `room`'s records: its ledger's
/// members past and present, and the roster a project room takes its
/// audience from. Where neither reads, the audience check fails on the room
/// as well, for everyone.
fn room_people(vault: &Vault, room: EntityId) -> BTreeSet<EntityId> {
    let mut people: BTreeSet<EntityId> = vault
        .membership_ledger(room)
        .map(|rows| rows.into_iter().map(|row| row.person).collect())
        .unwrap_or_default();
    people.extend(vault.room_audience_members(room).unwrap_or_default());
    people
}

/// A relationship's participants as the audience check reads them: those
/// whose `participates_in` edges reach it, and those its body lists. One
/// whose participants do not read fails the check for every audience.
fn participants(vault: &Vault, txn: &heed::RoTxn<'_>, relationship: EntityId) -> Vec<EntityId> {
    let mut people = crate::conversation_dag::edge_ids(
        &vault.store,
        txn,
        &relationship,
        EdgeKind::ParticipatesIn,
        true,
        crate::limits::MAX_ANCESTOR_DEPTH,
    )
    .unwrap_or_default();
    if let Ok(Some(raw)) = vault.store.port_entity_raw(txn, &relationship)
        && let Some(body) = raw.get(ENTITY_METADATA_HEADER_LEN..)
        && let Ok(value) = rmp_serde::from_slice::<serde_json::Value>(body)
        && let Some(ids) = value.get("participant_ids")
        && let Ok(ids) = serde_json::from_value::<Vec<EntityId>>(ids.clone())
    {
        people.extend(ids);
    }
    people
}

/// How a context assembly clamps what it discloses to the parties present
/// (`Vault::resolve_interlocutors`, then `DisclosureContext::resolve`): the
/// owner alone, supervised, or clamped to the met clearance of every
/// non-owner, as a sender on a channel identity resolves to a contact or
/// none, and as a voice session's roster resolves its speakers, with the
/// owner's session present or not.
pub(super) struct DisclosureClamps;

/// Who is present to a conversation, as a host names them.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Party {
    /// A sender on a channel identity.
    Channel(EntityId, String),
    /// The speakers a voice session's roster resolves.
    Voice(String),
}

/// The clamp an assembly runs under.
pub(super) struct Clamp {
    mode: DisclosureMode,
    /// The met clearance a scoped admission checks records against.
    scope: Option<Scope>,
}

impl Decision for DisclosureClamps {
    type Subject = (Party, bool);
    type Answer = Clamp;

    fn subjects(vaults: [&Vault; 2]) -> Result<BTreeSet<Self::Subject>> {
        let mut parties = BTreeSet::new();
        for vault in vaults {
            let txn = vault.store.env.read_txn()?;
            let store = &vault.store;
            for id in store.port_entity_ids_by_type(&txn, ENTITY_TYPE_COUNTERPARTY_CONTACT, None)? {
                // A contact that does not decode names no sender.
                if let Ok(Some(contact)) = read_counterparty_contact_in_txn(store, &txn, &id?) {
                    parties.insert(Party::Channel(contact.identity_ref, contact.counterparty));
                }
            }
        }
        // A roster is one row: one only one vault holds is content.
        let [live, restored] = vaults.map(rosters);
        let restored = restored?;
        for (key, session) in live? {
            if let Some(other) = restored.get(&key)
                && let Some(session) = session.or_else(|| other.clone())
            {
                parties.insert(Party::Voice(session));
            }
        }
        Ok(parties
            .into_iter()
            .flat_map(|party| [(party.clone(), false), (party, true)])
            .collect())
    }

    fn answers(
        vault: &Vault,
        subjects: &BTreeSet<Self::Subject>,
    ) -> Result<Vec<Option<Self::Answer>>> {
        Ok(subjects
            .iter()
            .map(|(party, owner_session)| {
                let (parties, voice_session_ref) = match party {
                    Party::Channel(identity_ref, counterparty) => (
                        vec![InterlocutorPartyInput::ChannelCounterparty {
                            identity_ref: *identity_ref,
                            counterparty: counterparty.clone(),
                        }],
                        None,
                    ),
                    Party::Voice(session) => (Vec::new(), Some(session.clone())),
                };
                let set = vault
                    .resolve_interlocutors(&InterlocutorResolutionInput {
                        owner_session: *owner_session,
                        parties,
                        voice_session_ref,
                    })
                    .ok()?;
                let context = DisclosureContext::resolve(vault, set).ok()?;
                Some(Clamp {
                    mode: context.mode(),
                    scope: context.scope().cloned(),
                })
            })
            .collect())
    }

    fn loosens(live: &Clamp, restored: &Clamp) -> bool {
        // Each mode admits all a narrower one does: the owner alone sees
        // everything, a supervised assembly every record below tier A, and
        // one the owner is absent from what the met clearance admits.
        let reach = |mode: DisclosureMode| match mode {
            DisclosureMode::OwnerAlone => 2,
            DisclosureMode::Supervised => 1,
            DisclosureMode::AbsenceClamp => 0,
        };
        match reach(restored.mode).cmp(&reach(live.mode)) {
            Ordering::Greater => true,
            Ordering::Less => false,
            // Where a clearance is checked, none admits nothing.
            Ordering::Equal => match (&live.scope, &restored.scope) {
                (None, Some(_)) => true,
                (Some(live), Some(restored)) => !restored.is_narrowing_of(live),
                _ => false,
            },
        }
    }
}

/// Every voice session roster `vault` holds, by its key, with the session it
/// records where it decodes.
fn rosters(vault: &Vault) -> Result<BTreeMap<Vec<u8>, Option<String>>> {
    let txn = vault.store.env.read_txn()?;
    let mut rosters = BTreeMap::new();
    for row in vault
        .store
        .vault_meta
        .prefix_iter(&txn, crate::side_table::VOICE_IDENTITY_ROSTER.prefix)?
    {
        let (key, bytes) = row?;
        rosters.insert(
            key.to_vec(),
            VoiceSessionRosterV1::from_raw(&bytes)
                .ok()
                .map(|roster| roster.voice_session_ref),
        );
    }
    Ok(rosters)
}

/// Whether a claim reaches a party the owner supervises
/// (`DisclosureContext::admits` under a supervised presence): a signed
/// history control never does, nor one the tier rules hold to tier A by its
/// sensitivity band or predicate. The rest of what the clamp reads of a
/// record does not move under one id: its kind and its birth scope stay, and
/// its tier-A mark is a refused family.
pub(super) struct DisclosureTiers;

impl Decision for DisclosureTiers {
    type Subject = EntityId;
    type Answer = bool;

    fn subjects(vaults: [&Vault; 2]) -> Result<BTreeSet<Self::Subject>> {
        live_in_both(vaults, [ENTITY_TYPE_CLAIM])
    }

    fn answers(
        vault: &Vault,
        subjects: &BTreeSet<Self::Subject>,
    ) -> Result<Vec<Option<Self::Answer>>> {
        let supervised = DisclosureContext::resolve(
            vault,
            InterlocutorSet::with_session_owner(vec![Interlocutor::unknown(String::new(), false)]),
        )?;
        let txn = vault.store.env.read_txn()?;
        Ok(subjects
            .iter()
            .map(|id| {
                supervised
                    .admits(&vault.store, &txn, id, ENTITY_TYPE_CLAIM, None)
                    .ok()
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

/// Whether a leader may speak in a leader chat: opening one between two
/// projects' leaders (`leader_chat_allowed`, the checks
/// `Vault::open_leader_chat` runs), and each turn a bound leader adds to one
/// (`admit_leader_chat_turn`). Both read the projects' leaders as the read
/// fold accepts them, the person each leader speaks as, and every rule
/// against it the shared ancestors' `claim_of` edges reach.
pub(super) struct LeaderChats;

/// Speech in a leader chat.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Speech {
    /// Opening a chat between the leaders of two projects.
    Open([EntityId; 2]),
    /// A turn by a leader in a room bound as a leader chat.
    Turn(EntityId, EntityId),
}

impl Decision for LeaderChats {
    type Subject = Speech;
    /// The project a turn speaks for; none for an opening, or for a room
    /// that binds no chat.
    type Answer = Option<EntityId>;

    fn subjects(vaults: [&Vault; 2]) -> Result<BTreeSet<Self::Subject>> {
        let mut subjects = BTreeSet::new();
        if let Ok(kind) = vaults[0].project_type_byte() {
            let projects: Vec<EntityId> = live_in_both(vaults, [kind])?.into_iter().collect();
            for (index, first) in projects.iter().enumerate() {
                for second in &projects[index + 1..] {
                    subjects.insert(Speech::Open([*first, *second]));
                }
            }
        }
        let rooms = live_in_both(vaults, [ENTITY_TYPE_CONVERSATION])?;
        for vault in vaults {
            let txn = vault.store.env.read_txn()?;
            for room in &rooms {
                if let Some(chat) = bound_chat(vault, &txn, *room) {
                    for actor in chat.actors {
                        subjects.insert(Speech::Turn(*room, actor));
                    }
                }
            }
        }
        Ok(subjects)
    }

    fn answers(
        vault: &Vault,
        subjects: &BTreeSet<Self::Subject>,
    ) -> Result<Vec<Option<Self::Answer>>> {
        let txn = vault.store.env.read_txn()?;
        Ok(subjects
            .iter()
            .map(|subject| match subject {
                Speech::Open(projects) => {
                    crate::workspace_roster::leader_chat_allowed(vault, &txn, *projects)
                        .ok()
                        .map(|()| None)
                }
                Speech::Turn(room, actor) => crate::workspace_roster::admit_leader_chat_turn(
                    vault, &txn, *room, *actor, false,
                )
                .ok(),
            })
            .collect())
    }

    /// A turn bound to another project. An opening the live vault refuses
    /// fails its read, so any restored opening loosens it.
    fn loosens(live: &Self::Answer, restored: &Self::Answer) -> bool {
        restored.is_some() && live != restored
    }
}

/// The leader chat `room`'s body binds, where it binds one.
fn bound_chat(vault: &Vault, txn: &heed::RoTxn<'_>, room: EntityId) -> Option<LeaderChat> {
    let body = crate::conversation::body_in(vault, txn, room).ok()?;
    let bytes = rmp_serde::to_vec_named(body.extra.get(LEADER_CHAT_FIELD)?).ok()?;
    rmp_serde::from_slice(&bytes).ok()
}

/// Whether ordinary readers see a project, as the read fold judges each
/// stored row (`ProjectReader::visible`): its proof and the anchors it
/// builds on, whether replay laid an unsigned row over a signed one, and
/// the same of every parent.
pub(super) struct ProjectVerdicts;

impl Decision for ProjectVerdicts {
    type Subject = EntityId;
    type Answer = bool;

    fn subjects(vaults: [&Vault; 2]) -> Result<BTreeSet<Self::Subject>> {
        match vaults[0].project_type_byte() {
            Ok(kind) => live_in_both(vaults, [kind]),
            Err(_) => Ok(BTreeSet::new()),
        }
    }

    fn answers(
        vault: &Vault,
        subjects: &BTreeSet<Self::Subject>,
    ) -> Result<Vec<Option<Self::Answer>>> {
        let txn = vault.store.env.read_txn()?;
        let Some(reader) = ProjectReader::new(&vault.store, &txn, vault.privacy_posture())? else {
            return Ok(vec![Some(false); subjects.len()]);
        };
        Ok(subjects
            .iter()
            .map(|id| reader.visible(*id).ok().map(|project| project.is_some()))
            .collect())
    }

    fn loosens(live: &bool, restored: &bool) -> bool {
        !live && *restored
    }

    fn refusal() -> Option<bool> {
        Some(false)
    }
}

/// Every entity of `kinds` both vaults hold live: deleted, stale or archived
/// in neither. A decision about one entity is asked only of these; one that
/// either vault deleted or archived is content the restore returns or drops
/// (RD-20).
fn live_in_both(
    vaults: [&Vault; 2],
    kinds: impl IntoIterator<Item = u8>,
) -> Result<BTreeSet<EntityId>> {
    let mut ids = BTreeSet::new();
    for kind in kinds {
        ids.extend(held_by_both(vaults, kind)?);
    }
    for vault in vaults {
        let txn = vault.store.env.read_txn()?;
        let mut live = BTreeSet::new();
        for id in ids {
            if crate::vault::live_entity_row_in_txn(&vault.store, &txn, &id)?.is_live()
                && vault.archive_tombstone_in_txn(&txn, &id)?.is_none()
            {
                live.insert(id);
            }
        }
        ids = live;
    }
    Ok(ids)
}
