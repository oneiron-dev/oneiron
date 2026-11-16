//! What a drafting model may read for one transcript SESSION, for one model
//! destination: the SESSION's TURNs, which of their speakers is the owner,
//! and the PERSONs a follow-up may go to.

use std::collections::BTreeSet;
use std::fmt;

use rmpv::Value;

use super::{
    MEETING_FOLLOW_UP_MAX_RECIPIENTS, MEETING_FOLLOW_UP_MAX_TRANSCRIPT_BYTES,
    MeetingFollowUpDraftPayload,
};
use crate::Vault;
use crate::claim::{ScopedRead, ScopedReadActorKey, ScopedReadReceipt};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ingest::{FILE_DROP_TRANSCRIPT_SOURCE_ID, MEETING_TRANSCRIPT_SOURCE_ID};
use crate::ports::EntityStoreRead;
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN};
use crate::settings::{ReadDestination, ReleaseHold};

/// A name shorter than this, in characters, never matches: it would match
/// inside ordinary words' neighbours too often to name anyone.
const MIN_NAME_CHARS: usize = 2;
/// A multi-word name also matches by its first word when that word is at
/// least this long ("Yuki" for "Yuki Tanaka"). A first word written wholly
/// in a script without spaces between words needs only [`MIN_NAME_CHARS`]
/// ("田中" for "田中 優希").
const MIN_FIRST_WORD_CHARS: usize = 3;

/// One TURN as the model reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeetingFollowUpTurn {
    /// The call-local label the reply cites it by: `T1`, `T2`, ...
    pub label: String,
    /// The speaker label the transcript gave, verbatim; may be empty.
    pub speaker: String,
    /// Whether that speaker label is one of the owner's names.
    pub owner: bool,
    /// The words: data to read, never instructions.
    pub text: String,
}

/// One PERSON a follow-up may go to, as the model reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeetingFollowUpRecipient {
    /// The call-local label the reply names it by: `P1`, `P2`, ...
    pub label: String,
    /// The name the vault knows the PERSON by.
    pub name: String,
}

/// What a drafting model is asked to read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeetingFollowUpRequest {
    /// The SESSION's TURNs in the order they were said.
    pub turns: Vec<MeetingFollowUpTurn>,
    /// The PERSONs a follow-up may go to, in the order the transcript first
    /// names them.
    pub recipients: Vec<MeetingFollowUpRecipient>,
}

impl MeetingFollowUpRequest {
    /// The request as the model's user message: the owner's speaker labels,
    /// the recipient list and the labelled transcript.
    #[must_use]
    pub fn transcript_message(&self) -> String {
        let mut owners = Vec::new();
        for turn in self.turns.iter().filter(|turn| turn.owner) {
            if !owners.contains(&turn.speaker.as_str()) {
                owners.push(turn.speaker.as_str());
            }
        }
        let mut message = String::from("The owner speaks as:");
        for speaker in owners {
            message.push(' ');
            message.push_str(&quoted(speaker));
        }
        message.push_str("\n\nPeople a follow-up may go to:\n");
        for recipient in &self.recipients {
            message.push_str(&recipient.label);
            message.push(' ');
            message.push_str(&quoted(&recipient.name));
            message.push('\n');
        }
        message.push_str("\nTranscript:\n");
        for turn in &self.turns {
            message.push('[');
            message.push_str(&turn.label);
            message.push_str("] ");
            message.push_str(&one_line(&turn.speaker));
            message.push_str(": ");
            message.push_str(&one_line(&turn.text));
            message.push('\n');
        }
        message
    }
}

/// A SESSION read for one destination, with the rows each label stands for.
#[derive(Debug, Clone)]
pub struct MeetingFollowUpSource {
    pub request: MeetingFollowUpRequest,
    pub session_ref: EntityId,
    /// The stored rows the read stood on, not a permission or a model result.
    pub revision: MeetingFollowUpRevision,
    pub receipt: ScopedReadReceipt,
    /// `T<n>` is `turn_refs[n - 1]`.
    pub(super) turn_refs: Vec<EntityId>,
    /// `P<n>` is `recipient_refs[n - 1]`.
    pub(super) recipient_refs: Vec<EntityId>,
    /// The rows the recipients' names were read from: each PERSON, and the
    /// names-class claim when the name is a claim's.
    pub(super) name_rows: Vec<EntityId>,
}

/// The stored rows a read stood on, each with its body (or `None` when the
/// row is gone): the TURNs, then each listed recipient's and each owner's
/// current name rows (the PERSON row and its current names-class claim).
/// A rename writes a new claim and leaves the old row as it was, so the name
/// rows are read afresh each time, never carried from the first read; which
/// PERSONs are the owners is part of it too. Two revisions are equal when
/// nothing a read stood on has changed.
#[derive(Clone, PartialEq, Eq)]
pub struct MeetingFollowUpRevision {
    turns: Vec<StoredRow>,
    recipients: Vec<(EntityId, Vec<StoredRow>)>,
    owners: Vec<(EntityId, Vec<StoredRow>)>,
}

/// One row's id and its stored body, if it is still stored.
type StoredRow = (EntityId, Option<Vec<u8>>);

impl fmt::Debug for MeetingFollowUpRevision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MeetingFollowUpRevision")
            .field("turns", &self.turns.len())
            .field("recipients", &self.recipients.len())
            .field("owners", &self.owners.len())
            .finish()
    }
}

/// Why a read SESSION gives a model nothing to draft from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeetingFollowUpSilence {
    /// No speaker label is one of the owner's names.
    NoOwnerSpeaker,
    /// The transcript names no PERSON the destination may read.
    NoRecipient,
    /// The rendered transcript is past [`MEETING_FOLLOW_UP_MAX_TRANSCRIPT_BYTES`].
    TooLong,
}

/// A drafting attempt's read.
#[derive(Debug, Clone)]
pub enum MeetingFollowUpRead {
    /// Not a transcript SESSION with TURNs, or a TURN of a conversation the
    /// owner keeps from the Dreamer.
    Missing,
    /// Read, and nothing to ask a model.
    Silent(MeetingFollowUpSilence),
    /// The destination may not receive a TURN now.
    Held(ReleaseHold),
    Ready(MeetingFollowUpSource),
}

/// The TURNs as the destination's scoped read gives them: each one's speaker
/// label and words, in order.
enum HeardTurns {
    Heard(Vec<(String, String)>),
    Missing,
    Held(ReleaseHold),
}

/// The listed recipients and the rows their labels and names stand for.
#[derive(Default)]
struct ListedRecipients {
    recipients: Vec<MeetingFollowUpRecipient>,
    recipient_refs: Vec<EntityId>,
    name_rows: Vec<EntityId>,
}

impl Vault {
    /// Reads the drafting attempt `payload` names for one model
    /// `destination`, as the vault's Dreamer. Every TURN and every listed
    /// recipient's name row is read through that destination's scoped read
    /// in one snapshot; a TURN it withholds holds the whole read, and a
    /// recipient it withholds is not listed.
    ///
    /// # Errors
    ///
    /// The Dreamer's principal, the scoped read or a row read failed.
    pub fn meeting_follow_up_source_for(
        &self,
        payload: &MeetingFollowUpDraftPayload,
        destination: &ReadDestination,
    ) -> Result<MeetingFollowUpRead> {
        use MeetingFollowUpRead::{Held, Missing, Ready, Silent};
        let Ok(session) = EntityId::from_hex(&payload.session_ref) else {
            return Ok(Missing);
        };
        let actor = self.dreamer_authority()?.entity_ref();
        let key = ScopedReadActorKey::with_actor_class(actor.to_hex(), "system")
            .ok_or(Error::InvalidConfig(
                "invalid meeting follow-up worker read key".into(),
            ))?
            .require_relationship_grants(Some(actor))
            .for_destination(destination);
        let reader = self.scoped_read(key);
        reader.persist_grant_clock()?;
        let txn = self.store.env.read_txn()?;
        if self.get_entity_type_in_txn(&txn, &session)? != Some(ENTITY_TYPE_SESSION) {
            return Ok(Missing);
        }
        let turn_refs = retained_turns_in_txn(self, &txn, &session)?;
        if turn_refs.is_empty() || self.any_turn_excluded_in_txn(&txn, &turn_refs)? {
            return Ok(Missing);
        }
        let heard = match self.heard_turns_in_txn(&reader, &txn, &turn_refs, destination)? {
            HeardTurns::Heard(heard) => heard,
            HeardTurns::Missing => return Ok(Missing),
            HeardTurns::Held(hold) => return Ok(Held(hold)),
        };
        let owners = owner_persons_in_txn(self, &txn)?;
        let owner_names = owner_names_in_txn(self, &txn, &owners)?;
        let turns: Vec<MeetingFollowUpTurn> = heard
            .into_iter()
            .enumerate()
            .map(|(index, (speaker, text))| MeetingFollowUpTurn {
                label: format!("T{}", index + 1),
                owner: speaker_is_owner(&speaker, &owner_names),
                speaker,
                text,
            })
            .collect();
        if !turns.iter().any(|turn| turn.owner) {
            return Ok(Silent(MeetingFollowUpSilence::NoOwnerSpeaker));
        }
        let listed = listed_recipients_in_txn(self, &reader, &txn, &turns, &owners)?;
        if listed.recipients.is_empty() {
            return Ok(Silent(MeetingFollowUpSilence::NoRecipient));
        }
        let request = MeetingFollowUpRequest {
            turns,
            recipients: listed.recipients,
        };
        if request.transcript_message().len() > MEETING_FOLLOW_UP_MAX_TRANSCRIPT_BYTES {
            return Ok(Silent(MeetingFollowUpSilence::TooLong));
        }
        let revision = revision_in_txn(self, &txn, &turn_refs, &listed.recipient_refs)?;
        let receipt = reader.read_receipt_in(&txn, None, 0)?;
        Ok(Ready(MeetingFollowUpSource {
            request,
            session_ref: session,
            revision,
            receipt,
            turn_refs,
            recipient_refs: listed.recipient_refs,
            name_rows: listed.name_rows,
        }))
    }

    /// Whether any of `turns` belongs to a conversation the owner keeps from
    /// the Dreamer.
    fn any_turn_excluded_in_txn(&self, txn: &heed::RoTxn<'_>, turns: &[EntityId]) -> Result<bool> {
        let excluded = self.dreamer_excluded_conversations_in_txn(txn)?;
        for turn in turns {
            if excluded.contains_turn(self, txn, turn)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// `turns` through the destination's scoped read: a withheld TURN, or a
    /// world the destination may not reach now, holds the read; a TURN that
    /// is not a transcript's makes the SESSION not a transcript.
    fn heard_turns_in_txn(
        &self,
        reader: &ScopedRead<'_>,
        txn: &heed::RoTxn<'_>,
        turns: &[EntityId],
        destination: &ReadDestination,
    ) -> Result<HeardTurns> {
        let rows = reader.get_entities_parts_in_txn(txn, turns)?;
        let mut worlds = BTreeSet::new();
        let mut heard = Vec::with_capacity(turns.len());
        for (turn, row) in turns.iter().zip(rows) {
            let Some((kind, _, bytes)) = row else {
                let world = self.turn_world_in_txn(txn, turn)?;
                let hold = self
                    .model_call_hold_in_txn(txn, Some(world), destination)?
                    .unwrap_or(ReleaseHold::Placement);
                return Ok(HeardTurns::Held(hold));
            };
            if kind != ENTITY_TYPE_TURN {
                return Err(Error::InvalidClaimBody(
                    "meeting follow-up source is not a turn",
                ));
            }
            let facts = crate::dreamer_consolidation::decode_turn_body(&bytes);
            if !matches!(
                facts.import_source.as_deref(),
                Some(FILE_DROP_TRANSCRIPT_SOURCE_ID | MEETING_TRANSCRIPT_SOURCE_ID)
            ) {
                return Ok(HeardTurns::Missing);
            }
            let world = facts.world_ref.unwrap_or_else(crate::claim::base_world_id);
            if worlds.insert(world)
                && let Some(hold) = self.model_call_hold_in_txn(txn, Some(world), destination)?
            {
                return Ok(HeardTurns::Held(hold));
            }
            heard.push((
                speaker_label(&bytes).unwrap_or_default(),
                facts.text.unwrap_or_default(),
            ));
        }
        Ok(HeardTurns::Heard(heard))
    }

    /// The world a withheld TURN's stored body names, else the base world.
    fn turn_world_in_txn(&self, txn: &heed::RoTxn<'_>, turn: &EntityId) -> Result<EntityId> {
        let world = self
            .store
            .port_entity_record(txn, turn)?
            .and_then(|row| crate::dreamer_consolidation::decode_turn_body(&row.body).world_ref);
        Ok(world.unwrap_or_else(crate::claim::base_world_id))
    }
}

/// The owners' casefolded names, less the embedded owner's placeholder (a
/// name set over it still moves the revision: [`revision_in_txn`] reads
/// every owner's name rows).
fn owner_names_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    owners: &[EntityId],
) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for owner in owners {
        for (name, _) in person_names_in_txn(vault, txn, *owner)? {
            if name.trim() != crate::vault::EMBEDDED_OWNER_ACTOR_NAME {
                names.push(casefold(&name));
            }
        }
    }
    Ok(names)
}

/// The PERSONs `turns` name, less the owners, that the destination's scoped
/// read admits with the row each name was read from; at most
/// [`MEETING_FOLLOW_UP_MAX_RECIPIENTS`], labelled in the order first named.
fn listed_recipients_in_txn(
    vault: &Vault,
    reader: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    turns: &[MeetingFollowUpTurn],
    owners: &[EntityId],
) -> Result<ListedRecipients> {
    let heard_text = casefold(
        &turns
            .iter()
            .map(|turn| format!("{}\n{}", turn.speaker, turn.text))
            .collect::<Vec<_>>()
            .join("\n"),
    );
    let mut listed = ListedRecipients::default();
    for candidate in named_persons_in_txn(vault, txn, &heard_text, owners)? {
        if listed.recipients.len() == MEETING_FOLLOW_UP_MAX_RECIPIENTS {
            break;
        }
        let mut rows = vec![candidate.person];
        if candidate.name_row != candidate.person {
            rows.push(candidate.name_row);
        }
        if reader
            .get_entities_parts_in_txn(txn, &rows)?
            .iter()
            .any(Option::is_none)
        {
            continue;
        }
        listed.recipients.push(MeetingFollowUpRecipient {
            label: format!("P{}", listed.recipients.len() + 1),
            name: candidate.name,
        });
        listed.recipient_refs.push(candidate.person);
        listed.name_rows.extend(rows);
    }
    Ok(listed)
}

/// Whether `source` still stands in `txn`: the SESSION retains exactly the
/// TURNs it was read with (none withdrawn, archived or added since), none of
/// them is in a conversation the owner keeps from the Dreamer, and its
/// [`MeetingFollowUpRevision`] read again is unchanged (no TURN body, no
/// recipient's or owner's current name row, and no owner moved).
pub(super) fn source_unchanged_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    source: &MeetingFollowUpSource,
) -> Result<bool> {
    if retained_turns_in_txn(vault, txn, &source.session_ref)? != source.turn_refs
        || vault.any_turn_excluded_in_txn(txn, &source.turn_refs)?
    {
        return Ok(false);
    }
    Ok(revision_in_txn(vault, txn, &source.turn_refs, &source.recipient_refs)? == source.revision)
}

/// The [`MeetingFollowUpRevision`] of a read of `turn_refs` listing
/// `recipient_refs`, read in `txn`.
fn revision_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn_refs: &[EntityId],
    recipient_refs: &[EntityId],
) -> Result<MeetingFollowUpRevision> {
    Ok(MeetingFollowUpRevision {
        turns: stored_rows_in_txn(vault, txn, turn_refs.iter().copied())?,
        recipients: name_rows_in_txn(vault, txn, recipient_refs)?,
        owners: name_rows_in_txn(vault, txn, &owner_persons_in_txn(vault, txn)?)?,
    })
}

/// Each of `ids` with its stored body, or `None` when it is not stored.
fn stored_rows_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    ids: impl IntoIterator<Item = EntityId>,
) -> Result<Vec<StoredRow>> {
    let mut rows = Vec::new();
    for id in ids {
        let body = vault
            .store
            .port_entity_record(txn, &id)?
            .map(|row| row.body);
        rows.push((id, body));
    }
    Ok(rows)
}

/// Each of `persons` with its current name rows (see [`person_names_in_txn`]),
/// stored as [`stored_rows_in_txn`] reads them.
fn name_rows_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    persons: &[EntityId],
) -> Result<Vec<(EntityId, Vec<StoredRow>)>> {
    let mut rows = Vec::new();
    for person in persons {
        let names = person_names_in_txn(vault, txn, *person)?;
        let stored = stored_rows_in_txn(vault, txn, names.into_iter().map(|(_, row)| row))?;
        rows.push((*person, stored));
    }
    Ok(rows)
}

/// The TURNs `session`'s membership rows name, by `(learned_at, id)`, less
/// a TURN withdrawn (deleted, stale or held from use) or archived.
fn retained_turns_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    session: &EntityId,
) -> Result<Vec<EntityId>> {
    let mut retained = Vec::new();
    for turn in vault
        .member_turns_in_txn(txn, session, |_, _| true)?
        .unwrap_or_default()
    {
        if !crate::ports::withdrawn_in_txn(&vault.store, txn, &turn)?
            && vault.archive_tombstone_in_txn(txn, &turn)?.is_none()
        {
            retained.push(turn);
        }
    }
    Ok(retained)
}

/// The vault's owner PERSONs: its owners, and the embedded owner when it is a
/// PERSON here.
fn owner_persons_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Vec<EntityId>> {
    let mut owners = crate::policy_model::owners_in_txn(vault, txn)?;
    let embedded = crate::vault::embedded_owner_actor_id()?;
    if !owners.contains(&embedded)
        && vault.get_entity_type_in_txn(txn, &embedded)? == Some(ENTITY_TYPE_PERSON)
    {
        owners.push(embedded);
    }
    Ok(owners)
}

/// A PERSON's names, each with the row it was read from: its body's
/// `display_name` or `name`, and its current names-class claim's string value.
fn person_names_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    person: EntityId,
) -> Result<Vec<(String, EntityId)>> {
    let mut names = Vec::new();
    if let Some(name) = crate::reaction::person_name_in(vault, txn, person)? {
        names.push((name, person));
    }
    if let Some((claim, body)) = crate::disclosure::person_name_claim_in(vault, txn, person)?
        && let Some(name) = body.value.as_str()
    {
        names.push((name.to_owned(), claim));
    }
    Ok(names)
}

/// A PERSON the transcript names.
struct NamedPerson {
    person: EntityId,
    name: String,
    name_row: EntityId,
    first_heard: usize,
}

/// Every PERSON but the owners whose name the casefolded transcript
/// `heard_text` says, by where it is first said, then by id.
fn named_persons_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    heard_text: &str,
    owners: &[EntityId],
) -> Result<Vec<NamedPerson>> {
    let mut named = Vec::new();
    for person in vault
        .store
        .port_entity_ids_by_type(txn, ENTITY_TYPE_PERSON, None)?
    {
        let person = person?;
        if owners.contains(&person) {
            continue;
        }
        let mut best: Option<NamedPerson> = None;
        for (name, name_row) in person_names_in_txn(vault, txn, person)? {
            let Some(first_heard) = first_heard(heard_text, &name) else {
                continue;
            };
            if best
                .as_ref()
                .is_none_or(|held| first_heard < held.first_heard)
            {
                best = Some(NamedPerson {
                    person,
                    name: name.trim().to_owned(),
                    name_row,
                    first_heard,
                });
            }
        }
        named.extend(best);
    }
    named.sort_by(|left, right| {
        (left.first_heard, left.person).cmp(&(right.first_heard, right.person))
    });
    Ok(named)
}

/// Where the casefolded `heard_text` first says `name` (whole), or its first
/// word when the name has several, as a whole word.
fn first_heard(heard_text: &str, name: &str) -> Option<usize> {
    let name = casefold(name);
    let mut forms = vec![name.as_str()];
    forms.extend(first_word_form(&name));
    forms
        .into_iter()
        .filter(|form| form.chars().count() >= MIN_NAME_CHARS)
        .filter_map(|form| whole_word_at(heard_text, form))
        .min()
}

/// The first word of a casefolded multi-word `name`, when it is long enough
/// to name someone alone; the one rule for owners' and recipients' names.
fn first_word_form(name: &str) -> Option<&str> {
    let mut words = name.split_whitespace();
    let first = words.next()?;
    words.next()?;
    let chars = first.chars().count();
    let unspaced = first.chars().all(is_unspaced_script);
    (chars >= MIN_FIRST_WORD_CHARS || (unspaced && chars >= MIN_NAME_CHARS)).then_some(first)
}

/// The first byte offset where `word` stands in `text` with no letter or
/// digit of a spaced script touching it on either side. A script written
/// without spaces between words (Han, kana, Hangul) never blocks a match: a
/// name there runs straight into the words around it ("田中さん").
fn whole_word_at(text: &str, word: &str) -> Option<usize> {
    let blocks = |c: char| c.is_alphanumeric() && !is_unspaced_script(c);
    text.match_indices(word).map(|(at, _)| at).find(|&at| {
        let before = text[..at].chars().next_back();
        let after = text[at + word.len()..].chars().next();
        !before.is_some_and(blocks) && !after.is_some_and(blocks)
    })
}

/// Whether `c` belongs to a script written without spaces between words:
/// CJK ideographs, kana (half-width too) and Hangul syllables; the ranges of
/// `failure_signals::verbatim`'s CJK test, plus the kana extension.
fn is_unspaced_script(c: char) -> bool {
    matches!(
        c,
        '\u{3040}'..='\u{30FF}'
            | '\u{31F0}'..='\u{31FF}'
            | '\u{3400}'..='\u{4DBF}'
            | '\u{4E00}'..='\u{9FFF}'
            | '\u{AC00}'..='\u{D7AF}'
            | '\u{F900}'..='\u{FAFF}'
            | '\u{FF66}'..='\u{FF9F}'
            | '\u{20000}'..='\u{2FA1F}'
    )
}

/// Whether a TURN's speaker label is one of the owner's casefolded names:
/// the whole name, or its first word by [`first_word_form`]'s rule.
fn speaker_is_owner(speaker: &str, owner_names: &[String]) -> bool {
    let speaker = casefold(speaker);
    if speaker.chars().count() < MIN_NAME_CHARS {
        return false;
    }
    owner_names
        .iter()
        .any(|name| *name == speaker || first_word_form(name) == Some(speaker.as_str()))
}

/// An imported TURN's display label (provenance only, never identity).
fn speaker_label(body: &[u8]) -> Option<String> {
    let Ok(Value::Map(entries)) = rmpv::decode::read_value(&mut &body[..]) else {
        return None;
    };
    entries.into_iter().find_map(|(key, value)| {
        (key.as_str() == Some("speaker_label"))
            .then(|| value.as_str().map(str::to_owned))
            .flatten()
    })
}

fn casefold(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn quoted(text: &str) -> String {
    serde_json::to_string(text).unwrap_or_else(|_| format!("\"{}\"", one_line(text)))
}
