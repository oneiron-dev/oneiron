//! Whether a companion profile reader's own credential keeps out the world
//! its read names or the exact words behind one of the snapshot's recorded
//! sources (FIX 11174, 8141, 11766). A source is kept out when its world lies
//! outside the credential's world ceiling; when its record no longer stands,
//! is kept from a caller off this device or lies outside the facets the
//! credential is limited to; or when the words it names do not read for this
//! reader: the exact version they were read at no longer resolves, that
//! version is kept from this reader by its device rule, facets or world, the
//! words at the recorded ranges are not the words pinned, or this reader
//! reads a lifted key among them as its handle where the producer read the
//! key. Everything is judged under this reader's own key, in the caller's
//! transaction, on the recorded version: never the Dreamer's key, never the
//! live document in its place, never the whole document's text. The
//! relationship gate, which the profile's own grant stands in for, is not
//! asked. Only a positive exclusion withholds the profile; a judgement that
//! cannot be read keeps the read as it was.

use super::ScopedRead;
use crate::EntityId;
use crate::batch::secret_scan::LiftedKeys;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{Error, Result};
use crate::file_secret_marks::SecretSight;
use crate::vault::ReadMode;
use crate::write_envelope::profile_snapshot::{
    PsychProfileByteRange, PsychProfileSource, PsychProfileSourceWords, PsychProfileSpanText,
    PsychProfileWordsPin, psych_profile_words_pin,
};
use oneiron_store::consolidation_evidence::swarm_evidence_content_hash;

/// What a companion profile reader's own credential says of the world a
/// profile read names and of the exact words behind its sources (FIX 11766).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompanionProfileSourceJudgement {
    /// Every judgement admits the read.
    Admitted,
    /// A judgement keeps the read out: the profile reads as missing and says
    /// nothing of itself.
    Excluded,
    /// No judgement keeps the read out, but one could not be read: the read
    /// stays as it was (FIX 11174).
    Unavailable,
}

impl CompanionProfileSourceJudgement {
    /// The judgement `readable` gives: admitted, excluded, or, for an error,
    /// unavailable.
    fn of(readable: Result<bool>) -> Self {
        match readable {
            Ok(true) => Self::Admitted,
            Ok(false) => Self::Excluded,
            Err(error) => {
                tracing::warn!(
                    error_kind = ?error.kind(),
                    "a companion profile source judgement could not be read; the read stays as \
                     it was (FIX 11174)"
                );
                Self::Unavailable
            }
        }
    }

    /// Both judgements together: an exclusion wins, then an unavailable one.
    fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::Excluded, _) | (_, Self::Excluded) => Self::Excluded,
            (Self::Unavailable, _) | (_, Self::Unavailable) => Self::Unavailable,
            (Self::Admitted, Self::Admitted) => Self::Admitted,
        }
    }
}

impl ScopedRead<'_> {
    /// What this read's credential says of `world`, the world a profile read
    /// names (`None` names none), and of the exact words behind each of
    /// `sources`, judged in `txn`.
    pub(crate) fn companion_profile_excluded_in(
        &self,
        txn: &heed::RoTxn<'_>,
        world: Option<EntityId>,
        sources: &[PsychProfileSource],
    ) -> CompanionProfileSourceJudgement {
        let mut judgement = match world {
            None => CompanionProfileSourceJudgement::Admitted,
            Some(_) => CompanionProfileSourceJudgement::of(self.world_readable_in(txn, world)),
        };
        for source in sources {
            if judgement == CompanionProfileSourceJudgement::Excluded {
                break;
            }
            judgement = judgement.and(self.companion_profile_source_judged_in(txn, source));
        }
        judgement
    }

    /// What this read's credential says of `source`: the world it is placed
    /// in, then the exact words it names.
    fn companion_profile_source_judged_in(
        &self,
        txn: &heed::RoTxn<'_>,
        source: &PsychProfileSource,
    ) -> CompanionProfileSourceJudgement {
        let placed =
            CompanionProfileSourceJudgement::of(self.world_readable_in(txn, source.world_ref));
        if placed == CompanionProfileSourceJudgement::Excluded {
            return placed;
        }
        placed.and(CompanionProfileSourceJudgement::of(
            self.companion_profile_source_words_readable_in(txn, source),
        ))
    }

    /// Whether this read's credential reads the exact words `source` names,
    /// in `txn`: its record still stands for this reader, the version the
    /// words were read at is one the record retains and still reads, this
    /// reader's device rule, facets and world ceiling admit that version
    /// (where that ceiling holds it; one with no provable world is outside a
    /// ceiling that narrows worlds), and the words it holds at the recorded
    /// ranges are the words pinned, in this reader's secret sight, under the
    /// lifted keys of every string the record holds. `Ok(false)` is a
    /// positive exclusion.
    fn companion_profile_source_words_readable_in(
        &self,
        txn: &heed::RoTxn<'_>,
        source: &PsychProfileSource,
    ) -> Result<bool> {
        let id = source.document_ref;
        let Some(live) = self.vault.get_raw_in(txn, &id)? else {
            return Ok(false);
        };
        if self.device_withholds_in(txn, &id, None)? || !self.facets_allow_in(txn, &id, &live)? {
            return Ok(false);
        }
        if !self.revision_owned_in(txn, &id, source.document_revision)? {
            return Ok(false);
        }
        let Some(version) =
            self.revision_raw_in(txn, &id, ReadMode::Pinned(source.document_revision))?
        else {
            return Ok(false);
        };
        let header =
            EntityMetadataHeader::parse(&version).ok_or(Error::CorruptedIndex("entity header"))?;
        let body = &version[ENTITY_METADATA_HEADER_LEN..];
        if version != live
            && (self.device_withholds_in(txn, &id, Some(version.as_slice()))?
                || !self.facets_allow_in(txn, &id, &version)?)
        {
            return Ok(false);
        }
        // The version sits where a read under this reader's world ceiling
        // holds it, a NOTE in several worlds at its witness there: outside
        // the ceiling, or with no position it can prove, it is kept out. A
        // ceiling that leaves worlds whole binds no world.
        let ceiling = self.actor_key.world_ceiling();
        let narrows_worlds = !matches!(
            ceiling.worlds,
            oneiron_authority::federation::ScopeAxis::All
        );
        if narrows_worlds
            && self
                .world_record_in(txn, &id, header.entity_type, body, &ceiling)?
                .is_none_or(|record| !record.is_narrowing_of(&ceiling))
        {
            return Ok(false);
        }
        let sight = self.actor_key.secret_sight();
        match &source.words {
            PsychProfileSourceWords::Record { content } => {
                if swarm_evidence_content_hash(body) != *content {
                    return Ok(false);
                }
                if sight != SecretSight::Masked {
                    return Ok(true);
                }
                let texts = body_texts(body);
                let keys = LiftedKeys::of_in_txn(&self.vault.store, txn, &texts)?;
                Ok(texts.iter().all(|text| keys.masked(text).is_none()))
            }
            PsychProfileSourceWords::Spans { text, ranges, pin } => {
                let live_body = live.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default();
                let (read, current) = match text {
                    PsychProfileSpanText::Document { frontier } => {
                        match crate::entity_doc::source_texts_at_in_txn(
                            &self.vault.store,
                            txn,
                            &id,
                            frontier,
                        )? {
                            Some(texts) => texts,
                            None => return Ok(false),
                        }
                    }
                    PsychProfileSpanText::Field { field } => {
                        let Some(read) = body_field(body, field) else {
                            return Ok(false);
                        };
                        let current = body_field(live_body, field).unwrap_or_default();
                        (read, current)
                    }
                };
                let keys = LiftedKeys::of_in_txn(
                    &self.vault.store,
                    txn,
                    masking_texts(body, live_body, &read, &current),
                )?;
                Ok(span_words_readable(&read, ranges, *pin, &keys, sight))
            }
        }
    }
}

/// Whether a reader in `sight` reads the words `ranges` select of `text` as
/// `pin` pinned them (FIX 11766); `keys` are the lifted keys a masked read of
/// the record reads as handles ([`masking_texts`]).
/// A content pin names the stored words: they must hash to it, and a reader
/// who reads lifted keys as handles must find none among them. A projection
/// pin names the words as a masked read shows them: that projection must
/// hash to it, and every reader reads at least that. A range off the text or
/// off a character boundary binds no words.
fn span_words_readable(
    text: &str,
    ranges: &[PsychProfileByteRange],
    pin: PsychProfileWordsPin,
    keys: &LiftedKeys,
    sight: SecretSight,
) -> bool {
    let mut stored: Vec<(usize, &str)> = Vec::with_capacity(ranges.len());
    for range in ranges {
        let (Ok(start), Ok(end)) = (usize::try_from(range.start), usize::try_from(range.end))
        else {
            return false;
        };
        let Some(words) = text.get(start..end) else {
            return false;
        };
        stored.push((start, words));
    }
    let chars: Vec<char> = text.chars().collect();
    let masked: Option<Vec<String>> = stored
        .iter()
        .map(|(start, words)| {
            let from = text[..*start].chars().count();
            crate::entity_doc::span_in_masked_sight(
                keys,
                &chars,
                from,
                from + words.chars().count(),
            )
            .map(|(_, shown)| shown)
        })
        .collect();
    match pin {
        PsychProfileWordsPin::Content(hash) => {
            hash == psych_profile_words_pin(stored.iter().map(|(_, words)| *words))
                && (sight != SecretSight::Masked
                    || masked.is_some_and(|masked| {
                        masked
                            .iter()
                            .zip(&stored)
                            .all(|(shown, (_, words))| shown == words)
                    }))
        }
        PsychProfileWordsPin::Projection(hash) => masked.is_some_and(|masked| {
            hash == psych_profile_words_pin(masked.iter().map(String::as_str))
        }),
    }
}

/// The texts whose lifted keys a masked read of a record's words reads as
/// handles, as the masked entity read collects them from every string of a
/// body (FIX 11766): each string of the version's `body` and of the `live`
/// body, then the selected text `read` and its live text `current`, each
/// once. A key marked in another field of the record masks the selected
/// words too.
fn masking_texts(body: &[u8], live: &[u8], read: &str, current: &str) -> Vec<String> {
    let mut texts: Vec<String> = Vec::new();
    let named = body_texts(body)
        .into_iter()
        .chain(body_texts(live))
        .chain([read.to_owned(), current.to_owned()]);
    for text in named {
        if !texts.contains(&text) {
            texts.push(text);
        }
    }
    texts
}

/// The string `field` holds at the top of `body`, a MessagePack map body.
fn body_field(body: &[u8], field: &str) -> Option<String> {
    let mut cursor = body;
    let Ok(rmpv::Value::Map(entries)) = rmpv::decode::read_value(&mut cursor) else {
        return None;
    };
    if !cursor.is_empty() {
        return None;
    }
    entries
        .into_iter()
        .find_map(|(key, value)| match (key, value) {
            (rmpv::Value::String(key), rmpv::Value::String(value))
                if key.as_str() == Some(field) =>
            {
                value.into_str()
            }
            _ => None,
        })
}

/// Every string a record body holds: each string value of a MessagePack
/// body, or the whole body where it is a document's UTF-8 text.
fn body_texts(body: &[u8]) -> Vec<String> {
    fn strings_of(value: &rmpv::Value, texts: &mut Vec<String>) {
        match value {
            rmpv::Value::String(text) => {
                if let Some(text) = text.as_str() {
                    texts.push(text.to_owned());
                }
            }
            rmpv::Value::Array(items) => items.iter().for_each(|item| strings_of(item, texts)),
            rmpv::Value::Map(entries) => entries
                .iter()
                .for_each(|(_, value)| strings_of(value, texts)),
            _ => {}
        }
    }
    let mut cursor = body;
    if let Ok(value) = rmpv::decode::read_value(&mut cursor)
        && cursor.is_empty()
    {
        let mut texts = Vec::new();
        strings_of(&value, &mut texts);
        return texts;
    }
    std::str::from_utf8(body)
        .map(|text| vec![text.to_owned()])
        .unwrap_or_default()
}
