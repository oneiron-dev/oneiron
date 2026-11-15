//! Where the words of one stored revision came from.

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::EdgeKind;
use crate::error::{Error, RecordError, Result};
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN};
use crate::store::{ManifestDbs, StoreRead};
use crate::{EntityId, Vault};
use heed::RoTxn;

/// The origin of one revision's words.
pub(crate) enum WordSources {
    /// The revision's own: it carries no summary's words.
    Own,
    /// A scope summary's, which came from these records and MESSAGEs.
    From(Vec<EntityId>),
    /// A summary's whose sources no longer resolve; a reader refuses it.
    Unresolved,
}

/// The word sources of the stored revision `raw` of `id`: an epoch summary,
/// a scope summary, a TURN that copies one, a claim whose merge header names
/// one, a `conversation.summary` claim's typed coverage, a native conflict
/// pair's two claims, the MESSAGE an owner's stated intent cites, or the
/// finding and subject a Dreamer finding's notice points at.
pub(crate) fn word_sources_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    id: &EntityId,
    raw: &[u8],
) -> Result<WordSources> {
    word_sources_through_in(vault, &vault.store.read(), txn, id, raw)
}

/// [`word_sources_in`], an epoch's `DerivedFrom` and dependency sources and
/// the epoch itself resolved through `dbs` as well as base when `dbs` is a
/// session's composed view (FIX 6548): every base source stays, and one the
/// overlay alone holds is named too. An epoch with no source in either is
/// still its own.
pub(crate) fn word_sources_through_in(
    vault: &Vault,
    dbs: &StoreRead<'_>,
    txn: &RoTxn<'_>,
    id: &EntityId,
    raw: &[u8],
) -> Result<WordSources> {
    let header = EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
    let body = &raw[ENTITY_METADATA_HEADER_LEN..];
    let names = |needle: &[u8]| body.windows(needle.len()).any(|window| window == needle);
    let epoch = match header.entity_type {
        ENTITY_TYPE_SUMMARY => {
            match crate::compaction::stored_epoch_in(&vault.store, txn, id, body)? {
                crate::compaction::StoredEpoch::Unresolved if dbs.is_union() => {
                    crate::compaction::stored_epoch_in(dbs, txn, id, body)?
                }
                epoch => epoch,
            }
        }
        _ => crate::compaction::StoredEpoch::No,
    };
    let dependencies = || {
        base_and_view(vault, dbs, |read| {
            crate::ports::dependency_sources_in(read, txn, id)
        })
    };
    let sources = match header.entity_type {
        // A pointer no head stands for may be an epoch summary's, whose
        // sources this read cannot name (Astra 1384e).
        ENTITY_TYPE_SUMMARY if epoch == crate::compaction::StoredEpoch::Unresolved => {
            return Ok(WordSources::Unresolved);
        }
        // An epoch summary's words are those of every record it was written
        // from, its `DerivedFrom` targets (agent-runtime-v1 §d7); a nested
        // epoch among them carries its own. A run that had read and said
        // nothing yet wrote one from its own steps alone.
        ENTITY_TYPE_SUMMARY if epoch == crate::compaction::StoredEpoch::Yes => {
            let sources = base_and_view(vault, dbs, |read| {
                read.port_edges(
                    txn,
                    id,
                    EdgeDirection::Out,
                    Some(EdgeKind::DerivedFrom),
                    None,
                )?
                .map(|edge| edge.map(|edge| edge.target))
                .collect::<Result<Vec<_>>>()
            })?;
            if sources.is_empty() {
                return Ok(WordSources::Own);
            }
            Ok(Some(sources))
        }
        ENTITY_TYPE_SUMMARY | crate::registry::ENTITY_TYPE_COMM_RECORD => {
            super::body_covers_through_in(vault, dbs, txn, id, header.entity_type, body)
        }
        // A reply carries its summary under the `summary` key, in any
        // string encoding; the decoder below decides. Its words are the
        // summary's as it landed, so the sources its landing registered
        // stay its sources whatever the summary covers now.
        ENTITY_TYPE_TURN if names(b"summary") => {
            super::body_covers_through_in(vault, dbs, txn, id, header.entity_type, body).and_then(
                |covers| {
                    covers
                        .map(|mut covers| {
                            covers.extend(dependencies()?);
                            covers.sort_unstable();
                            covers.dedup();
                            Ok(covers)
                        })
                        .transpose()
                },
            )
        }
        ENTITY_TYPE_CLAIM
            if names(b"merge.summary")
                || names(b"conversation.summary")
                || names(b"core.conflict.open")
                || names(PROFILE_INTENT_PREDICATE.as_bytes()) =>
        {
            let claim = crate::write_envelope::claim_body::decode_claim_body(body, true)?;
            if claim.predicate == crate::claim::PREDICATE_CONFLICT_OPEN
                && matches!(&claim.value, rmpv::Value::String(_))
            {
                Ok(Some(conflict_pair_sources(&claim).unwrap_or_default()))
            } else {
                let merged = match super::merge_word_sources_through_in(vault, dbs, txn, &claim) {
                    Ok(None) => {
                        crate::store::conversation_summary::conversation_summary_covers(&claim)
                    }
                    merged => merged,
                };
                if claim.predicate == PROFILE_INTENT_PREDICATE {
                    merged.map(|sources| with_cited_sources(sources, &claim))
                } else {
                    merged
                }
            }
        }
        crate::registry::ENTITY_TYPE_NOTIFICATION
            if names(crate::inbox::NOTIFICATION_PRODUCER_FINDING.as_bytes()) =>
        {
            return Ok(finding_notice_sources(body));
        }
        _ => return Ok(WordSources::Own),
    };
    Ok(match sources {
        Ok(Some(mut sources)) if !sources.is_empty() => {
            if header.entity_type == ENTITY_TYPE_SUMMARY {
                sources.extend(dependencies()?);
                sources.sort_unstable();
                sources.dedup();
            }
            WordSources::From(sources)
        }
        Ok(None) => WordSources::Own,
        Ok(Some(_))
        | Err(
            Error::EntityNotFound
            | Error::Record(
                RecordError::InvalidScopeSummary(_) | RecordError::InvalidConversationDag(_),
            ),
        ) => WordSources::Unresolved,
        Err(error) => return Err(error),
    })
}

/// The summary whose words the stored revision `raw` carries: the summary a
/// reply TURN copies, or the one a `merge.summary` header names. Its words
/// are that summary's, so the general clamp walks the summary itself: its
/// own row (its Tier A, its stamp) and every record its words came from,
/// its registered dependencies included, beyond the records
/// [`word_sources_in`] names for the copy (Sol review rounds 1-2 of #7692).
/// `None` for every other row; an association that does not decode is an
/// error.
pub(crate) fn carried_summary(raw: &[u8]) -> Result<Option<EntityId>> {
    let header = EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
    let body = &raw[ENTITY_METADATA_HEADER_LEN..];
    let names = |needle: &[u8]| body.windows(needle.len()).any(|window| window == needle);
    match header.entity_type {
        ENTITY_TYPE_TURN if names(b"summary") => super::codec::reply_summary(body),
        ENTITY_TYPE_CLAIM if names(b"merge.summary") => {
            let claim = crate::write_envelope::claim_body::decode_claim_body(body, true)?;
            Ok(super::merge_summary_ref(&claim)?.map(|(_, summary)| summary))
        }
        _ => Ok(None),
    }
}

/// The word sources of a notification body (FIX STEWARDSHIP-NOTICE-POINTER,
/// OPUS-LEAKS). A Dreamer finding's notice (producer `dreamer.finding`)
/// points at its finding and the finding's subject, so it reads only while
/// every one of its `subject_refs` reads; those refs must name every id of
/// its event key. A body under that producer that does not decode, or whose
/// refs do not cover its event key, is unresolved. Every other notice,
/// whatever its kind, is its own.
fn finding_notice_sources(body: &[u8]) -> WordSources {
    let producer =
        crate::inbox::notification_recipient::notification_body_json(body).and_then(|json| {
            json.get("source")?
                .get("producer")?
                .as_str()
                .map(str::to_owned)
        });
    if producer.as_deref() != Some(crate::inbox::NOTIFICATION_PRODUCER_FINDING) {
        return WordSources::Own;
    }
    let Ok(notice) = crate::inbox::decode_notification_body(body) else {
        return WordSources::Unresolved;
    };
    let subjects = notice
        .subject_refs
        .iter()
        .map(|hex| EntityId::from_hex(hex).ok())
        .collect::<Option<Vec<_>>>();
    let event = notice
        .source
        .event
        .split(':')
        .map(|hex| EntityId::from_hex(hex).ok())
        .collect::<Option<Vec<_>>>();
    match (subjects, event) {
        (Some(mut subjects), Some(event))
            if notice.kind == crate::inbox::NotificationKind::Finding
                && !subjects.is_empty()
                && event.iter().all(|id| subjects.contains(id)) =>
        {
            subjects.sort_unstable();
            subjects.dedup();
            WordSources::From(subjects)
        }
        _ => WordSources::Unresolved,
    }
}

/// The predicate an owner's stated intent is kept under
/// (`dreamer_consolidation::gap::intent`). Its value is the owner's exact
/// words, quoted from the MESSAGE its consolidation envelope cites.
const PROFILE_INTENT_PREDICATE: &str = "profile.intent";

/// `sources` and every ref `claim`'s consolidation envelope cites: an
/// intent quotes the MESSAGE it cites word for word, so a reader reads it
/// only while it reads that MESSAGE (OPUS-LEAKS, review round 2 of #6969).
/// `sources` unchanged when the envelope cites nothing.
fn with_cited_sources(
    sources: Option<Vec<EntityId>>,
    claim: &crate::write_envelope::claim_body::ClaimBody,
) -> Option<Vec<EntityId>> {
    let cited = crate::provenance::consolidation_refs(claim);
    if cited.is_empty() {
        return sources;
    }
    let mut sources = sources.unwrap_or_default();
    sources.extend(cited);
    sources.sort_unstable();
    sources.dedup();
    Some(sources)
}

/// The two landed claims a string-valued native conflict marker names.
/// Map-valued conflict variants may carry candidates that never landed.
fn conflict_pair_sources(
    claim: &crate::write_envelope::claim_body::ClaimBody,
) -> Option<Vec<EntityId>> {
    let evidence = claim.evidence.as_ref()?.as_map()?;
    let candidate = evidence
        .iter()
        .find(|(key, _)| {
            key.as_str() == Some(crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY)
        })?
        .1
        .as_map()?;
    let refs = candidate
        .iter()
        .find(|(key, _)| key.as_str() == Some("refs"))?
        .1
        .as_array()?;
    let [observed, stated] = refs.as_slice() else {
        return None;
    };
    [observed, stated]
        .into_iter()
        .map(|id| {
            let rmpv::Value::Binary(bytes) = id else {
                return None;
            };
            EntityId::from_bytes(bytes.as_slice().try_into().ok()?).ok()
        })
        .collect()
}

/// What a reply copying `summary`'s words depends on (FIX 10092): the
/// `sources` its words came from (covers and MESSAGEs) and every dependency
/// `summary` registered that is still stored, an edited predecessor's
/// sources among them. A registered source already erased is left out, so
/// the reply lands as it did before.
pub(super) fn reply_sources_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    summary: &EntityId,
    mut sources: Vec<EntityId>,
) -> Result<Vec<EntityId>> {
    for source in crate::ports::dependency_sources_in(&vault.store, txn, summary)? {
        if vault
            .store
            .entities()
            .get(txn, source.as_bytes())?
            .is_some()
        {
            sources.push(source);
        }
    }
    sources.sort_unstable();
    sources.dedup();
    Ok(sources)
}

/// `read` on base, then through `dbs` too when it is a session's composed
/// view (FIX 6548): base sources stay, and the overlay's own are added.
fn base_and_view(
    vault: &Vault,
    dbs: &StoreRead<'_>,
    read: impl Fn(&StoreRead<'_>) -> Result<Vec<EntityId>>,
) -> Result<Vec<EntityId>> {
    let mut sources = read(&vault.store.read())?;
    if dbs.is_union() {
        sources.extend(read(dbs)?);
        sources.sort_unstable();
        sources.dedup();
    }
    Ok(sources)
}
