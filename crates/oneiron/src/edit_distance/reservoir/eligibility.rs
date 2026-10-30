//! FIX 9796, 10194: which scoped pairs a corpus carries. One check, run by
//! the export door on every pair in its one snapshot, before a byte is
//! serialized.
//!
//! The corpus-wide grant clears the door, not any one pair or source. The
//! pair's own artifact row, when it has one, and its input source (the row
//! `source_turn_ref` names) must each pass the owner's own governed read at
//! an off-device destination, because the corpus leaves the vault, and must
//! not be a Tier-A withhold. A retained artifact with no entity row has no
//! row to judge, and a pair with no input source has no source to judge, as
//! the off-record tripwire reads it.
//!
//! A training run's corpus also holds each source with other people to the
//! owner's "I obtained consent" tick (ARCH-0053 #training-inputs). A TURN's
//! source is its conversation, and its people are everyone that ledger ever
//! joined. Any other source is its own row, and its people are its authors.
//! The acting owner and the vault's own agents need no tick; anyone else,
//! another Owner included, does. A source whose people cannot be read is
//! unknown, never consented, so it needs the tick too. The owner's own
//! export is no run and needs none.
//!
//! A pair that fails is left out and counted under its reason, and so is a
//! pair whose rows refuse or do not decode; the rest of the corpus still
//! exports. Only storage, I/O and the owner's proof fail the export.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{FIELD_EXPORT_EXCLUDED, FIELD_EXPORT_EXCLUDED_REASONS, TrainingPair};
use crate::authority::AuthorityView;
use crate::claim::ScopedRead;
use crate::consent::AuthenticatedOwner;
use crate::disclosure::{DisclosureTier, RoomParty, bound_room_party_in, disclosure_tier};
use crate::edit_distance::text_ref::retained_proposal_in_txn;
use crate::edit_distance::{PROPOSAL_ARTIFACT, ProposalArtifactRef, RetainedProposal};
use crate::entity_id::EntityId;
use crate::error::{Error, ErrorKind, Result};
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::registry::ENTITY_TYPE_TURN;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EdgeKind, Vault};

/// The pair's own artifact row is deleted, or the owner's own governed read
/// at the off-device destination refuses it.
const PAIR_UNREADABLE: &str = "gate.reservoir.pair_unreadable";
/// The pair's own artifact row is a Tier-A withhold.
const PAIR_WITHHELD: &str = "gate.reservoir.pair_withheld";
/// The input source is missing or deleted, or the owner's own governed read
/// at the off-device destination a corpus goes to refuses it.
const SOURCE_UNREADABLE: &str = "gate.reservoir.source_unreadable";
/// The input source is a Tier-A withhold: a governance kind or an owner mark.
const SOURCE_WITHHELD: &str = "gate.reservoir.source_withheld";
/// A run's source holds other people, and the owner did not tick "I obtained
/// consent" for it.
const SOURCE_CONSENT_MISSING: &str = "gate.reservoir.source_consent_missing";
/// A run's source whose people cannot be read, and the owner did not tick it.
const SOURCE_PEOPLE_UNKNOWN: &str = "gate.reservoir.source_people_unknown";
/// A row the check reads is sealed secret custody.
const ROW_SECRET_CUSTODY: &str = "gate.reservoir.row_secret_custody";
/// A row the check reads refused it or did not decode.
const ROW_FAILED: &str = "gate.reservoir.row_failed";

/// What a corpus is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorpusUse<'a> {
    /// The owner's own export: no run, so no source needs a tick.
    OwnerExport,
    /// A training run's corpus. `consented_sources` are the sources with
    /// other people the owner ticked "I obtained consent" for this run.
    TrainingRun { consented_sources: &'a [EntityId] },
}

/// What a training run's corpus also holds its sources to.
struct RunTerms {
    /// The sources the owner ticked "I obtained consent" for.
    consented: BTreeSet<EntityId>,
    /// The acting owner, whose own rows need no tick.
    actor: EntityId,
    /// The authority fold that names the vault's own agents.
    fold: AuthorityView,
}

/// How one row stands for a corpus.
enum RowCheck {
    /// No entity row has the id.
    Absent,
    /// Deleted, or the owner's governed read refuses it.
    Unreadable,
    /// A Tier-A withhold.
    Withheld,
    /// Readable and not withheld, with its entity type.
    Passes(u8),
}

/// Who an input source holds, and the source the owner ticks for it.
enum SourcePeople {
    /// The acting owner and the vault's own agents alone.
    Owner,
    /// Someone else.
    Others(EntityId),
    /// People that cannot be read. Never the owner's alone.
    Unknown(EntityId),
}

/// The pairs `reader`, the read of `owner`, may put in a corpus for
/// `corpus_use`, in their order, and how many were left out under each
/// reason code. Everything is read in the export's snapshot `rtxn`.
pub(super) fn admitted_pairs_in(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    owner: &AuthenticatedOwner,
    reader: &ScopedRead<'_>,
    corpus_use: CorpusUse<'_>,
    pairs: Vec<TrainingPair>,
) -> Result<(Vec<TrainingPair>, BTreeMap<String, u64>)> {
    // The owner's standing, rechecked in this snapshot, and one policy judge
    // every row of the corpus.
    let policy = reader.live_policy_manifest_in(rtxn)?;
    let readable = |id: &EntityId| reader.is_entity_readable_with_policy_in(rtxn, &policy, id);
    let run = match corpus_use {
        CorpusUse::OwnerExport => None,
        CorpusUse::TrainingRun { consented_sources } => Some(RunTerms {
            consented: consented_sources.iter().copied().collect(),
            actor: owner.revalidate_in_txn(vault, rtxn)?,
            fold: vault.authority_view_readonly_in_txn(rtxn)?,
        }),
    };
    let mut admitted = Vec::with_capacity(pairs.len());
    let mut excluded = BTreeMap::<String, u64>::new();
    let mut imported_owner_side = BTreeMap::<EntityId, bool>::new();
    for pair in pairs {
        let code = match refusal_in(
            vault,
            rtxn,
            &readable,
            run.as_ref(),
            pair.receipt_ref,
            &mut imported_owner_side,
        ) {
            Ok(None) => {
                admitted.push(pair);
                continue;
            }
            Ok(Some(code)) => code,
            Err(error) if fails_export(&error) => return Err(error),
            Err(error) if error.kind() == ErrorKind::InvalidSecretCustodyBody => ROW_SECRET_CUSTODY,
            Err(_) => ROW_FAILED,
        };
        *excluded.entry(code.to_owned()).or_default() += 1;
    }
    Ok((admitted, excluded))
}

/// FIX 11351, 11355: the proposal retained under `artifact` as the owner's
/// own read through `reader` may show it, in the snapshot `rtxn`. It is
/// judged as a corpus pair is: its artifact row and its input source must
/// each pass `reader`'s governed read and not be a Tier-A withhold. An
/// ordinary read is no run, so no source needs a consent tick. `None` when
/// nothing is retained there or either row is withheld, and so is a row
/// that refuses or does not decode. Only storage, I/O and the owner's proof
/// fail the read.
pub(crate) fn owner_readable_proposal_in(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    reader: &ScopedRead<'_>,
    artifact: EntityId,
) -> Result<Option<RetainedProposal>> {
    let policy = reader.live_policy_manifest_in(rtxn)?;
    let readable = |id: &EntityId| reader.is_entity_readable_with_policy_in(rtxn, &policy, id);
    // No run: refusal never reaches the source-people memo on this path.
    let mut imported_owner_side = BTreeMap::new();
    match refusal_in(
        vault,
        rtxn,
        &readable,
        None,
        artifact,
        &mut imported_owner_side,
    ) {
        Ok(None) => {}
        Err(error) if fails_export(&error) => return Err(error),
        Ok(Some(_)) | Err(_) => return Ok(None),
    }
    retained_proposal_in_txn(vault, rtxn, ProposalArtifactRef::new(artifact))
}

/// Whether `error` fails the whole export: storage, I/O or the owner's
/// proof. Any other error is about one pair's rows, which stay out.
fn fails_export(error: &Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::Storage
            | ErrorKind::Io
            | ErrorKind::MapFull
            | ErrorKind::ConsentOwnerNotAuthenticated
            | ErrorKind::ScopedReadOwnerNotLive
    )
}

/// What the pre-tick checks say about the pair whose artifact is `artifact`.
enum PreTick {
    /// No input source: nothing further to judge.
    NoSource,
    /// A row check refused, with the pair/source reason code.
    Refused(&'static str),
    /// The input source and its entity type, for the people check.
    Source { source: EntityId, entity_type: u8 },
}

/// The pair's row check, its PROPOSAL_ARTIFACT source lookup and the
/// source's row check: the checks `refusal_in` and `ticked_source_in` used
/// to carry as two copies (FIX 11721). Same order, same values, same `?`
/// propagation points as both copies.
fn pre_tick_checks_in(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    readable: &dyn Fn(&EntityId) -> Result<bool>,
    artifact: EntityId,
) -> Result<PreTick> {
    match row_check_in(vault, rtxn, readable, artifact)? {
        RowCheck::Absent | RowCheck::Passes(_) => {}
        RowCheck::Unreadable => return Ok(PreTick::Refused(PAIR_UNREADABLE)),
        RowCheck::Withheld => return Ok(PreTick::Refused(PAIR_WITHHELD)),
    }
    let Some(source) = PROPOSAL_ARTIFACT
        .get(&vault.store, rtxn, &artifact)?
        .and_then(|stored| stored.record.source_turn_ref)
    else {
        return Ok(PreTick::NoSource);
    };
    match row_check_in(vault, rtxn, readable, source)? {
        RowCheck::Passes(entity_type) => Ok(PreTick::Source {
            source,
            entity_type,
        }),
        RowCheck::Absent | RowCheck::Unreadable => Ok(PreTick::Refused(SOURCE_UNREADABLE)),
        RowCheck::Withheld => Ok(PreTick::Refused(SOURCE_WITHHELD)),
    }
}

/// Why the pair whose artifact is `artifact` stays out, or `None` when it
/// goes in. `run` is what a training run also holds its source to.
fn refusal_in(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    readable: &dyn Fn(&EntityId) -> Result<bool>,
    run: Option<&RunTerms>,
    artifact: EntityId,
    imported_owner_side: &mut BTreeMap<EntityId, bool>,
) -> Result<Option<&'static str>> {
    let (source, entity_type) = match pre_tick_checks_in(vault, rtxn, readable, artifact)? {
        PreTick::NoSource => return Ok(None),
        PreTick::Refused(code) => return Ok(Some(code)),
        PreTick::Source {
            source,
            entity_type,
        } => (source, entity_type),
    };
    let Some(run) = run else {
        return Ok(None);
    };
    Ok(
        match source_people_in(vault, rtxn, run, source, entity_type, imported_owner_side)? {
            SourcePeople::Owner => None,
            SourcePeople::Others(key) | SourcePeople::Unknown(key)
                if run.consented.contains(&key) =>
            {
                None
            }
            SourcePeople::Others(_) => Some(SOURCE_CONSENT_MISSING),
            SourcePeople::Unknown(_) => Some(SOURCE_PEOPLE_UNKNOWN),
        },
    )
}

/// `id` as the owner's governed read and the Tier-A rules see it.
fn row_check_in(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    readable: &dyn Fn(&EntityId) -> Result<bool>,
    id: EntityId,
) -> Result<RowCheck> {
    let entity_type = match live_entity_row_in_txn(&vault.store, rtxn, &id)? {
        LiveEntityRow::Live { entity_type, .. } => entity_type,
        LiveEntityRow::Absent => return Ok(RowCheck::Absent),
        LiveEntityRow::DeletedShell => return Ok(RowCheck::Unreadable),
    };
    if !readable(&id)? {
        return Ok(RowCheck::Unreadable);
    }
    if disclosure_tier(&vault.store, rtxn, &id, entity_type, None)? == DisclosureTier::TierA {
        return Ok(RowCheck::Withheld);
    }
    Ok(RowCheck::Passes(entity_type))
}

/// Who `source` holds. A TURN's source is its conversation, and its people
/// are everyone that ledger ever joined. Any other row is its own source,
/// and its people are the authors its `AuthoredBy` edges name. The acting
/// owner and the vault's own agents (`bound_room_party_in`) are the owner's
/// side. A room or ledger that cannot be read, or no one to class, is
/// unknown. A never-joined imported conversation's recorded speakers decide
/// (FIX 11353).
fn source_people_in(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    run: &RunTerms,
    source: EntityId,
    entity_type: u8,
    imported_owner_side: &mut BTreeMap<EntityId, bool>,
) -> Result<SourcePeople> {
    let (key, people) = if entity_type == ENTITY_TYPE_TURN {
        let room = match crate::conversation_dag::conversation_of(&vault.store, rtxn, &source) {
            Ok(room) => room,
            Err(error) if fails_export(&error) => return Err(error),
            Err(_) => return Ok(SourcePeople::Unknown(source)),
        };
        match vault.ever_members_in_txn(rtxn, room) {
            Ok(members) => (room, members.into_iter().collect::<Vec<_>>()),
            Err(error) if fails_export(&error) => return Err(error),
            Err(_) => return Ok(SourcePeople::Unknown(room)),
        }
    } else {
        let mut authors = Vec::new();
        for edge in vault.store.port_edges(
            rtxn,
            &source,
            EdgeDirection::Out,
            Some(EdgeKind::AuthoredBy),
            None,
        )? {
            authors.push(edge?.target);
        }
        (source, authors)
    };
    if people.is_empty() {
        // FIX 11353: a never-joined imported conversation's speakers are side
        // strings, not members. An owner-side import needs no tick.
        if entity_type == ENTITY_TYPE_TURN {
            let owner_side = match imported_owner_side.get(&key) {
                Some(cached) => *cached,
                None => {
                    let verdict =
                        match crate::ingest::history::imported_speakers_in(vault, rtxn, key) {
                            Ok(crate::ingest::history::ImportedConversationSpeakers::OwnerSide) => {
                                true
                            }
                            Ok(_) => false,
                            Err(error) if fails_export(&error) => return Err(error),
                            Err(_) => false,
                        };
                    imported_owner_side.insert(key, verdict);
                    verdict
                }
            };
            if owner_side {
                return Ok(SourcePeople::Owner);
            }
        }
        return Ok(SourcePeople::Unknown(key));
    }
    for person in people {
        if person != run.actor
            && bound_room_party_in(vault, rtxn, &run.fold, person)? != RoomParty::VaultAgent
        {
            return Ok(SourcePeople::Others(key));
        }
    }
    Ok(SourcePeople::Owner)
}

/// FIX 11352: who a source a training run's corpus would hold to the
/// owner's tick holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReservoirSourcePeople {
    /// Someone other than the acting owner and the vault's own agents.
    Others,
    /// People that cannot be read.
    Unknown,
}

/// FIX 11352: one source a training run's corpus would hold to the owner's
/// "I obtained consent" tick.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReservoirSourceRow {
    /// The key a tick names: a TURN's conversation, else the source row.
    pub source: EntityId,
    pub people: ReservoirSourcePeople,
    /// The scope's pairs that rest on it.
    pub pairs: u64,
    /// Whether the ticks the preview was given name it.
    pub consented: bool,
}

/// FIX 11352: what a training run's corpus over one reservoir scope would
/// hold, read before the owner prepares it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReservoirSourcePreview {
    /// The pairs the corpus would carry under the ticks given.
    pub carried: u64,
    /// The pairs the source check would leave out under them, by reason
    /// code.
    pub excluded: BTreeMap<String, u64>,
    /// Each source with other people or people that cannot be read, in key
    /// order: what the owner ticks.
    pub sources: Vec<ReservoirSourceRow>,
}

/// FIX 11352: the preview of a training run's corpus over `scope`, under
/// `consented`, the ticks the owner gave so far: each source its pairs rest
/// on that holds other people or people that cannot be read, and how many
/// pairs the source check would carry and leave out, as the run's export
/// would judge them in one snapshot. It reads as the owner's own read at
/// the off-device destination, as that export does. Read only: it clears
/// no consent, spends no approve-once, keeps no receipt and returns no pair
/// body.
///
/// # Errors
///
/// The owner's standing lapsed; an unusable task-class filter; the
/// off-record tripwire; storage errors.
pub fn reservoir_source_preview(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    scope: super::ReservoirScope,
    consented: &[EntityId],
) -> Result<ReservoirSourcePreview> {
    let scope = super::normalized_scope(scope)?;
    let key = vault.owner_proof_read_key(owner)?;
    let reader = vault.scoped_read(key.at(crate::claim::CallerLocality::OffDevice));
    reader.persist_grant_clock()?;
    let rtxn = vault.store.env.read_txn()?;
    let pairs = super::resolve_candidates(vault, &rtxn, &scope)?;
    let sources = ticked_sources_in(vault, &rtxn, owner, &reader, &pairs, consented)?;
    let corpus_use = CorpusUse::TrainingRun {
        consented_sources: consented,
    };
    let (carried, excluded) = admitted_pairs_in(vault, &rtxn, owner, &reader, corpus_use, pairs)?;
    Ok(ReservoirSourcePreview {
        carried: carried.len() as u64,
        excluded,
        sources,
    })
}

/// The sources `pairs` rest on that a run holds to the owner's tick, each
/// with the pairs that rest on it. A pair its own rows or its source's keep
/// out whatever the tick, or whose rows refuse or do not decode, names
/// none.
fn ticked_sources_in(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    owner: &AuthenticatedOwner,
    reader: &ScopedRead<'_>,
    pairs: &[TrainingPair],
    consented: &[EntityId],
) -> Result<Vec<ReservoirSourceRow>> {
    let policy = reader.live_policy_manifest_in(rtxn)?;
    let readable = |id: &EntityId| reader.is_entity_readable_with_policy_in(rtxn, &policy, id);
    let run = RunTerms {
        consented: consented.iter().copied().collect(),
        actor: owner.revalidate_in_txn(vault, rtxn)?,
        fold: vault.authority_view_readonly_in_txn(rtxn)?,
    };
    let mut sources = BTreeMap::<EntityId, ReservoirSourceRow>::new();
    let mut imported_owner_side = BTreeMap::<EntityId, bool>::new();
    for pair in pairs {
        let people = match ticked_source_in(
            vault,
            rtxn,
            &readable,
            &run,
            pair.receipt_ref,
            &mut imported_owner_side,
        ) {
            Ok(people) => people,
            Err(error) if fails_export(&error) => return Err(error),
            Err(_) => None,
        };
        let (source, people) = match people {
            Some(SourcePeople::Others(key)) => (key, ReservoirSourcePeople::Others),
            Some(SourcePeople::Unknown(key)) => (key, ReservoirSourcePeople::Unknown),
            Some(SourcePeople::Owner) | None => continue,
        };
        sources
            .entry(source)
            .or_insert(ReservoirSourceRow {
                source,
                people,
                pairs: 0,
                consented: run.consented.contains(&source),
            })
            .pairs += 1;
    }
    Ok(sources.into_values().collect())
}

/// Who the input source of the pair whose artifact is `artifact` holds,
/// when the pair's own row and its source pass every check but the tick;
/// `None` when they do not, or when the pair has no source.
fn ticked_source_in(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    readable: &dyn Fn(&EntityId) -> Result<bool>,
    run: &RunTerms,
    artifact: EntityId,
    imported_owner_side: &mut BTreeMap<EntityId, bool>,
) -> Result<Option<SourcePeople>> {
    let PreTick::Source {
        source,
        entity_type,
    } = pre_tick_checks_in(vault, rtxn, readable, artifact)?
    else {
        return Ok(None);
    };
    source_people_in(vault, rtxn, run, source, entity_type, imported_owner_side).map(Some)
}

/// The export receipt's exclusion fields: the count always, and each reason
/// as `code=count`, comma-joined, when any pair was left out.
pub(super) fn excluded_fields(
    excluded: &BTreeMap<String, u64>,
    fields: &mut BTreeMap<String, String>,
) {
    fields.insert(
        FIELD_EXPORT_EXCLUDED.to_owned(),
        excluded.values().sum::<u64>().to_string(),
    );
    if !excluded.is_empty() {
        let reasons = excluded
            .iter()
            .map(|(code, count)| format!("{code}={count}"))
            .collect::<Vec<_>>();
        fields.insert(FIELD_EXPORT_EXCLUDED_REASONS.to_owned(), reasons.join(","));
    }
}
