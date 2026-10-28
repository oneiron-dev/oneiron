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

use super::{FIELD_EXPORT_EXCLUDED, FIELD_EXPORT_EXCLUDED_REASONS, TrainingPair};
use crate::authority::AuthorityView;
use crate::claim::ScopedRead;
use crate::consent::AuthenticatedOwner;
use crate::disclosure::{DisclosureTier, RoomParty, bound_room_party_in, disclosure_tier};
use crate::edit_distance::PROPOSAL_ARTIFACT;
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
    for pair in pairs {
        let code = match refusal_in(vault, rtxn, &readable, run.as_ref(), pair.receipt_ref) {
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

/// Why the pair whose artifact is `artifact` stays out, or `None` when it
/// goes in. `run` is what a training run also holds its source to.
fn refusal_in(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    readable: &dyn Fn(&EntityId) -> Result<bool>,
    run: Option<&RunTerms>,
    artifact: EntityId,
) -> Result<Option<&'static str>> {
    match row_check_in(vault, rtxn, readable, artifact)? {
        RowCheck::Absent | RowCheck::Passes(_) => {}
        RowCheck::Unreadable => return Ok(Some(PAIR_UNREADABLE)),
        RowCheck::Withheld => return Ok(Some(PAIR_WITHHELD)),
    }
    let Some(source) = PROPOSAL_ARTIFACT
        .get(&vault.store, rtxn, &artifact)?
        .and_then(|record| record.source_turn_ref)
    else {
        return Ok(None);
    };
    let entity_type = match row_check_in(vault, rtxn, readable, source)? {
        RowCheck::Passes(entity_type) => entity_type,
        RowCheck::Absent | RowCheck::Unreadable => return Ok(Some(SOURCE_UNREADABLE)),
        RowCheck::Withheld => return Ok(Some(SOURCE_WITHHELD)),
    };
    let Some(run) = run else {
        return Ok(None);
    };
    Ok(
        match source_people_in(vault, rtxn, run, source, entity_type)? {
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
/// unknown.
fn source_people_in(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    run: &RunTerms,
    source: EntityId,
    entity_type: u8,
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
