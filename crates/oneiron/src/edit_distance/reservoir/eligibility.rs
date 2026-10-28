//! FIX 9796, 10194: which scoped pairs a corpus carries. One source check,
//! run by the export door on every pair in its one snapshot, before a byte
//! is serialized.
//!
//! The corpus-wide grant clears the door, not any one source. A pair's input
//! source is the TURN its proposal derives from. That TURN must pass the
//! owner's own governed read at an off-device destination, because the
//! corpus leaves the vault, and it must not be a Tier-A withhold. A pair with
//! no input TURN has no source to judge, as the off-record tripwire reads it.
//!
//! A training run's corpus also holds each source with other people to the
//! owner's "I obtained consent" tick (ARCH-0053 #training-inputs). The source
//! is the input TURN's conversation, and its people are everyone its ledger
//! ever joined. The owner and the vault's own agents need no tick. A source
//! whose people cannot be read is unknown, never consented, so it needs the
//! tick too. The owner's own export is no run and needs none.
//!
//! A pair that fails is left out and counted under its reason; the rest of
//! the corpus still exports.

use std::collections::{BTreeMap, BTreeSet};

use super::{FIELD_EXPORT_EXCLUDED, FIELD_EXPORT_EXCLUDED_REASONS, TrainingPair};
use crate::Vault;
use crate::authority::AuthorityFold;
use crate::claim::ScopedRead;
use crate::disclosure::{DisclosureTier, RoomParty, bound_room_party_in, disclosure_tier};
use crate::edit_distance::PROPOSAL_ARTIFACT;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// The input source fails the owner's own governed read at the off-device
/// destination a corpus goes to.
const SOURCE_UNREADABLE: &str = "gate.reservoir.source_unreadable";
/// The input source is a Tier-A withhold: a governance kind or an owner mark.
const SOURCE_WITHHELD: &str = "gate.reservoir.source_withheld";
/// A run's source holds other people, and the owner did not tick "I obtained
/// consent" for it.
const SOURCE_CONSENT_MISSING: &str = "gate.reservoir.source_consent_missing";
/// A run's source whose people cannot be read, and the owner did not tick it.
const SOURCE_PEOPLE_UNKNOWN: &str = "gate.reservoir.source_people_unknown";

/// What a corpus is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorpusUse<'a> {
    /// The owner's own export: no run, so no source needs a tick.
    OwnerExport,
    /// A training run's corpus. `consented_sources` are the sources with
    /// other people the owner ticked "I obtained consent" for this run.
    TrainingRun { consented_sources: &'a [EntityId] },
}

/// Who an input source holds, and the source the owner ticks for it.
enum SourcePeople {
    /// The owner and the vault's own agents alone.
    Owner,
    /// Someone else.
    Others(EntityId),
    /// People that cannot be read. Never the owner's alone.
    Unknown(EntityId),
}

/// The pairs `reader` may put in a corpus for `corpus_use`, in their order,
/// and how many were left out under each reason code. Everything is read in
/// the export's snapshot `rtxn`.
pub(super) fn admitted_pairs_in(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    reader: &ScopedRead<'_>,
    corpus_use: CorpusUse<'_>,
    pairs: Vec<TrainingPair>,
) -> Result<(Vec<TrainingPair>, BTreeMap<String, u64>)> {
    let mut inputs = Vec::with_capacity(pairs.len());
    for pair in &pairs {
        inputs.push(
            PROPOSAL_ARTIFACT
                .get(&vault.store, rtxn, &pair.receipt_ref)?
                .and_then(|record| record.source_turn_ref),
        );
    }
    // One policy and one held authority judge every source of the corpus.
    let turns = inputs.iter().flatten().copied().collect::<Vec<_>>();
    let readable = reader.entities_readable_in_txn(rtxn, &turns)?;
    let readable = turns.into_iter().zip(readable).collect::<BTreeMap<_, _>>();
    let terms = match corpus_use {
        CorpusUse::OwnerExport => None,
        CorpusUse::TrainingRun { consented_sources } => Some((
            consented_sources.iter().copied().collect::<BTreeSet<_>>(),
            vault.authority_view_readonly_in_txn(rtxn)?,
        )),
    };
    let run = terms.as_ref().map(|(consented, fold)| (consented, &**fold));
    let mut admitted = Vec::with_capacity(pairs.len());
    let mut excluded = BTreeMap::<String, u64>::new();
    for (pair, input) in pairs.into_iter().zip(inputs) {
        match refusal_in(vault, rtxn, &readable, run, input)? {
            None => admitted.push(pair),
            Some(code) => *excluded.entry(code.to_owned()).or_default() += 1,
        }
    }
    Ok((admitted, excluded))
}

/// Why the pair whose input source is `input` stays out, or `None` when it
/// goes in. `run` is a training run's ticked sources and authority fold.
fn refusal_in(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    readable: &BTreeMap<EntityId, bool>,
    run: Option<(&BTreeSet<EntityId>, &AuthorityFold)>,
    input: Option<EntityId>,
) -> Result<Option<&'static str>> {
    let Some(turn) = input else {
        return Ok(None);
    };
    if !readable.get(&turn).copied().unwrap_or(false) {
        return Ok(Some(SOURCE_UNREADABLE));
    }
    let LiveEntityRow::Live { entity_type, .. } =
        live_entity_row_in_txn(&vault.store, rtxn, &turn)?
    else {
        return Ok(Some(SOURCE_UNREADABLE));
    };
    if disclosure_tier(&vault.store, rtxn, &turn, entity_type, None)? == DisclosureTier::TierA {
        return Ok(Some(SOURCE_WITHHELD));
    }
    let Some((consented, fold)) = run else {
        return Ok(None);
    };
    Ok(match source_people_in(vault, rtxn, fold, turn)? {
        SourcePeople::Owner => None,
        SourcePeople::Others(source) | SourcePeople::Unknown(source)
            if consented.contains(&source) =>
        {
            None
        }
        SourcePeople::Others(_) => Some(SOURCE_CONSENT_MISSING),
        SourcePeople::Unknown(_) => Some(SOURCE_PEOPLE_UNKNOWN),
    })
}

/// Who `turn`'s conversation holds: everyone its ledger ever joined, each
/// classed as a room meet classes them, with the vault owner read as the
/// bound owner (`bound_room_party_in`). A room or ledger that cannot be read,
/// or a ledger with no one in it, is unknown.
fn source_people_in(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    turn: EntityId,
) -> Result<SourcePeople> {
    let Ok(room) = crate::conversation_dag::conversation_of(&vault.store, rtxn, &turn) else {
        return Ok(SourcePeople::Unknown(turn));
    };
    let members = match vault.ever_members_in_txn(rtxn, room) {
        Ok(members) if !members.is_empty() => members,
        _ => return Ok(SourcePeople::Unknown(room)),
    };
    for member in members {
        match bound_room_party_in(vault, rtxn, fold, member)? {
            RoomParty::VaultOwner | RoomParty::VaultAgent => {}
            _ => return Ok(SourcePeople::Others(room)),
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
