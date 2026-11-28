//! Rebuilds the local dependency registrations of an own-vault scope SUMMARY or PSYCH_PROFILE put
//! (PR3 of [PORT-ONLY-DEPENDENCY-NOT-REPLICATED]).
//!
//! Each body names the sources its words came from, the sources its writer registers: a scope
//! SUMMARY its `covers` and `messages` (`scope_summary::doors::word_sources`, at the mint), a
//! PSYCH_PROFILE each source's `document_ref` (`derive::artifact`, at its landing). Each takes the
//! rule of a CLAIM's non-locator source (PR2-DEEP-DOC-ROOT-ORDER = A, 28 Nov): the row is never
//! held; a source this device can resolve is registered, resident at its header or listed at its
//! listing; deletion evidence marks the row stale; any other absent source, on every device, gets
//! a cold-citation row, and the row lands readable. A source that lands later is judged at its
//! landing (`replicated_sources::register_arrived_source_in_txn`). A peer's copy keeps today's
//! rule, and a self-source is skipped, as the writer's dependency index refuses one.
//!
//! A PSYCH_PROFILE is derived again at the same id. Each version replaces the previous version's
//! registrations, as on its writer, and a newer version completes the regeneration of a profile a
//! deletion withdrew through the writer's own fence (`ports/regeneration.rs`; ASK
//! PR3-PROFILE-REGEN-OVER-STALE, 28 Nov 16:27).

use super::IngestCtx;
use crate::EntityId;
use crate::batch::EntityMetadataHeader;
use crate::dreamer_consolidation::replicated_sources::{
    SourceStanding, mark_dependent_stale_in_txn, resolve_dependent_source_in_txn,
};
use crate::error::{Error, Result};
use crate::ports::{DependencyIndex, EntityStoreRead, SourceSpan};
use crate::registry::{ENTITY_TYPE_PSYCH_PROFILE, ENTITY_TYPE_SUMMARY};
use crate::store::{ManifestDbs, Store};
use crate::vault::Vault;
use std::collections::BTreeSet;

/// A row kind whose body names its sources.
enum Dependent {
    ScopeSummary,
    PsychProfile,
}

/// The learned-at of the version of a scope SUMMARY or PSYCH_PROFILE this device holds, read
/// before a put replaces it; `None` for any other kind and for a row not held.
pub(super) fn held_learned_at_in_txn(
    ctx: &IngestCtx<'_>,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
) -> Result<Option<u64>> {
    if entity_type != ENTITY_TYPE_SUMMARY && entity_type != ENTITY_TYPE_PSYCH_PROFILE {
        return Ok(None);
    }
    Ok(ctx
        .vault
        .store
        .entities()
        .get(txn, id.as_bytes())?
        .and_then(EntityMetadataHeader::parse)
        .map(|header| header.learned_at))
}

/// Registers the sources an own-vault scope SUMMARY or PSYCH_PROFILE put names, once the put has
/// applied. The version judged is the one this device holds after the put. A version older than
/// the one held before the put (`held_before`) changes nothing: the registrations and the stale
/// mark stay those of the newer version, whatever order the versions arrive in
/// (PR3-PROFILE-REGEN-OVER-STALE = A, condition 3). Any other row, and a peer's copy, is left as
/// it is.
pub(super) fn register_in_txn(
    ctx: &IngestCtx<'_>,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    header: &EntityMetadataHeader,
    blob: &[u8],
    held_before: Option<u64>,
) -> Result<()> {
    if header.entity_type != ENTITY_TYPE_SUMMARY && header.entity_type != ENTITY_TYPE_PSYCH_PROFILE
    {
        return Ok(());
    }
    let store = &ctx.vault.store;
    let Some(row) = store.port_entity_record(wtxn, id)? else {
        return Ok(());
    };
    if held_before.is_some_and(|held| row.learned_at < held) {
        return Ok(());
    }
    let Some((dependent, sources)) =
        body_sources_in_txn(store, wtxn, id, row.entity_type, &row.body)?
    else {
        return Ok(());
    };
    if super::peer_import::peer_row_in_txn(ctx.vault, wtxn, ctx.window_key, id, blob)? {
        return Ok(());
    }
    let carrier_deleted =
        super::claim_source_tombstones::proven_carrier_deletions_of_in_txn(ctx, wtxn, &sources)?;
    match dependent {
        Dependent::ScopeSummary => {
            register_summary_sources_in_txn(store, wtxn, id, &sources, &carrier_deleted)
        }
        Dependent::PsychProfile => register_profile_sources_in_txn(
            ctx.vault,
            wtxn,
            id,
            row.learned_at,
            &sources,
            &carrier_deleted,
        ),
    }
}

/// The sources a scope SUMMARY or PSYCH_PROFILE `body` names, without `id` itself. `None` for any
/// other row, for a body that does not decode (its put judged it already), and for a profile of
/// an earlier schema, whose sources name no record.
fn body_sources_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    body: &[u8],
) -> Result<Option<(Dependent, BTreeSet<EntityId>)>> {
    let (dependent, mut sources) = if entity_type == ENTITY_TYPE_SUMMARY
        && oneiron_store::scope_summary::codec::is_scope_summary(body)
    {
        let logical = crate::entity_doc::resolve_record_body(store, txn, id, body)?;
        let Ok(summary) = crate::scope_summary::decode_scope_summary_body(&logical) else {
            return Ok(None);
        };
        let sources = summary
            .covers
            .iter()
            .copied()
            .chain(summary.messages.iter().map(|message| message.id))
            .collect::<BTreeSet<_>>();
        (Dependent::ScopeSummary, sources)
    } else if entity_type == ENTITY_TYPE_PSYCH_PROFILE {
        let Ok(profile) = crate::psych_profile::decode_psych_profile_body(body) else {
            return Ok(None);
        };
        let sources = profile
            .sources
            .iter()
            .map(|source| source.document_ref)
            .collect::<BTreeSet<_>>();
        (Dependent::PsychProfile, sources)
    } else {
        return Ok(None);
    };
    sources.remove(id);
    Ok(Some((dependent, sources)))
}

/// A scope SUMMARY's sources: each mint is a new id, so each landing only adds what it resolves.
fn register_summary_sources_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    summary: &EntityId,
    sources: &BTreeSet<EntityId>,
    carrier_deleted: &BTreeSet<EntityId>,
) -> Result<()> {
    let mut withdrawn = false;
    for source in sources {
        match resolve_dependent_source_in_txn(
            store,
            txn,
            summary,
            source,
            carrier_deleted.contains(source),
        )? {
            SourceStanding::Deleted => withdrawn = true,
            SourceStanding::Registered => {}
            SourceStanding::Unresolved => {
                crate::sync::residence::put_cold_citation_in_txn(store, txn, summary, source)?
            }
        }
    }
    if withdrawn {
        mark_dependent_stale_in_txn(store, txn, summary)?;
    }
    Ok(())
}

/// A PSYCH_PROFILE's sources, as `derive::artifact::land_profile_in_txn` lands them on its writer:
/// this version's resident sources at their headers either complete the regeneration of a
/// profile a deletion withdrew, or replace the previous version's registrations. Listed sources
/// register at their listing and absent ones take a cold-citation row, which replaces the previous
/// version's. A source with deletion evidence withdraws this version, and nothing completes.
fn register_profile_sources_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    profile: &EntityId,
    learned_at: u64,
    sources: &BTreeSet<EntityId>,
    carrier_deleted: &BTreeSet<EntityId>,
) -> Result<()> {
    let store = &vault.store;
    crate::sync::residence::delete_cold_citations_of_dependent_in_txn(store, txn, profile)?;
    let mut withdrawn = false;
    let mut resident = Vec::new();
    let mut listed = Vec::new();
    let mut cold = Vec::new();
    for source in sources {
        if carrier_deleted.contains(source)
            || crate::ports::source_deleted_or_withdrawn_in_txn(store, txn, source)?
        {
            withdrawn = true;
        } else if let Some(raw) = store.entities().get(txn, source.as_bytes())? {
            let frontier = EntityMetadataHeader::parse(raw)
                .map(|header| header.learned_at)
                .ok_or(Error::CorruptedIndex("dependency source header"))?;
            resident.push(SourceSpan {
                document: *source,
                frontier,
            });
        } else if crate::sync::residence::index_listing_of_item_in_txn(
            store,
            txn,
            &source.to_hex(),
        )?
        .is_some()
        {
            listed.push(*source);
        } else {
            cold.push(*source);
        }
    }
    let regenerated = !withdrawn
        && vault.port_dependency_complete_regeneration(txn, profile, learned_at, &resident)?;
    if !regenerated {
        crate::ports::remove_dependency_rows_for_dependent_in_txn(store, txn, profile)?;
        for span in &resident {
            crate::ports::record_dependency_in_txn(store, txn, *span, profile)?;
        }
    }
    for source in &listed {
        crate::ports::record_index_listed_dependency_in_txn(store, txn, source, profile)?;
    }
    for source in &cold {
        crate::sync::residence::put_cold_citation_in_txn(store, txn, profile, source)?;
    }
    if withdrawn {
        mark_dependent_stale_in_txn(store, txn, profile)?;
    }
    Ok(())
}
