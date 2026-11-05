//! Foreign expression histories restored by their owning source-aware writer.
//! Archive evidence is data, never a local actor, grant, or provenance stamp.

use std::collections::{BTreeMap, BTreeSet};

use super::expression_preference::{ExpressionPreferenceWrite, ExpressionWriteOrigin};
use super::*;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};

/// Binding proof tying a restored foreign expression-preference claim to the exact local row it
/// reconstructed. Key: id16.
const ARCHIVE_BINDING: SideTable<EntityId, Vec<u8>, Raw> =
    SideTable::new(&side_table::EXPRESSION_ARCHIVE_BINDING);

/// An untrusted archived row plus an explicitly mapped local subject.
pub(crate) struct ArchivedExpressionPreference {
    pub(crate) id: EntityId,
    pub(crate) body: ClaimBody,
    pub(crate) subject: EntityId,
    pub(crate) occurred: TimeRange,
    pub(crate) learned_at: u64,
}

/// A complete archived history for exactly one subject/predicate, in the
/// shapes the native writer leaves: mixed sources under source precedence,
/// same-second closes, retracted heads, and several live heads at once.
/// The rows alone do not say which head closed which, so the archived
/// Supersedes links among them are part of the history.
pub(crate) struct ExpressionPreferenceArchive {
    rows: Vec<ArchivedExpressionPreference>,
    /// Every archived Supersedes link among `rows`: (closer, closed, at).
    links: Vec<(EntityId, EntityId, u64)>,
    /// The close each Superseded row stands in, ordered so every closer is
    /// still active when its close is applied: (closer, closed, at).
    closes: Vec<(EntityId, EntityId, u64)>,
}

impl ExpressionPreferenceArchive {
    pub(crate) fn new(
        mut rows: Vec<ArchivedExpressionPreference>,
        links: Vec<(EntityId, EntityId, u64)>,
    ) -> Result<Self> {
        rows.sort_by_key(|row| (row.learned_at, row.id));
        let first = rows.first().ok_or_else(|| invalid("empty history"))?;
        for row in &rows {
            let body = &row.body;
            // Revalidate even at this crate-private door. Never normalize away
            // scope, demotion or a parked consent that the native writer cannot replay.
            decode_claim_body(&encode_claim_body(body)?, false)?;
            if !is_expression_preference_predicate(&body.predicate)
                || row.subject != first.subject
                || body.subject != first.body.subject
                || body.predicate != first.body.predicate
                || !matches!(
                    body.source,
                    Some(ClaimSource::UserStated | ClaimSource::Inferred | ClaimSource::Imported)
                )
                || body.approval != ClaimApprovalStatus::Auto
                || body.confidence != 1.0
                || body.valid_from.is_none()
                || body.salience.is_some()
                || body.world.is_some()
                || body.rel.is_some()
                || body.scope.is_some()
                || body.session_tag.is_some()
                || body.stale
            {
                return Err(invalid("unsupported native history shape"));
            }
            // Each lifecycle stands as its native transition leaves it: a
            // supersede closes at its `now` (the end never before the
            // start), a retract at its own.
            let closed = match body.lifecycle {
                ClaimLifecycleStatus::Active => body.valid_to.is_none(),
                ClaimLifecycleStatus::Superseded => body
                    .valid_to
                    .is_some_and(|at| row.occurred.end == at.max(row.occurred.start)),
                ClaimLifecycleStatus::Retracted => body
                    .valid_to
                    .is_some_and(|at| row.occurred.end == at && at >= row.occurred.start),
            };
            if !closed {
                return Err(invalid("row does not stand as its lifecycle leaves it"));
            }
        }
        let by_id: BTreeMap<EntityId, &ArchivedExpressionPreference> =
            rows.iter().map(|row| (row.id, row)).collect();
        if by_id.len() != rows.len() {
            return Err(invalid("duplicate row in history"));
        }
        let mut pairs = BTreeSet::new();
        for &(closer, closed, _) in &links {
            if closer == closed
                || !by_id.contains_key(&closer)
                || !by_id.contains_key(&closed)
                || !pairs.insert((closer, closed))
            {
                return Err(invalid("supersession link outside the history"));
            }
        }
        // A Superseded row stands closed by the link minted at its
        // `valid_to`. A retracted closer is impossible: the family retract
        // restores its direct predecessors, so none stands closed by it.
        let mut closes = Vec::new();
        for row in &rows {
            if row.body.lifecycle != ClaimLifecycleStatus::Superseded {
                continue;
            }
            let at = row
                .body
                .valid_to
                .ok_or_else(|| invalid("superseded row has no close"))?;
            // REVIEW-4378 P1: several closers for one row at one time is
            // the branching-ambiguous shape this history refuses: require
            // exactly one eligible closer, never silently keep the max.
            // Blind-review P1 (round 2): a Retracted closer is a retained
            // historical edge, never a standing close — exclude it before
            // the uniqueness check (its link stays exempt below). A row
            // whose only closer is retracted still refuses: a retracted row
            // closes no standing row.
            let mut matching: Vec<EntityId> = links
                .iter()
                .filter(|&(_, closed, link_at)| *closed == row.id && *link_at == at)
                .map(|&(closer, _, _)| closer)
                .filter(|closer| by_id[closer].body.lifecycle != ClaimLifecycleStatus::Retracted)
                .collect();
            matching.sort();
            matching.dedup();
            let &[closer] = matching.as_slice() else {
                return Err(invalid("superseded row has no unique archived closer"));
            };
            closes.push((closer, row.id, at));
        }
        // REVIEW-4378 P1: every archived link must take effect as a
        // selected close. A link whose closed row stands Active (a
        // reciprocal pair, a never-applied edge) restores branching/cyclic
        // history the edge import would then whitelist, so refuse it here.
        // Blind-review P1: a link whose closer stands Retracted is a
        // retained historical edge whose effect the retraction undid, so it
        // takes no standing effect and is exempt. Cycles and standing
        // closes still validate on the effective set above and below.
        if !links.iter().all(|link| {
            closes.contains(link)
                || by_id[&link.0].body.lifecycle == ClaimLifecycleStatus::Retracted
        }) {
            return Err(invalid("supersession link takes no archived effect"));
        }
        // Blind-review P1 (round 2): the historical-edge exemption above
        // must not smuggle cycles — two retracted rows with reciprocal
        // links leave `closes` empty and would replay the cycle. Check
        // acyclicity over ALL archived links, retracted closers included,
        // separately from ordering the effective closes below.
        let mut pending_all: Vec<(EntityId, EntityId)> = links
            .iter()
            .map(|&(closer, closed, _)| (closer, closed))
            .collect();
        while !pending_all.is_empty() {
            let Some(at) = pending_all
                .iter()
                .position(|&(_, closed)| !pending_all.iter().any(|&(closer, _)| closer == closed))
            else {
                return Err(invalid("cyclic supersession history"));
            };
            pending_all.remove(at);
        }
        // A closer must still be active when its close lands, so a row
        // closes before the close that closes it. No such order, no history.
        let mut ordered = Vec::with_capacity(closes.len());
        let mut pending = closes;
        while !pending.is_empty() {
            let Some(at) = pending.iter().position(|&(_, closed, _)| {
                !pending.iter().any(|&(closer, _, _)| closer == closed)
            }) else {
                return Err(invalid("cyclic supersession history"));
            };
            ordered.push(pending.remove(at));
        }
        Ok(Self {
            rows,
            links,
            closes: ordered,
        })
    }

    pub(crate) fn ids(&self) -> impl Iterator<Item = EntityId> + '_ {
        self.rows.iter().map(|row| row.id)
    }

    pub(crate) fn supersessions(&self) -> impl Iterator<Item = (EntityId, EntityId, u64)> + '_ {
        self.links.iter().copied()
    }

    /// Caller must abort the WHOLE transaction on any error. No JSON field is
    /// accepted as a local repeat binding or a claim-materialization capability.
    pub(crate) fn restore_in_txn(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        actor: &WriteActor,
    ) -> Result<(usize, usize)> {
        let mut existing_count = 0;
        for row in &self.rows {
            if vault.store.off_record_sessions.contains_entity(&row.id)? {
                return Err(invalid("ID belongs to an off-record overlay"));
            }
            if let Some(raw) =
                crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &row.id)?
            {
                if !crate::vault::live_entity_row_in_txn(&vault.store, txn, &row.id)?.is_live() {
                    return Err(invalid("ID collides with a deleted entity"));
                }
                let expected = binding(row, &raw)?;
                if ARCHIVE_BINDING.get(&vault.store, txn, &row.id)? != Some(expected) {
                    return Err(invalid("ID collision or locally changed restore result"));
                }
                existing_count += 1;
            } else if ARCHIVE_BINDING.contains(&vault.store, txn, &row.id)? {
                return Err(invalid("restore binding has no live result"));
            }
        }
        // An overlap is not proof that the missing segment belongs to this
        // history. In particular, never reopen a previously closed generation.
        if existing_count != 0 && existing_count != self.rows.len() {
            return Err(invalid("partial history overlaps existing local rows"));
        }
        if existing_count == 0 {
            // Every row lands first, closing nothing: uniform Imported
            // precedence cannot re-derive who closed whom. The archived
            // closes and retracts then land through the same lifecycle
            // doors the native writer uses, at their archived times.
            for row in &self.rows {
                let result = vault.write_expression_preference_in_txn(
                    txn,
                    actor,
                    row.id,
                    &write_spec(row)?,
                    row.occurred,
                    row.learned_at,
                )?;
                if !result.superseded_claim_ids.is_empty() {
                    return Err(invalid("replay write closed a head on its own"));
                }
            }
            for &(closer, closed, at) in &self.closes {
                vault.supersede_claim_in_txn(txn, &closer, &closed, at)?;
            }
            for row in &self.rows {
                if row.body.lifecycle == ClaimLifecycleStatus::Retracted {
                    let at = row
                        .body
                        .valid_to
                        .ok_or_else(|| invalid("retracted row has no close"))?;
                    vault.retract_claim_in_txn(txn, &row.id, at)?;
                }
            }
        }
        // Only source and provenance change. Lifecycle, validity and header
        // times must be reconstructed exactly by the native transitions.
        for row in &self.rows {
            let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &row.id)?
                .ok_or(Error::EntityNotFound)?;
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("expression archive header"))?;
            let actual = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], false)?;
            let mut expected = row.body.clone();
            expected.subject = ClaimSubject::Entity(row.subject);
            expected.source = Some(ClaimSource::Imported);
            expected.evidence = actual.evidence.clone();
            expected.scope_facet = vault.default_facet_in_txn(txn)?;
            if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
                || header.occurred_start != row.occurred.start
                || header.occurred_end != row.occurred.end
                || header.learned_at != row.learned_at
                || actual != expected
            {
                return Err(invalid("final lifecycle or body not reconstructed"));
            }
            if existing_count == 0 {
                let encoded = binding(row, &raw)?;
                ARCHIVE_BINDING.put(&vault.store, txn, &row.id, &encoded)?;
            }
        }
        Ok((self.rows.len() - existing_count, existing_count))
    }
}

fn write_spec(row: &ArchivedExpressionPreference) -> Result<ExpressionPreferenceWrite> {
    let value = row
        .body
        .value
        .as_str()
        .ok_or_else(|| invalid("value is not a string"))?;
    let value = match (row.body.predicate.as_str(), value) {
        (PREDICATE_COMPANION_EXPRESSION_LANGUAGE, value) => {
            ExpressionPreferenceValue::Language(value.to_owned())
        }
        (PREDICATE_COMPANION_EXPRESSION_STYLE, value) => {
            ExpressionPreferenceValue::Style(value.to_owned())
        }
        (PREDICATE_COMPANION_EXPRESSION_REGISTER, "casual") => {
            ExpressionPreferenceValue::Register(ExpressionRegister::Casual)
        }
        (PREDICATE_COMPANION_EXPRESSION_REGISTER, "neutral") => {
            ExpressionPreferenceValue::Register(ExpressionRegister::Neutral)
        }
        (PREDICATE_COMPANION_EXPRESSION_REGISTER, "formal") => {
            ExpressionPreferenceValue::Register(ExpressionRegister::Formal)
        }
        (PREDICATE_COMPANION_EXPRESSION_KEIGO, "none") => {
            ExpressionPreferenceValue::Keigo(ExpressionKeigo::None)
        }
        (PREDICATE_COMPANION_EXPRESSION_KEIGO, "teineigo") => {
            ExpressionPreferenceValue::Keigo(ExpressionKeigo::Teineigo)
        }
        (PREDICATE_COMPANION_EXPRESSION_KEIGO, "sonkeigo") => {
            ExpressionPreferenceValue::Keigo(ExpressionKeigo::Sonkeigo)
        }
        (PREDICATE_COMPANION_EXPRESSION_KEIGO, "kenjogo") => {
            ExpressionPreferenceValue::Keigo(ExpressionKeigo::Kenjogo)
        }
        (PREDICATE_COMPANION_EXPRESSION_KEIGO, "adaptive") => {
            ExpressionPreferenceValue::Keigo(ExpressionKeigo::Adaptive)
        }
        _ => return Err(invalid("invalid expression value")),
    };
    Ok(ExpressionPreferenceWrite {
        subject: row.subject,
        value,
        valid_from: row
            .body
            .valid_from
            .ok_or_else(|| invalid("missing validity start"))?,
        origin: ExpressionWriteOrigin::Imported,
        replay: true,
    })
}

fn binding(row: &ArchivedExpressionPreference, actual: &[u8]) -> Result<Vec<u8>> {
    let mut archive = blake3::Hasher::new();
    archive.update(row.id.as_bytes());
    archive.update(&row.occurred.start.to_be_bytes());
    archive.update(&row.occurred.end.to_be_bytes());
    archive.update(&row.learned_at.to_be_bytes());
    archive.update(&encode_claim_body(&row.body)?);
    let mut result = archive.finalize().as_bytes().to_vec();
    // Include the actual header as well as body, so a later local lifecycle
    // edit invalidates the binding even if only its end timestamp changes.
    result.extend_from_slice(blake3::hash(actual).as_bytes());
    Ok(result)
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("expression preference archive: {reason}"))
}
