//! Feed-diff machinery: UID-to-EVENT resolvers, feed-row classifiers, revision
//! filing, and UID-index writes.

use super::*;

/// The one admitted passport on `event` for exactly `(system, uid)` as
/// written. Two admitted heads for one key are refused, never picked by scan
/// order. Its callers key the engine's own invite system, which the claim
/// door masks only where the owner registered the engine's own string as a
/// secret; the move door keys an owner upload's system, which it may mask,
/// through [`admitted_passport_keyed`].
pub(crate) fn admitted_passport_for_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    event: &EntityId,
    system: &str,
    uid: &str,
) -> Result<Option<(EntityId, CalendarPassportValue)>, CalendarError> {
    sole_admitted_head(
        admitted_passports_for_event_in_txn(vault, txn, event)?
            .into_iter()
            .filter(|(_, value)| value.system == system && value.uid == uid),
    )
}

/// The one admitted passport on `event` keyed exactly `(system, uid)` as the
/// vault reads it now: those whose system and UID are `system` and `uid` as
/// written, else those that carry the key as custody reads their system and
/// UID, each where it is pinned ([`MaskedKey`]). The claim door can store an
/// owner upload's system name as a custody handle, so the move door finds
/// the series' passport it amends (CAL-PASSPORT-STORES-NO-SYSTEM-IDENTITY).
/// Two admitted heads for one key are refused, never picked by scan order.
///
/// # Errors
///
/// [`CalendarError::IcsIngest`] on store or stored-claim decode failures and
/// on two heads, and the custody read's.
pub(in crate::calendar) fn admitted_passport_keyed(
    vault: &Vault,
    event: &EntityId,
    system: &str,
    uid: &str,
) -> Result<Option<(EntityId, CalendarPassportValue)>, CalendarError> {
    let written = |value: &CalendarPassportValue| value.system == system && value.uid == uid;
    let (passports, masked) = {
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        let passports = admitted_passports_for_event_in_txn(vault, &txn, event)?;
        if passports.is_empty() || passports.iter().any(|(_, value)| written(value)) {
            return sole_admitted_head(passports.into_iter().filter(|(_, value)| written(value)));
        }
        let masked = MaskedKey::read_in_txn(vault, &txn, event, system, uid)?;
        (passports, masked)
    };
    let base_known = || vault.known_values_now();
    let known = CompareKnown::new(Some(&base_known));
    let mut carried = Vec::new();
    for head in passports {
        if masked.carried_by(&head.1, &known)? {
            carried.push(head);
        }
    }
    sole_admitted_head(carried.into_iter())
}

/// The one head of `heads`, the admitted passports of one key; two are
/// refused.
fn sole_admitted_head(
    mut heads: impl Iterator<Item = (EntityId, CalendarPassportValue)>,
) -> Result<Option<(EntityId, CalendarPassportValue)>, CalendarError> {
    let found = heads.next();
    if heads.next().is_some() {
        return Err(ingest("competing live calendar passports"));
    }
    Ok(found)
}

/// The importer's own pending passports on `event`: live heads an import
/// filed that still wait for the owner's review. The caller picks those of
/// its system: a stored system name may hold a custody handle, which only a
/// custody read outside this reader meets
/// (CAL-MASKED-SYSTEM-LITERAL-COMPARES-OUTSIDE-KEYED-LOOKUP).
///
/// The one exception to the admitted-only rule of
/// [`admitted_passports_for_event_in_txn`] (the lead's ruling 10 Nov 10:3x,
/// FIX CALDAV-PENDING-IMPORT-WRITEBACK-DUPLICATE): the importer's own pending
/// passport may vouch for its own UID when the EVENT is written back to the
/// same calendar, so the write replaces the pulled object rather than adding a
/// second one. Only an imported, Proposed, inbound-bearing passport that its
/// source still reports counts. A rejected, superseded or retracted proposal,
/// an outbound-only passport and another system's passport never do.
///
/// # Errors
///
/// [`CalendarError::IcsIngest`] on store or stored-claim decode failures.
pub(crate) fn importer_pending_passports_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    event: &EntityId,
) -> Result<Vec<(EntityId, CalendarPassportValue)>, CalendarError> {
    let mut values = Vec::new();
    for id in vault.claims_for_subject_in_txn(txn, event)? {
        let Some(body) = vault.get_claim_in_txn(txn, &id)? else {
            continue;
        };
        if body.predicate != PREDICATE_CALENDAR_PASSPORT
            || body.subject != ClaimSubject::Entity(*event)
            || body.lifecycle != ClaimLifecycleStatus::Active
            || body.approval != crate::claim::ClaimApprovalStatus::Proposed
            || body.source != Some(crate::claim::ClaimSource::Imported)
        {
            continue;
        }
        let value = decode_passport_value(&body.value)?;
        if value.direction.is_inbound_bearing() && value.presence == CalendarPassportPresence::Live
        {
            values.push((id, value));
        }
    }
    Ok(values)
}

/// The per-`(system × UID)` diff verdict for one feed row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PassportDecision {
    /// No live passport anywhere carries this UID: mint a new EVENT.
    CreateEvent,
    /// The UID already names an EVENT through another source's passport;
    /// attach this source's passport to it.
    AttachToExisting {
        /// The EVENT the UID index resolved.
        event_ref: EntityId,
    },
    /// Same SEQUENCE and same content hash (or an older SEQUENCE replay):
    /// nothing moves.
    SkipUnchanged {
        /// The EVENT the UID index resolved.
        event_ref: EntityId,
    },
    /// Higher SEQUENCE, same-SEQUENCE content drift, or re-appearance of a
    /// source whose passport was marked absent: supersede the passport.
    UpdateExisting {
        /// The EVENT the UID index resolved.
        event_ref: EntityId,
    },
    /// A complete feed omitted a UID this source previously reported:
    /// supersede only that source's passport with `presence: absent`.
    MarkSourceAbsent {
        /// The EVENT the UID index resolved.
        event_ref: EntityId,
    },
}

/// Resolves one VEVENT UID to its EVENT through the index, repairing the
/// node-local shortcut from synced truth on a stale or missing hit.
///
/// Like [`crate::comm`]'s party resolution, an index miss means "look again",
/// never "absent": the scan walks live passport claims so an EVENT that
/// synced in on another node is still found rather than twinned.
///
/// This is the ingest diff's resolver, so a pending passport vouches for its
/// EVENT: the import gate files its own passports pending review. Only an
/// admitted passport repairs the index, though, because the first outbound
/// invite falls back to that shortcut (`event_ref_for_indexed_uid`).
///
/// # Errors
///
/// [`CalendarError::IcsIngest`] on store or stored-claim decode failures.
pub fn resolve_event_by_uid(vault: &Vault, uid: &str) -> Result<Option<EntityId>, CalendarError> {
    resolve_uid(vault, uid, carries_live_uid, is_live_series_exception)
}

/// Resolves one UID to its EVENT through admitted passports only.
///
/// The authority form of [`resolve_event_by_uid`]: an index hit counts only
/// when an admitted passport on that EVENT carries the UID, and the scan reads
/// only admitted passports. So a pending, rejected or stale proposal never
/// picks the EVENT an outbound invite binds to.
///
/// # Errors
///
/// [`CalendarError::IcsIngest`] on store or stored-claim decode failures.
pub(crate) fn resolve_admitted_event_by_uid(
    vault: &Vault,
    uid: &str,
) -> Result<Option<EntityId>, CalendarError> {
    resolve_uid(
        vault,
        uid,
        carries_admitted_uid,
        is_admitted_series_exception,
    )
}

/// The shared resolver. `vouches` and `detached` read the same authority: a
/// passport that vouches for the UID and an exception claim that excludes a
/// detached instance are judged by one reader, so the two never disagree on
/// which claims count. `vouches` reads a passport's UID as custody reads it
/// only where the UID is pinned to that EVENT ([`uid_pinned_to`]), through
/// one read of the values custody holds, taken once a compare as written
/// misses: the index entry pins the UID to the EVENT it points at, and the
/// scan's EVENTs are pinned only by their own minted UID.
fn resolve_uid(
    vault: &Vault,
    uid: &str,
    vouches: fn(&Vault, &EntityId, &str, &CompareKnown<'_>) -> Result<bool, CalendarError>,
    detached: fn(&Vault, &EntityId) -> Result<bool, CalendarError>,
) -> Result<Option<EntityId>, CalendarError> {
    let base_known = || vault.known_values_now();
    let known = CompareKnown::new(Some(&base_known));
    let digest = passport_digest(uid);
    let indexed = {
        let rtxn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        PASSPORT_INDEX.get(&vault.store, &rtxn, &digest)?
    };
    if let Some(id) = indexed
        && vault.get_entity_type(&id)? == Some(ENTITY_TYPE_EVENT)
        && !detached(vault, &id)?
        && !source_bound(vault, &id)?
        && vouches(vault, &id, uid, &known)?
    {
        return Ok(Some(id));
    }

    // Miss or stale shortcut: synced truth is the set of live passport claims.
    let event_ids = {
        let rtxn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        let mut ids = Vec::new();
        for entry in vault
            .store
            .port_entity_ids_by_type(&rtxn, ENTITY_TYPE_EVENT, None)?
        {
            ids.push(entry?);
        }
        ids
    };
    let mut found: Option<EntityId> = None;
    for event_ref in event_ids {
        if !detached(vault, &event_ref)?
            && !source_bound(vault, &event_ref)?
            && vouches(vault, &event_ref, uid, &known)?
            && found.is_none_or(|current| event_ref.as_bytes() < current.as_bytes())
        {
            // Lexicographically smallest id, so every node converges on the
            // same EVENT when twins exist — the comm.rs convergence rule.
            found = Some(event_ref);
        }
    }
    if let Some(event_ref) = found
        && carries_admitted_uid(vault, &event_ref, uid, &known)?
    {
        index_passport_uid(vault, uid, &event_ref)?;
    }
    Ok(found)
}

/// Whether a pack calendar source binds `event` (FIX 12559): that copy is
/// the source's own, and no UID resolves to it, so an ordinary feed, seat or
/// invite never attaches to a person's private calendar.
fn source_bound(vault: &Vault, event: &EntityId) -> Result<bool, CalendarError> {
    let rtxn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    Ok(crate::source_audience::binding_in(vault, &rtxn, event)?.is_some())
}

/// Classifies one feed row against the current passport state.
///
/// The diff is SEQUENCE-first: a higher SEQUENCE updates; the same SEQUENCE
/// with a drifted content hash updates; the same SEQUENCE with the same hash
/// skips; an *older* SEQUENCE is a stale replay and also skips — a lagging
/// source never regresses passport state. A live passport whose source marked
/// it absent updates back to live on any re-appearance.
///
/// # Errors
///
/// [`CalendarError::IcsIngest`] on store or stored-claim decode failures.
pub fn classify_passport(
    vault: &Vault,
    system: &str,
    uid: &str,
    sequence: u32,
    content_hash: [u8; 32],
) -> Result<PassportDecision, CalendarError> {
    let Some(event_ref) = resolve_event_by_uid(vault, uid)? else {
        return Ok(PassportDecision::CreateEvent);
    };
    classify_event_passport(vault, event_ref, system, uid, sequence, content_hash)
}

pub(in crate::calendar) fn classify_event_passport(
    vault: &Vault,
    event_ref: EntityId,
    system: &str,
    uid: &str,
    sequence: u32,
    content_hash: [u8; 32],
) -> Result<PassportDecision, CalendarError> {
    let Some((_, current)) = live_passport_for(vault, &event_ref, system, uid)? else {
        return Ok(PassportDecision::AttachToExisting { event_ref });
    };
    if current.presence == CalendarPassportPresence::Absent
        || sequence > current.last_sequence
        || (sequence == current.last_sequence && content_hash != current.content_hash)
    {
        return Ok(PassportDecision::UpdateExisting { event_ref });
    }
    Ok(PassportDecision::SkipUnchanged { event_ref })
}

/// What filing a passport revision did to the admitted head of its
/// `(system × UID)` ([`revise_passport_in_txn`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassportRevision {
    /// No admitted passport carried the key: the revision replaced only
    /// waiting or rejected filings, and nothing had authority to keep.
    NoAdmittedHead,
    /// The revision landed admitted and closed the admitted head at once.
    HeadClosed,
    /// The revision waits for review: the head's closure is staged, and the
    /// owner's approval of the revision completes it in the approving write.
    HeadStaged,
}

/// Files `new_id` as the next revision of `(system × UID)` on `event_ref`,
/// against the live passports it replaces (ARCH-0060 §3: only an admitted
/// passport carries authority, and a pending or rejected proposal can neither
/// block a revision nor steer it).
///
/// A revision still waiting for review carries no authority: `new_id`
/// supersedes it at once, and drops the closure it had staged and the tray
/// item that asked the owner about it. A rejected revision stays on record as
/// it is: a Reject is final, and no lifecycle transition may follow it. The
/// admitted head closes only when `new_id` is admitted. A proposed `new_id`
/// stages that closure (`DeferredAction::Supersede`): the owner's approval of
/// `new_id` completes it in the approving write, and a rejection drops it, so
/// the head keeps its authority while the revision waits and after it is
/// rejected. A `new_id` that landed admitted closes the head at once. Answers
/// what the filing did to the admitted head, or `None` when no live passport,
/// rejected ones included, carried the key.
///
/// # Errors
///
/// [`CalendarError::IcsIngest`] when two admitted heads carry the key, or on
/// store failures.
pub(in crate::calendar) fn revise_passport_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    event_ref: &EntityId,
    system: &str,
    uid: &str,
    new_id: &EntityId,
    now: u64,
) -> Result<Option<PassportRevision>, CalendarError> {
    let (found, head, waiting) = {
        let reader: &heed::RwTxn<'_> = txn;
        let mut keyed = Vec::new();
        for claim_id in vault.claims_for_subject_in_txn(reader, event_ref)? {
            if claim_id == *new_id {
                continue;
            }
            let Some(body) = vault.get_claim_in_txn(reader, &claim_id)? else {
                continue;
            };
            if body.predicate != PREDICATE_CALENDAR_PASSPORT
                || body.subject != ClaimSubject::Entity(*event_ref)
                || body.lifecycle != ClaimLifecycleStatus::Active
            {
                continue;
            }
            let value = decode_passport_value(&body.value)
                .map_err(|_| ingest("stored passport claim did not decode"))?;
            keyed.push((claim_id, body, value));
        }
        // The key as written first; only when no claim carries it so are a
        // stored system and UID read as custody reads them, each where it is
        // pinned ([`MaskedKey`]): a masked passport the head of the scoped
        // lookup reads is the one revised (blind review round 2 of #10090,
        // CAL-PASSPORT-SYSTEM-UID-LOOKUP-MISSES-MASKED-PASSPORT).
        let exact = |value: &CalendarPassportValue| value.system == system && value.uid == uid;
        if keyed.iter().any(|(_, _, value)| exact(value)) {
            keyed.retain(|(_, _, value)| exact(value));
        } else if !keyed.is_empty() {
            let base_known = || KnownValues::shared_in_writer(&vault.store, reader);
            let known = CompareKnown::new(Some(&base_known));
            let masked = MaskedKey::read_in_txn(vault, reader, event_ref, system, uid)?;
            let mut carried = Vec::new();
            for entry in keyed {
                if masked.carried_by(&entry.2, &known)? {
                    carried.push(entry);
                }
            }
            keyed = carried;
        }
        let mut head = None;
        let mut waiting = Vec::new();
        for (claim_id, body, _) in &keyed {
            if passport_admitted_in_txn(vault, reader, claim_id, body)? {
                if head.replace(*claim_id).is_some() {
                    return Err(ingest("competing live calendar passports"));
                }
            } else if body.approval != ClaimApprovalStatus::Rejected {
                waiting.push(*claim_id);
            }
        }
        (!keyed.is_empty(), head, waiting)
    };
    // Before `new_id` stages a closure of its own: a staged replacement
    // closes nothing without its grant.
    for old in waiting {
        vault.cancel_deferred_claim_in_txn(txn, &old)?;
        // The owner is asked about `new_id` instead. The item's binding names
        // the open revision, so an Allow close would read it as stale.
        vault.store.close_pending_gate_consent_as_in_txn(
            txn,
            &old,
            crate::store::gate_reason::GateReceiptOutcome::Superseded,
            vec![REVISION_REPLACED_REASON.to_owned()],
            None,
            crate::store::TrayRemoval::Silent,
        )?;
        vault.supersede_claim_in_txn(txn, new_id, &old, now)?;
    }
    if !found {
        return Ok(None);
    }
    let Some(head) = head else {
        return Ok(Some(PassportRevision::NoAdmittedHead));
    };
    let landed = vault
        .get_claim_in_txn(txn, new_id)?
        .is_some_and(|body| claim_surfaceable(&body));
    if landed {
        vault.supersede_claim_in_txn(txn, new_id, &head, now)?;
        Ok(Some(PassportRevision::HeadClosed))
    } else {
        vault.stage_stored_claim_supersession_in_txn(txn, new_id, &head, now)?;
        Ok(Some(PassportRevision::HeadStaged))
    }
}

/// Points the UID index at `event_ref`. Called when a passport is minted;
/// resolution repairs it on every other path.
///
/// # Errors
///
/// [`CalendarError::IcsIngest`] on store failure.
pub fn index_passport_uid(
    vault: &Vault,
    uid: &str,
    event_ref: &EntityId,
) -> Result<(), CalendarError> {
    vault.try_with_write_txn_grouped(|txn| index_passport_uid_in_txn(vault, txn, uid, event_ref))
}

pub(in crate::calendar) fn index_passport_uid_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    uid: &str,
    event_ref: &EntityId,
) -> Result<(), CalendarError> {
    PASSPORT_INDEX.put(&vault.store, txn, &passport_digest(uid), event_ref)?;
    Ok(())
}
