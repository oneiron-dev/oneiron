//! Alias-aware communication membership. Source events and claims keep their
//! original references; projection and contact reads use one canonical slot.
use super::*;

pub(super) fn canonical_member_ref<'a>(
    aliases: &'a BTreeMap<String, String>,
    thread: &'a str,
) -> &'a str {
    aliases.get(thread).map_or(thread, String::as_str)
}

pub(super) fn equivalent_thread_keys(
    key: &PartyThreadKey,
    aliases: &BTreeMap<String, String>,
) -> Vec<PartyThreadKey> {
    let canonical = canonical_member_ref(aliases, &key.thread_ref);
    std::iter::once(canonical.to_owned())
        .chain(
            aliases
                .iter()
                .filter(|(_, target)| target.as_str() == canonical)
                .map(|(source, _)| source.clone()),
        )
        .map(|thread_ref| PartyThreadKey {
            party_ref: key.party_ref,
            thread_ref,
        })
        .collect()
}

pub(super) fn matching_thread_memberships_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    party_ref: EntityId,
    thread_ref: Option<&str>,
    active_only: bool,
) -> CommResult<Vec<(EntityId, CommClaim)>> {
    let Some(thread_ref) = thread_ref else {
        return Ok(Vec::new());
    };
    let mut boundary = None;
    if active_only {
        let aliases = crate::thread_passport::thread_aliases_in_txn(vault, rtxn)?;
        let canonical = canonical_member_ref(&aliases, thread_ref);
        // Only merged slots need cross-root source boundaries. For an
        // unaliased thread the standing claims remain authoritative, preserving
        // ordinary membership reads without a COMM_RECORD family scan.
        if !aliases.values().any(|target| target == canonical) {
            return matching_thread_membership_with_boundary_in_txn(
                vault, rtxn, party_ref, thread_ref, true, None,
            );
        }
        // Read APIs fold the current source-event union. The projector instead
        // supplies its existing pass index plus re-read peer boundaries below.
        for (_, record) in comm_records_in_txn(vault, rtxn)? {
            if let CommRecord::Event {
                kind,
                party_ref: owner,
                thread_ref: Some(thread),
                occurred_at,
                projected: true,
                ..
            } = record
                && owner == party_ref
                && canonical_member_ref(&aliases, &thread) == canonical
                && matches!(
                    kind,
                    CommEventKind::ThreadJoined | CommEventKind::ThreadLeft
                )
            {
                boundary = boundary.max(Some((occurred_at, kind == CommEventKind::ThreadLeft)));
            }
        }
    }
    matching_thread_membership_with_boundary_in_txn(
        vault,
        rtxn,
        party_ref,
        thread_ref,
        active_only,
        boundary,
    )
}

fn matching_thread_membership_with_boundary_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    party_ref: EntityId,
    thread_ref: &str,
    active_only: bool,
    mut boundary: Option<(u64, bool)>,
) -> CommResult<Vec<(EntityId, CommClaim)>> {
    let aliases = crate::thread_passport::thread_aliases_in_txn(vault, rtxn)?;
    let canonical = canonical_member_ref(&aliases, thread_ref);
    let mut rows = Vec::new();
    for id in vault.claims_for_subject_in_txn(rtxn, &party_ref)? {
        let Some(body) = vault.get_claim_in_txn(rtxn, &id)? else {
            continue;
        };
        if body.predicate != PREDICATE_COMM_THREAD_MEMBER {
            continue;
        }
        let claim = CommClaim::from_claim_body(&body)?;
        let CommClaimValue::ThreadMember { thread_ref, .. } = &claim.value else {
            unreachable!("thread predicate")
        };
        if canonical_member_ref(&aliases, thread_ref) == canonical {
            rows.push((id, claim));
        }
    }
    if !active_only {
        return Ok(rows);
    }
    // Fold the UNION of old slots. A leave without a claim is still a
    // boundary. Restrictive wins equal timestamps, independent of arrival.
    for (_, claim) in &rows {
        let stamp = if claim.is_standing() {
            claim.valid_from.map(|at| (at, false))
        } else {
            claim.valid_to.map(|at| (at, true))
        };
        boundary = boundary.max(stamp);
    }
    if boundary.is_some_and(|(_, left)| left) {
        return Ok(Vec::new());
    }
    rows.retain(|(_, claim)| claim.is_standing());
    // Physical heads stay history; logical membership is one representative.
    rows.sort_by_key(|(id, claim)| (std::cmp::Reverse(claim.valid_from), *id));
    rows.truncate(1);
    Ok(rows)
}

pub(super) fn active_thread_refs_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    party_ref: EntityId,
) -> CommResult<BTreeSet<String>> {
    let aliases = crate::thread_passport::thread_aliases_in_txn(vault, rtxn)?;
    let mut candidates = BTreeSet::new();
    for id in vault.claims_for_subject_in_txn(rtxn, &party_ref)? {
        let Some(body) = vault.get_claim_in_txn(rtxn, &id)? else {
            continue;
        };
        if body.predicate == PREDICATE_COMM_THREAD_MEMBER
            && let CommClaimValue::ThreadMember { thread_ref, .. } =
                CommClaim::from_claim_body(&body)?.value
        {
            candidates.insert(canonical_member_ref(&aliases, &thread_ref).to_owned());
        }
    }
    let mut active = BTreeSet::new();
    for thread in candidates {
        if !matching_thread_memberships_in_txn(vault, rtxn, party_ref, Some(&thread), true)?
            .is_empty()
        {
            active.insert(thread);
        }
    }
    Ok(active)
}

pub(super) fn apply_thread_membership_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    index: &CommProjectorIndex,
    event: &ProjectedCommEvent<'_>,
) -> CommResult<ProjectorIndexDelta> {
    let &ProjectedCommEvent {
        rule,
        source_event_id,
        party_ref,
        thread_ref,
        occurred_at,
        ..
    } = event;
    let aliases = crate::thread_passport::thread_aliases_in_txn(vault, wtxn)?;
    match rule.action {
        ProjectorAction::JoinThread => {
            let raw_thread = thread_ref.ok_or(CommError::InvalidRecord)?;
            let thread = canonical_member_ref(&aliases, raw_thread);
            let key = PartyThreadKey {
                party_ref,
                thread_ref: thread.to_owned(),
            };
            // A peer pass may already have committed a same-key snapshotted
            // join/leave still AHEAD of this pass's cursor. That boundary must
            // bound THIS decision — folding it index-only when the pass later
            // reaches that event's own id cannot retract a claim minted now.
            let peer_transition = index.peer_projected_thread_transition_in_txn(
                vault,
                &*wtxn,
                &key,
                source_event_id,
            )?;
            let active = matching_thread_membership_with_boundary_in_txn(
                vault,
                wtxn,
                party_ref,
                thread,
                true,
                index
                    .latest_thread_boundary(&key, &aliases)
                    .max(peer_transition),
            )?;
            require_at_most_one(&active)?;
            if active.is_empty() {
                let history = matching_thread_membership_with_boundary_in_txn(
                    vault, wtxn, party_ref, thread, false, None,
                )?;
                let latest_transition = latest_claim_transition_boundary(&history)
                    .max(index.latest_thread_transition(&key, &aliases))
                    .max(peer_transition.map(|(at, _)| at));
                // The derived id includes this value's thread key. Keep the
                // immutable source reference so replicas projecting before and
                // after a bridge author the same claim, not two different ids.
                // Lookups above still use the current canonical membership slot.
                let value = CommClaimValue::ThreadMember {
                    party_ref,
                    thread_ref: raw_thread.to_owned(),
                    occurred_at,
                };
                let (claim_id, minted) = put_projected_comm_claim_in_txn(
                    vault,
                    wtxn,
                    source_event_id,
                    &value,
                    occurred_at,
                )?;
                // Deterministic tie-breaker: at equal occurred_at a join loses to
                // the boundary (a same-time leave/transition), so equal-time
                // opposing thread events converge to non-membership regardless of
                // projection order (restrictive-wins-tie, symmetric with LeaveThread).
                if minted
                    && let Some(boundary) =
                        latest_transition.filter(|boundary| occurred_at <= *boundary)
                {
                    vault.retract_claim_in_txn(wtxn, &claim_id, boundary)?;
                }
            }
            // The source event row is stamped `projected` by the same commit,
            // so this join becomes part of the boundary history either way —
            // exactly what a full rescan of projected thread events would see.
            // The peer-committed boundary observed above folds in too, but only
            // via this post-commit delta: the EntityNotFound path returns no
            // delta, so a still-absent party can never poison the index.
            Ok(ProjectorIndexDelta {
                consumed_gate_ids: Vec::new(),
                projected_thread_transition: Some((
                    key,
                    (
                        occurred_at,
                        matches!(rule.action, ProjectorAction::LeaveThread),
                    )
                        .max(peer_transition.unwrap_or((0, false))),
                )),
            })
        }
        ProjectorAction::LeaveThread => {
            let raw_thread = thread_ref.ok_or(CommError::InvalidRecord)?;
            let thread = canonical_member_ref(&aliases, raw_thread);
            let key = PartyThreadKey {
                party_ref,
                thread_ref: thread.to_owned(),
            };
            // Same ahead-of-cursor observation as JoinThread: a peer can
            // commit a later same-key transition while this pass is still
            // retrying this earlier leave, and this leave's staleness check
            // must see it now rather than at that event's own id.
            let peer_transition = index.peer_projected_thread_transition_in_txn(
                vault,
                &*wtxn,
                &key,
                source_event_id,
            )?;
            let active = matching_thread_membership_with_boundary_in_txn(
                vault,
                wtxn,
                party_ref,
                thread,
                true,
                index
                    .latest_thread_boundary(&key, &aliases)
                    .max(peer_transition),
            )?;
            require_at_most_one(&active)?;
            if let Some((_, matched)) = active.into_iter().next() {
                // Latest-event-wins: a leave older than the newest projected
                // transition for this membership is stale and must not end
                // it; the COMM_RECORD event row remains its durable trace.
                let latest_transition = matched
                    .valid_from
                    .max(index.latest_thread_transition(&key, &aliases))
                    .max(peer_transition.map(|(at, _)| at));
                if latest_transition.is_none_or(|boundary| occurred_at >= boundary) {
                    for (claim_id, claim) in matching_thread_memberships_in_txn(
                        vault,
                        wtxn,
                        party_ref,
                        Some(thread),
                        false,
                    )? {
                        if claim.is_standing() {
                            vault.retract_claim_in_txn(wtxn, &claim_id, occurred_at)?;
                        }
                    }
                }
            }
            Ok(ProjectorIndexDelta {
                consumed_gate_ids: Vec::new(),
                projected_thread_transition: Some((
                    key,
                    (
                        occurred_at,
                        matches!(rule.action, ProjectorAction::LeaveThread),
                    )
                        .max(peer_transition.unwrap_or((0, false))),
                )),
            })
        }
        _ => Err(CommError::InvalidRecord),
    }
}
