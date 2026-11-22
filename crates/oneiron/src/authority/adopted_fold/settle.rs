//! The tail's seeded fold past an adopted image, settled and projected
//! (OF-469, slice C): what the live fold past the image and a later image
//! built past it share ([`super::fold_adopted_checkpoint_tail`],
//! [`super::capture_adopted_checkpoint_tail`]).

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use super::super::fold_engine::FoldContext;
use super::super::fold_project::Settled;
use super::super::fold_resume::{ConfirmKeys, Resumed};
use super::covered_floors::{CoveredFloors, NoVouchPast};
use super::*;
use crate::EntityId;
use crate::error::Result;
use oneiron_contracts::authority::AuthorityHistoryReason;

mod tail_rows;

use tail_rows::{
    approves_on_revoked_key, image_fold_under, judged_tail, serial_revocation_fences,
    signed_outside_tail_line, tail_issuers, tail_pairs,
};

/// The tail's seeded fold past the image, settled and projected: what this
/// install's fold past the image and a later image built past it share.
pub(super) struct SettledTail {
    pub(super) judged: BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    pub(super) states: BTreeMap<AuthorityEntryHash, FoldState>,
    /// The image's merged state with every tail state merged in.
    pub(super) merged: FoldState,
    pub(super) writers: BTreeMap<AuthorityKey, BTreeSet<(EntityId, String)>>,
    /// The slip issuers once the tail joined the image's ([`tail_issuers`]).
    pub(super) issuers: BTreeSet<AuthorityKey>,
    pub(super) uncounted: BTreeSet<AuthorityEntryHash>,
    pub(super) pairs: u64,
    pub(super) counted_pairs: u64,
    /// The ancestors and counted ancestors of each image frontier row and
    /// each judged tail row.
    pub(super) ancestry: BTreeMap<AuthorityEntryHash, (u64, u64)>,
    /// The issues before the projection.
    pub(super) issues: Vec<AuthorityFoldIssue>,
    /// The covered rows a fold past the image reads whole, from their
    /// carried bodies.
    pub(super) projected: BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    /// The projected once fold, before any install's stale window.
    pub(super) fold: AuthorityFold,
    /// The projection's final merge.
    pub(super) final_merged: Option<FoldState>,
    /// The restrictive facts the projection applied: the image's, with each
    /// serial tail actor or device revocation's and machine removal's (FIX 11760).
    pub(super) revoke_facts: crate::authority::revoke_proof::RevokeFacts,
    /// The roster marks before custody is judged: the image's, with each
    /// serial tail machine profile's (FIX 11760).
    pub(super) marks: Vec<(AuthorityEntryHash, MarkProof)>,
    /// The keys closed fences hold: the image's, with each key a serial tail
    /// device revocation ([`serial_revocation_fences`]) or re-root
    /// ([`serial_handoff_fence`]) retired (FIX 11760).
    pub(super) retired_keys: BTreeSet<AuthorityKey>,
    /// The keys of `retired_keys` a closed handoff or appointment fence
    /// holds: the image's, with each key a serial tail re-root retired.
    pub(super) handoff_or_appointment_retired_keys: BTreeSet<AuthorityKey>,
    /// The handoffs whose fences are closed: the image's, with each serial
    /// tail re-root (FIX 11760).
    pub(super) closed_handoffs: BTreeSet<AuthorityEntryHash>,
    /// What the whole install fold's fold with no vouch makes of the tail.
    pub(super) no_vouch: NoVouchPast,
}

/// Whether `op` is a withdrawal the tail folds past the image only serially,
/// every covered row in its causal past (FIX 11760,
/// [`super::serial_withdrawal`]).
pub(super) fn serial_withdrawal_op(op: &AuthorityOp) -> bool {
    matches!(
        op,
        AuthorityOp::RevokeActor { .. }
            | AuthorityOp::SlipRevoke { .. }
            | AuthorityOp::SlipGrantRevoke { .. }
    )
}

/// Whether `op` is another row the tail folds past the image only serially,
/// every covered row in its causal past (FIX 11760,
/// [`super::serial_fold_past`]): a federation lifecycle act or a membership
/// execution. Each reads only state the image's frontier keeps, and its
/// tail then folds whole.
pub(super) fn serial_fold_past_op(op: &AuthorityOp) -> bool {
    matches!(
        op,
        AuthorityOp::FederationLifecycle(_) | AuthorityOp::MembershipExecution(_)
    )
}

/// Whether `op` is a device revocation, which the tail folds past the image
/// only serially, every covered row in its causal past (FIX 11760,
/// [`super::serial_fold_past`]). It moves its key's roster bit, which every
/// merge ORs in, and its restrictive fact (FIX
/// [CONFIRM-COLLISION-SUBTREE-ROLLBACK]), which it takes on its own branch
/// ([`crate::authority::revoke_proof::RevokeFacts::add_serial_device_revokes`]),
/// and its fence retires its key ([`serial_revocation_fences`]), so its tail
/// need not fold whole: a row above it that its key signs folds rejected
/// there, a row beside it folds on its own parents' states, as in the whole
/// fold, one its key signs that folds to a state is left to the whole
/// history, whose fence refuses it, and so is one with no state on a parent
/// with none ([`settle_tail`]).
/// A covered approval on its key expires on this install's own first sight
/// of it, its first-seen receipt: the one the adoption kept for a row this
/// install never stored before
/// (FOLDPAST-COVERED-APPROVAL-CLOCK; [`super::fold_adopted_checkpoint_tail`]).
pub(super) fn serial_roster_revoke_op(op: &AuthorityOp) -> bool {
    matches!(op, AuthorityOp::RevokeDevice { .. })
}

/// Whether `op` is an actor binding or rebinding, which the tail folds past
/// the image serially, every covered row in its causal past (FIX 11760,
/// [`super::serial_fold_past`]), whether the fold accepts it or not. Its
/// transition reads only its key's roster row and binding state, which its
/// parents' states, the whole fold's own, keep: the tail accepts or rejects
/// it exactly where the whole fold does, and a row beside it folds on its
/// own parents' states, so its tail need not fold whole. A covered row is a
/// write frontier of the key only for a binding some covered state holds
/// (`Resumed::actor_write_frontiers`): the tail projects the key's
/// frontiers as the whole fold does, or asks for the whole history.
pub(super) fn serial_binding_op(op: &AuthorityOp) -> bool {
    matches!(
        op,
        AuthorityOp::BindActor { .. } | AuthorityOp::RebindActor { .. }
    )
}

/// Whether `op` is a machine profile with no owner act: a roster revision or
/// removal. The op names no signer, so this alone never means the row is
/// admitted: [`super::serial_fold_past`] admits it past the image only
/// serially, every covered row in its causal past, and only when no owner
/// anchor signed it, since an anchor's mark folds through the anchor's own
/// chain (FIX 11760). Its transition reads its parents' states,
/// the whole fold's own, under the image's pin and peers. No covered row
/// sets its floor: every covered row of its signer is in its past, so it
/// folds only above them all (`NonMonotonicSeq`). Its tail then folds
/// whole, and the machines project from the whole fold's states with each
/// tail removal's fact and each tail mark. An owner answer still needs the
/// whole history: its standing reads its carrier chain's covered revisions
/// under this install's own floors, which no image keeps.
pub(super) fn serial_machine_op(op: &AuthorityOp) -> bool {
    matches!(op, AuthorityOp::MachineProfile(profile) if profile.act.is_none())
}

/// Whether `op` is a re-root, which the tail folds past the image only
/// serially, every covered row in its causal past, and as the tail's one
/// handoff (FIX 11760, [`super::serial_fold_past`]). Its tail then folds
/// whole, and the handoff settles as the whole fold settles it
/// ([`serial_handoff_fence`]). A covered approval on a key it retires
/// expires on this install's own first sight of it, as after a device
/// revocation ([`serial_roster_revoke_op`]).
pub(super) fn serial_handoff_op(op: &AuthorityOp) -> bool {
    matches!(op, AuthorityOp::ReRoot { .. })
}

/// The keys the serial re-root `handoff` fences, as the whole fold's
/// settlement reads them (`retired_signers`, `Fence::of`): every key in its
/// parents' rosters, live or revoked, other than its successor's. Every
/// covered row is in its causal past, so its line holds them all: its fence
/// refuses no covered row and no covered handoff. No covered fence refuses
/// it or a row in its line: the serial fold reads only a clean image
/// ([`super::clean_image`]), whose covered rows all folded valid, so none is
/// signed outside a covered fence, and no tail row is signed by a key the
/// image retired ([`super::tail_folds_past`]). It is the tail's one handoff,
/// so its fence closes and it settles. None where its fence could refuse a
/// tail row outside its line (one beside it or above it signed by a key it
/// fences): the whole fold drops such a row with its descendants, which only
/// the whole history folds here. This test is stricter than the whole fold's
/// (`Fence::signed_outside`): it exempts no genesis, no anchored row and no
/// row of another vault, so such a row outside the line asks for the whole
/// history even where the whole fold settles the handoff. None too where a
/// parent has no state here.
fn serial_handoff_fence(
    handoff: &AuthorityEntryHash,
    judged: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    seed: &BTreeMap<AuthorityEntryHash, FoldState>,
) -> Option<BTreeSet<AuthorityKey>> {
    let entry = judged.get(handoff)?;
    let AuthorityOp::ReRoot { new_device } = &entry.op else {
        return None;
    };
    let mut keys = BTreeSet::new();
    for parent in &entry.parent_hashes {
        let state = states.get(parent).or_else(|| seed.get(parent))?;
        keys.extend(
            state
                .roster
                .keys()
                .filter(|key| **key != new_device.key)
                .cloned(),
        );
    }
    (!signed_outside_tail_line(handoff, &keys, judged, states)).then_some(keys)
}

/// Whether the tail row `entry` is of a kind the tail folds past the image
/// only as rejected, with no state (FIX 11760, [`super::serial_fold_past`]):
/// a key rotation or a non-agent enrollment (a retired device-key op, which
/// stands only in a re-root's pre-handoff line), an agent enrollment
/// [`crate::authority::fold_resume::admits_past`] leaves to the history, or
/// a federation confirm whose id or nonce a covered confirm spent. The kind
/// alone does not make the whole fold reject the row: it may accept such an
/// enrollment. A serial row's parents' states are the whole fold's own, so
/// the tail rejects it exactly where the whole fold does, and one the tail
/// folds to a state still needs the whole history ([`settle_tail`]). A
/// binding folds serially whether the fold accepts it or not
/// ([`serial_binding_op`]).
pub(super) fn folds_rejected_op(image: &AuthorityCheckpointV2, entry: &AuthorityLogEntry) -> bool {
    match &entry.op {
        AuthorityOp::RotateKey { .. } => true,
        AuthorityOp::EnrollDevice { .. } => {
            let mut unused: ConfirmKeys = Default::default();
            !crate::authority::fold_resume::admits_past(&image.aggregate.merged, entry, &mut unused)
        }
        AuthorityOp::FederationConfirm(action) => {
            image.safety.confirm_ids.contains(&action.confirm_id)
                || image.safety.confirm_nonces.contains(&action.nonce)
        }
        _ => false,
    }
}

/// The tail's fold on the image's frontier states, merged into the image's
/// fold and projected, with `floors` the covered rows the tail floors
/// ([`tail_folds_past`]).
/// Wherever only the whole history folds the tail, why: the first guard
/// below that refuses it. A carried body that does not decode is corruption.
pub(super) fn settle_tail(
    image: &AuthorityCheckpointV2,
    tail: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
    log: AdoptedTail<'_>,
    mut floors: CoveredFloors,
) -> Result<std::result::Result<SettledTail, AuthorityHistoryReason>> {
    let mut issues = image.safety.issues.clone();
    let judged = judged_tail(image, tail, &mut issues);
    // The seeded fold takes rows; everything else here reads the judged whole entries.
    let judged_rows = judged
        .iter()
        .map(|(hash, entry)| (*hash, FoldRow::Open(entry.clone())))
        .collect::<BTreeMap<_, _>>();
    // Every body the image carries, decoded once.
    let carried = image
        .rows
        .iter()
        .filter_map(|(hash, row)| Some((*hash, row.body.as_ref()?)))
        .map(|(hash, body)| -> Result<_> { Ok((hash, decode_authority_log_entry_body(body)?)) })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let Some(issuers) = tail_issuers(image, &carried, &judged) else {
        return Ok(Err(AuthorityHistoryReason::IssuersRecounted));
    };
    let uncounted: BTreeSet<_> = image
        .safety
        .uncounted
        .iter()
        .copied()
        .chain(
            judged_rows
                .iter()
                .filter(|(_, row)| crate::authority::log_budget::is_uncounted(row, &issuers))
                .map(|(hash, _)| *hash),
        )
        .collect();
    let (pairs, counted_pairs, ancestry) = tail_pairs(image, &judged, &uncounted);
    let memory_floor_bytes =
        crate::authority::log_budget::fold_memory_floor(Some(&log.observations.policy));
    if crate::authority::log_budget::fold_projected_bytes(image.covered.len() + judged.len(), pairs)
        > memory_floor_bytes
    {
        return Ok(Err(AuthorityHistoryReason::FoldOverMemoryFloor));
    }
    // Each tail row folds on its parents' states as the scheduler folds it,
    // the frontier's kept states seeding it.
    let (consent_arm, _) = crate::authority::fold_engine::own_log_inputs(log.posture, None);
    let no_handoff_line = BTreeSet::new();
    let summaries = crate::authority::fold_engine::ImagePast {
        image,
        judged: &judged,
    };
    let causal = crate::authority::fold_engine::CausalPast::new(&summaries);
    let context = FoldContext {
        // No tail row sits past a floor, and a covered row the tail floors
        // folds as the image folded it (`tail_folds_past`).
        sequence_floors: Some(&crate::authority::fold_engine::SEQUENCE_FLOORS_FROM_ROWS),
        floor_vouched: (!log.observations.unvouched).then_some(&log.observations.vouched),
        install_held: None,
        entry_ancestors: None,
        causal_past: Some(&causal),
        peer_consent_roots: log.peer_consent_roots,
        consent_arm,
        hosted: log.posture == crate::HostingPrivacyPosture::Hosted,
        machine_standing: &crate::authority::machine_standing::every_chain,
        pre_handoff_entries: Some(&no_handoff_line),
        memory_floor_bytes,
        pin: log.pin,
        owner_key_lines: None,
        appointments: None,
    };
    let mut seed: BTreeMap<_, _> = image
        .per_parent
        .iter()
        .filter_map(|(hash, state)| Some((*hash, state.clone()?)))
        .collect();
    // A late fork's covered parent seeds from its replay state (FIX 3007);
    // a point that does not decode leaves the whole history to fold it.
    for parent in judged.values().flat_map(|entry| entry.parent_hashes.iter()) {
        if !image.rows.contains_key(parent)
            || image.per_parent.contains_key(parent)
            || seed.contains_key(parent)
            || image.holds_rejected(parent)
        {
            continue;
        }
        let Some(Some(state)) = image.state_at(parent) else {
            return Ok(Err(AuthorityHistoryReason::LateForkWithoutState));
        };
        seed.insert(*parent, state);
    }
    let mut states = crate::authority::fold_schedule::fold_entry_states_seeded(
        &judged_rows,
        &seed,
        context,
        &mut issues,
    );
    // A key record's request walk that met a row the image shows nothing of
    // judged nothing here (FIX 5464): only the whole history does.
    if causal.incomplete() {
        return Ok(Err(AuthorityHistoryReason::CausalWalkIncomplete));
    }
    // A world key record, or a restrictive main-log choice (a world edit,
    // grant travel, checkpoint policy, home pick or training choice), on a
    // row with no state here (a frontier row the image holds rejected, a
    // rejected tail row) is folded again with that row crossed
    // (`world_refold`), which only the whole history does (FIX 4881, 5463),
    // as is a root request, the owner's cancel of one or its result (FIX
    // 5584, 5649), the request's kind read from the tail or the image.
    let kind_of = |request: &AuthorityEntryHash| match judged.get(request) {
        Some(asked) => crate::authority::world_refold::request_kind(asked),
        None => crate::authority::world_refold::carried_request_kind(image, request),
    };
    if judged.iter().any(|(hash, entry)| {
        crate::authority::world_refold::refolds(&entry.op, kind_of)
            && !states.contains_key(hash)
            && entry
                .parent_hashes
                .iter()
                .any(|parent| !states.contains_key(parent))
    }) {
        return Ok(Err(AuthorityHistoryReason::RejectedRowCrossed));
    }
    // A restrictive withdrawal (a slip burn, a slip, Grant or actor
    // revocation, a machine removal) waiting here on a row with no state (a
    // rejected tail row) still withdraws in the whole fold, whose proof
    // crosses rejected permissive rows to it (`revoke_proof`); the image's
    // facts do not hold it, so only the whole history folds it (FIX 11760).
    if judged.iter().any(|(hash, entry)| {
        crate::authority::revoke_proof::restrictive_withdrawal(&entry.op)
            && !states.contains_key(hash)
            && entry
                .parent_hashes
                .iter()
                .any(|parent| !states.contains_key(parent))
    }) {
        return Ok(Err(AuthorityHistoryReason::RejectedRowCrossed));
    }
    // No tail row vouches for a covered row past its floor
    // (`tail_signers_covered_rows_unfloored`), so every covered verdict
    // stands past the image.
    states.retain(|hash, _| judged.contains_key(hash));
    // A row of a kind that folds past the image only as rejected (FIX
    // 11760): one the tail folds to a state is judged by the whole history.
    if judged
        .iter()
        .any(|(hash, entry)| states.contains_key(hash) && folds_rejected_op(image, entry))
    {
        return Ok(Err(AuthorityHistoryReason::OpNotFoldedPast));
    }
    // A pact the tail moves is read only on a row that folds serially
    // (FIX 11760), whose parents' states are the whole fold's own; on any
    // other row only the whole history tells it.
    if states.iter().any(|(hash, state)| {
        state.federation_pacts != image.aggregate.merged.federation_pacts
            && !judged
                .get(hash)
                .is_some_and(|entry| super::folds_serially(image, tail, log, entry))
    }) {
        return Ok(Err(AuthorityHistoryReason::UnsettledMove));
    }
    // A serial row's tail folds whole, every row of it on its own parents'
    // states (FIX 11760): a row the fold rejects could still carry a
    // withdrawal its branch proves past it, which only the whole history
    // proves. The image's facts then gain each actor revocation's own, and
    // each machine removal's.
    let withdrawal = tail.values().any(|entry| serial_withdrawal_op(&entry.op));
    let machine = tail.values().any(|entry| serial_machine_op(&entry.op));
    let serial = withdrawal
        || machine
        || tail
            .values()
            .any(|entry| serial_fold_past_op(&entry.op) || serial_handoff_op(&entry.op));
    if serial && tail.keys().any(|hash| !states.contains_key(hash)) {
        return Ok(Err(AuthorityHistoryReason::RejectedRowCrossed));
    }
    // A tail that floors covered rows folds past them only counted whole and
    // with no issue of its own: the image's issues then stand in the whole
    // fold's order, but for its fork block (`CoveredFloors::issues_past`).
    if !floors.is_empty() {
        if issues.len() != image.safety.issues.len()
            || tail.keys().any(|hash| !states.contains_key(hash))
        {
            return Ok(Err(AuthorityHistoryReason::SequenceFloorMoved));
        }
        issues = floors.issues_past(image);
    }
    let mut revoke_facts = if withdrawal {
        image
            .safety
            .revoke_facts
            .with_serial_actor_revokes(&judged, &states)
    } else {
        image.safety.revoke_facts.clone()
    };
    // A device revocation is a restrictive fact in the whole fold (FIX
    // [CONFIRM-COLLISION-SUBTREE-ROLLBACK]): each one the tail folds takes
    // its own, which the image this install builds next keeps.
    revoke_facts.add_serial_device_revokes(&judged, &states);
    // Each device revocation's fence retires its key, as the whole fold's
    // settlement does; one that could refuse a tail row leaves the tail to
    // the whole history.
    let Some(revoked) = serial_revocation_fences(&judged, &states) else {
        return Ok(Err(AuthorityHistoryReason::RetirementFence));
    };
    let mut retired_keys = image.safety.retired_keys.clone();
    retired_keys.extend(revoked);
    // A serial re-root's fence closes as in the whole fold (FIX 11760): it
    // retires every key it fences, a handoff's retirement, and its handoff
    // joins the closed ones. No tail row with a state stands on a key a tail
    // fence holds outside its line, and every covered row is in each line,
    // so no restrictive fact stands on a retired key: the facts forget none.
    let mut handoff_or_appointment_retired_keys =
        image.safety.handoff_or_appointment_retired_keys.clone();
    let mut closed_handoffs = image.safety.closed_handoffs.clone();
    for (hash, entry) in &judged {
        if !serial_handoff_op(&entry.op) {
            continue;
        }
        let Some(fenced) = serial_handoff_fence(hash, &judged, &states, &seed) else {
            return Ok(Err(AuthorityHistoryReason::RetirementFence));
        };
        retired_keys.extend(fenced.iter().cloned());
        handoff_or_appointment_retired_keys.extend(fenced);
        closed_handoffs.insert(*hash);
    }
    let mut marks = image.safety.marks.clone();
    if machine {
        revoke_facts.add_serial_machine_removals(&judged, &states);
        marks.extend(tail_marks(&judged, &states));
        marks.sort_unstable_by_key(|(hash, _)| *hash);
    }
    let mut merged = image.aggregate.merged.clone();
    let mut writers = image.safety.writers.clone();
    for state in states.values() {
        merged = merge_states(&merged, state);
        crate::authority::fold_resume::add_writers(&mut writers, state);
    }
    let mut valid_entries = image.fold().valid_entries.clone();
    valid_entries.extend(states.keys().copied());
    // The rows a fold past the image reads whole: carried bodies of the
    // projected kinds alone, whatever else an image carries, and the judged
    // tail's rows of those kinds (a world key record's envelopes, FIX 4881).
    let mut projected = BTreeMap::new();
    for (hash, entry) in carried {
        floors.note(&hash, &entry.op);
        if crate::authority::fold_resume::is_projected(&entry.op) {
            projected.insert(hash, entry);
        }
    }
    // Under another pin than the image's, the guards below read the image's
    // own fold as this install projects it (FIX 3004).
    let here = (log.pin.copied() != image.building_pin)
        .then(|| image_fold_under(image, &projected, context));
    let image_fold = here.as_ref().unwrap_or_else(|| image.fold());
    for (hash, entry) in &judged {
        if crate::authority::fold_resume::is_projected(&entry.op) {
            projected.insert(*hash, entry.clone());
        }
    }
    let rows = Resumed {
        marks: &marks,
        fold: image.fold(),
        revocations: &image.safety.revocations,
        bound_keys: &image.safety.bound_keys,
        chain: states
            .iter()
            .filter(|(hash, _)| judged.get(*hash).is_some_and(is_main))
            .map(|(hash, state)| (*hash, state))
            .collect(),
        writers: &writers,
        base_writers: &image.safety.writers,
        missed: Cell::new(false),
    };
    // The projection reads rows only for world-key envelopes, the image's
    // and the tail's alike.
    let (fold, final_merged) = crate::authority::fold_project::project_once(
        Settled {
            merged: Some(merged.clone()),
            valid_entries,
            by_hash: &projected,
            revoke_facts: &revoke_facts,
            retired_keys: retired_keys.clone(),
            handoff_or_appointment_retired_keys: handoff_or_appointment_retired_keys.clone(),
            closed_handoffs: closed_handoffs.clone(),
            crossed_revocations: image.safety.crossed_revocations.clone(),
            unsettled: image.safety.unsettled,
            counted_ancestor_pairs: counted_pairs,
            issues: issues.clone(),
        },
        &rows,
        context,
    );
    // Machines move only past a serial machine profile, whose whole tail
    // folded on the whole fold's states and projects with its facts and
    // marks (FIX 11760); any other move only the whole history tells.
    if rows.missed.get()
        || (!machine && fold.machines != image_fold.machines)
        || fold.restored_enrolments != image_fold.restored_enrolments
        || !crate::authority::world_privacy::worlds_unmoved_past(
            &fold,
            image_fold,
            judged.iter().map(|(hash, entry)| (*hash, entry)),
        )
    {
        return Ok(Err(AuthorityHistoryReason::UnsettledMove));
    }
    if approves_on_revoked_key(&fold, &judged, &states) {
        return Ok(Err(AuthorityHistoryReason::StaleRosterWindow));
    }
    let no_vouch = if floors.is_empty() {
        NoVouchPast::Idle
    } else {
        let read_whole: Vec<&AuthorityLogEntry> = projected
            .values()
            .chain(
                judged
                    .iter()
                    .filter(|(hash, _)| !projected.contains_key(*hash))
                    .map(|(_, entry)| entry),
            )
            .collect();
        let no_vouch =
            floors.no_vouch_past(image, tail, log.observations, &states, &fold, &read_whole);
        let Some(no_vouch) = no_vouch else {
            return Ok(Err(AuthorityHistoryReason::SequenceFloorMoved));
        };
        no_vouch
    };
    Ok(Ok(SettledTail {
        judged,
        states,
        merged,
        writers,
        issuers,
        uncounted,
        pairs,
        counted_pairs,
        ancestry,
        issues,
        projected,
        fold,
        final_merged,
        revoke_facts,
        marks,
        retired_keys,
        handoff_or_appointment_retired_keys,
        closed_handoffs,
        no_vouch,
    }))
}

/// The roster marks of the tail's machine profiles, as an image built over
/// the whole history keeps them (`fold_resume::ImageFold`): each one that
/// heads its machine's roster chain in its own state, under an owner-held
/// key or as an admitted owner answer ([`MarkProof::of`]).
fn tail_marks(
    judged: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
) -> Vec<(AuthorityEntryHash, MarkProof)> {
    states
        .iter()
        .filter_map(|(hash, state)| {
            let profile =
                crate::authority::stale_roster::filed_machine_profile(&judged.get(hash)?.op)?;
            let chain = state
                .machines
                .get(&profile.machine)?
                .get(&MachineAdmitter::Roster)?;
            MarkProof::of(&chain.head)
                .filter(|_| chain.head.entry == *hash)
                .map(|proof| (*hash, proof))
        })
        .collect()
}
