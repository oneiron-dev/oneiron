//! Whether an adopted image's fold is the one this install reaches in its
//! own context, and whether a late fork may fold on a covered row's kept
//! state (OF-469; FIX 3004, 3005, 3007; CALLS "FIX 3004 3005 cold context").
//!
//! The image's per-row states were judged under its building install's pin
//! and admitted peers. Where this install's differ, the covered rows whose
//! transition reads the changed input are judged again on their parents'
//! kept states, under the image's input and under this install's: the pin
//! for every owner act and machine standing transition ([`reads_pin`]), the
//! peers' consent roots for a federation lifecycle act naming a peer whose
//! roots differ. When each lands as its kept state says under both, every
//! covered state is the one this install's fold reaches, and the image
//! stands here; the projection is read under this install's pin anyway. A
//! row the image's settlement pruned lands alike too (FIX 11263): no fence
//! reads either input. Otherwise, or where the image keeps no state to
//! judge on, the whole history decides, as before. The posture still has to
//! match: it decides which consent arm judges every row.

use super::super::fold_engine::{CausalPast, FoldContext, ImagePast};
use super::*;

/// What a fold past an image built under another pin or other admitted
/// peers does (CALLS COLD_AUTHORITY_CONTEXT_POLICY): judge again the covered
/// rows whose transition reads the changed input.
pub(super) const COLD_AUTHORITY_CONTEXT_POLICY: ColdContextPolicy =
    ColdContextPolicy::ReevaluateDependencies;

/// The policy hook behind [`COLD_AUTHORITY_CONTEXT_POLICY`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ColdContextPolicy {
    /// Judge the dependent covered rows again; any that moves, or that the
    /// image keeps no state to judge on, needs the whole history.
    ReevaluateDependencies,
}

/// Whether the image's fold is the one this install would reach: built
/// under this install's posture, and under its pin and its admitted peers'
/// consent roots, or judged here alike under both (see the module doc).
pub(super) fn image_stands_here(image: &AuthorityCheckpointV2, log: AdoptedTail<'_>) -> bool {
    if image.aggregate.posture != log.posture {
        return false;
    }
    let pin_moved = image.building_pin != log.pin.copied();
    let moved_peers: BTreeSet<AuthorityVaultId> = image
        .aggregate
        .peers
        .keys()
        .chain(log.peer_consent_roots.keys())
        .filter(|vault| image.aggregate.peers.get(*vault) != log.peer_consent_roots.get(*vault))
        .copied()
        .collect();
    if !pin_moved && moved_peers.is_empty() {
        return true;
    }
    match COLD_AUTHORITY_CONTEXT_POLICY {
        ColdContextPolicy::ReevaluateDependencies => {}
    }
    // A row whose kind reads either input carries its body (FIX 3004, 3005):
    // a row with none reads neither.
    image.rows.iter().all(|(hash, row)| {
        let Some(body) = &row.body else {
            return true;
        };
        let Ok(entry) = decode_authority_log_entry_body(body) else {
            return false;
        };
        let reads = (pin_moved && reads_pin(&entry.op))
            || matches!(&entry.op, AuthorityOp::FederationLifecycle(action)
                if moved_peers.contains(&action.peer_vault_id));
        !reads || judged_alike(image, log, *hash, &entry)
    })
}

/// Whether `op`'s transition reads the install's pin: every owner act, a
/// machine's revision or answer, a frontier join, a world key record, a home
/// candidacy and an owner key enrollment judge their carrier or signer
/// through this install's trusted admitter, and a kit request through the
/// pinned root itself.
pub(super) fn reads_pin(op: &AuthorityOp) -> bool {
    matches!(
        op,
        AuthorityOp::FrontierJoin(_)
            | AuthorityOp::WorldPrivacy(_)
            | AuthorityOp::GrantTravelSet(_)
            | AuthorityOp::CheckpointPolicySet(_)
            | AuthorityOp::HomeNodePick(_)
            | AuthorityOp::ConversationTrainingSet(_)
            | AuthorityOp::ConversationTrainingVaultSet(_)
            | AuthorityOp::AgentGrantAct(_)
            | AuthorityOp::PolicySettingSet(_)
            | AuthorityOp::ExportAct(_)
            | AuthorityOp::MachineProfile(_)
            | AuthorityOp::OwnerWorkRequest(_)
            | AuthorityOp::OwnerWorkResult(_)
            | AuthorityOp::OwnerWorkCancel(_)
            | AuthorityOp::WorldKeyWraps(_)
            | AuthorityOp::HomeCandidacy(_)
            | AuthorityOp::OwnerKeyEnroll(_)
    )
}

/// Whether covered row `entry`, signed as `hash`, lands on its parents' kept
/// states as its own kept state says, under the image's pin and peers and
/// under this install's alike. False where the image keeps no state at the
/// row or at a parent of it.
///
/// A row the image's fold holds no state at, though its own transition
/// admits it there under the image's inputs, fell to the fold's settlement
/// (FIX 11263): a retired signer's fence, a confirmation collision or an
/// unsettled handoff on it or beneath it, or a causal sequence floor. None
/// of those reads the pin or the peers, so under this install's inputs it
/// falls the same way, whether its transition admits it there or not. A row
/// the world refold folds again ([`refolded_kind`]) is judged by that
/// refold, which reads them: its kept state alone decides, as before.
fn judged_alike(
    image: &AuthorityCheckpointV2,
    log: AdoptedTail<'_>,
    hash: AuthorityEntryHash,
    entry: &AuthorityLogEntry,
) -> bool {
    let Some(kept) = image.state_at(&hash) else {
        return false;
    };
    let mut parents = BTreeMap::new();
    for parent in &entry.parent_hashes {
        let Some(Some(state)) = image.state_at(parent) else {
            return false;
        };
        parents.insert(*parent, state);
    }
    let judged = BTreeMap::new();
    let summaries = ImagePast {
        image,
        judged: &judged,
    };
    let causal = CausalPast::new(&summaries);
    let no_floors = BTreeMap::new();
    let no_handoff_line = BTreeSet::new();
    let (consent_arm, _) = super::super::fold_engine::own_log_inputs(log.posture, None);
    let memory_floor_bytes =
        super::super::log_budget::fold_memory_floor(Some(&log.observations.policy));
    let judge = |pin: Option<&PinnedRoot>,
                 peers: &BTreeMap<AuthorityVaultId, BTreeSet<AuthorityKey>>| {
        let context = FoldContext {
            sequence_floors: Some(&no_floors),
            floor_vouched: None,
            install_held: None,
            entry_ancestors: None,
            causal_past: Some(&causal),
            peer_consent_roots: peers,
            consent_arm,
            hosted: log.posture == crate::HostingPrivacyPosture::Hosted,
            machine_standing: &super::super::machine_standing::every_chain,
            pre_handoff_entries: Some(&no_handoff_line),
            memory_floor_bytes,
            pin,
        };
        match fold_entry_state(entry, hash, &parents, context) {
            EntryFold::Ready(state) => Some(Some(state)),
            EntryFold::Invalid(_) => Some(None),
            EntryFold::Waiting => None,
        }
    };
    let built = judge(image.building_pin.as_ref(), &image.aggregate.peers);
    let here = judge(log.pin, log.peer_consent_roots);
    if causal.incomplete() {
        return false;
    }
    if built.as_ref() == Some(&kept) && here.as_ref() == Some(&kept) {
        return true;
    }
    kept.is_none()
        && matches!(built, Some(Some(_)))
        && here.is_some()
        && refolded_kind(image, &hash) == Some(false)
}

/// Whether the fold folds covered row `hash` again over a main-log row it
/// did not keep (`world_refold`): a world's side row, or a row of a kind the
/// refold takes. None for a row the image does not cover or whose carried
/// body does not decode.
fn refolded_kind(image: &AuthorityCheckpointV2, hash: &AuthorityEntryHash) -> Option<bool> {
    let row = image.rows.get(hash)?;
    if row.world.is_some() {
        return Some(true);
    }
    let Some(body) = &row.body else {
        return Some(false);
    };
    let entry = decode_authority_log_entry_body(body).ok()?;
    Some(super::super::world_refold::refolds(&entry.op, |request| {
        super::super::world_refold::carried_request_kind(image, request)
    }))
}

/// Whether a tail row may fold on covered row `hash`'s kept state as the
/// reference fold would fold it there (FIX 3007). A row of a kind the fold
/// folds again over a main-log row it did not keep (`world_refold`), with
/// such a row beneath it, may hold the state of that refold rather than of
/// its parents: only the whole history seeds a row on it.
pub(super) fn seeds_late_fork(image: &AuthorityCheckpointV2, hash: &AuthorityEntryHash) -> bool {
    let (Some(row), Some(refolded)) = (image.rows.get(hash), refolded_kind(image, hash)) else {
        return false;
    };
    if !refolded {
        return true;
    }
    let mut stack = row.parents.clone();
    let mut seen = BTreeSet::new();
    while let Some(at) = stack.pop() {
        if !seen.insert(at) {
            continue;
        }
        let Some(ancestor) = image.rows.get(&at) else {
            return false;
        };
        if ancestor.world.is_none() && image.holds_rejected(&at) {
            return false;
        }
        stack.extend(ancestor.parents.iter().copied());
    }
    true
}
