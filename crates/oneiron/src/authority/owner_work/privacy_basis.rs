//! The fold's one judgment of key work a world settings edit left (FIX
//! 4704): a request that carries a [`WorldPrivacyWorkBasis`] instead of an
//! owner's own key act.
//!
//! A holder who owns no vault, or an agent within its Grant, changes a
//! world's settings; the key work that change needs may still await a
//! holder. Its request then carries the settings edit's own act, exactly as
//! the edit's entry signed it, and names that edit, the world's revision
//! right after it and the live vault owner the key binds. The fold admits it
//! on the basis alone ([`privacy_key_work_basis_admits`]); a request it does
//! not admit is valid and without effect, as any other.

use super::*;

/// Whether the parents' fold `state` admits `request`'s basis: the one
/// judgment the fold makes of key work a settings edit left (CALLS "FIX 4704
/// derived key work authority").
///
/// - The basis's edit is an admitted world settings edit of the request's
///   world in `state`: live or superseded in that world's frontier, and not
///   valid-without-effect. Finding it in the parents' frontier proves it an
///   admitted ancestor.
/// - `after` is the world's revision at the edit's own point: an admitted
///   edit replaces every live edit at its parents, so that revision is over
///   the edit alone. A later edit leaves the request stale at its executor,
///   never refused here.
/// - The act's owner is live at the request's causal point, as the edit's
///   own admission checked, and so is the key owner.
///
/// It does not judge again the holder census or the agent's Grant line: the
/// fold has neither, and the edit's own admission already carried them on
/// its carrier's word (mesh contract §4). It does not compare the request's
/// act with the edit's either, since no fold state keeps an edit's act: the
/// recorder copies it from the stored edit in the same transaction, and the
/// fold trusts the carrier for that copy, as it trusts the carrier for any
/// owner act's say-so.
pub(super) fn privacy_key_work_basis_admits(
    state: &FoldState,
    request: &OwnerWorkRequest,
    basis: &WorldPrivacyWorkBasis,
) -> bool {
    let world = request.act.target;
    let admitted_edit = !state.refused_world_edits.contains(&basis.edit)
        && state.worlds.get(&world).is_some_and(|frontier| {
            frontier.live.contains_key(&basis.edit) || frontier.superseded.contains_key(&basis.edit)
        });
    admitted_edit
        && basis.after == PolicyRevision::of([basis.edit]).0
        && super::super::owner_act::owner_live_at(state, request.act.owner)
        && super::super::owner_act::owner_live_at(state, basis.key_owner)
}
