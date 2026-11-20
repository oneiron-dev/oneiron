//! Which window tombstones a selector export carries beside the rows it keeps
//! (FIX 10161). A grant that reads every record takes every tombstone the
//! open fallback carries, as before. A narrower grant takes one only where the
//! scope its delete captured is a scope the grant reads. A selector narrowed
//! to one world, or to base reality, takes one only where the position its
//! delete captured lies in the worlds it selects (FOLLOWED-WORLD-TIER1-
//! TOMBSTONE-IDS, blind review 2 of #9592): a hard delete took the row's
//! carrier out of the window, so the selector keeps no row to judge. A row
//! whose kind takes its worlds from live edges is held at the one world the
//! grant and the selector both hold, as a kept row is (FIX-LIST 9433;
//! REVIEW-10024). A
//! selector narrowed to some bands takes one only where the row type its
//! delete captured lies in a band it selects
//! (SELECTOR-FACET-BAND-EXPORT-DROPS-BODYLESS-TOMBSTONES). A selector narrowed
//! to some facets keeps a row by the row's `FacetOf` stamps, so it takes one
//! only where every stamp its delete captured names a facet it selects, as it
//! seeds a kept row; a row it reached only by closure, by a scope facet with
//! no stamp, or with a stamp in a facet it does not select stays off
//! (SELECTOR-FACET-EXPORT-DROPS-BODYLESS-TOMBSTONES).
//! A member who is not an Owner takes one only of a row it reads at the
//! relationship gate (OPUS-LEAKS, SELECTOR-TOMBSTONE-LABEL). A purged row
//! that carried the words of a world kept off the destination stays home,
//! as its live row did (REVIEW-10024).

use std::collections::BTreeSet;

use heed::RoTxn;

use crate::Vault;
use crate::access_grant::AccessContext;
use crate::deletion::decode_tombstone_value;
use crate::deletion::tombstone_scope::{
    DeletedRecordScope, deleted_record_scope_in, deleted_relationship_read_in,
};
use crate::entity_id::EntityId;
use crate::federation::record_scope::note_world::{self, NoteWorlds};
use crate::federation::{Scope, ScopeAxis, ScopeId, SelectorRange};

/// What a narrower grant gets of a tombstone whose delete left no scope it
/// can judge here: no captured row, a row bound to another request, a value
/// that names no request, or a failed read (a call).
const UNPROVEN_TOMBSTONE_EXPORTED: bool = false;

/// The tombstone rule of one export, for the tombstones of rows it does not
/// keep.
pub(super) struct TombstoneExport<'g> {
    grant: &'g Scope,
    /// The facets a selector narrowed to some facets selects, which it
    /// selects rows by through their `FacetOf` stamps; `None` for one that
    /// bounds no facet.
    facets: Option<&'g ScopeAxis<ScopeId>>,
    /// The type-byte bands a selector narrowed to some bands selects; `None`
    /// for one that bounds no band.
    bands: Option<&'g ScopeAxis<SelectorRange>>,
    /// The worlds a selector narrowed to one world or to base reality
    /// selects; `None` for the All-world selector, which bounds no world.
    worlds: Option<&'g ScopeAxis<ScopeId>>,
    /// The selector's world ceiling ([`note_world::selector_world_axis`]),
    /// which with the grant's holds a row that takes live worlds at one of
    /// them, as the kept rows are held.
    selector_worlds: ScopeAxis<ScopeId>,
    /// The grant reads every record, so the fallback shows it nothing it
    /// could not read.
    unrestricted: bool,
}

impl<'g> TombstoneExport<'g> {
    pub(super) fn new(
        grant: &'g Scope,
        facets: Option<&'g ScopeAxis<ScopeId>>,
        bands: Option<&'g ScopeAxis<SelectorRange>>,
        worlds: Option<&'g ScopeAxis<ScopeId>>,
        selector_worlds: ScopeAxis<ScopeId>,
    ) -> Self {
        // Judged as the kept rows are, with every axis open but the verb.
        let every_record = Scope {
            verbs: ScopeAxis::Some(BTreeSet::from(["read".to_owned()])),
            ..Scope::top()
        };
        Self {
            grant,
            facets,
            bands,
            worlds,
            selector_worlds,
            unrestricted: grant.admits("read", &every_record, &Scope::top()),
        }
    }

    /// Whether the tombstone `value` of `id`, a row this export does not
    /// keep, still travels. Under a selector narrowed to some facets, worlds
    /// or bands, it travels only where its delete's captured position lies in
    /// what the selector selects on each of those axes, so an unrestricted
    /// grant's export proves that position too.
    pub(super) fn admits(
        &self,
        vault: &Vault,
        txn: &RoTxn<'_>,
        id: &EntityId,
        value: &[u8],
    ) -> bool {
        if self.unrestricted
            && self.facets.is_none()
            && self.worlds.is_none()
            && self.bands.is_none()
        {
            return true;
        }
        let Some(request) = decode_tombstone_value(value).request_id else {
            return UNPROVEN_TOMBSTONE_EXPORTED;
        };
        match deleted_record_scope_in(&vault.store, txn, id, &request) {
            Ok(Some(captured)) => {
                let held = self.held_position(&captured);
                self.selects(vault, &captured, &held)
                    && (self.unrestricted || self.grant.admits("read", &held, &Scope::top()))
            }
            Ok(None) | Err(_) => UNPROVEN_TOMBSTONE_EXPORTED,
        }
    }

    /// The position the delete's capture `captured` is held at, as a kept row
    /// is held before the grant and the selector judge it: a row whose kind
    /// takes its worlds from live edges (a NOTE, an ASSET, a caption) at the
    /// one world it was in that the grant's and the selector's world ceilings
    /// both hold ([`note_world::position_at`], FIX-LIST 9433), so a NOTE in
    /// W and X travels under a World(W) selector, as it did live
    /// (REVIEW-10024). Its worlds are every world the capture kept it in
    /// ([`DeletedRecordScope::live_worlds`]), so a NOTE in base reality and W
    /// travels to a grant that reads only W, as it did live (REVIEW-10042);
    /// a capture older than that field holds the captured world axis, the
    /// row's one position ([`NoteWorlds::axis`]). Every other row, and a
    /// capture with no type, keeps its captured scope.
    fn held_position(&self, captured: &DeletedRecordScope) -> Scope {
        if !captured
            .entity_type
            .is_some_and(note_world::takes_live_worlds)
        {
            return captured.scope.clone();
        }
        let worlds = match (&captured.live_worlds, &captured.scope.worlds) {
            (Some(worlds), _) | (None, ScopeAxis::Some(worlds)) => NoteWorlds::In(worlds.clone()),
            (None, ScopeAxis::All) => NoteWorlds::NoSingleWorld,
            (None, ScopeAxis::Bottom) => return captured.scope.clone(),
        };
        note_world::position_at(
            &captured.scope,
            Some(&worlds),
            &[&self.grant.worlds, &self.selector_worlds],
        )
    }

    /// Whether the delete's capture `captured`, held at `held`, lies in what
    /// the selector selects, judged as a kept row is:
    /// - facets: `FacetOf` stamps that each name a selected facet, as a seed
    ///   is chosen and a row with an unselected stamp is withheld
    ///   ([`super::scope::facet_scope_by_source`],
    ///   [`super::scope::entity_selector_decision`]). The captured scope
    ///   facet is not what the selector selects by.
    /// - worlds: the held world position in the selected worlds or in base
    ///   reality, which every such selector selects (`SyncSelectorWorld`).
    /// - bands: the row's header type in a selected band
    ///   ([`super::scope::selector_identity`], as `entity_selector_decision`
    ///   bands a kept row). The scope's band axis is its disclosure position,
    ///   not the row's type, so it does not decide the band. A capture with
    ///   no type is in no band.
    fn selects(&self, vault: &Vault, captured: &DeletedRecordScope, held: &Scope) -> bool {
        let facets = self.facets.is_none_or(|facets| {
            !captured.facet_of.is_empty()
                && captured.facet_of.iter().all(|facet| facets.contains(facet))
        });
        let worlds = self.worlds.is_none_or(|worlds| {
            held.worlds == crate::federation::base_world_axis()
                || held.worlds.is_narrowing_of(worlds)
        });
        let bands = self.bands.is_none_or(|bands| {
            captured
                .entity_type
                .and_then(|kind| super::scope::selector_identity(vault, kind))
                .is_some_and(|band| bands.contains(&band))
        });
        facets && worlds && bands
    }
}

/// Whether the delete capture bound to the tombstone `value` of `id` says the
/// row carried the words of a world in `flagged`, the worlds this export keeps
/// off its destination (REVIEW-10024). The delete took the row's `InWorld`
/// edges and sources with it, so the live check
/// ([`crate::settings::device_only_withholds`]) no longer sees where its words
/// sat. A capture that does not read withholds while any world is flagged; a
/// tombstone that names no request, one with no capture bound to it, or a
/// capture older than the field leaves the live check's judgment.
pub(super) fn device_only_by_capture(
    vault: &Vault,
    txn: &RoTxn<'_>,
    flagged: &BTreeSet<EntityId>,
    id: &EntityId,
    value: &[u8],
) -> bool {
    if flagged.is_empty() {
        return false;
    }
    let Some(request) = decode_tombstone_value(value).request_id else {
        return false;
    };
    match deleted_record_scope_in(&vault.store, txn, id, &request) {
        Ok(Some(captured)) => captured
            .carried_worlds
            .is_some_and(|carried| carried.kept_by(flagged)),
        Ok(None) => false,
        Err(_) => true,
    }
}

/// Whether the selector's member reads the row that the tombstone `value` of
/// `id` removes, as the relationship read its delete captured decides
/// (OPUS-LEAKS, SELECTOR-TOMBSTONE-LABEL). The capture was taken while the
/// row was live, so it decides before any body the window still holds.
/// `Some(true)` for an Owner's member (`None`), which reads every row, and for
/// a capture older than the read, whose tombstone travels as the rules above
/// judge it. `Some(false)` for a failed read. `None` when no capture is bound
/// to the tombstone's request (it names none, there is no row, or the row is
/// bound to another request): the caller judges what the window still holds.
pub(super) fn member_reads_by_capture(
    vault: &Vault,
    txn: &RoTxn<'_>,
    member: Option<&AccessContext<'_>>,
    id: &EntityId,
    value: &[u8],
) -> Option<bool> {
    let Some(member) = member else {
        return Some(true);
    };
    let request = decode_tombstone_value(value).request_id?;
    match deleted_relationship_read_in(&vault.store, txn, id, &request) {
        Ok(Some(Some(read))) => Some(read.allowed_by(member)),
        Ok(Some(None)) => Some(true),
        Ok(None) => None,
        Err(_) => Some(false),
    }
}
