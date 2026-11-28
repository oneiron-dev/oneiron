//! The native run host's discovery view (3b-2b PR 2, D4): the strict,
//! credential-filtered projection of the code-mode catalogue for one
//! [`RunHostDoor`] binding. Dormant: PR 3 (typed run host) is its first caller.
//!
//! It admits only native routes proven from the door without guessing, and
//! every check it runs is a read: no write, no consent spent, no hook run,
//! no model call, no grant minted. With no door, no live admitting lane, a
//! trapped step, a slip-bound door or unreadable view data, it answers
//! [`DiscoveryView::empty`], never the vault-wide catalogue.
//!
//! Admitted: the resident rows (the run's own board, self brief and lens
//! seats, which the door serves under any binding with no admission check),
//! the browser and desktop rows the run's shared guest admission passes, and
//! the owner rows while the run host's live owner proof holds (proved by the
//! same check the owner-row dispatch proves per row). NOTE kinds go to the
//! owner audience only on that same live proof.
//!
//! Hidden (fail closed): everything served through the host seats or the
//! generated dispatcher, whose admission needs per-call scope the door alone
//! cannot prove (lane readability, connector grants, line spend scope, entry
//! bindings, record ACLs, Settings, permits, hooks); the run rows, which the
//! run and its action registry serve rather than the door, on surfaces and
//! powers the door cannot prove; the tree calls, which are not generated rows
//! and no door serves (PR 3's dispatcher serves them from the bound view);
//! and every row of a slip-woken program, whose per-row gate lives
//! dispatcher-side and cannot be shared narrowly from here. Grants and
//! Settings are never consulted. Dispatcher-side replay and session narrowing
//! stays dispatcher-side, as all per-call gates do: this view proves
//! live-call authority only.

#![cfg_attr(
    not(test),
    allow(dead_code, reason = "dormant until 3b-2b PR 3 binds the run host door")
)]

use oneiron::EdgeActorClass;
use oneiron::task_verb::sdk::AgentVerb;
use oneiron::verbs::tree::{AdmittedRows, DiscoveryView, NoteKindAudience, VerbTree};

use super::RunHostDoor;
use crate::server::owner_program_rows::is_owner_row;

/// The strict discovery view for `door`'s binding: the shipped catalogue
/// projected to the door-proven native routes, with NOTE kinds for its
/// audience. A missing door, a missing live lane, or unproven authority
/// returns the empty view.
pub(crate) fn native_discovery_view(door: Option<&RunHostDoor>) -> DiscoveryView {
    let Some(door) = door else {
        return DiscoveryView::empty();
    };
    // A slip-woken program's per-row gate lives dispatcher-side
    // (`program_authority_refusal`) and cannot be shared narrowly from here,
    // so none of its rows can be proven: empty, without consulting the slip.
    if door.proof.is_some() || door.media_trapped() || door.admitting_memory().read_key().is_err() {
        return DiscoveryView::empty();
    }
    let owner = live_owner_proof(door);
    let admitted: AdmittedRows = AgentVerb::ALL
        .iter()
        .copied()
        .filter(|verb| admit_agent(door, *verb, owner))
        .map(AgentVerb::as_str)
        .collect();
    // No catalogue cache exists server-side yet, so the view builds one
    // shipped tree per call; an unreadable catalogue or options file hides
    // every row rather than falling back to a vault-wide catalogue.
    let tree = match VerbTree::shipped() {
        Ok(tree) => tree,
        Err(_) => return DiscoveryView::empty(),
    };
    let options = match door.server.vault().verb_view_options() {
        Ok(options) => options,
        Err(_) => return DiscoveryView::empty(),
    };
    let kinds = if owner {
        NoteKindAudience::Owner
    } else {
        NoteKindAudience::NonOwner
    };
    tree.discovery_view(admitted, options, kinds)
}

/// The run host's live owner proof, proved exactly as the owner-row dispatch
/// proves it for each row (`owner_program_rows::program_owner`): a Human
/// actor the vault records as its owner, while that owner is live. The
/// actor's class alone is never the proof, and an unreadable vault proves
/// nothing. Reads only: the owner checks below open read transactions and
/// record nothing.
fn live_owner_proof(door: &RunHostDoor) -> bool {
    if door.actor.actor_class() != EdgeActorClass::Human {
        return false;
    }
    crate::api::managed_owner_proof(&door.server, door.actor.entity_ref())
        .ok()
        .flatten()
        .is_some()
}

/// Whether `verb` is proven callable under this binding: a browser or desktop
/// row the run's shared guest admission passes (pack installed, connection
/// checked, guest bound to this run), a resident row the run's own seats
/// serve under any binding, or an owner row while the live owner proof holds.
/// Every other row hides: host-served and generated rows need per-call scope
/// this door alone cannot prove, and run rows are not door-served.
fn admit_agent(door: &RunHostDoor, verb: AgentVerb, owner: bool) -> bool {
    if verb.is_browser() {
        return door.guests.admits(verb, &door.server).is_ok();
    }
    if is_resident(verb) {
        return true;
    }
    owner && is_owner_row(verb)
}

/// Whether `verb` is a resident row: the focus rows always take the board
/// seat, `describe` a resident seat for either shaped input, and the lens its
/// own. This mirrors the input-free part of `resident_row`/`is_board_row`.
fn is_resident(verb: AgentVerb) -> bool {
    matches!(
        verb,
        AgentVerb::SelfFocusRefresh
            | AgentVerb::SelfFocusSubscribe
            | AgentVerb::SelfFocusUnsubscribe
            | AgentVerb::Describe
            | AgentVerb::VaultWeaveLens
    )
}
