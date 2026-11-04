//! The owner's mark that he imported one export secret supplement, as the
//! fold keeps it (FIX 12062).
//!
//! A mark is valid when some chain of its carrier names the key that signed
//! it and the request it names is in its causal past (the fold of its
//! parents), an export secret request. It has effect when the one carrier
//! rule admits that carrier on the roster view, and its owner is live there
//! and is the owner whose export the request carries; otherwise it is valid
//! and without effect, as is a mark of a request without effect. A mark only
//! takes away: once the fold holds it, no install relays the request's
//! sealed copy on the window plane, so a later removal of its carrier does
//! not lift it. Nothing else changes: the request, its result and every copy
//! an install keeps stay, and the owner still reads his copy.

use super::*;

impl AuthorityFold {
    /// Whether the owner's import of the supplement of the export secret
    /// request signed as entry `request` is marked here, by a mark with
    /// effect.
    pub(crate) fn export_supplement_imported(&self, request: &AuthorityEntryHash) -> bool {
        self.owner_work.imported.contains(request)
    }
}

/// A mark lands as the owner's word that he imported the request's
/// supplement, unless its carrier or owner does not stand at its parents.
pub(super) fn apply_import_mark(
    state: &mut FoldState,
    entry: &AuthorityLogEntry,
    mark: &ExportSupplementImported,
    hash: AuthorityEntryHash,
    (pin, counted): (Option<&PinnedRoot>, InstallCounted<'_>),
) -> std::result::Result<(), AuthorityFoldIssue> {
    let standing = Standing::new(state, pin, counted);
    let key = install_signer(&standing, state, entry, mark.carrier, hash)?;
    let roster = StandingView::Under(MachineAdmitter::Roster);
    let admitted = standing.admits_owner_act_signer(mark.carrier, &key, roster);
    drop(standing);
    let live = admitted && super::super::owner_act::owner_live_at(state, mark.act.owner);
    let work = &mut state.owner_work;
    // The causal request-presence check, as a cancel's: the request is in
    // the mark's past, an export secret request. A mark of a request
    // without effect there is without effect too.
    let exporter = match work.requests.get(&mark.request) {
        Some(asked) => match &asked.request.work {
            OwnerWorkBody::ExportSecret(_) => asked.request.act.owner,
            _ => return Err(AuthorityFoldIssue::InvalidEntry(hash)),
        },
        None if work.refused.contains(&mark.request) => {
            work.refused.insert(hash);
            return Ok(());
        }
        None => return Err(AuthorityFoldIssue::InvalidEntry(hash)),
    };
    if !live || exporter != mark.act.owner {
        work.refused.insert(hash);
        return Ok(());
    }
    work.imported.insert(mark.request);
    Ok(())
}
