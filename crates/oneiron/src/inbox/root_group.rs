//! One complete root group card (FIX 9871): every pending row the root-group
//! index holds for a run-tree root, whichever run stamped it, with each
//! semantic duplicate owned by the earliest open row of its hash across
//! roots. Browse and the explicit doors (resolve, reopen) build the same card.
//! `root_group_card` is its call surface.

use std::collections::HashMap;
use std::collections::hash_map::Entry;

use crate::Vault;
use crate::error::Result;
use crate::receipt::{ReceiptView, gate_decision_receipt, hex_lower};
use crate::store::PendingGateConsentRecord;

use super::model::{InboxGroup, InboxGroupMember, InboxPointerRow, InboxReviewDial};
use super::projection::{
    GroupDraft, MemberDraft, OpenMember, classify_member, finish_group_draft, inbox_claim_hash,
    member_surfaces, open_dreamer_members_from_pending, resolve_run_identity, sub_cluster_key,
};

/// Each stamped run's group identity, resolved once per card or page.
pub(super) struct RunGroups<'v> {
    vault: &'v Vault,
    identities: HashMap<String, (String, Option<String>)>,
}

impl<'v> RunGroups<'v> {
    pub(super) fn new(vault: &'v Vault) -> Self {
        Self {
            vault,
            identities: HashMap::new(),
        }
    }

    /// `run_id`'s group key (its run-tree root, else the run id) and the
    /// root brief's stated intent.
    pub(super) fn identity(&mut self, run_id: &str) -> Result<&(String, Option<String>)> {
        if !self.identities.contains_key(run_id) {
            let identity = resolve_run_identity(self.vault, run_id)?;
            self.identities.insert(run_id.to_owned(), identity);
        }
        Ok(&self.identities[run_id])
    }
}

/// The card of the group keyed `group_key` over `pending`, the group's
/// complete indexed rows, oldest first, surfaced under `dial`. A member whose
/// semantic hash an earlier root's row owns is that group's pointer row; the
/// owning row carries every other root's duplicate and its exception
/// classes, so the dial can never hide them. Repeats inside one root stay
/// its members. `None` when no member or pointer row remains.
pub(super) fn root_group_card(
    vault: &Vault,
    runs: &mut RunGroups<'_>,
    group_key: &str,
    pending: Vec<PendingGateConsentRecord>,
    now: u64,
    dial: InboxReviewDial,
) -> Result<Option<InboxGroup>> {
    let members = open_dreamer_members_from_pending(vault, pending)?;
    let Some(first) = members.first() else {
        return Ok(None);
    };
    let intent = runs.identity(&first.run_id)?.1.clone();
    let mut draft = GroupDraft {
        group_key: group_key.to_owned(),
        run_id: first.run_id.clone(),
        intent,
        created_at: first.pending.created_at,
        members: Vec::new(),
        pointer_rows: Vec::new(),
    };
    let mut duplicates_by_hash: HashMap<[u8; 32], Vec<OpenMember>> = HashMap::new();

    for member in &members {
        let claim_hash = inbox_claim_hash(&member.body)?;
        if let Entry::Vacant(entry) = duplicates_by_hash.entry(claim_hash) {
            let pending = vault
                .store
                .pending_gate_consents_for_semantic_claim_hash(&claim_hash)?;
            entry.insert(open_dreamer_members_from_pending(vault, pending)?);
        }
        let duplicates = &duplicates_by_hash[&claim_hash];
        // A same-id proposal rewrite can leave its old semantic-hash sidecar
        // behind. Browse keeps the pending row visible; the card treats this
        // current member as its own singleton rather than calling the stale
        // sidecar corruption.
        let earliest = duplicates.first().unwrap_or(member);
        let claim_id_hex = hex_lower(&member.pending.claim_id);
        let earliest_key = runs.identity(&earliest.run_id)?.0.clone();
        if earliest_key != group_key {
            draft.pointer_rows.push(InboxPointerRow {
                claim_id: claim_id_hex,
                duplicate_of_claim_id: hex_lower(&earliest.pending.claim_id),
                duplicate_of_group_key: earliest_key,
            });
            continue;
        }

        let (mut classes, verb_class) = classify_member(vault, member)?;
        let mut duplicate_claim_ids = Vec::new();
        if earliest.pending.claim_id == member.pending.claim_id {
            for duplicate in duplicates {
                if runs.identity(&duplicate.run_id)?.0 == group_key {
                    continue;
                }
                let (duplicate_classes, _) = classify_member(vault, duplicate)?;
                duplicate_claim_ids.push(hex_lower(&duplicate.pending.claim_id));
                classes.extend(duplicate_classes);
            }
            classes.sort_unstable();
            classes.dedup();
        }
        let surfaced = member_surfaces(dial, &classes);
        draft.members.push(MemberDraft {
            member: InboxGroupMember {
                claim_id: claim_id_hex,
                created_at: member.pending.created_at,
                age_secs: now.saturating_sub(member.pending.created_at),
                hold_reasons: member.pending.reason_codes.clone(),
                exception_classes: classes,
                verb_class: verb_class.to_owned(),
                duplicate_claim_ids,
                receipt_view: ReceiptView::new(gate_decision_receipt(&member.decision)),
            },
            surfaced,
            cluster_key: sub_cluster_key(&member.body),
        });
    }
    Ok(finish_group_draft(draft))
}
