//! Complete root group cards (FIX 9871): every open Dreamer proposal in the
//! tray, read in one pass with its run-tree root and the semantic hash of
//! its current body, and the card of one root over that pass. Browse and the
//! explicit doors (resolve, reopen) build the same card from it.
//! `OpenTray::read` and `root_group_card` are its call surface.

use std::collections::HashMap;

use crate::Vault;
use crate::attempt_queue::AttemptQueue;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::Result;
use crate::receipt::{ReceiptView, gate_decision_receipt, hex_lower};

use super::model::{
    InboxGroup, InboxGroupCursor, InboxGroupMember, InboxPointerRow, InboxReviewDial,
};
use super::projection::{
    GroupDraft, MemberDraft, OpenMember, classify_member, finish_group_draft, inbox_claim_hash,
    member_surfaces, open_dreamer_members_from_pending, resolve_run_identity, sub_cluster_key,
};

/// Each stamped run's group identity, resolved once per read.
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

/// Every open Dreamer proposal in the tray, in the tray's order (proposal
/// time, decision id, claim id), each with its group key and the semantic
/// hash of its current body. Duplicate ownership reads these hashes: a
/// stored hash sidecar can lag a same-id rewrite, the current body cannot.
pub(super) struct OpenTray {
    members: Vec<OpenMember>,
    keys: Vec<String>,
    hashes: Vec<[u8; 32]>,
    by_key: HashMap<String, Vec<usize>>,
    by_hash: HashMap<[u8; 32], Vec<usize>>,
    /// Each group once, at its earliest row, in the tray's order.
    starts: Vec<(InboxGroupCursor, String)>,
}

impl OpenTray {
    /// The whole tray in one snapshot, no count cut.
    pub(super) fn read(vault: &Vault, runs: &mut RunGroups<'_>) -> Result<Self> {
        let pending = {
            let txn = vault.store.env.read_txn()?;
            vault.store.pending_gate_consents_in_txn(&txn, usize::MAX)?
        };
        let members = open_dreamer_members_from_pending(vault, pending)?;
        let mut tray = Self {
            keys: Vec::with_capacity(members.len()),
            hashes: Vec::with_capacity(members.len()),
            by_key: HashMap::new(),
            by_hash: HashMap::new(),
            starts: Vec::new(),
            members: Vec::new(),
        };
        for (index, member) in members.iter().enumerate() {
            let key = runs.identity(&member.run_id)?.0.clone();
            let hash = inbox_claim_hash(&member.body)?;
            let rows = tray.by_key.entry(key.clone()).or_default();
            if rows.is_empty() {
                tray.starts
                    .push((InboxGroupCursor::of(&member.pending), key.clone()));
            }
            rows.push(index);
            tray.by_hash.entry(hash).or_default().push(index);
            tray.keys.push(key);
            tray.hashes.push(hash);
        }
        tray.members = members;
        Ok(tray)
    }

    /// Each group once, at its earliest row, in the tray's order.
    pub(super) fn starts(&self) -> &[(InboxGroupCursor, String)] {
        &self.starts
    }

    /// The group a door names: a group key the tray holds, else the root
    /// group of the literal run id it names, whether or not that run still
    /// waits itself; a run with no run-tree root is its own group.
    pub(super) fn group_named(&self, vault: &Vault, group_ref: &str) -> Result<String> {
        if self.by_key.contains_key(group_ref) {
            return Ok(group_ref.to_owned());
        }
        Ok(AttemptQueue::new(vault)
            .dreamer_run_root_id(group_ref)?
            .map_or_else(
                || group_ref.to_owned(),
                |root| bytes_to_hex_lower(root.as_bytes()),
            ))
    }
}

/// The card of the group keyed `group_key` over every open row `tray` holds
/// for it, oldest first, surfaced under `dial`. A member whose current hash
/// an earlier group's row owns is that group's pointer row; the owning row
/// carries every other group's duplicate and its exception classes, so the
/// dial can never hide them. Repeats inside one group stay its members.
/// `None` when no member or pointer row remains.
pub(super) fn root_group_card(
    vault: &Vault,
    tray: &OpenTray,
    runs: &mut RunGroups<'_>,
    group_key: &str,
    now: u64,
    dial: InboxReviewDial,
) -> Result<Option<InboxGroup>> {
    let Some(rows) = tray.by_key.get(group_key) else {
        return Ok(None);
    };
    let first = &tray.members[rows[0]];
    let intent = runs.identity(&first.run_id)?.1.clone();
    let mut draft = GroupDraft {
        group_key: group_key.to_owned(),
        run_id: first.run_id.clone(),
        intent,
        created_at: first.pending.created_at,
        members: Vec::new(),
        pointer_rows: Vec::new(),
    };

    for &index in rows {
        let member = &tray.members[index];
        // The member itself is among its hash's rows, so the earliest exists.
        let duplicates = &tray.by_hash[&tray.hashes[index]];
        let earliest = duplicates[0];
        let claim_id_hex = hex_lower(&member.pending.claim_id);
        if tray.keys[earliest] != group_key {
            draft.pointer_rows.push(InboxPointerRow {
                claim_id: claim_id_hex,
                duplicate_of_claim_id: hex_lower(&tray.members[earliest].pending.claim_id),
                duplicate_of_group_key: tray.keys[earliest].clone(),
            });
            continue;
        }

        let (mut classes, verb_class) = classify_member(vault, member)?;
        let mut duplicate_claim_ids = Vec::new();
        if earliest == index {
            for &duplicate in duplicates {
                if tray.keys[duplicate] == group_key {
                    continue;
                }
                let duplicate = &tray.members[duplicate];
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
