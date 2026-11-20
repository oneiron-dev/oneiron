//! The owner authority a person's removal ends (row
//! OWNER-REVOKE-BY-NAMED-ATTRIBUTION; ruled OWNER-REVOKE-NAMED-ATTRIBUTION =
//! A, direction (b)).
//!
//! A row names the person an owner key speaks for, and an Owner who is about
//! to be removed can still write such rows while they stand. So the removal
//! does not stop at the keys whose enrolment names them. It ends:
//! - every key a counted enrolment names them for, by every such enrolment,
//!   not only the smallest one a listing keeps (a key enrolled on two sibling
//!   branches, once for them and once for another Owner, is theirs too);
//! - every owner key a key of theirs signed in, transitively: an owner key
//!   enrolment it signed, for whomever it names; an owner device it enrolled;
//!   an owner key it rotated to;
//! - every live `human` binding a key of theirs signed, for whomever it names.
//!
//! An owner key enrolment counts here only as the fold read it: an
//! enrolment, when no counted enrolment of the same key is among its
//! ancestors. A passkey vouch's confirmation (REVIEW-9585 round 2) puts no
//! key on the roster, so it neither signs a key in nor names a key's person.
//!
//! A key or a binding that also stands on a counted row none of their keys
//! signed is not theirs, and stays (REVIEW-9585 rounds 1 and 2): a key the
//! host root enrolled for another Owner keeps that row when a key of theirs
//! enrols it again on a sibling branch, replaying the same proof. A row one
//! of their keys signed or cosigned never stands without them, whoever else
//! signed it. The test reads the rows, not their order. A key whose
//! enrolment names them stays theirs whoever else enrolled it.
//!
//! A key in host custody never joins: a host root signs every Owner's
//! enrolment, so it is never the person's own. A key of theirs that is
//! already revoked still carries what it signed in while it stood.

use std::collections::BTreeMap;

use super::*;

/// What [`Vault::owner_authority_closure_in_txn`] finds for one person.
pub(super) struct OwnerAuthorityClosure {
    /// The live owner keys the removal ends, ascending: a device key or a
    /// passkey of the person's, or a key one of theirs signed in.
    pub(super) keys: Vec<AuthorityKey>,
    /// The roster keys of each live `human` binding a key of the person's
    /// signed, whomever the binding names.
    pub(super) signed_bindings: BTreeSet<AuthorityKey>,
}

/// One counted row that adds to a closure.
struct ClosureRow {
    /// The keys that signed it, its cosigners and a rotation's old key among
    /// them.
    signers: Vec<AuthorityKey>,
    /// The owner key it signs in, when it signs one in.
    signs_in: Option<AuthorityKey>,
    /// The roster key, person and epoch of the `human` binding it makes,
    /// when it makes one.
    binds: Option<(AuthorityKey, EntityId, u64)>,
}

impl ClosureRow {
    /// `entry`'s part of a closure, when it has one: an owner key enrolment,
    /// an owner device enrolment, a rotation to an owner device, or a `human`
    /// binding. The caller leaves out an owner key enrolment the fold read
    /// as a confirmation.
    fn of(entry: &AuthorityLogEntry) -> Option<Self> {
        let mut signers: Vec<AuthorityKey> = std::iter::once(entry.signer_key().clone())
            .chain(entry.cosigns.iter().map(|cosign| cosign.public_key.clone()))
            .collect();
        let (signs_in, binds) = match &entry.op {
            AuthorityOp::OwnerKeyEnroll(enroll) => (Some(enroll.device.key.clone()), None),
            AuthorityOp::EnrollDevice { device } if device.roles & ROLE_OWNER != 0 => {
                (Some(device.key.clone()), None)
            }
            AuthorityOp::RotateKey {
                old_key,
                new_device,
            } if new_device.roles & ROLE_OWNER != 0 => {
                signers.push(old_key.clone());
                (Some(new_device.key.clone()), None)
            }
            AuthorityOp::BindActor {
                authority_key,
                actor_ref,
                actor_class,
                epoch,
            }
            | AuthorityOp::RebindActor {
                authority_key,
                actor_ref,
                actor_class,
                epoch,
            } if actor_class == ACTOR_CLASS_HUMAN => {
                (None, Some((authority_key.clone(), *actor_ref, *epoch)))
            }
            _ => return None,
        };
        Some(Self {
            signers,
            signs_in,
            binds,
        })
    }

    /// Whether a key of `theirs` signed it, as its signer, a cosigner or a
    /// rotation's old key. A row none of `theirs` signed stands without them.
    fn signed_by(&self, theirs: &BTreeSet<AuthorityKey>) -> bool {
        self.signers.iter().any(|key| theirs.contains(key))
    }
}

/// One counted owner key enrolment, before the closure knows whether the
/// fold read it as an enrolment or a confirmation.
struct EnrolmentRow {
    hash: AuthorityEntryHash,
    key: AuthorityKey,
    owner: EntityId,
}

/// The counted owner key enrolments the fold read as confirmations: each
/// one with a counted enrolment of the same key among its ancestors in
/// `parents` (a counted entry's parents are counted). A key whose enrolment
/// is not among the visited rows reads as fresh, so its row signs it in.
fn confirmations(
    enrolments: &[EnrolmentRow],
    parents: &BTreeMap<AuthorityEntryHash, Vec<AuthorityEntryHash>>,
) -> BTreeSet<AuthorityEntryHash> {
    let mut by_key: BTreeMap<&AuthorityKey, BTreeSet<AuthorityEntryHash>> = BTreeMap::new();
    for row in enrolments {
        by_key.entry(&row.key).or_default().insert(row.hash);
    }
    let mut confirmed = BTreeSet::new();
    for rows in by_key.values().filter(|rows| rows.len() > 1) {
        for hash in rows {
            let mut seen: BTreeSet<AuthorityEntryHash> = BTreeSet::new();
            let mut todo: Vec<AuthorityEntryHash> = parents.get(hash).cloned().unwrap_or_default();
            while let Some(next) = todo.pop() {
                if !seen.insert(next) {
                    continue;
                }
                if rows.contains(&next) {
                    confirmed.insert(*hash);
                    break;
                }
                todo.extend(parents.get(&next).into_iter().flatten().copied());
            }
        }
    }
    confirmed
}

impl Vault {
    /// The owner authority the removal of `person` ends, read in `txn` from
    /// every counted row this vault keeps, stored or carried by an adopted
    /// checkpoint image (the module doc says what joins).
    ///
    /// # Errors
    /// The store's, reading the rows.
    pub(super) fn owner_authority_closure_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        person: EntityId,
    ) -> Result<OwnerAuthorityClosure> {
        let mut parents: BTreeMap<AuthorityEntryHash, Vec<AuthorityEntryHash>> = BTreeMap::new();
        let mut enrolments: Vec<EnrolmentRow> = Vec::new();
        let mut counted: Vec<(AuthorityEntryHash, ClosureRow)> = Vec::new();
        self.visit_authority_entries_in_txn(txn, |fold, hash, entry| {
            if !fold.valid_entries.contains(&hash) {
                return;
            }
            parents.insert(hash, entry.parent_hashes.clone());
            if let AuthorityOp::OwnerKeyEnroll(enroll) = &entry.op {
                enrolments.push(EnrolmentRow {
                    hash,
                    key: enroll.device.key.clone(),
                    owner: enroll.act.owner,
                });
            }
            if let Some(row) = ClosureRow::of(entry) {
                counted.push((hash, row));
            }
        })?;
        let confirmed = confirmations(&enrolments, &parents);
        let rows: Vec<ClosureRow> = counted
            .into_iter()
            .filter(|(hash, _)| !confirmed.contains(hash))
            .map(|(_, row)| row)
            .collect();
        let view = self.authority_view_readonly_in_txn(txn)?;
        let fold: &AuthorityFold = &view;
        let named: BTreeSet<AuthorityKey> = enrolments
            .iter()
            .filter(|row| row.owner == person && !confirmed.contains(&row.hash))
            .map(|row| row.key.clone())
            .filter(|key| !fold.in_host_custody(key))
            .collect();
        let mut theirs = named.clone();
        // Every key a key of theirs signed in, transitively.
        loop {
            let joined: Vec<AuthorityKey> = rows
                .iter()
                .filter(|row| row.signed_by(&theirs))
                .filter_map(|row| row.signs_in.clone())
                .filter(|key| !theirs.contains(key) && !fold.in_host_custody(key))
                .collect();
            if joined.is_empty() {
                break;
            }
            theirs.extend(joined);
        }
        // Less every key no enrolment names them for that a row none of
        // theirs signed also signs in, and what it signed in that then
        // stands without them.
        loop {
            let standing: BTreeSet<AuthorityKey> = rows
                .iter()
                .filter(|row| !row.signed_by(&theirs))
                .filter_map(|row| row.signs_in.clone())
                .filter(|key| theirs.contains(key) && !named.contains(key))
                .collect();
            if standing.is_empty() {
                break;
            }
            theirs.retain(|key| !standing.contains(key));
        }
        let keys = theirs
            .iter()
            .filter(|key| fold.roster.get(key).is_some_and(|device| !device.revoked))
            .cloned()
            .collect();
        let standing_bindings: BTreeSet<(AuthorityKey, EntityId, u64)> = rows
            .iter()
            .filter(|row| !row.signed_by(&theirs))
            .filter_map(|row| row.binds.clone())
            .collect();
        let signed_bindings = rows
            .iter()
            .filter(|row| row.signed_by(&theirs))
            .filter_map(|row| row.binds.clone())
            .filter(|binding| !standing_bindings.contains(binding))
            .filter(|(key, actor_ref, epoch)| {
                fold.actor_bindings.get(key).is_some_and(|binding| {
                    binding.status == ActorBindingStatus::Active
                        && binding.actor_class == ACTOR_CLASS_HUMAN
                        && binding.actor_ref == *actor_ref
                        && binding.epoch == *epoch
                })
            })
            .map(|(key, _, _)| key)
            .collect();
        Ok(OwnerAuthorityClosure {
            keys,
            signed_bindings,
        })
    }
}
