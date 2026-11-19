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
//!   a key it rotated to;
//! - every live `human` binding a key of theirs signed, for whomever it names.
//!
//! A key in host custody never joins: a host root signs every Owner's
//! enrolment, so it is never the person's own. A key of theirs that is
//! already revoked still carries what it signed in while it stood.

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
    /// The roster key and epoch of the `human` binding it makes, when it
    /// makes one.
    binds: Option<(AuthorityKey, u64)>,
}

impl ClosureRow {
    /// `entry`'s part of a closure, when it has one: an owner key enrolment,
    /// an owner device enrolment, a key rotation, or a `human` binding.
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
            } => {
                signers.push(old_key.clone());
                (Some(new_device.key.clone()), None)
            }
            AuthorityOp::BindActor {
                authority_key,
                actor_class,
                epoch,
                ..
            }
            | AuthorityOp::RebindActor {
                authority_key,
                actor_class,
                epoch,
                ..
            } if actor_class == ACTOR_CLASS_HUMAN => (None, Some((authority_key.clone(), *epoch))),
            _ => return None,
        };
        Some(Self {
            signers,
            signs_in,
            binds,
        })
    }
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
        let mut theirs: BTreeSet<AuthorityKey> = BTreeSet::new();
        let mut rows: Vec<ClosureRow> = Vec::new();
        self.visit_authority_entries_in_txn(txn, |fold, hash, entry| {
            if !fold.valid_entries.contains(&hash) {
                return;
            }
            if let AuthorityOp::OwnerKeyEnroll(enroll) = &entry.op
                && enroll.act.owner == person
                && !fold.in_host_custody(&enroll.device.key)
            {
                theirs.insert(enroll.device.key.clone());
            }
            if let Some(row) = ClosureRow::of(entry) {
                rows.push(row);
            }
        })?;
        let view = self.authority_view_readonly_in_txn(txn)?;
        let fold: &AuthorityFold = &view;
        let signed_by_theirs = |row: &ClosureRow, theirs: &BTreeSet<AuthorityKey>| {
            row.signers.iter().any(|key| theirs.contains(key))
        };
        loop {
            let joined: Vec<AuthorityKey> = rows
                .iter()
                .filter(|row| signed_by_theirs(row, &theirs))
                .filter_map(|row| row.signs_in.clone())
                .filter(|key| !theirs.contains(key) && !fold.in_host_custody(key))
                .collect();
            if joined.is_empty() {
                break;
            }
            theirs.extend(joined);
        }
        let keys = theirs
            .iter()
            .filter(|key| fold.roster.get(key).is_some_and(|device| !device.revoked))
            .cloned()
            .collect();
        let signed_bindings = rows
            .iter()
            .filter(|row| signed_by_theirs(row, &theirs))
            .filter_map(|row| row.binds.clone())
            .filter(|(key, epoch)| {
                fold.actor_bindings.get(key).is_some_and(|binding| {
                    binding.status == ActorBindingStatus::Active
                        && binding.actor_class == ACTOR_CLASS_HUMAN
                        && binding.epoch == *epoch
                })
            })
            .map(|(key, _)| key)
            .collect();
        Ok(OwnerAuthorityClosure {
            keys,
            signed_bindings,
        })
    }
}
