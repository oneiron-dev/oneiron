//! A kit change's carry: the roster standings and the actor bindings the new
//! recovery authority key R signs again, chosen before the R keys it replaces
//! are revoked and written under the new R.

use super::*;

/// The fold did not count a row by which a kit change's new R carries an
/// approval the revoked R signed. Nothing was written.
const CARRY_NOT_COUNTED: &str = "this install's fold does not count the new kit's carry of an \
                                 approval the old kit signed; nothing was written";

/// What a kit change's new R must carry, chosen before the act revokes the
/// R keys it replaces ([`Vault::recovery_authority_carry_in_txn`]).
#[derive(Debug, Default)]
pub(crate) struct RecoveryAuthorityCarry {
    /// Each roster standing the new R signs again, as the next revision
    /// above its machine's roster head: the head, or the accepted chain's
    /// head when that is another revision (REVIEW-9488 P1 5).
    machines: Vec<MachineProfile>,
    /// Each binding's `RebindActor` one epoch on, which the new R signs.
    rebinds: Vec<AuthorityOp>,
}

/// One standing's or binding's approvals, as the carry's one pass over the
/// history counts them ([`Vault::recovery_authority_carry_in_txn`]).
#[derive(Debug, Default)]
struct CarrySupport {
    /// An approval resting on no key revoked before the act exists.
    open: bool,
    /// An approval resting on no key revoked before the act, nor on a key
    /// the act revokes, exists, or an anchor's row, which never goes stale.
    independent: bool,
}

impl CarrySupport {
    /// The act's revocation would leave no approval that keeps it live.
    fn carried(&self) -> bool {
        self.open && !self.independent
    }
}

/// Whether `entry`'s primary signature or a cosign names a key `revoked`
/// holds: the keys an approval rests on, as the stale-roster window reads
/// them (`stale_roster.rs`).
fn rests_on(entry: &AuthorityLogEntry, revoked: impl Fn(&AuthorityKey) -> bool) -> bool {
    std::iter::once(&entry.signer)
        .chain(&entry.cosigns)
        .any(|signature| revoked(&signature.public_key))
}

impl Vault {
    /// Chooses, in the caller's write transaction and BEFORE any key in
    /// `revoking` is revoked, what the R that replaces them must carry
    /// (WAYBACK-R-REVOCATION-STALES-R-APPROVALS = A, Engine 07:13: a kit
    /// change must not unpair the owner's own machines). The choice comes
    /// first because an approval's stale deadline counts from the earlier of
    /// its own first sight and its key's revocation (`stale_roster.rs`): one
    /// older than the window goes stale the moment its key is revoked, so a
    /// fold read after the revocation would miss every aged approval (Sol
    /// carry F1).
    ///
    /// The test is the stale-roster window's own (Sol carry F2): an approval
    /// rests on every key its primary signature or a cosign names. Of the
    /// approvals that rest on no key revoked before this act, when at least
    /// one exists and every one rests on a key in `revoking`, the act would
    /// unpair the standing, so it is carried; one approval resting on none
    /// keeps it live and nothing is carried; and a standing that only rests
    /// on keys revoked before is already going stale (the ruling's guard).
    /// - A machine's live, act-free roster head: its approvals are the valid
    ///   roster rows with the head's exact profile (the rows that renew a
    ///   stale head; an anchor's row renews none). A head an anchor's row
    ///   carried never goes stale and is not carried.
    /// - An active binding: its approvals are the valid `BindActor` and
    ///   `RebindActor` rows of its current tuple (an anchor's row never goes
    ///   stale, so it keeps the binding live). The binding of a key in
    ///   `revoking` ends with that key and is not carried.
    ///
    /// A head at the last revision, or a binding at the last epoch, has no
    /// next row, so it is not carried: no row the revoked key signed can
    /// refuse the kit change that revokes the key (Sol carry F2, F3). Only a
    /// live R's holder can sign such a row, and the standing goes stale as
    /// it did before the carry (FIX [KIT-CHANGE-CARRY-SKIPS-LAST-COUNTER]).
    /// The history is read once (Sol carry F4): the stored rows and the
    /// bodies an adopted checkpoint image carries (Sol carry-fix F2).
    ///
    /// # Errors
    /// A fold or history read's.
    pub(crate) fn recovery_authority_carry_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        revoking: &[AuthorityKey],
    ) -> Result<RecoveryAuthorityCarry> {
        if revoking.is_empty() {
            return Ok(RecoveryAuthorityCarry::default());
        }
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let revoked_before: std::collections::BTreeSet<&AuthorityKey> = fold
            .roster
            .iter()
            .filter(|(_, device)| device.revoked)
            .map(|(key, _)| key)
            .collect();
        // Each machine's roster head and the accepted chain's head (a
        // custodial revision above an owner-held one leaves the accepted
        // chain at the owner-held one), each with its own support: the
        // stale-roster window expires either once the R it rests on is
        // revoked, and renews the accepted chain's only by a mark that chain
        // accepts (REVIEW-9488 round 2 P1 5).
        let mut machines: std::collections::BTreeMap<_, Vec<_>> = fold
            .machines
            .iter()
            .filter_map(|(machine, folded)| {
                let head = folded.roster.as_ref()?;
                if head.profile.revision == u64::MAX {
                    return None;
                }
                let heads: Vec<_> = [(Some(head), false), (folded.roster_trusted.as_ref(), true)]
                    .into_iter()
                    .filter_map(|(head, trusted)| Some((head?, trusted)))
                    .filter(|(head, _)| {
                        head.is_live()
                            && head.profile.act.is_none()
                            && !fold.anchor_entries.contains(&head.entry)
                    })
                    .map(|(head, trusted)| (&head.profile, trusted, CarrySupport::default()))
                    .collect();
                (!heads.is_empty()).then_some((*machine, heads))
            })
            .collect();
        let mut bindings: std::collections::BTreeMap<_, _> = fold
            .actor_bindings
            .iter()
            .filter(|(bound, binding)| {
                matches!(binding.status, ActorBindingStatus::Active)
                    && binding.epoch < u64::MAX
                    && !revoking.contains(bound)
            })
            .map(|(bound, binding)| (bound, (binding, CarrySupport::default())))
            .collect();
        // The approvals the stale-roster window reads: each stored row, and
        // each body an adopted checkpoint image carries that this vault does
        // not store (the adopted fold expires those too), a stored row
        // winning over the image's copy, as the enrolled-key reader reads
        // them (Sol carry-fix F2).
        let history = crate::authority::history_transfer::history_in_txn(self, txn)?;
        let stored: std::collections::BTreeSet<AuthorityEntryHash> =
            history.keys().copied().collect();
        let evidence =
            crate::authority::adopted_evidence::adopted_evidence_in_txn(&self.store, txn)?;
        let stored = &stored;
        let carried_past = evidence
            .iter()
            .flat_map(move |evidence| evidence.carried_past(stored));
        let approvals = history
            .iter()
            .map(|(hash, (_, entry))| (hash, entry))
            .chain(carried_past);
        for (hash, entry) in approvals {
            if !fold.valid_entries.contains(hash) {
                continue;
            }
            let anchor = fold.anchor_entries.contains(hash);
            // The accepted chain's head counts only a mark that chain
            // accepts, as the stale-roster window renews it, never a
            // custodial copy of its profile (`stale_roster.rs`).
            let accepted = fold.accepted_roster_marks.contains(hash);
            // A kit restore's inline join is its R's roster revision of the
            // machine, so a kit change carries it as a profile row
            // (REVIEW-9539 round 2 P1).
            let filed = crate::authority::stale_roster::filed_machine_profile(&entry.op)
                .filter(|_| !anchor);
            let supports: Vec<&mut CarrySupport> = match (filed, &entry.op) {
                (Some(profile), _) => machines
                    .get_mut(&profile.machine)
                    .into_iter()
                    .flatten()
                    .filter(|(head, trusted, _)| *head == profile && (accepted || !*trusted))
                    .map(|(_, _, support)| support)
                    .collect(),
                (
                    _,
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
                    },
                ) => match bindings.get_mut(authority_key) {
                    Some((binding, support))
                        if binding.actor_ref == *actor_ref
                            && binding.actor_class == *actor_class
                            && binding.epoch == *epoch =>
                    {
                        vec![support]
                    }
                    _ => Vec::new(),
                },
                _ => Vec::new(),
            };
            for support in supports {
                if anchor {
                    support.independent = true;
                } else if !rests_on(entry, |key| revoked_before.contains(key)) {
                    support.open = true;
                    if !rests_on(entry, |key| revoking.contains(key)) {
                        support.independent = true;
                    }
                }
            }
        }
        let rebinds = bindings
            .into_iter()
            .filter(|(_, (_, support))| support.carried())
            .map(|(bound, (binding, _))| {
                Ok(AuthorityOp::RebindActor {
                    authority_key: bound.clone(),
                    actor_ref: binding.actor_ref,
                    actor_class: binding.actor_class.clone(),
                    epoch: binding.epoch.checked_add(1).ok_or_else(invalid_authority)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        // One row per machine: the accepted chain's standing when the act
        // would leave it with no approval, else the head's.
        Ok(RecoveryAuthorityCarry {
            machines: machines
                .into_values()
                .filter_map(|heads| {
                    heads
                        .into_iter()
                        .rev()
                        .find(|(_, _, support)| support.carried())
                        .map(|(profile, _, _)| profile.clone())
                })
                .collect(),
            rebinds,
        })
    }

    /// Carries `carry`, chosen before the act revoked the R keys it names
    /// ([`Self::recovery_authority_carry_in_txn`]), under `next`, the R that
    /// replaces them and is live on the roster, as a host re-root carries
    /// its standings ([`Self::carry_machine_standing_in_txn`]): `next` signs
    /// the next revision of each chosen machine's roster head
    /// ([`Self::carry_roster_standing_under_key_in_txn`]), and a
    /// `RebindActor` one epoch on, with the same key, actor and class, for
    /// each chosen binding. Stored change: keep (ordinary rows).
    ///
    /// # Errors
    /// A carried row the fold does not count.
    pub(crate) fn carry_recovery_authority_approvals_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        carry: RecoveryAuthorityCarry,
        next: &crate::world_keys::RecoveryAuthoritySigner,
    ) -> Result<()> {
        let key = next.authority_key();
        let sign = |transcript: &[u8]| next.sign_authority_transcript(transcript);
        for standing in &carry.machines {
            self.carry_roster_standing_under_key_in_txn(txn, (&key, &sign), standing)?;
        }
        for rebind in carry.rebinds {
            self.append_key_signed_op_in_txn(txn, (&key, &sign), rebind, CARRY_NOT_COUNTED)?;
        }
        Ok(())
    }
}
