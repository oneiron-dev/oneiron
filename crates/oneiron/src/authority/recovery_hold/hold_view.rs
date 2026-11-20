//! A recovery hold as an owner device reads it (OPUS-WAYBACK): the hold
//! view, its states and who answered, judged from the counted log
//! ([`Vault::recovery_holds_in_txn`]).

use super::*;

/// Whether `key` is `actor`'s own owner key, as the vouch door reads one
/// (#8796): a key whose enrolment names `actor` as its owner (`enrolled`),
/// or a key no enrolment names (a self-host home's host root) that no live
/// `human` binding gives to another person. Only the hold's owner's own key
/// says `ItIsMe` (REVIEW2 #8800 P2-1): a co-owner's key never ends another
/// owner's wait, as it never vouches a key into another owner.
pub(super) fn key_is_the_owners(
    fold: &AuthorityFold,
    enrolled: Option<EntityId>,
    key: &AuthorityKey,
    actor: EntityId,
) -> bool {
    match enrolled {
        Some(owner) => owner == actor,
        None => fold.actor_bindings.get(key).is_none_or(|binding| {
            binding.status != ActorBindingStatus::Active
                || binding.actor_class != ACTOR_CLASS_HUMAN
                || binding.actor_ref == actor
        }),
    }
}

/// The person whose key `key` is, for a notice that names who answered: the
/// owner its enrolment names (`enrolled`), else the person a live `human`
/// binding gives it to (a self-host home's host root), else none.
fn key_person(
    fold: &AuthorityFold,
    enrolled: Option<EntityId>,
    key: &AuthorityKey,
) -> Option<EntityId> {
    enrolled.or_else(|| {
        fold.actor_bindings
            .get(key)
            .filter(|binding| {
                binding.status == ActorBindingStatus::Active
                    && binding.actor_class == ACTOR_CLASS_HUMAN
            })
            .map(|binding| binding.actor_ref)
    })
}

/// One counted answer to a hold: its kind, its signer and its entry hash.
type HoldAnswerRow = (RecoveryHoldAnswerKind, AuthorityKey, AuthorityEntryHash);

/// The rows the hold view reads off the counted log: each hold with its
/// signer R, each answer with its kind, signer and hash, every key a valid
/// enrolment made a recovery root's authority key (the fold's own memory of
/// the R keys), which tells the kit's Cancel from an owner device's, the
/// owner each valid owner-key enrolment names, which tells the hold's
/// owner's `ItIsMe` from a co-owner's, and each owner-key enrolment's hash
/// by the key it enrols, which tells whose attempt put a successor key on
/// the roster. `parents` holds every read entry's parents, counted or not,
/// for that causal question.
#[derive(Default)]
struct HoldRows {
    holds: Vec<(AuthorityEntryHash, RecoveryHold, AuthorityKey)>,
    answers: BTreeMap<AuthorityEntryHash, Vec<HoldAnswerRow>>,
    root_keys: BTreeSet<AuthorityKey>,
    key_owners: BTreeMap<AuthorityKey, EntityId>,
    enrolments: BTreeMap<AuthorityKey, Vec<AuthorityEntryHash>>,
    parents: BTreeMap<AuthorityEntryHash, Vec<AuthorityEntryHash>>,
}

impl HoldRows {
    fn read(&mut self, hash: AuthorityEntryHash, entry: &AuthorityLogEntry) {
        match &entry.op {
            AuthorityOp::RecoveryHold(hold) => {
                self.holds
                    .push((hash, hold.clone(), entry.signer_key().clone()));
            }
            AuthorityOp::RecoveryHoldAnswer(answer) => {
                self.answers.entry(answer.hold).or_default().push((
                    answer.answer,
                    entry.signer_key().clone(),
                    hash,
                ));
            }
            AuthorityOp::OwnerKeyEnroll(enroll) => {
                if enroll.is_recovery_authority() {
                    self.root_keys.insert(enroll.device.key.clone());
                }
                self.key_owners
                    .entry(enroll.device.key.clone())
                    .or_insert(enroll.act.owner);
                self.enrolments
                    .entry(enroll.device.key.clone())
                    .or_default()
                    .push(hash);
            }
            _ => {}
        }
    }

    /// Whether `ancestor` is in the causal past of `entry`, by the read
    /// entries' parents. An entry this reader holds no copy of ends that
    /// line of the walk.
    fn descends_from(
        &self,
        entry: AuthorityEntryHash,
        ancestor: &BTreeSet<AuthorityEntryHash>,
    ) -> bool {
        let mut seen = BTreeSet::new();
        let mut next = vec![entry];
        while let Some(at) = next.pop() {
            for parent in self.parents.get(&at).into_iter().flatten() {
                if ancestor.contains(parent) {
                    return true;
                }
                if seen.insert(*parent) {
                    next.push(*parent);
                }
            }
        }
        false
    }

    /// Whether the successor key `successor` on the roster is this hold's
    /// landing: the key is on the roster, and some enrolment of it does
    /// not follow any of `cancels`, this hold's counted Cancels. A landing
    /// writes only for a hold its fold reads as not cancelled, so an
    /// enrolment whose causal past holds this hold's Cancel is another
    /// attempt's: a retry with the same successor, or the kit's vouch that
    /// cancelled this hold first. A key on the roster through no owner-key
    /// enrolment the reader holds counts as landed.
    fn landed(
        &self,
        fold: &AuthorityFold,
        successor: &AuthorityKey,
        cancels: &BTreeSet<AuthorityEntryHash>,
    ) -> bool {
        if !fold.roster.contains_key(successor) {
            return false;
        }
        if cancels.is_empty() {
            return true;
        }
        self.enrolments.get(successor).is_none_or(|enrolments| {
            enrolments
                .iter()
                .any(|enrolment| !self.descends_from(*enrolment, cancels))
        })
    }
}

/// One recovery hold as this install reads it: the attempt, its successor
/// and lost keys, its landing second, its state on the reader's clock, and
/// who answered it. Every owner device folds the same rows; only the
/// Due/Waiting line moves with the reader's clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryHoldView {
    /// The hold's entry hash: the attempt id.
    pub hold: AuthorityEntryHash,
    /// The owner whose recovery this is: only their own keys say `ItIsMe`.
    pub owner: EntityId,
    /// The hold's signer R: the recovery root's authority key whose released
    /// seed the landing signs with. An R-signed Cancel (the kit's) counts for
    /// this hold only when this R signed it; another root's R is inert here.
    pub root_key: AuthorityKey,
    /// The successor key the landing enrols.
    pub successor_key: AuthorityKey,
    /// The machine that holds the successor key.
    pub successor_machine: EntityId,
    /// The lost keys the landing revokes.
    pub lost: Vec<AuthorityKey>,
    /// Unix seconds the wait ends at, on the door install's clock.
    pub lands_at: u64,
    /// What the attempt is now.
    pub state: RecoveryHoldState,
    /// The signers of the hold's valid answers that count for it,
    /// ascending, each once: an owner device key's Cancel (any owner's of
    /// this vault) and the hold's owner's own key's `ItIsMe`, and this
    /// hold's signer R for the kit's Cancel (another root's R is inert, and
    /// a co-owner's `ItIsMe` counts for nothing; neither leaves a name here).
    pub answered_by: Vec<AuthorityKey>,
    /// Who stopped the attempt, ascending, each once: the person each
    /// counted Cancel's key belongs to (its enrolment's owner, or the person
    /// a live `human` binding names). A co-owner's Cancel names the co-owner
    /// (WAYBACK-COOWNER-CANCEL-OTHER-OWNERS-RECOVERY = B); the kit's names
    /// the owner its R was enrolled for. Empty unless the hold is
    /// cancelled.
    pub cancelled_by: Vec<EntityId>,
}

/// What a recovery hold is now, judged from the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryHoldState {
    /// Live and not due: lands at `lands_at` unless answered first.
    Waiting,
    /// Live and due: the hold's owner's ItIsMe answered it, or the reader's
    /// clock reached `lands_at`. Lands at the seed holder's next call.
    Due,
    /// The successor key is on the roster, through an enrolment that
    /// follows none of the hold's Cancels: the attempt completed.
    Landed,
    /// A Cancel answered it: it never lands, and no later answer revives it.
    Cancelled,
    /// The hold's signer R is no longer a live roster key: it never lands.
    Void,
}

/// The view order: Landed, then Cancelled, then Void, then Due/Waiting.
fn state_rank(state: RecoveryHoldState) -> u8 {
    match state {
        RecoveryHoldState::Landed => 0,
        RecoveryHoldState::Cancelled => 1,
        RecoveryHoldState::Void => 2,
        RecoveryHoldState::Due | RecoveryHoldState::Waiting => 3,
    }
}

impl Vault {
    /// Every recovery hold this install's log holds, with its state: Landed
    /// once the successor key is on the roster (live or since revoked: the
    /// attempt completed) through an enrolment that follows none of the
    /// hold's counted Cancels (`HoldRows::landed`: a retry's or the kit's
    /// enrolment of the same key after a Cancel leaves a cancelled hold
    /// Cancelled), else Cancelled on any valid Cancel that counts
    /// for the hold (any owner device key's of this vault, a co-owner's
    /// included, or the kit's, which this hold's signer R signs; another
    /// root's R is inert, and an ItIsMe never revives one), else Void when
    /// the hold's signer R is no longer live, else Due on a valid ItIsMe
    /// from a key of the hold's owner ([`key_is_the_owners`]; a co-owner's
    /// counts for nothing) or when this reader's `instant_in_txn` reached
    /// `lands_at`, else Waiting. Only rows this
    /// install's fold counts are read: a refused hold or answer is as if
    /// unwritten, and an answer to an unknown hold is inert. On a vault
    /// that adopted a checkpoint image, a hold or an answer the image
    /// carries and the vault does not store counts as a stored one does.
    /// Ordered Landed, Cancelled, Void, then Due/Waiting; within a rank by
    /// `lands_at`, then the attempt id.
    ///
    /// # Errors
    /// The log's and the clock's.
    pub fn recovery_holds_in_txn(&self, txn: &heed::RoTxn<'_>) -> Result<Vec<RecoveryHoldView>> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let now = self.instant_in_txn(txn)?.secs();
        let history = crate::authority::history_transfer::history_in_txn(self, txn)?;
        let mut rows = HoldRows::default();
        let mut stored = BTreeSet::new();
        for (hash, (_, entry)) in &history {
            stored.insert(*hash);
            rows.parents.insert(*hash, entry.parent_hashes.clone());
            if !fold.valid_entries.contains(hash) {
                continue;
            }
            rows.read(*hash, entry);
        }
        if let Some(evidence) =
            crate::authority::adopted_evidence::adopted_evidence_in_txn(&self.store, txn)?
        {
            for (hash, entry) in evidence.carried_past(&stored) {
                rows.parents.insert(*hash, entry.parent_hashes.clone());
                if !fold.valid_entries.contains(hash) {
                    continue;
                }
                rows.read(*hash, entry);
            }
        }
        let mut views: Vec<RecoveryHoldView> = rows
            .holds
            .iter()
            .map(|(hash, hold, signer)| {
                let (hash, signer) = (*hash, signer.clone());
                let HoldRows {
                    answers,
                    root_keys,
                    key_owners,
                    ..
                } = &rows;
                let successor_key = hold.successor_key();
                let named = answers.get(&hash);
                // A Cancel counts for this hold when an owner device key of
                // any owner of this vault signed it (it only denies), or
                // when this hold's signer R did (the kit's Cancel). Another
                // root's R is inert for this hold. An ItIsMe counts only
                // from a key of the hold's owner: a co-owner's never ends
                // another owner's wait. The fold refused an ItIsMe that any
                // R signs.
                let counts = |kind: RecoveryHoldAnswerKind, answerer: &AuthorityKey| match kind {
                    RecoveryHoldAnswerKind::ItIsMe => key_is_the_owners(
                        &fold,
                        key_owners.get(answerer).copied(),
                        answerer,
                        hold.owner,
                    ),
                    RecoveryHoldAnswerKind::Cancel => {
                        !root_keys.contains(answerer) || *answerer == signer
                    }
                };
                let cancels: Vec<&HoldAnswerRow> = named.map_or(Vec::new(), |list| {
                    list.iter()
                        .filter(|(kind, answerer, _)| {
                            *kind == RecoveryHoldAnswerKind::Cancel && counts(*kind, answerer)
                        })
                        .collect()
                });
                let cancelled = !cancels.is_empty();
                let cancel_rows: BTreeSet<AuthorityEntryHash> =
                    cancels.iter().map(|(_, _, row)| *row).collect();
                let affirmed = named.is_some_and(|list| {
                    list.iter().any(|(kind, answerer, _)| {
                        *kind == RecoveryHoldAnswerKind::ItIsMe && counts(*kind, answerer)
                    })
                });
                let state = if rows.landed(&fold, &successor_key, &cancel_rows) {
                    RecoveryHoldState::Landed
                } else if cancelled {
                    RecoveryHoldState::Cancelled
                } else if !fold
                    .roster
                    .get(&signer)
                    .is_some_and(|device| !device.revoked)
                {
                    RecoveryHoldState::Void
                } else if affirmed || now >= hold.lands_at {
                    RecoveryHoldState::Due
                } else {
                    RecoveryHoldState::Waiting
                };
                let mut answered_by: Vec<AuthorityKey> = named.map_or(Vec::new(), |list| {
                    list.iter()
                        .filter(|(kind, answerer, _)| counts(*kind, answerer))
                        .map(|(_, answerer, _)| answerer.clone())
                        .collect()
                });
                answered_by.sort();
                answered_by.dedup();
                let mut cancelled_by: Vec<EntityId> = if state == RecoveryHoldState::Cancelled {
                    cancels
                        .into_iter()
                        .filter_map(|(_, answerer, _)| {
                            key_person(&fold, key_owners.get(answerer).copied(), answerer)
                        })
                        .collect()
                } else {
                    Vec::new()
                };
                cancelled_by.sort();
                cancelled_by.dedup();
                RecoveryHoldView {
                    hold: hash,
                    owner: hold.owner,
                    root_key: signer,
                    successor_key,
                    successor_machine: hold.enrolment.machine,
                    lost: hold.lost.clone(),
                    lands_at: hold.lands_at,
                    state,
                    answered_by,
                    cancelled_by,
                }
            })
            .collect();
        views.sort_by_key(|view| (state_rank(view.state), view.lands_at, view.hold));
        Ok(views)
    }

    /// [`Self::recovery_holds_in_txn`] in its own read transaction: the
    /// owner-visible "recovery started, lands at <time>, cancel?" event
    /// list, and what the recovering device's poll reads.
    ///
    /// # Errors
    /// The log's and the clock's.
    pub fn recovery_holds(&self) -> Result<Vec<RecoveryHoldView>> {
        let txn = self.store.env.read_txn()?;
        self.recovery_holds_in_txn(&txn)
    }
}
