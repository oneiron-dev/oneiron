//! The person's own "Learn from my conversations" door (FIX 4489, OF-420):
//! they say yes for an explicit list of worlds, or turn it off, from any
//! surface where they are authenticated, on any host. Their say-so is the
//! gate, revalidated at the person tier in the writing transaction
//! (`AuthenticatedOwner::revalidate_person_in_txn`): a live person of this
//! vault, owner or not, acting for themselves. The act's person is the
//! proof's own, never a caller's id, and no Grant action names it, so an
//! agent never makes it. This install carries it under its own live machine
//! profile, in any role the one carrier rule admits
//! ([`super::super::owner_act_signer_admits`]).

use crate::TimeRange;
use crate::consent::AuthenticatedOwner;
use crate::error::Error;

use super::*;

/// This install cannot carry the person's choice: it has no machine
/// identity or install key, or no live profile of it stands under that key.
/// No roster key, the host root included, carries an act (FIX 2222).
const NO_CARRIER: &str = "this install has no live machine profile in the vault's roster to carry \
                          the conversation training choice";
/// The choice would name more rows than one authority entry may: the log's
/// encoding bound, never a possession test.
const TOO_MANY_HEADS: &str = "the conversation training choice has more concurrent choices than \
                              one choice may name; nothing was written";
/// The supplied `seen` is not the person's current choice revision.
const STALE: &str = "the conversation training choice changed since it was read";
/// A listed world may not be named; the whole choice is refused.
const NOT_ELIGIBLE: &str = "conversation training may name only a live world that reads \
                            everywhere; nothing was written";
/// The fold did not count the signed choice here: it never reports success.
const NOT_COUNTED: &str = "this install's fold does not count the conversation training choice";

/// A person's "Learn from my conversations" choice, as their own surface
/// shows it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConversationTrainingView {
    /// The PERSON whose choice this is: the proof's own.
    pub person: EntityId,
    /// The worlds the choice in force names, as signed; `None` when it is
    /// off, no choice counts, or the person's live choices conflict.
    pub chosen: Option<BTreeSet<EntityId>>,
    /// The worlds that count now: `chosen` less every world no longer
    /// eligible (deleted, archived, or no longer readable everywhere);
    /// `None` when none is left.
    pub worlds: Option<BTreeSet<EntityId>>,
    /// The revision to present back as `seen`: the digest of the person's
    /// live choices, zero when none.
    pub revision: PolicyRevision,
    /// Whether the person's live choices conflict. While they do, the choice
    /// reads as off until one that saw them all supersedes them.
    pub conflicted: bool,
    /// The authority entry of the choice in force (a yes or an off); `None`
    /// while no choice counts or the choices conflict.
    pub act: Option<AuthorityEntryHash>,
}

impl Vault {
    /// The authenticated person's own conversation training choice.
    ///
    /// # Errors
    /// A refusal when the proof is no longer a live person of this vault;
    /// storage faults, and history this vault lacks, as the fold reads them.
    pub fn conversation_training_view(
        &self,
        owner: &AuthenticatedOwner,
    ) -> Result<ConversationTrainingView> {
        let txn = self.store.env.read_txn()?;
        let person = owner.revalidate_person_in_txn(self, &txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        self.conversation_training_view_in_txn(&txn, &fold, person)
    }

    fn conversation_training_view_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        person: EntityId,
    ) -> Result<ConversationTrainingView> {
        let training = &fold.conversation_training;
        let folded = training.persons.get(&person);
        let conflicted = folded.is_some_and(|folded| !folded.conflict.is_empty());
        Ok(ConversationTrainingView {
            person,
            chosen: training.chosen(person).cloned(),
            worlds: self.conversation_training_effective_in_txn(txn, fold, person)?,
            revision: training.revision(person),
            conflicted,
            act: folded
                .filter(|_| !conflicted)
                .and_then(|folded| folded.in_force.as_ref())
                .map(|head| head.act),
        })
    }

    /// The authenticated person says yes to training on the conversations
    /// of `worlds`, or turns it off (`None`, or an empty set), from
    /// `surface` (audit only). `seen` is the revision their surface showed
    /// them ([`ConversationTrainingView::revision`]); `None` takes the
    /// current one.
    ///
    /// Every listed world must be eligible now (a live WORLD row, or base
    /// reality, that reads everywhere), or the whole choice is refused;
    /// turning it off never judges the worlds of an earlier yes. The choice
    /// names the main-log heads, this install's standing rows and every live
    /// choice of the person's, so it supersedes all of them, and lands
    /// atomically or not at all.
    ///
    /// # Errors
    /// A refusal when the proof is no longer a live person of this vault;
    /// [`Error::ConcurrentWrite`] when `seen` is not the current revision;
    /// [`Error::InvalidConfig`] naming the first world that may not be
    /// listed, or when the choice would name more parents than one entry
    /// may; [`crate::error::RecordError::AuthorityRefused`] when this install
    /// cannot carry the choice or its fold does not count it.
    pub fn set_conversation_training(
        &self,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        worlds: Option<BTreeSet<EntityId>>,
        seen: Option<PolicyRevision>,
    ) -> Result<ConversationTrainingView> {
        // An empty list is off: one off has one encoding.
        let worlds = worlds.filter(|worlds| !worlds.is_empty());
        let mut txn = self.store.env.write_txn()?;
        let person = owner.revalidate_person_in_txn(self, &txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        // Revision integrity (mesh contract §4): the person chose on what
        // the surface showed them.
        let current = fold.conversation_training.revision(person);
        if seen.is_some_and(|seen| seen != current) {
            return Err(Error::ConcurrentWrite(STALE));
        }
        for world in worlds.iter().flatten() {
            if !self.conversation_training_world_admits(&txn, &fold, *world)? {
                return Err(Error::InvalidConfig(format!(
                    "{NOT_ELIGIBLE} (world {})",
                    world.to_hex()
                )));
            }
        }
        let machine = crate::identity::read_machine_id_in_txn(self, &txn)?
            .ok_or_else(|| authority_refused(NO_CARRIER))?;
        let key = crate::identity::read_machine_signing_key_in_txn(self, &txn)?
            .ok_or_else(|| authority_refused(NO_CARRIER))?;
        let public_key = key.verifying_key().to_bytes();
        if !owner_act_signer_admits(fold.machine(machine), &fold.roster, &public_key) {
            return Err(authority_refused(NO_CARRIER));
        }
        let signer = AuthorityKey::Ed25519(public_key);
        let seq = next_sequence(&fold, &signer)?;
        let mut parents = fold.append_heads.clone();
        parents.extend(standing_rows(&fold, machine));
        parents.extend(
            fold.conversation_training
                .persons
                .get(&person)
                .into_iter()
                .flat_map(|folded| folded.live.keys().copied()),
        );
        if parents.len() > MAX_PARENTS {
            return Err(Error::InvalidConfig(TOO_MANY_HEADS.to_owned()));
        }
        // The person's own act: owner and target are both the proof's
        // person (the holder meaning of `by: Owner`).
        let act = OwnerAct::by_owner(
            person,
            OwnerActKind::ConversationTraining,
            person,
            surface,
            current.0,
        );
        let now = self.instant_in_txn(&txn)?.secs();
        let entry = sign_side_entry(
            &fold,
            &key,
            seq,
            parents,
            AuthorityOp::ConversationTrainingSet(ConversationTrainingSet {
                act,
                machine,
                worlds,
            }),
            now,
        )?;
        let entry_hash = authority_entry_hash(&entry)?;
        let at = TimeRange {
            start: now,
            end: now,
        };
        self.put_authority_log_entries_in_txn(&mut txn, &[(entry, at, now)])?;
        let after = self.authority_view_readonly_in_txn(&txn)?;
        let landed = after
            .conversation_training
            .persons
            .get(&person)
            .is_some_and(|folded| folded.live.contains_key(&entry_hash));
        if !landed || after.install.held_back.contains(&entry_hash) {
            return Err(authority_refused(NOT_COUNTED));
        }
        let view = self.conversation_training_view_in_txn(&txn, &after, person)?;
        txn.commit()?;
        Ok(view)
    }
}
