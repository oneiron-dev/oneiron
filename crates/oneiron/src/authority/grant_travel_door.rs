//! The signed half of the owner's grant travel door (FIX 2998).
//!
//! The owner's door (`federation::grant_travel`) revalidates the owner in its
//! transaction, checks the grant and writes the Gate receipt; that say-so is
//! the gate, from whichever of the owner's surfaces it came (OWNER RULING
//! 10-19 00:5x). This half signs the choice with this install's machine key,
//! whatever the install's role in the roster, a hosted node included, as
//! long as the one carrier rule admits it ([`super::owner_act_signer_admits`]).
//! The choice carries his act ([`OwnerAct`], kind `grant_travel`, mesh
//! PR1b), whose `seen` is the grant's revision the deciding surface showed
//! him. The fold is the judge: a choice it does not count here never reports
//! success.

use crate::error::{Error, Result};
use crate::share_travel::TravelChoice;
use crate::{EntityId, TimeRange, Vault};

use super::*;

impl AuthorityFold {
    /// A grant's travel revision in this fold, as a deciding surface shows
    /// it to the owner: the digest of its live choices, zero for a grant no
    /// choice names ([`grant_travel_revision`]).
    pub(crate) fn grant_travel_revision_of(&self, grant: EntityId) -> [u8; 32] {
        grant_travel_revision(
            self.signed_grant_travel(grant)
                .into_iter()
                .flat_map(|folded| folded.live.keys().copied()),
        )
    }

    /// A digest of the main-log heads this fold names: the authority
    /// frontier a door observed.
    pub(crate) fn append_heads_digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key("oneiron/authority/append-heads/v1");
        for head in &self.append_heads {
            hasher.update(head);
        }
        *hasher.finalize().as_bytes()
    }
}

/// This install cannot sign: it has no machine identity, or the roster
/// holds no live profile of it under its key. Nothing was written.
fn no_signer() -> Error {
    Error::InvalidConfig(
        "this install has no live machine profile in the vault's roster to sign the grant's \
         travel choice"
            .to_owned(),
    )
}

/// One signed and folded grant travel choice.
pub(crate) struct GrantTravelSigned {
    pub(crate) machine: EntityId,
    pub(crate) entry_hash: AuthorityEntryHash,
    /// The grant's revision the act names as seen.
    pub(crate) seen: [u8; 32],
}

impl Vault {
    /// A grant's travel revision in this vault's fold: what a surface shows
    /// the owner, and passes back as the choice's `seen`.
    pub fn grant_travel_revision(&self, grant: &EntityId) -> Result<[u8; 32]> {
        let txn = self.store.env.read_txn()?;
        Ok(self
            .authority_view_readonly_in_txn(&txn)?
            .grant_travel_revision_of(*grant))
    }

    /// Signs and lands one choice in the caller's transaction. The caller
    /// has revalidated `owner` and checked that `grant` is a live federation
    /// grant. `choice` is `None` for a clear, never a choice of no field.
    /// `surface` is where the owner said so, for audit only; `seen` is the
    /// grant's revision the deciding surface showed him: it must be the
    /// current one, else the choice is a conflict, never a silent overwrite.
    /// `None` takes the current revision (a caller that showed none).
    ///
    /// The choice names the main-log heads alone. A choice is a main-log
    /// entry, so the grant's live choices and this machine's standing rows
    /// are among those heads or their ancestors: the fold at the heads
    /// carries them, and the choice supersedes every choice this install
    /// folds. Naming them again would put covered rows off a checkpoint
    /// image's frontier among its parents, which only the whole history
    /// folds (FIX 4455); the fold check below refuses a choice its parents
    /// do not carry. More heads than one entry may name refuses,
    /// atomically: a choice is never split, and no restrictive head is
    /// dropped to make room (FIX 2998).
    pub(crate) fn append_grant_travel_set_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: EntityId,
        surface: ActSurface,
        grant: EntityId,
        choice: Option<TravelChoice>,
        seen: Option<[u8; 32]>,
        now: u64,
    ) -> Result<GrantTravelSigned> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let machine = crate::identity::read_machine_id_in_txn(self, txn)?.ok_or_else(no_signer)?;
        let key =
            crate::identity::read_machine_signing_key_in_txn(self, txn)?.ok_or_else(no_signer)?;
        let public_key = key.verifying_key().to_bytes();
        if !super::owner_act_signer_admits(fold.machine(machine), &fold.roster, &public_key) {
            return Err(no_signer());
        }
        // Revision integrity (mesh contract §4): the owner chose on what the
        // surface showed him.
        let current = fold.grant_travel_revision_of(grant);
        if seen.is_some_and(|seen| seen != current) {
            return Err(Error::ConcurrentWrite(
                "the grant's travel choice changed since it was read",
            ));
        }
        let signer = AuthorityKey::Ed25519(public_key);
        let seq = next_sequence(&fold, &signer)?;
        let parents = fold.append_heads.clone();
        if parents.len() > MAX_PARENTS {
            return Err(Error::InvalidConfig(
                "the authority log has more concurrent heads than one travel choice may name; \
                 nothing was written"
                    .to_owned(),
            ));
        }
        let entry = sign_side_entry(
            &fold,
            &key,
            seq,
            parents,
            AuthorityOp::GrantTravelSet(GrantTravelSet {
                grant,
                act: OwnerAct::by_owner(owner, OwnerActKind::GrantTravel, grant, surface, current),
                machine,
                choice,
            }),
            now,
        )?;
        let entry_hash = authority_entry_hash(&entry)?;
        let at = TimeRange {
            start: now,
            end: now,
        };
        self.put_authority_log_entries_in_txn(txn, &[(entry, at, now)])?;
        let after = self.authority_view_readonly_in_txn(txn)?;
        let counted = after
            .signed_grant_travel(grant)
            .is_some_and(|folded| folded.live.contains_key(&entry_hash))
            && !after.install.held_back.contains(&entry_hash);
        if !counted {
            return Err(invalid_authority());
        }
        Ok(GrantTravelSigned {
            machine,
            entry_hash,
            seen: current,
        })
    }
}
