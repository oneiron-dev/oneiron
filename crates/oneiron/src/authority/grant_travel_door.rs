//! The signed half of the owner's grant travel door (FIX 2998).
//!
//! The owner's door (`federation::grant_travel`) revalidates the owner in its
//! transaction, checks the grant and writes the Gate receipt; that say-so is
//! the gate, from whichever of the owner's surfaces it came (OWNER RULING
//! 10-19 00:5x). This half signs the choice with this install's machine key,
//! whatever the install's role in the roster, a hosted node included, as
//! long as the one signer rule admits it
//! ([`super::grant_travel::grant_travel_signer_admits`]). The fold is the
//! judge: a choice it does not count here never reports success.

use crate::error::{Error, Result};
use crate::share_travel::TravelChoice;
use crate::{EntityId, TimeRange, Vault};

use super::*;

impl AuthorityFold {
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
}

impl Vault {
    /// Signs and lands one choice in the caller's transaction. The caller
    /// has revalidated `owner` and checked that `grant` is a live federation
    /// grant. `choice` is `None` for a clear, never a choice of no field.
    ///
    /// The choice names the main-log heads, this machine's standing rows
    /// and the grant's live choices, so it supersedes every choice this
    /// install folds. More than one entry may name refuses, atomically: a
    /// choice is never split, and no restrictive head is dropped to make
    /// room (FIX 2998).
    pub(crate) fn append_grant_travel_set_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: EntityId,
        grant: EntityId,
        choice: Option<TravelChoice>,
        now: u64,
    ) -> Result<GrantTravelSigned> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let machine = crate::identity::read_machine_id_in_txn(self, txn)?.ok_or_else(no_signer)?;
        let key =
            crate::identity::read_machine_signing_key_in_txn(self, txn)?.ok_or_else(no_signer)?;
        let public_key = key.verifying_key().to_bytes();
        if !super::grant_travel::grant_travel_signer_admits(
            fold.machine(machine),
            &fold.roster,
            &public_key,
        ) {
            return Err(no_signer());
        }
        let signer = AuthorityKey::Ed25519(public_key);
        let seq = next_sequence(&fold, &signer)?;
        let mut parents = fold.append_heads.clone();
        parents.extend(standing_rows(&fold, machine));
        parents.extend(
            fold.signed_grant_travel(grant)
                .into_iter()
                .flat_map(|folded| folded.live.keys().copied()),
        );
        if parents.len() > MAX_PARENTS {
            return Err(Error::InvalidConfig(
                "this grant has more concurrent travel choices than one choice may name; \
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
                owner,
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
        })
    }
}
