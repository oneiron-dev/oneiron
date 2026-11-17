//! A giving writer's half of the general grant act (Fable pass 28 R2): the row a Grant writer
//! puts is the one its giving act commits to, under a terms key fresh for that row.
//!
//! A giving refuses when this install cannot carry its act (Engine RULING
//! GRANT-ACT-FAILURE-POLICY = A, 16 Nov 03:42): the writer's door loads the install key before
//! its writer opens, so a refusal means this install has no live install key. An end never
//! refuses; it rides the change's own record (a membership change's carrier-signed
//! `MembershipExecution`, kept pending when no key is loaded).

use rand_core::{OsRng, RngCore};

use crate::Vault;
use crate::authority::{ActSurface, GrantActBy, GrantActChange, GrantFamily};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::{
    FederationGrant, GrantTermsKey, encode_federation_grant_body_keyed, federation_grant_terms,
};

/// A terms key fresh from the system's random source, so no two rows share one and the
/// public act's commitment cannot be tested against a guess of the row's terms. Never all
/// zero, which the codec refuses.
fn fresh_grant_terms_key() -> GrantTermsKey {
    loop {
        let mut key = [0_u8; 32];
        OsRng.fill_bytes(&mut key);
        if key.iter().any(|byte| *byte != 0) {
            return key;
        }
    }
}

const GRANT_ID_ENDED: &str = "a counted act already ended the Grant at this id; an ended Grant \
     is never given again, so a giving takes a fresh id";

impl Vault {
    /// `giver`'s giving of `grant` as row `id` of `family`, in the writer's transaction `txn`:
    /// signs, appends and folds the act that commits to `grant`'s terms under a fresh terms
    /// key, and returns the body the caller puts at `id` in `txn`: `grant` keyed by that key.
    /// One call per row id: each row gets its own act and its own key.
    ///
    /// The caller judged in `txn` that `giver` may give these terms by `family`'s own rule
    /// (the act's decider is audit; the reader judges the giver again in pass 28 R3). The act
    /// names the in-process surface: no membership door takes another.
    ///
    /// # Errors
    /// An id whose Grant a counted act already ended: an end is forever (pass 28 R1), so the
    /// row would stand for nothing although its giving counted. The act's refusal
    /// ([`Vault::append_grant_act_in_txn`]): an install that cannot carry it, more heads than
    /// one entry may name, or an act the fold did not count (an act of another family than
    /// the row's line holds). Nothing is written then, and the caller's writer must not
    /// commit the row.
    pub(crate) fn give_grant_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        giver: EntityId,
        id: EntityId,
        family: GrantFamily,
        grant: &FederationGrant,
    ) -> Result<Vec<u8>> {
        if self
            .authority_view_readonly_in_txn(txn)?
            .grant_line(id)
            .is_some_and(|line| line.ended)
        {
            return Err(crate::authority::authority_refused(GRANT_ID_ENDED));
        }
        let key = fresh_grant_terms_key();
        let terms = federation_grant_terms(id, grant, &key)?;
        self.append_grant_act_in_txn(
            txn,
            GrantActBy::Person {
                person: giver,
                surface: ActSurface::ThisInstall,
            },
            id,
            family,
            GrantActChange::Give { terms },
        )?;
        encode_federation_grant_body_keyed(grant, &key)
    }
}
