//! An ending writer's half of the general grant act (Fable pass 28 R2c): every taking back of a
//! Grant row is a counted end, and an end never refuses.
//!
//! A writer that takes a Grant back with no act of its own (a house unlink, a lapse, a direct
//! delete or erase of the row; Engine RULING GRANT-ROW-DELETE-NO-END = A, 16 Nov 05:49) ends its
//! line here, in its own transaction. The end is signed there when this install can carry it;
//! otherwise it stays owed, value-free, under the Grant's id, and is carried by the next pass that
//! can: the moment the install key loads, and the owner work pickup (Engine RULING
//! GRANT-ACT-FAILURE-POLICY = A, 16 Nov 03:42). A batch delete, which runs below any vault door,
//! owes the end of every Grant row it tears; the pass then ends the line by the line's own family,
//! or drops the debt when a counted act already ended it (the writer's own end: a membership
//! record, an owner's revoke, a slip revoke) or when no counted act names the Grant at all.
//!
//! An owed end keeps the deciding person only until their erase: the erase rewrites it, and each
//! owed membership record naming them, into a person-free end by rule.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::authority::{ActSurface, GrantActBy, GrantActChange, GrantFamily};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, HexId, Named, SideTable};
use crate::store::Store;

/// Each Grant whose counted end this install still owes, by the Grant's id.
const OWED_GRANT_END: SideTable<HexId, OwedGrantEnd, Named> =
    SideTable::new(&side_table::FEDERATION_OWED_GRANT_END);

/// One Grant end not signed yet. It holds no term, value, credential or proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct OwedGrantEnd {
    /// The authenticated PERSON who took the Grant back; `None` for a rule's end.
    decider: Option<EntityId>,
    /// The Grant's family as its writer knew it; `None` for a batch delete, which knows only
    /// the row, so the pass ends the line by its own family.
    family: Option<GrantFamily>,
}

/// How a Grant end stands once its writer filed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GrantEndRecord {
    /// The fold counted the end in the writer's transaction.
    Signed,
    /// This install cannot carry it now; it stays owed.
    Owed,
    /// Nothing is left to end: a counted act already ended the line, or none names it.
    Settled,
}

/// A batch delete's debt, below any vault door: the FEDERATION_GRANT row `grant`, about to be
/// torn in `wtxn`, is owed a counted end unless a writer already owes it a fuller one. Any other
/// kind, or no row, owes nothing.
///
/// # Errors
/// The row read, or the debt's write.
pub(crate) fn owe_torn_grant_end_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    grant: EntityId,
) -> Result<()> {
    let is_grant = crate::ports::EntityStoreRead::port_entity_record(store, &*wtxn, &grant)?
        .is_some_and(|row| row.entity_type == crate::registry::ENTITY_TYPE_FEDERATION_GRANT);
    if !is_grant || OWED_GRANT_END.get(store, wtxn, &HexId(grant))?.is_some() {
        return Ok(());
    }
    OWED_GRANT_END.put(
        store,
        wtxn,
        &HexId(grant),
        &OwedGrantEnd {
            decider: None,
            family: None,
        },
    )
}

impl Vault {
    /// `by`'s end of the Grant `grant` of `family`, in the writer's transaction `txn`, after the
    /// writer deleted its row: owed first, then signed in a savepoint of `txn` when this install
    /// can carry it now. Never refuses for want of a carrier: a failure past the debt's write is
    /// logged by kind and leaves it owed.
    ///
    /// # Errors
    /// The debt's own write.
    pub(crate) fn end_grant_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        by: GrantActBy,
        grant: EntityId,
        family: GrantFamily,
    ) -> Result<GrantEndRecord> {
        let decider = match by {
            GrantActBy::Person { person, .. } => Some(person),
            GrantActBy::Rule => None,
        };
        OWED_GRANT_END.put(
            &self.store,
            txn,
            &HexId(grant),
            &OwedGrantEnd {
                decider,
                family: Some(family),
            },
        )?;
        Ok(self.carry_owed_grant_end_in_savepoint(txn, grant))
    }

    /// A direct erase's end of the row `grant` (a hard delete door), in its transaction `txn`:
    /// owed as a batch delete owes it, then carried at once when this install can.
    ///
    /// # Errors
    /// The debt's own write.
    pub(crate) fn end_erased_grant_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        grant: EntityId,
    ) -> Result<GrantEndRecord> {
        owe_torn_grant_end_in_txn(&self.store, txn, grant)?;
        Ok(self.carry_owed_grant_end_in_savepoint(txn, grant))
    }

    fn carry_owed_grant_end_in_savepoint(
        &self,
        txn: &mut heed::RwTxn<'_>,
        grant: EntityId,
    ) -> GrantEndRecord {
        match self.carry_owed_grant_end_in_nested_txn(txn, grant) {
            Ok(Some(carried)) => carried,
            Ok(None) => GrantEndRecord::Owed,
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "a Grant's end was not signed in its writer; it stays owed"
                );
                GrantEndRecord::Owed
            }
        }
    }

    fn carry_owed_grant_end_in_nested_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        grant: EntityId,
    ) -> Result<Option<GrantEndRecord>> {
        let mut savepoint = self.store.env.nested_write_txn(txn)?;
        let carried = self.carry_owed_grant_end_in_txn(&mut savepoint, grant)?;
        if carried.is_some() {
            savepoint.commit()?;
        }
        Ok(carried)
    }

    /// Signs the end owed for `grant` in `txn` and clears the debt there once the fold counted
    /// it, by the line's own family (a writer's family when no counted act names the Grant). A
    /// debt with nothing left to end clears with no act. `None`, with nothing written, for no
    /// debt or an install that cannot carry now.
    fn carry_owed_grant_end_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        grant: EntityId,
    ) -> Result<Option<GrantEndRecord>> {
        let Some(owed) = OWED_GRANT_END.get(&self.store, txn, &HexId(grant))? else {
            return Ok(None);
        };
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let family = match fold.grant_line(grant) {
            Some(line) if line.ended => None,
            // A line in no one family (two branches named it in two) stands on neither.
            Some(line) => line.family,
            None => owed.family,
        };
        let Some(family) = family else {
            OWED_GRANT_END.delete(&self.store, txn, &HexId(grant))?;
            return Ok(Some(GrantEndRecord::Settled));
        };
        if crate::identity::read_machine_id_in_txn(self, txn)?.is_none()
            || crate::identity::read_machine_signing_key_in_txn(self, txn)?.is_none()
        {
            return Ok(None);
        }
        // A person never ends the owner's agent Grant by this act: its end by anyone but him
        // is a rule's.
        let by = match owed.decider {
            Some(person) if family != GrantFamily::OwnerAgent => GrantActBy::Person {
                person,
                surface: ActSurface::ThisInstall,
            },
            _ => GrantActBy::Rule,
        };
        self.append_grant_act_in_txn(txn, by, grant, family, GrantActChange::End)?;
        OWED_GRANT_END.delete(&self.store, txn, &HexId(grant))?;
        Ok(Some(GrantEndRecord::Signed))
    }

    /// Carries every Grant end this install still owes, each in a writer of its own. The caller
    /// loads the install key first. Returns how many it settled.
    ///
    /// # Errors
    /// The first carry that failed; the others are still tried, and each that failed stays owed.
    fn carry_owed_grant_ends(&self) -> Result<usize> {
        let owed = self.owed_grant_ends()?;
        let mut settled = 0;
        let mut failed = None;
        for grant in owed {
            match self.with_write_txn(|txn| self.carry_owed_grant_end_in_txn(txn, grant)) {
                Ok(Some(_)) => settled += 1,
                Ok(None) => {}
                Err(error) => {
                    failed.get_or_insert(error);
                }
            }
        }
        failed.map_or(Ok(settled), Err)
    }

    /// [`Self::carry_owed_grant_ends`] for a pass that goes on without it, such as the install
    /// key's load: a failure is logged by kind, never with a value.
    pub(crate) fn carry_owed_grant_ends_logged(&self) {
        match self.carry_owed_grant_ends() {
            Ok(settled) if settled > 0 => {
                tracing::debug!(settled, "owed Grant ends carried");
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "owed Grant ends were not carried on this install"
                );
            }
        }
    }

    /// The owner work pickup's arm: with a Grant end owed, loads this install's key and carries
    /// what it can. Nothing is read from the keystore while none is owed.
    pub(crate) fn carry_owed_grant_ends_at_pickup(&self) {
        match self.owed_grant_ends() {
            Ok(owed) if owed.is_empty() => return,
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "owed Grant ends were not read on this install"
                );
                return;
            }
        }
        // A key that loads now carries them as it loads; this pass carries them with a key
        // loaded before.
        self.load_membership_carrier();
        self.carry_owed_grant_ends_logged();
    }

    /// The Grant ids whose end this install still owes.
    fn owed_grant_ends(&self) -> Result<Vec<EntityId>> {
        let txn = self.store.env.read_txn()?;
        Ok(OWED_GRANT_END
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(HexId(grant), _)| grant)
            .collect())
    }

    /// The Grants `grants`, ended by a membership record that a person's erase drops unsigned:
    /// each is owed a person-free end by rule instead, by its line's own family, so the erase
    /// never leaves a taking back uncounted. A Grant already owed keeps its debt.
    ///
    /// # Errors
    /// A debt's write.
    pub(crate) fn owe_rule_grant_ends_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        grants: &[EntityId],
    ) -> Result<()> {
        for grant in grants {
            if OWED_GRANT_END
                .get(&self.store, wtxn, &HexId(*grant))?
                .is_none()
            {
                OWED_GRANT_END.put(
                    &self.store,
                    wtxn,
                    &HexId(*grant),
                    &OwedGrantEnd {
                        decider: None,
                        family: None,
                    },
                )?;
            }
        }
        Ok(())
    }

    /// A person's erase, in its own writer (FIX 3520): every owed Grant end that names them as
    /// its decider becomes a rule's, so no act is signed in their name and the end still counts.
    /// It is the declared actor scrub of the debt table.
    pub(crate) fn erase_owed_grant_end_actor_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()> {
        if crate::deletion::names_no_actor(self, wtxn, actor)? {
            return Ok(());
        }
        let mut rewritten = 0_usize;
        for (grant, owed) in OWED_GRANT_END.scan(&self.store, wtxn)? {
            if owed.decider == Some(*actor) {
                OWED_GRANT_END.put(
                    &self.store,
                    wtxn,
                    &grant,
                    &OwedGrantEnd {
                        decider: None,
                        ..owed
                    },
                )?;
                rewritten += 1;
            }
        }
        if rewritten > 0 {
            tracing::info!(
                rewritten,
                "a person's erase turned the Grant ends owed in their name into ends by rule"
            );
        }
        Ok(())
    }
}
