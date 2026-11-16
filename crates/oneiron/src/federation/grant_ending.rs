//! An ending writer's half of the general grant act (Fable pass 28 R2c): every taking back of a
//! Grant row is a counted end, and an end never refuses.
//!
//! A writer that takes a Grant back with no act of its own (a house unlink, a lapse, a direct
//! delete or erase of the row; Engine RULING GRANT-ROW-DELETE-NO-END = A, 16 Nov 05:49) ends its
//! line here, in its own transaction. The end is signed there when this install can carry it;
//! otherwise it stays owed, value-free, under the Grant's id, and is carried by the next pass that
//! can: the moment the install key loads, and the owner work pickup (Engine RULING
//! GRANT-ACT-FAILURE-POLICY = A, 16 Nov 03:42). A batch delete, which runs below any vault door,
//! owes the end of every Grant row it tears, whatever its body; the pass then ends the line by
//! the line's own family, or drops the debt when a counted act already ended it (the writer's own
//! end: a membership record, an owner's revoke, a slip revoke). A torn row whose giving has not
//! reached this install yet stays owed until it does (Astra r1-r2d F3): no act naming the Grant
//! here is no proof that none exists. So does a line two branches named in two families: no act
//! of one family ends it, and the debt keeps the taking back on record.
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
    /// Nothing is left to end: a counted act already ended the line.
    Settled,
}

/// A batch delete's debt, below any vault door: the FEDERATION_GRANT row `grant`, about to be
/// torn in `wtxn`, is owed a counted end unless a writer already owes it a fuller one. Any other
/// kind, or no row, owes nothing.
///
/// The row's body decides nothing. A body that took another shape at the Grant's id (an
/// own-device or engine-default Steward shape, or one that no longer decodes) is no proof that
/// no counted act gives the Grant here or will: a newer replicated overwrite can land over a
/// minted row before its tear (review #8982 P1-1). A debt no act can pay waits and holds the
/// Grant back, as the withdrawal marker it replaces held it for any torn row (pass 28 R3e).
///
/// # Errors
/// The row read, or the debt's write.
pub(crate) fn owe_torn_grant_end_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    grant: EntityId,
) -> Result<()> {
    let grant_row = crate::ports::EntityStoreRead::port_entity_record(store, &*wtxn, &grant)?
        .is_some_and(|row| row.entity_type == crate::registry::ENTITY_TYPE_FEDERATION_GRANT);
    if !grant_row || OWED_GRANT_END.get(store, wtxn, &HexId(grant))?.is_some() {
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

/// Whether this install still owes the counted end of the Grant `grant`: an end its writer
/// filed and could not sign yet ([`OWED_GRANT_END`]), or the unsigned record of a membership
/// change that withdrew it. Until that end counts here the Grant's line still reads as given,
/// so a reader of a withdrawal asks this first: a row put back at its id in the meantime (a
/// restore, or a peer the tombstone never reached) confers nothing. Once the end counts, the
/// line's end answers and the debt is gone (pass 28 R3e: it replaces the permanent withdrawal
/// marker, FIX-LIST 5107). A debt that cannot be read answers by
/// [`crate::authority::ISOLATION_NEW_CHECK_ERROR_MODE`]: not known, as the marker's read did.
pub(crate) fn grant_end_owed_in_txn(store: &Store, txn: &heed::RoTxn<'_>, grant: EntityId) -> bool {
    let owed = OWED_GRANT_END
        .contains(store, txn, &HexId(grant))
        .and_then(|owed| {
            Ok(owed || super::shared_act::membership_withdrawal_owed_in_txn(store, txn, grant)?)
        });
    match owed {
        Ok(owed) => owed,
        Err(_) => match crate::authority::ISOLATION_NEW_CHECK_ERROR_MODE {
            crate::authority::NewCheckErrorMode::KeepExistingPath => false,
        },
    }
}

/// What a carry pass can do with the end owed for one Grant, as the fold reads its line now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OwedEndCarry {
    /// Sign the end by this family: the line's one family, or its writer's family while no
    /// counted act names the Grant here.
    Sign(GrantFamily),
    /// A counted act already ended the line: the debt clears with no act.
    Settle,
    /// No act can end the line yet, so the debt stays and holds the Grant back: no counted act
    /// names the Grant here and its writer knew no family (a torn row whose giving has not
    /// arrived, or a kind with no act before R4), or two branches named it in two families.
    /// Clearing that last debt with no act would drop the taking back from the record while no
    /// end counts (review #8982 P2-1).
    Wait,
}

/// How a pass carries `owed` over the Grant's line as the fold holds it: `line` is whether a
/// counted act ended it and its one family, `None` while no counted act names the Grant.
fn owed_end_carry(line: Option<(bool, Option<GrantFamily>)>, owed: &OwedGrantEnd) -> OwedEndCarry {
    let family = match line {
        Some((true, _)) => return OwedEndCarry::Settle,
        Some((false, None)) => return OwedEndCarry::Settle,
        Some((false, family)) => family,
        // No counted act names the Grant here yet: its writer's family ends it before its
        // giving arrives. A torn row's debt knows no family, so it waits for the giving to
        // name one (Astra r1-r2d F3).
        None => owed.family,
    };
    family.map_or(OwedEndCarry::Wait, OwedEndCarry::Sign)
}

/// Whether a counted act ended the line `fold` holds for `grant`, and its one family; `None`
/// while no counted act names the Grant.
fn grant_line_state(
    fold: &crate::authority::AuthorityView,
    grant: EntityId,
) -> Option<(bool, Option<GrantFamily>)> {
    fold.grant_line(grant).map(|line| (line.ended, line.family))
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
    /// debt whose line a counted act already ended clears with no act. `None`, with nothing
    /// written, for no debt, a debt that waits ([`OwedEndCarry::Wait`]), or an install that
    /// cannot carry now.
    fn carry_owed_grant_end_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        grant: EntityId,
    ) -> Result<Option<GrantEndRecord>> {
        let Some(owed) = OWED_GRANT_END.get(&self.store, txn, &HexId(grant))? else {
            return Ok(None);
        };
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let family = match owed_end_carry(grant_line_state(&fold, grant), &owed) {
            OwedEndCarry::Sign(family) => family,
            OwedEndCarry::Settle => {
                OWED_GRANT_END.delete(&self.store, txn, &HexId(grant))?;
                return Ok(Some(GrantEndRecord::Settled));
            }
            OwedEndCarry::Wait => return Ok(None),
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

    /// Carries every Grant end this install still owes and can sign or clear now, each in a
    /// writer of its own; a debt that waits is left as it is, with no writer opened. The caller
    /// loads the install key first. Returns how many it settled, and the first carry that
    /// failed: the others are still tried, and each that failed stays owed.
    ///
    /// # Errors
    /// The read of the owed ends.
    fn carry_owed_grant_ends(&self) -> Result<(usize, Option<crate::error::Error>)> {
        let owed = self.carriable_owed_grant_ends()?;
        let mut settled = 0;
        let mut failed = None;
        for (grant, _) in owed {
            match self.with_write_txn(|txn| self.carry_owed_grant_end_in_txn(txn, grant)) {
                Ok(Some(_)) => settled += 1,
                Ok(None) => {}
                Err(error) => {
                    failed.get_or_insert(error);
                }
            }
        }
        Ok((settled, failed))
    }

    /// [`Self::carry_owed_grant_ends`] for a pass that goes on without it, such as the install
    /// key's load: a failure is logged by kind, never with a value.
    pub(crate) fn carry_owed_grant_ends_logged(&self) {
        match self.carry_owed_grant_ends() {
            Ok((settled, None)) if settled > 0 => {
                tracing::debug!(settled, "owed Grant ends carried");
            }
            Ok((_, None)) => {}
            Ok((settled, Some(error))) => {
                tracing::warn!(
                    settled,
                    kind = ?error.kind(),
                    "some owed Grant ends were not carried on this install; they stay owed"
                );
            }
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "owed Grant ends were not read on this install"
                );
            }
        }
    }

    /// The owner work pickup's arm: with a Grant end owed that a pass can carry now, carries
    /// it, and loads this install's key first when one is to be signed. Nothing is read from
    /// the keystore while no owed end can be signed, as for a debt that waits.
    pub(crate) fn carry_owed_grant_ends_at_pickup(&self) {
        let signs = match self.carriable_owed_grant_ends() {
            Ok(owed) if owed.is_empty() => return,
            Ok(owed) => owed.iter().any(|(_, signs)| *signs),
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "owed Grant ends were not read on this install"
                );
                return;
            }
        };
        // A key that loads now carries them as it loads; this pass carries them with a key
        // loaded before.
        if signs {
            self.load_membership_carrier();
        }
        self.carry_owed_grant_ends_logged();
    }

    /// Each Grant whose owed end a pass can sign or clear now, with whether it is signed (it
    /// needs this install's key); the debts that wait ([`OwedEndCarry::Wait`]) are left out.
    fn carriable_owed_grant_ends(&self) -> Result<Vec<(EntityId, bool)>> {
        let txn = self.store.env.read_txn()?;
        let owed = OWED_GRANT_END.scan(&self.store, &txn)?;
        if owed.is_empty() {
            return Ok(Vec::new());
        }
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        Ok(owed
            .into_iter()
            .filter_map(|(HexId(grant), owed)| {
                match owed_end_carry(grant_line_state(&fold, grant), &owed) {
                    OwedEndCarry::Sign(_) => Some((grant, true)),
                    OwedEndCarry::Settle => Some((grant, false)),
                    OwedEndCarry::Wait => None,
                }
            })
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
