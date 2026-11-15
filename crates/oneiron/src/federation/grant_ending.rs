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
//! An access grant's revoke is owed the same way (pass 28 R2e): a revoke restates its row (the
//! revoked body is the line's newest giving, so a re-grant at the id stays one line), so its debt
//! holds the commitment to the revoked terms, and the pass gives them in the decider's name.
//!
//! An owed act keeps the deciding person, or agent, only until their erase: the erase rewrites
//! it, and each owed membership record naming them, into a person-free end by rule.

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

/// One Grant end, or access grant revoke, not signed yet. It holds no term, value, credential
/// or proof: a revoke's terms only by their keyed commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct OwedGrantEnd {
    /// The authenticated PERSON who took the Grant back (for an agent's act, the person whose
    /// Grant the agent acts in); `None` for a rule's end.
    decider: Option<EntityId>,
    /// The agent that decided within its own Grant, in `decider`'s name: an access grant's
    /// alone. `None` for a person's or a rule's act.
    agent: Option<OwedAgent>,
    /// The Grant's family as its writer knew it; `None` for a batch delete, which knows only
    /// the row, so the pass ends the line by its own family.
    family: Option<GrantFamily>,
    /// An access grant's revoke: the commitment to the revoked row's terms
    /// (`crate::access_grant::access_grant_terms`), which the pass gives. `None` for an end.
    restated: Option<[u8; 32]>,
}

/// An agent that decided within its own live Grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct OwedAgent {
    agent: EntityId,
    grant: EntityId,
}

/// The debt `by` owes for `family`'s Grant: `restated` for an access grant's revoke.
fn owed_act(by: GrantActBy, family: GrantFamily, restated: Option<[u8; 32]>) -> OwedGrantEnd {
    let (decider, agent) = match by {
        GrantActBy::Person { person, .. } => (Some(person), None),
        GrantActBy::Agent {
            owner,
            agent,
            grant,
            ..
        } => (Some(owner), Some(OwedAgent { agent, grant })),
        GrantActBy::Rule => (None, None),
    };
    OwedGrantEnd {
        decider,
        agent,
        family: Some(family),
        restated,
    }
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

/// A batch delete's debt, below any vault door: the FEDERATION_GRANT or ACCESS_GRANT row
/// `grant`, about to be torn in `wtxn`, is owed a counted end unless a writer already owes it a
/// fuller one; an owed revoke's restatement becomes the end. Any other kind, or no row, owes
/// nothing.
///
/// # Errors
/// The row read, or the debt's write.
pub(crate) fn owe_torn_grant_end_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    grant: EntityId,
) -> Result<()> {
    let is_grant = crate::ports::EntityStoreRead::port_entity_record(store, &*wtxn, &grant)?
        .is_some_and(|row| {
            row.entity_type == crate::registry::ENTITY_TYPE_FEDERATION_GRANT
                || row.entity_type == crate::registry::ENTITY_TYPE_ACCESS_GRANT
        });
    let owed_end = OWED_GRANT_END
        .get(store, wtxn, &HexId(grant))?
        .is_some_and(|owed| owed.restated.is_none());
    if !is_grant || owed_end {
        return Ok(());
    }
    OWED_GRANT_END.put(store, wtxn, &HexId(grant), &OwedGrantEnd::by_rule())
}

impl OwedGrantEnd {
    /// A rule's end, of the line's own family.
    fn by_rule() -> Self {
        Self {
            decider: None,
            agent: None,
            family: None,
            restated: None,
        }
    }
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
        OWED_GRANT_END.put(&self.store, txn, &HexId(grant), &owed_act(by, family, None))?;
        Ok(self.carry_owed_grant_end_in_savepoint(txn, grant))
    }

    /// `by`'s revoke of the access grant `grant`, in its writer's transaction `txn`: a giving of
    /// the revoked row's terms, `terms` committing to them, that never refuses. Owed first, then
    /// signed in a savepoint of `txn` when this install can carry it now, as an end is.
    ///
    /// # Errors
    /// The debt's own write.
    pub(crate) fn restate_revoked_grant_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        by: GrantActBy,
        grant: EntityId,
        terms: [u8; 32],
    ) -> Result<GrantEndRecord> {
        OWED_GRANT_END.put(
            &self.store,
            txn,
            &HexId(grant),
            &owed_act(by, GrantFamily::AccessGrant, Some(terms)),
        )?;
        Ok(self.carry_owed_grant_end_in_savepoint(txn, grant))
    }

    /// A signed giving of `grant` in `txn` replaces the revoke this install still owes for it:
    /// the newer terms stand, so the older revoke must never be given after them. An owed end
    /// stays.
    ///
    /// # Errors
    /// The debt's read or delete.
    pub(crate) fn settle_owed_restatement_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        grant: EntityId,
    ) -> Result<()> {
        if OWED_GRANT_END
            .get(&self.store, txn, &HexId(grant))?
            .is_some_and(|owed| owed.restated.is_some())
        {
            OWED_GRANT_END.delete(&self.store, txn, &HexId(grant))?;
        }
        Ok(())
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
    /// debt with nothing left to end clears with no act. An owed revoke gives its terms in its
    /// writer's family, in its decider's name, or ends the line by rule once that decider was
    /// erased: no one is left to restate it in. `None`, with nothing written, for no debt or an
    /// install that cannot carry now.
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
            // A revoke restates its row in the family its writer gave it in.
            _ if owed.restated.is_some() => owed.family,
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
        // is a rule's. An agent's act names the agent, never the person.
        let surface = ActSurface::ThisInstall;
        let by = match (owed.decider, owed.agent) {
            (Some(owner), Some(OwedAgent { agent, grant: via })) => GrantActBy::Agent {
                owner,
                agent,
                grant: via,
                surface,
            },
            (Some(person), None) if family != GrantFamily::OwnerAgent => {
                GrantActBy::Person { person, surface }
            }
            _ => GrantActBy::Rule,
        };
        let change = match (owed.restated, by) {
            (Some(terms), GrantActBy::Person { .. } | GrantActBy::Agent { .. }) => {
                GrantActChange::Give { terms }
            }
            _ => GrantActChange::End,
        };
        self.append_grant_act_in_txn(txn, by, grant, family, change)?;
        OWED_GRANT_END.delete(&self.store, txn, &HexId(grant))?;
        Ok(Some(GrantEndRecord::Signed))
    }

    /// Carries every Grant end this install still owes, each in a writer of its own. The caller
    /// loads the install key first. Returns how many it settled, and the first carry that
    /// failed: the others are still tried, and each that failed stays owed.
    ///
    /// # Errors
    /// The read of the owed ends.
    fn carry_owed_grant_ends(&self) -> Result<(usize, Option<crate::error::Error>)> {
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
                OWED_GRANT_END.put(&self.store, wtxn, &HexId(*grant), &OwedGrantEnd::by_rule())?;
            }
        }
        Ok(())
    }

    /// A person's or agent's erase, in its own writer (FIX 3520): every owed Grant end or revoke
    /// that names them as its decider becomes a rule's end, so no act is signed in their name
    /// and the taking back still counts.
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
            let named = owed.decider == Some(*actor)
                || owed.agent.is_some_and(|decided| decided.agent == *actor);
            if named {
                OWED_GRANT_END.put(
                    &self.store,
                    wtxn,
                    &grant,
                    &OwedGrantEnd {
                        decider: None,
                        agent: None,
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
