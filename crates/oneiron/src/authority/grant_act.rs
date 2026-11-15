//! The general grant act's fold transition and its in-transaction writer (Fable pass 28 R2,
//! Engine SR-E3): a person's giving or end of a Grant row that no other act carries, or a
//! rule's end, signed by this install's key in the writer's own transaction.
//!
//! The transition runs the carrier checks every grant act runs
//! ([`super::agent_grant_act::apply_carried_grant_act`]); the Grant's line is
//! [`super::grant_lines::apply_grant_act_line`]'s. Whether the decider could give those terms
//! is no fold question (every giver rule reads rows: a vault's owners, an admin's powers, a
//! delegate's parent); the reader judges it by the family's own rule.

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::{TimeRange, Vault};

use super::machine_standing::InstallCounted;
use super::*;

/// This install cannot carry the act: it has no machine identity or loaded install key, or no
/// live profile of it stands under that key (FIX 2222: no roster key carries an act).
const NO_CARRIER: &str = "this install has no live machine profile in the vault's roster to carry \
                          the grant act; nothing was written";
/// The act would name more rows than one authority entry may.
const TOO_MANY_HEADS: &str = "the authority log has more concurrent heads than one grant act may \
                              name; nothing was written";
/// The fold did not count the signed act, so the caller's transaction must not commit the
/// Grant change it records.
const NOT_COUNTED: &str = "the authority fold did not count the grant act; nothing was written";

/// Who decides a grant act at its writer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    not(oneiron_test_support),
    allow(dead_code, reason = "pass 28 R2's writers decide")
)]
pub(crate) enum GrantActBy {
    /// `person`, whom the writer's door authenticated and whose standing it judged, decided at
    /// `surface` (audit only).
    Person {
        person: EntityId,
        surface: ActSurface,
    },
    /// A rule ended the Grant; nobody decided.
    Rule,
}

/// The `GrantAct` transition, after the shape, signature, retired, sequence-floor,
/// parent-merge and vault checks: the carrier checks alone. It moves no fold state of its own.
pub(super) fn apply_grant_act(
    state: &FoldState,
    entry: &AuthorityLogEntry,
    record: &GrantActRecord,
    hash: AuthorityEntryHash,
    standing: (Option<&PinnedRoot>, InstallCounted<'_>),
) -> std::result::Result<(), AuthorityFoldIssue> {
    super::agent_grant_act::apply_carried_grant_act(state, entry, record.machine, hash, standing)
}

impl Vault {
    /// Signs, appends and folds `by`'s act giving or ending row `subject` of `family` in the
    /// caller's write transaction `txn`, before the caller puts or deletes the row. A giving's
    /// `terms` is the row's commitment (`crate::federation::federation_grant_terms`) under the
    /// key the caller writes into it.
    ///
    /// The act names the main-log heads alone and returns only once the fold in `txn` counted
    /// it. Nothing commits here: the caller's commit lands the act and the row together.
    ///
    /// # Errors
    /// [`crate::error::RecordError::AuthorityRefused`] for an install that cannot carry the
    /// act, more heads than one entry may name, or an act the fold did not count; an invalid
    /// act (a rule's giving).
    #[cfg_attr(
        not(oneiron_test_support),
        allow(dead_code, reason = "pass 28 R2's writers call it")
    )]
    pub(crate) fn append_grant_act_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        by: GrantActBy,
        subject: EntityId,
        family: GrantFamily,
        change: GrantActChange,
    ) -> Result<AuthorityEntryHash> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let machine = crate::identity::read_machine_id_in_txn(self, txn)?
            .ok_or_else(|| authority_refused(NO_CARRIER))?;
        let key = crate::identity::read_machine_signing_key_in_txn(self, txn)?
            .ok_or_else(|| authority_refused(NO_CARRIER))?;
        let public_key = key.verifying_key().to_bytes();
        if !super::owner_act_signer_admits(fold.machine(machine), &fold.roster, &public_key) {
            return Err(authority_refused(NO_CARRIER));
        }
        let joiner = FrontierSigner::Install(machine, &key);
        let fold = self
            .prepare_authority_frontier_in_txn(txn, &fold, joiner, MAX_PARENTS)?
            .unwrap_or(fold);
        let signer = AuthorityKey::Ed25519(public_key);
        let seq = next_sequence(&fold, &signer)?;
        let parents = fold.append_heads.clone();
        if parents.len() > MAX_PARENTS {
            return Err(authority_refused(TOO_MANY_HEADS));
        }
        let decider = match by {
            GrantActBy::Person { person, surface } => GrantDecider::Person(OwnerAct::by_owner(
                person,
                change.act_kind(),
                subject,
                surface,
                GRANT_ACT_SEEN,
            )),
            GrantActBy::Rule => GrantDecider::Rule,
        };
        let record = GrantActRecord {
            decider,
            machine,
            subject,
            family,
            change,
        };
        record.validate()?;
        let now = self.instant_in_txn(txn)?.secs();
        let entry = sign_side_entry(
            &fold,
            &key,
            seq,
            parents,
            AuthorityOp::GrantAct(record),
            now,
        )?;
        let entry_hash = authority_entry_hash(&entry)?;
        let at = TimeRange {
            start: now,
            end: now,
        };
        self.put_authority_log_entries_in_txn(txn, &[(entry, at, now)])?;
        let after = self.authority_view_readonly_in_txn(txn)?;
        if !after.valid_entries.contains(&entry_hash)
            || after.install.held_back.contains(&entry_hash)
        {
            return Err(authority_refused(NOT_COUNTED));
        }
        Ok(entry_hash)
    }
}
