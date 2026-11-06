//! The signed record of a shared-vault membership change no host issuer
//! could sign (FIX 12335, Engine 13:13 call A): its fold transition and its
//! checked carrier signing.
//!
//! The membership writer keeps the change's effects at once and, with no
//! host issuer, a value-free pending intent of it
//! (`federation::shared_act::membership::pending_execution`). This install
//! signs that committed fact with its machine key under the one carrier rule
//! ([`super::owner_act_signer_admits`]), as a carried owner act is signed, in
//! the same writer when it can and on a later pass otherwise. The signing is
//! checked: an install that cannot carry answers `None` and keeps the
//! intent; any other fault fails the caller's writer, so an intent is never
//! cleared without the record the fold counted.
//!
//! The fold withdraws every slip minted under each Grant the record names,
//! now and when a replica's mint merges later, as a `SlipGrantRevoke` does.
//! Whether the person could make the change is the writer's to judge: the
//! fold cannot read FEDERATION_GRANT rows, so it trusts the carrier, as it
//! does an owner act's.

use crate::entity_id::EntityId;
use crate::error::{Error, Result, SecretError};
use crate::{TimeRange, Vault};

use super::machine_standing::{InstallCounted, Standing, StandingView};
use super::*;

/// The record would name more rows than one authority entry may: the log's
/// encoding bound, never a possession test.
const TOO_MANY_HEADS: &str = "the authority log has more concurrent heads than one membership \
                              execution record may name; it stays pending";
/// The fold did not count the signed record, so the writer must not clear
/// the intent it signs.
const NOT_COUNTED: &str =
    "the authority fold did not count the membership execution record; it stays pending";

/// The `MembershipExecution` transition, after the shape, signature,
/// retired, sequence-floor, parent-merge and vault checks and before any
/// roster check: its signer is a machine's install key, never a roster key
/// (FIX 2222), and some chain of the machine must name the key. While
/// that machine is a live carrier at the record's parents, under the one
/// carrier rule in the roster view, it withdraws every slip minted under
/// each Grant the record names, in `state.slips`, one merged in later
/// included; a record a removed machine signed counts and withdraws
/// nothing.
pub(super) fn apply_membership_execution(
    state: &mut FoldState,
    entry: &AuthorityLogEntry,
    record: &MembershipExecution,
    hash: AuthorityEntryHash,
    (pin, counted): (Option<&PinnedRoot>, InstallCounted<'_>),
) -> std::result::Result<(), AuthorityFoldIssue> {
    if !entry.cosigns.is_empty() {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    }
    let signer = entry.signer_key();
    let AuthorityKey::Ed25519(key) = signer else {
        return Err(AuthorityFoldIssue::SignerNotInAncestry(hash));
    };
    let standing = Standing::new(state, pin, counted);
    if !standing.names_key(record.machine, key) || state.roster.contains_key(signer) {
        return Err(AuthorityFoldIssue::SignerNotInAncestry(hash));
    }
    // The withdrawals land only while the carrier is live at the record's
    // causal parents under the one carrier rule, judged pin-free in the
    // roster view so every replica agrees: a machine removed before it
    // signed (its key still named by the Removed chain) withdraws nothing.
    // The executing person's standing is never judged again.
    let admitted = standing.admits_owner_act_signer(
        record.machine,
        key,
        StandingView::Under(MachineAdmitter::Roster),
    );
    drop(standing);
    if state
        .seqs
        .get(signer)
        .is_some_and(|prior| entry.seq <= *prior)
    {
        return Err(AuthorityFoldIssue::NonMonotonicSeq(hash));
    }
    if !admitted {
        return Ok(());
    }
    for grant in &record.withdrawn_grants {
        state.slips.revoke_grant(grant.to_hex());
    }
    Ok(())
}

/// Whether `error` says this install's signing keys are not loaded here:
/// the one failure a pending record waits out.
fn signing_unavailable(error: &Error) -> bool {
    matches!(error, Error::Secret(SecretError::KeystoreUnavailable(_)))
}

impl Vault {
    /// Signs, appends and folds `record`, built for the carrier this install
    /// is, in `txn`, naming the main-log heads alone; returns its entry hash
    /// only once the fold in `txn` counted it. `None`, with nothing written,
    /// when this install cannot carry for the vault now: no machine identity,
    /// no install key loaded, or no live profile of it under that key.
    ///
    /// # Errors
    /// [`crate::error::RecordError::AuthorityRefused`] for more heads than
    /// one entry may name or a record the fold did not count; a store, fold
    /// or clock failure.
    pub(crate) fn append_membership_execution_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        record: impl FnOnce(EntityId) -> MembershipExecution,
    ) -> Result<Option<AuthorityEntryHash>> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let (machine, key) = match self.owner_work_carrier_in_txn(txn, &fold) {
            Ok(Some(carrier)) => carrier,
            Ok(None) => return Ok(None),
            Err(error) if signing_unavailable(&error) => return Ok(None),
            Err(error) => return Err(error),
        };
        let record = record(machine);
        record.validate()?;
        // The writer clears its intent only once these withdrawals land.
        let withdrawn_grants = record.withdrawn_grants.clone();
        // FIX 7908: join a frontier wider than one entry names, else today's path.
        let joiner = FrontierSigner::Install(machine, &key);
        let fold = self
            .prepare_authority_frontier_in_txn(txn, &fold, joiner, MAX_PARENTS)?
            .unwrap_or(fold);
        let signer = AuthorityKey::Ed25519(key.verifying_key().to_bytes());
        let seq = next_sequence(&fold, &signer)?;
        let parents = fold.append_heads.clone();
        if parents.len() > MAX_PARENTS {
            return Err(authority_refused(TOO_MANY_HEADS));
        }
        let now = self.instant_in_txn(txn)?.secs();
        let entry = sign_side_entry(
            &fold,
            &key,
            seq,
            parents,
            AuthorityOp::MembershipExecution(record),
            now,
        )?;
        let entry_hash = authority_entry_hash(&entry)?;
        let at = TimeRange {
            start: now,
            end: now,
        };
        self.put_authority_log_entries_in_txn(txn, &[(entry, at, now)])?;
        let after = self.authority_view_readonly_in_txn(txn)?;
        let withdrawn = |grant: &EntityId| after.slips.revoked_grants.contains(&grant.to_hex());
        if !after.valid_entries.contains(&entry_hash)
            || after.install.held_back.contains(&entry_hash)
            || !withdrawn_grants.iter().all(withdrawn)
        {
            return Err(authority_refused(NOT_COUNTED));
        }
        Ok(Some(entry_hash))
    }
}
