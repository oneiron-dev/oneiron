//! The owner-key move a device confirms (row HOSTED-OWNER-MOVE-TWO-PHASE;
//! Engine RULING OWNERKEY-HOSTED-MOVE-NEXT-STEP = A, 16 Nov 19:53, and
//! ANSWER OWNERKEY-TWO-PHASE-SIGNER = A, 21:00).
//!
//! A membership move that ends a member's owner keys revokes each with an
//! owner key's proof (row HOSTED-ROOT-REVOKES-OWNER-KEY). A managed host holds
//! no owner key, so there the move's shared act stays pending, and the
//! executing Owner confirms it on a device of theirs in three steps:
//! - the server answers the act's plan ([`OwnerKeyMovePlan`]): the parents
//!   it stands on, the member's live owner keys, and each owner key the
//!   executor enrolled with its next sequence;
//! - the device checks the plan against its own copy of the vault and signs
//!   a chain of `RevokeDevice` rows itself, its owner key the primary signer
//!   of each, its own key last when the move ends it
//!   ([`sign_owner_key_move`]): one round trip, since it knows every hash in
//!   its own chain;
//! - the server lands those rows in the act's one writer, after judging them
//!   again at its own heads, and the move then runs with no owner key left
//!   to revoke. Its `RevokeActor` rows and its execution record stay
//!   host-signed.
//!
//! Nothing is stored between the steps. A plan gone stale (the signer's
//! sequence moved, the member's keys changed, or a row the revokes would
//! fence has landed since) is refused, writing nothing, and planned again.

use std::collections::BTreeSet;

use super::*;
use crate::error::{Error, RecordError, Result};
use crate::temporal::TimeRange;
use crate::{EntityId, Vault};

/// A device's rows that are not the confirm its plan names.
pub const OWNER_KEY_MOVE_NOT_PLANNED: &str =
    "these rows are not the owner-key revokes this move's plan names";

/// A confirm whose plan went stale before it landed.
pub const OWNER_KEY_MOVE_PLAN_STALE: &str = "since this move was planned, its signer's sequence, the member's owner keys or the rows they stand on changed: plan it again and confirm the new plan";

/// A confirm signed by a key that is not the executing Owner's own.
pub const OWNER_KEY_MOVE_SIGNER_NOT_EXECUTORS: &str =
    "only an owner key the executing Owner enrolled on a device of theirs confirms this move";

/// A device whose copy of the vault does not show the plan's keys.
pub const OWNER_KEY_MOVE_NOT_SYNCED: &str = "this device's copy of the vault does not show the member's owner keys as the plan names them: sync, then confirm again";

/// A device that holds none of the executor's owner keys the plan names.
pub const OWNER_KEY_MOVE_NO_HELD_KEY: &str =
    "this device holds none of your owner keys that this move's plan names";

/// A plan whose member is not the one the Owner confirmed on the device.
pub const OWNER_KEY_MOVE_MEMBER_NOT_CONFIRMED: &str = "this move's plan ends the owner keys of another member than the one you confirmed on this device: nothing was signed";

/// One owner key the executing Owner may confirm a move with: Ed25519, live,
/// enrolled to them, and outside the host's custody.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerKeyMoveSigner {
    /// The key.
    pub public_key: [u8; 32],
    /// The sequence its first revoke takes: its next on the plan's fold.
    pub seq: u64,
}

/// What a device needs to confirm a pending move that ends `member`'s owner
/// keys: the rows it signs stand on `parents`, revoke each of `revoked`,
/// and are signed by one of `signers` at its `seq` and on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerKeyMovePlan {
    /// The pending shared act the move runs for.
    pub act_id: String,
    /// The vault's authority id.
    pub vault_id: AuthorityVaultId,
    /// The member whose Owner standing the move ends.
    pub member: EntityId,
    /// The heads the first revoke names.
    pub parents: Vec<AuthorityEntryHash>,
    /// The member's live owner keys, each of which one revoke ends: their
    /// device keys and their passkeys (row WEB-PASSKEY-OWNER-KEY).
    pub revoked: Vec<AuthorityKey>,
    /// The executor's keys that may sign.
    pub signers: Vec<OwnerKeyMoveSigner>,
    /// When it was planned, advisory unix seconds: each revoke's time.
    pub at: u64,
}

fn not_valid(reason: &'static str) -> Error {
    Error::Record(RecordError::InvalidAuthorityLogBody(reason))
}

/// The `RevokeDevice` rows that confirm `plan`, signed by `signer`, one of
/// the plan's signers, through `sign` (an owner key's signature over an
/// authority transcript): one row per revoked key, `signer`'s own last when
/// the plan revokes it, each at the next sequence; the first on the plan's
/// parents, each next on the one before.
///
/// # Errors
/// [`RecordError::InvalidAuthorityLogBody`] for a `signer` the plan does not
/// name, a plan with no key to revoke, or parents a row cannot name; `sign`'s
/// error.
pub fn sign_owner_key_move<S>(
    plan: &OwnerKeyMovePlan,
    signer: [u8; 32],
    mut sign: S,
) -> Result<Vec<AuthorityLogEntry>>
where
    S: FnMut(&[u8]) -> Result<Vec<u8>>,
{
    let mut seq = plan
        .signers
        .iter()
        .find(|candidate| candidate.public_key == signer)
        .map(|candidate| candidate.seq)
        .ok_or_else(|| not_valid(OWNER_KEY_MOVE_NOT_PLANNED))?;
    let mut parents: BTreeSet<AuthorityEntryHash> = plan.parents.iter().copied().collect();
    if plan.revoked.is_empty() || parents.is_empty() || parents.len() > MAX_PARENTS {
        return Err(not_valid(OWNER_KEY_MOVE_NOT_PLANNED));
    }
    let signer_key = AuthorityKey::Ed25519(signer);
    let mut keys = plan.revoked.clone();
    // A key that proves the others ends last, after it proved them (as the
    // one-writer move orders its proof key).
    keys.sort_by_key(|key| *key == signer_key);
    let mut rows = Vec::with_capacity(keys.len());
    for key in keys {
        let mut row = AuthorityLogEntry {
            schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
            vault_id: Some(plan.vault_id),
            seq,
            parent_hashes: parents.into_iter().collect(),
            op: AuthorityOp::RevokeDevice { revoked_key: key },
            signer: AuthoritySignature {
                suite: signer_key.suite(),
                public_key: signer_key.clone(),
                signature: vec![0; 64],
            },
            cosigns: Vec::new(),
            ts: plan.at,
        };
        row.signer.signature = sign(&authority_transcript(&row)?)?;
        parents = BTreeSet::from([authority_entry_hash(&row)?]);
        seq = seq.checked_add(1).ok_or_else(invalid_authority)?;
        rows.push(row);
    }
    Ok(rows)
}

/// `keys`, the live owner keys enrolled to a member
/// (`Vault::live_owner_keys_enrolled_for_in_txn`: their device keys and
/// their passkeys), but `root` (a self-host root that is also an owner key
/// ends only its binding).
fn member_owner_keys(keys: Vec<AuthorityKey>, root: Option<&AuthorityKey>) -> Vec<AuthorityKey> {
    keys.into_iter().filter(|key| root != Some(key)).collect()
}

/// The owner keys `person` may confirm a move with on `fold`: live, enrolled
/// to them, and trusted as the owner's under this posture (never a key in a
/// managed host's custody), each with its next sequence.
fn owner_key_move_signers(
    fold: &AuthorityFold,
    keys: &[EnrolledOwnerKey],
    person: EntityId,
    hosted: bool,
) -> Result<Vec<OwnerKeyMoveSigner>> {
    keys.iter()
        .filter(|key| key.live && key.owner == person)
        .filter(|key| fold.proves_owner_acts(&AuthorityKey::Ed25519(key.public_key), hosted))
        .map(|key| {
            Ok(OwnerKeyMoveSigner {
                public_key: key.public_key,
                seq: next_sequence(fold, &AuthorityKey::Ed25519(key.public_key))?,
            })
        })
        .collect()
}

/// Whether `vault` is served under the Hosted posture.
fn hosted(vault: &Vault) -> bool {
    vault.privacy_posture() == crate::HostingPrivacyPosture::Hosted
}

impl Vault {
    /// The next step of a refused owner-key move whose shared act `executor`
    /// runs: confirm it on a device when they hold an owner key that may
    /// sign it, else enrol one first.
    ///
    /// # Errors
    /// The log's read errors.
    pub(crate) fn owner_key_move_step_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        executor: EntityId,
    ) -> Result<crate::error::OwnerKeyMoveStep> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let keys = self.enrolled_owner_keys_in_txn(txn)?;
        Ok(
            if owner_key_move_signers(&fold, &keys, executor, hosted(self))?.is_empty() {
                crate::error::OwnerKeyMoveStep::EnrolOwnerDevice
            } else {
                crate::error::OwnerKeyMoveStep::ConfirmOnOwnerDevice
            },
        )
    }

    /// The plan of the move `act_id` runs, which ends `member`'s owner keys
    /// and which `executor` confirms, at this writer's heads; a frontier
    /// wider than one row names is joined under `issuer` first (FIX 7908)
    /// and kept, as a prepared enrolment's join is. `root`, the host root,
    /// is never revoked as an owner key.
    ///
    /// # Errors
    /// [`invalid_authority`] for an unrooted log or a frontier no row can
    /// name; the join's and the log's errors.
    pub(crate) fn owner_key_move_plan_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: Option<&HostSlipIssuer>,
        executor: EntityId,
        member: EntityId,
        act_id: &str,
    ) -> Result<OwnerKeyMovePlan> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let fold = match issuer {
            Some(issuer) => self
                .prepare_authority_frontier_in_txn(
                    txn,
                    &fold,
                    FrontierSigner::Host(issuer),
                    MAX_PARENTS,
                )?
                .unwrap_or(fold),
            None => fold,
        };
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        if fold.append_heads.is_empty() || fold.append_heads.len() > MAX_PARENTS {
            return Err(invalid_authority());
        }
        let keys = self.enrolled_owner_keys_in_txn(txn)?;
        let root = issuer.map(HostSlipIssuer::public_key);
        Ok(OwnerKeyMovePlan {
            act_id: act_id.to_owned(),
            vault_id,
            member,
            parents: fold.append_heads.iter().copied().collect(),
            revoked: member_owner_keys(
                self.live_owner_keys_enrolled_for_in_txn(txn, member)?,
                root.as_ref(),
            ),
            signers: owner_key_move_signers(&fold, &keys, executor, hosted(self))?,
            at: self.instant_in_txn(txn)?.secs(),
        })
    }

    /// A device's confirm of `plan` (row HOSTED-OWNER-MOVE-TWO-PHASE): the
    /// owner `authority` proves checks the plan against this install's copy
    /// of the vault (the same vault; the plan's member is `member`, the one
    /// the Owner confirmed on this device; each key it revokes a live owner
    /// key enrolled to that member, and no other of theirs; the key this
    /// install holds enrolled to `authority`'s owner and named among the
    /// plan's signers), then signs the plan's revokes with that key
    /// ([`sign_owner_key_move`]). It writes nothing; the answer is each row's
    /// encoded body, in order, for the server's land.
    ///
    /// The act lives on the host, so the device cannot check that the plan's
    /// member is the act's. The Owner's confirm of `member`, shown from this
    /// device's own copy and never filled from the plan, is what binds the
    /// revokes to the move they chose (REVIEW2 #9093 P1-1; Engine ANSWER
    /// OWNERKEY-TWO-PHASE-MEMBER-CONFIRM = A). The device's words are
    /// `oneiron_contracts::error::OWNER_KEY_MOVE_DEVICE_CONFIRM_TEXT`.
    ///
    /// # Errors
    /// [`RecordError::AuthorityRefused`] for an agent's act or a person who
    /// is not this vault's owner; [`RecordError::InvalidAuthorityLogBody`]
    /// for a plan of another member than `member`
    /// ([`OWNER_KEY_MOVE_MEMBER_NOT_CONFIRMED`]), a plan of another vault,
    /// keys this copy does not show as the plan names them (sync first), or
    /// when this install holds none of the owner's keys the plan names.
    pub fn sign_owner_key_move_as(
        &self,
        authority: &ActAuthority,
        plan: &OwnerKeyMovePlan,
        member: EntityId,
    ) -> Result<Vec<Vec<u8>>> {
        let ActAuthority::Owner(owner, _) = authority else {
            return Err(authority_refused(OWNER_KEY_MOVE_SIGNER_NOT_EXECUTORS));
        };
        if plan.member != member {
            return Err(not_valid(OWNER_KEY_MOVE_MEMBER_NOT_CONFIRMED));
        }
        let txn = self.store.env.read_txn()?;
        let actor = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        if fold.vault_id != Some(plan.vault_id) {
            return Err(not_valid(OWNER_KEY_MOVE_NOT_PLANNED));
        }
        let keys = self.enrolled_owner_keys_in_txn(&txn)?;
        let shown: BTreeSet<AuthorityKey> = member_owner_keys(
            self.live_owner_keys_enrolled_for_in_txn(&txn, plan.member)?,
            None,
        )
        .into_iter()
        .collect();
        let planned: BTreeSet<AuthorityKey> = plan.revoked.iter().cloned().collect();
        if shown != planned {
            return Err(not_valid(OWNER_KEY_MOVE_NOT_SYNCED));
        }
        let signer = self
            .owner_proof_signer(&fold)
            .ok_or_else(|| not_valid(OWNER_KEY_MOVE_NO_HELD_KEY))?;
        let AuthorityKey::Ed25519(held) = signer.root() else {
            return Err(not_valid(OWNER_KEY_MOVE_NO_HELD_KEY));
        };
        let own = keys
            .iter()
            .any(|key| key.live && key.owner == actor && key.public_key == held);
        if !own || !plan.signers.iter().any(|named| named.public_key == held) {
            return Err(not_valid(OWNER_KEY_MOVE_NO_HELD_KEY));
        }
        drop(txn);
        sign_owner_key_move(plan, held, |transcript| signer.sign_owner_proof(transcript))?
            .iter()
            .map(encode_authority_log_entry_body)
            .collect()
    }

    /// Lands a device's confirm of a move that ends `member`'s owner keys,
    /// which `executor` runs, in the act's writer `txn` (row
    /// HOSTED-OWNER-MOVE-TWO-PHASE): `rows`, as [`sign_owner_key_move`]
    /// signed them, judged again at the heads read here. Each must be a
    /// `RevokeDevice` signed alone by one key, an owner key enrolled to
    /// `executor` that may sign ([`OwnerKeyMovePlan::signers`]), at its
    /// next sequence and on, the first on rows this log holds and each next
    /// on the one before; together they revoke exactly the member's live
    /// owner keys, but `root`, the signer's own last. Every row must count,
    /// no row this log counted may fall, and no owner key of the member may
    /// stay live. No rows is no confirm, and writes nothing.
    ///
    /// # Errors
    /// [`RecordError::AuthorityRefused`] for a signer that is not the
    /// executor's; [`RecordError::InvalidAuthorityLogBody`] for rows that
    /// are not such a confirm, or for a plan gone stale; the log's. The
    /// caller's writer drops with the error.
    pub(crate) fn land_owner_key_move_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        executor: EntityId,
        member: EntityId,
        root: Option<&AuthorityKey>,
        rows: &[Vec<u8>],
    ) -> Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let before = self.authority_view_readonly_in_txn(txn)?;
        let keys = self.enrolled_owner_keys_in_txn(txn)?;
        let signers = owner_key_move_signers(&before, &keys, executor, hosted(self))?;
        let entries = rows
            .iter()
            .map(|row| decode_authority_log_entry_body(row))
            .collect::<Result<Vec<_>>>()
            .map_err(|_| not_valid(OWNER_KEY_MOVE_NOT_PLANNED))?;
        let Some(first) = entries.first() else {
            return Ok(());
        };
        let signer_key = first.signer_key().clone();
        let AuthorityKey::Ed25519(signer_bytes) = signer_key else {
            return Err(authority_refused(OWNER_KEY_MOVE_SIGNER_NOT_EXECUTORS));
        };
        let Some(signer) = signers
            .iter()
            .find(|candidate| candidate.public_key == signer_bytes)
        else {
            return Err(authority_refused(OWNER_KEY_MOVE_SIGNER_NOT_EXECUTORS));
        };
        // The fold judges the rows at the heads the plan named; what moved
        // since is judged again here, as a prepared enrolment's land does.
        if first.seq < signer.seq {
            return Err(not_valid(OWNER_KEY_MOVE_PLAN_STALE));
        }
        if first.seq != signer.seq
            || first.parent_hashes.is_empty()
            || first.parent_hashes.len() > MAX_PARENTS
        {
            return Err(not_valid(OWNER_KEY_MOVE_NOT_PLANNED));
        }
        if !first
            .parent_hashes
            .iter()
            .all(|parent| before.valid_entries.contains(parent))
        {
            return Err(not_valid(OWNER_KEY_MOVE_PLAN_STALE));
        }
        let mut revoked = Vec::with_capacity(entries.len());
        let mut previous: Option<AuthorityEntryHash> = None;
        let mut hashes = Vec::with_capacity(entries.len());
        for (offset, entry) in entries.iter().enumerate() {
            let AuthorityOp::RevokeDevice { revoked_key } = &entry.op else {
                return Err(not_valid(OWNER_KEY_MOVE_NOT_PLANNED));
            };
            let seq = u64::try_from(offset)
                .ok()
                .and_then(|offset| signer.seq.checked_add(offset))
                .ok_or_else(invalid_authority)?;
            let chained = match previous {
                Some(parent) => entry.parent_hashes == [parent],
                None => true,
            };
            if entry.signer_key() != &signer_key
                || !entry.cosigns.is_empty()
                || entry.vault_id != before.vault_id
                || entry.seq != seq
                || !chained
            {
                return Err(not_valid(OWNER_KEY_MOVE_NOT_PLANNED));
            }
            revoked.push(revoked_key.clone());
            let hash = authority_entry_hash(entry)?;
            previous = Some(hash);
            hashes.push(hash);
        }
        let named: BTreeSet<AuthorityKey> = revoked.iter().cloned().collect();
        if named.len() != revoked.len() {
            return Err(not_valid(OWNER_KEY_MOVE_NOT_PLANNED));
        }
        let live: BTreeSet<AuthorityKey> =
            member_owner_keys(self.live_owner_keys_enrolled_for_in_txn(txn, member)?, root)
                .into_iter()
                .collect();
        if named != live {
            return Err(not_valid(OWNER_KEY_MOVE_PLAN_STALE));
        }
        if live.contains(&signer_key) && revoked.last() != Some(&signer_key) {
            return Err(not_valid(OWNER_KEY_MOVE_NOT_PLANNED));
        }
        let now = self.instant_in_txn(txn)?.secs();
        let at = TimeRange {
            start: now,
            end: now,
        };
        let stored: Vec<(AuthorityLogEntry, TimeRange, u64)> =
            entries.into_iter().map(|entry| (entry, at, now)).collect();
        self.put_authority_log_entries_in_txn(txn, &stored)?;
        let after = self.authority_view_readonly_in_txn(txn)?;
        if !hashes.iter().all(|hash| after.valid_entries.contains(hash)) {
            return Err(not_valid(OWNER_KEY_MOVE_NOT_PLANNED));
        }
        // A revoke fences every row its key signs outside its ancestry: a
        // row that landed after the plan would fall, with every row above it.
        if before
            .valid_entries
            .difference(&after.valid_entries)
            .next()
            .is_some()
        {
            return Err(not_valid(OWNER_KEY_MOVE_PLAN_STALE));
        }
        if !member_owner_keys(self.live_owner_keys_enrolled_for_in_txn(txn, member)?, root)
            .is_empty()
        {
            return Err(not_valid(OWNER_KEY_MOVE_PLAN_STALE));
        }
        Ok(())
    }
}
