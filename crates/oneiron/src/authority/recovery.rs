//! Lost-owner authority recovery from material explicitly enrolled before loss.

use super::*;
use crate::store::recovery_kit::RestoredKitSecret;
use crate::world_keys::{RecoveryAuthoritySigner, RecoveryRootSeed};
use crate::{Result, Vault};

/// On a hosted vault whose host still serves, a ReRoot signed by a key the
/// host does not hold revokes the host's live root, and every slip the host
/// minted stops verifying (NOTE WAYBACK-REROOT-TRACE, 15 Nov 22:02). The
/// roster then holds a live owner key, that root itself, so the root's door
/// serves with the two ordinary ops instead (Engine NOTE 15 Nov 22:10;
/// WAYBACK-E2 = A). Nothing was written.
const HOSTED_FOLD_REROOT: &str = "a ReRoot by a key the host does not hold revokes this hosted \
                                  vault's live host root and ends its service; recover with the \
                                  root's door, which enrols the new key and revokes the lost \
                                  ones; nothing was written";

/// Refuses a ReRoot that `signer` signs while `fold`'s roster holds a live
/// owner key stamped as the host's (`ROLE_CLOUD` or `CloudCustodial`, the
/// stamp a hosted vault's root carries, [`HostSlipIssuer::root_device`]),
/// unless `signer` carries that stamp itself: the host's own move, as
/// [`Vault::recover_cloud_account`] signs it, still serves. The ReRoot writer
/// meets it ([`Vault::apply_signed_re_root_with_joins`] and the moves signed
/// here), and each admission door that stages a ReRoot meets it against the
/// fold before that row: the signed-history import, the authority-log puts,
/// and the replicated validator. It reads the fold alone, never this
/// install's posture, so a device's replica of a hosted vault or a stopped
/// hosted vault opened under another posture refuses alike, and a self-hosted
/// vault, whose root carries no cloud stamp, never does. Rows already stored,
/// a replica without this engine, and a gap-closing import's rows stay open
/// under the fold rule (FIX [HOSTED-REROOT-FOLD-RULE]).
pub(super) fn refuse_re_root_of_a_serving_host(
    fold: &AuthorityFold,
    signer: &AuthorityKey,
) -> Result<()> {
    refuse_re_root_of_a_serving_host_beside(fold, fold, signer)
}

/// [`refuse_re_root_of_a_serving_host`] at the replicated door, where a
/// window's rows arrive in no set order. `before`, the fold before the row,
/// says whether the host serves. The signer's stamp is read from `before`,
/// else from `with_rows`, the fold with the row and the rows beside it, so a
/// host's move signed by the root its earlier move in the same window named
/// still serves.
pub(crate) fn refuse_re_root_of_a_serving_host_beside(
    before: &AuthorityFold,
    with_rows: &AuthorityFold,
    signer: &AuthorityKey,
) -> Result<()> {
    let host_stamped = |device: &FoldedDevice| {
        device.roles & ROLE_CLOUD != 0 || device.tier == AuthorityTier::CloudCustodial
    };
    let host_serves = before
        .roster
        .values()
        .any(|device| !device.revoked && device.roles & ROLE_OWNER != 0 && host_stamped(device));
    let signer_row = before
        .roster
        .get(signer)
        .or_else(|| with_rows.roster.get(signer));
    if host_serves && !signer_row.is_some_and(host_stamped) {
        return Err(authority_refused(HOSTED_FOLD_REROOT));
    }
    Ok(())
}

/// The signer of `entry` when it is a ReRoot this vault does not hold yet
/// (`resident` false), which an admission door judges before it stages the
/// row.
pub(crate) fn arriving_re_root_signer(
    entry: &AuthorityLogEntry,
    resident: bool,
) -> Option<AuthorityKey> {
    (!resident && matches!(entry.op, AuthorityOp::ReRoot { .. }))
        .then(|| entry.signer_key().clone())
}

impl Vault {
    /// Rebuild the kit's distinct authority key for this vault and hand its
    /// authority to `new_device`. The key must have been explicitly enrolled
    /// before loss and still stand under the ordinary authority fold.
    ///
    /// No current owner proof, old host secret, current kit pin or world-key
    /// restoration grants authority here. The existing ReRoot path checks the
    /// live signer and fresh successor, joins its frontier and counts the move.
    /// All of that, including the vault identity used for derivation, shares one
    /// write transaction. An error commits no recovery or frontier join.
    ///
    /// It is a self-hosted vault's door, for a lost host root. On a hosted
    /// vault whose host root is live the ReRoot writer refuses it
    /// ([`refuse_re_root_of_a_serving_host`]): [`Vault::recover_owner_root`]
    /// serves there with the two ordinary ops, and the host's service stands
    /// (pass 27 R4).
    pub fn recover_owner_authority_from_kit(
        &self,
        secret: RestoredKitSecret,
        new_device: DeviceAuthority,
    ) -> Result<AuthorityLogEntry> {
        let seed = RecoveryRootSeed::from_restored_kit(secret)?;
        let mut txn = self.store.env.write_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        // The kit's live generation signs, so the same kit ReRoots with
        // generation 1 after a rotation. With none live, the highest enrolled
        // (revoked) or generation 0 goes to the fold, which refuses it as
        // today: this door keeps its meaning and only looks the live
        // generation up.
        let found = self.recovery_authority_generations_in_txn(&txn, &seed, &vault_id)?;
        let signer = match (found.live, found.enrolled) {
            (Some((_, live)), _) => live,
            (None, Some((_, enrolled))) => enrolled,
            (None, None) => RecoveryAuthoritySigner::from_seed(&seed, &vault_id, 0)?,
        };
        let sign = |transcript: &[u8]| signer.sign_authority_transcript(transcript);
        let signer_key = signer.authority_key();
        let (entry, rows) = self.re_root_authority_in_txn(
            &mut txn,
            new_device,
            (
                &signer_key,
                Some(FrontierSigner::Callback(&signer_key, &sign)),
            ),
            &sign,
        )?;
        txn.commit()?;
        self.note_committed_authority_rows(rows);
        Ok(entry)
    }
}
