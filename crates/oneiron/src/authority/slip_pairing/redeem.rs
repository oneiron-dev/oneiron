//! Redeeming a pairing link: the slip, and the profile of a machine the link
//! adds, in one transaction.

use ed25519_dalek::{Signature, VerifyingKey};

use super::code::pairing_row_key;
use super::principal::canonical_id;
use super::*;
use crate::authority::machine_answers::AnswerAct;
use crate::authority::slip_vault::{random_slip_id, require_host};

/// The install the explicit bootstrap arm serves (C4): one the vault never
/// profiled, such as a fresh self-host first install, whose host root signs
/// as the owner's own key. A profiled install that cannot carry (removed,
/// poisoned) never falls back to the root.
fn unprofiled_install(fold: &AuthorityFold, machine: Option<crate::EntityId>) -> bool {
    machine.is_none_or(|machine| fold.machine(machine).is_none())
}

impl Vault {
    /// No prior bearer is required. The link is the one-use enrollment grant;
    /// the binding signature proves possession of the receiving connection key.
    /// Consuming the link and appending SlipMint are one LMDB transaction.
    /// A link that adds a machine is refused here: it must enrol that machine.
    pub fn redeem_pairing_link(
        &self,
        issuer: &HostSlipIssuer,
        code: &str,
        holder_ref: &str,
        binding_key: [u8; 32],
        signature: &[u8],
    ) -> Result<CapabilitySlip> {
        self.redeem_pairing_link_in(issuer, code, holder_ref, binding_key, signature, None)
            .map(|redeemed| redeemed.slip)
    }
    /// Redeems any link, a machine's with its `request`, and returns the
    /// checkpoint pin the link kept as well, for the joining device to check
    /// against the challenge and digest its owner-delivered link carries.
    pub fn redeem_pairing_link_pinned(
        &self,
        issuer: &HostSlipIssuer,
        code: &str,
        holder_ref: &str,
        binding_key: [u8; 32],
        signature: &[u8],
        request: Option<&MachineEnrolmentRequest>,
    ) -> Result<PairingRedeemed> {
        self.redeem_pairing_link_in(issuer, code, holder_ref, binding_key, signature, request)
    }
    /// Redeems a link that adds a machine: the slip and the owner's profile
    /// for `request` land in one transaction, under the answer the owner gave
    /// when making the link.
    pub fn redeem_machine_pairing_link(
        &self,
        issuer: &HostSlipIssuer,
        code: &str,
        holder_ref: &str,
        binding_key: [u8; 32],
        signature: &[u8],
        request: &MachineEnrolmentRequest,
    ) -> Result<(CapabilitySlip, FoldedMachine)> {
        let redeemed = self.redeem_pairing_link_in(
            issuer,
            code,
            holder_ref,
            binding_key,
            signature,
            Some(request),
        )?;
        Ok((
            redeemed.slip,
            redeemed.machine.ok_or_else(invalid_authority)?,
        ))
    }
    fn redeem_pairing_link_in(
        &self,
        issuer: &HostSlipIssuer,
        code: &str,
        holder_ref: &str,
        binding_key: [u8; 32],
        signature: &[u8],
        request: Option<&MachineEnrolmentRequest>,
    ) -> Result<PairingRedeemed> {
        let key = VerifyingKey::from_bytes(&binding_key).map_err(|_| invalid_authority())?;
        let signature = Signature::from_slice(signature).map_err(|_| invalid_authority())?;
        let mut txn = self.store.env.write_txn()?;
        let now = self.instant_in_txn(&txn)?.secs();
        let row_key = pairing_row_key(issuer, code)?;
        let pending = PAIRING_PENDING
            .get(&self.store, &txn, &row_key)
            .map_err(|_| invalid_authority())?
            .ok_or_else(invalid_authority)?;
        // The connection key signs the challenge and pin digest the link kept,
        // so a redeemer handed another link's pin cannot spend this one.
        let pin_ref = pending.pin.as_ref().map(PairingPinRef::of).transpose()?;
        key.verify_strict(
            &pairing_binding_transcript_pinned(code, &binding_key, holder_ref, pin_ref.as_ref())?,
            &signature,
        )
        .map_err(|_| invalid_authority())?;
        if now >= pending.expires_at
            || pending.host_key != issuer.binding_key()
            || pending.machine.is_some() != request.is_some()
        {
            return Err(invalid_authority());
        }
        if pending
            .principal
            .holder_ref
            .as_deref()
            .is_some_and(|intended| intended != holder_ref)
        {
            return Err(invalid_authority());
        }
        self.validate_pairing_principal_in_txn(&txn, &pending.principal, &pending.scope)?;
        // The holder is known only now when the link left it open.
        self.validate_pairing_facets_in_txn(
            &txn,
            &pending.principal,
            &pending.scope,
            Some(holder_ref),
        )?;
        let write_facet = pending
            .principal
            .write_facet
            .as_deref()
            .map(canonical_id)
            .transpose()?;
        // Recheck in the actual mint transaction: policy may have narrowed
        // after link issuance while the one-hour link was still outstanding.
        let ceiling = crate::gate::resolve_credential_lifetimes(&self.store, &txn)?;
        let slip_lifetime_secs = pending.slip_lifetime_secs.min(ceiling.initial_owner_secs);
        // A live owner's own device gets their residence grant, named in the
        // slip so the device's selector can name it (FIX 3134).
        let grant_ref = self.own_device_grant_for_holder_in_txn(
            &mut txn,
            holder_ref,
            pending.principal.actor_class.as_deref(),
            now,
        )?;
        let fold = self.authority_fold_readonly_in_txn(&txn)?;
        require_host(&fold, issuer)?;
        let claims = SlipClaims {
            slip_id: random_slip_id(),
            vault_id: fold.vault_id.ok_or_else(invalid_authority)?,
            parent_id: None,
            holder_ref: holder_ref.to_owned(),
            binding_key,
            scope: pending.scope,
            issued_at: now,
            expires_at: now.saturating_add(slip_lifetime_secs),
            ttl_secs: slip_lifetime_secs,
            single_use: false,
            records: Default::default(),
            channels: Default::default(),
            actor_class: pending.principal.actor_class,
            org_ref: pending.principal.org_ref,
            grant_ref: grant_ref.map(|id| id.to_hex()),
            invitation_ref: None,
            delegation: None,
        };
        let slip = self.mint_slip_in_txn(&mut txn, issuer, claims)?;
        if let Some(facet) = write_facet {
            PAIRED_WRITE_FACET.put(
                &self.store,
                &mut txn,
                &write_facet_key(&slip.claims.slip_id),
                &facet,
            )?;
        }
        let machine = match (pending.machine, request) {
            (Some(answer), Some(request)) => {
                // The owner who answered must still own the vault at redemption.
                if !crate::policy_model::is_live_vault_owner_in_txn(self, &txn, &answer.owner)? {
                    return Err(invalid_authority());
                }
                Some(self.redeem_machine_answer_in_txn(&mut txn, issuer, answer, request)?)
            }
            _ => None,
        };
        PAIRING_PENDING.delete(&self.store, &mut txn, &row_key)?;
        txn.commit()?;
        // A machine admitted here changed the roster: seal the portable
        // credentials again, as `enroll_machine` does. The redemption stands
        // whatever happens, since the link is spent and its slip exists only
        // in this reply; the sync lane's upkeep re-seal retries a failure.
        #[cfg(feature = "sync")]
        if machine.is_some()
            && let Err(error) = self.reseal_after_machine_admission()
        {
            tracing::warn!(
                error = %error,
                "custody re-seal after a paired machine's admission failed; upkeep retries it"
            );
        }
        Ok(PairingRedeemed {
            slip,
            machine,
            pin: pending.pin,
            link_owner: pending.owner,
        })
    }
    /// Enrols the machine a link adds under the approval it kept (C2): this
    /// install carries the owner's act, its target the redeeming machine and
    /// its `seen` that machine's revision here, zero for a new one. An
    /// install the vault never profiled takes the explicit bootstrap arm
    /// instead (C4, a fresh self-host first install): the host root signs
    /// the owner's answer with no act, as it always has, and the fold judges
    /// the root's custody, so a hosted root never answers for the owner
    /// there. Any other install that cannot carry refuses, and nothing is
    /// written.
    fn redeem_machine_answer_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: &HostSlipIssuer,
        answer: PendingMachine,
        request: &MachineEnrolmentRequest,
    ) -> Result<FoldedMachine> {
        let role = MachineRole::Owned(answer.ownership);
        let fold = self.authority_view_readonly_in_txn(txn)?;
        if self.carrier_in_txn(txn, &fold).is_ok() {
            let act = AnswerAct {
                owner: answer.owner,
                by: answer.by,
                surface: answer.surface,
                kind: answer.kind,
                seen: None,
            };
            return self.enroll_machine_in_txn(txn, act, request, role);
        }
        if unprofiled_install(&fold, crate::identity::read_machine_id_in_txn(self, txn)?) {
            return self.enroll_bootstrap_in_txn(txn, issuer, answer.owner, request, role);
        }
        Err(crate::authority::machine_answers::no_carrier())
    }

    /// The facet a credential redeemed from a link writes in, as the owner
    /// named it there: `None` for a link that named none.
    pub fn paired_write_facet(&self, slip_id: &[u8; 32]) -> Result<Option<crate::EntityId>> {
        let txn = self.store.env.read_txn()?;
        PAIRED_WRITE_FACET.get(&self.store, &txn, &write_facet_key(slip_id))
    }
}
