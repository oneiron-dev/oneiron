//! Redeeming a pairing link: the slip, and the profile of a machine the link
//! adds, in one transaction.

use ed25519_dalek::{Signature, VerifyingKey};

use super::code::pairing_row_key;
use super::principal::canonical_id;
use super::re_pairing::re_paired_standing;
use super::*;
use crate::authority::machine_answers::AnswerAct;
use crate::authority::slip_vault::{random_slip_id, require_host};

/// The install the explicit bootstrap arm serves (C4): one the vault never
/// profiled, such as a fresh self-host first install, whose host root signs
/// as the owner's own key, or one whose only standing is its own unanswered
/// profile from its first serving start (FIX 4648), which pairs its first
/// device exactly as a never-profiled install does (Engine, CALLS
/// "selfprofile serving-install role", amendment (c)). A profiled install
/// that cannot carry (removed, poisoned) never falls back to the root.
fn unprofiled_install(fold: &AuthorityFold, machine: Option<crate::EntityId>) -> bool {
    machine.is_none_or(|machine| {
        fold.machine(machine).is_none_or(|folded| {
            folded.chains().all(|(_, chain)| {
                !chain.profile.role.answered() && !chain.removed && !chain.conflicted
            })
        })
    })
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
        self.redeem_pairing_link_in(issuer, code, holder_ref, binding_key, signature, None, None)
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
        self.redeem_pairing_link_in(
            issuer,
            code,
            holder_ref,
            binding_key,
            signature,
            request,
            None,
        )
    }
    /// Redeems any link as [`Self::redeem_pairing_link_pinned`] does, with
    /// `possession`, the machine key's signature over this redemption
    /// ([`machine_possession_transcript`]), beside a machine's `request`. A
    /// machine the roster already holds live in the request's class and the
    /// role the link answers pairs again here, credential only (FIX 8636):
    /// its identity, profile and standing stay as they are, and the reply
    /// names them with the new slip. Any other request enrols as before.
    #[allow(clippy::too_many_arguments)]
    pub fn redeem_pairing_link_with_possession(
        &self,
        issuer: &HostSlipIssuer,
        code: &str,
        holder_ref: &str,
        binding_key: [u8; 32],
        signature: &[u8],
        request: Option<&MachineEnrolmentRequest>,
        possession: Option<&[u8; 64]>,
    ) -> Result<PairingRedeemed> {
        self.redeem_pairing_link_in(
            issuer,
            code,
            holder_ref,
            binding_key,
            signature,
            request,
            possession,
        )
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
            None,
        )?;
        Ok((
            redeemed.slip,
            redeemed.machine.ok_or_else(invalid_authority)?,
        ))
    }
    #[allow(clippy::too_many_arguments)]
    fn redeem_pairing_link_in(
        &self,
        issuer: &HostSlipIssuer,
        code: &str,
        holder_ref: &str,
        binding_key: [u8; 32],
        signature: &[u8],
        request: Option<&MachineEnrolmentRequest>,
        possession: Option<&[u8; 64]>,
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
        let transcript =
            pairing_binding_transcript_pinned(code, &binding_key, holder_ref, pin_ref.as_ref())?;
        key.verify_strict(&transcript, &signature).map_err(|_| invalid_authority())?;
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
            comm: pending.principal.comm,
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
        let (machine, re_paired) = match (pending.machine, request) {
            (Some(answer), Some(request)) => {
                // The owner who answered must still own the vault at redemption.
                if !crate::policy_model::is_live_vault_owner_in_txn(self, &txn, &answer.owner)? {
                    return Err(invalid_authority());
                }
                let possession = possession.map(|proof| (proof, transcript.as_slice()));
                let (machine, re_paired) = self.redeem_machine_answer_in_txn(
                    &mut txn,
                    issuer,
                    answer,
                    request,
                    possession,
                )?;
                (Some(machine), re_paired)
            }
            _ => (None, false),
        };
        PAIRING_PENDING.delete(&self.store, &mut txn, &row_key)?;
        txn.commit()?;
        // A machine admitted here changed the roster: seal the portable
        // credentials again, as `enroll_machine` does. The redemption stands
        // whatever happens, since the link is spent and its slip exists only
        // in this reply; the sync lane's upkeep re-seal retries a failure. A
        // credential-only re-pairing changed no roster and seals nothing.
        #[cfg(feature = "sync")]
        if machine.is_some()
            && !re_paired
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
            re_paired,
        })
    }
    /// Enrols the machine a link adds under the approval it kept (C2): this
    /// install carries the owner's act, its target the redeeming machine and
    /// its `seen` that machine's revision here, zero for a new one. An
    /// install the vault never profiled, or whose own profile is still
    /// unanswered, takes the explicit bootstrap arm instead (C4, a fresh
    /// self-host first install): the host root signs the owner's answer with
    /// no act, as it always has, and the fold judges the root's custody, so a
    /// hosted root never answers for the owner there. Any other install that
    /// cannot carry refuses, and nothing is written. A machine the roster
    /// already holds, pairing again under its own identity and class with
    /// its machine key's `possession` proof over this redemption's binding
    /// transcript, takes its credential alone first (FIX 8636). The flag is
    /// `true` for that re-pairing, which changed no roster.
    fn redeem_machine_answer_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: &HostSlipIssuer,
        answer: PendingMachine,
        request: &MachineEnrolmentRequest,
        possession: Option<(&[u8; 64], &[u8])>,
    ) -> Result<(FoldedMachine, bool)> {
        let role = MachineRole::Owned(answer.ownership);
        let fold = self.authority_view_readonly_in_txn(txn)?;
        // A credential-only re-pairing writes no revision, so it needs no
        // carrier, and no arm below enrols the machine again.
        if let Some((proof, transcript)) = possession
            && let Some(standing) = re_paired_standing(&fold, request, role, proof, transcript)?
        {
            return Ok((standing, true));
        }
        // The never-profiled path first: an unanswered serving install also
        // carries, and it keeps pairing exactly as it did before its profile.
        if unprofiled_install(&fold, crate::identity::read_machine_id_in_txn(self, txn)?) {
            return self
                .enroll_bootstrap_in_txn(txn, issuer, answer.owner, request, role)
                .map(|machine| (machine, false));
        }
        if self.carrier_in_txn(txn, &fold).is_ok() {
            let act = AnswerAct {
                owner: answer.owner,
                by: answer.by,
                surface: answer.surface,
                kind: answer.kind,
                seen: None,
            };
            return self
                .enroll_machine_in_txn(txn, act, request, role)
                .map(|machine| (machine, false));
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
