//! The mesh binding a machine link's redemption makes for the machine it
//! enrols (FIX 3374, L02 04:5x). The joining machine sends its endpoint key
//! and both binding proofs with its enrolment request; in the redemption's
//! own transaction the host checks that they name exactly the MACHINE and
//! machine key the redemption enrols and that both proofs verify, before it
//! mints anything. Then, in one savepoint of that transaction, it mints a
//! pairing slip held by that MACHINE under its machine key, binds the
//! endpoint on it and grants the one ALPN the enrolment asks now: all of
//! them land with the pairing, or none do. A binding refused at any step
//! leaves the pairing as it would stand without one, with the reason.
//!
//! The pairing slip is the binding's ceiling: the owner's later grants
//! (`vault.mesh.set_alpn_grant`) must narrow it. It carries the mesh verb of
//! every protocol in the enrolment's [`MeshEnrolmentAsk::ceiling`], which
//! the server fills from the protocols it serves (MESH-PAIRING-CEILING = A,
//! Engine 25 Nov 01:1x): the control stays the grant, per protocol,
//! owner-only and host-signed, and no protocol is granted by the ceiling
//! alone.
//!
//! A removed MACHINE's binding admits nothing (`mesh_pairing_live`), and
//! [`Vault::revoke_removed_machine_mesh`] revokes its pairing and grants in
//! the log.

use super::super::setting_keys::MESH_GRANT_MAX_TTL;
use super::super::slip_vault::{random_slip_id, require_host};
use super::super::{AuthorityOp, MachineEnrolmentRequest, SlipClaims, strong_ed25519_key};
use super::*;
use crate::consent::AuthenticatedOwner;

/// What a machine link's redemption binds on the mesh for the machine it
/// enrols: its mesh identity, the one protocol it is granted now, and the
/// protocols the owner may grant its binding later (the binding pairing's
/// ceiling). `granted` is under the ceiling whether or not the ceiling
/// names it.
#[derive(Debug, Clone, Copy)]
pub struct MeshEnrolmentAsk<'a> {
    pub identity: &'a MeshBindingIdentity,
    pub granted: &'a [u8],
    pub ceiling: &'a [&'a [u8]],
}

impl MeshEnrolmentAsk<'_> {
    /// The scope the binding's pairing slip carries: the mesh verbs of
    /// `granted` and of every valid ALPN of the ceiling.
    fn ceiling_scope(&self) -> Scope {
        mesh_ceiling_scope(self.ceiling.iter().copied().chain([self.granted]))
    }
}

/// The scope a binding's pairing slip carries: the mesh verb of every valid
/// ALPN of `alpns`.
fn mesh_ceiling_scope<'a>(alpns: impl IntoIterator<Item = &'a [u8]>) -> Scope {
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(
        alpns
            .into_iter()
            .filter(|alpn| valid_alpn(alpn))
            .map(mesh_verb)
            .collect(),
    );
    scope
}

/// Why a redemption's mesh binding was not made. The pairing stands, and no
/// part of the binding was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshBindRefusal {
    /// The identity names another MACHINE or key than the one the redemption
    /// enrols.
    NotTheEnrolledMachine,
    /// A proof does not verify under its key.
    BadProof,
    /// The binding or its grant was refused where it would land: an endpoint
    /// another MACHINE holds, a deleted holder, a binding already revoked.
    BindRefused,
}

/// What a redemption's mesh binding did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeshEnrolment {
    /// Bound and granted the ALPN with the pairing, on a fresh pairing slip.
    Bound {
        machine: EntityId,
        endpoint_key: [u8; 32],
        pairing_slip_id: [u8; 32],
    },
    /// The endpoint's binding stood from an earlier pairing, and the ALPN was
    /// granted on it again. `re_paired` is as in [`Self::AlreadyGranted`].
    Regranted {
        machine: EntityId,
        endpoint_key: [u8; 32],
        re_paired: Option<[u8; 32]>,
    },
    /// The endpoint already held a live grant on the ALPN, and it stands. Its
    /// binding moved to a pairing under the ask's ceiling if its own did not
    /// cover it: `re_paired` names that new pairing slip, on which the
    /// owner binds the machine again in each other replica that bound it
    /// (`vault.mesh.bind_machine`); `None` when the binding did not move.
    AlreadyGranted {
        machine: EntityId,
        endpoint_key: [u8; 32],
        re_paired: Option<[u8; 32]>,
    },
    Refused(MeshBindRefusal),
}

/// What an enrolment's binding step made: a fresh binding on its new
/// pairing slip, or a binding that stood from an earlier pairing and the
/// pairing slip it moved to, if it moved.
enum EnrolledBinding {
    Fresh([u8; 32]),
    Standing { re_paired: Option<[u8; 32]> },
}

/// Whether a head `machine` stands under with `pin` removed it: removal is
/// terminal. Another anchor's chain removes nothing here (FIX
/// FOREIGN-ANCHOR-CHAIN-COUNTS-IN-EVERY-CHAIN-PREDICATES).
pub(super) fn machine_removed(
    machine: &crate::authority::FoldedMachine,
    pin: Option<&crate::authority::PinnedRoot>,
) -> bool {
    machine
        .standing_heads(pin)
        .into_iter()
        .any(|chain| chain.removed)
}

impl Vault {
    /// Binds `ask.identity`'s endpoint for the machine `request` enrols and
    /// grants it `ask.granted`, in the caller's redemption transaction.
    pub(in crate::authority) fn bind_enrolled_mesh_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: &HostSlipIssuer,
        request: &MachineEnrolmentRequest,
        ask: MeshEnrolmentAsk<'_>,
    ) -> MeshEnrolment {
        let (identity, alpn) = (ask.identity, ask.granted);
        let (machine, endpoint_key) = (request.machine, identity.endpoint_key);
        if identity.machine != machine || identity.device_key != request.machine_key {
            return MeshEnrolment::Refused(MeshBindRefusal::NotTheEnrolledMachine);
        }
        let transcript = binding_transcript(machine, endpoint_key);
        let proven = [
            (identity.device_key, identity.device_proof.as_slice()),
            (endpoint_key, identity.transport_proof.as_slice()),
        ]
        .into_iter()
        .all(|(key, proof)| {
            strong_ed25519_key(&key).is_ok_and(|key| {
                Signature::from_slice(proof)
                    .is_ok_and(|proof| key.verify_strict(&transcript, &proof).is_ok())
            })
        });
        if !proven {
            return MeshEnrolment::Refused(MeshBindRefusal::BadProof);
        }
        if self
            .mesh_grant_permits_in_txn(txn, machine, endpoint_key, alpn)
            .unwrap_or(false)
        {
            // A re-enrolment: the binding moves to the ask's ceiling in a
            // savepoint that lands whole or not at all, and the grant stands.
            // A move that does not land refuses the binding, so no answer
            // promises a ceiling the binding lacks.
            return match self.re_pair_enrolled_in_savepoint(txn, issuer, request, ask) {
                Ok(re_paired) => MeshEnrolment::AlreadyGranted {
                    machine,
                    endpoint_key,
                    re_paired,
                },
                Err(_) => MeshEnrolment::Refused(MeshBindRefusal::BindRefused),
            };
        }
        match self.bind_enrolled_in_savepoint(txn, issuer, request, ask) {
            Ok(EnrolledBinding::Fresh(pairing_slip_id)) => MeshEnrolment::Bound {
                machine,
                endpoint_key,
                pairing_slip_id,
            },
            Ok(EnrolledBinding::Standing { re_paired }) => MeshEnrolment::Regranted {
                machine,
                endpoint_key,
                re_paired,
            },
            Err(_) => MeshEnrolment::Refused(MeshBindRefusal::BindRefused),
        }
    }

    /// The pairing slip, the binding and the grant, in one savepoint of `txn`
    /// that lands only whole, and the new pairing slip's id. A binding that
    /// stands from an earlier pairing moves to the ask's ceiling if it must
    /// and takes the grant, as the owner's grant door gives it
    /// ([`EnrolledBinding::Standing`]). The slip runs no longer than a grant
    /// may.
    fn bind_enrolled_in_savepoint(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: &HostSlipIssuer,
        request: &MachineEnrolmentRequest,
        ask: MeshEnrolmentAsk<'_>,
    ) -> Result<EnrolledBinding> {
        let (identity, alpn) = (ask.identity, ask.granted);
        let (machine, endpoint_key) = (request.machine, identity.endpoint_key);
        let mut savepoint = self.store.env.nested_write_txn(txn)?;
        let grant = MeshAlpnGrant {
            machine,
            endpoint_key,
            alpn: alpn.to_vec(),
            allow: true,
        };
        if MESH_AUTHORITY.contains(&self.store, &savepoint, &HexId(machine))? {
            let re_paired = self.re_pair_enrolled_in_txn(&mut savepoint, issuer, request, ask)?;
            self.set_mesh_alpn_grant_in_txn(&mut savepoint, issuer, grant)?;
            savepoint.commit()?;
            return Ok(EnrolledBinding::Standing { re_paired });
        }
        let pairing_slip_id =
            self.mint_enrolment_pairing_in_txn(&mut savepoint, issuer, request, ask, 0)?;
        let count = self.bind_mesh_machine_in_txn(
            &mut savepoint,
            issuer,
            MeshMachineBinding {
                machine,
                address: MeshMachineAddress {
                    endpoint_key,
                    direct_addrs: Vec::new(),
                    relay_url: None,
                },
                device_key: request.machine_key,
                pairing_slip_id,
                device_proof: identity.device_proof.clone(),
                transport_proof: identity.transport_proof.clone(),
            },
        )?;
        self.set_mesh_alpn_grant_in_txn(&mut savepoint, issuer, grant)?;
        savepoint.commit()?;
        count.finish(self);
        Ok(EnrolledBinding::Fresh(pairing_slip_id))
    }

    /// The binding's pairing slip for an enrolment: held by the MACHINE under
    /// its machine key, carrying the mesh verb of every protocol of
    /// `ask`'s ceiling, and running as long as the owner's mesh grant ceiling
    /// (`mesh.grant.max_ttl_secs`, one year by default), so a grant can, and
    /// never ending before `at_least_until`.
    fn mint_enrolment_pairing_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: &HostSlipIssuer,
        request: &MachineEnrolmentRequest,
        ask: MeshEnrolmentAsk<'_>,
        at_least_until: u64,
    ) -> Result<[u8; 32]> {
        self.mint_mesh_pairing_in_txn(
            txn,
            issuer,
            request.vault_id,
            (request.machine, request.machine_key),
            ask.ceiling_scope(),
            at_least_until,
        )
    }

    /// A pairing slip of vault `vault_id` held by `holder`'s MACHINE under
    /// its machine key, with `scope`, running as long as the owner's mesh
    /// grant ceiling (`mesh.grant.max_ttl_secs`, one year by default) and
    /// never ending before `at_least_until`. Answers its slip id.
    fn mint_mesh_pairing_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: &HostSlipIssuer,
        vault_id: [u8; 32],
        holder: (EntityId, [u8; 32]),
        scope: Scope,
        at_least_until: u64,
    ) -> Result<[u8; 32]> {
        let (machine, machine_key) = holder;
        let now = self.instant_in_txn(txn)?.secs();
        let ceiling = MESH_GRANT_MAX_TTL
            .read_in_txn(self, txn, &[], None)?
            .value
            .secs();
        let expires_at = now.saturating_add(ceiling).max(at_least_until);
        let pairing = self.mint_slip_in_txn(
            txn,
            issuer,
            SlipClaims {
                slip_id: random_slip_id(),
                vault_id,
                parent_id: None,
                holder_ref: machine.to_hex(),
                binding_key: machine_key,
                scope,
                issued_at: now,
                expires_at,
                ttl_secs: expires_at.saturating_sub(now),
                single_use: false,
                records: Default::default(),
                channels: Default::default(),
                actor_class: None,
                org_ref: None,
                grant_ref: None,
                invitation_ref: None,
                share_ref: None,
                delegation: None,
                comm: None,
                trusted_contact: None,
                seat_claim: None,
            },
        )?;
        Ok(pairing.claims.slip_id)
    }

    /// Why [`Self::pair_own_mesh_machine_as_owner`] refuses an install whose own
    /// profile no owner answered, and the owner's step that answers it.
    pub const PAIR_SELF_UNANSWERED: &str = "this install's own MACHINE has no answered \
        profile, so no replica could prove it: the owner first answers it on this install \
        (POST /v1/owner/machines/answer with {\"machine\": \"<this MACHINE, 32 hex>\", \
        \"answer\": \"yours\"}), then pairs it";

    /// Pairs this install's own MACHINE as a machine of its vault
    /// (PLAN-HOME-ISSUER-MESH-PROOF, R6 1.5). It mints a pairing slip held by
    /// that MACHINE under its machine key, carrying the mesh verb of every
    /// protocol of `ceiling`, as a link's redemption mints one for the machine
    /// it enrols.
    ///
    /// The home never redeems a link of its own, so nothing else pairs it.
    /// With no pairing, no other replica can bind it, and no node proves a home
    /// that issues it jobs ([`Self::mesh_peer_machine`]).
    ///
    /// Answers the body with which the owner binds this MACHINE on each other
    /// replica (`vault.mesh.bind_machine` there), both proofs included and
    /// with no address. It binds and grants nothing here; the grants stay the
    /// owner's own acts on each replica. Each call mints a new pairing. The
    /// owner's proof is revalidated in the write.
    ///
    /// # Errors
    ///
    /// `invalid_authority` for an install with no machine identity yet, a
    /// vault no root roots, or an issuer that is not this vault's host. Also
    /// an owner proof that no longer stands, and store errors.
    pub fn pair_own_mesh_machine_as_owner(
        &self,
        issuer: &HostSlipIssuer,
        owner: &AuthenticatedOwner,
        ceiling: &[&[u8]],
    ) -> Result<MeshMachineBinding> {
        let identity = self.mesh_binding_identity_as_owner(owner)?;
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        // A replica proves a MACHINE only by a profile its owner answered
        // (`proving_profile`); a serving start enrols this install as
        // `unanswered`, so a pairing minted before the answer would bind and
        // grant on every replica and still prove nothing there.
        if self
            .authority_view_readonly_in_txn(&txn)?
            .machine_proof_key(identity.machine)
            != Some(identity.device_key)
        {
            return Err(crate::error::Error::Record(
                crate::error::RecordError::AuthorityRefused(Self::PAIR_SELF_UNANSWERED),
            ));
        }
        let fold = self.authority_fold_readonly_in_txn(&txn)?;
        require_host(&fold, issuer)?;
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        let pairing_slip_id = self.mint_mesh_pairing_in_txn(
            &mut txn,
            issuer,
            vault_id,
            (identity.machine, identity.device_key),
            mesh_ceiling_scope(ceiling.iter().copied()),
            0,
        )?;
        txn.commit()?;
        Ok(MeshMachineBinding {
            machine: identity.machine,
            address: MeshMachineAddress {
                endpoint_key: identity.endpoint_key,
                direct_addrs: Vec::new(),
                relay_url: None,
            },
            device_key: identity.device_key,
            pairing_slip_id,
            device_proof: identity.device_proof,
            transport_proof: identity.transport_proof,
        })
    }

    /// [`Self::re_pair_enrolled_in_txn`] in a savepoint of `txn` that lands
    /// whole or not at all.
    fn re_pair_enrolled_in_savepoint(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: &HostSlipIssuer,
        request: &MachineEnrolmentRequest,
        ask: MeshEnrolmentAsk<'_>,
    ) -> Result<Option<[u8; 32]>> {
        let mut savepoint = self.store.env.nested_write_txn(txn)?;
        let re_paired = self.re_pair_enrolled_in_txn(&mut savepoint, issuer, request, ask)?;
        if re_paired.is_some() {
            savepoint.commit()?;
        }
        Ok(re_paired)
    }

    /// A re-enrolment of a machine this vault has bound at the same endpoint
    /// under the same machine key (the owner issued its new machine link,
    /// and its proofs verified): the binding moves to a new pairing slip
    /// under `ask`'s ceiling, so a machine bound under a narrower ceiling can
    /// take the owner's later grants, and one whose pairing expired takes a
    /// live one. Its grants stand: the new pairing ends no earlier than the
    /// old one, which no grant outlives. The old pairing is left to its
    /// expiry, never revoked here: another replica's binding of the machine
    /// may stand on it, and moves to the new one when its owner binds the
    /// machine again there (`Vault::bind_mesh_machine`). The new pairing
    /// slip's id; `None` when nothing moved: the pairing is live and covers
    /// the ceiling already, or the binding is revoked, names another
    /// endpoint, key or host, or stands on a pairing a revoke or the
    /// MACHINE's removal ended (the grant refuses those).
    fn re_pair_enrolled_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: &HostSlipIssuer,
        request: &MachineEnrolmentRequest,
        ask: MeshEnrolmentAsk<'_>,
    ) -> Result<Option<[u8; 32]>> {
        let Some((fold, mut claims)) = self.mesh_authority_signed_in_txn(txn, request.machine)?
        else {
            return Ok(None);
        };
        if claims.revoked
            || claims.endpoint_key != ask.identity.endpoint_key
            || claims.device_key != request.machine_key
            || claims.host_key != issuer.binding_key()
        {
            return Ok(None);
        }
        let Some(pair) = mesh_pairing_standing(&fold, &claims) else {
            return Ok(None);
        };
        let now = self.instant_in_txn(txn)?.secs();
        if now >= pair.issued_at
            && now < pair.expires_at
            && ask.ceiling_scope().is_narrowing_of(&pair.scope)
        {
            return Ok(None);
        }
        let at_least_until = pair.expires_at;
        let pairing_slip_id =
            self.mint_enrolment_pairing_in_txn(txn, issuer, request, ask, at_least_until)?;
        claims.pairing_slip_id = pairing_slip_id;
        self.write_mesh_authority_in_txn(txn, issuer, claims)?;
        Ok(Some(pairing_slip_id))
    }

    /// Revokes, for a MACHINE the owner removed, the pairing its mesh binding
    /// stands on and every ALPN grant it holds, and marks the binding revoked;
    /// `false` when the MACHINE is not removed or holds no binding this host
    /// signed. Removal already left the binding admitting nothing; this
    /// writes the revocations to the log.
    pub fn revoke_removed_machine_mesh(
        &self,
        issuer: &HostSlipIssuer,
        machine: EntityId,
    ) -> Result<bool> {
        let mut txn = self.store.env.write_txn()?;
        let fold = self.authority_fold_readonly_in_txn(&txn)?;
        require_host(&fold, issuer)?;
        if !fold
            .machine(machine)
            .is_some_and(|folded| machine_removed(folded, fold.pinned_root.as_ref()))
        {
            return Ok(false);
        }
        let Some(signed) = MESH_AUTHORITY.get(&self.store, &txn, &HexId(machine))? else {
            return Ok(false);
        };
        let mut claims = signed.claims;
        if claims.machine != machine || claims.host_key != issuer.binding_key() || claims.revoked {
            return Ok(false);
        }
        let held: Vec<[u8; 32]> = claims
            .alpns
            .values()
            .copied()
            .chain([claims.pairing_slip_id])
            .filter(|id| fold.slip_is_live(id))
            .collect();
        for slip_id in held {
            self.append_slip_op_in_txn(&mut txn, issuer, AuthorityOp::SlipRevoke { slip_id })?;
        }
        claims.revoked = true;
        claims.alpns.clear();
        self.write_mesh_authority_in_txn(&mut txn, issuer, claims)?;
        txn.commit()?;
        self.store.notify_credential_revocations();
        Ok(true)
    }
}
