//! The owner-project signer (decision 3): every owner door signs the project
//! state it writes through one capability, not a caller's closure. The host
//! signs for the owner, who sits on every board through the root; the door
//! revalidates the owner in its own write transaction, lands the state as
//! history, and commits only a state the fold installs as the head. A signed
//! owner state is held history, so a replayed unsigned row cannot widen it.
use super::fold::ProjectDisposition;
use super::read::stored;
use super::*;
use crate::authority::{CapabilitySlip, HostSlipIssuer};
use crate::consent::AuthenticatedOwner;

/// The host's slip issuer and the host-held slip an owner door signs with.
/// The slip's standing (its mint, revocation, expiry and project.write scope)
/// is judged by the authority fold at each door, as for any project proof.
pub struct OwnerProjectSigner<'a> {
    issuer: &'a HostSlipIssuer,
    slip: CapabilitySlip,
    wire: String,
}

impl<'a> OwnerProjectSigner<'a> {
    /// `slip` must be held by the host: only the host signs for the owner.
    pub fn new(issuer: &'a HostSlipIssuer, slip: CapabilitySlip) -> Result<Self> {
        if slip.claims.holder_ref != "host" {
            return Err(Error::InvalidConfig(
                "an owner project signer needs a host-held slip".into(),
            ));
        }
        let wire = slip.to_token()?;
        Ok(Self { issuer, slip, wire })
    }

    pub(super) fn wire(&self) -> &str {
        &self.wire
    }

    /// The slip's binding proof over `challenge`.
    pub(super) fn sign(&self, challenge: &[u8]) -> Result<Vec<u8>> {
        self.issuer.binding_proof(&self.slip, challenge)
    }
}

/// The time an owner door signs at: the authority clock, as a live proof is
/// judged.
pub(super) fn owner_signed_at(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<u64> {
    crate::authority::authority_clock_reading_in_txn(
        &vault.store,
        txn,
        vault.store.clock.now_recorded_at(),
    )
}

impl Vault {
    /// Signs `next` for the owner at `signed_at`: the owner is revalidated in
    /// this transaction, and the host signs `next`'s fields as a v3 state over
    /// `over`, or, when no signed state precedes it, over `next`'s own
    /// unsigned boundary. The door then lands `next` as history and commits
    /// only once [`Self::require_owner_head_in_txn`] finds it installed.
    #[expect(
        clippy::too_many_arguments,
        reason = "one owner act's transaction, owner, signer, state, anchor and time"
    )]
    pub(super) fn sign_owner_project_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        owner: &AuthenticatedOwner,
        signer: &OwnerProjectSigner<'_>,
        id: EntityId,
        next: &mut ProjectRecord,
        over: Option<Vec<ProjectAnchorLink>>,
        signed_at: u64,
    ) -> Result<()> {
        owner.revalidate_as_vault_owner_in_txn(self, txn)?;
        let anchor = over.unwrap_or_else(|| {
            vec![ProjectAnchorLink {
                authority: next.authority_at(ProjectProofVersion::V2),
                proof: None,
            }]
        });
        let challenge = next.authority_at(ProjectProofVersion::V3).write_challenge(
            id,
            ProjectProofVersion::V3,
            signed_at,
            &anchor,
        )?;
        next.write_proof = Some(ProjectWriteProof {
            slip_wire: signer.wire().to_owned(),
            holder_signature: signer.sign(&challenge)?,
            signed_at,
            anchor,
            version: ProjectProofVersion::V3,
        });
        Ok(())
    }

    /// The owner's act commits only the state it signed as the head the fold
    /// installs: a signature or slip the fold refuses fails here, not on a
    /// later read.
    pub(super) fn require_owner_head_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
        next: &ProjectRecord,
    ) -> Result<ProjectRevisionHash> {
        let head = revision::revisions_of_row(id, next)?
            .last()
            .map(|(hash, _)| *hash)
            .ok_or_else(invalid)?;
        let installed = ProjectReader::new(&self.store, txn, self.privacy_posture())?
            .ok_or_else(invalid)?
            .frontier(id)?
            .is_some_and(|frontier| {
                frontier.disposition == ProjectDisposition::Settled
                    && frontier.witness.is_some_and(|witness| witness.head == head)
            });
        if !installed {
            return Err(RecordError::ProjectAuthorityUnresolved {
                project: id,
                reason: "the owner's project state does not install",
            }
            .into());
        }
        Ok(head)
    }

    /// The owner's first signature over a project no signed state governs:
    /// the root the vault seeds at its first open, before any owner signer
    /// exists, or a row an owner door wrote unsigned. The host signs the
    /// state the fold serves as v3 over its unsigned boundary.
    pub fn sign_owner_project(
        &self,
        owner: &AuthenticatedOwner,
        signer: &OwnerProjectSigner<'_>,
        id: EntityId,
    ) -> Result<ProjectRevisionHash> {
        let kind = self.project_type_byte()?;
        self.with_write_txn(|txn| {
            let frontier = ProjectReader::new(&self.store, txn, self.privacy_posture())?
                .ok_or_else(invalid)?
                .frontier(id)?
                .ok_or(Error::EntityNotFound)?;
            if frontier.disposition != ProjectDisposition::Unsigned {
                return Err(RecordError::ProjectAuthorityUnresolved {
                    project: id,
                    reason: "only an unsigned project takes the owner's first signature",
                }
                .into());
            }
            let mut next = stored(&self.store, txn, id, kind)?.ok_or(Error::EntityNotFound)?;
            let at = owner_signed_at(self, txn)?;
            self.sign_owner_project_in_txn(txn, owner, signer, id, &mut next, None, at)?;
            self.batch_in()
                .put_engine_history(
                    &id,
                    kind,
                    TimeRange { start: at, end: at },
                    at,
                    &encode(&next)?,
                )
                .apply(txn)?;
            self.require_owner_head_in_txn(txn, id, &next)
        })
    }
}
