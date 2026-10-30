//! `vault.esign.links.issue` for a narrowed credential (FIX 6403). The mint
//! stays the vault owner's: a world-, facet- or record-scoped credential
//! mints a draft's signing links only when it is the owner's own (self-held,
//! undelegated, a person's, live) and its read lane reaches the draft
//! ([`super::super::lane_scope`]). Its proof authorizes this one mint and
//! no other act; no owner proof is made from it.
use super::super::EsignCapability;
use super::super::capability::mint_draft_capabilities_in;
use super::super::lane_scope;
use super::super::ledger::state_in;
use super::super::model::EsignState;
use super::{EsignIssuedLink, EsignLinksView};
use crate::authority::VerifiedSlip;
use crate::claim::ScopedRead;
use crate::edge::EdgeActorClass;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::{EntityId, Vault};
use std::collections::BTreeMap;

const VERB: &str = "vault.esign.links.issue";

/// The proof a narrowed credential mints a draft's links by (CALLS `FIX 6403
/// scoped link owner`, proposed): the credential the call presented, held by
/// the bound actor itself, a person, with no parent, organization, support
/// delegation or transfer, live, and the actor a live vault owner with the
/// owner's authority. A narrowing of the owner's own records keeps it.
struct ScopedLinkOwner<'a> {
    proof: &'a VerifiedSlip,
    actor: EntityId,
    class: EdgeActorClass,
}

impl ScopedLinkOwner<'_> {
    /// Proves the owner's own credential in `txn`, as the mint's writer
    /// proves the owner's proof there.
    /// # Errors
    /// A credential that is not the live vault owner's own, as the row
    /// refuses any caller that is not the owner, or the store's failure.
    fn stands_in(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> MemoryResult<()> {
        let claims = self.proof.claims();
        if self.class != EdgeActorClass::Human
            || claims.actor_class.as_deref() != Some("human")
            || claims.holder_ref != self.actor.to_hex()
            || claims.parent_id.is_some()
            || claims.org_ref.is_some()
            || claims.delegation.is_some()
            || self.proof.is_transferred()
            || !vault.capability_slip_is_live_in_txn(txn, self.proof)?
            || !crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &self.actor)?
        {
            return Err(not_owner());
        }
        crate::memory::verify_deletion_authority_in_txn(vault, txn, self.actor, self.class)
            .map_err(|_| not_owner())
    }
}

/// The refusal of a caller that is not the vault owner.
fn not_owner() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!("{VERB} is the vault owner's"),
        &["Call it as the vault's owner."],
    )
}

impl Memory<'_> {
    /// [`Self::esign_links_issue`] for a narrowed credential: the owner's own
    /// credential and the draft judged by `lane` before the mint and again
    /// in its writer, the draft's own content writer, which also reads the
    /// view.
    /// # Errors
    /// A credential that is not the vault owner's own, a draft the lane
    /// does not reach, a document already sent, or no such document.
    pub(super) fn esign_links_issue_in_lane(
        &self,
        lane: &ScopedRead<'_>,
        document: EntityId,
        rotate: bool,
    ) -> MemoryResult<EsignLinksView> {
        let owner = ScopedLinkOwner {
            proof: self.presented_credential().ok_or_else(not_owner)?,
            actor: self.actor(),
            class: self.actor_class(),
        };
        let vault = self.vault();
        {
            let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
            owner.stands_in(vault, &txn)?;
            lane_scope::reaches_in(lane, &txn, document)?;
        }
        let (minted, state) = lane_scope::write_artifact(lane, self, document, |txn| {
            owner.stands_in(vault, txn)?;
            let minted = mint_draft_capabilities_in(vault, txn, document, rotate)?;
            Ok((minted, state_in(vault, txn, document)?))
        })?;
        Ok(links_view(document, state, minted))
    }
}

/// The view of the links `minted` on `document`, its recipients as `state`
/// folds them: each new link shown this once, in the draft's order.
pub(super) fn links_view(
    document: EntityId,
    state: EsignState,
    minted: Vec<(String, EsignCapability)>,
) -> EsignLinksView {
    let mut minted: BTreeMap<String, EsignCapability> = minted.into_iter().collect();
    let mut issued = Vec::new();
    let mut unchanged = Vec::new();
    for recipient in state.document.recipients {
        match minted.remove(&recipient.id) {
            Some(capability) => issued.push(EsignIssuedLink {
                capability: capability.expose_for_delivery().to_owned(),
                recipient: recipient.id,
                email: recipient.email,
            }),
            None => unchanged.push(recipient.id),
        }
    }
    EsignLinksView {
        document_ref: document.to_hex(),
        issued,
        unchanged,
    }
}
