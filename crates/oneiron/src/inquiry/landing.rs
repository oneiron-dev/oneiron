//! The copy landing (INQUIRE-1 PR 6; Engine ruling INQUIRE-SHAPE Q9 = A;
//! federation.md #inquiry-copy). When the company setting `inquiry_keep` is
//! `copy`, each statement of an `answered` inquiry lands in the company vault
//! as one CLAIM about the member's PERSON:
//!
//! * in the foreign WORLD derived from the member's vault and the world the
//!   member opened to this company, so no named-world export carries it on
//!   (`LocalWorldId` refuses a foreign id);
//! * attributed by a federation delivery record: the Connect pact, its
//!   consent epoch, the member's vault and the member's inquiry edge grant;
//! * with the statement's text, and its source (`member_word` or
//!   `companion_of_member`) and the inquiry's id as evidence. No record id of
//!   the member's vault crosses or lands;
//! * through the ordinary CLAIM put, so the company indexes and embeds it
//!   itself.
//!
//! The landing is the engine's own writer: no verb reaches it. It lands only
//! what a send brought back over a route the company Owner opened. Where the
//! copy lands is read before the send, from the company's own Active Connect
//! pact with the member's vault; a `copy` send with no such pact, or whose
//! pact does not open exactly one world to this company, gives `unavailable`
//! without a send.

use rmpv::Value;

use super::INQUIRY_STATEMENT_PREDICATE;
use super::record::InquiryStatement;
use super::route::InquiryRoute;
use crate::authority::{AuthorityFold, AuthorityVaultId, FederationPactStatus};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::entity_id::{EntityId, ForeignWorldId, derived_domains};
use crate::error::Result;
use crate::federation::ScopeAxis;
use crate::federation::delivery_record::{DeliveryOrigin, record_engine_delivery_in_txn};
use crate::{TimeRange, Vault};

/// The confidence a copied statement lands with: the federated import scale
/// (`sync::selector::peer_confidence`, 0.5) over the member vault's whole
/// word. The statement's source, not this number, says whether it is the
/// member's word or the companion's.
const COPY_CONFIDENCE: f32 = 0.5;

/// The evidence key naming the inquiry a copied statement answered.
const EVIDENCE_INQUIRY: &str = "inquiry";
/// The evidence key naming who made a copied statement.
const EVIDENCE_STATEMENT_SOURCE: &str = "statement_source";

/// Where one member's copied answers land, and the delivery that attributes
/// them.
#[derive(Clone, Copy)]
pub(super) struct InquiryLanding {
    pact: [u8; 32],
    consent_epoch: u64,
    origin: DeliveryOrigin,
    world: ForeignWorldId,
}

/// The landing of copies from the member vault `route` reaches, as `fold`
/// holds this vault's Connect pacts now: its one Active pact with that vault,
/// whose inbound half opens exactly one world here. `None` when there is no
/// such pact or world, or the route's edge grant is not an id.
///
/// # Errors
///
/// A derive error for the foreign world id.
pub(super) fn inquiry_landing(
    fold: &AuthorityFold,
    route: &InquiryRoute,
) -> Result<Option<InquiryLanding>> {
    let (Some(local), Ok(edge_grant)) = (fold.vault_id, EntityId::from_hex(&route.edge_grant))
    else {
        return Ok(None);
    };
    let mut live = fold.federation_pacts.iter().filter(|(_, state)| {
        state.peer_vault_id == route.member_vault_id && state.status == FederationPactStatus::Active
    });
    let (Some((pact, state)), None) = (live.next(), live.next()) else {
        return Ok(None);
    };
    // The member's half of the ceiling: what it may share with this vault.
    let inbound = if local <= state.peer_vault_id {
        &state.pact_scope.hi_to_lo
    } else {
        &state.pact_scope.lo_to_hi
    };
    let ScopeAxis::Some(worlds) = &inbound.worlds else {
        return Ok(None);
    };
    let mut worlds = worlds.iter();
    let (Some(opened), None) = (worlds.next(), worlds.next()) else {
        return Ok(None);
    };
    let Some(world) = crate::federation::pact_foreign_world(fold, pact, opened.0)? else {
        return Ok(None);
    };
    Ok(Some(InquiryLanding {
        pact: *pact,
        consent_epoch: state.pact_epoch,
        origin: DeliveryOrigin {
            grant_ref: edge_grant,
            source_vault: state.peer_vault_id,
        },
        world,
    }))
}

/// The CLAIM statement `ordinal` of inquiry `inquiry` about the PERSON
/// `member` lands on, when the member vault `source_vault` answered it: the
/// same one on every send of that inquiry to that member. The caller chooses
/// a re-send's id, so the member and its vault are part of the id: an id
/// re-used for another member lands on that member's own CLAIMs and never
/// replaces a copy of another member's answer.
fn inquiry_copy_claim_id(
    inquiry: EntityId,
    member: EntityId,
    source_vault: &AuthorityVaultId,
    ordinal: usize,
) -> Result<EntityId> {
    let ordinal = u64::try_from(ordinal).unwrap_or(u64::MAX);
    EntityId::derive(
        derived_domains::INQUIRY_COPY_CLAIM,
        &[
            inquiry.as_bytes(),
            member.as_bytes(),
            source_vault,
            &ordinal.to_le_bytes(),
        ],
    )
}

impl Vault {
    /// Lands each of `statements`, the answer to inquiry `inquiry` about the
    /// PERSON `member`, as one CLAIM in `landing`'s foreign world, and
    /// records its delivery, in `txn`. Each statement holds from `now` (or
    /// from `valid_until`, when that is earlier) to `valid_until`. An inquiry
    /// re-sent to the same member lands each statement on the CLAIM it landed
    /// on before.
    ///
    /// # Errors
    ///
    /// `member` is not an entity of this vault; a statement breaks a CLAIM
    /// field rule; storage errors.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn land_inquiry_copy_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        landing: &InquiryLanding,
        inquiry: EntityId,
        member: EntityId,
        statements: &[InquiryStatement],
        valid_until: u64,
        now: u64,
    ) -> Result<()> {
        let facet = self.default_facet_in_txn(txn)?;
        for (ordinal, statement) in statements.iter().enumerate() {
            let id = inquiry_copy_claim_id(inquiry, member, &landing.origin.source_vault, ordinal)?;
            let mut body = ClaimBody::new(
                INQUIRY_STATEMENT_PREDICATE,
                ClaimSubject::Entity(member),
                Value::from(statement.text()),
                COPY_CONFIDENCE,
                ClaimApprovalStatus::Approved,
                ClaimLifecycleStatus::Active,
            )?;
            body.source = Some(ClaimSource::Imported);
            body.world = Some(landing.world.entity_id());
            body.scope_facet = facet;
            body.valid_from = Some(now.min(valid_until));
            body.valid_to = Some(valid_until);
            body.evidence = Some(Value::Map(vec![
                (Value::from(EVIDENCE_INQUIRY), Value::from(inquiry.to_hex())),
                (
                    Value::from(EVIDENCE_STATEMENT_SOURCE),
                    Value::from(statement.source().as_str()),
                ),
            ]));
            self.put_claim_in_txn(
                txn,
                &id,
                &body,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
            )?;
            record_engine_delivery_in_txn(
                self,
                txn,
                &landing.pact,
                landing.consent_epoch,
                id,
                landing.origin,
                landing.world,
            )?;
        }
        Ok(())
    }
}
