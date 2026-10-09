//! What a campaign send reads about its recipient: the compliance rules the
//! campaign gate binds a send to an address to, and which of them it fails.
use super::Decision;
use crate::campaign::compliance::{
    ComplianceBinding, PREDICATE_CRM_COMPLIANCE_MESSAGE_ELEMENTS, campaign_compliance_binding,
    load_active_compliance_pack,
};
use crate::edge::EdgeKind;
use crate::gate::{
    ExternalEffectGateInput, ExternalEffectPolicyRisk, GateActor, GateProvenanceHandles,
};
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::{EntityId, Result, Vault};
use std::collections::BTreeSet;

/// Which compliance rules the campaign gate binds a send to an address on one
/// channel, from one sending identity or none, and which of them the send
/// fails: the PERSON the address resolves to, whether a membership's
/// `claim_of` edge puts it in a campaign, the jurisdiction, dispatch evidence
/// and message elements the gate hydrates (`campaign_compliance_gate`).
///
/// The rules are compared unfolded: the gate's verdict keeps only the first
/// block, and a row gone stale blocks every send alike, so a recipient whose
/// evidence a restore brings back would still read as blocked there.
pub(super) struct CampaignCompliance;

impl Decision for CampaignCompliance {
    /// An address, a channel, and the identity a send goes out from.
    type Subject = (String, String, Option<EntityId>);
    /// `None` where compliance does not govern the send.
    type Answer = Option<ComplianceBinding>;

    fn subjects(vaults: [&Vault; 2]) -> Result<BTreeSet<Self::Subject>> {
        // Every address the gate can resolve is a PERSON's party key. A
        // channel selects rows: each one a row names, and one none names,
        // where only the rows for every channel apply. An identity carries
        // message elements through a `claim_of` edge; one that carries none
        // reads as no identity.
        let mut addresses = BTreeSet::new();
        let mut channels = BTreeSet::from([String::new()]);
        let mut identities = BTreeSet::from([None]);
        for vault in vaults {
            // A pack that does not load fails every campaign send closed alike.
            if let Ok(pack) = load_active_compliance_pack(vault) {
                channels.extend(pack.rows.into_iter().map(|row| row.channel));
            }
            let txn = vault.store.env.read_txn()?;
            let store = &vault.store;
            addresses.extend(crate::comm::comm_party_keys_in_txn(store, &txn)?);
            vault.for_each_claim_with_predicate_in_txn(
                &txn,
                PREDICATE_CRM_COMPLIANCE_MESSAGE_ELEMENTS,
                |elements, _| {
                    for edge in store.port_edges(
                        &txn,
                        &elements,
                        EdgeDirection::Out,
                        Some(EdgeKind::ClaimOf),
                        None,
                    )? {
                        identities.insert(Some(edge?.target));
                    }
                    Ok(())
                },
            )?;
        }
        let mut subjects = BTreeSet::new();
        for address in &addresses {
            for channel in &channels {
                for identity in &identities {
                    subjects.insert((address.clone(), channel.clone(), *identity));
                }
            }
        }
        Ok(subjects)
    }

    fn answers(
        vault: &Vault,
        subjects: &BTreeSet<Self::Subject>,
    ) -> Result<Vec<Option<Self::Answer>>> {
        let txn = vault.store.env.read_txn()?;
        Ok(subjects
            .iter()
            .map(|(address, channel, identity)| {
                campaign_compliance_binding(&vault.store, &txn, &send(address, channel, *identity))
                    .ok()
            })
            .collect())
    }

    /// A send the gate governs now that it would not; a row that binds it now
    /// and would not, so its requirement and its staleness no longer apply;
    /// a consent class it lacks now and would not; or a row it fails now and
    /// would pass.
    fn loosens(live: &Self::Answer, restored: &Self::Answer) -> bool {
        match (live, restored) {
            (None, _) => false,
            (Some(_), None) => true,
            (Some(live), Some(restored)) => {
                !live.rows.is_subset(&restored.rows)
                    || (live.uncovered && !restored.uncovered)
                    || !live.failed.is_subset(&restored.failed)
            }
        }
    }
}

/// A send to `address` on `channel` from `identity`, from no one in
/// particular: the compliance leg reads nothing else of it.
fn send(address: &str, channel: &str, identity: Option<EntityId>) -> ExternalEffectGateInput {
    ExternalEffectGateInput {
        actor: GateActor {
            actor_class: String::new(),
            actor_ref: None,
            delegation_grant_ref: None,
        },
        provenance: GateProvenanceHandles::default(),
        verb: "send".to_owned(),
        channel: channel.to_owned(),
        channel_identity_ref: identity,
        counterparty: Some(address.to_owned()),
        brief_ref: None,
        send_ref: None,
        standing_grant_ref: None,
        scoped_mcp_call: None,
        counterparty_first_touch: None,
        counterparty_opted_out: false,
        counterparty_opt_out_receipt_reason: None,
        has_opted_in: false,
        has_permission: false,
        policy_risk: ExternalEffectPolicyRisk::default(),
    }
}
