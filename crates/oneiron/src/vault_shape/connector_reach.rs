//! The reach's connector rows (ARCH-0070 `shape:reach-line`): each key's
//! outward tools under the setting its slate gives them. It also holds the
//! reach lines that the slate stamp and every ramp offer carry. Each line is
//! the plan card's whole-set projection, recomputed with the one change in
//! place. It informs the owner's tap and never blocks it.
use super::ShapePlanReach;
use super::reach::{ReachConnector, reach_projection};
use crate::connector_key::{
    ConnectorGrantSlate, ConnectorKeyRecord, ConnectorKeyStatus, SlateDisposition,
    SlateOwnerOverride, decode_connector_key_body, governing_slate_in_txn,
};
use crate::consent_graduation::RampScope;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_CONNECTOR_KEY;
use crate::{EntityId, Vault};
use std::collections::{BTreeMap, BTreeSet};

/// A slate stamp the reach reads as landed: the slate, and the owner's
/// settings on its rows.
pub(super) type ReachStamp<'a> = (EntityId, &'a BTreeMap<String, SlateOwnerOverride>);

/// Key `id`'s outward tools under `slate`, with `overrides` on its rows as a
/// stamp sets them: the owner's setting taken, a holder's narrow reversed.
/// A tool the slate has no row for asks.
fn outward_tools(
    id: EntityId,
    key: &ConnectorKeyRecord,
    slate: &ConnectorGrantSlate,
    overrides: &BTreeMap<String, SlateOwnerOverride>,
    qualified: bool,
) -> Vec<ReachConnector> {
    slate
        .manifest()
        .iter()
        .filter(|tool| tool.sends_outward)
        .map(|tool| {
            let setting = slate
                .row(&tool.name)
                .map_or(SlateDisposition::AlwaysAsk, |row| {
                    let mut row = row.clone();
                    if let Some(owner) = overrides.get(&tool.name) {
                        row.owner_override = Some(owner.clone());
                        row.holder_narrow = None;
                    }
                    row.effective_disposition()
                });
            ReachConnector {
                key: id,
                connector: key.connector.clone(),
                actor: key.actor_entity_ref,
                except: Vec::new(),
                tool: tool.name.clone(),
                setting,
                held: !qualified && key.tool_requires_confirmation(&tool.name),
            }
        })
        .collect()
}

impl Vault {
    /// The outward tools of every connector key that can call now. With a
    /// `stamp`, the keys its slate governs are read as the stamp leaves them
    /// once they qualify: a pending key counts, and its manifest holds
    /// nothing. A key with no slate has no typed tool rows, so it joins no
    /// path.
    pub(super) fn reach_connectors_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        stamp: Option<ReachStamp<'_>>,
    ) -> Result<Vec<ReachConnector>> {
        let mut keys = Vec::new();
        for (id, body) in self.shape_bodies_in_txn(txn, ENTITY_TYPE_CONNECTOR_KEY)? {
            keys.push((id, decode_connector_key_body(&body)?));
        }
        // An actor's own key on a connector governs its calls there, over a
        // key bound to no actor, as the gate resolves the governing key.
        let own: BTreeSet<(&str, EntityId)> = keys
            .iter()
            .filter(|(_, key)| key.status != ConnectorKeyStatus::Revoked)
            .filter_map(|(_, key)| Some((key.connector.as_str(), key.actor_entity_ref?)))
            .collect();
        let unchanged = BTreeMap::new();
        let mut tools = Vec::new();
        for (id, key) in &keys {
            let Some((slate_id, slate)) = governing_slate_in_txn(&self.store, txn, key)? else {
                continue;
            };
            let stamped = stamp.filter(|(stamped, _)| *stamped == slate_id);
            let counts = match key.status {
                ConnectorKeyStatus::Active => true,
                ConnectorKeyStatus::Pending => stamped.is_some(),
                ConnectorKeyStatus::Suspended | ConnectorKeyStatus::Revoked => false,
            };
            if !counts {
                continue;
            }
            let overrides = stamped.map_or(&unchanged, |(_, overrides)| overrides);
            let qualified = stamped.is_some() && key.status == ConnectorKeyStatus::Pending;
            let mut outward = outward_tools(*id, key, &slate, overrides, qualified);
            if key.actor_entity_ref.is_none() {
                let except: Vec<EntityId> = own
                    .iter()
                    .filter(|(connector, _)| *connector == key.connector)
                    .map(|(_, actor)| *actor)
                    .collect();
                for tool in &mut outward {
                    tool.except.clone_from(&except);
                }
            }
            tools.extend(outward);
        }
        Ok(tools)
    }

    /// The reach line a slate stamp carries: what every actor can send now,
    /// and with `slate`'s keys under the owner's `overrides` once they
    /// qualify.
    ///
    /// # Errors
    ///
    /// A read failure, or an undecodable setup, key or slate row.
    pub fn slate_stamp_reach(
        &self,
        slate: EntityId,
        overrides: &BTreeMap<String, SlateOwnerOverride>,
    ) -> Result<ShapePlanReach> {
        let live = self.read_live_shape(&mut |_| Ok(true))?;
        let mut after = live.reach.clone();
        after.connectors = {
            let txn = self.store.env.read_txn()?;
            self.reach_connectors_in_txn(&txn, Some((slate, overrides)))?
        };
        Ok(ShapePlanReach::of(
            reach_projection(&live.reach),
            reach_projection(&after),
            Vec::new(),
        ))
    }

    /// The reach line a ramp offer carries: what every actor can send now,
    /// and with the standing grant accepting `scope` would mint.
    ///
    /// # Errors
    ///
    /// A read failure, an undecodable setup row, or a scope whose grant
    /// cannot be built.
    pub fn ramp_offer_reach(&self, scope: &RampScope) -> Result<ShapePlanReach> {
        let live = self.read_live_shape(&mut |_| Ok(true))?;
        let mut after = live.reach.clone();
        let bound = scope.to_grant_bound()?;
        if !after.grants.contains(&bound) {
            after.grants.push(bound);
        }
        Ok(ShapePlanReach::of(
            reach_projection(&live.reach),
            reach_projection(&after),
            Vec::new(),
        ))
    }
}
